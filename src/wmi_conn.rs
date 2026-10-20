//! One WQL query over DCOM: activation, then the WMI object exporter connection.
//!
//! Follows the sequence a working reference client uses against Windows
//! (MS-WMI 3.2.3, MS-DCOM 3.2.4): activate CLSID_WbemLevel1Login on port 135,
//! open one TCP connection to the port the activation advertised, and give each
//! interface its own presentation context *and* its own NTLM security context at
//! RPC_C_AUTHN_LEVEL_PKT_INTEGRITY (bind or alter_context, challenge, auth3).
//! Requests carry the target IPID as the object UUID; stubs are signed, not
//! sealed.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use byteorder::{LittleEndian, WriteBytesExt};
use thiserror::Error;
use tracing::debug;

use crate::auth::{AuthError, AuthProvider, Credentials};
use crate::dcom::{self, DcomError};
use crate::sspi_ntlm::SspiNtlmClient;
use crate::transport::{
    build_signed_request_pdu, is_last_fragment, verify_signed_response_pdu, write_context_list,
    TransportError, AUTH_TYPE_NTLM, DATA_REP, RPC_IO_TIMEOUT,
};
use crate::wmi_proto::{
    self, WmiProtoError, IID_IENUM_WBEM_CLASS_OBJECT, IID_IWBEM_LEVEL1_LOGIN, IID_IWBEM_SERVICES,
};
use crate::wmio::{self, WmioError};

#[derive(Debug, Error)]
pub enum WmiConnError {
    #[error("DCOM activation failed: {0}")]
    Activation(#[from] DcomError),
    #[error("authentication failed: {0}")]
    Auth(#[from] AuthError),
    #[error("RPC failure: {0}")]
    Transport(#[from] TransportError),
    #[error("WMI call failed: {0}")]
    Wmi(#[from] WmiProtoError),
    #[error("cannot decode WMI object: {0}")]
    Decode(#[from] WmioError),
    #[error("protocol error: {0}")]
    Protocol(String),
}

impl From<std::io::Error> for WmiConnError {
    fn from(err: std::io::Error) -> Self {
        WmiConnError::Transport(err.into())
    }
}

const PTYPE_RESPONSE: u8 = 0x02;
const PTYPE_FAULT: u8 = 0x03;
const PTYPE_BIND: u8 = 0x0B;
const PTYPE_BIND_ACK: u8 = 0x0C;
const PTYPE_BIND_NAK: u8 = 0x0D;
const PTYPE_ALTER_CONTEXT: u8 = 0x0E;
const PTYPE_ALTER_CONTEXT_RESP: u8 = 0x0F;
const PTYPE_AUTH3: u8 = 0x10;
const PFC_FIRST_LAST: u8 = 0x03;
const AUTH_LEVEL_PKT_INTEGRITY: u8 = 0x05;
const MAX_FRAG: u16 = 0x10B8;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const OPNUM_NTLM_LOGIN: u16 = 6;
const OPNUM_EXEC_QUERY: u16 = 20;
const OPNUM_ENUM_NEXT: u16 = 4;
/// lTimeout for IEnumWbemClassObject::Next: wait until objects are ready.
const WBEM_INFINITE: i32 = -1;
/// Objects requested per Next call.
const NEXT_BATCH: u32 = 32;

/// Build a bind or alter_context PDU offering one presentation context and
/// carrying an NTLM token at packet-integrity level (C706 12.6.4.3/12.6.4.1).
fn build_bind_pdu(
    ptype: u8,
    call_id: u32,
    context_id: u16,
    abstract_syntax: &[u8; 16],
    auth_context_id: u32,
    token: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.write_u16::<LittleEndian>(MAX_FRAG).unwrap(); // max_xmit_frag
    body.write_u16::<LittleEndian>(MAX_FRAG).unwrap(); // max_recv_frag
    body.write_u32::<LittleEndian>(0).unwrap(); // assoc_group_id
    write_context_list(&mut body, context_id, abstract_syntax);
    // The context list is 4-byte aligned, so the sec_trailer needs no pad.
    body.extend_from_slice(&[AUTH_TYPE_NTLM, AUTH_LEVEL_PKT_INTEGRITY, 0, 0]);
    body.write_u32::<LittleEndian>(auth_context_id).unwrap();
    body.extend_from_slice(token);
    finish_pdu(ptype, call_id, token.len(), body)
}

/// Build the rpc_auth_3 PDU that completes an NTLM handshake (MS-RPCE
/// 2.2.2.10): four pad bytes, then sec_trailer and the AUTHENTICATE message.
fn build_auth3_pdu(call_id: u32, auth_context_id: u32, token: &[u8]) -> Vec<u8> {
    // Pad content is unspecified; spaces match what Windows has accepted.
    let mut body = vec![0x20u8; 4];
    body.extend_from_slice(&[AUTH_TYPE_NTLM, AUTH_LEVEL_PKT_INTEGRITY, 0, 0]);
    body.write_u32::<LittleEndian>(auth_context_id).unwrap();
    body.extend_from_slice(token);
    finish_pdu(PTYPE_AUTH3, call_id, token.len(), body)
}

fn finish_pdu(ptype: u8, call_id: u32, auth_len: usize, body: Vec<u8>) -> Vec<u8> {
    let frag_len = 16 + body.len();
    let mut pdu = Vec::with_capacity(frag_len);
    pdu.extend_from_slice(&[5, 0, ptype, PFC_FIRST_LAST]);
    pdu.extend_from_slice(&DATA_REP);
    pdu.write_u16::<LittleEndian>(frag_len as u16).unwrap();
    pdu.write_u16::<LittleEndian>(auth_len as u16).unwrap();
    pdu.write_u32::<LittleEndian>(call_id).unwrap();
    pdu.extend_from_slice(&body);
    pdu
}

/// Parse a bind_ack / alter_context_resp: check the single presentation result
/// was accepted and return (max_xmit_frag, NTLM CHALLENGE token).
fn parse_bind_ack(pdu: &[u8], expected_ptype: u8) -> Result<(u16, Vec<u8>), WmiConnError> {
    let malformed = || {
        WmiConnError::Protocol(format!(
            "malformed bind response PDU type 0x{expected_ptype:02x}"
        ))
    };
    let u16_at = |off: usize| {
        pdu.get(off..off + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .ok_or_else(malformed)
    };
    if pdu.len() < 16 {
        return Err(malformed());
    }
    if pdu[2] == PTYPE_BIND_NAK {
        return Err(TransportError::Bind {
            result: u16_at(16).unwrap_or(0),
            reason: 0,
        }
        .into());
    }
    if pdu[2] != expected_ptype {
        return Err(WmiConnError::Protocol(format!(
            "expected PDU type 0x{expected_ptype:02x}, got 0x{:02x}",
            pdu[2]
        )));
    }
    let frag_len = u16_at(8)? as usize;
    let auth_len = u16_at(10)? as usize;
    if frag_len != pdu.len() {
        return Err(malformed());
    }
    let max_xmit = u16_at(16)?;
    // max_xmit, max_recv, assoc_group (8), then port_any_t secondary address.
    let sec_addr_len = u16_at(24)? as usize;
    let mut off = 26 + sec_addr_len;
    off += (4 - off % 4) % 4;
    let n_results = *pdu.get(off).ok_or_else(malformed)?;
    if n_results != 1 {
        return Err(malformed());
    }
    let result = u16_at(off + 4)?;
    if result != 0 {
        let reason = u16_at(off + 6)?;
        return Err(TransportError::Bind { result, reason }.into());
    }

    let trailer_at = frag_len
        .checked_sub(auth_len + 8)
        .filter(|&at| auth_len > 0 && at >= off + 4 + 24)
        .ok_or_else(malformed)?;
    if pdu[trailer_at] != AUTH_TYPE_NTLM {
        return Err(WmiConnError::Protocol(format!(
            "server answered with auth type {}, expected NTLM",
            pdu[trailer_at]
        )));
    }
    Ok((max_xmit, pdu[frag_len - auth_len..].to_vec()))
}

/// An interface bound on the connection: its presentation context, its own
/// NTLM context, and the IPID calls are addressed to.
struct BoundInterface {
    name: &'static str,
    context_id: u16,
    auth_context_id: u32,
    auth: SspiNtlmClient,
    ipid: [u8; 16],
}

/// The TCP connection to the server's WMI object exporter.
struct WmiConnection {
    stream: TcpStream,
    creds: Credentials,
    target_name: String,
    call_id: u32,
    next_context_id: u16,
    max_xmit: u16,
}

impl WmiConnection {
    fn open(host: &str, port: u16, creds: &Credentials) -> Result<Self, WmiConnError> {
        let addr = (host, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| WmiConnError::Protocol(format!("{host} resolved to no addresses")))?;
        let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
        stream.set_read_timeout(Some(RPC_IO_TIMEOUT))?;
        stream.set_write_timeout(Some(RPC_IO_TIMEOUT))?;
        let _ = stream.set_nodelay(true);
        Ok(Self {
            stream,
            creds: creds.clone(),
            target_name: format!("host/{host}"),
            call_id: 0,
            next_context_id: 0,
            max_xmit: MAX_FRAG,
        })
    }

    fn next_call_id(&mut self) -> u32 {
        self.call_id += 1;
        self.call_id
    }

    /// Add a presentation context for `iid` (bind for the first, alter_context
    /// afterwards) and authenticate a fresh NTLM context for it.
    fn bind_interface(
        &mut self,
        name: &'static str,
        iid: &[u8; 16],
        ipid: [u8; 16],
    ) -> Result<BoundInterface, WmiConnError> {
        let mut auth = SspiNtlmClient::new(&self.creds, &self.target_name)?;
        let context_id = self.next_context_id;
        let auth_context_id = u32::from(context_id);
        let (ptype, ack_ptype) = if context_id == 0 {
            (PTYPE_BIND, PTYPE_BIND_ACK)
        } else {
            (PTYPE_ALTER_CONTEXT, PTYPE_ALTER_CONTEXT_RESP)
        };
        let call_id = self.next_call_id();

        let negotiate = auth.negotiate()?;
        let pdu = build_bind_pdu(ptype, call_id, context_id, iid, auth_context_id, &negotiate);
        self.stream.write_all(&pdu)?;
        let ack = self.read_fragment()?;
        let (max_xmit, challenge) = parse_bind_ack(&ack, ack_ptype)?;
        if context_id == 0 {
            self.max_xmit = max_xmit.min(MAX_FRAG);
        }

        let authenticate = auth.respond(&challenge)?;
        self.stream
            .write_all(&build_auth3_pdu(call_id, auth_context_id, &authenticate))?;
        self.next_context_id += 1;
        debug!(interface = name, context_id, "interface bound");
        Ok(BoundInterface {
            name,
            context_id,
            auth_context_id,
            auth,
            ipid,
        })
    }

    /// Issue one ORPC call and return the reassembled, verified response stub.
    fn call(
        &mut self,
        iface: &mut BoundInterface,
        opnum: u16,
        stub: &[u8],
    ) -> Result<Vec<u8>, WmiConnError> {
        let call_id = self.next_call_id();
        let pdu = build_signed_request_pdu(
            &mut iface.auth,
            call_id,
            iface.context_id,
            opnum,
            &iface.ipid,
            stub,
            iface.auth_context_id,
        )?;
        if pdu.len() > usize::from(self.max_xmit) {
            return Err(WmiConnError::Protocol(format!(
                "{} request of {} bytes exceeds max_xmit_frag {}; request fragmentation is not implemented",
                iface.name,
                pdu.len(),
                self.max_xmit
            )));
        }
        self.stream.write_all(&pdu)?;

        let mut response = Vec::new();
        loop {
            let frag = self.read_fragment()?;
            let frag_call_id = u32::from_le_bytes(frag[12..16].try_into().unwrap());
            if frag_call_id != call_id {
                return Err(WmiConnError::Protocol(format!(
                    "response for call {frag_call_id}, expected {call_id}"
                )));
            }
            if frag[2] != PTYPE_RESPONSE && frag[2] != PTYPE_FAULT {
                return Err(WmiConnError::Protocol(format!(
                    "unexpected PDU type 0x{:02x} in response",
                    frag[2]
                )));
            }
            response.extend(verify_signed_response_pdu(&mut iface.auth, &frag)?);
            if is_last_fragment(&frag) {
                break;
            }
        }
        debug!(
            interface = iface.name,
            opnum,
            len = response.len(),
            "call complete"
        );
        tracing::trace!(stub = %hex::encode(&response), "response stub");
        Ok(response)
    }

    fn read_fragment(&mut self) -> Result<Vec<u8>, WmiConnError> {
        let mut header = [0u8; 16];
        self.stream.read_exact(&mut header)?;
        let frag_len = usize::from(u16::from_le_bytes([header[8], header[9]]));
        if frag_len < 16 {
            return Err(WmiConnError::Protocol(format!(
                "invalid fragment length {frag_len}"
            )));
        }
        let mut pdu = vec![0u8; frag_len];
        pdu[..16].copy_from_slice(&header);
        self.stream.read_exact(&mut pdu[16..])?;
        Ok(pdu)
    }
}

/// `namespace` as the NTLMLogin network path, e.g. `root\cimv2` -> `//./root/cimv2`.
fn namespace_path(namespace: &str) -> String {
    let ns = namespace.replace('\\', "/");
    if ns.starts_with("//") {
        ns
    } else {
        format!("//./{}", ns.trim_start_matches('/'))
    }
}

/// Run `wql` in `namespace` on `host` and return one JSON object per result.
pub fn query(
    host: &str,
    creds: &Credentials,
    namespace: &str,
    wql: &str,
) -> Result<Vec<serde_json::Value>, WmiConnError> {
    let (port, activation) = dcom::activate_level1_login(host, creds)?;
    // The advertised bindings name the server's own view of itself (which may
    // be unreachable behind NAT); keep dialing the address we were given.
    let mut conn = WmiConnection::open(host, port, creds)?;
    let causality_id = *uuid::Uuid::new_v4().as_bytes();

    let mut login =
        conn.bind_interface("IWbemLevel1Login", &IID_IWBEM_LEVEL1_LOGIN, activation.ipid)?;
    let resp = conn.call(
        &mut login,
        OPNUM_NTLM_LOGIN,
        &wmi_proto::encode_ntlm_login(&causality_id, &namespace_path(namespace)),
    )?;
    let services_ipid = wmi_proto::parse_interface_response(&resp, &IID_IWBEM_SERVICES)?;

    let mut services = conn.bind_interface("IWbemServices", &IID_IWBEM_SERVICES, services_ipid)?;
    let resp = conn.call(
        &mut services,
        OPNUM_EXEC_QUERY,
        &wmi_proto::encode_exec_query(&causality_id, wql, 0),
    )?;
    let enum_ipid = wmi_proto::parse_interface_response(&resp, &IID_IENUM_WBEM_CLASS_OBJECT)?;

    let mut enumerator = conn.bind_interface(
        "IEnumWbemClassObject",
        &IID_IENUM_WBEM_CLASS_OBJECT,
        enum_ipid,
    )?;
    let mut rows = Vec::new();
    loop {
        let resp = conn.call(
            &mut enumerator,
            OPNUM_ENUM_NEXT,
            &wmi_proto::encode_enum_next(&causality_id, WBEM_INFINITE, NEXT_BATCH),
        )?;
        let batch = wmio::decode_next_response(&resp)?;
        let done = batch.len() < NEXT_BATCH as usize;
        rows.extend(batch);
        if done {
            break;
        }
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    // PDUs a reference client exchanged with Windows Server 2022 on the WMI
    // port, up to (not including) the NTLM token.
    const REF_BIND: [u8; 80] = hex_literal::hex!(
        "05000b03100000007000200001000000b810b81000000000010000000000010018ad09f36ad8d011a07500c04fb6882000000000045d888aeb1cc9119fe808002b104860020000000a0500007f350100"
    );
    const REF_ALTER: [u8; 80] = hex_literal::hex!(
        "05000e03100000007000200003000000b810b8100000000001000000010001003101000000000000c00000000000004600000000045d888aeb1cc9119fe808002b104860020000000a05000080350100"
    );
    const REF_AUTH3: [u8; 28] =
        hex_literal::hex!("05001003100000008401680101000000202020200a0500007f350100");
    const REF_BIND_ACK: [u8; 68] = hex_literal::hex!(
        "05000c0310000000fe00ba0001000000b810b81055321c0006003234313538000100000000000000045d888aeb1cc9119fe808002b104860020000000a0500007f350100"
    );
    const REF_ALTER_RESP: [u8; 64] = hex_literal::hex!(
        "05000f0310000000fa00ba0003000000b810b81055321c00000000000100000000000000045d888aeb1cc9119fe808002b104860020000000a05000080350100"
    );
    const IREMUNKNOWN2: [u8; 16] = hex_literal::hex!("3101000000000000c000000000000046");

    #[test]
    fn bind_pdu_matches_reference() {
        let pdu = build_bind_pdu(
            PTYPE_BIND,
            1,
            0,
            &IID_IWBEM_LEVEL1_LOGIN,
            79231,
            &[0xAA; 32],
        );
        assert_eq!(pdu.len(), 112);
        assert_eq!(pdu[..80], REF_BIND);
        assert_eq!(pdu[80..], [0xAA; 32]);
    }

    #[test]
    fn alter_context_pdu_matches_reference() {
        let pdu = build_bind_pdu(PTYPE_ALTER_CONTEXT, 3, 1, &IREMUNKNOWN2, 79232, &[0xAA; 32]);
        assert_eq!(pdu[..80], REF_ALTER);
    }

    #[test]
    fn auth3_pdu_matches_reference() {
        let pdu = build_auth3_pdu(1, 79231, &[0xAA; 360]);
        assert_eq!(pdu.len(), 388);
        assert_eq!(pdu[..28], REF_AUTH3);
    }

    /// Reference ack prefix with a short stand-in token and lengths fixed up.
    fn ack_with_token(prefix: &[u8], token: &[u8]) -> Vec<u8> {
        let mut pdu = [prefix, token].concat();
        let len = pdu.len() as u16;
        pdu[8..10].copy_from_slice(&len.to_le_bytes());
        pdu[10..12].copy_from_slice(&(token.len() as u16).to_le_bytes());
        pdu
    }

    #[test]
    fn parse_bind_ack_returns_challenge() {
        let ack = ack_with_token(&REF_BIND_ACK, b"NTLMSSP\0challenge");
        let (max_xmit, token) = parse_bind_ack(&ack, PTYPE_BIND_ACK).unwrap();
        assert_eq!(max_xmit, 0x10B8);
        assert_eq!(token, b"NTLMSSP\0challenge");
    }

    #[test]
    fn parse_alter_context_resp_returns_challenge() {
        let ack = ack_with_token(&REF_ALTER_RESP, b"NTLMSSP\0challenge");
        let (_, token) = parse_bind_ack(&ack, PTYPE_ALTER_CONTEXT_RESP).unwrap();
        assert_eq!(token, b"NTLMSSP\0challenge");
    }

    #[test]
    fn parse_bind_ack_rejects_refused_context() {
        let mut ack = ack_with_token(&REF_BIND_ACK, b"NTLMSSP\0");
        ack[36..38].copy_from_slice(&2u16.to_le_bytes()); // provider_rejection
        ack[38..40].copy_from_slice(&2u16.to_le_bytes()); // proposed transfer syntaxes not supported
        assert!(matches!(
            parse_bind_ack(&ack, PTYPE_BIND_ACK),
            Err(WmiConnError::Transport(TransportError::Bind {
                result: 2,
                reason: 2
            }))
        ));
    }

    #[test]
    fn parse_bind_ack_rejects_wrong_type_and_truncation() {
        let ack = ack_with_token(&REF_BIND_ACK, b"NTLMSSP\0");
        assert!(parse_bind_ack(&ack, PTYPE_ALTER_CONTEXT_RESP).is_err());
        for len in 0..ack.len() {
            assert!(parse_bind_ack(&ack[..len], PTYPE_BIND_ACK).is_err());
        }
    }

    #[test]
    fn namespace_path_normalizes() {
        assert_eq!(namespace_path(r"root\cimv2"), "//./root/cimv2");
        assert_eq!(namespace_path("root/cimv2"), "//./root/cimv2");
        assert_eq!(namespace_path("//./root/cimv2"), "//./root/cimv2");
        assert_eq!(namespace_path(r"\\.\root\cimv2"), "//./root/cimv2");
    }
}
