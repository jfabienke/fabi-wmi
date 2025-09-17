use crate::auth::{AuthProvider, Credentials, NtlmV2Client};
use crate::tower;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Write};
use std::net::TcpStream;
use thiserror::Error;

/// Errors produced by RPC transports when issuing calls.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("transport not implemented")]
    NotImplemented,
    #[error("transport failure: {0}")]
    Failure(String),
}

impl From<std::io::Error> for TransportError {
    fn from(err: std::io::Error) -> Self {
        TransportError::Failure(err.to_string())
    }
}

/// Abstraction over the RPC transport/channel used to reach WMI services.
pub trait RpcTransport: Send {
    /// Identify the transport implementation (useful for logging/diagnostics).
    fn name(&self) -> &'static str;

    /// Invoke an RPC operation using the provided opnum and stub payload.
    fn invoke(&mut self, _opnum: u16, _payload: &[u8]) -> Result<Vec<u8>, TransportError> {
        Ok(Vec::new())
    }
}

/// Default no-op transport used by the current stubs.
#[derive(Default)]
pub struct StubTransport;

impl RpcTransport for StubTransport {
    fn name(&self) -> &'static str {
        "stub-transport"
    }

    fn invoke(&mut self, _opnum: u16, _payload: &[u8]) -> Result<Vec<u8>, TransportError> {
        // The stub simply returns an empty buffer. Real transports will marshal and send the
        // payload to a remote endpoint before returning the response.
        Ok(Vec::new())
    }
}

/// Configuration that will be consumed by the real transport implementation once the
/// EPM and bind logic is in place.
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct RealTransportConfig {
    pub host: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub domain: Option<String>,
}

/// Placeholder for the authenticated RPC transport that will speak to real WMI services.
#[allow(dead_code)]
#[derive(Debug)]
pub struct RealRpcTransport {
    stream: std::net::TcpStream,
    context_id: u16,
    call_id: u32,
    session_key: Vec<u8>,
    auth_level: u8,
    max_xmit: u16,
    max_recv: u16,
}

#[allow(dead_code)]
impl RealRpcTransport {
    /// Creates a new transport after resolving the dynamic endpoint via EPM and performing the
    /// NTLM authenticated bind.  The detailed network logic will be filled in during the
    /// subsequent iterations of Step 1.
    pub fn connect(config: RealTransportConfig) -> Result<Self, TransportError> {
        let host = &config.host;
        let creds = Credentials {
            username: config.username.clone().unwrap_or_default(),
            password: config.password.clone().unwrap_or_default(),
            domain: config.domain.clone().unwrap_or_default(),
            workstation: host.clone(),
        };

        let mut auth =
            NtlmV2Client::new(creds).map_err(|err| TransportError::Failure(err.to_string()))?;

        let port = Self::resolve_wmi_port(host)?;
        let mut stream = TcpStream::connect((host.as_str(), port))?;

        let negotiate = auth
            .negotiate()
            .map_err(|err| TransportError::Failure(err.to_string()))?;
        let bind_pdu = Self::build_bind_pdu(1, &negotiate);
        stream.write_all(&bind_pdu)?;

        let bind_ack = Self::read_pdu(&mut stream)?;
        let (context_id, challenge, max_xmit, max_recv) = Self::parse_bind_ack(&bind_ack)?;

        let authenticate = auth
            .respond(&challenge)
            .map_err(|err| TransportError::Failure(err.to_string()))?;
        let alter_context = Self::build_alter_context_pdu(2, context_id, &authenticate);
        stream.write_all(&alter_context)?;
        let _alter_ack = Self::read_pdu(&mut stream)?;

        let session_key = auth
            .session_key()
            .map(|key| key.to_vec())
            .ok_or_else(|| TransportError::Failure("Missing NTLM session key".into()))?;

        Ok(Self {
            stream,
            context_id,
            call_id: 3,
            session_key,
            auth_level: 6, // Packet Privacy
            max_xmit,
            max_recv,
        })
    }

    fn resolve_wmi_port(host: &str) -> Result<u16, TransportError> {
        let mut stream = TcpStream::connect((host, 135))?;
        let tower = tower::build_wmi_tower();
        let request_pdu = Self::build_epm_request_pdu(1, &tower);
        stream.write_all(&request_pdu)?;
        let response = Self::read_pdu(&mut stream)?;
        Self::parse_epm_response(&response)
    }

    fn build_epm_request_pdu(call_id: u32, tower: &[u8]) -> Vec<u8> {
        let mut pdu = Vec::with_capacity(16 + tower.len());
        let frag_len = (16 + tower.len()) as u16;
        let alloc_hint = tower.len() as u32;

        pdu.write_u8(5).unwrap(); // version
        pdu.write_u8(0).unwrap(); // minor
        pdu.write_u8(0x00).unwrap(); // request
        pdu.write_u8(0x03).unwrap(); // flags: first+last
        pdu.write_u32::<LittleEndian>(0x10_00_00_00).unwrap(); // data rep
        pdu.write_u16::<LittleEndian>(frag_len).unwrap();
        pdu.write_u16::<LittleEndian>(0).unwrap(); // auth length
        pdu.write_u32::<LittleEndian>(call_id).unwrap();
        pdu.write_u32::<LittleEndian>(alloc_hint).unwrap();
        pdu.write_u16::<LittleEndian>(0).unwrap(); // context id
        pdu.write_u16::<LittleEndian>(3).unwrap(); // opnum (EptMap)
        pdu.extend_from_slice(tower);
        pdu
    }

    fn parse_epm_response(pdu: &[u8]) -> Result<u16, TransportError> {
        // Attempt to interpret the response stub as one or more EPM tower entries. If that
        // fails (because the payload does not follow the expected layout) fall back to the
        // heuristic scan so existing stub traffic continues to work.
        match Self::parse_epm_tower(pdu) {
            Ok(Some(port)) => Ok(port),
            Ok(None) | Err(_) => Self::scan_for_tcp_floor(pdu),
        }
    }

    fn parse_epm_tower(pdu: &[u8]) -> Result<Option<u16>, TransportError> {
        if pdu.len() < 24 {
            return Err(TransportError::Failure("EPM reply truncated".into()));
        }

        let frag_len = u16::from_le_bytes([pdu[8], pdu[9]]) as usize;
        let auth_len = u16::from_le_bytes([pdu[10], pdu[11]]) as usize;
        if frag_len > pdu.len() {
            return Err(TransportError::Failure("Invalid fragment length".into()));
        }

        let stub_start = 24; // Common request/response prefix (16 byte header + 8 byte stub header)
        if stub_start > frag_len || frag_len < auth_len + stub_start {
            return Err(TransportError::Failure("EPM reply malformed".into()));
        }
        let stub_end = frag_len - auth_len;
        if stub_end > pdu.len() {
            return Err(TransportError::Failure("EPM reply overruns buffer".into()));
        }

        let stub = &pdu[stub_start..stub_end];
        let mut cursor = Cursor::new(stub);
        let floor_count = cursor
            .read_u16::<LittleEndian>()
            .map_err(|_| TransportError::Failure("Failed to read tower header".into()))?
            as usize;

        for _ in 0..floor_count {
            let lhs_len = cursor
                .read_u16::<LittleEndian>()
                .map_err(|_| TransportError::Failure("Missing floor length".into()))?
                as usize;
            if lhs_len == 0 {
                continue;
            }
            let mut lhs = vec![0u8; lhs_len];
            cursor
                .read_exact(&mut lhs)
                .map_err(|_| TransportError::Failure("Incomplete floor data".into()))?;

            let rhs_len = cursor
                .read_u16::<LittleEndian>()
                .map_err(|_| TransportError::Failure("Missing floor address length".into()))?
                as usize;
            let mut rhs = vec![0u8; rhs_len];
            cursor
                .read_exact(&mut rhs)
                .map_err(|_| TransportError::Failure("Incomplete floor address".into()))?;

            if let Some(port) = Self::extract_port_from_floor(&lhs, &rhs) {
                return Ok(Some(port));
            }
        }

        Ok(None)
    }

    fn extract_port_from_floor(lhs: &[u8], _rhs: &[u8]) -> Option<u16> {
        // Floor layouts follow [MS-EPMR] 2.2.  Protocol identifier 0x07 corresponds to
        // ncacn_ip_tcp, where the following bytes include an IPv4 address and a little-endian
        // port value.
        if lhs.first().copied() != Some(0x07) {
            return None;
        }
        if lhs.len() < 7 {
            return None;
        }
        Some(u16::from_le_bytes([lhs[5], lhs[6]]))
    }

    fn scan_for_tcp_floor(pdu: &[u8]) -> Result<u16, TransportError> {
        for i in 0..pdu.len().saturating_sub(7) {
            if pdu[i] == 0x07 && i + 7 < pdu.len() {
                let port_bytes = [pdu[i + 5], pdu[i + 6]];
                return Ok(u16::from_le_bytes(port_bytes));
            }
        }
        Err(TransportError::Failure(
            "Failed to locate TCP port in EPM response".into(),
        ))
    }

    fn build_bind_pdu(call_id: u32, ntlm: &[u8]) -> Vec<u8> {
        const MAX_XMIT_RECV: u16 = 0x10B8;
        const AUTH_TYPE_NTLM: u8 = 0x0A;
        const AUTH_LEVEL_PRIVACY: u8 = 0x06;

        let mut body = Vec::new();
        body.write_u16::<LittleEndian>(MAX_XMIT_RECV).unwrap();
        body.write_u16::<LittleEndian>(MAX_XMIT_RECV).unwrap();
        body.write_u32::<LittleEndian>(0).unwrap(); // association group
        body.write_u8(1).unwrap(); // number of context items
        body.write_u8(0).unwrap(); // alignment padding
        body.write_u16::<LittleEndian>(0).unwrap(); // context ID
        body.write_u8(1).unwrap(); // number of transfer syntaxes
        body.write_u8(0).unwrap();
        // Abstract syntax: IObjectExporter
        body.extend_from_slice(&hex_literal::hex!("c4fe9f9960521b10bbcb00aa0021347a"));
        body.write_u16::<LittleEndian>(0).unwrap(); // version major
        body.write_u16::<LittleEndian>(0).unwrap(); // version minor
                                                    // Transfer syntax: NDR
        body.extend_from_slice(&hex_literal::hex!("045d888aeb1cc9119fe808002b104860"));
        body.write_u32::<LittleEndian>(2).unwrap(); // version 2.0

        let pad = (4 - (body.len() % 4)) % 4;
        for _ in 0..pad {
            body.push(0);
        }

        body.push(AUTH_TYPE_NTLM);
        body.push(AUTH_LEVEL_PRIVACY);
        body.push(pad as u8);
        body.push(0);
        body.write_u32::<LittleEndian>(0).unwrap(); // auth context id
        for _ in 0..pad {
            body.push(0);
        }
        body.extend_from_slice(ntlm);

        let frag_len = (16 + body.len()) as u16;
        let auth_len = ntlm.len() as u16;

        let mut pdu = Vec::with_capacity(frag_len as usize);
        pdu.write_u8(5).unwrap();
        pdu.write_u8(0).unwrap();
        pdu.write_u8(0x0B).unwrap(); // bind
        pdu.write_u8(0x03).unwrap();
        pdu.write_u32::<LittleEndian>(0x10_00_00_00).unwrap();
        pdu.write_u16::<LittleEndian>(frag_len).unwrap();
        pdu.write_u16::<LittleEndian>(auth_len).unwrap();
        pdu.write_u32::<LittleEndian>(call_id).unwrap();
        pdu.extend_from_slice(&body);
        pdu
    }

    fn build_alter_context_pdu(call_id: u32, context_id: u16, ntlm: &[u8]) -> Vec<u8> {
        const MAX_XMIT_RECV: u16 = 0x10B8;
        const AUTH_TYPE_NTLM: u8 = 0x0A;
        const AUTH_LEVEL_PRIVACY: u8 = 0x06;

        let mut body = Vec::new();
        body.write_u16::<LittleEndian>(MAX_XMIT_RECV).unwrap();
        body.write_u16::<LittleEndian>(MAX_XMIT_RECV).unwrap();
        body.write_u32::<LittleEndian>(0).unwrap();
        body.write_u8(1).unwrap();
        body.write_u8(0).unwrap();
        body.write_u16::<LittleEndian>(context_id).unwrap();
        body.write_u8(1).unwrap();
        body.write_u8(0).unwrap();
        body.extend_from_slice(&hex_literal::hex!("c4fe9f9960521b10bbcb00aa0021347a"));
        body.write_u16::<LittleEndian>(0).unwrap();
        body.write_u16::<LittleEndian>(0).unwrap();
        body.extend_from_slice(&hex_literal::hex!("045d888aeb1cc9119fe808002b104860"));
        body.write_u32::<LittleEndian>(2).unwrap();

        let pad = (4 - (body.len() % 4)) % 4;
        for _ in 0..pad {
            body.push(0);
        }

        body.push(AUTH_TYPE_NTLM);
        body.push(AUTH_LEVEL_PRIVACY);
        body.push(pad as u8);
        body.push(0);
        body.write_u32::<LittleEndian>(0).unwrap();
        for _ in 0..pad {
            body.push(0);
        }
        body.extend_from_slice(ntlm);

        let frag_len = (16 + body.len()) as u16;
        let auth_len = ntlm.len() as u16;

        let mut pdu = Vec::with_capacity(frag_len as usize);
        pdu.write_u8(5).unwrap();
        pdu.write_u8(0).unwrap();
        pdu.write_u8(0x0E).unwrap(); // alter_context
        pdu.write_u8(0x03).unwrap();
        pdu.write_u32::<LittleEndian>(0x10_00_00_00).unwrap();
        pdu.write_u16::<LittleEndian>(frag_len).unwrap();
        pdu.write_u16::<LittleEndian>(auth_len).unwrap();
        pdu.write_u32::<LittleEndian>(call_id).unwrap();
        pdu.extend_from_slice(&body);
        pdu
    }

    fn parse_bind_ack(pdu: &[u8]) -> Result<(u16, Vec<u8>, u16, u16), TransportError> {
        let mut cursor = Cursor::new(pdu);
        let _version = cursor.read_u8()?;
        let _minor = cursor.read_u8()?;
        let ptype = cursor.read_u8()?;
        if ptype != 0x0C {
            return Err(TransportError::Failure(
                "Unexpected PDU type in bind_ack".into(),
            ));
        }
        cursor.read_u8()?; // flags
        cursor.read_u32::<LittleEndian>()?; // data rep
        let _frag_len = cursor.read_u16::<LittleEndian>()?;
        let auth_len = cursor.read_u16::<LittleEndian>()?;
        cursor.read_u32::<LittleEndian>()?; // call id
        let max_xmit = cursor.read_u16::<LittleEndian>()?;
        let max_recv = cursor.read_u16::<LittleEndian>()?;
        cursor.read_u32::<LittleEndian>()?; // assoc group
        let num_results = cursor.read_u8()? as usize;
        cursor.read_u8()?; // pad
        cursor.read_u16::<LittleEndian>()?; // reserved

        for _ in 0..num_results {
            let result = cursor.read_u16::<LittleEndian>()?;
            let reason = cursor.read_u16::<LittleEndian>()?;
            let mut syntax = [0u8; 16];
            cursor.read_exact(&mut syntax)?;
            cursor.read_u32::<LittleEndian>()?; // syntax version
            if result != 0 {
                return Err(TransportError::Failure(format!(
                    "Bind context rejected (reason={})",
                    reason
                )));
            }
        }

        let sec_addr_len = cursor.read_u16::<LittleEndian>()? as usize;
        if sec_addr_len > 0 {
            let mut buf = vec![0u8; sec_addr_len];
            cursor.read_exact(&mut buf)?;
            let pad = (4 - (sec_addr_len % 4)) % 4;
            if pad > 0 {
                let mut padding = vec![0u8; pad];
                cursor.read_exact(&mut padding)?;
            }
        }

        // Align to 4 before security trailer
        let pos = cursor.position() as usize;
        let pad = (4 - (pos % 4)) % 4;
        if pad > 0 {
            let mut padding = vec![0u8; pad];
            cursor.read_exact(&mut padding)?;
        }

        if auth_len == 0 {
            return Err(TransportError::Failure("bind_ack missing auth data".into()));
        }

        let auth_type = cursor.read_u8()?;
        let _auth_level = cursor.read_u8()?;
        let auth_pad_len = cursor.read_u8()?;
        cursor.read_u8()?; // reserved
        cursor.read_u32::<LittleEndian>()?; // auth context id
        if auth_pad_len > 0 {
            let mut padding = vec![0u8; auth_pad_len as usize];
            cursor.read_exact(&mut padding)?;
        }
        let mut blob = vec![0u8; auth_len as usize];
        cursor.read_exact(&mut blob)?;

        if auth_type != 0x0A {
            return Err(TransportError::Failure(
                "Unexpected auth type in bind_ack".into(),
            ));
        }

        Ok((0, blob, max_xmit, max_recv))
    }

    fn read_pdu(stream: &mut TcpStream) -> Result<Vec<u8>, TransportError> {
        let mut header = [0u8; 8];
        stream.read_exact(&mut header)?;
        let frag_len = u16::from_le_bytes([header[4], header[5]]) as usize;
        let mut buffer = Vec::with_capacity(frag_len);
        buffer.extend_from_slice(&header);
        let mut rest = vec![0u8; frag_len.saturating_sub(8)];
        stream.read_exact(&mut rest)?;
        buffer.extend_from_slice(&rest);
        Ok(buffer)
    }
}

impl RpcTransport for RealRpcTransport {
    fn name(&self) -> &'static str {
        "real-transport"
    }

    fn invoke(&mut self, _opnum: u16, _payload: &[u8]) -> Result<Vec<u8>, TransportError> {
        Err(TransportError::NotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{LittleEndian, ReadBytesExt};
    use hex_literal::hex;
    use std::io::{Cursor, Read};

    #[test]
    fn stub_transport_invoke_returns_empty() {
        let mut transport = StubTransport::default();
        let result = transport.invoke(9, &[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn epm_request_pdu_matches_expected_layout() {
        let tower = crate::tower::build_wmi_tower();
        let pdu = RealRpcTransport::build_epm_request_pdu(42, &tower);

        assert_eq!(pdu[0], 5, "RPC version");
        assert_eq!(pdu[1], 0, "RPC minor version");
        assert_eq!(pdu[2], 0x00, "PDU type: request");
        assert_eq!(pdu[3], 0x03, "Flags should indicate first|last frag");
        assert_eq!(
            &pdu[4..8],
            &[0x00, 0x00, 0x00, 0x10],
            "little-endian data rep"
        );

        let frag_len = u16::from_le_bytes([pdu[8], pdu[9]]);
        assert_eq!(frag_len as usize, 16 + tower.len());

        let auth_len = u16::from_le_bytes([pdu[10], pdu[11]]);
        assert_eq!(auth_len, 0, "EPM bind should not include auth data");

        let call_id = u32::from_le_bytes([pdu[12], pdu[13], pdu[14], pdu[15]]);
        assert_eq!(call_id, 42);

        let mut cursor = Cursor::new(&pdu[16..]);
        let alloc_hint = cursor.read_u32::<LittleEndian>().unwrap();
        assert_eq!(alloc_hint as usize, tower.len());
        let context_id = cursor.read_u16::<LittleEndian>().unwrap();
        assert_eq!(context_id, 0);
        let opnum = cursor.read_u16::<LittleEndian>().unwrap();
        assert_eq!(opnum, 3);

        let mut payload = Vec::new();
        cursor.read_to_end(&mut payload).unwrap();
        assert_eq!(payload, tower);
    }

    #[test]
    fn parse_epm_response_extracts_tcp_port() {
        let stub = crate::tower::sample_epm_response_stub();
        let mut pdu = vec![0u8; 24];
        pdu.extend_from_slice(stub);
        let frag_len = (pdu.len() as u16).to_le_bytes();
        pdu[8] = frag_len[0];
        pdu[9] = frag_len[1];
        let port = RealRpcTransport::parse_epm_response(&pdu).unwrap();
        assert_eq!(port, 0xc002);
    }

    #[test]
    fn parse_epm_response_errors_when_missing_tcp_floor() {
        let mut pdu = vec![0u8; 24];
        let frag_len = (pdu.len() as u16).to_le_bytes();
        pdu[8] = frag_len[0];
        pdu[9] = frag_len[1];
        let err = RealRpcTransport::parse_epm_response(&pdu).unwrap_err();
        assert!(matches!(err, TransportError::Failure(_)));
    }

    #[test]
    fn bind_pdu_contains_expected_context_and_auth_fields() {
        let ntlm = [0xAA, 0xBB, 0xCC, 0xDD];
        let pdu = RealRpcTransport::build_bind_pdu(7, &ntlm);

        assert_eq!(pdu[0], 5);
        assert_eq!(pdu[1], 0);
        assert_eq!(pdu[2], 0x0B);
        assert_eq!(pdu[3], 0x03);
        assert_eq!(&pdu[4..8], &[0x00, 0x00, 0x00, 0x10]);

        let frag_len = u16::from_le_bytes([pdu[8], pdu[9]]);
        assert_eq!(frag_len as usize, pdu.len());

        let auth_len = u16::from_le_bytes([pdu[10], pdu[11]]);
        assert_eq!(auth_len, ntlm.len() as u16);

        let call_id = u32::from_le_bytes([pdu[12], pdu[13], pdu[14], pdu[15]]);
        assert_eq!(call_id, 7);

        // Walk the body to ensure context ID and transfer syntax are present.
        let mut cursor = Cursor::new(&pdu[16..]);
        let max_xmit = cursor.read_u16::<LittleEndian>().unwrap();
        let max_recv = cursor.read_u16::<LittleEndian>().unwrap();
        assert_eq!(max_xmit, 0x10B8);
        assert_eq!(max_recv, 0x10B8);
        cursor.read_u32::<LittleEndian>().unwrap(); // assoc group
        let num_context_items = cursor.read_u8().unwrap();
        assert_eq!(num_context_items, 1);
        cursor.read_u8().unwrap(); // pad
        let context_id = cursor.read_u16::<LittleEndian>().unwrap();
        assert_eq!(context_id, 0);

        let num_transfer_syntax = cursor.read_u8().unwrap();
        assert_eq!(num_transfer_syntax, 1);
        cursor.read_u8().unwrap(); // alignment pad

        let mut abstract_syntax = [0u8; 16];
        cursor.read_exact(&mut abstract_syntax).unwrap();
        assert_eq!(abstract_syntax, hex!("c4fe9f9960521b10bbcb00aa0021347a"));
        let abstract_version_major = cursor.read_u16::<LittleEndian>().unwrap();
        let abstract_version_minor = cursor.read_u16::<LittleEndian>().unwrap();
        assert_eq!(abstract_version_major, 0);
        assert_eq!(abstract_version_minor, 0);

        let mut transfer_syntax = [0u8; 16];
        cursor.read_exact(&mut transfer_syntax).unwrap();
        assert_eq!(transfer_syntax, hex!("045d888aeb1cc9119fe808002b104860"));
        let transfer_version = cursor.read_u32::<LittleEndian>().unwrap();
        assert_eq!(transfer_version, 2);
        let ntlm_offset = pdu.len() - ntlm.len();
        assert_eq!(&pdu[ntlm_offset..], ntlm);

        let trailer_search_end = ntlm_offset;
        let trailer_signature = [0x0A, 0x06];
        let auth_type_offset = pdu
            .windows(2)
            .take(trailer_search_end.saturating_sub(1))
            .rposition(|window| window == trailer_signature)
            .expect("auth trailer not present");
        assert!(auth_type_offset + 8 <= trailer_search_end);

        let auth_pad_len = pdu[auth_type_offset + 2] as usize;
        let auth_context_id = u32::from_le_bytes([
            pdu[auth_type_offset + 4],
            pdu[auth_type_offset + 5],
            pdu[auth_type_offset + 6],
            pdu[auth_type_offset + 7],
        ]);
        assert_eq!(auth_context_id, 0);

        let pad_slice = &pdu[auth_type_offset + 8..trailer_search_end];
        assert_eq!(pad_slice.len(), auth_pad_len);
        assert!(pad_slice.iter().all(|b| *b == 0));
    }

    #[test]
    fn alter_context_pdu_reuses_context_and_trailer_layout() {
        let ntlm = [0x11, 0x22, 0x33, 0x44, 0x55];
        let pdu = RealRpcTransport::build_alter_context_pdu(9, 0x1234, &ntlm);

        assert_eq!(pdu[0], 5);
        assert_eq!(pdu[1], 0);
        assert_eq!(pdu[2], 0x0E);
        assert_eq!(pdu[3], 0x03);
        assert_eq!(&pdu[4..8], &[0x00, 0x00, 0x00, 0x10]);

        let call_id = u32::from_le_bytes([pdu[12], pdu[13], pdu[14], pdu[15]]);
        assert_eq!(call_id, 9);

        let mut cursor = Cursor::new(&pdu[16..]);
        cursor.read_u16::<LittleEndian>().unwrap();
        cursor.read_u16::<LittleEndian>().unwrap();
        cursor.read_u32::<LittleEndian>().unwrap();
        assert_eq!(cursor.read_u8().unwrap(), 1);
        cursor.read_u8().unwrap();
        assert_eq!(cursor.read_u16::<LittleEndian>().unwrap(), 0x1234);
        assert_eq!(cursor.read_u8().unwrap(), 1);
        cursor.read_u8().unwrap();

        let mut abstract_syntax = [0u8; 16];
        cursor.read_exact(&mut abstract_syntax).unwrap();
        assert_eq!(abstract_syntax, hex!("c4fe9f9960521b10bbcb00aa0021347a"));
        cursor.read_u16::<LittleEndian>().unwrap();
        cursor.read_u16::<LittleEndian>().unwrap();
        let mut transfer_syntax = [0u8; 16];
        cursor.read_exact(&mut transfer_syntax).unwrap();
        assert_eq!(transfer_syntax, hex!("045d888aeb1cc9119fe808002b104860"));
        cursor.read_u32::<LittleEndian>().unwrap();

        let ntlm_offset = pdu.len() - ntlm.len();
        assert_eq!(&pdu[ntlm_offset..], &ntlm);
    }
}
