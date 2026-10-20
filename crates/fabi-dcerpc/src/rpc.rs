//! DCE/RPC connection-oriented PDUs (C706 ch. 12, MS-RPCE 2.2.2): bind /
//! alter_context / auth3 framing, request and response PDUs protected at the
//! packet-integrity (signed) or packet-privacy (sealed) level, request/response
//! fragmentation, and [`RpcConnection`].

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use byteorder::{LittleEndian, WriteBytesExt};
use thiserror::Error;
use tracing::debug;

use crate::auth::{AuthError, AuthProvider, AUTH_TYPE_NTLM};

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bind rejected (result={result:#06x}, reason={reason:#06x})")]
    Bind { result: u16, reason: u16 },
    #[error("RPC fault 0x{0:08x}")]
    Fault(u32),
    #[error("RPC protocol error: {0}")]
    Protocol(String),
    #[error("RPC message protection failed: {0}")]
    Protection(String),
}

impl From<AuthError> for RpcError {
    fn from(err: AuthError) -> Self {
        RpcError::Protection(err.to_string())
    }
}

pub const PTYPE_REQUEST: u8 = 0x00;
pub const PTYPE_RESPONSE: u8 = 0x02;
pub const PTYPE_FAULT: u8 = 0x03;
pub const PTYPE_BIND: u8 = 0x0B;
pub const PTYPE_BIND_ACK: u8 = 0x0C;
pub const PTYPE_BIND_NAK: u8 = 0x0D;
pub const PTYPE_ALTER_CONTEXT: u8 = 0x0E;
pub const PTYPE_ALTER_CONTEXT_RESP: u8 = 0x0F;
pub const PTYPE_AUTH3: u8 = 0x10;

pub const PFC_FIRST_FRAG: u8 = 0x01;
pub const PFC_LAST_FRAG: u8 = 0x02;
const PFC_FIRST_LAST: u8 = PFC_FIRST_FRAG | PFC_LAST_FRAG;
const PFC_OBJECT_UUID: u8 = 0x80;

/// max_xmit_frag / max_recv_frag offered in binds (what Windows offers too).
pub const MAX_FRAG: u16 = 0x10B8;

/// Packed drep (MS-RPCE 2.2.2.1 / C706 14.1): little-endian integers, ASCII, IEEE floats.
/// Wire bytes `10 00 00 00`; write with `extend_from_slice`, never as an integer.
pub const DATA_REP: [u8; 4] = [0x10, 0x00, 0x00, 0x00];

/// Default socket read/write timeout for RPC exchanges. Windows can take >5s
/// to answer the first PDU on a connection (seen: 5.3s behind QEMU NAT).
pub const RPC_IO_TIMEOUT: Duration = Duration::from_secs(30);

const NDR_TRANSFER_SYNTAX: [u8; 16] = hex_literal::hex!("045d888aeb1cc9119fe808002b104860");

/// Write a bind/alter_context `p_cont_list_t` with one presentation context
/// (C706 12.6.3.1): abstract syntax version 0.0, transfer syntax NDR 2.0.
fn write_context_list(buf: &mut Vec<u8>, context_id: u16, abstract_syntax: &[u8; 16]) {
    buf.write_u8(1).unwrap(); // n_context_elem
    buf.write_u8(0).unwrap(); // reserved
    buf.write_u16::<LittleEndian>(0).unwrap(); // reserved2
    buf.write_u16::<LittleEndian>(context_id).unwrap(); // p_cont_id
    buf.write_u8(1).unwrap(); // n_transfer_syn
    buf.write_u8(0).unwrap(); // reserved
    buf.extend_from_slice(abstract_syntax);
    buf.write_u16::<LittleEndian>(0).unwrap(); // abstract syntax version major
    buf.write_u16::<LittleEndian>(0).unwrap(); // abstract syntax version minor
    buf.extend_from_slice(&NDR_TRANSFER_SYNTAX);
    buf.write_u32::<LittleEndian>(2).unwrap(); // NDR version 2
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

/// Build a bind or alter_context PDU offering one presentation context and
/// carrying an auth token of `auth_type` (C706 12.6.4.3 / 12.6.4.1).
#[allow(clippy::too_many_arguments)]
pub fn build_bind_pdu_with_auth_type(
    ptype: u8,
    call_id: u32,
    context_id: u16,
    abstract_syntax: &[u8; 16],
    auth_type: u8,
    auth_level: u8,
    auth_context_id: u32,
    token: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.write_u16::<LittleEndian>(MAX_FRAG).unwrap(); // max_xmit_frag
    body.write_u16::<LittleEndian>(MAX_FRAG).unwrap(); // max_recv_frag
    body.write_u32::<LittleEndian>(0).unwrap(); // assoc_group_id
    write_context_list(&mut body, context_id, abstract_syntax);
    // The context list is 4-byte aligned, so the sec_trailer needs no pad.
    body.extend_from_slice(&[auth_type, auth_level, 0, 0]);
    body.write_u32::<LittleEndian>(auth_context_id).unwrap();
    body.extend_from_slice(token);
    finish_pdu(ptype, call_id, token.len(), body)
}

/// Build a bind or alter_context PDU offering one presentation context and
/// carrying an NTLM token (C706 12.6.4.3 / 12.6.4.1).
pub fn build_bind_pdu(
    ptype: u8,
    call_id: u32,
    context_id: u16,
    abstract_syntax: &[u8; 16],
    auth_level: u8,
    auth_context_id: u32,
    token: &[u8],
) -> Vec<u8> {
    build_bind_pdu_with_auth_type(
        ptype,
        call_id,
        context_id,
        abstract_syntax,
        AUTH_TYPE_NTLM,
        auth_level,
        auth_context_id,
        token,
    )
}

/// Build the rpc_auth_3 PDU that completes a 3-leg handshake (MS-RPCE
/// 2.2.2.10): four pad bytes, then sec_trailer and the final auth token.
pub fn build_auth3_pdu_with_auth_type(
    call_id: u32,
    auth_type: u8,
    auth_level: u8,
    auth_context_id: u32,
    token: &[u8],
) -> Vec<u8> {
    // Pad content is unspecified; spaces match what Windows has accepted.
    let mut body = vec![0x20u8; 4];
    body.extend_from_slice(&[auth_type, auth_level, 0, 0]);
    body.write_u32::<LittleEndian>(auth_context_id).unwrap();
    body.extend_from_slice(token);
    finish_pdu(PTYPE_AUTH3, call_id, token.len(), body)
}

/// Build the rpc_auth_3 PDU that completes an NTLM handshake (MS-RPCE
/// 2.2.2.10): four pad bytes, then sec_trailer and the AUTHENTICATE message.
pub fn build_auth3_pdu(
    call_id: u32,
    auth_level: u8,
    auth_context_id: u32,
    token: &[u8],
) -> Vec<u8> {
    build_auth3_pdu_with_auth_type(call_id, AUTH_TYPE_NTLM, auth_level, auth_context_id, token)
}

/// The parts of a bind_ack / alter_context_resp a client needs.
#[derive(Debug)]
pub struct BindAck {
    pub max_xmit: u16,
    /// The `auth_type` reported in the server's `sec_trailer` when `auth_token`
    /// is non-empty (0 when no `sec_trailer` is present).
    pub auth_type: u8,
    /// The server's auth token (e.g. the NTLM CHALLENGE or Kerberos AP-REP);
    /// empty when the PDU carries none (an alter_context_resp that completes a
    /// handshake).
    pub auth_token: Vec<u8>,
}

/// Parse a bind_ack or alter_context_resp: check it is `expected_ptype` and
/// that its single presentation result was accepted. A bind_nak or a fault
/// (Windows' answer to bad credentials) become errors.
pub fn parse_bind_ack(pdu: &[u8], expected_ptype: u8) -> Result<BindAck, RpcError> {
    let malformed = || {
        RpcError::Protocol(format!(
            "malformed bind response (expected type 0x{expected_ptype:02x})"
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
    match pdu[2] {
        PTYPE_BIND_NAK => {
            return Err(RpcError::Bind {
                result: u16_at(16).unwrap_or(0),
                reason: 0,
            })
        }
        PTYPE_FAULT => return Err(RpcError::Fault(fault_status(pdu).ok_or_else(malformed)?)),
        t if t != expected_ptype => {
            return Err(RpcError::Protocol(format!(
                "expected PDU type 0x{expected_ptype:02x}, got 0x{t:02x}"
            )))
        }
        _ => {}
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
    if *pdu.get(off).ok_or_else(malformed)? != 1 {
        return Err(malformed()); // n_results: we always offer one context
    }
    let result = u16_at(off + 4)?;
    if result != 0 {
        let reason = u16_at(off + 6)?;
        return Err(RpcError::Bind { result, reason });
    }
    let results_end = off + 4 + 24;
    if results_end > frag_len {
        return Err(malformed());
    }
    if auth_len == 0 {
        return Ok(BindAck {
            max_xmit,
            auth_type: 0,
            auth_token: Vec::new(),
        });
    }
    let trailer_at = frag_len
        .checked_sub(auth_len + 8)
        .filter(|&at| at >= results_end)
        .ok_or_else(malformed)?;
    let auth_type = pdu[trailer_at];
    if auth_type == 0 {
        return Err(RpcError::Protocol(
            "server answered with auth_type 0 in authenticated bind_ack".into(),
        ));
    }
    Ok(BindAck {
        max_xmit,
        auth_type,
        auth_token: pdu[frag_len - auth_len..].to_vec(),
    })
}

/// The status of an RPC fault PDU (C706 12.6.4.7), if `pdu` is one.
pub fn fault_status(pdu: &[u8]) -> Option<u32> {
    (pdu.get(2) == Some(&PTYPE_FAULT))
        .then(|| pdu.get(24..28))
        .flatten()
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

/// Read one PDU (fragment) from `stream`.
pub fn read_pdu(stream: &mut impl Read) -> Result<Vec<u8>, RpcError> {
    let mut header = [0u8; 16];
    stream.read_exact(&mut header)?;
    let frag_len = usize::from(u16::from_le_bytes([header[8], header[9]]));
    if frag_len < 16 {
        return Err(RpcError::Protocol(format!(
            "invalid fragment length {frag_len}"
        )));
    }
    let mut pdu = vec![0u8; frag_len];
    pdu[..16].copy_from_slice(&header);
    stream.read_exact(&mut pdu[16..])?;
    Ok(pdu)
}

pub const AUTH_LEVEL_PKT_PRIVACY: u8 = 0x06;
pub const AUTH_LEVEL_PKT_INTEGRITY: u8 = 0x05;
const REQUEST_HEADER_LEN: usize = 24; // common header (16) + alloc_hint, p_cont_id, opnum
                                      // With PFC_OBJECT_UUID the request header carries a 16-byte object UUID (IPID).
const REQUEST_HEADER_WITH_OBJECT_LEN: usize = REQUEST_HEADER_LEN + 16;
const RESPONSE_HEADER_LEN: usize = 24; // common header (16) + alloc_hint, p_cont_id, cancel_count, reserved
const SEC_TRAILER_LEN: usize = 8;

/// Reject a PDU whose fragment length would not fit the 16-bit frag_length
/// field.
fn check_frag_len(frag_len: usize) -> Result<(), RpcError> {
    if frag_len > u16::MAX as usize {
        return Err(RpcError::Protocol(format!(
            "request PDU too large for a single fragment: {frag_len} bytes"
        )));
    }
    Ok(())
}

/// Build one request fragment PDU at `auth_level` (`AUTH_LEVEL_PKT_PRIVACY` or
/// `AUTH_LEVEL_PKT_INTEGRITY`), with explicit `pfc_flags` (`PFC_FIRST_FRAG`,
/// `PFC_LAST_FRAG`) and `alloc_hint`.
#[allow(clippy::too_many_arguments)]
pub fn build_request_fragment_pdu(
    auth: &mut dyn AuthProvider,
    call_id: u32,
    context_id: u16,
    opnum: u16,
    object_ipid: Option<&[u8; 16]>,
    stub_chunk: &[u8],
    alloc_hint: u32,
    pfc_flags: u8,
    auth_level: u8,
    auth_context_id: u32,
) -> Result<Vec<u8>, RpcError> {
    let sealed = match auth_level {
        AUTH_LEVEL_PKT_PRIVACY => true,
        AUTH_LEVEL_PKT_INTEGRITY => false,
        other => {
            return Err(RpcError::Protocol(format!(
                "unsupported auth_level 0x{other:02x}"
            )))
        }
    };
    let pad_align = if sealed { 16 } else { 4 };
    let pad = (pad_align - stub_chunk.len() % pad_align) % pad_align;
    let padded_stub_len = stub_chunk.len() + pad;
    let auth_value_len = auth
        .auth_value_len(sealed, padded_stub_len)
        .map_err(|err| RpcError::Protection(err.to_string()))?;
    let auth_type = auth.auth_type();
    let header_len = if object_ipid.is_some() {
        REQUEST_HEADER_WITH_OBJECT_LEN
    } else {
        REQUEST_HEADER_LEN
    };
    let frag_len = header_len + padded_stub_len + SEC_TRAILER_LEN + auth_value_len;
    check_frag_len(frag_len)?;

    let flags = pfc_flags
        | if object_ipid.is_some() {
            PFC_OBJECT_UUID
        } else {
            0
        };
    let mut pdu = Vec::with_capacity(frag_len);
    pdu.extend_from_slice(&[5, 0, PTYPE_REQUEST, flags]);
    pdu.extend_from_slice(&DATA_REP);
    pdu.write_u16::<LittleEndian>(frag_len as u16).unwrap();
    pdu.write_u16::<LittleEndian>(auth_value_len as u16)
        .unwrap();
    pdu.write_u32::<LittleEndian>(call_id).unwrap();
    pdu.write_u32::<LittleEndian>(alloc_hint).unwrap();
    pdu.write_u16::<LittleEndian>(context_id).unwrap();
    pdu.write_u16::<LittleEndian>(opnum).unwrap();
    if let Some(ipid) = object_ipid {
        pdu.extend_from_slice(ipid);
    }
    pdu.extend_from_slice(stub_chunk);
    pdu.extend(std::iter::repeat_n(0u8, pad));
    let trailer_at = pdu.len();
    pdu.extend_from_slice(&[auth_type, auth_level, pad as u8, 0]);
    pdu.write_u32::<LittleEndian>(auth_context_id).unwrap();

    let (head, rest) = pdu.split_at_mut(header_len);
    let (body, trailer) = rest.split_at_mut(trailer_at - header_len);
    let auth_value = if sealed {
        auth.seal_rpc(head, body, trailer)
    } else {
        auth.sign_rpc(head, body, trailer)
    }
    .map_err(|err| RpcError::Protection(err.to_string()))?;
    if auth_value.len() != auth_value_len {
        return Err(RpcError::Protocol(format!(
            "unexpected auth_value length {} (expected {auth_value_len})",
            auth_value.len()
        )));
    }
    pdu.extend_from_slice(&auth_value);
    Ok(pdu)
}

/// Build a request PDU protected at RPC_C_AUTHN_LEVEL_PKT_PRIVACY: the stub is
/// padded to a 16-byte multiple and encrypted; header and sec_trailer are signed.
pub fn build_sealed_request_pdu(
    auth: &mut dyn AuthProvider,
    call_id: u32,
    context_id: u16,
    opnum: u16,
    stub: &[u8],
    auth_context_id: u32,
) -> Result<Vec<u8>, RpcError> {
    build_request_fragment_pdu(
        auth,
        call_id,
        context_id,
        opnum,
        None,
        stub,
        stub.len() as u32,
        PFC_FIRST_LAST,
        AUTH_LEVEL_PKT_PRIVACY,
        auth_context_id,
    )
}

/// Build a request PDU at RPC_C_AUTHN_LEVEL_PKT_INTEGRITY that targets an ORPC
/// object: PFC_OBJECT_UUID is set and the 16-byte IPID follows opnum. The stub
/// stays cleartext (signed, not encrypted); the auth_value is the signature over
/// header, stub, padding and sec_trailer.
pub fn build_signed_request_pdu(
    auth: &mut dyn AuthProvider,
    call_id: u32,
    context_id: u16,
    opnum: u16,
    object_ipid: &[u8; 16],
    stub: &[u8],
    auth_context_id: u32,
) -> Result<Vec<u8>, RpcError> {
    build_request_fragment_pdu(
        auth,
        call_id,
        context_id,
        opnum,
        Some(object_ipid),
        stub,
        stub.len() as u32,
        PFC_FIRST_LAST,
        AUTH_LEVEL_PKT_INTEGRITY,
        auth_context_id,
    )
}

/// Build one or more request PDUs for `stub`, splitting into fragments when a
/// single PDU would exceed `max_xmit` (MS-RPCE 2.2.2.6 / C706 12.6.4.9).
#[allow(clippy::too_many_arguments)]
pub fn build_request_pdus(
    auth: &mut dyn AuthProvider,
    call_id: u32,
    context_id: u16,
    opnum: u16,
    object_ipid: Option<&[u8; 16]>,
    stub: &[u8],
    auth_level: u8,
    auth_context_id: u32,
    max_xmit: u16,
) -> Result<Vec<Vec<u8>>, RpcError> {
    let sealed = auth_level == AUTH_LEVEL_PKT_PRIVACY;
    let pad_align = if sealed { 16 } else { 4 };
    let header_len = if object_ipid.is_some() {
        REQUEST_HEADER_WITH_OBJECT_LEN
    } else {
        REQUEST_HEADER_LEN
    };
    let pad = (pad_align - stub.len() % pad_align) % pad_align;
    let auth_len = auth
        .auth_value_len(sealed, stub.len() + pad)
        .map_err(|err| RpcError::Protection(err.to_string()))?;
    let single_len = header_len + stub.len() + pad + SEC_TRAILER_LEN + auth_len;

    if single_len <= usize::from(max_xmit) {
        return Ok(vec![build_request_fragment_pdu(
            auth,
            call_id,
            context_id,
            opnum,
            object_ipid,
            stub,
            stub.len() as u32,
            PFC_FIRST_LAST,
            auth_level,
            auth_context_id,
        )?]);
    }

    // Non-final fragments must carry a 16-byte-multiple stub body so they need
    // zero auth padding before sec_trailer.
    let overhead = header_len + SEC_TRAILER_LEN + auth_len;
    let max_chunk = usize::from(max_xmit)
        .checked_sub(overhead)
        .map(|avail| (avail / 16) * 16)
        .filter(|&c| c > 0)
        .ok_or_else(|| {
            RpcError::Protocol(format!("max_xmit_frag {max_xmit} too small for RPC header"))
        })?;

    let mut pdus = Vec::new();
    let mut offset = 0usize;
    while offset < stub.len() {
        let remaining = stub.len() - offset;
        let is_first = offset == 0;
        // Check if the remainder (plus its alignment pad) fits in the last fragment.
        let rem_pad = (pad_align - remaining % pad_align) % pad_align;
        let (chunk_len, is_last) = if remaining + rem_pad + overhead <= usize::from(max_xmit) {
            (remaining, true)
        } else {
            (max_chunk.min(remaining), false)
        };
        let pfc_flags =
            (if is_first { PFC_FIRST_FRAG } else { 0 }) | (if is_last { PFC_LAST_FRAG } else { 0 });
        let pdu = build_request_fragment_pdu(
            auth,
            call_id,
            context_id,
            opnum,
            object_ipid,
            &stub[offset..offset + chunk_len],
            remaining as u32,
            pfc_flags,
            auth_level,
            auth_context_id,
        )?;
        pdus.push(pdu);
        offset += chunk_len;
    }
    Ok(pdus)
}

/// Verify one packet-integrity response fragment and return its cleartext stub
/// (without the NDR pad). Fault PDUs become an error carrying the status.
pub fn verify_signed_response_pdu(
    auth: &mut dyn AuthProvider,
    pdu: &[u8],
) -> Result<Vec<u8>, RpcError> {
    if pdu.len() < RESPONSE_HEADER_LEN + 4 {
        return Err(RpcError::Protocol("response PDU too short".into()));
    }
    let ptype = pdu[2];
    if ptype == PTYPE_FAULT {
        let status = u32::from_le_bytes(pdu[24..28].try_into().unwrap());
        return Err(RpcError::Fault(status));
    }
    if ptype != PTYPE_RESPONSE {
        return Err(RpcError::Protocol(format!(
            "unexpected PDU type 0x{ptype:02x}, expected response"
        )));
    }
    let frag_len = u16::from_le_bytes([pdu[8], pdu[9]]) as usize;
    let auth_len = u16::from_le_bytes([pdu[10], pdu[11]]) as usize;
    if frag_len != pdu.len() || auth_len == 0 {
        return Err(RpcError::Protocol(
            "response is not an authenticated PDU".into(),
        ));
    }
    let trailer_at = frag_len
        .checked_sub(auth_len + SEC_TRAILER_LEN)
        .filter(|&at| at >= RESPONSE_HEADER_LEN)
        .ok_or_else(|| RpcError::Protocol("bad auth_length in response".into()))?;
    let pad = pdu[trailer_at + 2] as usize;
    let stub_end = trailer_at
        .checked_sub(pad)
        .filter(|&e| e >= RESPONSE_HEADER_LEN)
        .ok_or_else(|| RpcError::Protocol("bad auth_pad in response".into()))?;

    // The stub stays cleartext; verify_rpc only checks the signature.
    auth.verify_rpc(
        &pdu[..RESPONSE_HEADER_LEN],
        &pdu[RESPONSE_HEADER_LEN..trailer_at],
        &pdu[trailer_at..trailer_at + SEC_TRAILER_LEN],
        &pdu[frag_len - auth_len..],
    )
    .map_err(|err| RpcError::Protection(err.to_string()))?;
    Ok(pdu[RESPONSE_HEADER_LEN..stub_end].to_vec())
}

/// Map an RPC fault status to an HRESULT: access-denied (Win32 error 5 or
/// nca_s_fault_access_denied) becomes E_ACCESSDENIED, an HRESULT passes
/// through, and any other Win32 error becomes HRESULT_FROM_WIN32.
pub fn fault_to_hresult(status: u32) -> u32 {
    match status {
        0x0000_0005 | 0x1c01_0002 => 0x8007_0005,
        s if s & 0x8000_0000 != 0 => s,
        s => 0x8007_0000 | (s & 0xFFFF),
    }
}

/// True if this fragment is the last of a response (PFC_LAST).
pub fn is_last_fragment(pdu: &[u8]) -> bool {
    pdu.len() > 3 && pdu[3] & PFC_LAST_FRAG != 0
}

/// Verify and decrypt a packet-privacy response PDU, returning it with the stub
/// in plaintext (same layout). Fault PDUs become an error carrying the status.
pub fn unseal_response_pdu(auth: &mut dyn AuthProvider, pdu: &[u8]) -> Result<Vec<u8>, RpcError> {
    if pdu.len() < RESPONSE_HEADER_LEN + 4 {
        return Err(RpcError::Protocol("response PDU too short".into()));
    }
    let ptype = pdu[2];
    if ptype == PTYPE_FAULT {
        let status = u32::from_le_bytes(pdu[24..28].try_into().unwrap());
        return Err(RpcError::Fault(status));
    }
    if ptype != PTYPE_RESPONSE {
        return Err(RpcError::Protocol(format!(
            "unexpected PDU type 0x{ptype:02x}, expected response"
        )));
    }
    let frag_len = u16::from_le_bytes([pdu[8], pdu[9]]) as usize;
    let auth_len = u16::from_le_bytes([pdu[10], pdu[11]]) as usize;
    if frag_len != pdu.len() || auth_len == 0 {
        return Err(RpcError::Protocol(
            "response is not an authenticated PDU".into(),
        ));
    }
    let trailer_at = frag_len
        .checked_sub(auth_len + SEC_TRAILER_LEN)
        .filter(|&at| at >= RESPONSE_HEADER_LEN)
        .ok_or_else(|| RpcError::Protocol("bad auth_length in response".into()))?;

    let mut plain = pdu.to_vec();
    let (head, rest) = plain.split_at_mut(RESPONSE_HEADER_LEN);
    let (body, tail) = rest.split_at_mut(trailer_at - RESPONSE_HEADER_LEN);
    let (trailer, auth_value) = tail.split_at_mut(SEC_TRAILER_LEN);
    auth.unseal_rpc(head, body, trailer, auth_value)
        .map_err(|err| RpcError::Protection(err.to_string()))?;
    Ok(plain)
}

/// Verify and decrypt one packet-privacy response fragment and return its
/// cleartext stub (without header, NDR auth pad, `sec_trailer`, or `auth_value`).
pub fn unseal_response_stub(auth: &mut dyn AuthProvider, pdu: &[u8]) -> Result<Vec<u8>, RpcError> {
    let plain = unseal_response_pdu(auth, pdu)?;
    let frag_len = plain.len();
    let auth_len = u16::from_le_bytes([plain[10], plain[11]]) as usize;
    let trailer_at = frag_len - auth_len - SEC_TRAILER_LEN;
    let pad = plain[trailer_at + 2] as usize;
    let stub_end = trailer_at
        .checked_sub(pad)
        .filter(|&e| e >= RESPONSE_HEADER_LEN)
        .ok_or_else(|| RpcError::Protocol("bad auth_pad in response".into()))?;
    Ok(plain[RESPONSE_HEADER_LEN..stub_end].to_vec())
}

/// How the third leg of an authentication handshake is carried on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeStyle {
    /// Send the third leg in `PTYPE_ALTER_CONTEXT` and read `PTYPE_ALTER_CONTEXT_RESP`
    /// (used by the DCOM activation / object exporter endpoint on port 135).
    AlterContext,
    /// Send the third leg in `PTYPE_AUTH3` with no server reply
    /// (used by dynamic DCOM/WMI endpoints).
    Auth3,
}

/// A presentation context bound on an [`RpcConnection`] together with its
/// authenticated security context.
pub struct BoundContext {
    pub name: &'static str,
    pub context_id: u16,
    pub auth_context_id: u32,
    pub auth_level: u8,
    pub auth: Box<dyn AuthProvider>,
}

/// A connection-oriented DCE/RPC client association over a stream, owning the
/// socket, presentation-context handshakes, call dispatch, and fragment
/// splitting/reassembly.
pub struct RpcConnection<S = TcpStream> {
    stream: S,
    call_id: u32,
    next_context_id: u16,
    max_xmit: u16,
}

impl RpcConnection<TcpStream> {
    /// Dial `(host, port)` over TCP with `connect_timeout` and set read/write
    /// timeouts to `io_timeout`.
    pub fn connect(
        host: &str,
        port: u16,
        connect_timeout: Duration,
        io_timeout: Duration,
    ) -> Result<Self, RpcError> {
        let addr = (host, port).to_socket_addrs()?.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{host} resolved to no addresses"),
            )
        })?;
        let stream = TcpStream::connect_timeout(&addr, connect_timeout.min(io_timeout))?;
        let _ = stream.set_nodelay(true);
        let mut conn = Self::from_stream(stream);
        conn.set_timeout(io_timeout)?;
        Ok(conn)
    }

    /// Change the read/write timeout on the underlying TCP stream.
    pub fn set_timeout(&mut self, timeout: Duration) -> Result<(), RpcError> {
        // A zero Duration means "no timeout" to the socket API; never allow it.
        let timeout = Some(timeout.max(Duration::from_millis(1)));
        self.stream.set_read_timeout(timeout)?;
        self.stream.set_write_timeout(timeout)?;
        Ok(())
    }
}

impl<S: Read + Write> RpcConnection<S> {
    /// Wrap an existing stream (e.g. a `TcpStream` or an in-memory test pipe).
    pub fn from_stream(stream: S) -> Self {
        Self {
            stream,
            call_id: 0,
            next_context_id: 0,
            max_xmit: MAX_FRAG,
        }
    }

    pub fn max_xmit(&self) -> u16 {
        self.max_xmit
    }

    fn next_call_id(&mut self) -> u32 {
        self.call_id += 1;
        self.call_id
    }

    /// Bind a presentation context for `abstract_syntax` (`PTYPE_BIND` for the
    /// first context on the connection, `PTYPE_ALTER_CONTEXT` afterwards) and
    /// complete the `auth` handshake at `auth_level`.
    pub fn bind_context(
        &mut self,
        name: &'static str,
        abstract_syntax: &[u8; 16],
        auth_level: u8,
        handshake: HandshakeStyle,
        mut auth: Box<dyn AuthProvider>,
    ) -> Result<BoundContext, RpcError> {
        let context_id = self.next_context_id;
        let auth_context_id = u32::from(context_id);
        let auth_type = auth.auth_type();
        let (ptype, ack_ptype) = if context_id == 0 {
            (PTYPE_BIND, PTYPE_BIND_ACK)
        } else {
            (PTYPE_ALTER_CONTEXT, PTYPE_ALTER_CONTEXT_RESP)
        };
        let call_id = self.next_call_id();

        let negotiate = auth.negotiate()?;
        self.stream.write_all(&build_bind_pdu_with_auth_type(
            ptype,
            call_id,
            context_id,
            abstract_syntax,
            auth_type,
            auth_level,
            auth_context_id,
            &negotiate,
        ))?;
        let ack = parse_bind_ack(&read_pdu(&mut self.stream)?, ack_ptype)?;
        if ack.auth_type != 0 && ack.auth_type != auth_type {
            return Err(RpcError::Protocol(format!(
                "server answered with auth type {}, expected {}",
                ack.auth_type, auth_type
            )));
        }
        if context_id == 0 {
            self.max_xmit = ack.max_xmit.min(MAX_FRAG);
        }

        if !ack.auth_token.is_empty() {
            let authenticate = auth.respond(&ack.auth_token)?;
            if !authenticate.is_empty() {
                match handshake {
                    HandshakeStyle::Auth3 => {
                        self.stream.write_all(&build_auth3_pdu_with_auth_type(
                            call_id,
                            auth_type,
                            auth_level,
                            auth_context_id,
                            &authenticate,
                        ))?;
                    }
                    HandshakeStyle::AlterContext => {
                        let alter_call_id = self.next_call_id();
                        self.stream.write_all(&build_bind_pdu_with_auth_type(
                            PTYPE_ALTER_CONTEXT,
                            alter_call_id,
                            context_id,
                            abstract_syntax,
                            auth_type,
                            auth_level,
                            auth_context_id,
                            &authenticate,
                        ))?;
                        parse_bind_ack(&read_pdu(&mut self.stream)?, PTYPE_ALTER_CONTEXT_RESP)?;
                    }
                }
            }
        }

        self.next_context_id += 1;
        debug!(interface = name, context_id, "interface bound");
        Ok(BoundContext {
            name,
            context_id,
            auth_context_id,
            auth_level,
            auth,
        })
    }

    /// Issue one RPC/ORPC call on `ctx` (splitting the request across fragments
    /// if `stub` exceeds `max_xmit`) and return the reassembled, verified/decrypted
    /// response stub.
    pub fn call(
        &mut self,
        ctx: &mut BoundContext,
        opnum: u16,
        object_ipid: Option<&[u8; 16]>,
        stub: &[u8],
    ) -> Result<Vec<u8>, RpcError> {
        let call_id = self.next_call_id();
        let pdus = build_request_pdus(
            &mut *ctx.auth,
            call_id,
            ctx.context_id,
            opnum,
            object_ipid,
            stub,
            ctx.auth_level,
            ctx.auth_context_id,
            self.max_xmit,
        )?;
        for pdu in &pdus {
            self.stream.write_all(pdu)?;
        }

        let mut response = Vec::new();
        loop {
            let frag = read_pdu(&mut self.stream)?;
            let frag_call_id = u32::from_le_bytes(frag[12..16].try_into().unwrap());
            if frag_call_id != call_id {
                return Err(RpcError::Protocol(format!(
                    "response for call {frag_call_id}, expected {call_id}"
                )));
            }
            if frag[2] != PTYPE_RESPONSE && frag[2] != PTYPE_FAULT {
                return Err(RpcError::Protocol(format!(
                    "unexpected PDU type 0x{:02x} in response",
                    frag[2]
                )));
            }
            let chunk = match ctx.auth_level {
                AUTH_LEVEL_PKT_PRIVACY => unseal_response_stub(&mut *ctx.auth, &frag)?,
                AUTH_LEVEL_PKT_INTEGRITY => verify_signed_response_pdu(&mut *ctx.auth, &frag)?,
                other => {
                    return Err(RpcError::Protocol(format!(
                        "unsupported auth_level 0x{other:02x}"
                    )))
                }
            };
            response.extend(chunk);
            if is_last_fragment(&frag) {
                break;
            }
        }
        debug!(
            interface = ctx.name,
            opnum,
            len = response.len(),
            "call complete"
        );
        tracing::trace!(stub = %hex::encode(&response), "response stub");
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_frag_len_rejects_overflow() {
        assert!(check_frag_len(u16::MAX as usize).is_ok());
        assert!(check_frag_len(u16::MAX as usize + 1).is_err());
    }

    // PDUs a reference client exchanged with Windows Server 2022, up to (not
    // including) the NTLM token. On port 135 (activation, packet privacy):
    const REF_SCM_BIND: [u8; 72] = hex_literal::hex!(
        "05000b03100000007000200001000000b810b81000000000"
        "0100000000000100a001000000000000c000000000000046"
        "00000000045d888aeb1cc9119fe808002b10486002000000"
    );
    // On the WMI port (packet integrity):
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
    /// alter_context_resp Windows sent to complete activation's NTLM
    /// handshake (packet privacy): a sec_trailer but no auth token.
    const REF_ALTER_RESP_NO_AUTH: [u8; 64] = hex_literal::hex!(
        "05000f03100000004000000002000000b810b81027580000000031330100000000000000045d888aeb1cc9119fe808002b104860020000000a06000000000000"
    );
    /// Fault Windows sends for an alter_context carrying bad credentials.
    const REF_ACCESS_DENIED_FAULT: [u8; 32] =
        hex_literal::hex!("0500032310000000200000000200000020000000000000000500000000000000");
    const IREMOTESCMACTIVATOR: [u8; 16] = hex_literal::hex!("a001000000000000c000000000000046");
    const IWBEMLEVEL1LOGIN: [u8; 16] = hex_literal::hex!("18ad09f36ad8d011a07500c04fb68820");
    const IREMUNKNOWN: [u8; 16] = hex_literal::hex!("3101000000000000c000000000000046");

    #[test]
    fn scm_bind_matches_reference() {
        let pdu = build_bind_pdu(
            PTYPE_BIND,
            1,
            0,
            &IREMOTESCMACTIVATOR,
            AUTH_LEVEL_PKT_PRIVACY,
            0,
            &[0xAA; 32],
        );
        // frag_length/auth_length (8..12) depend on the reference's NTLM token.
        assert_eq!(pdu[..8], REF_SCM_BIND[..8]);
        assert_eq!(pdu[12..72], REF_SCM_BIND[12..]);
        assert_eq!(
            pdu[72..80],
            [AUTH_TYPE_NTLM, AUTH_LEVEL_PKT_PRIVACY, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn bind_pdu_matches_reference() {
        let pdu = build_bind_pdu(
            PTYPE_BIND,
            1,
            0,
            &IWBEMLEVEL1LOGIN,
            AUTH_LEVEL_PKT_INTEGRITY,
            79231,
            &[0xAA; 32],
        );
        assert_eq!(pdu.len(), 112);
        assert_eq!(pdu[..80], REF_BIND);
        assert_eq!(pdu[80..], [0xAA; 32]);
    }

    #[test]
    fn alter_context_pdu_matches_reference() {
        let pdu = build_bind_pdu(
            PTYPE_ALTER_CONTEXT,
            3,
            1,
            &IREMUNKNOWN,
            AUTH_LEVEL_PKT_INTEGRITY,
            79232,
            &[0xAA; 32],
        );
        assert_eq!(pdu[..80], REF_ALTER);
    }

    #[test]
    fn auth3_pdu_matches_reference() {
        let pdu = build_auth3_pdu(1, AUTH_LEVEL_PKT_INTEGRITY, 79231, &[0xAA; 360]);
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
        let ack = parse_bind_ack(&ack, PTYPE_BIND_ACK).unwrap();
        assert_eq!(ack.max_xmit, 0x10B8);
        assert_eq!(ack.auth_type, AUTH_TYPE_NTLM);
        assert_eq!(ack.auth_token, b"NTLMSSP\0challenge");
    }

    #[test]
    fn parse_alter_context_resp_returns_challenge() {
        let ack = ack_with_token(&REF_ALTER_RESP, b"NTLMSSP\0challenge");
        let ack = parse_bind_ack(&ack, PTYPE_ALTER_CONTEXT_RESP).unwrap();
        assert_eq!(ack.auth_token, b"NTLMSSP\0challenge");
    }

    #[test]
    fn parse_alter_context_resp_without_token() {
        let ack = parse_bind_ack(&REF_ALTER_RESP_NO_AUTH, PTYPE_ALTER_CONTEXT_RESP).unwrap();
        assert!(ack.auth_token.is_empty());
    }

    #[test]
    fn parse_bind_ack_reports_access_denied_fault() {
        assert!(matches!(
            parse_bind_ack(&REF_ACCESS_DENIED_FAULT, PTYPE_ALTER_CONTEXT_RESP),
            Err(RpcError::Fault(5))
        ));
        assert_eq!(fault_status(&REF_ACCESS_DENIED_FAULT), Some(5));
        assert_eq!(fault_status(&REF_ALTER_RESP_NO_AUTH), None);
    }

    #[test]
    fn parse_bind_ack_rejects_refused_context() {
        let mut ack = ack_with_token(&REF_BIND_ACK, b"NTLMSSP\0");
        ack[36..38].copy_from_slice(&2u16.to_le_bytes()); // provider_rejection
        ack[38..40].copy_from_slice(&2u16.to_le_bytes()); // proposed transfer syntaxes not supported
        assert!(matches!(
            parse_bind_ack(&ack, PTYPE_BIND_ACK),
            Err(RpcError::Bind {
                result: 2,
                reason: 2
            })
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
    fn fault_to_hresult_maps_win32_and_nca_codes() {
        assert_eq!(fault_to_hresult(5), 0x8007_0005);
        assert_eq!(fault_to_hresult(0x1c01_0002), 0x8007_0005);
        assert_eq!(fault_to_hresult(0x6ba), 0x8007_06ba);
        assert_eq!(fault_to_hresult(0x8004_1003), 0x8004_1003);
    }

    #[test]
    fn read_pdu_reads_exactly_one_fragment() {
        let two = [REF_ALTER_RESP_NO_AUTH.as_slice(), &REF_ACCESS_DENIED_FAULT].concat();
        let mut cursor = std::io::Cursor::new(two);
        assert_eq!(read_pdu(&mut cursor).unwrap(), REF_ALTER_RESP_NO_AUTH);
        assert_eq!(read_pdu(&mut cursor).unwrap(), REF_ACCESS_DENIED_FAULT);
        assert!(read_pdu(&mut cursor).is_err());
    }

    struct DummyVariableSsp {
        auth_type: u8,
        sig_len: usize,
    }

    impl AuthProvider for DummyVariableSsp {
        fn auth_type(&self) -> u8 {
            self.auth_type
        }
        fn auth_value_len(
            &mut self,
            _sealed: bool,
            _padded_stub_len: usize,
        ) -> Result<usize, AuthError> {
            Ok(self.sig_len)
        }
        fn negotiate(&mut self) -> Result<Vec<u8>, AuthError> {
            Ok(vec![1, 2, 3])
        }
        fn respond(&mut self, _challenge: &[u8]) -> Result<Vec<u8>, AuthError> {
            Ok(Vec::new())
        }
        fn seal_rpc(
            &mut self,
            header: &[u8],
            stub: &mut [u8],
            sec_trailer: &[u8],
        ) -> Result<Vec<u8>, AuthError> {
            for b in stub.iter_mut() {
                *b ^= 0x5A;
            }
            let tag = header[0] ^ sec_trailer[0];
            Ok(vec![tag; self.sig_len])
        }
        fn unseal_rpc(
            &mut self,
            _header: &[u8],
            stub: &mut [u8],
            _sec_trailer: &[u8],
            auth_value: &[u8],
        ) -> Result<(), AuthError> {
            if auth_value.len() != self.sig_len {
                return Err(AuthError::Protection("bad len".into()));
            }
            for b in stub.iter_mut() {
                *b ^= 0x5A;
            }
            Ok(())
        }
        fn sign_rpc(
            &mut self,
            header: &[u8],
            _stub: &[u8],
            sec_trailer: &[u8],
        ) -> Result<Vec<u8>, AuthError> {
            let tag = header[0] ^ sec_trailer[0];
            Ok(vec![tag; self.sig_len])
        }
        fn verify_rpc(
            &mut self,
            _header: &[u8],
            _stub: &[u8],
            _sec_trailer: &[u8],
            auth_value: &[u8],
        ) -> Result<(), AuthError> {
            if auth_value.len() != self.sig_len {
                return Err(AuthError::Protection("bad len".into()));
            }
            Ok(())
        }
    }

    #[test]
    fn variable_length_auth_token_and_request_fragmentation() {
        let mut ssp = DummyVariableSsp {
            auth_type: 0x10, // Kerberos
            sig_len: 28,     // RFC 4121 MIC length
        };
        let ipid = [0x22u8; 16];
        let stub = vec![0xABu8; 200];
        // Force fragmentation with a small max_xmit (128 bytes).
        // Header (40) + sec_trailer (8) + auth_value (28) = 76 bytes overhead,
        // leaving 52 -> 48 bytes (multiple of 16) per non-last fragment.
        let pdus = build_request_pdus(
            &mut ssp,
            7,
            0,
            20,
            Some(&ipid),
            &stub,
            AUTH_LEVEL_PKT_INTEGRITY,
            0,
            128,
        )
        .unwrap();
        assert_eq!(pdus.len(), 5); // 48 * 4 + 8 = 200
        assert_eq!(pdus[0][3] & PFC_FIRST_LAST, PFC_FIRST_FRAG);
        assert_eq!(pdus[1][3] & PFC_FIRST_LAST, 0);
        assert_eq!(pdus[4][3] & PFC_FIRST_LAST, PFC_LAST_FRAG);
        for pdu in &pdus {
            assert!(pdu.len() <= 128);
            assert_eq!(u16::from_le_bytes([pdu[10], pdu[11]]), 28);
            let trailer_at = pdu.len() - 28 - 8;
            assert_eq!(pdu[trailer_at], 0x10);
        }
    }
}
