//! DCE/RPC connection-oriented PDUs (C706 ch. 12, MS-RPCE 2.2.2): bind /
//! alter_context / auth3 framing, request and response PDUs protected at the
//! packet-integrity (signed) or packet-privacy (sealed) level, request/response
//! fragmentation, and [`RpcConnection`].

use std::borrow::Cow;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

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
    /// The server refused the whole bind or alter_context with a bind_nak.
    #[error("bind refused: {} (reason {reason})", reject_reason(.reason))]
    BindNak { reason: u16 },
    /// A fault PDU. `did_not_execute` is set when the server says the call
    /// never ran, so it is safe to retry. Windows sets it for faults from the
    /// RPC runtime, such as access denied on a bind, but not for faults a
    /// DCOM call returns, even when the call never ran.
    #[error("RPC fault 0x{status:08x}{}", if *.did_not_execute { " (the call did not run)" } else { "" })]
    Fault { status: u32, did_not_execute: bool },
    #[error("RPC protocol error: {0}")]
    Protocol(String),
    #[error("RPC message protection failed: {0}")]
    Protection(String),
}

/// What a bind_nak's `provider_reject_reason` means (C706 12.6.3.1, MS-RPCE
/// 2.2.2.5).
fn reject_reason(reason: &u16) -> &'static str {
    match reason {
        0 => "reason not specified",
        1 => "temporary congestion",
        2 => "local limit exceeded",
        3 => "called presentation address unknown",
        4 => "protocol version not supported",
        5 => "default context not supported",
        6 => "user data not readable",
        7 => "no PSAP available",
        8 => "authentication type not recognized",
        9 => "invalid checksum",
        _ => "unknown reason",
    }
}

impl From<AuthError> for RpcError {
    fn from(err: AuthError) -> Self {
        match err {
            // Its message already says protection failed; don't say it twice.
            AuthError::Protection(why) => RpcError::Protection(why),
            other => RpcError::Protection(other.to_string()),
        }
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
/// In bind, bind_ack, alter_context and alter_context_resp PDUs: the sender
/// supports header signing (MS-RPCE 2.2.2.3); elsewhere `PFC_PENDING_CANCEL`.
pub const PFC_SUPPORT_HEADER_SIGN: u8 = 0x04;
const PFC_FIRST_LAST: u8 = PFC_FIRST_FRAG | PFC_LAST_FRAG;
/// In a fault PDU: the call never ran (C706 12.6.3.1).
const PFC_DID_NOT_EXECUTE: u8 = 0x20;
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
    write_syntaxes(buf, abstract_syntax);
}

/// Write `abstract_syntax` (version 0.0) and the NDR 2.0 transfer syntax, as a
/// bind offers them and a verification trailer repeats them.
fn write_syntaxes(buf: &mut Vec<u8>, abstract_syntax: &[u8; 16]) {
    buf.extend_from_slice(abstract_syntax);
    buf.write_u16::<LittleEndian>(0).unwrap(); // abstract syntax version major
    buf.write_u16::<LittleEndian>(0).unwrap(); // abstract syntax version minor
    buf.extend_from_slice(&NDR_TRANSFER_SYNTAX);
    buf.write_u32::<LittleEndian>(2).unwrap(); // NDR version 2
}

/// Opens a verification trailer (MS-RPCE 2.2.2.13.1).
const SEC_VT_SIGNATURE: [u8; 8] = [0x8a, 0xe3, 0x13, 0x71, 0x02, 0xf4, 0x36, 0x71];
const SEC_VT_COMMAND_BITMASK_1: u16 = 0x0001;
const SEC_VT_COMMAND_PCONTEXT: u16 = 0x0002;
const SEC_VT_COMMAND_END: u16 = 0x4000;
/// In `SEC_VT_COMMAND_BITMASK_1`: the bind on this connection offered header
/// signing (`PFC_SUPPORT_HEADER_SIGN`).
const CLIENT_SUPPORT_HEADER_SIGNING: u32 = 0x0000_0001;

/// The bytes to append to a request stub of `stub_len` bytes for its
/// verification trailer (MS-RPCE 2.2.2.13): `header_signing` confirms that the
/// bind offered header signing, `abstract_syntax` the presentation context the
/// request uses. Empty when there is neither.
///
/// The request's signature or encryption covers the trailer, so a server can
/// tell when someone on the path removed the header-signing offer from the
/// unprotected bind, or swapped the presentation context.
fn verification_trailer(
    stub_len: usize,
    header_signing: bool,
    abstract_syntax: Option<&[u8; 16]>,
) -> Vec<u8> {
    let mut trailer = Vec::new();
    if !header_signing && abstract_syntax.is_none() {
        return trailer;
    }
    // The trailer starts 4-byte aligned in the PDU. Fragments before the last
    // carry multiples of 16 stub bytes, so aligning it in the stub is enough.
    trailer.resize(stub_len.next_multiple_of(4) - stub_len, 0);
    trailer.extend_from_slice(&SEC_VT_SIGNATURE);
    if header_signing {
        let end = if abstract_syntax.is_none() {
            SEC_VT_COMMAND_END
        } else {
            0
        };
        trailer
            .write_u16::<LittleEndian>(SEC_VT_COMMAND_BITMASK_1 | end)
            .unwrap();
        trailer.write_u16::<LittleEndian>(4).unwrap();
        trailer
            .write_u32::<LittleEndian>(CLIENT_SUPPORT_HEADER_SIGNING)
            .unwrap();
    }
    if let Some(abstract_syntax) = abstract_syntax {
        trailer
            .write_u16::<LittleEndian>(SEC_VT_COMMAND_PCONTEXT | SEC_VT_COMMAND_END)
            .unwrap();
        trailer.write_u16::<LittleEndian>(0x28).unwrap();
        write_syntaxes(&mut trailer, abstract_syntax);
    }
    trailer
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
    /// The server set `PFC_SUPPORT_HEADER_SIGN`.
    pub header_signing: bool,
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
            return Err(RpcError::BindNak {
                reason: u16_at(16).unwrap_or(0),
            })
        }
        PTYPE_FAULT => return Err(fault_error(pdu).ok_or_else(malformed)?),
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
    let header_signing = pdu[3] & PFC_SUPPORT_HEADER_SIGN != 0;
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
            header_signing,
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
        header_signing,
    })
}

/// The status of an RPC fault PDU (C706 12.6.4.7), if `pdu` is one.
pub fn fault_status(pdu: &[u8]) -> Option<u32> {
    (pdu.get(2) == Some(&PTYPE_FAULT))
        .then(|| pdu.get(24..28))
        .flatten()
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

/// The error an RPC fault PDU reports, if `pdu` is one.
fn fault_error(pdu: &[u8]) -> Option<RpcError> {
    Some(RpcError::Fault {
        status: fault_status(pdu)?,
        did_not_execute: pdu[3] & PFC_DID_NOT_EXECUTE != 0,
    })
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
    let auth_value_len = auth.auth_value_len(sealed, padded_stub_len)?;
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
    }?;
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
    let auth_len = auth.auth_value_len(sealed, stub.len() + pad)?;
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
    if let Some(fault) = fault_error(pdu) {
        return Err(fault);
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
    )?;
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
    if let Some(fault) = fault_error(pdu) {
        return Err(fault);
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
    auth.unseal_rpc(head, body, trailer, auth_value)?;
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
    /// The abstract syntax, until a request on this context has carried it in
    /// a verification trailer.
    unconfirmed_syntax: Option<[u8; 16]>,
}

/// Most bytes one response may take on the wire, all its fragments together.
/// A 32-object `Next` batch of large WMI objects is a few hundred KiB, so this
/// only stops a server that never finishes.
pub const MAX_RESPONSE_LEN: usize = 32 << 20;

/// How many I/O timeouts one exchange may take in total. A read may wait one
/// I/O timeout for the server to start answering; the rest is for the answer
/// to arrive. A server that trickles bytes cannot hold a call open longer.
const EXCHANGE_TIMEOUTS: u32 = 4;

/// A stream an [`RpcConnection`] runs over. Besides reading and writing, the
/// connection shortens the read timeout as an exchange nears its deadline.
pub trait RpcStream: Read + Write {
    /// Make each following read wait at most `timeout`.
    fn set_read_timeout(&mut self, timeout: Duration) -> std::io::Result<()>;
}

impl RpcStream for TcpStream {
    fn set_read_timeout(&mut self, timeout: Duration) -> std::io::Result<()> {
        TcpStream::set_read_timeout(self, Some(timeout))
    }
}

/// What is left to one exchange: a call, or one round trip of a bind.
struct Exchange {
    /// `None` when the I/O timeout is so long that the limit cannot be
    /// represented; the exchange then has no deadline.
    deadline: Option<Instant>,
    /// Bytes the rest of the response may take.
    room: usize,
}

/// A connection-oriented DCE/RPC client association over a stream, owning the
/// socket, presentation-context handshakes, call dispatch, and fragment
/// splitting/reassembly.
///
/// Each exchange, from sending a request to reading the end of its response,
/// must finish within four I/O timeouts, and the response may take at most
/// [`MAX_RESPONSE_LEN`] bytes. Breaking either limit fails the exchange with
/// the rest of the response unread, so the connection is unusable afterwards.
pub struct RpcConnection<S = TcpStream> {
    stream: S,
    call_id: u32,
    next_context_id: u16,
    max_xmit: u16,
    /// Header signing agreed for this connection (MS-RPCE 3.3.1.5.2.2); `None`
    /// until the first authenticated bind or alter_context settles it.
    header_signing: Option<bool>,
    /// A request has gone out, so the verification trailer that confirms the
    /// header-signing offer has too, if there was an offer.
    sent_request: bool,
    /// How long one read or write may block.
    io_timeout: Duration,
    /// The read timeout last set on the stream; `None` until one is set.
    read_timeout: Option<Duration>,
    max_response_len: usize,
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

    /// Change the read/write timeout on the underlying TCP stream. An exchange
    /// may take four times this in total.
    pub fn set_timeout(&mut self, timeout: Duration) -> Result<(), RpcError> {
        // A zero Duration means "no timeout" to the socket API; never allow it.
        let timeout = timeout.max(Duration::from_millis(1));
        self.stream.set_read_timeout(Some(timeout))?;
        self.stream.set_write_timeout(Some(timeout))?;
        self.io_timeout = timeout;
        self.read_timeout = Some(timeout);
        Ok(())
    }
}

impl<S: RpcStream> RpcConnection<S> {
    /// Wrap an existing stream (e.g. a `TcpStream` or an in-memory test pipe).
    /// The connection sets its read timeout from here on, assuming an I/O
    /// timeout of [`RPC_IO_TIMEOUT`].
    pub fn from_stream(stream: S) -> Self {
        Self {
            stream,
            call_id: 0,
            next_context_id: 0,
            max_xmit: MAX_FRAG,
            header_signing: None,
            sent_request: false,
            io_timeout: RPC_IO_TIMEOUT,
            read_timeout: None,
            max_response_len: MAX_RESPONSE_LEN,
        }
    }

    pub fn max_xmit(&self) -> u16 {
        self.max_xmit
    }

    fn next_call_id(&mut self) -> u32 {
        self.call_id += 1;
        self.call_id
    }

    /// Start an exchange: its deadline and how much response it may read.
    fn exchange(&self) -> Exchange {
        Exchange {
            deadline: self
                .io_timeout
                .checked_mul(EXCHANGE_TIMEOUTS)
                .and_then(|limit| Instant::now().checked_add(limit)),
            room: self.max_response_len,
        }
    }

    fn overdue(&self) -> RpcError {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "the server did not finish answering within {:?}",
                self.io_timeout.saturating_mul(EXCHANGE_TIMEOUTS)
            ),
        )
        .into()
    }

    /// Fill `buf` from the stream by `deadline`. Each read waits at most the
    /// I/O timeout, and less once the deadline is closer than that.
    fn read_by(&mut self, deadline: Option<Instant>, buf: &mut [u8]) -> Result<(), RpcError> {
        let mut filled = 0;
        while filled < buf.len() {
            let wait = match deadline {
                Some(deadline) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(self.overdue());
                    }
                    left.min(self.io_timeout)
                }
                None => self.io_timeout,
            };
            if self.read_timeout != Some(wait) {
                self.stream.set_read_timeout(wait)?;
                self.read_timeout = Some(wait);
            }
            match self.stream.read(&mut buf[filled..]) {
                Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into()),
                Ok(n) => filled += n,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                // A read shortened to end at the deadline ran out.
                Err(err)
                    if wait < self.io_timeout
                        && matches!(
                            err.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                {
                    return Err(self.overdue());
                }
                Err(err) => return Err(err.into()),
            }
        }
        Ok(())
    }

    /// Read one PDU (fragment) within what is left to `exchange`.
    fn read_fragment(&mut self, exchange: &mut Exchange) -> Result<Vec<u8>, RpcError> {
        let mut header = [0u8; 16];
        self.read_by(exchange.deadline, &mut header)?;
        let frag_len = usize::from(u16::from_le_bytes([header[8], header[9]]));
        if frag_len < 16 {
            return Err(RpcError::Protocol(format!(
                "invalid fragment length {frag_len}"
            )));
        }
        exchange.room = exchange.room.checked_sub(frag_len).ok_or_else(|| {
            RpcError::Protocol(format!(
                "response longer than {} bytes",
                self.max_response_len
            ))
        })?;
        let mut pdu = vec![0u8; frag_len];
        pdu[..16].copy_from_slice(&header);
        self.read_by(exchange.deadline, &mut pdu[16..])?;
        Ok(pdu)
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

        // MS-RPCE 3.3.1.5.2.2: the first authenticated bind or alter_context at
        // integrity or higher offers header signing, and the reply settles it
        // for the connection.
        let offer_header_signing =
            self.header_signing.is_none() && auth_level >= AUTH_LEVEL_PKT_INTEGRITY;
        let negotiate = auth.negotiate()?;
        let mut pdu = build_bind_pdu_with_auth_type(
            ptype,
            call_id,
            context_id,
            abstract_syntax,
            auth_type,
            auth_level,
            auth_context_id,
            &negotiate,
        );
        if offer_header_signing {
            pdu[3] |= PFC_SUPPORT_HEADER_SIGN;
        }
        let mut exchange = self.exchange();
        self.stream.write_all(&pdu)?;
        let ack = parse_bind_ack(&self.read_fragment(&mut exchange)?, ack_ptype)?;
        if ack.auth_type != 0 && ack.auth_type != auth_type {
            return Err(RpcError::Protocol(format!(
                "server answered with auth type {}, expected {}",
                ack.auth_type, auth_type
            )));
        }
        if context_id == 0 {
            self.max_xmit = ack.max_xmit.min(MAX_FRAG);
        }
        if offer_header_signing {
            self.header_signing = Some(ack.header_signing);
            debug!(
                header_signing = ack.header_signing,
                "header signing negotiated"
            );
        }
        auth.set_header_signing(self.header_signing.unwrap_or(false));

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
                        let mut exchange = self.exchange();
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
                        parse_bind_ack(
                            &self.read_fragment(&mut exchange)?,
                            PTYPE_ALTER_CONTEXT_RESP,
                        )?;
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
            unconfirmed_syntax: Some(*abstract_syntax),
        })
    }

    /// Issue one RPC/ORPC call on `ctx` (splitting the request across fragments
    /// if `stub` exceeds `max_xmit`) and return the reassembled, verified/decrypted
    /// response stub.
    ///
    /// As Windows does, the first request on the connection confirms the
    /// header-signing offer in a verification trailer, and the first request on
    /// each presentation context confirms its abstract and transfer syntax.
    pub fn call(
        &mut self,
        ctx: &mut BoundContext,
        opnum: u16,
        object_ipid: Option<&[u8; 16]>,
        stub: &[u8],
    ) -> Result<Vec<u8>, RpcError> {
        let call_id = self.next_call_id();
        let trailer = verification_trailer(
            stub.len(),
            !self.sent_request && self.header_signing.is_some(),
            ctx.unconfirmed_syntax.as_ref(),
        );
        let stub: Cow<[u8]> = if trailer.is_empty() {
            stub.into()
        } else {
            [stub, &trailer].concat().into()
        };
        let pdus = build_request_pdus(
            &mut *ctx.auth,
            call_id,
            ctx.context_id,
            opnum,
            object_ipid,
            &stub,
            ctx.auth_level,
            ctx.auth_context_id,
            self.max_xmit,
        )?;
        let mut exchange = self.exchange();
        for pdu in &pdus {
            self.stream.write_all(pdu)?;
        }
        self.sent_request = true;
        ctx.unconfirmed_syntax = None;

        let mut response = Vec::new();
        let mut first = true;
        loop {
            let frag = self.read_fragment(&mut exchange)?;
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
            // Only the first fragment of a response is marked first. (A fault
            // ends the call wherever it arrives.)
            if frag[2] == PTYPE_RESPONSE && (frag[3] & PFC_FIRST_FRAG != 0) != first {
                return Err(RpcError::Protocol(if first {
                    "response does not start with a first fragment".into()
                } else {
                    "a later response fragment is marked first".into()
                }));
            }
            first = false;
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

    #[test]
    fn protection_errors_are_prefixed_once() {
        let err = RpcError::from(AuthError::Protection("bad signature".into()));
        assert_eq!(
            err.to_string(),
            "RPC message protection failed: bad signature"
        );
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
    /// Fault Windows sends for a DCOM call to an opnum the interface does not
    /// have (HRESULT_FROM_WIN32(RPC_S_PROCNUM_OUT_OF_RANGE)), without the flag
    /// that the call never ran.
    const REF_PROCNUM_FAULT: [u8; 32] =
        hex_literal::hex!("050003031000000020000000060000002000000002000000d106078000000000");
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
        let err = parse_bind_ack(&REF_ACCESS_DENIED_FAULT, PTYPE_ALTER_CONTEXT_RESP).unwrap_err();
        assert!(matches!(
            err,
            RpcError::Fault {
                status: 5,
                did_not_execute: true
            }
        ));
        assert_eq!(
            err.to_string(),
            "RPC fault 0x00000005 (the call did not run)"
        );
        assert_eq!(fault_status(&REF_ACCESS_DENIED_FAULT), Some(5));
        assert_eq!(fault_status(&REF_ALTER_RESP_NO_AUTH), None);
    }

    #[test]
    fn responses_report_faults_and_whether_the_call_ran() {
        let err = verify_signed_response_pdu(&mut signing_ssp(), &REF_PROCNUM_FAULT).unwrap_err();
        assert!(matches!(
            err,
            RpcError::Fault {
                status: 0x8007_06d1,
                did_not_execute: false
            }
        ));
        assert_eq!(err.to_string(), "RPC fault 0x800706d1");
        let mut not_run = REF_PROCNUM_FAULT;
        not_run[3] |= PFC_DID_NOT_EXECUTE;
        assert!(matches!(
            unseal_response_pdu(&mut signing_ssp(), &not_run),
            Err(RpcError::Fault {
                status: 0x8007_06d1,
                did_not_execute: true
            })
        ));
    }

    #[test]
    fn parse_bind_ack_reports_bind_nak_reason() {
        // Windows' bind_nak (C706 12.6.4.5) for a bind with an auth type it
        // does not know: provider_reject_reason, then the one protocol
        // version it supports (5.0).
        let nak = hex_literal::hex!("05000d031000000018000000010000000800010500000000");
        let err = parse_bind_ack(&nak, PTYPE_BIND_ACK).unwrap_err();
        assert!(matches!(err, RpcError::BindNak { reason: 8 }));
        assert_eq!(
            err.to_string(),
            "bind refused: authentication type not recognized (reason 8)"
        );
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
    fn read_fragment_reads_exactly_one_fragment() {
        let mut conn = replying(&[
            REF_ALTER_RESP_NO_AUTH.to_vec(),
            REF_ACCESS_DENIED_FAULT.to_vec(),
        ]);
        let mut exchange = conn.exchange();
        assert_eq!(
            conn.read_fragment(&mut exchange).unwrap(),
            REF_ALTER_RESP_NO_AUTH
        );
        assert_eq!(
            conn.read_fragment(&mut exchange).unwrap(),
            REF_ACCESS_DENIED_FAULT
        );
        assert!(conn.read_fragment(&mut exchange).is_err());
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

    #[test]
    fn parse_bind_ack_reports_header_signing() {
        let mut ack = ack_with_token(&REF_BIND_ACK, b"token");
        assert!(!parse_bind_ack(&ack, PTYPE_BIND_ACK).unwrap().header_signing);
        ack[3] |= PFC_SUPPORT_HEADER_SIGN;
        assert!(parse_bind_ack(&ack, PTYPE_BIND_ACK).unwrap().header_signing);
    }

    /// Canned server replies in, client PDUs out.
    struct Duplex {
        replies: std::io::Cursor<Vec<u8>>,
        sent: Vec<u8>,
    }

    impl Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.replies.read(buf)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.sent.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl RpcStream for Duplex {
        fn set_read_timeout(&mut self, _timeout: Duration) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn replying(fragments: &[Vec<u8>]) -> RpcConnection<Duplex> {
        RpcConnection::from_stream(Duplex {
            replies: std::io::Cursor::new(fragments.concat()),
            sent: Vec::new(),
        })
    }

    fn signing_ssp() -> DummyVariableSsp {
        DummyVariableSsp {
            auth_type: AUTH_TYPE_NTLM,
            sig_len: 16,
        }
    }

    /// A signed response fragment for call 1 with the given `PFC_*` flags.
    fn response_fragment(flags: u8, stub: &[u8]) -> Vec<u8> {
        let mut pdu = build_request_pdus(
            &mut signing_ssp(),
            1,
            0,
            0,
            None,
            stub,
            AUTH_LEVEL_PKT_INTEGRITY,
            0,
            MAX_FRAG,
        )
        .unwrap()
        .remove(0);
        pdu[2] = PTYPE_RESPONSE;
        pdu[3] = flags;
        pdu
    }

    /// Make the first call on `conn`, signed.
    fn signed_call<S: RpcStream>(conn: &mut RpcConnection<S>) -> Result<Vec<u8>, RpcError> {
        let mut ctx = BoundContext {
            name: "test",
            context_id: 0,
            auth_context_id: 0,
            auth_level: AUTH_LEVEL_PKT_INTEGRITY,
            auth: Box::new(signing_ssp()),
            unconfirmed_syntax: None,
        };
        conn.call(&mut ctx, 0, None, &[0; 8])
    }

    /// A single-fragment signed response to call `call_id`.
    fn response_to(call_id: u32, stub: &[u8]) -> Vec<u8> {
        let mut pdu = response_fragment(PFC_FIRST_FRAG | PFC_LAST_FRAG, stub);
        pdu[12..16].copy_from_slice(&call_id.to_le_bytes());
        pdu
    }

    /// The body of each request PDU in `sent`: its stub data and verification
    /// trailer, without the auth padding.
    fn request_bodies(mut sent: &[u8]) -> Vec<&[u8]> {
        let mut bodies = Vec::new();
        while !sent.is_empty() {
            let frag_len = usize::from(u16::from_le_bytes([sent[8], sent[9]]));
            let auth_len = usize::from(u16::from_le_bytes([sent[10], sent[11]]));
            let (pdu, rest) = sent.split_at(frag_len);
            if pdu[2] == PTYPE_REQUEST {
                let trailer_at = frag_len - auth_len - SEC_TRAILER_LEN;
                let pad = usize::from(pdu[trailer_at + 2]);
                bodies.push(&pdu[REQUEST_HEADER_LEN..trailer_at - pad]);
            }
            sent = rest;
        }
        bodies
    }

    #[test]
    fn requests_confirm_their_binds_in_a_verification_trailer() {
        let mut bind_ack = ack_with_token(&REF_BIND_ACK, b"challenge");
        bind_ack[3] |= PFC_SUPPORT_HEADER_SIGN;
        let alter_resp = ack_with_token(&REF_ALTER_RESP, b"challenge");
        let mut conn = replying(&[
            bind_ack,
            alter_resp,
            response_to(3, &[1; 4]),
            response_to(4, &[1; 4]),
            response_to(5, &[1; 4]),
        ]);
        let mut bind = |name, syntax| {
            conn.bind_context(
                name,
                syntax,
                AUTH_LEVEL_PKT_INTEGRITY,
                HandshakeStyle::Auth3,
                Box::new(signing_ssp()),
            )
            .unwrap()
        };
        let mut first = bind("first", &[0x11; 16]);
        let mut second = bind("second", &[0x22; 16]);
        conn.call(&mut first, 0, None, &[0xAB; 5]).unwrap();
        conn.call(&mut first, 0, None, &[0xAB; 5]).unwrap();
        conn.call(&mut second, 0, None, &[0xAB; 5]).unwrap();

        // Bits 0x4000 mark the last command.
        let bitmask = [0x01, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00];
        let pcontext = |syntax| {
            [
                &[0x02, 0x40, 0x28, 0x00][..],
                &[syntax; 16],
                &[0, 0, 0, 0],
                &NDR_TRANSFER_SYNTAX,
                &[2, 0, 0, 0],
            ]
            .concat()
        };
        let aligned_stub = [&[0xAB; 5][..], &[0; 3]].concat();
        let bodies = request_bodies(&conn.stream.sent);
        assert_eq!(
            bodies[0],
            [
                &aligned_stub,
                &SEC_VT_SIGNATURE[..],
                &bitmask,
                &pcontext(0x11)
            ]
            .concat(),
            "the first request confirms the header-signing offer and its context"
        );
        assert_eq!(
            bodies[1], [0xAB; 5],
            "a context's later requests carry none"
        );
        assert_eq!(
            bodies[2],
            [&aligned_stub, &SEC_VT_SIGNATURE[..], &pcontext(0x22)].concat(),
            "the first request on another context confirms only that context"
        );
    }

    #[test]
    fn call_reassembles_fragments_in_order() {
        let mut conn = replying(&[
            response_fragment(PFC_FIRST_FRAG, &[1; 8]),
            response_fragment(0, &[2; 4]),
            response_fragment(PFC_LAST_FRAG, &[3; 4]),
        ]);
        assert_eq!(
            signed_call(&mut conn).unwrap(),
            [&[1; 8][..], &[2; 4], &[3; 4]].concat()
        );
    }

    #[test]
    fn a_timeout_too_long_to_multiply_means_no_deadline() {
        let mut conn = replying(&[response_fragment(PFC_FIRST_FRAG | PFC_LAST_FRAG, &[1; 8])]);
        conn.io_timeout = Duration::MAX;
        assert!(conn.exchange().deadline.is_none());
        assert_eq!(signed_call(&mut conn).unwrap(), [1; 8]);
    }

    #[test]
    fn call_rejects_misplaced_first_fragments() {
        let unmarked_start = vec![response_fragment(PFC_LAST_FRAG, &[1; 4])];
        let marked_twice = vec![
            response_fragment(PFC_FIRST_FRAG, &[1; 4]),
            response_fragment(PFC_FIRST_FRAG | PFC_LAST_FRAG, &[2; 4]),
        ];
        for fragments in [unmarked_start, marked_twice] {
            let err = signed_call(&mut replying(&fragments)).unwrap_err();
            assert!(matches!(err, RpcError::Protocol(_)), "{err}");
        }
    }

    #[test]
    fn call_stops_at_the_response_length_limit() {
        let first = response_fragment(PFC_FIRST_FRAG, &[1; 16]);
        let mut conn = replying(&[first.clone(), response_fragment(PFC_LAST_FRAG, &[2; 16])]);
        conn.max_response_len = first.len() + 10;
        let err = signed_call(&mut conn).unwrap_err();
        assert!(err.to_string().contains("response longer than"), "{err}");
        // The second fragment's header said it would not fit; its body stays unread.
        assert_eq!(conn.stream.replies.position() as usize, first.len() + 16);
    }

    /// Sends one byte per `delay` and times out reads like a socket, keeping
    /// every read timeout it is given.
    struct Trickle {
        bytes: std::collections::VecDeque<u8>,
        delay: Duration,
        timeout: Duration,
        timeouts: Vec<Duration>,
    }

    impl Read for Trickle {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.timeout < self.delay {
                std::thread::sleep(self.timeout);
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            std::thread::sleep(self.delay);
            match (self.bytes.pop_front(), buf.first_mut()) {
                (Some(byte), Some(slot)) => {
                    *slot = byte;
                    Ok(1)
                }
                _ => Ok(0),
            }
        }
    }

    impl Write for Trickle {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl RpcStream for Trickle {
        fn set_read_timeout(&mut self, timeout: Duration) -> std::io::Result<()> {
            self.timeout = timeout;
            self.timeouts.push(timeout);
            Ok(())
        }
    }

    fn trickling(delay: Duration, io_timeout: Duration) -> RpcConnection<Trickle> {
        let mut conn = RpcConnection::from_stream(Trickle {
            bytes: response_fragment(PFC_FIRST_FRAG | PFC_LAST_FRAG, &[1; 64]).into(),
            delay,
            timeout: Duration::MAX,
            timeouts: Vec::new(),
        });
        conn.io_timeout = io_timeout;
        conn
    }

    #[test]
    fn a_trickling_server_cannot_outlast_the_call_deadline() {
        // Each byte arrives well within the I/O timeout, but the 100-odd bytes
        // take longer than four of them.
        let mut conn = trickling(Duration::from_millis(2), Duration::from_millis(10));
        let started = Instant::now();
        let err = signed_call(&mut conn).unwrap_err();
        assert!(
            matches!(&err, RpcError::Io(e) if e.kind() == std::io::ErrorKind::TimedOut),
            "{err}"
        );
        assert!(
            err.to_string().contains("did not finish answering"),
            "{err}"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        // Near the deadline, reads were cut to the time left.
        assert!(*conn.stream.timeouts.last().unwrap() < conn.io_timeout);
    }

    #[test]
    fn a_silent_server_still_fails_at_the_io_timeout() {
        let mut conn = trickling(Duration::from_secs(5), Duration::from_millis(10));
        let started = Instant::now();
        let err = signed_call(&mut conn).unwrap_err();
        assert!(
            matches!(&err, RpcError::Io(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "{err}"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// Records what `set_header_signing` reports; never protects a PDU.
    struct HeaderSignRecorder(std::sync::Arc<std::sync::Mutex<Vec<bool>>>);

    impl AuthProvider for HeaderSignRecorder {
        fn negotiate(&mut self) -> Result<Vec<u8>, AuthError> {
            Ok(vec![1, 2, 3])
        }
        fn respond(&mut self, _challenge: &[u8]) -> Result<Vec<u8>, AuthError> {
            Ok(Vec::new())
        }
        fn set_header_signing(&mut self, negotiated: bool) {
            self.0.lock().unwrap().push(negotiated);
        }
        fn seal_rpc(&mut self, _: &[u8], _: &mut [u8], _: &[u8]) -> Result<Vec<u8>, AuthError> {
            unreachable!()
        }
        fn unseal_rpc(
            &mut self,
            _: &[u8],
            _: &mut [u8],
            _: &[u8],
            _: &[u8],
        ) -> Result<(), AuthError> {
            unreachable!()
        }
        fn sign_rpc(&mut self, _: &[u8], _: &[u8], _: &[u8]) -> Result<Vec<u8>, AuthError> {
            unreachable!()
        }
        fn verify_rpc(&mut self, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<(), AuthError> {
            unreachable!()
        }
    }

    #[test]
    fn first_authenticated_bind_offers_header_signing() {
        let mut bind_ack = ack_with_token(&REF_BIND_ACK, b"challenge");
        bind_ack[3] |= PFC_SUPPORT_HEADER_SIGN;
        let alter_resp = ack_with_token(&REF_ALTER_RESP, b"challenge");
        let mut conn = RpcConnection::from_stream(Duplex {
            replies: std::io::Cursor::new([bind_ack, alter_resp].concat()),
            sent: Vec::new(),
        });
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        for name in ["first", "second"] {
            conn.bind_context(
                name,
                &[0x11; 16],
                AUTH_LEVEL_PKT_INTEGRITY,
                HandshakeStyle::Auth3,
                Box::new(HeaderSignRecorder(seen.clone())),
            )
            .unwrap();
        }

        let sent = &conn.stream.sent;
        let bind_len = u16::from_le_bytes([sent[8], sent[9]]) as usize;
        assert_eq!(sent[2], PTYPE_BIND);
        assert_ne!(
            sent[3] & PFC_SUPPORT_HEADER_SIGN,
            0,
            "the first bind offers it"
        );
        assert_eq!(sent[bind_len + 2], PTYPE_ALTER_CONTEXT);
        assert_eq!(
            sent[bind_len + 3] & PFC_SUPPORT_HEADER_SIGN,
            0,
            "later ones do not"
        );
        // The server's answer applies to every context on the connection.
        assert_eq!(*seen.lock().unwrap(), [true, true]);
    }

    /// Everything here parses PDUs a server sent: whatever the bytes, the
    /// parsers must return (Ok or Err), never panic or abort.
    mod properties {
        use super::*;
        use fabi_testkit::{bytes, config, mutated, mutated_any};
        use proptest::prelude::*;

        const REPLIES: &[&[u8]] = &[
            &REF_BIND_ACK,
            &REF_ALTER_RESP,
            &REF_ALTER_RESP_NO_AUTH,
            &REF_ACCESS_DENIED_FAULT,
        ];

        /// A single-fragment authenticated response at `auth_level`, built the
        /// way requests are (no object UUID, so the header matches a response's).
        fn authenticated_response(auth_level: u8) -> Vec<u8> {
            let mut ssp = DummyVariableSsp {
                auth_type: 0x10,
                sig_len: 28,
            };
            let mut pdus =
                build_request_pdus(&mut ssp, 1, 0, 0, None, &[0xAB; 40], auth_level, 0, 4096)
                    .unwrap();
            let mut pdu = pdus.remove(0);
            pdu[2] = PTYPE_RESPONSE;
            pdu
        }

        fn ssp() -> DummyVariableSsp {
            DummyVariableSsp {
                auth_type: 0x10,
                sig_len: 28,
            }
        }

        /// The seeds must be valid, so mutations start from PDUs the
        /// verifiers accept.
        #[test]
        fn authenticated_response_seeds_verify() {
            let signed = authenticated_response(AUTH_LEVEL_PKT_INTEGRITY);
            assert!(verify_signed_response_pdu(&mut ssp(), &signed).is_ok());
            let sealed = authenticated_response(AUTH_LEVEL_PKT_PRIVACY);
            assert_eq!(
                unseal_response_stub(&mut ssp(), &sealed).unwrap(),
                [0xAB; 40]
            );
        }

        proptest! {
            #![proptest_config(config())]

            #[test]
            fn bind_replies_never_panic(
                pdu in prop_oneof![bytes(256), mutated_any(REPLIES)],
                ptype in prop_oneof![Just(PTYPE_BIND_ACK), Just(PTYPE_ALTER_CONTEXT_RESP)],
            ) {
                let _ = parse_bind_ack(&pdu, ptype);
                let _ = fault_status(&pdu);
                let _ = is_last_fragment(&pdu);
            }

            #[test]
            fn fragment_reads_never_panic(
                stream in prop_oneof![bytes(256), mutated_any(REPLIES)],
            ) {
                let mut conn = replying(&[stream]);
                let mut exchange = conn.exchange();
                while conn.read_fragment(&mut exchange).is_ok() {}
            }

            #[test]
            fn signed_responses_never_panic(
                pdu in prop_oneof![
                    bytes(256),
                    mutated(authenticated_response(AUTH_LEVEL_PKT_INTEGRITY)),
                ],
            ) {
                let _ = verify_signed_response_pdu(&mut ssp(), &pdu);
            }

            #[test]
            fn sealed_responses_never_panic(
                pdu in prop_oneof![
                    bytes(256),
                    mutated(authenticated_response(AUTH_LEVEL_PKT_PRIVACY)),
                ],
            ) {
                let _ = unseal_response_stub(&mut ssp(), &pdu);
            }

            #[test]
            fn calls_never_panic(
                replies in prop_oneof![
                    bytes(512),
                    mutated(response_fragment(PFC_FIRST_FRAG | PFC_LAST_FRAG, &[0xAB; 40])),
                    mutated(
                        [
                            response_fragment(PFC_FIRST_FRAG, &[1; 16]),
                            response_fragment(PFC_LAST_FRAG, &[2; 16]),
                        ]
                        .concat()
                    ),
                ],
            ) {
                let mut conn = RpcConnection::from_stream(Duplex {
                    replies: std::io::Cursor::new(replies),
                    sent: Vec::new(),
                });
                conn.max_response_len = 256;
                let _ = signed_call(&mut conn);
            }
        }
    }
}
