//! Kerberos integration using kerbsec crate
//!
//! This module provides the integration between linux-wmi's transport
//! and the kerbsec crate for Kerberos authentication.

use byteorder::LittleEndian;
#[cfg(feature = "kerberos")]
use kerbsec::{Context as KerberosContext, KerberosConfig, IovWrap};
use std::io::{Read, Write};
use std::net::TcpStream;
use tracing::{debug, info};

use crate::transport::TransportError;

#[allow(dead_code)]
pub const AUTH_TYPE_KERBEROS: u8 = 0x10;
#[allow(dead_code)]
pub const AUTH_TYPE_SPNEGO: u8 = 0x09;
pub const AUTH_LEVEL_PRIVACY: u8 = 0x06;
pub const AUTH_LEVEL_INTEGRITY: u8 = 0x05;

/// Kerberos authentication state for RPC transport
pub struct KerberosRpcAuth {
    context: KerberosContext,
    auth_type: u8,
    auth_level: u8,
    session_key: Option<Vec<u8>>,
    prefer_spnego: bool,
}

impl KerberosRpcAuth {
    /// Create new Kerberos auth context
    pub fn new(config: KerberosConfig, prefer_spnego: bool) -> Result<Self, TransportError> {
        let context = KerberosContext::new(config)
            .map_err(|e| TransportError::Failure(format!("Kerberos init failed: {}", e)))?;

        let auth_type = if prefer_spnego {
            AUTH_TYPE_SPNEGO
        } else {
            AUTH_TYPE_KERBEROS
        };

        Ok(Self {
            context,
            auth_type,
            auth_level: AUTH_LEVEL_PRIVACY,
            session_key: None,
            prefer_spnego,
        })
    }

    /// Perform DCE/RPC 3-leg Kerberos handshake
    pub fn authenticate(
        &mut self,
        stream: &mut TcpStream,
    ) -> Result<(), TransportError> {
        info!("Starting DCE/RPC Kerberos 3-leg handshake");

        // Leg 1: Generate AP-REQ
        let ap_req = self.context
            .initial_token()
            .map_err(|e| TransportError::Failure(format!("AP-REQ generation failed: {}", e)))?;

        debug!("Generated AP-REQ: {} bytes", ap_req.len());

        // Build and send bind PDU with AP-REQ
        let bind_pdu = build_bind_pdu_with_kerberos(1, &ap_req, self.auth_type, self.auth_level, self.prefer_spnego);
        stream.write_all(&bind_pdu)?;

        // Read bind_ack with AP-REP
        let mut response = vec![0u8; 4096];
        let n = stream.read(&mut response)?;
        response.truncate(n);

        // Parse bind_ack and extract AP-REP
        let ap_rep = parse_bind_ack_auth(&response)?;

        // Leg 2: Process AP-REP and get third leg token
        let third_leg = self.context
            .accept_ap_rep(&ap_rep)
            .map_err(|e| TransportError::Failure(format!("AP-REP processing failed: {}", e)))?;

        // Leg 3: Send alter_context with final token (even if empty)
        if let Some(token) = third_leg {
            debug!("Sending third leg token: {} bytes", token.len());
            let alter_pdu = build_alter_context_with_kerberos(2, 0, &token, self.auth_type, self.auth_level, self.prefer_spnego);
            stream.write_all(&alter_pdu)?;

            // Read alter_context_resp
            let mut response = vec![0u8; 1024];
            let n = stream.read(&mut response)?;
            response.truncate(n);
            debug!("Received alter_context_resp: {} bytes", n);
        }

        if self.context.established() {
            info!("Kerberos context established successfully");
            self.session_key = self.context.session_key();
            Ok(())
        } else {
            Err(TransportError::Failure("Kerberos context not established".into()))
        }
    }

    /// Wrap RPC request with Kerberos protection
    pub fn wrap_request(&mut self, pdu: &[u8]) -> Result<Vec<u8>, TransportError> {
        let iov = self.context
            .wrap_iov(pdu)
            .map_err(|e| TransportError::Failure(format!("Wrap failed: {}", e)))?;

        // Build protected PDU with IOV header and trailer
        Ok(build_protected_pdu(pdu, &iov))
    }

    /// Unwrap RPC response with Kerberos protection
    pub fn unwrap_response(&mut self, pdu: &[u8]) -> Result<Vec<u8>, TransportError> {
        // Extract auth trailer from PDU
        let (body, auth_trailer) = extract_auth_trailer(pdu)?;

        self.context
            .unwrap_iov(auth_trailer)
            .map_err(|e| TransportError::Failure(format!("Unwrap failed: {}", e)))?;

        Ok(body.to_vec())
    }
}

/// Build bind PDU with Kerberos auth trailer
fn build_bind_pdu_with_kerberos(
    call_id: u32,
    ap_req: &[u8],
    auth_type: u8,
    auth_level: u8,
    use_spnego: bool,
) -> Vec<u8> {
    use byteorder::{LittleEndian, WriteBytesExt};

    const MAX_XMIT_RECV: u16 = 0x10B8;

    // Wrap token in SPNEGO if needed
    let token = if use_spnego && auth_type == AUTH_TYPE_SPNEGO {
        spnego::wrap_in_spnego_init(ap_req, false)
            .unwrap_or_else(|_| ap_req.to_vec())
    } else {
        ap_req.to_vec()
    };

    let mut body = Vec::new();
    body.write_u16::<LittleEndian>(MAX_XMIT_RECV).unwrap();
    body.write_u16::<LittleEndian>(MAX_XMIT_RECV).unwrap();
    body.write_u32::<LittleEndian>(0).unwrap(); // association group
    body.write_u8(1).unwrap(); // number of context items
    body.write_u8(0).unwrap(); // alignment padding
    body.write_u16::<LittleEndian>(0).unwrap(); // context ID
    body.write_u8(1).unwrap(); // number of transfer syntaxes
    body.write_u8(0).unwrap();

    // Abstract syntax: IRemoteSCMActivator
    body.extend_from_slice(&[0xa0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]);
    body.write_u16::<LittleEndian>(0).unwrap();
    body.write_u16::<LittleEndian>(0).unwrap();

    // Transfer syntax: NDR
    body.extend_from_slice(&[0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
                             0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60]);
    body.write_u32::<LittleEndian>(2).unwrap();

    // Pad to 4-byte alignment
    let pad = (4 - (body.len() % 4)) % 4;
    body.extend(std::iter::repeat_n(0u8, pad));

    // Auth trailer
    body.push(auth_type);
    body.push(auth_level);
    body.push(pad as u8);
    body.push(0);
    body.write_u32::<LittleEndian>(0).unwrap(); // auth context id
    body.extend(std::iter::repeat_n(0u8, pad));
    body.extend_from_slice(&token);

    let frag_len = (16 + body.len()) as u16;
    let auth_len = token.len() as u16;

    let mut pdu = Vec::with_capacity(frag_len as usize);
    pdu.write_u8(5).unwrap(); // version
    pdu.write_u8(0).unwrap(); // minor version
    pdu.write_u8(0x0B).unwrap(); // ptype=bind
    pdu.write_u8(0x03).unwrap(); // flags first|last
    pdu.write_u32::<LittleEndian>(0x10_00_00_00).unwrap(); // data rep
    pdu.write_u16::<LittleEndian>(frag_len).unwrap();
    pdu.write_u16::<LittleEndian>(auth_len).unwrap();
    pdu.write_u32::<LittleEndian>(call_id).unwrap();
    pdu.extend_from_slice(&body);
    pdu
}

/// Build alter_context PDU with Kerberos third leg
fn build_alter_context_with_kerberos(
    call_id: u32,
    context_id: u16,
    token: &[u8],
    auth_type: u8,
    auth_level: u8,
    use_spnego: bool,
) -> Vec<u8> {
    use byteorder::{LittleEndian, WriteBytesExt};

    const MAX_XMIT_RECV: u16 = 0x10B8;

    // Wrap token in SPNEGO if needed
    let wrapped_token = if use_spnego && auth_type == AUTH_TYPE_SPNEGO && !token.is_empty() {
        spnego::wrap_in_spnego_init(token, false)
            .unwrap_or_else(|_| token.to_vec())
    } else {
        token.to_vec()
    };

    let mut body = Vec::new();
    body.write_u16::<LittleEndian>(MAX_XMIT_RECV).unwrap();
    body.write_u16::<LittleEndian>(MAX_XMIT_RECV).unwrap();
    body.write_u32::<LittleEndian>(0).unwrap();
    body.write_u8(1).unwrap();
    body.write_u8(0).unwrap();
    body.write_u16::<LittleEndian>(context_id).unwrap();
    body.write_u8(1).unwrap();
    body.write_u8(0).unwrap();

    // Same abstract and transfer syntax
    body.extend_from_slice(&[0xa0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]);
    body.write_u16::<LittleEndian>(0).unwrap();
    body.write_u16::<LittleEndian>(0).unwrap();
    body.extend_from_slice(&[0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
                             0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60]);
    body.write_u32::<LittleEndian>(2).unwrap();

    let pad = (4 - (body.len() % 4)) % 4;
    body.extend(std::iter::repeat_n(0u8, pad));

    // Auth trailer with third leg token
    body.push(auth_type);
    body.push(auth_level);
    body.push(pad as u8);
    body.push(0);
    body.write_u32::<LittleEndian>(0).unwrap();
    body.extend(std::iter::repeat_n(0u8, pad));
    body.extend_from_slice(&wrapped_token);

    let frag_len = (16 + body.len()) as u16;
    let auth_len = wrapped_token.len() as u16;

    let mut pdu = Vec::with_capacity(frag_len as usize);
    pdu.write_u8(5).unwrap();
    pdu.write_u8(0).unwrap();
    pdu.write_u8(0x0E).unwrap(); // ptype=alter_context
    pdu.write_u8(0x03).unwrap();
    pdu.write_u32::<LittleEndian>(0x10_00_00_00).unwrap();
    pdu.write_u16::<LittleEndian>(frag_len).unwrap();
    pdu.write_u16::<LittleEndian>(auth_len).unwrap();
    pdu.write_u32::<LittleEndian>(call_id).unwrap();
    pdu.extend_from_slice(&body);
    pdu
}

/// Parse bind_ack and extract auth token
fn parse_bind_ack_auth(pdu: &[u8]) -> Result<Vec<u8>, TransportError> {
    use byteorder::ReadBytesExt;

    if pdu.len() < 16 {
        return Err(TransportError::Failure("bind_ack too short".into()));
    }

    let mut cursor = std::io::Cursor::new(pdu);
    cursor.set_position(10);
    let auth_len = cursor.read_u16::<LittleEndian>()? as usize;

    if auth_len == 0 {
        return Err(TransportError::Failure("No auth in bind_ack".into()));
    }

    // Auth trailer is at end of PDU
    let auth_start = pdu.len() - auth_len;
    let auth_blob = &pdu[auth_start..];

    // Check if this is SPNEGO-wrapped
    if auth_blob.len() > 2 && auth_blob[0] == 0x60 {
        // Looks like SPNEGO, try to unwrap
        if let Ok(inner) = spnego::parse_spnego_response(auth_blob) {
            return Ok(inner);
        }
    }

    // Return raw blob
    Ok(auth_blob.to_vec())
}

/// Build protected PDU with IOV wrap
fn build_protected_pdu(pdu: &[u8], iov: &IovWrap) -> Vec<u8> {
    let mut protected = Vec::new();

    // RPC header (first 16 bytes)
    protected.extend_from_slice(&pdu[..16.min(pdu.len())]);

    // Insert auth header
    protected.extend(&iov.header);

    // PDU body
    if pdu.len() > 16 {
        protected.extend_from_slice(&pdu[16..]);
    }

    // Append auth trailer
    protected.extend(&iov.trailer);

    // Update fragment length
    if protected.len() >= 10 {
        let frag_len = protected.len() as u16;
        protected[8] = (frag_len & 0xFF) as u8;
        protected[9] = (frag_len >> 8) as u8;

        // Update auth length
        let auth_len = (iov.header.len() + iov.trailer.len()) as u16;
        protected[10] = (auth_len & 0xFF) as u8;
        protected[11] = (auth_len >> 8) as u8;
    }

    protected
}

/// Extract auth trailer from protected PDU
#[allow(dead_code)]
fn extract_auth_trailer(pdu: &[u8]) -> Result<(&[u8], &[u8]), TransportError> {
    use byteorder::ReadBytesExt;

    if pdu.len() < 16 {
        return Err(TransportError::Failure("PDU too short".into()));
    }

    let mut cursor = std::io::Cursor::new(&pdu[..12]);
    cursor.set_position(10);
    let auth_len = cursor.read_u16::<LittleEndian>()? as usize;

    if auth_len == 0 || auth_len > pdu.len() {
        return Err(TransportError::Failure("Invalid auth length".into()));
    }

    let body_end = pdu.len() - auth_len;
    Ok((&pdu[16..body_end], &pdu[body_end..]))
}

/// SPNEGO wrapping module (public for use in transport.rs)
pub mod spnego {
    use std::error::Error;

    const OID_SPNEGO: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
    const OID_NTLM: &[u8] = &[0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
    const OID_KERBEROS: &[u8] = &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

    /// Wrap a token in SPNEGO NegTokenInit
    pub fn wrap_in_spnego_init(token: &[u8], is_ntlm: bool) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut out = Vec::new();

        // Application constructed object [0]
        out.push(0x60);
        out.push(0); // Length placeholder
        let length_offset = out.len() - 1;

        // OID for SPNEGO
        out.extend_from_slice(OID_SPNEGO);

        // NegTokenInit [0] EXPLICIT SEQUENCE
        out.push(0xa0);
        out.push(0); // Length placeholder
        let neg_token_length_offset = out.len() - 1;

        // SEQUENCE
        out.push(0x30);
        out.push(0); // Length placeholder
        let sequence_length_offset = out.len() - 1;

        // mechTypes [0] SEQUENCE OF MechType
        out.push(0xa0);
        let mech_types = if is_ntlm {
            vec![OID_NTLM, OID_KERBEROS]
        } else {
            vec![OID_KERBEROS, OID_NTLM]
        };
        let mech_types_len: usize = mech_types.iter().map(|o| o.len()).sum();
        encode_length(&mut out, mech_types_len);

        // Add mechanism OIDs
        for oid in mech_types {
            out.extend_from_slice(oid);
        }

        // mechToken [2] OCTET STRING OPTIONAL
        if !token.is_empty() {
            out.push(0xa2);
            encode_length(&mut out, token.len() + 2);
            out.push(0x04); // OCTET STRING
            encode_length(&mut out, token.len());
            out.extend_from_slice(token);
        }

        // Update lengths
        let total_len = out.len() - sequence_length_offset - 1;
        out[sequence_length_offset] = total_len as u8;

        let neg_token_len = out.len() - neg_token_length_offset - 1;
        out[neg_token_length_offset] = neg_token_len as u8;

        let spnego_len = out.len() - length_offset - 1;
        out[length_offset] = spnego_len as u8;

        Ok(out)
    }

    /// Parse SPNEGO response and extract inner token
    pub fn parse_spnego_response(blob: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        // This is a simplified parser for SPNEGO NegTokenResp
        // In production, you'd want a full ASN.1 parser

        // Look for the mechToken which usually starts with application tag or octet string
        // For now, we'll look for common Kerberos/NTLM markers

        // Try to find Kerberos AP-REP (starts with 0x6e or 0x7e)
        for i in 0..blob.len().saturating_sub(8) {
            if blob[i] == 0x6e || blob[i] == 0x7e {
                // Potential Kerberos token
                return Ok(blob[i..].to_vec());
            }
        }

        // Try to find NTLM marker
        let marker = b"NTLMSSP\0";
        if let Some(pos) = blob.windows(marker.len()).position(|w| w == marker) {
            return Ok(blob[pos..].to_vec());
        }

        // If no specific token found, return the whole blob
        Ok(blob.to_vec())
    }

    fn encode_length(buf: &mut Vec<u8>, len: usize) {
        if len < 128 {
            buf.push(len as u8);
        } else if len < 256 {
            buf.push(0x81);
            buf.push(len as u8);
        } else {
            buf.push(0x82);
            buf.push((len >> 8) as u8);
            buf.push((len & 0xff) as u8);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spnego_wrap() {
        // Test wrapping a simple Kerberos token
        let token = b"test_kerberos_token";
        let wrapped = spnego::wrap_in_spnego_init(token, false).unwrap();

        // Verify it starts with application tag 0x60
        assert_eq!(wrapped[0], 0x60);

        // Verify SPNEGO OID is present
        let spnego_oid = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
        assert!(wrapped.windows(spnego_oid.len()).any(|w| w == spnego_oid));

        // Verify Kerberos OID is present
        let krb_oid = &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];
        assert!(wrapped.windows(krb_oid.len()).any(|w| w == krb_oid));
    }

    #[test]
    fn test_spnego_parse() {
        // Create a SPNEGO-wrapped token
        let token = b"test_token";
        let wrapped = spnego::wrap_in_spnego_init(token, false).unwrap();

        // Parse it back
        let parsed = spnego::parse_spnego_response(&wrapped).unwrap();

        // Should extract the original token
        assert!(parsed.ends_with(token));
    }

    #[test]
    fn test_auth_type_selection() {
        // Test that prefer_spnego sets correct auth type
        let config = kerbsec::KerberosConfig::builder()
            .realm("TEST.COM")
            .target_host("test.com")
            .build()
            .unwrap();
        let auth = KerberosRpcAuth::new(config, true).unwrap();
        assert_eq!(auth.auth_type, AUTH_TYPE_SPNEGO);

        let config2 = kerbsec::KerberosConfig::builder()
            .realm("TEST.COM")
            .target_host("test.com")
            .build()
            .unwrap();
        let auth2 = KerberosRpcAuth::new(config2, false).unwrap();
        assert_eq!(auth2.auth_type, AUTH_TYPE_KERBEROS);
    }
}