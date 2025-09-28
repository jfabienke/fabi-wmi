//! Kerberos integration using kerbsec crate
//!
//! This module provides the integration between linux-wmi's transport
//! and the kerbsec crate for Kerberos authentication.

/// SPNEGO wrapping module (public for use in transport.rs)
pub mod spnego {
    use std::error::Error;

    const OID_SPNEGO: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
    const OID_NTLM: &[u8] = &[
        0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
    ];
    const OID_KERBEROS: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
    ];

    /// Wrap a token in SPNEGO NegTokenInit
    pub fn wrap_in_spnego_init(token: &[u8], is_ntlm: bool) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut out = Vec::new();
        fn write_tlv(buf: &mut Vec<u8>, tag: u8, build: impl FnOnce(&mut Vec<u8>)) {
            buf.push(tag);
            let mut inner = Vec::new();
            build(&mut inner);
            encode_length(buf, inner.len());
            buf.extend_from_slice(&inner);
        }

        write_tlv(&mut out, 0x60, |buf| {
            buf.extend_from_slice(OID_SPNEGO);
            write_tlv(buf, 0xa0, |buf| {
                write_tlv(buf, 0x30, |buf| {
                    write_tlv(buf, 0xa0, |buf| {
                        let mech_types = if is_ntlm {
                            vec![OID_NTLM, OID_KERBEROS]
                        } else {
                            vec![OID_KERBEROS, OID_NTLM]
                        };
                        for oid in mech_types {
                            buf.extend_from_slice(oid);
                        }
                    });

                    if !token.is_empty() {
                        write_tlv(buf, 0xa2, |buf| {
                            buf.push(0x04);
                            encode_length(buf, token.len());
                            buf.extend_from_slice(token);
                        });
                    }
                });
            });
        });

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
    use crate::kerberos_integration::spnego::wrap_in_spnego_init;

    #[test]
    fn wrap_in_spnego_init_with_large_token() {
        let large_token = vec![0xAA; 300];
        let encoded = wrap_in_spnego_init(&large_token, false).expect("encode spnego");
        assert!(encoded.len() > 320);
        assert_eq!(encoded[0], 0x60);
        assert!(encoded.contains(&0x04));
    }

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
        let krb_oid = &[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
        ];
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
}
