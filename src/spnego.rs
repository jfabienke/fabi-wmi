//! Lightweight SPNEGO wrapper exposed regardless of Kerberos support.

#[cfg(feature = "kerberos")]
pub use crate::kerberos_integration::spnego::*;

#[cfg(not(feature = "kerberos"))]
pub use fallback::*;

#[cfg(not(feature = "kerberos"))]
mod fallback {
    use std::error::Error;

    pub fn wrap_in_spnego_init(_token: &[u8], _is_ntlm: bool) -> Result<Vec<u8>, Box<dyn Error>> {
        Err("SPNEGO support requires the `kerberos` feature".into())
    }

    pub fn parse_spnego_response(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(data.to_vec())
    }
}
