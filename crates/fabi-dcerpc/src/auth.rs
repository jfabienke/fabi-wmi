//! Credentials and the authentication-provider seam used by the RPC layer.

use std::fmt;

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// `RPC_C_AUTHN_GSS_NEGOTIATE` (SPNEGO).
pub const AUTH_TYPE_SPNEGO: u8 = 0x09;
/// `RPC_C_AUTHN_WINNT` (NTLMSSP).
pub const AUTH_TYPE_NTLM: u8 = 0x0A;
/// `RPC_C_AUTHN_GSS_KERBEROS` (Kerberos v5).
pub const AUTH_TYPE_KERBEROS: u8 = 0x10;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("username and password are required")]
    Creds,
    #[error("RPC message protection failed: {0}")]
    Protection(String),
}

/// Credentials for a Windows account. `domain` is empty for a local account.
/// The password is wiped from memory when the value is dropped.
#[derive(Clone)]
pub struct Credentials {
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) domain: String,
}

impl Zeroize for Credentials {
    fn zeroize(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
        self.domain.zeroize();
    }
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Credentials {}

impl Credentials {
    /// Credentials for a local account on the target host.
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            domain: String::new(),
        }
    }

    /// Use a domain account (NetBIOS or DNS domain name).
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = domain.into();
        self
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn validate(&self) -> Result<(), AuthError> {
        if self.username.is_empty() || self.password.is_empty() {
            return Err(AuthError::Creds);
        }
        Ok(())
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// A security context that authenticates one RPC association and protects its
/// PDUs (MS-RPCE 2.2.2.11): the handshake tokens, and the per-PDU signature or
/// encryption for the packet-integrity and packet-privacy levels.
pub trait AuthProvider: Send {
    /// Wire `auth_type` byte for `sec_trailer` (e.g. [`AUTH_TYPE_NTLM`],
    /// [`AUTH_TYPE_KERBEROS`], [`AUTH_TYPE_SPNEGO`]).
    fn auth_type(&self) -> u8 {
        AUTH_TYPE_NTLM
    }

    /// Byte length of the `auth_value` (signature / GSS token) that
    /// [`seal_rpc`](Self::seal_rpc) (`sealed = true`) or
    /// [`sign_rpc`](Self::sign_rpc) (`sealed = false`) will return for a
    /// padded stub of `padded_stub_len` bytes.
    ///
    /// Required before signing because `frag_length` and `auth_length` sit in
    /// the signed PDU header.
    fn auth_value_len(&mut self, sealed: bool, padded_stub_len: usize) -> Result<usize, AuthError> {
        let _ = (sealed, padded_stub_len);
        Ok(16)
    }

    fn negotiate(&mut self) -> Result<Vec<u8>, AuthError>;
    fn respond(&mut self, challenge: &[u8]) -> Result<Vec<u8>, AuthError>;

    /// Whether the connection agreed on header signing (MS-RPCE 3.3.1.5.2.2),
    /// reported once the bind response arrives. Without it, the PDU header and
    /// `sec_trailer` get no protection, so a provider that signs them only when
    /// agreed (Kerberos) must leave them out of the signature. The default does
    /// nothing: NTLM always signs the whole PDU.
    fn set_header_signing(&mut self, negotiated: bool) {
        let _ = negotiated;
    }

    /// Packet privacy: encrypt `stub` in place and return the auth_value
    /// signing `header || stub || sec_trailer` (plaintext).
    fn seal_rpc(
        &mut self,
        header: &[u8],
        stub: &mut [u8],
        sec_trailer: &[u8],
    ) -> Result<Vec<u8>, AuthError>;

    /// Reverse of [`seal_rpc`](Self::seal_rpc) for a received PDU.
    fn unseal_rpc(
        &mut self,
        header: &[u8],
        stub: &mut [u8],
        sec_trailer: &[u8],
        auth_value: &[u8],
    ) -> Result<(), AuthError>;

    /// Packet integrity: the stub stays cleartext; return the auth_value
    /// signing `header || stub || sec_trailer`.
    fn sign_rpc(
        &mut self,
        header: &[u8],
        stub: &[u8],
        sec_trailer: &[u8],
    ) -> Result<Vec<u8>, AuthError>;

    /// Verify the signature of a received packet-integrity PDU.
    fn verify_rpc(
        &mut self,
        header: &[u8],
        stub: &[u8],
        sec_trailer: &[u8],
        auth_value: &[u8],
    ) -> Result<(), AuthError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_require_user_and_password() {
        assert!(Credentials::new("u", "p").validate().is_ok());
        assert!(Credentials::new("", "p").validate().is_err());
        assert!(Credentials::new("u", "").validate().is_err());
    }

    #[test]
    fn credentials_debug_redacts_password() {
        let creds = Credentials::new("admin", "hunter2").with_domain("CORP");
        let shown = format!("{creds:?}");
        assert!(shown.contains("admin") && shown.contains("CORP"));
        assert!(!shown.contains("hunter2"));
    }

    #[test]
    fn zeroize_clears_every_field() {
        let mut creds = Credentials::new("admin", "hunter2").with_domain("CORP");
        creds.zeroize();
        assert!(creds.username.is_empty() && creds.password.is_empty() && creds.domain.is_empty());
    }
}
