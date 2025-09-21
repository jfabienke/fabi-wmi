//! Mock security contexts for testing
//!
//! Provides mock implementations of security contexts for testing
//! without real Kerberos/NTLM infrastructure.

use crate::auth::{AuthError, AuthProvider};

/// TEST INFRASTRUCTURE - DO NOT DELETE
///
/// Mock authentication provider for testing.
/// Returns predictable authentication tokens without actual crypto.
pub struct MockAuthProvider {
    username: String,
    domain: String,
}

impl MockAuthProvider {
    pub fn new(username: String, domain: String) -> Self {
        Self { username, domain }
    }
}

impl AuthProvider for MockAuthProvider {
    fn negotiate(&mut self) -> Result<Vec<u8>, AuthError> {
        // Return a mock Type1 message
        Ok(vec![0x4E, 0x54, 0x4C, 0x4D]) // "NTLM"
    }

    fn respond(&mut self, _challenge: &[u8]) -> Result<Vec<u8>, AuthError> {
        // Return a mock Type3 message
        Ok(format!("MOCK_AUTH_{}_{}", self.username, self.domain).into_bytes())
    }

    fn session_key(&self) -> Option<&[u8]> {
        // Return a fake session key
        Some(b"MOCK_SESSION_KEY")
    }
}