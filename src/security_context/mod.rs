//! Security Context Abstraction Layer
//!
//! Provides a platform-agnostic interface for RPC authentication and encryption.
//! Implementations use GSSAPI on Unix/macOS and SSPI on Windows.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Context not established")]
    NotEstablished,
    #[error("Token generation failed: {0}")]
    TokenGeneration(String),
    #[error("Wrap/unwrap failed: {0}")]
    CryptoOperation(String),
    #[error("Clock skew detected: {0}")]
    ClockSkew(String),
    #[error("Invalid credentials: {0}")]
    InvalidCredentials(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("SPN resolution failed: {0}")]
    SpnResolution(String),
    #[error("Platform error: code={code:#x}, details={details}")]
    PlatformSpecific {
        code: u32,
        details: String,
    },
}

/// Platform-agnostic security context for RPC authentication
pub trait SecurityContext: Send {
    /// Initialize or continue security context establishment
    /// Returns token to send to peer, or empty vec when complete
    fn init_step(&mut self, input: Option<&[u8]>) -> Result<Vec<u8>, SecurityError>;

    /// Wrap (encrypt/sign) data for transmission
    /// conf_req: true for encryption, false for signing only
    fn wrap(&mut self, data: &[u8], conf_req: bool) -> Result<Vec<u8>, SecurityError>;

    /// Unwrap (decrypt/verify) received data
    fn unwrap(&mut self, token: &[u8]) -> Result<Vec<u8>, SecurityError>;

    /// Get session key for additional crypto operations
    fn session_key(&self) -> Option<Vec<u8>>;

    /// Check if context is fully established
    fn is_established(&self) -> bool;

    /// Get security trailer size for RPC PDUs
    fn trailer_size(&self) -> usize;
}

// Platform-specific implementations
#[cfg(unix)]
pub mod gssapi;

#[cfg(windows)]
pub mod sspi;

// Mock implementation for testing
#[cfg(test)]
pub mod mock;

// Re-export the appropriate implementation based on platform
#[cfg(unix)]
pub use gssapi::GssapiContext;

#[cfg(windows)]
pub use sspi::SspiContext;

#[cfg(test)]
pub use mock::MockSecurityContext;

/// Helper trait for mapping platform errors to SecurityError
pub(crate) trait ErrorMapper {
    fn map_platform_error(&self, code: u32) -> SecurityError;
}