//! Improved cryptographic module using RustCrypto ecosystem
//!
//! This module provides cryptographic primitives required for NTLM and MS-RPC protocols.
//! It uses well-vetted implementations from the RustCrypto project where possible.

pub mod cipher;
pub mod hmac_utils;
pub mod legacy;
pub mod secure;

// Re-export commonly used items
pub use self::cipher::{rc4_decrypt, rc4_encrypt};
pub use self::hmac_utils::{compute_hmac_md5, verify_hmac_md5};
pub use self::legacy::compute_nt_hash;
pub use self::secure::SecureBytes;
