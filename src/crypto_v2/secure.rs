//! Secure memory handling utilities
//!
//! This module provides wrappers and utilities for secure handling of sensitive data.

use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Secure bytes wrapper that zeroizes on drop
///
/// This wrapper ensures sensitive data is cleared from memory when no longer needed.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecureBytes {
    #[zeroize(drop)]
    inner: Vec<u8>,
}

impl SecureBytes {
    /// Create a new SecureBytes from a vector
    pub fn new(data: Vec<u8>) -> Self {
        Self { inner: data }
    }

    /// Create SecureBytes with specified capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Vec::with_capacity(capacity),
        }
    }

    /// Get the length of the secure bytes
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the secure bytes are empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Extend from a slice
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.inner.extend_from_slice(slice);
    }

    /// Convert to a fixed-size array (clones the data)
    pub fn to_array<const N: usize>(&self) -> Option<[u8; N]> {
        if self.inner.len() == N {
            let mut array = [0u8; N];
            array.copy_from_slice(&self.inner);
            Some(array)
        } else {
            None
        }
    }
}

impl Deref for SecureBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for SecureBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl From<Vec<u8>> for SecureBytes {
    fn from(vec: Vec<u8>) -> Self {
        Self::new(vec)
    }
}

impl From<&[u8]> for SecureBytes {
    fn from(slice: &[u8]) -> Self {
        Self::new(slice.to_vec())
    }
}

/// Secure string wrapper for passwords and sensitive text
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecureString {
    #[zeroize(drop)]
    inner: String,
}

impl SecureString {
    /// Create a new SecureString
    pub fn new(s: String) -> Self {
        Self { inner: s }
    }

    /// Get as string slice
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Convert to UTF-16LE bytes (for NTLM)
    pub fn to_utf16le(&self) -> SecureBytes {
        let utf16: Vec<u16> = self.inner.encode_utf16().collect();
        let mut bytes = Vec::with_capacity(utf16.len() * 2);
        for codepoint in utf16 {
            bytes.extend_from_slice(&codepoint.to_le_bytes());
        }
        SecureBytes::new(bytes)
    }
}

impl From<String> for SecureString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for SecureString {
    fn from(s: &str) -> Self {
        Self::new(s.to_string())
    }
}

/// Constant-time comparison for byte arrays
///
/// Prevents timing attacks by ensuring comparison time doesn't depend on data.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (byte_a, byte_b) in a.iter().zip(b.iter()) {
        result |= byte_a ^ byte_b;
    }
    result == 0
}

/// Clear a mutable byte slice
pub fn zeroize_bytes(bytes: &mut [u8]) {
    bytes.zeroize();
}

/// Create a Zeroizing wrapper for temporary sensitive data
pub fn secure_temp<T: Zeroize>(data: T) -> Zeroizing<T> {
    Zeroizing::new(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_bytes() {
        let data = vec![1, 2, 3, 4, 5];
        let mut secure = SecureBytes::new(data);

        assert_eq!(secure.len(), 5);
        assert_eq!(&secure[..], &[1, 2, 3, 4, 5]);

        secure.extend_from_slice(&[6, 7, 8]);
        assert_eq!(secure.len(), 8);
    }

    #[test]
    fn test_secure_string() {
        let password = "SecretPassword123";
        let secure = SecureString::from(password);

        assert_eq!(secure.as_str(), password);

        let utf16 = secure.to_utf16le();
        assert_eq!(utf16.len(), password.len() * 2);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 4, 5];
        let c = [1, 2, 3, 4, 6];
        let d = [1, 2, 3];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &d));
    }

    #[test]
    fn test_secure_temp() {
        let sensitive_data = vec![0x42; 16];
        let secure = secure_temp(sensitive_data);

        assert_eq!(&**secure, &[0x42; 16]);
        // Data will be zeroized when secure goes out of scope
    }

    #[test]
    fn test_zeroize_bytes() {
        let mut data = [1, 2, 3, 4, 5];
        zeroize_bytes(&mut data);
        assert_eq!(data, [0, 0, 0, 0, 0]);
    }
}
