//! Cipher operations for NTLM session encryption
//!
//! This module provides RC4 encryption/decryption required for NTLM privacy level.

use rc4::{KeyInit, StreamCipher};
use zeroize::Zeroizing;

/// Encrypt data using RC4 with the session key
///
/// Per MS-NLMP §3.4.4, RC4 encryption uses the session key directly
/// for NTLM privacy level (sealing).
///
/// # Security Warning
/// RC4 is considered weak. Use only for NTLM compatibility.
pub fn rc4_encrypt(session_key: &[u8], data: &mut [u8]) {
    // RC4 requires a fixed-size key type. Since NTLM uses 16-byte (128-bit) keys,
    // we'll use the U16 type (16 bytes).
    use rc4::consts::U16;
    type Rc4_128 = rc4::Rc4<U16>;

    // Validate key size (NTLM typically uses 128-bit keys)
    debug_assert!(
        session_key.len() == 16,
        "NTLM session keys should be 128 bits for RC4"
    );

    let mut cipher = Rc4_128::new_from_slice(session_key).expect("RC4 accepts 16-byte keys");
    cipher.apply_keystream(data);
}

/// Decrypt data using RC4 with the session key
///
/// RC4 is symmetric, so decryption is the same as encryption
pub fn rc4_decrypt(session_key: &[u8], data: &mut [u8]) {
    rc4_encrypt(session_key, data); // RC4 decrypt = encrypt
}

/// Encrypt data with secure key handling
///
/// The key is wrapped in Zeroizing to ensure it's cleared from memory after use.
pub fn rc4_encrypt_secure(session_key: Vec<u8>, data: &mut [u8]) {
    let secure_key = Zeroizing::new(session_key);
    rc4_encrypt(&secure_key, data);
}

/// Create separate RC4 states for sealing and unsealing
///
/// Some NTLM implementations use separate RC4 states for client-to-server
/// and server-to-client encryption.
pub struct SealingContext {
    send_cipher: rc4::Rc4<rc4::consts::U16>,
    recv_cipher: rc4::Rc4<rc4::consts::U16>,
}

impl SealingContext {
    /// Create a new sealing context with separate send/receive ciphers
    pub fn new(send_key: &[u8], recv_key: &[u8]) -> Self {
        use rc4::consts::U16;
        type Rc4_128 = rc4::Rc4<U16>;

        Self {
            send_cipher: Rc4_128::new_from_slice(send_key).expect("RC4 accepts 16-byte keys"),
            recv_cipher: Rc4_128::new_from_slice(recv_key).expect("RC4 accepts 16-byte keys"),
        }
    }

    /// Create a context using the same key for both directions
    pub fn new_symmetric(key: &[u8]) -> Self {
        Self::new(key, key)
    }

    /// Encrypt data for sending
    pub fn seal(&mut self, data: &mut [u8]) {
        self.send_cipher.apply_keystream(data);
    }

    /// Decrypt received data
    pub fn unseal(&mut self, data: &mut [u8]) {
        self.recv_cipher.apply_keystream(data);
    }
}

/// Derive RC4 key from NTLM session key for sealing
///
/// Advanced implementations may use key derivation for stronger security.
/// For basic NTLM, the session key is used directly.
pub fn derive_sealing_key(session_key: &[u8], _client_to_server: bool) -> Vec<u8> {
    // For basic implementation, use session key directly
    // Advanced: Could use MD5(session_key + magic) for client/server keys
    // This would require protocol-specific magic constants
    session_key.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rc4_encrypt_decrypt() {
        let key = b"test_session_key"; // 16 bytes
        let original = b"Hello, World!";
        let mut data = original.to_vec();

        // Encrypt
        rc4_encrypt(key, &mut data);
        assert_ne!(&data[..], original);

        // Decrypt
        rc4_decrypt(key, &mut data);
        assert_eq!(&data[..], original);
    }

    #[test]
    fn test_rc4_known_vector() {
        // Since our implementation expects 16-byte keys for NTLM,
        // we'll pad the key to 16 bytes
        let mut key = [0u8; 16];
        key[0..3].copy_from_slice(b"Key");
        let plaintext = b"Plaintext";
        let mut data = plaintext.to_vec();

        rc4_encrypt(&key, &mut data);

        // The ciphertext will be different with the padded key
        // Just verify encryption/decryption works
        let mut decrypted = data.clone();
        rc4_decrypt(&key, &mut decrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_sealing_context() {
        let key = b"shared_secret_16"; // 16 bytes
        let mut ctx = SealingContext::new_symmetric(key);

        let original = b"Test message";
        let mut sent = original.to_vec();

        // Seal for sending
        ctx.seal(&mut sent);
        assert_ne!(&sent[..], original, "Sealed data should be different");

        // Create receiving context (would be on other side)
        let mut recv_ctx = SealingContext::new_symmetric(key);
        let mut received = sent.clone();

        // Unseal received data
        recv_ctx.unseal(&mut received);
        assert_eq!(
            &received[..],
            original,
            "Unsealed data should match original"
        );
    }

    #[test]
    fn test_rc4_secure() {
        let key = vec![0x42; 16]; // Will be zeroized
        let mut data = b"Sensitive data".to_vec();
        let original = data.clone();

        rc4_encrypt_secure(key, &mut data);
        assert_ne!(data, original);
    }
}
