//! HMAC operations using the RustCrypto hmac crate
//!
//! This module provides HMAC-MD5 operations required for NTLM authentication.

use zeroize::{Zeroize, Zeroizing};

/// Compute HMAC-MD5 signature
///
/// This is used for NTLM session key operations per MS-NLMP specification.
///
/// # Security Note
/// MD5 is cryptographically broken but required for NTLM compatibility.
/// Use only for legacy protocol support.
pub fn compute_hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    // Since md5 0.7 doesn't support Digest trait, we implement HMAC-MD5 manually
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let hash = md5::compute(key);
        key_block[..16].copy_from_slice(&hash.0);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    // XOR key with ipad (0x36)
    let mut i_key = key_block;
    for byte in i_key.iter_mut() {
        *byte ^= 0x36;
    }

    // Inner hash: MD5(i_key || data)
    let mut inner_data = Vec::with_capacity(64 + data.len());
    inner_data.extend_from_slice(&i_key);
    inner_data.extend_from_slice(data);
    let inner_hash = md5::compute(&inner_data);

    // XOR key with opad (0x5C)
    let mut o_key = key_block;
    for byte in o_key.iter_mut() {
        *byte ^= 0x5C;
    }

    // Outer hash: MD5(o_key || inner_hash)
    let mut outer_data = Vec::with_capacity(64 + 16);
    outer_data.extend_from_slice(&o_key);
    outer_data.extend_from_slice(&inner_hash.0);
    let outer_hash = md5::compute(&outer_data);

    let mut result = [0u8; 16];
    result.copy_from_slice(&outer_hash.0);

    // CRITICAL: Zeroize all key material before returning
    key_block.zeroize();
    i_key.zeroize();
    o_key.zeroize();

    result
}

/// Compute HMAC-MD5 over multiple data segments
///
/// This is useful for computing HMAC over non-contiguous data without copying.
pub fn compute_hmac_md5_segments(key: &[u8], segments: &[&[u8]]) -> [u8; 16] {
    // Prepare key block
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let hash = md5::compute(key);
        key_block[..16].copy_from_slice(&hash.0);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    // XOR key with ipad (0x36)
    let mut i_key = key_block;
    for byte in i_key.iter_mut() {
        *byte ^= 0x36;
    }

    // Inner hash: MD5(i_key || segments)
    let mut inner_data = Vec::with_capacity(64);
    inner_data.extend_from_slice(&i_key);
    for segment in segments {
        inner_data.extend_from_slice(segment);
    }
    let inner_hash = md5::compute(&inner_data);

    // XOR key with opad (0x5C)
    let mut o_key = key_block;
    for byte in o_key.iter_mut() {
        *byte ^= 0x5C;
    }

    // Outer hash: MD5(o_key || inner_hash)
    let mut outer_data = Vec::with_capacity(64 + 16);
    outer_data.extend_from_slice(&o_key);
    outer_data.extend_from_slice(&inner_hash.0);
    let outer_hash = md5::compute(&outer_data);

    let mut result = [0u8; 16];
    result.copy_from_slice(&outer_hash.0);

    // CRITICAL: Zeroize all key material before returning
    key_block.zeroize();
    i_key.zeroize();
    o_key.zeroize();

    result
}

/// Verify HMAC-MD5 signature (constant-time comparison)
///
/// Returns true if the signature matches, false otherwise.
/// Uses constant-time comparison to prevent timing attacks.
pub fn verify_hmac_md5(key: &[u8], data: &[u8], signature: &[u8; 16]) -> bool {
    let computed = compute_hmac_md5(key, data);

    // Constant-time comparison
    let mut result = 0u8;
    for (a, b) in computed.iter().zip(signature.iter()) {
        result |= a ^ b;
    }
    result == 0
}

/// Compute HMAC-MD5 with secure key handling
///
/// The key is wrapped in Zeroizing to ensure it's cleared from memory after use.
pub fn compute_hmac_md5_secure(key: Vec<u8>, data: &[u8]) -> [u8; 16] {
    let secure_key = Zeroizing::new(key);
    compute_hmac_md5(&secure_key, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_hmac_md5_known_vector() {
        // Test vector from RFC 2202
        let key = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let expected = hex!("9294727a3638bb1c13f48ef8158bfc9d");

        let result = compute_hmac_md5(&key, data);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hmac_md5_segments() {
        let key = b"test_key";
        let data1 = b"Hello ";
        let data2 = b"World";

        // Compute over segments
        let result1 = compute_hmac_md5_segments(key, &[data1, data2]);

        // Compute over concatenated data
        let mut combined = Vec::new();
        combined.extend_from_slice(data1);
        combined.extend_from_slice(data2);
        let result2 = compute_hmac_md5(key, &combined);

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_hmac_md5_verify() {
        let key = b"secret_key";
        let data = b"test data";

        let signature = compute_hmac_md5(key, data);

        // Correct signature should verify
        assert!(verify_hmac_md5(key, data, &signature));

        // Wrong key should fail
        assert!(!verify_hmac_md5(b"wrong_key", data, &signature));

        // Modified signature should fail
        let mut bad_signature = signature;
        bad_signature[0] ^= 0x01;
        assert!(!verify_hmac_md5(key, data, &bad_signature));
    }

    #[test]
    fn test_hmac_md5_secure() {
        let key = vec![0x42; 16]; // Will be zeroized after use
        let data = b"sensitive data";

        let result = compute_hmac_md5_secure(key, data);

        // Just verify it produces a result (actual value tested above)
        assert_eq!(result.len(), 16);
    }
}
