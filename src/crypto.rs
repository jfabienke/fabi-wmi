use rc4::{KeyInit, StreamCipher};

/// Compute HMAC-MD5 signature for RPC PDU authentication
///
/// Per MS-RPCE §3.3.3, the signature is computed over the PDU header and body
/// using the NTLM session key as the HMAC key.
pub fn hmac_md5_sign(session_key: &[u8], data: &[u8]) -> [u8; 16] {
    // Use the existing hmac_md5_segments implementation from auth module
    // For now, we'll implement a simplified version here
    let mut key_block = [0u8; 64];
    if session_key.len() > 64 {
        let hash = md5::compute(session_key);
        key_block[..16].copy_from_slice(&hash.0);
    } else {
        key_block[..session_key.len()].copy_from_slice(session_key);
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
    result
}

/// Verify HMAC-MD5 signature
pub fn hmac_md5_verify(session_key: &[u8], data: &[u8], signature: &[u8; 16]) -> bool {
    let computed = hmac_md5_sign(session_key, data);
    computed == *signature
}

/// Encrypt data using RC4 with the session key
///
/// Per MS-NLMP §3.4.4, RC4 encryption uses the session key directly
/// for NTLM privacy level (sealing).
pub fn rc4_encrypt(session_key: &[u8], data: &mut [u8]) {
    // RC4 requires a fixed-size key type. Since NTLM uses 16-byte (128-bit) keys,
    // we'll use the U16 type (16 bytes).
    // Import the specific size we need
    use rc4::consts::U16;
    type Rc4_128 = rc4::Rc4<U16>;

    let mut cipher = Rc4_128::new_from_slice(session_key).expect("RC4 accepts 16-byte keys");
    cipher.apply_keystream(data);
}

/// Decrypt data using RC4 with the session key
///
/// RC4 is symmetric, so decryption is the same as encryption
pub fn rc4_decrypt(session_key: &[u8], data: &mut [u8]) {
    rc4_encrypt(session_key, data); // RC4 decrypt = encrypt
}

/// Derive RC4 key from NTLM session key for sealing
///
/// Some implementations use key derivation for stronger security.
/// For basic NTLM, the session key is used directly.
#[allow(dead_code)]
pub fn derive_sealing_key(session_key: &[u8], _client_to_server: bool) -> Vec<u8> {
    // For basic implementation, use session key directly
    // Advanced: Could use MD5(session_key + magic) for client/server keys
    session_key.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_md5_sign_verify() {
        let key = b"test_session_key";
        let data = b"test data to sign";

        let signature = hmac_md5_sign(key, data);
        assert!(hmac_md5_verify(key, data, &signature));

        // Wrong key should fail
        let wrong_key = b"wrong_key";
        assert!(!hmac_md5_verify(wrong_key, data, &signature));

        // Modified data should fail
        let wrong_data = b"modified data";
        assert!(!hmac_md5_verify(key, wrong_data, &signature));
    }

    #[test]
    fn test_rc4_encrypt_decrypt() {
        let key = b"test_session_key";
        let original_data = b"sensitive WMI data to encrypt";
        let mut data = original_data.to_vec();

        // Encrypt
        rc4_encrypt(key, &mut data);
        assert_ne!(&data[..], original_data);

        // Decrypt (should restore original)
        rc4_decrypt(key, &mut data);
        assert_eq!(&data[..], original_data);
    }

    #[test]
    fn test_hmac_md5_known_vector() {
        // Test vector from RFC 2202
        let key = hex_literal::hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let expected = hex_literal::hex!("9294727a3638bb1c13f48ef8158bfc9d");

        let signature = hmac_md5_sign(&key, data);
        assert_eq!(signature, expected);
    }

    #[test]
    fn test_hmac_md5_with_long_key() {
        // Test line 12-13: key > 64 bytes triggers MD5 hash
        let long_key = vec![0xAA; 80]; // 80 bytes > 64
        let data = b"Test data";

        // This should trigger the MD5 hash path for long keys
        let signature = hmac_md5_sign(&long_key, data);

        // Verify it produces a valid 16-byte signature
        assert_eq!(signature.len(), 16);

        // Verify with same key
        assert!(hmac_md5_verify(&long_key, data, &signature));
    }

    #[test]
    fn test_derive_sealing_key() {
        // Test line 80-83: derive_sealing_key function
        let session_key = b"test_session_key";

        // Test client to server
        let client_key = derive_sealing_key(session_key, true);
        assert_eq!(client_key, session_key.to_vec());

        // Test server to client
        let server_key = derive_sealing_key(session_key, false);
        assert_eq!(server_key, session_key.to_vec());

        // Currently just returns session key, but tests the function
    }

    #[test]
    fn test_hmac_md5_empty_inputs() {
        // Edge case: empty key and data
        let empty_key = b"";
        let empty_data = b"";

        let signature = hmac_md5_sign(empty_key, empty_data);
        assert_eq!(signature.len(), 16);
        assert!(hmac_md5_verify(empty_key, empty_data, &signature));
    }

    #[test]
    fn test_rc4_with_exact_16_byte_key() {
        // Ensure RC4 works with exactly 16-byte keys (NTLM standard)
        let key_16 = b"sixteen_byte_key"; // exactly 16 bytes
        let mut data = b"test data".to_vec();
        let original = data.clone();

        rc4_encrypt(key_16, &mut data);
        assert_ne!(data, original);

        rc4_decrypt(key_16, &mut data);
        assert_eq!(data, original);
    }
}
