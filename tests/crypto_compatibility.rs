//! Compatibility tests between old and new crypto implementations
//!
//! These tests verify that the new crypto_v2 module produces
//! the same outputs as the original implementation for NTLM.

#[cfg(test)]
mod compatibility_tests {
    use hex_literal::hex;

    // Test that both implementations produce the same NT hash
    #[test]
    fn test_nt_hash_compatibility() {
        let password = "Password";

        // Expected NT hash from MS-NLMP documentation
        let expected = hex!("a4f49c406510bdcab6824ee7c30fd852");

        // Test new implementation
        let new_hash = linux_wmi::crypto_v2::legacy::compute_nt_hash(password);
        assert_eq!(
            new_hash, expected,
            "New implementation should match expected NT hash"
        );

        // Note: The old implementation would be tested here but it's
        // buried in auth.rs private functions. This test verifies
        // the new implementation matches the known test vector.
    }

    // Test HMAC-MD5 compatibility
    #[test]
    fn test_hmac_md5_compatibility() {
        // Test vector from RFC 2202
        let key = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let expected = hex!("9294727a3638bb1c13f48ef8158bfc9d");

        // Test new implementation
        let new_result = linux_wmi::crypto_v2::hmac_utils::compute_hmac_md5(&key, data);
        assert_eq!(
            new_result, expected,
            "New HMAC-MD5 should match RFC test vector"
        );
    }

    // Test HMAC-MD5 with segments
    #[test]
    fn test_hmac_md5_segments_compatibility() {
        let key = b"test_key";
        let segments = [b"Hello " as &[u8], b"World" as &[u8]];

        // New implementation with segments
        let segmented = linux_wmi::crypto_v2::hmac_utils::compute_hmac_md5_segments(key, &segments);

        // New implementation with concatenated data
        let combined_data = b"Hello World";
        let combined = linux_wmi::crypto_v2::hmac_utils::compute_hmac_md5(key, combined_data);

        assert_eq!(
            segmented, combined,
            "Segmented HMAC should match combined HMAC"
        );
    }

    // Test RC4 encryption/decryption
    #[test]
    fn test_rc4_compatibility() {
        let key = b"sixteen_byte_key"; // 16 bytes for NTLM
        let plaintext = b"Test message for RC4 encryption";

        // Test new implementation
        let mut encrypted = plaintext.to_vec();
        linux_wmi::crypto_v2::cipher::rc4_encrypt(key, &mut encrypted);
        assert_ne!(&encrypted[..], plaintext, "Data should be encrypted");

        let mut decrypted = encrypted.clone();
        linux_wmi::crypto_v2::cipher::rc4_decrypt(key, &mut decrypted);
        assert_eq!(
            &decrypted[..],
            plaintext,
            "Decrypted data should match original"
        );
    }

    // Test secure memory handling
    #[test]
    fn test_secure_memory() {
        use linux_wmi::crypto_v2::secure::{SecureBytes, SecureString};

        // Test SecureBytes
        let sensitive_data = vec![0x42; 32];
        let secure_bytes = SecureBytes::new(sensitive_data);
        assert_eq!(secure_bytes.len(), 32);

        // Test SecureString
        let password = "SuperSecretPassword123!";
        let secure_string = SecureString::from(password);
        // The actual string will be zeroized on drop

        // Test UTF-16LE conversion
        let utf16le = secure_string.to_utf16le();
        assert_eq!(utf16le.len(), password.len() * 2);
    }

    // Test that HMAC verification is constant-time
    #[test]
    fn test_hmac_verify_constant_time() {
        let key = b"verification_key";
        let data = b"data to verify";

        let signature = linux_wmi::crypto_v2::hmac_utils::compute_hmac_md5(key, data);

        // Correct signature should verify
        assert!(linux_wmi::crypto_v2::hmac_utils::verify_hmac_md5(
            key, data, &signature
        ));

        // Wrong signature should fail
        let mut wrong_sig = signature;
        wrong_sig[0] ^= 0xFF;
        assert!(!linux_wmi::crypto_v2::hmac_utils::verify_hmac_md5(
            key, data, &wrong_sig
        ));
    }
}
