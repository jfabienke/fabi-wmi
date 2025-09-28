//! Legacy cryptographic algorithms required for NTLM compatibility
//!
//! WARNING: These algorithms (MD4, MD5) are cryptographically broken and
//! should only be used for compatibility with existing Windows systems.

use digest::Digest;
use md4::Md4;
use zeroize::Zeroizing;

/// Compute NT hash (MD4 of UTF-16LE password)
///
/// This is required for NTLMv2 authentication per MS-NLMP specification.
///
/// # Security Warning
/// MD4 is cryptographically broken. This function exists only for NTLM compatibility.
pub fn compute_nt_hash(password: &str) -> [u8; 16] {
    // Convert password to UTF-16LE
    let password_utf16 = Zeroizing::new(utf16le(password));

    // Compute MD4 hash
    let mut hasher = Md4::new();
    hasher.update(&*password_utf16);

    let result = hasher.finalize();
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&result);
    hash
}

// LM hash is intentionally not implemented
// LM is cryptographically broken and should never be used.
// NTLMv2 does not require LM hashes.

/// Compute MD5 hash
///
/// # Security Warning
/// MD5 is cryptographically broken. Use only for legacy protocol compatibility.
pub fn compute_md5(data: &[u8]) -> [u8; 16] {
    let digest = md5::compute(data);
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&digest.0);
    hash
}

/// Convert string to UTF-16LE bytes
fn utf16le(s: &str) -> Vec<u8> {
    let utf16: Vec<u16> = s.encode_utf16().collect();
    let mut result = Vec::with_capacity(utf16.len() * 2);
    for codepoint in utf16 {
        result.extend_from_slice(&codepoint.to_le_bytes());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_nt_hash_known_vector() {
        // Test vector from MS-NLMP documentation
        let password = "Password";
        let expected = hex!("a4f49c406510bdcab6824ee7c30fd852");
        let hash = compute_nt_hash(password);
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_md5_known_vector() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let expected = hex!("9e107d9d372bb6826bd81d3542a419d6");
        let hash = compute_md5(data);
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_utf16le_conversion() {
        let text = "Hello";
        let expected = vec![0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00];
        assert_eq!(utf16le(text), expected);
    }
}
