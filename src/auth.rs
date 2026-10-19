#![allow(dead_code)]

use std::convert::TryInto;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::{rngs::OsRng, RngCore};
use thiserror::Error;
use tracing::debug;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto_v2::compute_nt_hash;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("NTLM unsupported")]
    Ntlm,
    #[error("Invalid creds")]
    Creds,
    #[error("Type2 message invalid")]
    InvalidType2,
}

const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

/// NTLM Negotiate Flags for a secure WMI connection.
/// Enables signing, sealing, extended session security, and strong keys.
///
/// See: [MS-NLMP] §3.2.5.1.2, Table 3 "Negotiate Flags"
const NEGOTIATE_FLAGS: u32 = 0xE289_8235;
pub(crate) const NTLMSSP_NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
/// NTLMSSP VERSION (MS-NLMP 2.2.2.10): Windows 10.0, build 0, NTLMSSP_REVISION_W2K3.
const NTLM_VERSION: [u8; 8] = [0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F];

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Credentials {
    pub username: String,
    #[zeroize(skip)]
    pub password: SecureString,
    pub domain: String,
    pub workstation: String,
}

/// Secure string wrapper that zeroizes on drop
#[derive(Clone)]
pub struct SecureString(String);

impl SecureString {
    pub fn new(s: String) -> Self {
        SecureString(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Credentials {
    pub fn new(username: String, password: String, domain: String, workstation: String) -> Self {
        Self {
            username,
            password: SecureString::new(password),
            domain,
            workstation,
        }
    }

    pub fn validate(&self) -> Result<(), AuthError> {
        if self.username.is_empty() || self.password.is_empty() {
            return Err(AuthError::Creds);
        }
        Ok(())
    }
}

pub struct NegotiateMessage {
    pub message: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ChallengeMessage {
    pub flags: u32,
    pub server_challenge: [u8; 8],
    pub target_info: Vec<u8>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AuthenticateMessage {
    pub message: Vec<u8>,
    pub session_key: [u8; 16],
    pub negotiate_flags: u32,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct NtlmV2Client {
    creds: Credentials,
    last_session_key: Option<[u8; 16]>,
    type1_message: Option<Vec<u8>>,
    type2_message: Option<Vec<u8>>,
}

impl NtlmV2Client {
    pub fn new(creds: Credentials) -> Result<Self, AuthError> {
        creds.validate()?;
        Ok(Self {
            creds,
            last_session_key: None,
            type1_message: None,
            type2_message: None,
        })
    }

    pub fn negotiate_message(&mut self) -> NegotiateMessage {
        debug!(domain = %self.creds.domain, workstation = %self.creds.workstation, "building NTLM type1");
        let message = build_type1_message(&self.creds.domain, &self.creds.workstation);
        self.type1_message = Some(message.clone());
        NegotiateMessage { message }
    }

    pub fn respond_message(
        &mut self,
        challenge_bytes: &[u8],
    ) -> Result<AuthenticateMessage, AuthError> {
        let challenge = parse_type2_message(challenge_bytes)?;
        debug!("received NTLM challenge");

        // Store Type2 message for MIC calculation
        self.type2_message = Some(challenge_bytes.to_vec());

        // Build Type3 with MIC support
        let auth = build_type3_message_with_mic(
            &self.creds,
            &challenge,
            self.type1_message.as_deref(),
            challenge_bytes,
            None,
            None,
            None,
        )?;

        debug!("generated NTLM type3 response with MIC");
        self.last_session_key = Some(auth.session_key);
        Ok(auth)
    }
}

/// Trait describing an authentication provider used by the RPC layer.
pub trait AuthProvider: Send {
    fn negotiate(&mut self) -> Result<Vec<u8>, AuthError>;
    fn respond(&mut self, challenge: &[u8]) -> Result<Vec<u8>, AuthError>;
    fn session_key(&self) -> Option<&[u8]>;
}

impl AuthProvider for NtlmV2Client {
    fn negotiate(&mut self) -> Result<Vec<u8>, AuthError> {
        let msg = self.negotiate_message();
        Ok(msg.message)
    }

    fn respond(&mut self, challenge: &[u8]) -> Result<Vec<u8>, AuthError> {
        let auth = self.respond_message(challenge)?;
        Ok(auth.message.clone())
    }

    fn session_key(&self) -> Option<&[u8]> {
        self.last_session_key.as_ref().map(|k| k.as_ref())
    }
}

fn build_type1_message(domain: &str, workstation: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(40);
    message.extend_from_slice(NTLMSSP_SIGNATURE);
    message.extend_from_slice(&1u32.to_le_bytes());
    message.extend_from_slice(&NEGOTIATE_FLAGS.to_le_bytes());

    let domain_utf16 = utf16le(domain);
    let workstation_utf16 = utf16le(workstation);

    let mut payload_offset = 40u32;
    let append_security_buffer = |buf: &[u8], message: &mut Vec<u8>, offset: &mut u32| {
        let len = buf.len() as u16;
        message.extend_from_slice(&len.to_le_bytes());
        message.extend_from_slice(&len.to_le_bytes());
        message.extend_from_slice(&offset.to_le_bytes());
        *offset += buf.len() as u32;
    };

    append_security_buffer(&domain_utf16, &mut message, &mut payload_offset);
    append_security_buffer(&workstation_utf16, &mut message, &mut payload_offset);

    message.extend_from_slice(&[0u8; 8]);
    message.extend_from_slice(&domain_utf16);
    message.extend_from_slice(&workstation_utf16);
    message
}

pub(crate) fn parse_type2_message(bytes: &[u8]) -> Result<ChallengeMessage, AuthError> {
    if bytes.len() < 48 || &bytes[..8] != NTLMSSP_SIGNATURE {
        return Err(AuthError::InvalidType2);
    }
    if u32::from_le_bytes(bytes[8..12].try_into().unwrap()) != 2 {
        return Err(AuthError::InvalidType2);
    }

    let negotiate_flags = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
    let mut challenge = [0u8; 8];
    challenge.copy_from_slice(&bytes[24..32]);

    let target_info_len = u16::from_le_bytes(bytes[40..42].try_into().unwrap()) as usize;
    let target_info_offset = u32::from_le_bytes(bytes[44..48].try_into().unwrap()) as usize;

    if target_info_offset + target_info_len > bytes.len() {
        return Err(AuthError::InvalidType2);
    }

    let target_info = bytes[target_info_offset..target_info_offset + target_info_len].to_vec();

    Ok(ChallengeMessage {
        flags: negotiate_flags,
        server_challenge: challenge,
        target_info,
    })
}

fn build_type3_message(
    creds: &Credentials,
    challenge: &ChallengeMessage,
    forced_client_nonce: Option<[u8; 8]>,
    forced_timestamp: Option<u64>,
) -> Result<AuthenticateMessage, AuthError> {
    let username_upper = creds.username.to_uppercase();

    let mut nt_hash = compute_nt_hash(creds.password.as_str());

    // NTOWFv2 (MS-NLMP 3.3.2): uppercase the user name only, never the domain.
    let mut identity = utf16le(&(username_upper.clone() + &creds.domain));
    let ntlm_v2_hash = hmac_md5_segments(&nt_hash, &[&identity]);
    zeroize_bytes(&mut identity);

    let mut ntlm_v2_hash_arr = ntlm_v2_hash;

    let mut client_nonce = if let Some(nonce) = forced_client_nonce {
        nonce
    } else {
        generate_client_nonce()
    };

    // MS-NLMP 3.1.5.1.2: echo the server's MsvAvTimestamp when the challenge has one.
    let timestamp = forced_timestamp
        .or_else(|| av_timestamp(&challenge.target_info))
        .unwrap_or_else(current_filetime);
    let mut blob = Vec::new();
    blob.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]); // RespType, HiRespType, Reserved1
    blob.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
    blob.extend_from_slice(&timestamp.to_le_bytes());
    blob.extend_from_slice(&client_nonce);
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&challenge.target_info);
    blob.extend_from_slice(&0u32.to_le_bytes());

    let nt_proof = hmac_md5_segments(&ntlm_v2_hash_arr, &[&challenge.server_challenge, &blob]);

    let mut nt_response = Vec::with_capacity(nt_proof.len() + blob.len());
    nt_response.extend_from_slice(&nt_proof);
    nt_response.extend_from_slice(&blob);
    blob.zeroize();

    let lm_proof = hmac_md5_segments(
        &ntlm_v2_hash_arr,
        &[&challenge.server_challenge, &client_nonce],
    );

    let mut lm_response = Vec::with_capacity(lm_proof.len() + client_nonce.len());
    lm_response.extend_from_slice(&lm_proof);
    lm_response.extend_from_slice(&client_nonce);

    let session_key = hmac_md5_segments(&ntlm_v2_hash_arr, &[&nt_proof]);

    let domain_utf16 = utf16le(&creds.domain);
    let user_utf16 = utf16le(&creds.username);
    let workstation_utf16 = utf16le(&creds.workstation);

    let mut buffers = Vec::with_capacity(6 * 8);
    let mut offset = 64u32;
    for buf in [
        lm_response.as_slice(),
        nt_response.as_slice(),
        domain_utf16.as_slice(),
        user_utf16.as_slice(),
        workstation_utf16.as_slice(),
        session_key.as_slice(),
    ] {
        let len = buf.len() as u16;
        buffers.extend_from_slice(&len.to_le_bytes());
        buffers.extend_from_slice(&len.to_le_bytes());
        buffers.extend_from_slice(&offset.to_le_bytes());
        offset += buf.len() as u32;
    }

    let mut message = Vec::new();
    message.extend_from_slice(NTLMSSP_SIGNATURE);
    message.extend_from_slice(&3u32.to_le_bytes());
    message.extend_from_slice(&buffers);
    message.extend_from_slice(&NEGOTIATE_FLAGS.to_le_bytes());
    message.extend_from_slice(&lm_response);
    message.extend_from_slice(&nt_response);
    message.extend_from_slice(&domain_utf16);
    message.extend_from_slice(&user_utf16);
    message.extend_from_slice(&workstation_utf16);
    message.extend_from_slice(&session_key);

    zeroize_bytes(&mut nt_hash);
    zeroize_bytes(&mut ntlm_v2_hash_arr);
    zeroize_bytes(&mut client_nonce);

    Ok(AuthenticateMessage {
        message,
        session_key,
        negotiate_flags: challenge.flags,
    })
}

/// Build Type3 message with MIC (Message Integrity Code) for Windows 11 compatibility
fn build_type3_message_with_mic(
    creds: &Credentials,
    challenge: &ChallengeMessage,
    type1_message: Option<&[u8]>,
    type2_message: &[u8],
    forced_client_nonce: Option<[u8; 8]>,
    forced_timestamp: Option<u64>,
    forced_exported_session_key: Option<[u8; 16]>,
) -> Result<AuthenticateMessage, AuthError> {
    let username_upper = creds.username.to_uppercase();

    let mut nt_hash = compute_nt_hash(creds.password.as_str());

    // NTOWFv2 (MS-NLMP 3.3.2): uppercase the user name only, never the domain.
    let mut identity = utf16le(&(username_upper.clone() + &creds.domain));
    let ntlm_v2_hash = hmac_md5_segments(&nt_hash, &[&identity]);
    zeroize_bytes(&mut identity);

    let mut ntlm_v2_hash_arr = ntlm_v2_hash;

    let mut client_nonce = if let Some(nonce) = forced_client_nonce {
        nonce
    } else {
        generate_client_nonce()
    };

    // MS-NLMP 3.1.5.1.2: echo the server's MsvAvTimestamp when the challenge has one.
    let timestamp = forced_timestamp
        .or_else(|| av_timestamp(&challenge.target_info))
        .unwrap_or_else(current_filetime);

    // Build the NTLMv2 blob
    let mut blob = Vec::new();
    blob.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]); // RespType, HiRespType, Reserved1
    blob.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
    blob.extend_from_slice(&timestamp.to_le_bytes());
    blob.extend_from_slice(&client_nonce);
    blob.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
    blob.extend_from_slice(&challenge.target_info);
    blob.extend_from_slice(&0u32.to_le_bytes()); // Reserved3

    // Calculate NT proof
    let nt_proof = hmac_md5_segments(&ntlm_v2_hash_arr, &[&challenge.server_challenge, &blob]);

    let mut nt_response = Vec::with_capacity(nt_proof.len() + blob.len());
    nt_response.extend_from_slice(&nt_proof);
    nt_response.extend_from_slice(&blob);
    blob.zeroize();

    // Calculate LM response
    let lm_proof = hmac_md5_segments(
        &ntlm_v2_hash_arr,
        &[&challenge.server_challenge, &client_nonce],
    );

    let mut lm_response = Vec::with_capacity(lm_proof.len() + client_nonce.len());
    lm_response.extend_from_slice(&lm_proof);
    lm_response.extend_from_slice(&client_nonce);

    // SessionBaseKey; for NTLMv2 it is also the KeyExchangeKey (MS-NLMP 3.4.5.1).
    let mut session_base_key = hmac_md5_segments(&ntlm_v2_hash_arr, &[&nt_proof]);

    // With KEY_EXCH the client picks a random ExportedSessionKey and sends it
    // RC4-encrypted under the KeyExchangeKey (MS-NLMP 3.1.5.1.2).
    let key_exch = challenge.flags & NEGOTIATE_FLAGS & NTLMSSP_NEGOTIATE_KEY_EXCH != 0;
    let (session_key, encrypted_session_key) = if key_exch {
        let exported = forced_exported_session_key.unwrap_or_else(generate_session_key);
        let mut encrypted = exported;
        crate::crypto::rc4_encrypt(&session_base_key, &mut encrypted);
        (exported, encrypted.to_vec())
    } else {
        (session_base_key, Vec::new())
    };
    zeroize_bytes(&mut session_base_key);

    // Prepare UTF-16LE strings
    let domain_utf16 = utf16le(&creds.domain);
    let user_utf16 = utf16le(&creds.username);
    let workstation_utf16 = utf16le(&creds.workstation);

    // Build buffer descriptors
    let mut buffers = Vec::with_capacity(6 * 8);
    // NEGOTIATE_VERSION is set, so the fixed header is 64 bytes + Version (8) + MIC (16).
    let mut offset = 88u32;

    for buf in [
        lm_response.as_slice(),
        nt_response.as_slice(),
        domain_utf16.as_slice(),
        user_utf16.as_slice(),
        workstation_utf16.as_slice(),
        encrypted_session_key.as_slice(),
    ] {
        let len = buf.len() as u16;
        buffers.extend_from_slice(&len.to_le_bytes()); // Length
        buffers.extend_from_slice(&len.to_le_bytes()); // MaxLength
        buffers.extend_from_slice(&offset.to_le_bytes()); // Offset
        offset += buf.len() as u32;
    }

    // Build Type3 message with placeholder for MIC
    let mut message = Vec::new();
    message.extend_from_slice(NTLMSSP_SIGNATURE);
    message.extend_from_slice(&3u32.to_le_bytes()); // Type 3
    message.extend_from_slice(&buffers); // 6 buffer descriptors (48 bytes)
    message.extend_from_slice(&NEGOTIATE_FLAGS.to_le_bytes()); // Flags (4 bytes)
    message.extend_from_slice(&NTLM_VERSION); // Version (8 bytes)

    // Add 16-byte placeholder for MIC (will be calculated and replaced)
    let mic_offset = message.len();
    message.extend_from_slice(&[0u8; 16]);

    // Add the actual payloads
    message.extend_from_slice(&lm_response);
    message.extend_from_slice(&nt_response);
    message.extend_from_slice(&domain_utf16);
    message.extend_from_slice(&user_utf16);
    message.extend_from_slice(&workstation_utf16);
    message.extend_from_slice(&encrypted_session_key);

    // Calculate MIC if we have all three messages
    if let Some(type1) = type1_message {
        // MIC = HMAC-MD5(ExportedSessionKey, Type1 || Type2 || Type3 with zero MIC)
        let mut mic_data = Vec::new();
        mic_data.extend_from_slice(type1);
        mic_data.extend_from_slice(type2_message);
        mic_data.extend_from_slice(&message); // Type3 with zero MIC

        let mic = hmac_md5_segments(&session_key, &[&mic_data]);
        mic_data.zeroize();

        debug!(
            "MIC calculation: type1_len={}, type2_len={}, type3_len={}, mic={}, mic_offset={}",
            type1.len(),
            type2_message.len(),
            message.len(),
            hex::encode(mic),
            mic_offset
        );

        // Replace the zero MIC with the calculated MIC
        message[mic_offset..mic_offset + 16].copy_from_slice(&mic);
        debug!("Added MIC to Type3 message at offset {}", mic_offset);
    } else {
        debug!("Skipping MIC calculation (Type1 message not available)");
    }

    // Clean up sensitive data
    zeroize_bytes(&mut nt_hash);
    zeroize_bytes(&mut ntlm_v2_hash_arr);
    zeroize_bytes(&mut client_nonce);

    Ok(AuthenticateMessage {
        message,
        session_key,
        negotiate_flags: challenge.flags,
    })
}

fn utf16le(value: &str) -> Vec<u8> {
    value
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect::<Vec<u8>>()
}

/// MsvAvTimestamp (AvId 7) from a CHALLENGE_MESSAGE TargetInfo, if present.
fn av_timestamp(target_info: &[u8]) -> Option<u64> {
    let mut rest = target_info;
    while rest.len() >= 4 {
        let id = u16::from_le_bytes([rest[0], rest[1]]);
        let len = u16::from_le_bytes([rest[2], rest[3]]) as usize;
        let value = rest.get(4..4 + len)?;
        match id {
            0 => return None,
            7 if len == 8 => return Some(u64::from_le_bytes(value.try_into().ok()?)),
            _ => rest = &rest[4 + len..],
        }
    }
    None
}

fn generate_session_key() -> [u8; 16] {
    let mut key = [0u8; 16];
    OsRng.fill_bytes(&mut key);
    key
}

fn current_filetime() -> u64 {
    const WINDOWS_TICK: u64 = 10_000_000; // 100ns intervals per second
    const SEC_TO_UNIX_EPOCH: u64 = 11_644_473_600;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    ((now.as_secs() + SEC_TO_UNIX_EPOCH) * WINDOWS_TICK) + (now.subsec_nanos() as u64 / 100)
}

fn generate_client_nonce() -> [u8; 8] {
    let mut nonce = [0u8; 8];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn md5_hash(data: &[u8]) -> [u8; 16] {
    let result = md5::compute(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&result.0);
    out
}

fn hmac_md5_segments(key: &[u8], segments: &[&[u8]]) -> [u8; 16] {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let hash = md5_hash(key);
        key_block[..16].copy_from_slice(&hash);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let total_len: usize = segments.iter().map(|seg| seg.len()).sum();
    let mut inner = Vec::with_capacity(64 + total_len);
    inner.extend_from_slice(&ipad);
    for segment in segments {
        inner.extend_from_slice(segment);
    }
    let mut inner_hash = md5_hash(&inner);
    inner.zeroize();

    let mut outer = Vec::with_capacity(64 + inner_hash.len());
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    let result = md5_hash(&outer);
    outer.zeroize();

    zeroize_bytes(&mut key_block);
    zeroize_bytes(&mut ipad);
    zeroize_bytes(&mut opad);
    zeroize_bytes(&mut inner_hash);

    result
}

fn zeroize_bytes(bytes: &mut [u8]) {
    for b in bytes {
        *b = 0;
    }
}

#[allow(clippy::ptr_arg)]
fn zeroize_string(value: &mut String) {
    value.zeroize();
}

#[cfg(test)]
pub(crate) fn sample_type2() -> Vec<u8> {
    vec![
        0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0c,
        0x00, 0x30, 0x00, 0x00, 0x00, 0x05, 0x82, 0x8a, 0x82, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x14, 0x00, 0x3c,
        0x00, 0x00, 0x00, 0x02, 0x00, 0x0c, 0x00, 0x44, 0x00, 0x4f, 0x00, 0x4d, 0x00, 0x41, 0x00,
        0x49, 0x00, 0x4e, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x53, 0x00, 0x45, 0x00, 0x52, 0x00, 0x56,
        0x00, 0x45, 0x00, 0x52, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    const TEST_PASSWORD: &str = "Password";

    #[test]
    fn generate_client_nonce_is_randomized() {
        let nonce1 = generate_client_nonce();
        let nonce2 = generate_client_nonce();
        assert!(
            nonce1.iter().any(|&b| b != 0),
            "nonce1 should not be all zeros"
        );
        assert!(
            nonce2.iter().any(|&b| b != 0),
            "nonce2 should not be all zeros"
        );
        assert_ne!(nonce1, nonce2, "sequential nonces should differ");
    }

    #[test]
    fn type1_message_contains_signature() {
        let msg = build_type1_message("DOMAIN", "WORKSTATION");
        assert_eq!(&msg[..8], NTLMSSP_SIGNATURE);
        assert_eq!(u32::from_le_bytes(msg[8..12].try_into().unwrap()), 1);
    }

    #[test]
    fn parse_type2_extracts_challenge() {
        let type2 = sample_type2();
        let parsed = parse_type2_message(&type2).unwrap();
        assert_eq!(
            parsed.server_challenge,
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
        assert_eq!(parsed.target_info.len(), 20);
    }

    #[test]
    fn build_type3_matches_reference() {
        let creds = Credentials::new(
            "User".into(),
            TEST_PASSWORD.into(),
            "Domain".into(),
            "COMPUTER".into(),
        );
        let expected_nt_hash = [
            0xa4, 0xf4, 0x9c, 0x40, 0x65, 0x10, 0xbd, 0xca, 0xb6, 0x82, 0x4e, 0xe7, 0xc3, 0x0f,
            0xd8, 0x52,
        ];
        assert_eq!(
            utf16le(TEST_PASSWORD),
            vec![
                0x50, 0x00, 0x61, 0x00, 0x73, 0x00, 0x73, 0x00, 0x77, 0x00, 0x6f, 0x00, 0x72, 0x00,
                0x64, 0x00,
            ]
        );
        assert_eq!(compute_nt_hash(TEST_PASSWORD), expected_nt_hash);
        let challenge = parse_type2_message(&sample_type2()).unwrap();
        let client_nonce = [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa];
        let timestamp = 0x00000001_6b5de5cd;
        let auth =
            build_type3_message(&creds, &challenge, Some(client_nonce), Some(timestamp)).unwrap();
        assert_eq!(auth.message[..8], NTLMSSP_SIGNATURE[..]);
        assert_eq!(auth.message[8..12], 3u32.to_le_bytes());
        let lm_offset = 64usize;
        let lm = &auth.message[lm_offset..lm_offset + 24];
        assert_eq!(lm.len(), 24);
        assert_eq!(&lm[16..], &client_nonce);
    }

    #[test]
    fn type1_message_encodes_buffers() {
        let msg = build_type1_message("DOMAIN", "WORKSTATION");
        let domain_len = u16::from_le_bytes(msg[16..18].try_into().unwrap()) as usize;
        let domain_offset = u32::from_le_bytes(msg[20..24].try_into().unwrap()) as usize;
        let workstation_len = u16::from_le_bytes(msg[24..26].try_into().unwrap()) as usize;
        let workstation_offset = u32::from_le_bytes(msg[28..32].try_into().unwrap()) as usize;
        let domain_utf16 = utf16le("DOMAIN");
        let workstation_utf16 = utf16le("WORKSTATION");
        assert_eq!(domain_len, domain_utf16.len());
        assert_eq!(workstation_len, workstation_utf16.len());
        assert_eq!(
            &msg[domain_offset..domain_offset + domain_len],
            domain_utf16
        );
        assert_eq!(
            &msg[workstation_offset..workstation_offset + workstation_len],
            workstation_utf16
        );
    }

    #[test]
    fn parse_type2_rejects_short_message() {
        let err = parse_type2_message(b"short").unwrap_err();
        matches!(err, AuthError::InvalidType2);
    }

    #[test]
    fn parse_type2_rejects_bad_signature() {
        let mut bytes = sample_type2();
        bytes[0] = 0x00;
        let err = parse_type2_message(&bytes).unwrap_err();
        matches!(err, AuthError::InvalidType2);
    }

    #[test]
    fn parse_type2_rejects_overflowing_target_info() {
        let mut bytes = sample_type2();
        // Set target info offset past the buffer length.
        let offset = (bytes.len() + 10) as u32;
        bytes[44..48].copy_from_slice(&offset.to_le_bytes());
        let err = parse_type2_message(&bytes).unwrap_err();
        matches!(err, AuthError::InvalidType2);
    }

    #[test]
    fn test_auth_provider_trait_implementation() {
        // Test lines 108-119: AuthProvider trait methods
        let creds = Credentials::new(
            "test".to_string(),
            "pass".to_string(),
            "DOMAIN".to_string(),
            "WORKSTATION".to_string(),
        );
        let mut client = NtlmV2Client::new(creds).unwrap();

        // Test negotiate
        let negotiate_msg = client.negotiate();
        assert!(negotiate_msg.is_ok());
        assert!(!negotiate_msg.unwrap().is_empty());

        // Test respond with valid challenge
        let challenge = sample_type2();
        let response = client.respond(&challenge);
        assert!(response.is_ok());

        // Test session_key after response
        assert!(client.session_key().is_some());
        assert_eq!(client.session_key().unwrap().len(), 16);
    }

    #[test]
    fn test_respond_with_invalid_type2() {
        // Test line 91-94: respond_message error paths
        let creds = Credentials::new(
            "test".to_string(),
            "pass".to_string(),
            "DOMAIN".to_string(),
            "WORKSTATION".to_string(),
        );
        let mut client = NtlmV2Client::new(creds).unwrap();

        // Invalid challenge should fail
        let invalid_challenge = b"invalid";
        let result = client.respond(invalid_challenge);
        assert!(result.is_err());
    }

    #[test]
    fn test_credentials_validation() {
        // Test Credentials validation
        let empty_username = Credentials::new(
            "".to_string(),
            "pass".to_string(),
            "DOMAIN".to_string(),
            "WORKSTATION".to_string(),
        );

        // Validate should fail with empty username
        assert!(empty_username.validate().is_err());
        assert!(matches!(
            empty_username.validate().unwrap_err(),
            AuthError::Creds
        ));

        let empty_password = Credentials::new(
            "user".to_string(),
            "".to_string(),
            "DOMAIN".to_string(),
            "WORKSTATION".to_string(),
        );

        // Validate should fail with empty password
        assert!(empty_password.validate().is_err());
    }

    #[test]
    fn test_parse_type2_with_wrong_message_type() {
        // Test line 154: parse_type2_message checks message type
        let mut bytes = sample_type2();
        // Change message type from 2 to 3
        bytes[8] = 0x03;
        let err = parse_type2_message(&bytes).unwrap_err();
        assert!(matches!(err, AuthError::InvalidType2));
    }

    #[test]
    fn test_build_type3_error_paths() {
        // Test build_type3_message error handling
        let creds = Credentials::new(
            "a".repeat(256), // Very long username
            "pass".to_string(),
            "DOMAIN".to_string(),
            "WORKSTATION".to_string(),
        );
        let challenge = parse_type2_message(&sample_type2()).unwrap();

        // Should still work with long username
        let result = build_type3_message(&creds, &challenge, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_session_key_before_response() {
        // Test line 117-118: session_key returns None before response
        let creds = Credentials::new(
            "test".to_string(),
            "pass".to_string(),
            "DOMAIN".to_string(),
            "WORKSTATION".to_string(),
        );
        let client = NtlmV2Client::new(creds).unwrap();

        // No session key before authentication
        assert!(client.session_key().is_none());
    }

    #[test]
    fn credentials_validation_requires_username_and_password() {
        let creds = Credentials::new(String::new(), "pass".into(), String::new(), "wkst".into());
        assert!(matches!(creds.validate(), Err(AuthError::Creds)));

        let creds = Credentials::new("user".into(), String::new(), String::new(), "wkst".into());
        assert!(matches!(creds.validate(), Err(AuthError::Creds)));
    }

    fn security_buffer(message: &[u8], field: usize) -> &[u8] {
        let at = 12 + 8 * field;
        let len = u16::from_le_bytes([message[at], message[at + 1]]) as usize;
        let off = u32::from_le_bytes(message[at + 4..at + 8].try_into().unwrap()) as usize;
        &message[off..off + len]
    }

    /// MS-NLMP 4.2.4 (NTLMv2 Authentication) published test vectors.
    #[test]
    fn type3_matches_ms_nlmp_ntlmv2_test_vectors() {
        let creds = Credentials::new(
            "User".into(),
            "Password".into(),
            "Domain".into(),
            "COMPUTER".into(),
        );
        let challenge = ChallengeMessage {
            flags: NEGOTIATE_FLAGS,
            server_challenge: hex!("0123456789abcdef"),
            target_info: hex!(
                "02000c0044006f006d00610069006e00"
                "01000c005300650072007600650072000000 0000"
            )
            .to_vec(),
        };
        let auth =
            build_type3_message_with_mic(
                &creds,
                &challenge,
                None,
                &[],
                Some([0xaa; 8]),
                Some(0),
                Some([0x55; 16]),
            )
                .unwrap();
        let msg = &auth.message;

        // Header: Version at 64, MIC at 72, payload from 88.
        assert_eq!(&msg[64..72], &NTLM_VERSION);
        assert_eq!(
            u32::from_le_bytes(msg[16..20].try_into().unwrap()),
            88,
            "LmChallengeResponse offset"
        );

        let nt = security_buffer(msg, 1);
        assert_eq!(
            &nt[..16],
            &hex!("68cd0ab851e51c96aabc927bebef6a1c"),
            "NTProofStr"
        );
        assert_eq!(
            &nt[16..20],
            &[0x01, 0x01, 0x00, 0x00],
            "RespType/HiRespType"
        );
        assert_eq!(
            security_buffer(msg, 0),
            &hex!("86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa"),
            "LMv2 response"
        );
        // SessionBaseKey 8de40ccadbc14a82f15cb0ad0de95ca3 encrypts the
        // RandomSessionKey (55..55) into the EncryptedRandomSessionKey.
        assert_eq!(
            security_buffer(msg, 5),
            &hex!("c5dad2544fc9799094ce1ce90bc9d03e"),
            "EncryptedRandomSessionKey"
        );
        assert_eq!(auth.session_key, [0x55; 16], "ExportedSessionKey");
    }

    #[test]
    fn av_timestamp_reads_msv_av_timestamp() {
        let info = hex!("07000800 4a268755e95fdd01 00000000");
        assert_eq!(av_timestamp(&info), Some(0x01dd5fe95587264a));
        assert_eq!(av_timestamp(&hex!("00000000")), None);
    }

    #[test]
    fn current_filetime_is_after_2020() {
        // 2020-01-01T00:00:00Z as FILETIME
        assert!(current_filetime() > 132_223_104_000_000_000);
    }
}
