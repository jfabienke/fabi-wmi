#![allow(dead_code)]

use std::convert::TryInto;
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;
use tracing::debug;
use zeroize::{Zeroize, ZeroizeOnDrop};

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
        NegotiateMessage {
            message,
        }
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
            None
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
    let domain_upper = creds.domain.to_uppercase();

    let mut password_utf16 = utf16le(creds.password.as_str());
    let mut nt_hash = md4_hash(&password_utf16);
    zeroize_bytes(&mut password_utf16);

    let mut identity = utf16le(&(username_upper.clone() + &domain_upper));
    let ntlm_v2_hash = hmac_md5_segments(&nt_hash, &[&identity]);
    zeroize_bytes(&mut identity);

    let mut ntlm_v2_hash_arr = ntlm_v2_hash;

    let mut client_nonce = if let Some(nonce) = forced_client_nonce {
        nonce
    } else {
        generate_client_nonce()
    };

    let timestamp = forced_timestamp.unwrap_or_else(current_filetime);
    let mut blob = Vec::new();
    blob.extend_from_slice(&0x0101_0000u32.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&timestamp.to_le_bytes());
    blob.extend_from_slice(&client_nonce);
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&challenge.target_info);
    blob.extend_from_slice(&0u32.to_le_bytes());

    let nt_proof = hmac_md5_segments(&ntlm_v2_hash_arr, &[&challenge.server_challenge, &blob]);

    let mut nt_response = Vec::with_capacity(nt_proof.len() + blob.len());
    nt_response.extend_from_slice(&nt_proof);
    nt_response.extend_from_slice(&blob);

    let lm_proof = hmac_md5_segments(
        &ntlm_v2_hash_arr,
        &[&challenge.server_challenge, &client_nonce],
    );

    let mut lm_response = Vec::with_capacity(lm_proof.len() + client_nonce.len());
    lm_response.extend_from_slice(&lm_proof);
    lm_response.extend_from_slice(&client_nonce);

    let session_key_bytes = hmac_md5_segments(&ntlm_v2_hash_arr, &[&nt_proof]);

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
        session_key_bytes.as_slice(),
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
    message.extend_from_slice(&session_key_bytes);

    zeroize_bytes(&mut nt_hash);
    zeroize_bytes(&mut ntlm_v2_hash_arr);
    zeroize_bytes(&mut client_nonce);

    let mut session_key = [0u8; 16];
    session_key.copy_from_slice(&session_key_bytes);

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
) -> Result<AuthenticateMessage, AuthError> {
    let username_upper = creds.username.to_uppercase();
    let domain_upper = creds.domain.to_uppercase();

    let mut password_utf16 = utf16le(creds.password.as_str());
    let mut nt_hash = md4_hash(&password_utf16);
    zeroize_bytes(&mut password_utf16);

    let mut identity = utf16le(&(username_upper.clone() + &domain_upper));
    let ntlm_v2_hash = hmac_md5_segments(&nt_hash, &[&identity]);
    zeroize_bytes(&mut identity);

    let mut ntlm_v2_hash_arr = ntlm_v2_hash;

    let mut client_nonce = if let Some(nonce) = forced_client_nonce {
        nonce
    } else {
        generate_client_nonce()
    };

    let timestamp = forced_timestamp.unwrap_or_else(current_filetime);

    // Build the NTLMv2 blob
    let mut blob = Vec::new();
    blob.extend_from_slice(&0x0101_0000u32.to_le_bytes()); // RespType and HiRespType
    blob.extend_from_slice(&0u32.to_le_bytes()); // Reserved1
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

    // Calculate LM response
    let lm_proof = hmac_md5_segments(
        &ntlm_v2_hash_arr,
        &[&challenge.server_challenge, &client_nonce],
    );

    let mut lm_response = Vec::with_capacity(lm_proof.len() + client_nonce.len());
    lm_response.extend_from_slice(&lm_proof);
    lm_response.extend_from_slice(&client_nonce);

    // Calculate session key
    let session_key_bytes = hmac_md5_segments(&ntlm_v2_hash_arr, &[&nt_proof]);

    // Prepare UTF-16LE strings
    let domain_utf16 = utf16le(&creds.domain);
    let user_utf16 = utf16le(&creds.username);
    let workstation_utf16 = utf16le(&creds.workstation);

    // Build buffer descriptors
    let mut buffers = Vec::with_capacity(6 * 8);
    let mut offset = 80u32; // Start after header (64 bytes) + MIC (16 bytes)

    for buf in [
        lm_response.as_slice(),
        nt_response.as_slice(),
        domain_utf16.as_slice(),
        user_utf16.as_slice(),
        workstation_utf16.as_slice(),
        session_key_bytes.as_slice(),
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

    // Add 16-byte placeholder for MIC (will be calculated and replaced)
    let mic_offset = message.len();
    message.extend_from_slice(&[0u8; 16]);

    // Add the actual payloads
    message.extend_from_slice(&lm_response);
    message.extend_from_slice(&nt_response);
    message.extend_from_slice(&domain_utf16);
    message.extend_from_slice(&user_utf16);
    message.extend_from_slice(&workstation_utf16);
    message.extend_from_slice(&session_key_bytes);

    // Calculate MIC if we have all three messages
    if let Some(type1) = type1_message {
        // MIC = HMAC-MD5(session_key, concatenation of Type1, Type2, and Type3 with zero MIC)
        let mut mic_data = Vec::new();
        mic_data.extend_from_slice(type1);
        mic_data.extend_from_slice(type2_message);
        mic_data.extend_from_slice(&message); // Type3 with zero MIC

        let mic = hmac_md5_segments(&session_key_bytes, &[&mic_data]);

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

    let mut session_key = [0u8; 16];
    session_key.copy_from_slice(&session_key_bytes);

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

fn current_filetime() -> u64 {
    const WINDOWS_TICK: u64 = 10_000;
    const SEC_TO_UNIX_EPOCH: u64 = 11_644_473_600;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    ((now.as_secs() + SEC_TO_UNIX_EPOCH) * WINDOWS_TICK) + (now.subsec_nanos() as u64 / 100)
}

fn generate_client_nonce() -> [u8; 8] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut seed = [0u8; 16];
    seed[..8].copy_from_slice(&now.as_secs().to_le_bytes());
    seed[8..12].copy_from_slice(&now.subsec_nanos().to_le_bytes());
    seed[12..].copy_from_slice(&std::process::id().to_le_bytes());
    let digest = md5_hash(&seed);
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&digest[..8]);
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
    let inner_hash = md5_hash(&inner);

    let mut outer = Vec::with_capacity(64 + inner_hash.len());
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    let result = md5_hash(&outer);

    zeroize_bytes(&mut key_block);
    zeroize_bytes(&mut ipad);
    zeroize_bytes(&mut opad);

    result
}

fn zeroize_bytes(bytes: &mut [u8]) {
    for b in bytes {
        *b = 0;
    }
}

#[allow(clippy::ptr_arg)]
fn zeroize_string(value: &mut String) {
    unsafe {
        let bytes = value.as_bytes_mut();
        zeroize_bytes(bytes);
    }
}

fn md4_hash(data: &[u8]) -> [u8; 16] {
    let mut message = data.to_vec();
    let bit_len = (message.len() as u64) * 8;
    message.push(0x80);
    while (message.len() % 64) != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_le_bytes());

    let mut a = 0x67452301u32;
    let mut b = 0xefcdab89u32;
    let mut c = 0x98badcfeu32;
    let mut d = 0x10325476u32;

    for chunk in message.chunks(64) {
        let mut x = [0u32; 16];
        for i in 0..16 {
            x[i] = u32::from_le_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }

        let (mut aa, mut bb, mut cc, mut dd) = (a, b, c, d);

        ff(&mut aa, bb, cc, dd, x[0], 3);
        ff(&mut dd, aa, bb, cc, x[1], 7);
        ff(&mut cc, dd, aa, bb, x[2], 11);
        ff(&mut bb, cc, dd, aa, x[3], 19);
        ff(&mut aa, bb, cc, dd, x[4], 3);
        ff(&mut dd, aa, bb, cc, x[5], 7);
        ff(&mut cc, dd, aa, bb, x[6], 11);
        ff(&mut bb, cc, dd, aa, x[7], 19);
        ff(&mut aa, bb, cc, dd, x[8], 3);
        ff(&mut dd, aa, bb, cc, x[9], 7);
        ff(&mut cc, dd, aa, bb, x[10], 11);
        ff(&mut bb, cc, dd, aa, x[11], 19);
        ff(&mut aa, bb, cc, dd, x[12], 3);
        ff(&mut dd, aa, bb, cc, x[13], 7);
        ff(&mut cc, dd, aa, bb, x[14], 11);
        ff(&mut bb, cc, dd, aa, x[15], 19);

        gg(&mut aa, bb, cc, dd, x[0], 3);
        gg(&mut dd, aa, bb, cc, x[4], 5);
        gg(&mut cc, dd, aa, bb, x[8], 9);
        gg(&mut bb, cc, dd, aa, x[12], 13);
        gg(&mut aa, bb, cc, dd, x[1], 3);
        gg(&mut dd, aa, bb, cc, x[5], 5);
        gg(&mut cc, dd, aa, bb, x[9], 9);
        gg(&mut bb, cc, dd, aa, x[13], 13);
        gg(&mut aa, bb, cc, dd, x[2], 3);
        gg(&mut dd, aa, bb, cc, x[6], 5);
        gg(&mut cc, dd, aa, bb, x[10], 9);
        gg(&mut bb, cc, dd, aa, x[14], 13);
        gg(&mut aa, bb, cc, dd, x[3], 3);
        gg(&mut dd, aa, bb, cc, x[7], 5);
        gg(&mut cc, dd, aa, bb, x[11], 9);
        gg(&mut bb, cc, dd, aa, x[15], 13);

        hh(&mut aa, bb, cc, dd, x[0], 3);
        hh(&mut dd, aa, bb, cc, x[8], 9);
        hh(&mut cc, dd, aa, bb, x[4], 11);
        hh(&mut bb, cc, dd, aa, x[12], 15);
        hh(&mut aa, bb, cc, dd, x[2], 3);
        hh(&mut dd, aa, bb, cc, x[10], 9);
        hh(&mut cc, dd, aa, bb, x[6], 11);
        hh(&mut bb, cc, dd, aa, x[14], 15);
        hh(&mut aa, bb, cc, dd, x[1], 3);
        hh(&mut dd, aa, bb, cc, x[9], 9);
        hh(&mut cc, dd, aa, bb, x[5], 11);
        hh(&mut bb, cc, dd, aa, x[13], 15);
        hh(&mut aa, bb, cc, dd, x[3], 3);
        hh(&mut dd, aa, bb, cc, x[11], 9);
        hh(&mut cc, dd, aa, bb, x[7], 11);
        hh(&mut bb, cc, dd, aa, x[15], 15);

        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);
    }

    let mut out = [0u8; 16];
    out[..4].copy_from_slice(&a.to_le_bytes());
    out[4..8].copy_from_slice(&b.to_le_bytes());
    out[8..12].copy_from_slice(&c.to_le_bytes());
    out[12..].copy_from_slice(&d.to_le_bytes());
    out
}

fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | ((!x) & z)
}

fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn ff(a: &mut u32, b: u32, c: u32, d: u32, x: u32, s: u32) {
    *a = a.wrapping_add(f(b, c, d)).wrapping_add(x).rotate_left(s);
}

fn gg(a: &mut u32, b: u32, c: u32, d: u32, x: u32, s: u32) {
    *a = a
        .wrapping_add(g(b, c, d))
        .wrapping_add(x)
        .wrapping_add(0x5a827999)
        .rotate_left(s);
}

fn hh(a: &mut u32, b: u32, c: u32, d: u32, x: u32, s: u32) {
    *a = a
        .wrapping_add(h(b, c, d))
        .wrapping_add(x)
        .wrapping_add(0x6ed9eba1)
        .rotate_left(s);
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
            "Password".into(),
            "Domain".into(),
            "COMPUTER".into(),
        );
        let expected_nt_hash = [
            0xa4, 0xf4, 0x9c, 0x40, 0x65, 0x10, 0xbd, 0xca, 0xb6, 0x82, 0x4e, 0xe7, 0xc3, 0x0f,
            0xd8, 0x52,
        ];
        assert_eq!(
            utf16le(creds.password.as_str()),
            vec![
                0x50, 0x00, 0x61, 0x00, 0x73, 0x00, 0x73, 0x00, 0x77, 0x00, 0x6f, 0x00, 0x72, 0x00,
                0x64, 0x00,
            ]
        );
        assert_eq!(md4_hash(&utf16le(creds.password.as_str())), expected_nt_hash);
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
        assert!(matches!(empty_username.validate().unwrap_err(), AuthError::Creds));

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
        let creds = Credentials::new(
            String::new(),
            "pass".into(),
            String::new(),
            "wkst".into(),
        );
        assert!(matches!(creds.validate(), Err(AuthError::Creds)));

        let creds = Credentials::new(
            "user".into(),
            String::new(),
            String::new(),
            "wkst".into(),
        );
        assert!(matches!(creds.validate(), Err(AuthError::Creds)));
    }
}
