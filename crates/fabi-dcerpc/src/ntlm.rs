//! NTLMv2 client (MS-NLMP) for DCE/RPC: the NEGOTIATE / CHALLENGE /
//! AUTHENTICATE handshake, then signing and sealing each PDU with extended
//! session security.
//!
//! Only what Windows offers DCE/RPC clients is supported: NTLMv2 with
//! extended session security, 128-bit keys and key exchange. A server that
//! does not agree to all of them is refused rather than met with a weaker
//! scheme.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use md4::{Digest, Md4};
use md5::Md5;
use zeroize::{Zeroize, Zeroizing};

use crate::auth::{AuthError, AuthProvider, Credentials, AUTH_TYPE_NTLM};

const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
const NEGOTIATE_MESSAGE: u32 = 1;
const CHALLENGE_MESSAGE: u32 = 2;
const AUTHENTICATE_MESSAGE: u32 = 3;

// NegotiateFlags (MS-NLMP 2.2.2.5).
const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
const REQUEST_TARGET: u32 = 0x0000_0004;
const NEGOTIATE_SIGN: u32 = 0x0000_0010;
const NEGOTIATE_SEAL: u32 = 0x0000_0020;
const NEGOTIATE_NTLM: u32 = 0x0000_0200;
const NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
const NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
const NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
const NEGOTIATE_VERSION: u32 = 0x0200_0000;
const NEGOTIATE_128: u32 = 0x2000_0000;
const NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
const NEGOTIATE_56: u32 = 0x8000_0000;

/// The flags the client asks for, and sends again in AUTHENTICATE. They are
/// the flags of the AUTHENTICATE message in MS-NLMP's NTLMv2 example
/// (4.2.4.3).
const CLIENT_FLAGS: u32 = NEGOTIATE_UNICODE
    | REQUEST_TARGET
    | NEGOTIATE_SIGN
    | NEGOTIATE_SEAL
    | NEGOTIATE_NTLM
    | NEGOTIATE_ALWAYS_SIGN
    | NEGOTIATE_EXTENDED_SESSIONSECURITY
    | NEGOTIATE_TARGET_INFO
    | NEGOTIATE_VERSION
    | NEGOTIATE_128
    | NEGOTIATE_KEY_EXCH
    | NEGOTIATE_56;

/// What the server must agree to. Without any of these the keys would be
/// weaker, or the PDUs protected by an older scheme this client lacks.
const REQUIRED_FLAGS: [(u32, &str); 6] = [
    (NEGOTIATE_UNICODE, "Unicode"),
    (NEGOTIATE_SIGN, "signing"),
    (NEGOTIATE_SEAL, "sealing"),
    (
        NEGOTIATE_EXTENDED_SESSIONSECURITY,
        "extended session security",
    ),
    (NEGOTIATE_128, "128-bit keys"),
    (NEGOTIATE_KEY_EXCH, "key exchange"),
];

/// The Version field (MS-NLMP 2.2.2.10): Windows 10.0, NTLMSSP revision 15.
const VERSION: [u8; 8] = [10, 0, 0, 0, 0, 0, 0, 15];

// AvId values (MS-NLMP 2.2.2.1).
const AV_EOL: u16 = 0;
const AV_NB_COMPUTER_NAME: u16 = 1;
const AV_NB_DOMAIN_NAME: u16 = 2;
const AV_FLAGS: u16 = 6;
const AV_TIMESTAMP: u16 = 7;
const AV_CHANNEL_BINDINGS: u16 = 10;
/// MsvAvFlags bit: the AUTHENTICATE message carries a MIC.
const AV_FLAG_MIC: u32 = 0x0000_0002;

/// Where AUTHENTICATE's MIC sits: after the fixed fields and the Version.
const MIC_AT: usize = 72;
/// Where AUTHENTICATE's payload starts: after the MIC.
const PAYLOAD_AT: usize = MIC_AT + 16;

const CLIENT_SIGNING: &[u8] = b"session key to client-to-server signing key magic constant\0";
const SERVER_SIGNING: &[u8] = b"session key to server-to-client signing key magic constant\0";
const CLIENT_SEALING: &[u8] = b"session key to client-to-server sealing key magic constant\0";
const SERVER_SEALING: &[u8] = b"session key to server-to-client sealing key magic constant\0";

/// Byte length of a message signature (MS-NLMP 2.2.2.9.1).
const SIGNATURE_LEN: usize = 16;

/// An NTLMv2 security context for one RPC presentation context.
///
/// The password is hashed when the client is created and not kept.
pub struct NtlmClient {
    user: String,
    domain: String,
    workstation: String,
    /// NTOWFv2 of the credentials: the key every response is computed with.
    response_key: Zeroizing<[u8; 16]>,
    state: State,
}

enum State {
    Initial,
    /// NEGOTIATE was sent; the MIC covers it.
    Negotiated(Vec<u8>),
    Established(Box<Session>),
    /// A handshake step failed or ran out of order.
    Failed,
}

impl NtlmClient {
    pub fn new(creds: &Credentials) -> Result<Self, AuthError> {
        creds.validate()?;
        Ok(Self {
            user: creds.username.clone(),
            domain: creds.domain.clone(),
            workstation: local_workstation_name(),
            response_key: ntowf_v2(&creds.password, &creds.username, &creds.domain),
            state: State::Initial,
        })
    }

    fn session(&mut self) -> Result<&mut Session, AuthError> {
        match &mut self.state {
            State::Established(session) => Ok(session),
            _ => Err(AuthError::Protection(
                "the NTLM handshake has not completed".into(),
            )),
        }
    }

    fn authenticate(
        &self,
        negotiate: &[u8],
        challenge_msg: &[u8],
    ) -> Result<(Vec<u8>, Session), AuthError> {
        let challenge = parse_challenge(challenge_msg)?;
        let missing: Vec<&str> = REQUIRED_FLAGS
            .iter()
            .filter(|(flag, _)| challenge.flags & flag == 0)
            .map(|&(_, name)| name)
            .collect();
        if !missing.is_empty() {
            return Err(AuthError::Protection(format!(
                "the NTLM server did not agree to {}",
                missing.join(", ")
            )));
        }
        let server_pairs = av_pairs(challenge.target_info)?;
        // MS-NLMP 3.1.5.1.2: without both NetBIOS names, fail the logon.
        let has = |id| server_pairs.iter().any(|&(pair, _)| pair == id);
        if !has(AV_NB_COMPUTER_NAME) || !has(AV_NB_DOMAIN_NAME) {
            return Err(AuthError::Protection(
                "the NTLM challenge lacks the server's NetBIOS names".into(),
            ));
        }
        let timestamp = server_pairs
            .iter()
            .find(|&&(id, _)| id == AV_TIMESTAMP)
            .and_then(|&(_, value)| value.try_into().ok())
            .map(u64::from_le_bytes);

        let client_challenge: [u8; 8] = random()?;
        let exported_key = Zeroizing::new(random::<16>()?);
        let (nt_response, session_base_key) = ntlmv2_response(
            &self.response_key,
            &challenge.server_challenge,
            &client_challenge,
            timestamp.unwrap_or_else(now_filetime),
            &client_av_pairs(&server_pairs),
        );
        // NTLMv2's KeyExchangeKey is the SessionBaseKey (MS-NLMP 3.4.5.1).
        let mut encrypted_key = *exported_key;
        Rc4::new(&session_base_key).apply(&mut encrypted_key);
        // With a server timestamp the LM response is Z(24) (MS-NLMP 3.1.5.1.2).
        let lm_response = match timestamp {
            Some(_) => [0; 24],
            None => lmv2_response(
                &self.response_key,
                &challenge.server_challenge,
                &client_challenge,
            ),
        };

        let mut message = authenticate_message(&[
            &lm_response,
            &nt_response,
            &utf16le(&self.domain),
            &utf16le(&self.user),
            &utf16le(&self.workstation),
            &encrypted_key,
        ])?;
        let mic = hmac_md5(&*exported_key, &[negotiate, challenge_msg, &message]);
        message[MIC_AT..PAYLOAD_AT].copy_from_slice(&mic);
        Ok((message, Session::client(&exported_key)))
    }
}

impl AuthProvider for NtlmClient {
    fn auth_type(&self) -> u8 {
        AUTH_TYPE_NTLM
    }

    fn auth_value_len(
        &mut self,
        _sealed: bool,
        _padded_stub_len: usize,
    ) -> Result<usize, AuthError> {
        Ok(SIGNATURE_LEN)
    }

    fn negotiate(&mut self) -> Result<Vec<u8>, AuthError> {
        if !matches!(self.state, State::Initial) {
            self.state = State::Failed;
            return Err(AuthError::Protection("NTLM negotiate sent twice".into()));
        }
        let message = negotiate_message();
        self.state = State::Negotiated(message.clone());
        Ok(message)
    }

    fn respond(&mut self, challenge: &[u8]) -> Result<Vec<u8>, AuthError> {
        let State::Negotiated(negotiate) = std::mem::replace(&mut self.state, State::Failed) else {
            return Err(AuthError::Protection(
                "NTLM challenge arrived out of order".into(),
            ));
        };
        let (message, session) = self.authenticate(&negotiate, challenge)?;
        self.state = State::Established(Box::new(session));
        Ok(message)
    }

    fn sign_rpc(
        &mut self,
        header: &[u8],
        stub: &[u8],
        sec_trailer: &[u8],
    ) -> Result<Vec<u8>, AuthError> {
        let send = &mut self.session()?.send;
        let checksum = send.checksum(&[header, stub, sec_trailer]);
        Ok(send.signature(checksum).to_vec())
    }

    fn seal_rpc(
        &mut self,
        header: &[u8],
        stub: &mut [u8],
        sec_trailer: &[u8],
    ) -> Result<Vec<u8>, AuthError> {
        let send = &mut self.session()?.send;
        // The signature covers the plaintext (MS-NLMP 3.4.3).
        let checksum = send.checksum(&[header, stub, sec_trailer]);
        send.sealing.apply(stub);
        Ok(send.signature(checksum).to_vec())
    }

    fn verify_rpc(
        &mut self,
        header: &[u8],
        stub: &[u8],
        sec_trailer: &[u8],
        auth_value: &[u8],
    ) -> Result<(), AuthError> {
        let recv = &mut self.session()?.recv;
        let checksum = recv.checksum(&[header, stub, sec_trailer]);
        check_signature(&recv.signature(checksum), auth_value)
    }

    fn unseal_rpc(
        &mut self,
        header: &[u8],
        stub: &mut [u8],
        sec_trailer: &[u8],
        auth_value: &[u8],
    ) -> Result<(), AuthError> {
        let recv = &mut self.session()?.recv;
        recv.sealing.apply(stub);
        let checksum = recv.checksum(&[header, stub, sec_trailer]);
        check_signature(&recv.signature(checksum), auth_value)
    }
}

/// Compare signatures in constant time, so timing reveals nothing about the
/// expected one.
fn check_signature(expected: &[u8; SIGNATURE_LEN], received: &[u8]) -> Result<(), AuthError> {
    let differs = received.len() != SIGNATURE_LEN
        || expected
            .iter()
            .zip(received)
            .fold(0, |acc, (a, b)| acc | (a ^ b))
            != 0;
    if differs {
        return Err(AuthError::Protection("NTLM signature mismatch".into()));
    }
    Ok(())
}

/// The keys and state of an established context, one set per direction.
struct Session {
    send: Direction,
    recv: Direction,
}

impl Session {
    fn client(exported_key: &[u8; 16]) -> Self {
        Self {
            send: Direction::new(exported_key, CLIENT_SIGNING, CLIENT_SEALING),
            recv: Direction::new(exported_key, SERVER_SIGNING, SERVER_SEALING),
        }
    }
}

struct Direction {
    signing_key: [u8; 16],
    /// One RC4 stream for the whole direction: every sealed stub and every
    /// signature's checksum continues it.
    sealing: Rc4,
    seq: u32,
}

impl Drop for Direction {
    fn drop(&mut self) {
        // `sealing` wipes itself.
        self.signing_key.zeroize();
        self.seq.zeroize();
    }
}

impl Direction {
    /// SIGNKEY and SEALKEY with extended session security and 128-bit keys
    /// (MS-NLMP 3.4.5.2, 3.4.5.3).
    fn new(exported_key: &[u8; 16], signing_magic: &[u8], sealing_magic: &[u8]) -> Self {
        Self {
            signing_key: md5(&[exported_key, signing_magic]),
            sealing: Rc4::new(&Zeroizing::new(md5(&[exported_key, sealing_magic]))),
            seq: 0,
        }
    }

    /// HMAC_MD5(SigningKey, SeqNum || message)[0..8] (MS-NLMP 3.4.4.2).
    fn checksum(&self, message: &[&[u8]]) -> [u8; 8] {
        let seq = self.seq.to_le_bytes();
        let parts: Vec<&[u8]> = std::iter::once(&seq[..])
            .chain(message.iter().copied())
            .collect();
        let digest = hmac_md5(&self.signing_key, &parts);
        digest[..8].try_into().expect("8 of 16 bytes")
    }

    /// The signature for the message `checksum` was computed over: version 1,
    /// the checksum encrypted with the sealing stream (key exchange is always
    /// negotiated), and the sequence number, which then moves on.
    fn signature(&mut self, mut checksum: [u8; 8]) -> [u8; SIGNATURE_LEN] {
        self.sealing.apply(&mut checksum);
        let mut signature = [0; SIGNATURE_LEN];
        signature[..4].copy_from_slice(&1u32.to_le_bytes());
        signature[4..12].copy_from_slice(&checksum);
        signature[12..].copy_from_slice(&self.seq.to_le_bytes());
        self.seq = self.seq.wrapping_add(1);
        signature
    }
}

/// RC4, the cipher NTLM seals with, keeping its state across messages.
struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Drop for Rc4 {
    fn drop(&mut self) {
        self.s.zeroize();
        self.i.zeroize();
        self.j.zeroize();
    }
}

impl Rc4 {
    fn new(key: &[u8; 16]) -> Self {
        let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, usize::from(j));
        }
        Self { s, i: 0, j: 0 }
    }

    fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[usize::from(self.i)]);
            self.s.swap(usize::from(self.i), usize::from(self.j));
            let k = self.s[usize::from(self.i)].wrapping_add(self.s[usize::from(self.j)]);
            *byte ^= self.s[usize::from(k)];
        }
    }
}

/// NEGOTIATE_MESSAGE (MS-NLMP 2.2.1.1), with no domain or workstation
/// supplied.
fn negotiate_message() -> Vec<u8> {
    const LEN: usize = 40;
    let mut message = Vec::with_capacity(LEN);
    message.extend_from_slice(SIGNATURE);
    message.extend_from_slice(&NEGOTIATE_MESSAGE.to_le_bytes());
    message.extend_from_slice(&CLIENT_FLAGS.to_le_bytes());
    for _ in 0..2 {
        push_field(&mut message, 0, LEN);
    }
    message.extend_from_slice(&VERSION);
    message
}

/// The parts of a CHALLENGE_MESSAGE (MS-NLMP 2.2.1.2) the client uses.
struct Challenge<'a> {
    flags: u32,
    server_challenge: [u8; 8],
    target_info: &'a [u8],
}

fn parse_challenge(message: &[u8]) -> Result<Challenge<'_>, AuthError> {
    let malformed = || AuthError::Protection("the NTLM challenge is malformed".into());
    if message.get(..8) != Some(&SIGNATURE[..]) || u32_at(message, 8) != Some(CHALLENGE_MESSAGE) {
        return Err(malformed());
    }
    Ok(Challenge {
        flags: u32_at(message, 20).ok_or_else(malformed)?,
        server_challenge: message
            .get(24..32)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(malformed)?,
        target_info: field(message, 40).ok_or_else(malformed)?,
    })
}

/// The AV_PAIRs of a TargetInfo field (MS-NLMP 2.2.2.1) before MsvAvEOL.
fn av_pairs(mut info: &[u8]) -> Result<Vec<(u16, &[u8])>, AuthError> {
    let malformed =
        || AuthError::Protection("the NTLM challenge's target info is malformed".into());
    let mut pairs = Vec::new();
    loop {
        let id = u16_at(info, 0).ok_or_else(malformed)?;
        let len = usize::from(u16_at(info, 2).ok_or_else(malformed)?);
        let value = info.get(4..4 + len).ok_or_else(malformed)?;
        if id == AV_EOL {
            return Ok(pairs);
        }
        pairs.push((id, value));
        info = &info[4 + len..];
    }
}

/// The client's AV_PAIRs in its NTLMv2 response: the server's, with the MIC
/// bit set in MsvAvFlags and an all-zero MsvAvChannelBindings (there is no
/// TLS channel to bind to), as MS-NLMP 3.1.5.1.2 has clients send them.
fn client_av_pairs(server_pairs: &[(u16, &[u8])]) -> Vec<u8> {
    let mut flags = AV_FLAG_MIC;
    let mut info = Vec::new();
    for &(id, value) in server_pairs {
        match id {
            AV_FLAGS => {
                if let Ok(bits) = value.try_into() {
                    flags |= u32::from_le_bytes(bits);
                }
            }
            AV_CHANNEL_BINDINGS => {}
            _ => push_av_pair(&mut info, id, value),
        }
    }
    push_av_pair(&mut info, AV_FLAGS, &flags.to_le_bytes());
    push_av_pair(&mut info, AV_CHANNEL_BINDINGS, &[0; 16]);
    push_av_pair(&mut info, AV_EOL, &[]);
    info
}

/// `value` is at most a u16 long: it came from a parsed pair or is ours.
fn push_av_pair(info: &mut Vec<u8>, id: u16, value: &[u8]) {
    info.extend_from_slice(&id.to_le_bytes());
    info.extend_from_slice(&(value.len() as u16).to_le_bytes());
    info.extend_from_slice(value);
}

/// NTOWFv2 (MS-NLMP 3.3.2): HMAC_MD5(MD4(UNICODE(password)),
/// UNICODE(Uppercase(user) || domain)).
fn ntowf_v2(password: &str, user: &str, domain: &str) -> Zeroizing<[u8; 16]> {
    let password = Zeroizing::new(utf16le(password));
    let nt_hash = Zeroizing::<[u8; 16]>::new(Md4::digest(&*password).into());
    let identity = utf16le(&(upcase(user) + domain));
    Zeroizing::new(hmac_md5(&*nt_hash, &[&identity]))
}

/// Uppercase as Windows does for NTOWFv2: character for character, so one
/// whose uppercase is longer (such as ß) stays as it is.
fn upcase(s: &str) -> String {
    s.chars()
        .map(|c| {
            let mut upper = c.to_uppercase();
            match (upper.next(), upper.next()) {
                (Some(u), None) => u,
                _ => c,
            }
        })
        .collect()
}

/// NTChallengeResponse and SessionBaseKey (MS-NLMP 3.3.2).
fn ntlmv2_response(
    response_key: &[u8; 16],
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
    timestamp: u64,
    av_pairs: &[u8],
) -> (Vec<u8>, Zeroizing<[u8; 16]>) {
    let mut temp = Vec::with_capacity(28 + av_pairs.len() + 4);
    temp.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0]); // RespType, HiRespType, Z(6)
    temp.extend_from_slice(&timestamp.to_le_bytes());
    temp.extend_from_slice(client_challenge);
    temp.extend_from_slice(&[0; 4]);
    temp.extend_from_slice(av_pairs);
    temp.extend_from_slice(&[0; 4]);
    let proof = hmac_md5(response_key, &[server_challenge, &temp]);
    let session_base_key = Zeroizing::new(hmac_md5(response_key, &[&proof]));
    ([&proof[..], &temp].concat(), session_base_key)
}

/// LmChallengeResponse for NTLMv2 (MS-NLMP 3.3.2).
fn lmv2_response(
    response_key: &[u8; 16],
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
) -> [u8; 24] {
    let mut response = [0; 24];
    response[..16].copy_from_slice(&hmac_md5(
        response_key,
        &[server_challenge, client_challenge],
    ));
    response[16..].copy_from_slice(client_challenge);
    response
}

/// AUTHENTICATE_MESSAGE (MS-NLMP 2.2.1.3) with a zero MIC. `fields` are, in
/// header order: LmChallengeResponse, NtChallengeResponse, DomainName,
/// UserName, Workstation, EncryptedRandomSessionKey.
fn authenticate_message(fields: &[&[u8]; 6]) -> Result<Vec<u8>, AuthError> {
    // The payload order of MS-NLMP's example: domain, user, workstation,
    // then the responses and the key.
    const PAYLOAD_ORDER: [usize; 6] = [2, 3, 4, 0, 1, 5];
    let mut offsets = [0; 6];
    let mut at = PAYLOAD_AT;
    for i in PAYLOAD_ORDER {
        if fields[i].len() > usize::from(u16::MAX) {
            return Err(AuthError::Protection(
                "an NTLM authenticate field is too long".into(),
            ));
        }
        offsets[i] = at;
        at += fields[i].len();
    }
    let mut message = Vec::with_capacity(at);
    message.extend_from_slice(SIGNATURE);
    message.extend_from_slice(&AUTHENTICATE_MESSAGE.to_le_bytes());
    for (field, offset) in fields.iter().zip(offsets) {
        push_field(&mut message, field.len(), offset);
    }
    message.extend_from_slice(&CLIENT_FLAGS.to_le_bytes());
    message.extend_from_slice(&VERSION);
    message.extend_from_slice(&[0; 16]); // MIC
    for i in PAYLOAD_ORDER {
        message.extend_from_slice(fields[i]);
    }
    Ok(message)
}

/// A field descriptor: Len and MaxLen (u16), BufferOffset (u32). Callers keep
/// `len` within a u16.
fn push_field(message: &mut Vec<u8>, len: usize, offset: usize) {
    let len = (len as u16).to_le_bytes();
    message.extend_from_slice(&len);
    message.extend_from_slice(&len);
    message.extend_from_slice(&(offset as u32).to_le_bytes());
}

/// The bytes a field descriptor at `at` points to.
fn field(message: &[u8], at: usize) -> Option<&[u8]> {
    let len = usize::from(u16_at(message, at)?);
    let offset = usize::try_from(u32_at(message, at + 4)?).ok()?;
    message.get(offset..offset.checked_add(len)?)
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mut mac =
        <Hmac<Md5> as KeyInit>::new_from_slice(key).expect("HMAC takes keys of any length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

fn md5(parts: &[&[u8]]) -> [u8; 16] {
    let mut hasher = Md5::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn random<const N: usize>() -> Result<[u8; N], AuthError> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes)
        .map_err(|err| AuthError::Protection(format!("no random bytes for NTLM: {err}")))?;
    Ok(bytes)
}

/// Now as a FILETIME: 100-nanosecond ticks since 1601-01-01.
fn now_filetime() -> u64 {
    const UNIX_EPOCH_AS_FILETIME: u64 = 116_444_736_000_000_000;
    let since_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    UNIX_EPOCH_AS_FILETIME + (since_unix.as_nanos() / 100) as u64
}

/// NetBIOS-style name of this machine for the AUTHENTICATE Workstation field.
fn local_workstation_name() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: buf is valid for buf.len() bytes; gethostname NUL-terminates on success.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    let host = if rc == 0 {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).into_owned()
    } else {
        String::new()
    };
    // Short name only: NetBIOS names stop at the first dot.
    match host.split('.').next().map(str::to_uppercase) {
        Some(name) if !name.is_empty() => name,
        _ => "LINUX-WMI".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{
        build_sealed_request_pdu, build_signed_request_pdu, unseal_response_pdu,
        verify_signed_response_pdu,
    };
    use hex_literal::hex;

    /// The TargetInfo of MS-NLMP's NTLMv2 example (4.2.4): NetBIOS domain
    /// "Domain" and server "Server", no timestamp.
    const SPEC_TARGET_INFO: [u8; 36] = hex!(
        "02000c0044006f006d00610069006e00"
        "01000c0053006500720076006500720000000000"
    );
    const TIMESTAMP: u64 = 0x01dd_5fe9_5587_264a;

    #[test]
    fn ntowf_v2_matches_ms_nlmp() {
        assert_eq!(
            *ntowf_v2("Password", "User", "Domain"),
            hex!("0c868a403bfd7a93a3001ef22ef02e3f")
        );
    }

    #[test]
    fn responses_and_key_exchange_match_ms_nlmp() {
        let key = ntowf_v2("Password", "User", "Domain");
        let server_challenge = hex!("0123456789abcdef");
        let client_challenge = [0xaa; 8];
        assert_eq!(
            lmv2_response(&key, &server_challenge, &client_challenge),
            hex!("86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa")
        );
        let (nt_response, session_base_key) = ntlmv2_response(
            &key,
            &server_challenge,
            &client_challenge,
            0,
            &SPEC_TARGET_INFO,
        );
        assert_eq!(
            nt_response[..16],
            hex!("68cd0ab851e51c96aabc927bebef6a1c"),
            "NTProofStr"
        );
        let temp = [
            &hex!("01010000000000000000000000000000aaaaaaaaaaaaaaaa00000000")[..],
            &SPEC_TARGET_INFO,
            &[0; 4],
        ]
        .concat();
        assert_eq!(nt_response[16..], temp);
        assert_eq!(*session_base_key, hex!("8de40ccadbc14a82f15cb0ad0de95ca3"));
        let mut random_session_key = [0x55; 16];
        Rc4::new(&session_base_key).apply(&mut random_session_key);
        assert_eq!(
            random_session_key,
            hex!("c5dad2544fc9799094ce1ce90bc9d03e"),
            "EncryptedRandomSessionKey"
        );
    }

    #[test]
    fn sealing_matches_ms_nlmp() {
        // The GSS_WrapEx example (4.2.4.4): RandomSessionKey 55..55, SeqNum 0.
        let exported_key = [0x55; 16];
        assert_eq!(
            md5(&[&exported_key, CLIENT_SEALING]),
            hex!("59f600973cc4960a25480a7c196e4c58")
        );
        let mut client = established(Session::client(&exported_key));
        let Ok(session) = client.session() else {
            unreachable!()
        };
        assert_eq!(
            session.send.signing_key,
            hex!("4788dc861b4782f35d43fd98fe1a2d39")
        );
        let mut data = utf16le("Plaintext");
        let signature = client.seal_rpc(&[], &mut data, &[]).unwrap();
        assert_eq!(data, hex!("54e50165bf1936dc996020c1811b0f06fb5f"));
        assert_eq!(signature, hex!("010000007fb38ec5c55d497600000000"));
    }

    #[test]
    fn client_flags_are_those_of_the_ms_nlmp_example() {
        // The NegotiateFlags of the example's AUTHENTICATE_MESSAGE (4.2.4.3).
        assert_eq!(CLIENT_FLAGS.to_le_bytes(), hex!("358288e2"));
    }

    #[test]
    fn upcase_maps_one_character_to_one() {
        assert_eq!(upcase("Administrator"), "ADMINISTRATOR");
        assert_eq!(upcase("straße äö"), "STRAßE ÄÖ");
    }

    fn established(session: Session) -> NtlmClient {
        let mut client = NtlmClient::new(&Credentials::new("u", "p")).unwrap();
        client.state = State::Established(Box::new(session));
        client
    }

    /// A Windows-like TargetInfo: NetBIOS names, optionally a timestamp.
    fn target_info(timestamp: Option<u64>) -> Vec<u8> {
        let mut info = Vec::new();
        push_av_pair(&mut info, AV_NB_DOMAIN_NAME, &utf16le("TEST"));
        push_av_pair(&mut info, AV_NB_COMPUTER_NAME, &utf16le("SERVER"));
        if let Some(timestamp) = timestamp {
            push_av_pair(&mut info, AV_TIMESTAMP, &timestamp.to_le_bytes());
        }
        push_av_pair(&mut info, AV_EOL, &[]);
        info
    }

    fn challenge_message(flags: u32, target_info: &[u8]) -> Vec<u8> {
        const LEN: usize = 56;
        let mut message = SIGNATURE.to_vec();
        message.extend_from_slice(&CHALLENGE_MESSAGE.to_le_bytes());
        push_field(&mut message, 0, LEN); // TargetName
        message.extend_from_slice(&flags.to_le_bytes());
        message.extend_from_slice(&hex!("0123456789abcdef"));
        message.extend_from_slice(&[0; 8]); // Reserved
        push_field(&mut message, target_info.len(), LEN);
        message.extend_from_slice(&VERSION);
        message.extend_from_slice(target_info);
        message
    }

    /// The fields of an AUTHENTICATE message, in header order.
    fn fields(authenticate: &[u8]) -> [&[u8]; 6] {
        std::array::from_fn(|i| field(authenticate, 12 + 8 * i).unwrap())
    }

    /// Accept `authenticate` as an NTLMv2 server does (MS-NLMP 3.2.5.1.2):
    /// check NTProofStr and the MIC, then derive the server's session.
    fn accept(negotiate: &[u8], challenge: &[u8], authenticate: &[u8], password: &str) -> Session {
        let [_, nt_response, domain, user, _, encrypted_key] = fields(authenticate);
        let utf16 = |bytes: &[u8]| {
            let units: Vec<u16> = bytes
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16(&units).unwrap()
        };
        let key = ntowf_v2(password, &utf16(user), &utf16(domain));
        let (proof, temp) = nt_response.split_at(16);
        assert_eq!(
            proof,
            hmac_md5(&*key, &[&challenge[24..32], temp]),
            "NTProofStr"
        );
        let mut exported_key: [u8; 16] = encrypted_key.try_into().unwrap();
        Rc4::new(&hmac_md5(&*key, &[proof])).apply(&mut exported_key);
        let mut zero_mic = authenticate.to_vec();
        zero_mic[MIC_AT..PAYLOAD_AT].fill(0);
        assert_eq!(
            authenticate[MIC_AT..PAYLOAD_AT],
            hmac_md5(&exported_key, &[negotiate, challenge, &zero_mic]),
            "MIC"
        );
        Session {
            send: Direction::new(&exported_key, SERVER_SIGNING, SERVER_SEALING),
            recv: Direction::new(&exported_key, CLIENT_SIGNING, CLIENT_SEALING),
        }
    }

    /// Run the handshake against [`accept`]; returns the client, the server's
    /// session and the AUTHENTICATE message.
    fn handshake(creds: &Credentials, timestamp: Option<u64>) -> (NtlmClient, Session, Vec<u8>) {
        let mut client = NtlmClient::new(creds).unwrap();
        let negotiate = client.negotiate().unwrap();
        let challenge = challenge_message(CLIENT_FLAGS, &target_info(timestamp));
        let authenticate = client.respond(&challenge).unwrap();
        let server = accept(&negotiate, &challenge, &authenticate, &creds.password);
        (client, server, authenticate)
    }

    fn creds() -> Credentials {
        Credentials::new("Administrator", "Lab-Passw0rd").with_domain("TEST")
    }

    #[test]
    fn negotiate_asks_for_the_client_flags() {
        let negotiate = NtlmClient::new(&creds()).unwrap().negotiate().unwrap();
        assert_eq!(negotiate.len(), 40);
        assert_eq!(&negotiate[..12], b"NTLMSSP\0\x01\0\0\0");
        assert_eq!(u32_at(&negotiate, 12), Some(CLIENT_FLAGS));
    }

    #[test]
    fn authenticate_is_what_a_server_verifies() {
        let (_, _, authenticate) = handshake(&creds(), Some(TIMESTAMP));
        let [lm_response, nt_response, domain, user, workstation, _] = fields(&authenticate);
        assert_eq!(u32_at(&authenticate, 60), Some(CLIENT_FLAGS));
        assert_eq!(&authenticate[64..72], &VERSION);
        assert_eq!(domain, utf16le("TEST"));
        assert_eq!(user, utf16le("Administrator"));
        assert_eq!(workstation, utf16le(&local_workstation_name()));
        // With the server's timestamp: no LM response, the timestamp echoed,
        // and the MIC announced next to empty channel bindings.
        assert_eq!(lm_response, [0; 24]);
        assert_eq!(nt_response[24..32], TIMESTAMP.to_le_bytes());
        let pairs = av_pairs(&nt_response[44..]).unwrap();
        assert!(pairs.contains(&(AV_NB_COMPUTER_NAME, &utf16le("SERVER")[..])));
        assert!(pairs.contains(&(AV_FLAGS, &AV_FLAG_MIC.to_le_bytes()[..])));
        assert!(pairs.contains(&(AV_CHANNEL_BINDINGS, &[0; 16][..])));
    }

    #[test]
    fn without_a_server_timestamp_the_lm_response_is_lmv2() {
        let (_, _, authenticate) = handshake(&creds(), None);
        let [lm_response, nt_response, ..] = fields(&authenticate);
        assert_ne!(lm_response[..16], [0; 16]);
        assert_eq!(lm_response[16..], nt_response[32..40], "client challenge");
    }

    #[test]
    fn local_accounts_authenticate_with_an_empty_domain() {
        let (_, _, authenticate) = handshake(&Credentials::new("Administrator", "pw"), None);
        assert_eq!(fields(&authenticate)[2], b"");
    }

    #[test]
    fn signed_and_sealed_messages_round_trip_in_both_directions() {
        let (mut client, mut server, _) = handshake(&creds(), Some(TIMESTAMP));
        for round in 0..3u8 {
            let stub = vec![round; 40];
            let signature = client.sign_rpc(b"head", &stub, b"trailer").unwrap();
            let checksum = server.recv.checksum(&[b"head", &stub, b"trailer"]);
            check_signature(&server.recv.signature(checksum), &signature).unwrap();

            let mut sealed = stub.clone();
            let signature = client.seal_rpc(b"head", &mut sealed, b"trailer").unwrap();
            assert_ne!(sealed, stub);
            server.recv.sealing.apply(&mut sealed);
            assert_eq!(sealed, stub);
            let checksum = server.recv.checksum(&[b"head", &stub, b"trailer"]);
            check_signature(&server.recv.signature(checksum), &signature).unwrap();

            let checksum = server.send.checksum(&[b"head", &stub, b"trailer"]);
            let signature = server.send.signature(checksum);
            client
                .verify_rpc(b"head", &stub, b"trailer", &signature)
                .unwrap();

            let checksum = server.send.checksum(&[b"head", &stub, b"trailer"]);
            let mut sealed = stub.clone();
            server.send.sealing.apply(&mut sealed);
            let signature = server.send.signature(checksum);
            client
                .unseal_rpc(b"head", &mut sealed, b"trailer", &signature)
                .unwrap();
            assert_eq!(sealed, stub);
        }
    }

    #[test]
    fn altered_or_replayed_messages_are_rejected() {
        let (mut client, mut server, _) = handshake(&creds(), Some(TIMESTAMP));
        let checksum = server.send.checksum(&[b"head", b"stub", b"trailer"]);
        let signature = server.send.signature(checksum);
        assert!(client
            .verify_rpc(b"head", b"stuB", b"trailer", &signature)
            .is_err());

        let (mut client, mut server, _) = handshake(&creds(), Some(TIMESTAMP));
        let checksum = server.send.checksum(&[b"head", b"stub", b"trailer"]);
        let signature = server.send.signature(checksum);
        client
            .verify_rpc(b"head", b"stub", b"trailer", &signature)
            .unwrap();
        assert!(
            client
                .verify_rpc(b"head", b"stub", b"trailer", &signature)
                .is_err(),
            "the same signature again is a replay"
        );
        assert!(client
            .verify_rpc(b"head", b"stub", b"trailer", &[])
            .is_err());
    }

    #[test]
    fn weaker_servers_are_refused() {
        for (flag, name) in REQUIRED_FLAGS {
            let mut client = NtlmClient::new(&creds()).unwrap();
            client.negotiate().unwrap();
            let challenge = challenge_message(CLIENT_FLAGS & !flag, &target_info(None));
            let err = client.respond(&challenge).unwrap_err();
            assert!(err.to_string().contains(name), "{err}");
            assert!(client.sign_rpc(b"h", b"s", b"t").is_err());
        }
    }

    #[test]
    fn challenges_without_netbios_names_are_refused() {
        let mut info = Vec::new();
        push_av_pair(&mut info, AV_NB_DOMAIN_NAME, &utf16le("TEST"));
        push_av_pair(&mut info, AV_EOL, &[]);
        let mut client = NtlmClient::new(&creds()).unwrap();
        client.negotiate().unwrap();
        let err = client
            .respond(&challenge_message(CLIENT_FLAGS, &info))
            .unwrap_err();
        assert!(err.to_string().contains("NetBIOS"), "{err}");
    }

    #[test]
    fn handshake_steps_must_come_in_order() {
        let challenge = challenge_message(CLIENT_FLAGS, &target_info(None));
        let mut client = NtlmClient::new(&creds()).unwrap();
        assert!(client.sign_rpc(b"h", b"s", b"t").is_err());
        assert!(client.respond(&challenge).is_err(), "challenge first");
        let mut client = NtlmClient::new(&creds()).unwrap();
        client.negotiate().unwrap();
        assert!(client.negotiate().is_err(), "negotiate twice");
        assert!(client.respond(&challenge).is_err());
    }

    #[test]
    fn malformed_challenges_are_refused() {
        let good = challenge_message(CLIENT_FLAGS, &target_info(None));
        let mut wrong_type = good.clone();
        wrong_type[8] = 3;
        let mut target_info_past_end = good.clone();
        target_info_past_end[44..48].copy_from_slice(&(good.len() as u32).to_le_bytes());
        let mut no_eol = good.clone();
        no_eol.truncate(good.len() - 4);
        no_eol[40..42].copy_from_slice(&((good.len() - 4 - 56) as u16).to_le_bytes());
        for challenge in [&good[..20], &wrong_type, &target_info_past_end, &no_eol] {
            let mut client = NtlmClient::new(&creds()).unwrap();
            client.negotiate().unwrap();
            assert!(client.respond(challenge).is_err());
        }
    }

    /// Split a single-fragment PDU into header, stub, sec_trailer and
    /// auth_value.
    fn split_pdu(
        pdu: &mut [u8],
        header_len: usize,
    ) -> (&mut [u8], &mut [u8], &mut [u8], &mut [u8]) {
        let auth_len = usize::from(u16::from_le_bytes([pdu[10], pdu[11]]));
        let trailer_at = pdu.len() - auth_len - 8;
        let (head, rest) = pdu.split_at_mut(header_len);
        let (body, tail) = rest.split_at_mut(trailer_at - header_len);
        let (trailer, auth_value) = tail.split_at_mut(8);
        (head, body, trailer, auth_value)
    }

    /// Server side of an RPC PDU: decrypt (if `sealed`) and verify.
    fn open(
        server: &mut Session,
        pdu: &mut [u8],
        header_len: usize,
        sealed: bool,
    ) -> Result<(), AuthError> {
        let (head, body, trailer, auth_value) = split_pdu(pdu, header_len);
        if sealed {
            server.recv.sealing.apply(body);
        }
        let checksum = server.recv.checksum(&[head, body, trailer]);
        check_signature(&server.recv.signature(checksum), auth_value)
    }

    /// A single-fragment response PDU carrying `stub`, signed or sealed by
    /// the server.
    fn response(server: &mut Session, call_id: u32, stub: &[u8], sealed: bool) -> Vec<u8> {
        let (align, level) = if sealed { (16, 6) } else { (4, 5) };
        let pad = (align - stub.len() % align) % align;
        let frag_len = 24 + stub.len() + pad + 8 + 16;
        let mut pdu = vec![5, 0, 0x02, 0x03, 0x10, 0, 0, 0];
        pdu.extend_from_slice(&(frag_len as u16).to_le_bytes());
        pdu.extend_from_slice(&16u16.to_le_bytes());
        pdu.extend_from_slice(&call_id.to_le_bytes());
        pdu.extend_from_slice(&(stub.len() as u32).to_le_bytes());
        pdu.extend_from_slice(&[0, 0, 0, 0]); // p_cont_id, cancel_count, reserved
        pdu.extend_from_slice(stub);
        pdu.extend(std::iter::repeat_n(0u8, pad));
        pdu.extend_from_slice(&[0x0a, level, pad as u8, 0, 0, 0, 0, 0]);
        pdu.extend_from_slice(&[0; 16]);
        let (head, body, trailer, auth_value) = split_pdu(&mut pdu, 24);
        let checksum = server.send.checksum(&[head, body, trailer]);
        if sealed {
            server.send.sealing.apply(body);
        }
        auth_value.copy_from_slice(&server.send.signature(checksum));
        pdu
    }

    #[test]
    fn sealed_rpc_request_and_response_round_trip() {
        let (mut client, mut server, _) = handshake(&creds(), Some(TIMESTAMP));
        // Two calls in a row: per-direction RC4 state and sequence numbers advance.
        for (call_id, stub) in [
            (3u32, b"first activation stub".to_vec()),
            (4, vec![0xAB; 48]),
        ] {
            let mut pdu = build_sealed_request_pdu(&mut client, call_id, 0, 4, &stub, 0).unwrap();
            assert_ne!(
                &pdu[24..24 + stub.len()],
                &stub[..],
                "stub must be encrypted"
            );
            open(&mut server, &mut pdu, 24, true).unwrap();
            assert_eq!(&pdu[24..24 + stub.len()], &stub[..]);

            let reply = response(&mut server, call_id, b"response stub data", true);
            let plain = unseal_response_pdu(&mut client, &reply).unwrap();
            assert_eq!(&plain[24..24 + 18], b"response stub data");
        }
    }

    #[test]
    fn signed_rpc_request_and_response_round_trip() {
        let (mut client, mut server, _) = handshake(&creds(), Some(TIMESTAMP));
        let stub = b"ORPCTHIS and NTLMLogin stub bytes".to_vec();
        let mut pdu =
            build_signed_request_pdu(&mut client, 2, 0, 6, &[0x11; 16], &stub, 0).unwrap();
        // Integrity: the stub travels in cleartext after the 40-byte header.
        assert_eq!(&pdu[40..40 + stub.len()], &stub[..]);
        open(&mut server, &mut pdu, 40, false).unwrap();

        let stub = b"ORPCTHAT + IWbemServices OBJREF + HRESULT".to_vec();
        let reply = response(&mut server, 2, &stub, false);
        assert_eq!(
            verify_signed_response_pdu(&mut client, &reply).unwrap(),
            stub
        );
    }

    #[test]
    fn tampered_rpc_pdus_are_rejected() {
        let (mut client, mut server, _) = handshake(&creds(), Some(TIMESTAMP));
        let mut pdu =
            build_signed_request_pdu(&mut client, 2, 0, 6, &[0x11; 16], b"stub data here!!", 0)
                .unwrap();
        pdu[40] ^= 0x01; // a cleartext stub byte
        assert!(open(&mut server, &mut pdu, 40, false).is_err());

        let (mut client, mut server, _) = handshake(&creds(), Some(TIMESTAMP));
        let mut reply = response(&mut server, 2, b"response stub data", false);
        reply[24] ^= 0x01;
        assert!(verify_signed_response_pdu(&mut client, &reply).is_err());

        let (mut client, mut server, _) = handshake(&creds(), Some(TIMESTAMP));
        let mut reply = response(&mut server, 3, b"response stub data", true);
        reply[4] ^= 0x01; // a signed, unencrypted header bit
        assert!(unseal_response_pdu(&mut client, &reply).is_err());
    }

    /// The challenge comes from the server: whatever its bytes, the client
    /// must return an error or a message, never panic.
    mod properties {
        use super::*;
        use fabi_testkit::{bytes, config, mutated};
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(config())]

            #[test]
            fn challenges_never_panic(
                challenge in prop_oneof![
                    bytes(256),
                    mutated(challenge_message(CLIENT_FLAGS, &target_info(Some(TIMESTAMP)))),
                ],
            ) {
                let mut client = NtlmClient::new(&creds()).unwrap();
                client.negotiate().unwrap();
                let _ = client.respond(&challenge);
            }
        }
    }
}
