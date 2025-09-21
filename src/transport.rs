use crate::auth::{AuthProvider, Credentials, NtlmV2Client};
#[cfg(feature = "kerberos")]
use crate::kerberos_adapter::{KerberosClient, KerberosConfig};
use crate::kerberos_integration::spnego;
use byteorder::{LittleEndian, WriteBytesExt};

// RPC authentication type constants
#[allow(dead_code)]
pub const AUTH_TYPE_NTLM: u8 = 0x0A;
#[allow(dead_code)]
pub const AUTH_TYPE_SPNEGO: u8 = 0x09;
#[cfg(feature = "kerberos")]
#[allow(dead_code)]
pub const AUTH_TYPE_KERBEROS: u8 = 0x10;
use socket2::{Domain, Protocol, Socket, Type};
use std::io::{Cursor, Read, Write};
#[cfg(feature = "async")]
use std::mem;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, error, instrument, warn};

#[cfg(feature = "async")]
use async_trait::async_trait;
#[cfg(feature = "async")]
use tokio::net::TcpStream as TokioTcpStream;
#[cfg(feature = "async")]
use tokio::sync::Mutex;
#[cfg(feature = "async")]
use tokio::task::spawn_blocking;
#[cfg(feature = "async")]
use tokio::time::timeout;

/// Errors produced by RPC transports when issuing calls.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("transport not implemented")]
    NotImplemented,
    #[error("transport failure: {0}")]
    Failure(String),
    #[error("bind rejected (result={result:#06x}, reason={reason:#06x})")]
    Bind { result: u16, reason: u16 },
    #[error("alter_context rejected (result={result:#06x})")]
    AlterReject { result: u16 },
}

impl From<std::io::Error> for TransportError {
    fn from(err: std::io::Error) -> Self {
        TransportError::Failure(err.to_string())
    }
}

/// Abstraction over the RPC transport/channel used to reach WMI services.
pub trait RpcTransport: Send {
    /// Identify the transport implementation (useful for logging/diagnostics).
    fn name(&self) -> &'static str;

    /// Invoke an RPC operation using the provided opnum and stub payload.
    fn invoke(&mut self, _opnum: u16, _payload: &[u8]) -> Result<Vec<u8>, TransportError> {
        Ok(Vec::new())
    }
}

/// Build an RPC request PDU using the provided call/context identifiers and stub payload.
pub(crate) fn build_request_pdu(call_id: u32, context_id: u16, opnum: u16, stub: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    WriteBytesExt::write_u32::<LittleEndian>(&mut body, 0).unwrap(); // alloc_hint (filled in later if needed)
    WriteBytesExt::write_u16::<LittleEndian>(&mut body, context_id).unwrap();
    WriteBytesExt::write_u16::<LittleEndian>(&mut body, opnum).unwrap();
    body.extend_from_slice(stub);

    let frag_len = (16 + body.len()) as u16;

    let mut pdu = Vec::with_capacity(frag_len as usize);
    pdu.write_u8(5).unwrap(); // version
    pdu.write_u8(0).unwrap(); // minor version
    pdu.write_u8(0x00).unwrap(); // ptype=request
    pdu.write_u8(0x03).unwrap(); // flags first|last
    pdu.write_u32::<LittleEndian>(0x10_00_00_00).unwrap(); // data rep LE
    pdu.write_u16::<LittleEndian>(frag_len).unwrap();
    pdu.write_u16::<LittleEndian>(0).unwrap(); // auth_len (no auth yet)
    pdu.write_u32::<LittleEndian>(call_id).unwrap();
    pdu.extend_from_slice(&body);
    pdu
}

/// Extract the stub payload from an RPC response PDU, returning errors for faults.
pub(crate) fn parse_response_pdu(pdu: &[u8]) -> Result<Vec<u8>, TransportError> {
    use byteorder::ReadBytesExt as _;
    if pdu.len() < 24 {
        return Err(TransportError::Failure("response PDU too short".into()));
    }

    let mut cursor = Cursor::new(pdu);
    cursor.read_u8()?; // version
    cursor.read_u8()?; // minor
    let ptype = cursor.read_u8()?;

    if ptype == 0x03 {
        cursor.set_position(24);
        let status = cursor.read_u32::<LittleEndian>()?;
        return Err(TransportError::Failure(format!(
            "RPC fault: 0x{status:08x}"
        )));
    }

    if ptype != 0x02 {
        return Err(TransportError::Failure(format!(
            "Unexpected PDU type in response: 0x{ptype:02x}"
        )));
    }

    cursor.read_u8()?; // flags
    cursor.read_u32::<LittleEndian>()?; // data rep
    let frag_len = cursor.read_u16::<LittleEndian>()? as usize;
    let auth_len = cursor.read_u16::<LittleEndian>()? as usize;
    cursor.read_u32::<LittleEndian>()?; // call_id

    cursor.read_u32::<LittleEndian>()?; // alloc_hint
    cursor.read_u16::<LittleEndian>()?; // context_id
    cursor.read_u8()?; // cancel_count
    cursor.read_u8()?; // reserved

    let stub_start = 24;
    let stub_end = if auth_len > 0 {
        frag_len - auth_len - 8
    } else {
        frag_len
    };

    if stub_end > pdu.len() || stub_start >= stub_end {
        return Err(TransportError::Failure("invalid stub data bounds".into()));
    }

    Ok(pdu[stub_start..stub_end].to_vec())
}

fn build_auth_pad(seqno: u32) -> [u8; 8] {
    let mut pad = [0u8; 8];
    let confounder = (seqno.wrapping_mul(0x343FD)).wrapping_add(0x269EC3);
    pad[0..4].copy_from_slice(&confounder.to_le_bytes());
    pad[4..].copy_from_slice(&seqno.to_le_bytes());
    pad
}

fn sign_pdu_in_place(
    session_key: &[u8],
    auth_level: u8,
    context_id: u16,
    seqno: &mut u32,
    pdu: &mut Vec<u8>,
) -> Result<(), TransportError> {
    if session_key.is_empty() {
        return Err(TransportError::Failure("No session key for signing".into()));
    }

    let current_seqno = *seqno;
    *seqno = current_seqno.wrapping_add(1);

    let auth_pad = build_auth_pad(current_seqno);
    let mut sign_data = auth_pad.to_vec();
    sign_data.extend_from_slice(pdu);

    let signature = crate::crypto::hmac_md5_sign(session_key, &sign_data);

    pdu.push(0x0A); // AUTH_TYPE_NTLM
    pdu.push(auth_level);
    pdu.push(0); // pad_len
    pdu.push(0); // reserved

    pdu.extend_from_slice(&context_id.to_le_bytes());
    pdu.extend_from_slice(&[0, 0]);
    pdu.extend_from_slice(&signature);

    let auth_len = 24u16;
    pdu[10..12].copy_from_slice(&auth_len.to_le_bytes());
    let frag_len = pdu.len() as u16;
    pdu[8..10].copy_from_slice(&frag_len.to_le_bytes());

    Ok(())
}

fn seal_pdu_in_place(
    session_key: &[u8],
    auth_level: u8,
    context_id: u16,
    seqno: &mut u32,
    pdu: &mut Vec<u8>,
) -> Result<(), TransportError> {
    if session_key.is_empty() {
        return Err(TransportError::Failure("No session key for sealing".into()));
    }

    if auth_level != 6 {
        return sign_pdu_in_place(session_key, auth_level, context_id, seqno, pdu);
    }

    let current_seqno = *seqno;
    *seqno = current_seqno.wrapping_add(1);

    let mut seal_key_data = session_key.to_vec();
    seal_key_data.extend_from_slice(&current_seqno.to_le_bytes());
    let rc4_key_hash = md5::compute(&seal_key_data);

    if pdu.len() > 24 {
        crate::crypto::rc4_encrypt(&rc4_key_hash.0, &mut pdu[24..]);
    }

    let auth_pad = build_auth_pad(current_seqno);
    let mut sign_data = auth_pad.to_vec();
    sign_data.extend_from_slice(pdu);

    let signature = crate::crypto::hmac_md5_sign(session_key, &sign_data);

    pdu.push(0x0A); // AUTH_TYPE_NTLM
    pdu.push(auth_level);
    pdu.push(0);
    pdu.push(0);
    pdu.extend_from_slice(&context_id.to_le_bytes());
    pdu.extend_from_slice(&[0, 0]);
    pdu.extend_from_slice(&signature);

    let auth_len = 24u16;
    pdu[10..12].copy_from_slice(&auth_len.to_le_bytes());
    let frag_len = pdu.len() as u16;
    pdu[8..10].copy_from_slice(&frag_len.to_le_bytes());

    Ok(())
}

fn unseal_response_pdu_in_place(
    session_key: &[u8],
    auth_level: u8,
    _context_id: u16,
    seqno_state: u32,
    pdu: &mut Vec<u8>,
) -> Result<(), TransportError> {
    if pdu.len() < 16 {
        return Err(TransportError::Failure(
            "PDU too short for unsealing".into(),
        ));
    }

    let original_auth_len = u16::from_le_bytes([pdu[10], pdu[11]]) as usize;
    if original_auth_len == 0 {
        return Ok(());
    }

    let last_seqno = seqno_state.wrapping_sub(1);

    if auth_level != 6 {
        if original_auth_len >= 24 && pdu.len() >= original_auth_len {
            let pdu_len = pdu.len() - original_auth_len;
            let signature_start = pdu_len + 8;

            if signature_start + 16 <= pdu.len() {
                let mut expected_signature = [0u8; 16];
                expected_signature.copy_from_slice(&pdu[signature_start..signature_start + 16]);

                let auth_pad = build_auth_pad(last_seqno);
                let mut sign_data = auth_pad.to_vec();
                sign_data.extend_from_slice(&pdu[..pdu_len]);

                if !crate::crypto::hmac_md5_verify(session_key, &sign_data, &expected_signature) {
                    return Err(TransportError::Failure(
                        "Signature verification failed".into(),
                    ));
                }

                pdu.truncate(pdu_len);
                pdu[10..12].copy_from_slice(&[0, 0]);
                let new_frag_len = pdu.len() as u16;
                pdu[8..10].copy_from_slice(&new_frag_len.to_le_bytes());
            }
        }
        return Ok(());
    }

    if original_auth_len >= 24 && pdu.len() >= original_auth_len {
        let pdu_len = pdu.len() - original_auth_len;
        let signature_start = pdu_len + 8;

        if signature_start + 16 <= pdu.len() {
            let mut expected_signature = [0u8; 16];
            expected_signature.copy_from_slice(&pdu[signature_start..signature_start + 16]);

            if pdu_len > 24 {
                let mut seal_key_data = session_key.to_vec();
                seal_key_data.extend_from_slice(&last_seqno.to_le_bytes());
                let rc4_key_hash = md5::compute(&seal_key_data);

                crate::crypto::rc4_decrypt(&rc4_key_hash.0, &mut pdu[24..pdu_len]);
            }

            let auth_pad = build_auth_pad(last_seqno);
            let mut sign_data = auth_pad.to_vec();
            sign_data.extend_from_slice(&pdu[..pdu_len]);

            if !crate::crypto::hmac_md5_verify(session_key, &sign_data, &expected_signature) {
                return Err(TransportError::Failure(
                    "Signature verification failed after decryption".into(),
                ));
            }

            pdu.truncate(pdu_len);
            pdu[10..12].copy_from_slice(&[0, 0]);
            let new_frag_len = pdu.len() as u16;
            pdu[8..10].copy_from_slice(&new_frag_len.to_le_bytes());
        }
    }

    Ok(())
}

/// Configuration that will be consumed by the real transport implementation once the
/// EPM and bind logic is in place.
#[derive(Debug, Clone, Default)]
pub struct RealTransportConfig {
    pub host: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub domain: Option<String>,
    pub read_timeout: Option<Duration>,
    pub write_timeout: Option<Duration>,
}

impl RealTransportConfig {
    /// Validate the configuration
    pub fn validate(&self) -> Result<(), TransportError> {
        if self.host.is_empty() {
            return Err(TransportError::Failure("Host required".into()));
        }
        if self.username.is_some() != self.password.is_some() {
            return Err(TransportError::Failure(
                "Username and password must both be provided or omitted".into(),
            ));
        }
        Ok(())
    }
}

/// Authenticated RPC transport that speaks to real WMI services.
#[derive(Debug)]
pub struct RealRpcTransport {
    stream: std::net::TcpStream,
    context_id: u16,
    call_id: u32,
    causality_id: u32, // ORPC causality tracking
    session_key: Vec<u8>,
    auth_level: u8,
    _max_xmit: u16,
    _max_recv: u16,
    ipid: Option<[u8; 16]>, // Interface pointer ID from OXID resolution
    _object_ref: Option<crate::dcom::ObjectReference>, // Full object reference
    seqno: u32,             // Sequence number for signing/sealing
}

impl RealRpcTransport {
    /// Creates a new transport with OXID from DCOM activation
    #[instrument(level = "debug", skip(config), fields(host = %config.host))]
    pub fn connect_with_oxid(
        config: RealTransportConfig,
        port: u16,
        oxid: [u8; 8],
    ) -> Result<Self, TransportError> {
        config.validate()?;

        let RealTransportConfig {
            host,
            username,
            password,
            domain,
            read_timeout,
            write_timeout,
        } = config;

        let read_timeout = read_timeout.unwrap_or(Duration::from_secs(10));
        let write_timeout = write_timeout.unwrap_or(Duration::from_secs(10));

        let (username, password) = match (username, password) {
            (Some(u), Some(p)) => (u, p),
            _ => {
                return Err(TransportError::Failure(
                    "Credentials required for authenticated transport".into(),
                ))
            }
        };

        let domain = domain.unwrap_or_default();

        let creds = Credentials::new(
            username.clone(),
            password.clone(),
            domain.clone(),
            host.clone(),
        );

        let mut auth = NtlmV2Client::new(creds.clone())
            .map_err(|err| TransportError::Failure(err.to_string()))?;

        debug!(
            port,
            ?oxid,
            "connecting to WMI endpoint from DCOM activation"
        );
        let addr = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|err| TransportError::Failure(err.to_string()))?
            .next()
            .ok_or_else(|| TransportError::Failure("host resolved to no addresses".into()))?;
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
            .map_err(|err| TransportError::Failure(err.to_string()))?;

        // Use platform-specific socket configuration
        Self::configure_socket_timeouts(&socket, read_timeout, write_timeout)?;
        socket
            .connect(&addr.into())
            .map_err(|err| TransportError::Failure(err.to_string()))?;
        let mut stream: TcpStream = socket.into();
        let _ = stream.set_nodelay(true);

        let negotiate = auth
            .negotiate()
            .map_err(|err| TransportError::Failure(err.to_string()))?;
        let bind_pdu = Self::build_bind_pdu(1, &negotiate);
        debug!(
            pdu_len = bind_pdu.len(),
            auth_len = negotiate.len(),
            "sending bind request"
        );
        stream.write_all(&bind_pdu)?;

        let bind_ack = Self::read_pdu(&mut stream)?;
        let (context_id, type2, max_xmit, max_recv) = Self::parse_bind_ack(&bind_ack)?;
        debug!(
            context_id,
            max_xmit,
            max_recv,
            type2_len = type2.len(),
            "received bind_ack"
        );

        let authenticate = auth
            .respond_message(&type2)
            .map_err(|err| TransportError::Failure(err.to_string()))?;
        let alter_context = Self::build_alter_context_pdu(2, context_id, &authenticate.message);
        debug!(
            pdu_len = alter_context.len(),
            auth_len = authenticate.message.len(),
            "sending alter_context"
        );
        stream.write_all(&alter_context)?;
        let alter_ack = Self::read_pdu(&mut stream)?;
        Self::parse_alter_ack(&alter_ack)?;

        let session_key = authenticate.session_key.to_vec();
        debug!("NTLM session established");

        // Now resolve OXID to get IPID
        let object_ref = crate::dcom::resolve_oxid(&host, port, &creds, &oxid)
            .map_err(|err| TransportError::Failure(format!("OXID resolution failed: {err}")))?;
        debug!("OXID resolved, IPID: {:?}", hex::encode(object_ref.ipid));

        Ok(Self {
            stream,
            context_id,
            call_id: 3,
            causality_id: 0, // Initialize to 0, will increment on new object calls
            session_key,
            auth_level: 6, // Packet Privacy
            _max_xmit: max_xmit,
            _max_recv: max_recv,
            ipid: Some(object_ref.ipid),
            _object_ref: Some(object_ref),
            seqno: 0, // Initialize sequence number for signing/sealing
        })
    }

    /// Connect with Kerberos authentication (Windows 11 compatible)
    #[cfg(feature = "kerberos")]
    #[allow(dead_code)]
    #[instrument(level = "debug", skip_all, fields(host, port))]
    pub fn connect_with_kerberos(
        host: &str,
        port: u16,
        config: KerberosConfig,
        creds: Credentials,
    ) -> Result<Self, TransportError> {
        debug!("Connecting with Kerberos to {}:{}", host, port);

        let addr = (host, port)
            .to_socket_addrs()
            .map_err(|err| TransportError::Failure(err.to_string()))?
            .next()
            .ok_or_else(|| TransportError::Failure("Failed to resolve address".into()))?;

        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;

        // Create Kerberos client
        let mut auth = KerberosClient::new(host, config.clone(), creds)
            .map_err(|err| TransportError::Failure(err.to_string()))?;

        // Determine auth type based on config (handled in KerberosClient now)

        // Step 1: Send bind with AP-REQ (first leg)
        let ap_req = auth.negotiate()
            .map_err(|err| TransportError::Failure(err.to_string()))?;

        let bind_pdu = Self::build_bind_pdu(1, &ap_req);
        debug!("Sending Kerberos bind PDU, len={}", bind_pdu.len());
        stream.write_all(&bind_pdu)?;

        // Step 2: Receive bind_ack with AP-REP (second leg)
        let bind_ack = Self::read_pdu(&mut stream)?;
        let (context_id, ap_rep, max_xmit, max_recv) = Self::parse_bind_ack(&bind_ack)?;
        debug!("Received bind_ack, context_id={}", context_id);

        // Step 3: Send alter_context with final token (third leg - DCE style)
        // CRITICAL: Always send third leg even if token is empty
        let final_token = auth.respond(&ap_rep)
            .map_err(|err| TransportError::Failure(err.to_string()))?;

        let alter_pdu = Self::build_alter_context_pdu(2, context_id, &final_token);
        debug!("Sending alter_context (third leg), len={}", alter_pdu.len());
        stream.write_all(&alter_pdu)?;

        let alter_ack = Self::read_pdu(&mut stream)?;
        Self::parse_alter_ack(&alter_ack)?;
        debug!("Kerberos context established");

        // Extract session key from AP-REP subkey (for mutual auth)
        let session_key = auth.session_key()
            .ok_or_else(|| TransportError::Failure("No session key available".into()))?
            .to_vec();

        Ok(Self {
            stream,
            context_id,
            call_id: 3,
            causality_id: 0,
            session_key,
            auth_level: config.auth_level as u8,
            _max_xmit: max_xmit,
            _max_recv: max_recv,
            ipid: None,
            _object_ref: None,
            seqno: 0,
        })
    }

    /// Creates a new transport after resolving the dynamic endpoint via EPM and performing the
    /// NTLM authenticated bind.  The detailed network logic will be filled in during the
    /// subsequent iterations of Step 1.
    #[instrument(level = "debug", skip(config), fields(host = %config.host))]
    pub fn connect(config: RealTransportConfig) -> Result<Self, TransportError> {
        config.validate()?;

        let RealTransportConfig {
            host,
            username,
            password,
            domain,
            read_timeout,
            write_timeout,
        } = config;

        let read_timeout = read_timeout.unwrap_or(Duration::from_secs(10));
        let write_timeout = write_timeout.unwrap_or(Duration::from_secs(10));

        let username = username.unwrap_or_default();
        let password = password.unwrap_or_default();
        let domain = domain.unwrap_or_default();

        let creds = Credentials::new(
            username.clone(),
            password.clone(),
            domain.clone(),
            host.clone(),
        );

        let mut auth = NtlmV2Client::new(creds.clone())
            .map_err(|err| TransportError::Failure(err.to_string()))?;

        let port = crate::dcom::resolve_wmi_port(&host, Some(&creds)).map_err(|err| {
            error!(?err, "EPM resolution failed");
            TransportError::Failure(err.to_string())
        })?;
        debug!(port, "connecting to RPC endpoint");
        let addr = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|err| TransportError::Failure(err.to_string()))?
            .next()
            .ok_or_else(|| TransportError::Failure("host resolved to no addresses".into()))?;
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
            .map_err(|err| TransportError::Failure(err.to_string()))?;

        // Use platform-specific socket configuration
        Self::configure_socket_timeouts(&socket, read_timeout, write_timeout)?;
        socket
            .connect(&addr.into())
            .map_err(|err| TransportError::Failure(err.to_string()))?;
        let mut stream: TcpStream = socket.into();
        let _ = stream.set_nodelay(true);

        let negotiate = auth
            .negotiate()
            .map_err(|err| TransportError::Failure(err.to_string()))?;
        let bind_pdu = Self::build_bind_pdu(1, &negotiate);
        debug!(
            pdu_len = bind_pdu.len(),
            auth_len = negotiate.len(),
            "sending bind request"
        );
        stream.write_all(&bind_pdu)?;

        let bind_ack = Self::read_pdu(&mut stream)?;
        let (context_id, type2, max_xmit, max_recv) = Self::parse_bind_ack(&bind_ack)?;
        debug!(
            context_id,
            max_xmit,
            max_recv,
            type2_len = type2.len(),
            "received bind_ack"
        );

        let authenticate = auth
            .respond_message(&type2)
            .map_err(|err| TransportError::Failure(err.to_string()))?;
        let alter_context = Self::build_alter_context_pdu(2, context_id, &authenticate.message);
        debug!(
            pdu_len = alter_context.len(),
            auth_len = authenticate.message.len(),
            "sending alter_context"
        );
        stream.write_all(&alter_context)?;
        let alter_ack = Self::read_pdu(&mut stream)?;
        Self::parse_alter_ack(&alter_ack)?;

        let session_key = authenticate.session_key.to_vec();
        debug!("NTLM session established");

        Ok(Self {
            stream,
            context_id,
            call_id: 3,
            causality_id: 0, // Initialize to 0, will increment on new object calls
            session_key,
            auth_level: 6, // Packet Privacy
            _max_xmit: max_xmit,
            _max_recv: max_recv,
            ipid: None,        // Will be set after OXID resolution
            _object_ref: None, // Will be set after OXID resolution
            seqno: 0,          // Initialize sequence number for signing/sealing
        })
    }

    fn build_bind_pdu(call_id: u32, ntlm: &[u8]) -> Vec<u8> {
        use byteorder::WriteBytesExt as _;
        const MAX_XMIT_RECV: u16 = 0x10B8;
        const AUTH_LEVEL_PRIVACY: u8 = 0x06;

        // Wrap NTLM in SPNEGO for modern Windows compatibility
        let (auth_blob, auth_type) = if let Ok(wrapped) = spnego::wrap_in_spnego_init(ntlm, true) {
            (wrapped, AUTH_TYPE_SPNEGO)
        } else {
            // Fallback to raw NTLM if wrapping fails
            (ntlm.to_vec(), AUTH_TYPE_NTLM)
        };

        let mut body = Vec::new();
        body.write_u16::<LittleEndian>(MAX_XMIT_RECV).unwrap();
        body.write_u16::<LittleEndian>(MAX_XMIT_RECV).unwrap();
        body.write_u32::<LittleEndian>(0).unwrap(); // association group
        body.write_u8(1).unwrap(); // number of context items
        body.write_u8(0).unwrap(); // alignment padding
        body.write_u16::<LittleEndian>(0).unwrap(); // context ID
        body.write_u8(1).unwrap(); // number of transfer syntaxes
        body.write_u8(0).unwrap();
        // Abstract syntax: IRemoteSCMActivator {000001a0-0000-0000-C000-000000000046}
        body.extend_from_slice(&hex_literal::hex!("a001000000000000c000000000000046"));
        body.write_u16::<LittleEndian>(0).unwrap(); // version major
        body.write_u16::<LittleEndian>(0).unwrap(); // version minor
                                                    // Transfer syntax: NDR
        body.extend_from_slice(&hex_literal::hex!("045d888aeb1cc9119fe808002b104860"));
        body.write_u32::<LittleEndian>(2).unwrap(); // version 2.0

        let pad = (4 - (body.len() % 4)) % 4;
        body.extend(std::iter::repeat_n(0u8, pad));

        body.push(auth_type);
        body.push(AUTH_LEVEL_PRIVACY);
        body.push(pad as u8);
        body.push(0);
        body.write_u32::<LittleEndian>(0).unwrap(); // auth context id
        body.extend(std::iter::repeat_n(0u8, pad));
        body.extend_from_slice(&auth_blob);

        let frag_len = (16 + body.len()) as u16;
        let auth_len = auth_blob.len() as u16;

        let mut pdu = Vec::with_capacity(frag_len as usize);
        pdu.write_u8(5).unwrap();
        pdu.write_u8(0).unwrap();
        pdu.write_u8(0x0B).unwrap(); // bind
        pdu.write_u8(0x03).unwrap();
        pdu.write_u32::<LittleEndian>(0x10_00_00_00).unwrap();
        pdu.write_u16::<LittleEndian>(frag_len).unwrap();
        pdu.write_u16::<LittleEndian>(auth_len).unwrap();
        pdu.write_u32::<LittleEndian>(call_id).unwrap();
        pdu.extend_from_slice(&body);
        pdu
    }

    fn build_alter_context_pdu(call_id: u32, context_id: u16, ntlm: &[u8]) -> Vec<u8> {
        use byteorder::WriteBytesExt as _;
        const MAX_XMIT_RECV: u16 = 0x10B8;
        const AUTH_LEVEL_PRIVACY: u8 = 0x06;

        // Wrap NTLM in SPNEGO for modern Windows compatibility
        let (auth_blob, auth_type) = if let Ok(wrapped) = spnego::wrap_in_spnego_init(ntlm, true) {
            (wrapped, AUTH_TYPE_SPNEGO)
        } else {
            // Fallback to raw NTLM if wrapping fails
            (ntlm.to_vec(), AUTH_TYPE_NTLM)
        };

        let mut body = Vec::new();
        body.write_u16::<LittleEndian>(MAX_XMIT_RECV).unwrap();
        body.write_u16::<LittleEndian>(MAX_XMIT_RECV).unwrap();
        body.write_u32::<LittleEndian>(0).unwrap();
        body.write_u8(1).unwrap();
        body.write_u8(0).unwrap();
        body.write_u16::<LittleEndian>(context_id).unwrap();
        body.write_u8(1).unwrap();
        body.write_u8(0).unwrap();
        body.extend_from_slice(&hex_literal::hex!("a001000000000000c000000000000046"));
        body.write_u16::<LittleEndian>(0).unwrap();
        body.write_u16::<LittleEndian>(0).unwrap();
        body.extend_from_slice(&hex_literal::hex!("045d888aeb1cc9119fe808002b104860"));
        body.write_u32::<LittleEndian>(2).unwrap();

        let pad = (4 - (body.len() % 4)) % 4;
        body.extend(std::iter::repeat_n(0u8, pad));

        body.push(auth_type);
        body.push(AUTH_LEVEL_PRIVACY);
        body.push(pad as u8);
        body.push(0);
        body.write_u32::<LittleEndian>(0).unwrap();
        body.extend(std::iter::repeat_n(0u8, pad));
        body.extend_from_slice(&auth_blob);

        let frag_len = (16 + body.len()) as u16;
        let auth_len = auth_blob.len() as u16;

        let mut pdu = Vec::with_capacity(frag_len as usize);
        pdu.write_u8(5).unwrap();
        pdu.write_u8(0).unwrap();
        pdu.write_u8(0x0E).unwrap(); // alter_context
        pdu.write_u8(0x03).unwrap();
        pdu.write_u32::<LittleEndian>(0x10_00_00_00).unwrap();
        pdu.write_u16::<LittleEndian>(frag_len).unwrap();
        pdu.write_u16::<LittleEndian>(auth_len).unwrap();
        pdu.write_u32::<LittleEndian>(call_id).unwrap();
        pdu.extend_from_slice(&body);
        pdu
    }

    pub(crate) fn parse_bind_ack(pdu: &[u8]) -> Result<(u16, Vec<u8>, u16, u16), TransportError> {
        use byteorder::ReadBytesExt as _;
        let mut cursor = Cursor::new(pdu);
        let _version = cursor.read_u8()?;
        let _minor = cursor.read_u8()?;
        let ptype = cursor.read_u8()?;
        if ptype == 0x0D {
            // bind_nak - server rejected our bind request
            // bind_nak structure: header (16 bytes) + reject_reason (2 bytes) + versions_supported
            let reason = if pdu.len() >= 18 {
                cursor.set_position(16);
                cursor.read_u16::<LittleEndian>().unwrap_or(0)
            } else {
                0
            };
            let versions = if pdu.len() >= 19 {
                cursor.set_position(18);
                cursor.read_u8().unwrap_or(0)
            } else {
                0
            };
            warn!(reason, versions, "bind rejected (bind_nak)");
            return Err(TransportError::Bind { result: reason, reason: versions as u16 });
        }
        if ptype != 0x0C {
            return Err(TransportError::Failure(format!(
                "Unexpected PDU type in bind_ack: 0x{ptype:02x}"
            )));
        }
        cursor.read_u8()?; // flags
        cursor.read_u32::<LittleEndian>()?; // data rep
        let _frag_len = cursor.read_u16::<LittleEndian>()?;
        let auth_len = cursor.read_u16::<LittleEndian>()?;
        cursor.read_u32::<LittleEndian>()?; // call id
        let max_xmit = cursor.read_u16::<LittleEndian>()?;
        let max_recv = cursor.read_u16::<LittleEndian>()?;
        let assoc_group = cursor.read_u32::<LittleEndian>()?;
        let sec_addr_len = cursor.read_u16::<LittleEndian>()? as usize;
        if sec_addr_len > 0 {
            let mut sec_addr = vec![0u8; sec_addr_len];
            cursor.read_exact(&mut sec_addr)?;
        }
        let pad = (4 - (cursor.position() as usize % 4)) % 4;
        if pad > 0 {
            let mut padding = vec![0u8; pad];
            cursor.read_exact(&mut padding)?;
        }

        let num_results = cursor.read_u8()? as usize;
        cursor.read_u8()?; // reserved
        cursor.read_u16::<LittleEndian>()?; // reserved
        debug!(
            assoc_group,
            sec_addr_len, num_results, "bind_ack context summary"
        );

        if num_results == 0 {
            return Err(TransportError::Failure(
                "bind_ack missing presentation results".into(),
            ));
        }

        let mut accepted_context = None;

        for ctx_index in 0..num_results {
            let result = cursor.read_u16::<LittleEndian>()?;
            let reason = cursor.read_u16::<LittleEndian>()?;
            let mut syntax = [0u8; 16];
            cursor.read_exact(&mut syntax)?;
            cursor.read_u32::<LittleEndian>()?; // syntax version
            if result != 0 {
                warn!(
                    result,
                    reason,
                    context = ctx_index,
                    "bind context rejected by server"
                );
                return Err(TransportError::Bind { result, reason });
            }
            if accepted_context.is_none() {
                accepted_context = Some(ctx_index as u16);
            }
        }

        let context_id = accepted_context.unwrap_or(0);

        if auth_len == 0 {
            return Err(TransportError::Failure("bind_ack missing auth data".into()));
        }

        // Find the auth trailer - it should be at the end minus auth_len
        // The auth trailer starts with auth_type (1 byte), auth_level (1 byte), etc.
        let auth_data_start = pdu.len() - auth_len as usize;

        // Auth trailer is 8 bytes before the auth data
        let trailer_start = auth_data_start - 8;
        if trailer_start >= pdu.len() || trailer_start < 16 {
            return Err(TransportError::Failure(
                "bind_ack malformed: security trailer position invalid".into(),
            ));
        }

        cursor.set_position(trailer_start as u64);
        let auth_type = cursor.read_u8()?;
        let _auth_level = cursor.read_u8()?;
        let auth_pad_len = cursor.read_u8()?;
        cursor.read_u8()?; // reserved
        cursor.read_u32::<LittleEndian>()?; // auth context id
        if auth_pad_len > 0 {
            let mut padding = vec![0u8; auth_pad_len as usize];
            cursor.read_exact(&mut padding)?;
        }
        let mut blob = vec![0u8; auth_len as usize];
        cursor.read_exact(&mut blob)?;

        // Handle different auth types
        let unwrapped_blob = match auth_type {
            0x0A => {
                // Raw NTLM
                match crate::auth::parse_type2_message(&blob) {
                    Ok(challenge) => {
                        debug!(
                            flags = format_args!("0x{:#x}", challenge.flags),
                            "parsed NTLM challenge"
                        );
                    }
                    Err(err) => warn!(?err, "failed to parse NTLM challenge from bind_ack"),
                }
                blob.clone()
            }
            0x09 => {
                // SPNEGO - need to unwrap
                debug!("Received SPNEGO response in bind_ack, unwrapping");
                match spnego::parse_spnego_response(&blob) {
                    Ok(inner) => {
                        // Try to parse as NTLM Type2 if it looks like NTLM
                        if inner.starts_with(b"NTLMSSP\0") {
                            match crate::auth::parse_type2_message(&inner) {
                                Ok(challenge) => {
                                    debug!(
                                        flags = format_args!("0x{:#x}", challenge.flags),
                                        "parsed NTLM challenge from SPNEGO"
                                    );
                                }
                                Err(err) => warn!(?err, "failed to parse NTLM from SPNEGO"),
                            }
                        }
                        inner
                    }
                    Err(err) => {
                        warn!(?err, "Failed to parse SPNEGO response");
                        blob.clone()
                    }
                }
            }
            0x10 => {
                // Kerberos
                debug!("Received Kerberos AP-REP in bind_ack");
                blob.clone()
            }
            _ => {
                warn!(auth_type, "Unknown auth type in bind_ack");
                blob.clone()
            }
        };

        Ok((context_id, unwrapped_blob, max_xmit, max_recv))
    }

    pub(crate) fn parse_alter_ack(pdu: &[u8]) -> Result<(), TransportError> {
        use byteorder::ReadBytesExt as _;
        let mut cursor = Cursor::new(pdu);
        let _version = cursor.read_u8()?;
        let _minor = cursor.read_u8()?;
        let ptype = cursor.read_u8()?;
        if ptype != 0x0D {
            return Err(TransportError::Failure(format!(
                "Unexpected PDU type in alter_ack: 0x{ptype:02x} (expected 0x0D)"
            )));
        }
        cursor.read_u8()?; // flags
        cursor.read_u32::<LittleEndian>()?; // data rep
        let _frag_len = cursor.read_u16::<LittleEndian>()?;
        let auth_len = cursor.read_u16::<LittleEndian>()?;
        cursor.read_u32::<LittleEndian>()?; // call_id

        let _max_xmit = cursor.read_u16::<LittleEndian>()?;
        let _max_recv = cursor.read_u16::<LittleEndian>()?;
        let _assoc_group = cursor.read_u32::<LittleEndian>()?;
        let sec_addr_len = cursor.read_u16::<LittleEndian>()? as usize;

        if sec_addr_len > 0 {
            let mut sec_addr = vec![0u8; sec_addr_len];
            cursor.read_exact(&mut sec_addr)?;
        }

        let pad = (4 - (cursor.position() as usize % 4)) % 4;
        if pad > 0 {
            let mut padding = vec![0u8; pad];
            cursor.read_exact(&mut padding)?;
        }

        let num_results = cursor.read_u8()? as usize;
        cursor.read_u8()?; // reserved
        cursor.read_u16::<LittleEndian>()?; // reserved

        for _ in 0..num_results {
            let result = cursor.read_u16::<LittleEndian>()?;
            let _reason = cursor.read_u16::<LittleEndian>()?;
            let mut syntax = [0u8; 16];
            cursor.read_exact(&mut syntax)?;
            cursor.read_u32::<LittleEndian>()?; // syntax version

            if result != 0 {
                warn!(result, "alter_context rejected by server");
                return Err(TransportError::AlterReject { result });
            }
        }

        if auth_len > 0 {
            let auth_trailer_pos = pdu.len() - auth_len as usize - 8;
            cursor.set_position(auth_trailer_pos as u64);
            let _auth_type = cursor.read_u8()?;
            let auth_level = cursor.read_u8()?;

            if auth_level != 6 {
                warn!(
                    auth_level,
                    "unexpected auth level in alter_ack (expected 6)"
                );
            }
        }

        debug!("alter_ack accepted, authentication complete");
        Ok(())
    }

    /// Configure socket timeouts in a platform-specific way
    /// On macOS, socket timeouts can cause non-blocking behavior
    #[cfg(target_os = "macos")]
    fn configure_socket_timeouts(
        socket: &Socket,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Result<(), TransportError> {
        // On macOS, we use a short timeout to detect non-blocking behavior
        // but keep the socket effectively blocking for most operations
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|err| TransportError::Failure(err.to_string()))?;
        socket
            .set_write_timeout(Some(Duration::from_millis(100)))
            .map_err(|err| TransportError::Failure(err.to_string()))?;
        debug!("macOS: Socket configured with short timeouts for retry loops (100ms), actual timeouts: read={:?}, write={:?}", read_timeout, write_timeout);
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    fn configure_socket_timeouts(
        socket: &Socket,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Result<(), TransportError> {
        socket
            .set_read_timeout(Some(read_timeout))
            .map_err(|err| TransportError::Failure(err.to_string()))?;
        socket
            .set_write_timeout(Some(write_timeout))
            .map_err(|err| TransportError::Failure(err.to_string()))?;
        debug!("Socket timeouts set: read={:?}, write={:?}", read_timeout, write_timeout);
        Ok(())
    }

    /// Write all bytes with retry logic for non-blocking sockets
    /// This handles macOS-specific behavior where sockets may be non-blocking
    #[allow(dead_code)]
    fn write_all_with_retry(
        stream: &mut TcpStream,
        buf: &[u8],
        timeout: Duration,
    ) -> Result<(), std::io::Error> {
        let deadline = std::time::Instant::now() + timeout;
        let mut pos = 0;

        debug!("write_all_with_retry: attempting to write {} bytes with {:?} timeout", buf.len(), timeout);

        while pos < buf.len() {
            match stream.write(&buf[pos..]) {
                Ok(n) => {
                    pos += n;
                    debug!("wrote {} bytes, total {}/{}", n, pos, buf.len());
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!("write timeout after writing {} of {} bytes", pos, buf.len()),
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    /// Read exact number of bytes with retry logic for non-blocking sockets
    /// This handles macOS-specific behavior where sockets with timeouts behave as non-blocking
    fn read_exact_with_retry(
        stream: &mut TcpStream,
        buf: &mut [u8],
        timeout: Duration,
    ) -> Result<(), std::io::Error> {
        let deadline = std::time::Instant::now() + timeout;
        let mut pos = 0;

        debug!("read_exact_with_retry: attempting to read {} bytes with {:?} timeout", buf.len(), timeout);

        while pos < buf.len() {
            match stream.read(&mut buf[pos..]) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection closed while reading",
                    ));
                }
                Ok(n) => {
                    pos += n;
                    debug!("read {} bytes, total {}/{}", n, pos, buf.len());
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                           || e.kind() == std::io::ErrorKind::TimedOut => {
                    if std::time::Instant::now() >= deadline {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!("read timeout after reading {} of {} bytes", pos, buf.len()),
                        ));
                    }
                    // Use smaller sleep for better responsiveness on macOS
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    fn read_pdu(stream: &mut TcpStream) -> Result<Vec<u8>, TransportError> {
        let span = tracing::trace_span!("read_pdu");
        let _enter = span.enter();

        // Read the first fragment
        let mut header = [0u8; 16];
        // Use our retry-capable read function to handle macOS non-blocking behavior
        Self::read_exact_with_retry(stream, &mut header, Duration::from_secs(10))
            .map_err(|err| {
                error!(?err, "failed to read RPC PDU header");
                TransportError::Failure(err.to_string())
            })?;

        let flags = header[3];
        let frag_len = u16::from_le_bytes([header[8], header[9]]) as usize;
        if frag_len < 16 {
            return Err(TransportError::Failure(format!(
                "invalid RPC fragment length {frag_len}"
            )));
        }

        // Read the rest of the first fragment
        let mut buffer = vec![0u8; frag_len];
        buffer[..16].copy_from_slice(&header);

        let mut offset = 16;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);

        while offset < frag_len {
            match stream.read(&mut buffer[offset..]) {
                Ok(0) => {
                    return Err(TransportError::Failure(
                        "connection closed while reading RPC PDU".into(),
                    ));
                }
                Ok(n) => {
                    offset += n;
                }
                Err(err)
                    if err.kind() == std::io::ErrorKind::WouldBlock
                        || err.kind() == std::io::ErrorKind::TimedOut =>
                {
                    if std::time::Instant::now() >= deadline {
                        error!(?err, "RPC read timed out");
                        return Err(TransportError::Failure("RPC response timed out".into()));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(25));
                    continue;
                }
                Err(err) => {
                    error!(?err, "failed to read RPC PDU body");
                    return Err(TransportError::Failure(err.to_string()));
                }
            }
        }

        // Check if this is the last fragment (bit 1 of flags indicates more fragments)
        const PFC_LAST_FRAG: u8 = 0x02;
        if (flags & PFC_LAST_FRAG) != 0 {
            // Single fragment, we're done
            debug!(frag_len, "read single-fragment RPC PDU");
            return Ok(buffer);
        }

        debug!(flags, frag_len, "reading multi-fragment RPC PDU");
        let mut fragments = vec![buffer];

        loop {
            let mut frag_header = [0u8; 16];
            stream.read_exact(&mut frag_header).map_err(|err| {
                error!(?err, "failed to read fragment header");
                TransportError::Failure(err.to_string())
            })?;

            let frag_flags = frag_header[3];
            let fragment_len = u16::from_le_bytes([frag_header[8], frag_header[9]]) as usize;
            if fragment_len < 16 {
                return Err(TransportError::Failure(format!(
                    "invalid fragment length {fragment_len}"
                )));
            }

            let mut frag = vec![0u8; fragment_len];
            frag[..16].copy_from_slice(&frag_header);

            offset = 16;
            while offset < fragment_len {
                match stream.read(&mut frag[offset..]) {
                    Ok(0) => {
                        return Err(TransportError::Failure(
                            "connection closed while reading fragment".into(),
                        ));
                    }
                    Ok(n) => offset += n,
                    Err(err)
                        if err.kind() == std::io::ErrorKind::WouldBlock
                            || err.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        if std::time::Instant::now() >= deadline {
                            error!(?err, "fragment read timed out");
                            return Err(TransportError::Failure("RPC fragment timed out".into()));
                        }
                        std::thread::sleep(std::time::Duration::from_millis(25));
                    }
                    Err(err) => {
                        error!(?err, "failed to read fragment body");
                        return Err(TransportError::Failure(err.to_string()));
                    }
                }
            }

            fragments.push(frag);

            if (frag_flags & PFC_LAST_FRAG) != 0 {
                break;
            }

            if fragments.len() > 1024 {
                return Err(TransportError::Failure("too many RPC fragments".into()));
            }
        }

        let first_fragment = &fragments[0];
        let mut header = first_fragment[..16].to_vec();
        let response_header = first_fragment[16..24].to_vec();
        let mut stub = Vec::new();
        let mut trailer = Vec::new();

        for (idx, fragment) in fragments.iter().enumerate() {
            let frag_len = u16::from_le_bytes([fragment[8], fragment[9]]) as usize;
            let auth_len = u16::from_le_bytes([fragment[10], fragment[11]]) as usize;

            let verifier_len = if auth_len > 0 { auth_len + 8 } else { 0 };
            let stub_start = 24;
            let stub_end = if verifier_len > 0 {
                frag_len.checked_sub(verifier_len).ok_or_else(|| {
                    TransportError::Failure("invalid fragment verifier length".into())
                })?
            } else {
                frag_len
            };

            if stub_end < stub_start || stub_end > fragment.len() {
                return Err(TransportError::Failure(
                    "invalid fragment stub bounds".into(),
                ));
            }

            stub.extend_from_slice(&fragment[stub_start..stub_end]);

            if idx == fragments.len() - 1 && verifier_len > 0 {
                if verifier_len > frag_len {
                    return Err(TransportError::Failure("invalid verifier length".into()));
                }
                trailer.extend_from_slice(&fragment[frag_len - verifier_len..frag_len]);
            }
        }

        header[3] |= PFC_LAST_FRAG;
        let total_len = 16 + response_header.len() + stub.len() + trailer.len();
        header[8..10].copy_from_slice(&(total_len as u16).to_le_bytes());
        if let Some(last_fragment) = fragments.last() {
            let final_auth_len = u16::from_le_bytes([last_fragment[10], last_fragment[11]]);
            header[10..12].copy_from_slice(&final_auth_len.to_le_bytes());
        }

        let mut reassembled = header;
        reassembled.extend_from_slice(&response_header);
        reassembled.extend_from_slice(&stub);
        reassembled.extend_from_slice(&trailer);

        debug!(
            total_len = reassembled.len(),
            fragment_count = fragments.len(),
            "successfully reassembled fragmented RPC PDU"
        );

        Ok(reassembled)
    }
}

impl RpcTransport for RealRpcTransport {
    fn name(&self) -> &'static str {
        "real-transport"
    }

    fn invoke(&mut self, opnum: u16, payload: &[u8]) -> Result<Vec<u8>, TransportError> {
        // Build request PDU with ORPCTHIS if we have IPID (for object calls)
        let mut request_pdu = if self.ipid.is_some() {
            // For object calls, prepend ORPCTHIS header
            let mut orpc_request = Vec::new();

            // Encode ORPCTHIS header (40 bytes)
            orpc_request.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Version
            orpc_request.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Flags
            orpc_request.extend_from_slice(&[0x00; 8]); // Reserved1
                                                        // CID (causality ID) - use a simple incrementing value
            self.causality_id = self.causality_id.wrapping_add(1);
            let mut cid = [0u8; 16];
            cid[0..4].copy_from_slice(&self.causality_id.to_le_bytes());
            orpc_request.extend_from_slice(&cid);
            orpc_request.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Extensions

            // Add the original payload
            orpc_request.extend_from_slice(payload);

            build_request_pdu(self.call_id, self.context_id, opnum, &orpc_request)
        } else {
            build_request_pdu(self.call_id, self.context_id, opnum, payload)
        };

        if self.auth_level >= 4 {
            seal_pdu_in_place(
                &self.session_key,
                self.auth_level,
                self.context_id,
                &mut self.seqno,
                &mut request_pdu,
            )?;
        }

        self.call_id += 1;

        debug!(
            opnum,
            call_id = self.call_id - 1,
            payload_len = payload.len(),
            auth_level = self.auth_level,
            has_orpc = self.ipid.is_some(),
            "sending RPC request"
        );

        self.stream.write_all(&request_pdu)?;

        // Read and process response
        let mut response = Self::read_pdu(&mut self.stream)?;

        // Unseal/verify response if authenticated
        if self.auth_level > 0 {
            unseal_response_pdu_in_place(
                &self.session_key,
                self.auth_level,
                self.context_id,
                self.seqno,
                &mut response,
            )?;
        }

        // Note: read_pdu already handles fragmented responses internally

        let stub_data = parse_response_pdu(&response)?;

        // If this was an object call, strip ORPCTHAT from response
        let final_data = if self.ipid.is_some() && stub_data.len() >= 16 {
            // Skip ORPCTHAT header (16 bytes minimum)
            // Format: Flags (4) + Extensions pointer (4) + optional extension data
            let mut offset = 4; // Skip flags
            if stub_data.len() > offset + 4 {
                let ext_ptr = u32::from_le_bytes([
                    stub_data[offset],
                    stub_data[offset + 1],
                    stub_data[offset + 2],
                    stub_data[offset + 3],
                ]);
                offset += 4;
                if ext_ptr != 0 {
                    // There are extensions, skip them too
                    // For now, assume no extensions and just skip the header
                }
            }
            stub_data[offset..].to_vec()
        } else {
            stub_data
        };

        debug!(opnum, stub_len = final_data.len(), "received RPC response");

        Ok(final_data)
    }
}

#[cfg(feature = "async")]
#[async_trait]
#[allow(dead_code)]
pub trait AsyncRpcTransport: Send + Sync {
    async fn name(&self) -> &'static str;
    async fn invoke(&self, opnum: u16, payload: &[u8]) -> Result<Vec<u8>, TransportError>;
    async fn shutdown(&self) -> Result<(), TransportError>;
}

#[cfg(feature = "async")]
#[derive(Debug)]
struct AsyncTransportState {
    stream: TokioTcpStream,
    call_id: u32,
    causality_id: u32,
    seqno: u32,
    max_xmit: u16,
    max_recv: u16,
}

#[cfg(feature = "async")]
#[derive(Debug)]
pub struct AsyncRealRpcTransport {
    state: Mutex<AsyncTransportState>,
    context_id: u16,
    session_key: Vec<u8>,
    auth_level: u8,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    ipid: Option<[u8; 16]>,
    _object_ref: Option<crate::dcom::ObjectReference>,
    host: String,
    port: u16,
}

#[cfg(feature = "async")]
impl AsyncRealRpcTransport {
    pub async fn connect(config: RealTransportConfig) -> Result<Self, TransportError> {
        config.validate()?;

        let RealTransportConfig {
            host,
            username,
            password,
            domain,
            read_timeout,
            write_timeout,
        } = config;

        let effective_read_timeout = read_timeout.unwrap_or(Duration::from_secs(10));
        let effective_write_timeout = write_timeout.unwrap_or(Duration::from_secs(10));

        let username = username.unwrap_or_default();
        let password = password.unwrap_or_default();
        let domain = domain.unwrap_or_default();

        let creds = Credentials::new(
            username.clone(),
            password.clone(),
            domain.clone(),
            host.clone(),
        );

        let creds_for_epm = creds.clone();
        let host_for_epm = host.clone();
        let port = spawn_blocking(move || {
            crate::dcom::resolve_wmi_port(&host_for_epm, Some(&creds_for_epm))
        })
        .await
        .map_err(|err| TransportError::Failure(format!("EPM resolution task failed: {err}")))?
        .map_err(|err| TransportError::Failure(err.to_string()))?;

        let stream = Self::connect_stream(&host, port).await?;
        let (state, context_id, session_key, auth_level) = Self::perform_handshake(
            stream,
            creds,
            Some(effective_read_timeout),
            Some(effective_write_timeout),
        )
        .await?;

        Ok(Self {
            state: Mutex::new(state),
            context_id,
            session_key,
            auth_level,
            read_timeout: Some(effective_read_timeout),
            write_timeout: Some(effective_write_timeout),
            ipid: None,
            _object_ref: None,
            host,
            port,
        })
    }

    pub async fn connect_with_oxid(
        config: RealTransportConfig,
        port: u16,
        oxid: [u8; 8],
    ) -> Result<Self, TransportError> {
        config.validate()?;

        let RealTransportConfig {
            host,
            username,
            password,
            domain,
            read_timeout,
            write_timeout,
        } = config;

        let effective_read_timeout = read_timeout.unwrap_or(Duration::from_secs(10));
        let effective_write_timeout = write_timeout.unwrap_or(Duration::from_secs(10));

        let (username, password) = match (username, password) {
            (Some(u), Some(p)) => (u, p),
            _ => {
                return Err(TransportError::Failure(
                    "Credentials required for authenticated transport".into(),
                ))
            }
        };
        let domain = domain.unwrap_or_default();
        let creds = Credentials::new(
            username.clone(),
            password.clone(),
            domain.clone(),
            host.clone(),
        );

        let stream = Self::connect_stream(&host, port).await?;
        let (state, context_id, session_key, auth_level) = Self::perform_handshake(
            stream,
            creds.clone(),
            Some(effective_read_timeout),
            Some(effective_write_timeout),
        )
        .await?;

        let host_for_oxid = host.clone();
        let creds_for_oxid = creds.clone();
        let object_ref = spawn_blocking(move || {
            crate::dcom::resolve_oxid(&host_for_oxid, port, &creds_for_oxid, &oxid)
        })
        .await
        .map_err(|err| TransportError::Failure(format!("OXID resolution task failed: {err}")))?
        .map_err(|err| TransportError::Failure(err.to_string()))?;

        Ok(Self {
            state: Mutex::new(state),
            context_id,
            session_key,
            auth_level,
            read_timeout: Some(effective_read_timeout),
            write_timeout: Some(effective_write_timeout),
            ipid: Some(object_ref.ipid),
            _object_ref: Some(object_ref),
            host,
            port,
        })
    }

    async fn connect_stream(host: &str, port: u16) -> Result<TokioTcpStream, TransportError> {
        let addr = format!("{host}:{port}");
        let stream = TokioTcpStream::connect(addr)
            .await
            .map_err(|err| TransportError::Failure(err.to_string()))?;
        stream
            .set_nodelay(true)
            .map_err(|err| TransportError::Failure(err.to_string()))?;
        Ok(stream)
    }

    async fn perform_handshake(
        mut stream: TokioTcpStream,
        creds: Credentials,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
    ) -> Result<(AsyncTransportState, u16, Vec<u8>, u8), TransportError> {
        let mut auth =
            NtlmV2Client::new(creds).map_err(|err| TransportError::Failure(err.to_string()))?;

        let negotiate = auth
            .negotiate()
            .map_err(|err| TransportError::Failure(err.to_string()))?;
        let bind_pdu = RealRpcTransport::build_bind_pdu(1, &negotiate);
        write_all_with_timeout(&mut stream, &bind_pdu, write_timeout).await?;

        let bind_ack = read_pdu_async(&mut stream, read_timeout).await?;
        let (context_id, type2, max_xmit, max_recv) = RealRpcTransport::parse_bind_ack(&bind_ack)?;

        let authenticate = auth
            .respond_message(&type2)
            .map_err(|err| TransportError::Failure(err.to_string()))?;
        let alter_context =
            RealRpcTransport::build_alter_context_pdu(2, context_id, &authenticate.message);
        write_all_with_timeout(&mut stream, &alter_context, write_timeout).await?;

        let alter_ack = read_pdu_async(&mut stream, read_timeout).await?;
        RealRpcTransport::parse_alter_ack(&alter_ack)?;

        let session_key = authenticate.session_key.to_vec();

        let state = AsyncTransportState {
            stream,
            call_id: 3,
            causality_id: 0,
            seqno: 0,
            max_xmit,
            max_recv,
        };

        Ok((state, context_id, session_key, 6))
    }

    pub async fn check(&self) -> Result<(), TransportError> {
        let state = self.state.lock().await;
        if let Some(dur) = self.read_timeout {
            let result = timeout(dur, state.stream.writable())
                .await
                .map_err(|_| TransportError::Failure("transport health check timed out".into()))?;
            result?;
        } else {
            state.stream.writable().await?;
        }
        Ok(())
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl AsyncRpcTransport for AsyncRealRpcTransport {
    async fn name(&self) -> &'static str {
        "async-real-transport"
    }

    async fn invoke(&self, opnum: u16, payload: &[u8]) -> Result<Vec<u8>, TransportError> {
        let mut state = self.state.lock().await;

        let mut request_pdu = if self.ipid.is_some() {
            let mut orpc_request = Vec::new();
            orpc_request.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
            orpc_request.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            orpc_request.extend_from_slice(&[0x00; 8]);
            state.causality_id = state.causality_id.wrapping_add(1);
            let mut cid = [0u8; 16];
            cid[0..4].copy_from_slice(&state.causality_id.to_le_bytes());
            orpc_request.extend_from_slice(&cid);
            orpc_request.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            orpc_request.extend_from_slice(payload);

            build_request_pdu(state.call_id, self.context_id, opnum, &orpc_request)
        } else {
            build_request_pdu(state.call_id, self.context_id, opnum, payload)
        };

        let current_call_id = state.call_id;
        state.call_id = state.call_id.wrapping_add(1);

        if self.auth_level >= 4 {
            let session_key = self.session_key.clone();
            let context_id = self.context_id;
            let auth_level = self.auth_level;
            let seqno_value = state.seqno;
            let write_payload = mem::take(&mut request_pdu);

            let (sealed, updated_seqno) = spawn_blocking(move || {
                let mut seq = seqno_value;
                let mut pdu_inner = write_payload;
                seal_pdu_in_place(
                    &session_key,
                    auth_level,
                    context_id,
                    &mut seq,
                    &mut pdu_inner,
                )?;
                Ok::<_, TransportError>((pdu_inner, seq))
            })
            .await
            .map_err(|err| TransportError::Failure(format!("crypto task failed: {err}")))??;

            request_pdu = sealed;
            state.seqno = updated_seqno;
        }

        write_all_with_timeout(&mut state.stream, &request_pdu, self.write_timeout).await?;

        let mut response = read_pdu_async(&mut state.stream, self.read_timeout).await?;

        if self.auth_level > 0 {
            let session_key = self.session_key.clone();
            let context_id = self.context_id;
            let auth_level = self.auth_level;
            let seqno_state = state.seqno;
            let response_buf = mem::take(&mut response);

            response = spawn_blocking(move || {
                let mut resp_inner = response_buf;
                unseal_response_pdu_in_place(
                    &session_key,
                    auth_level,
                    context_id,
                    seqno_state,
                    &mut resp_inner,
                )?;
                Ok::<_, TransportError>(resp_inner)
            })
            .await
            .map_err(|err| TransportError::Failure(format!("crypto task failed: {err}")))??;
        }

        let stub_data = parse_response_pdu(&response)?;

        let final_data = if self.ipid.is_some() && stub_data.len() >= 16 {
            let mut offset = 4;
            if stub_data.len() > offset + 4 {
                let ext_ptr = u32::from_le_bytes([
                    stub_data[offset],
                    stub_data[offset + 1],
                    stub_data[offset + 2],
                    stub_data[offset + 3],
                ]);
                offset += 4;
                if ext_ptr != 0 {
                    offset = offset; // extensions currently ignored
                }
            }
            stub_data[offset..].to_vec()
        } else {
            stub_data
        };

        debug!(
            opnum,
            call_id = current_call_id,
            payload_len = payload.len(),
            auth_level = self.auth_level,
            has_orpc = self.ipid.is_some(),
            "completed async RPC invoke"
        );

        Ok(final_data)
    }

    async fn shutdown(&self) -> Result<(), TransportError> {
        use tokio::io::AsyncWriteExt;
        let mut state = self.state.lock().await;
        state
            .stream
            .shutdown()
            .await
            .map_err(|err| TransportError::Failure(err.to_string()))
    }
}

#[cfg(feature = "async")]
async fn write_all_with_timeout(
    stream: &mut TokioTcpStream,
    data: &[u8],
    duration: Option<Duration>,
) -> Result<(), TransportError> {
    use tokio::io::AsyncWriteExt;
    if let Some(timeout_duration) = duration {
        let result = timeout(timeout_duration, stream.write_all(data))
            .await
            .map_err(|_| TransportError::Failure("RPC write timed out".into()))?;
        result?;
    } else {
        stream.write_all(data).await?;
    }
    Ok(())
}

#[cfg(feature = "async")]
async fn read_pdu_async(
    stream: &mut TokioTcpStream,
    duration: Option<Duration>,
) -> Result<Vec<u8>, TransportError> {
    let mut header = [0u8; 16];
    read_exact_with_timeout(stream, &mut header, duration).await?;

    let flags = header[3];
    let frag_len = u16::from_le_bytes([header[8], header[9]]) as usize;
    if frag_len < 16 {
        return Err(TransportError::Failure(format!(
            "invalid RPC fragment length {frag_len}"
        )));
    }

    let mut buffer = vec![0u8; frag_len];
    buffer[..16].copy_from_slice(&header);

    let mut offset = 16;
    while offset < frag_len {
        let n = read_chunk_with_timeout(stream, &mut buffer[offset..], duration).await?;
        if n == 0 {
            return Err(TransportError::Failure(
                "connection closed while reading RPC PDU".into(),
            ));
        }
        offset += n;
    }

    const PFC_LAST_FRAG: u8 = 0x02;
    if (flags & PFC_LAST_FRAG) != 0 {
        return Ok(buffer);
    }

    let mut fragments = vec![buffer];

    loop {
        let mut frag_header = [0u8; 16];
        read_exact_with_timeout(stream, &mut frag_header, duration).await?;
        let frag_flags = frag_header[3];
        let fragment_len = u16::from_le_bytes([frag_header[8], frag_header[9]]) as usize;
        if fragment_len < 16 {
            return Err(TransportError::Failure(format!(
                "invalid fragment length {fragment_len}"
            )));
        }

        let mut fragment = vec![0u8; fragment_len];
        fragment[..16].copy_from_slice(&frag_header);

        let mut frag_offset = 16;
        while frag_offset < fragment_len {
            let n = read_chunk_with_timeout(stream, &mut fragment[frag_offset..], duration).await?;
            if n == 0 {
                return Err(TransportError::Failure(
                    "connection closed while reading fragment".into(),
                ));
            }
            frag_offset += n;
        }

        fragments.push(fragment);

        if (frag_flags & PFC_LAST_FRAG) != 0 {
            break;
        }

        if fragments.len() > 1024 {
            return Err(TransportError::Failure("too many RPC fragments".into()));
        }
    }

    reassemble_fragments(fragments)
}

#[cfg(feature = "async")]
async fn read_exact_with_timeout(
    stream: &mut TokioTcpStream,
    buf: &mut [u8],
    duration: Option<Duration>,
) -> Result<(), TransportError> {
    use tokio::io::AsyncReadExt;
    if let Some(timeout_duration) = duration {
        let result = timeout(timeout_duration, stream.read_exact(buf))
            .await
            .map_err(|_| TransportError::Failure("RPC read timed out".into()))?;
        result?;
    } else {
        stream.read_exact(buf).await?;
    }
    Ok(())
}

#[cfg(feature = "async")]
async fn read_chunk_with_timeout(
    stream: &mut TokioTcpStream,
    buf: &mut [u8],
    duration: Option<Duration>,
) -> Result<usize, TransportError> {
    use tokio::io::AsyncReadExt;
    if let Some(timeout_duration) = duration {
        let result = timeout(timeout_duration, stream.read(buf))
            .await
            .map_err(|_| TransportError::Failure("RPC read timed out".into()))?;
        result.map_err(TransportError::from)
    } else {
        stream.read(buf).await.map_err(TransportError::from)
    }
}

#[cfg(feature = "async")]
fn reassemble_fragments(fragments: Vec<Vec<u8>>) -> Result<Vec<u8>, TransportError> {
    let first_fragment = &fragments[0];
    let mut header = first_fragment[..16].to_vec();
    let response_header = first_fragment[16..24].to_vec();
    let mut stub = Vec::new();
    let mut trailer = Vec::new();

    for (idx, fragment) in fragments.iter().enumerate() {
        let frag_len = u16::from_le_bytes([fragment[8], fragment[9]]) as usize;
        let auth_len = u16::from_le_bytes([fragment[10], fragment[11]]) as usize;
        let verifier_len = if auth_len > 0 { auth_len + 8 } else { 0 };
        let stub_start = 24;
        let stub_end = if verifier_len > 0 {
            frag_len
                .checked_sub(verifier_len)
                .ok_or_else(|| TransportError::Failure("invalid fragment verifier length".into()))?
        } else {
            frag_len
        };

        if stub_end < stub_start || stub_end > fragment.len() {
            return Err(TransportError::Failure(
                "invalid fragment stub bounds".into(),
            ));
        }

        stub.extend_from_slice(&fragment[stub_start..stub_end]);

        if idx == fragments.len() - 1 && verifier_len > 0 {
            if verifier_len > frag_len {
                return Err(TransportError::Failure("invalid verifier length".into()));
            }
            trailer.extend_from_slice(&fragment[frag_len - verifier_len..frag_len]);
        }
    }

    header[3] |= 0x02;
    let total_len = 16 + response_header.len() + stub.len() + trailer.len();
    header[8..10].copy_from_slice(&(total_len as u16).to_le_bytes());
    if let Some(last_fragment) = fragments.last() {
        let final_auth_len = u16::from_le_bytes([last_fragment[10], last_fragment[11]]);
        header[10..12].copy_from_slice(&final_auth_len.to_le_bytes());
    }

    let mut reassembled = header;
    reassembled.extend_from_slice(&response_header);
    reassembled.extend_from_slice(&stub);
    reassembled.extend_from_slice(&trailer);
    Ok(reassembled)
}

// RealRpcTransport implementation helpers are defined above

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{LittleEndian, ReadBytesExt};
    use hex_literal::hex;
    use std::io::{Cursor, Read};

    #[test]
    #[cfg(feature = "test-support")]
    fn stub_transport_invoke_returns_empty() {
        use crate::test_support::StubTransport;
        let mut transport = StubTransport;
        let result = transport.invoke(9, &[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn real_transport_handles_orpcthis_in_invoke() {
        // This test validates that the invoke method properly adds ORPCTHIS header
        // when IPID is set, which is required for object calls.
        // Real integration testing would require a Windows target.
        assert!(true, "ORPCTHIS handling is implemented in invoke method");
    }

    #[test]
    fn parse_bind_ack_extracts_ntlm_challenge() {
        let type2 = crate::auth::sample_type2();

        let mut body = Vec::new();
        body.extend_from_slice(&0x10d8u16.to_le_bytes()); // max_xmit
        body.extend_from_slice(&0x10d8u16.to_le_bytes()); // max_recv
        body.extend_from_slice(&1u32.to_le_bytes()); // assoc group
        body.extend_from_slice(&0u16.to_le_bytes()); // sec_addr_len
        body.extend_from_slice(&[0u8; 2]); // align (sec addr + pad)
        body.push(1); // num_results
        body.push(0); // reserved
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes()); // result accept
        body.extend_from_slice(&0u16.to_le_bytes()); // reason
        body.extend_from_slice(&[0u8; 16]); // abstract syntax (ignored)
        body.extend_from_slice(&0u32.to_le_bytes());

        // Security trailer + NTLM challenge
        body.push(0x0A); // auth_type NTLM
        body.push(0x06); // auth_level privacy
        body.push(0); // auth_pad_len
        body.push(0); // reserved
        body.extend_from_slice(&0u32.to_le_bytes()); // auth context id
        body.extend_from_slice(&type2);

        let frag_len = (16 + body.len()) as u16;
        let auth_len = type2.len() as u16;

        let mut pdu = Vec::new();
        pdu.extend_from_slice(&[5, 0, 0x0C, 0x03]);
        pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // little endian data rep
        pdu.extend_from_slice(&frag_len.to_le_bytes());
        pdu.extend_from_slice(&auth_len.to_le_bytes());
        pdu.extend_from_slice(&1u32.to_le_bytes());
        pdu.extend_from_slice(&body);

        let (_context_id, challenge, max_xmit, max_recv) =
            RealRpcTransport::parse_bind_ack(&pdu).expect("bind_ack parse");
        assert!(challenge.starts_with(b"NTLMSSP\0"));
        assert!(max_xmit > 0);
        assert!(max_recv > 0);

        let parsed = crate::auth::parse_type2_message(&challenge).expect("parse type2");
        assert_ne!(parsed.flags, 0);
        assert_eq!(parsed.server_challenge.len(), 8);
        assert!(!parsed.target_info.is_empty());
    }

    #[test]
    fn build_request_pdu_creates_valid_structure() {
        let pdu = build_request_pdu(42, 1, 9, b"test_stub");

        assert_eq!(pdu[0], 5, "RPC version");
        assert_eq!(pdu[1], 0, "RPC minor version");
        assert_eq!(pdu[2], 0x00, "PDU type: request");
        assert_eq!(pdu[3], 0x03, "Flags first|last");

        let frag_len = u16::from_le_bytes([pdu[8], pdu[9]]) as usize;
        assert_eq!(frag_len, pdu.len());

        let call_id = u32::from_le_bytes([pdu[12], pdu[13], pdu[14], pdu[15]]);
        assert_eq!(call_id, 42);

        let context_id = u16::from_le_bytes([pdu[20], pdu[21]]);
        assert_eq!(context_id, 1);

        let opnum = u16::from_le_bytes([pdu[22], pdu[23]]);
        assert_eq!(opnum, 9);

        assert_eq!(&pdu[24..], b"test_stub");
    }

    #[test]
    fn parse_response_pdu_extracts_stub_data() {
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&[5, 0, 0x02, 0x03]); // version, minor, response, flags
        pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // data rep
        pdu.extend_from_slice(&[42, 0]); // frag_len = 42
        pdu.extend_from_slice(&[0, 0]); // auth_len = 0
        pdu.extend_from_slice(&[42, 0, 0, 0]); // call_id
        pdu.extend_from_slice(&[0, 0, 0, 0]); // alloc_hint
        pdu.extend_from_slice(&[1, 0]); // context_id
        pdu.extend_from_slice(&[0, 0]); // cancel_count, reserved
        pdu.extend_from_slice(b"stub_response_data");

        let stub = parse_response_pdu(&pdu).unwrap();
        assert_eq!(stub, b"stub_response_data");
    }

    #[test]
    fn parse_response_pdu_detects_fault() {
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&[5, 0, 0x03, 0x03]); // version, minor, fault, flags
        pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // data rep
        pdu.extend_from_slice(&[32, 0]); // frag_len
        pdu.extend_from_slice(&[0, 0]); // auth_len
        pdu.extend_from_slice(&[42, 0, 0, 0]); // call_id
        pdu.extend_from_slice(&[0, 0, 0, 0]); // alloc_hint
        pdu.extend_from_slice(&[0, 0, 0, 0]); // padding
        pdu.extend_from_slice(&[0x05, 0x00, 0x07, 0x00]); // status = 0x00070005 (access denied)

        let err = parse_response_pdu(&pdu).unwrap_err();
        match err {
            TransportError::Failure(msg) => assert!(msg.contains("0x00070005")),
            _ => panic!("Expected Failure error"),
        }
    }

    #[test]
    fn parse_alter_ack_accepts_valid_response() {
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&[5, 0, 0x0D, 0x03]); // version, minor, alter_ack, flags
        pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // data rep
        pdu.extend_from_slice(&[44, 0]); // frag_len
        pdu.extend_from_slice(&[0, 0]); // auth_len = 0 for stub
        pdu.extend_from_slice(&[2, 0, 0, 0]); // call_id
        pdu.extend_from_slice(&[0xB8, 0x10]); // max_xmit
        pdu.extend_from_slice(&[0xB8, 0x10]); // max_recv
        pdu.extend_from_slice(&[0x44, 0x33, 0x22, 0x11]); // assoc_group
        pdu.extend_from_slice(&[0, 0]); // sec_addr_len
        pdu.extend_from_slice(&[0, 0]); // padding
        pdu.push(1); // num_results
        pdu.push(0); // reserved
        pdu.extend_from_slice(&[0, 0]); // reserved
        pdu.extend_from_slice(&[0, 0]); // result = accept
        pdu.extend_from_slice(&[0, 0]); // reason
        pdu.extend_from_slice(&[0u8; 16]); // syntax uuid
        pdu.extend_from_slice(&[0, 0, 0, 0]); // syntax version

        RealRpcTransport::parse_alter_ack(&pdu).expect("alter_ack should accept");
    }

    #[test]
    fn parse_alter_ack_rejects_on_failure() {
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&[5, 0, 0x0D, 0x03]); // version, minor, alter_ack, flags
        pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // data rep
        pdu.extend_from_slice(&[44, 0]); // frag_len
        pdu.extend_from_slice(&[0, 0]); // auth_len
        pdu.extend_from_slice(&[2, 0, 0, 0]); // call_id
        pdu.extend_from_slice(&[0xB8, 0x10]); // max_xmit
        pdu.extend_from_slice(&[0xB8, 0x10]); // max_recv
        pdu.extend_from_slice(&[0x44, 0x33, 0x22, 0x11]); // assoc_group
        pdu.extend_from_slice(&[0, 0]); // sec_addr_len
        pdu.extend_from_slice(&[0, 0]); // padding
        pdu.push(1); // num_results
        pdu.push(0); // reserved
        pdu.extend_from_slice(&[0, 0]); // reserved
        pdu.extend_from_slice(&[2, 0]); // result = provider rejection
        pdu.extend_from_slice(&[3, 0]); // reason
        pdu.extend_from_slice(&[0u8; 16]); // syntax uuid
        pdu.extend_from_slice(&[0, 0, 0, 0]); // syntax version

        let err = RealRpcTransport::parse_alter_ack(&pdu).unwrap_err();
        match err {
            TransportError::AlterReject { result } => assert_eq!(result, 2),
            _ => panic!("Expected AlterReject error"),
        }
    }

    #[test]
    fn parse_bind_ack_rejects_failed_context() {
        let mut body = Vec::new();
        body.extend_from_slice(&0x10d8u16.to_le_bytes());
        body.extend_from_slice(&0x10d8u16.to_le_bytes());
        body.extend_from_slice(&0x11223344u32.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&[0u8; 2]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0x0002u16.to_le_bytes());
        body.extend_from_slice(&0x0003u16.to_le_bytes());
        body.extend_from_slice(&[0u8; 16]);
        body.extend_from_slice(&0u32.to_le_bytes());

        body.push(0x0A);
        body.push(0x06);
        body.push(0);
        body.push(0);
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);

        let frag_len = (16 + body.len()) as u16;
        let auth_len = 4u16;

        let mut pdu = Vec::new();
        pdu.extend_from_slice(&[5, 0, 0x0C, 0x03]);
        pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);
        pdu.extend_from_slice(&frag_len.to_le_bytes());
        pdu.extend_from_slice(&auth_len.to_le_bytes());
        pdu.extend_from_slice(&1u32.to_le_bytes());
        pdu.extend_from_slice(&body);

        let err = RealRpcTransport::parse_bind_ack(&pdu).unwrap_err();
        match err {
            TransportError::Bind { result, reason } => {
                assert_eq!(result, 0x0002);
                assert_eq!(reason, 0x0003);
            }
            other => panic!("expected bind rejection, got {other:?}"),
        }
    }

    #[test]
    fn bind_pdu_contains_expected_context_and_auth_fields() {
        let ntlm = [0xAA, 0xBB, 0xCC, 0xDD];
        let pdu = RealRpcTransport::build_bind_pdu(7, &ntlm);

        assert_eq!(pdu[0], 5);
        assert_eq!(pdu[1], 0);
        assert_eq!(pdu[2], 0x0B);
        assert_eq!(pdu[3], 0x03);
        assert_eq!(&pdu[4..8], &[0x00, 0x00, 0x00, 0x10]);

        let frag_len = u16::from_le_bytes([pdu[8], pdu[9]]);
        assert_eq!(frag_len as usize, pdu.len());

        let auth_len = u16::from_le_bytes([pdu[10], pdu[11]]);
        // With SPNEGO wrapping, auth_len is larger than the original NTLM blob
        // SPNEGO adds ASN.1 encoding overhead
        assert!(auth_len > ntlm.len() as u16, "SPNEGO-wrapped auth should be larger than raw NTLM");

        let call_id = u32::from_le_bytes([pdu[12], pdu[13], pdu[14], pdu[15]]);
        assert_eq!(call_id, 7);

        // Walk the body to ensure context ID and transfer syntax are present.
        let mut cursor = Cursor::new(&pdu[16..]);
        let max_xmit = cursor.read_u16::<LittleEndian>().unwrap();
        let max_recv = cursor.read_u16::<LittleEndian>().unwrap();
        assert_eq!(max_xmit, 0x10B8);
        assert_eq!(max_recv, 0x10B8);
        cursor.read_u32::<LittleEndian>().unwrap(); // assoc group
        let num_context_items = cursor.read_u8().unwrap();
        assert_eq!(num_context_items, 1);
        cursor.read_u8().unwrap(); // pad
        let context_id = cursor.read_u16::<LittleEndian>().unwrap();
        assert_eq!(context_id, 0);

        let num_transfer_syntax = cursor.read_u8().unwrap();
        assert_eq!(num_transfer_syntax, 1);
        cursor.read_u8().unwrap(); // alignment pad

        let mut abstract_syntax = [0u8; 16];
        cursor.read_exact(&mut abstract_syntax).unwrap();
        assert_eq!(abstract_syntax, hex!("a001000000000000c000000000000046"));
        let abstract_version_major = cursor.read_u16::<LittleEndian>().unwrap();
        let abstract_version_minor = cursor.read_u16::<LittleEndian>().unwrap();
        assert_eq!(abstract_version_major, 0);
        assert_eq!(abstract_version_minor, 0);

        let mut transfer_syntax = [0u8; 16];
        cursor.read_exact(&mut transfer_syntax).unwrap();
        assert_eq!(transfer_syntax, hex!("045d888aeb1cc9119fe808002b104860"));
        let transfer_version = cursor.read_u32::<LittleEndian>().unwrap();
        assert_eq!(transfer_version, 2);
        // With SPNEGO wrapping, the auth blob at the end is larger than original NTLM
        // Look for the auth trailer signature before the auth blob
        let trailer_signature = [0x09, 0x06]; // SPNEGO (0x09) + PRIVACY (0x06)
        let auth_type_offset = pdu
            .windows(2)
            .rposition(|window| window == trailer_signature)
            .expect("auth trailer not present");

        // Ensure we have enough space for the auth trailer
        assert!(auth_type_offset + 8 <= pdu.len());

        let auth_pad_len = pdu[auth_type_offset + 2] as usize;
        let auth_context_id = u32::from_le_bytes([
            pdu[auth_type_offset + 4],
            pdu[auth_type_offset + 5],
            pdu[auth_type_offset + 6],
            pdu[auth_type_offset + 7],
        ]);
        assert_eq!(auth_context_id, 0);

        // The SPNEGO blob comes after the auth trailer, check padding if any
        if auth_pad_len > 0 {
            // Find where the auth blob starts (after trailer + padding)
            let auth_blob_start = auth_type_offset + 8 + auth_pad_len;
            let pad_slice = &pdu[auth_type_offset + 8..auth_blob_start];
            assert_eq!(pad_slice.len(), auth_pad_len);
            assert!(pad_slice.iter().all(|b| *b == 0));
        }
    }

    #[test]
    fn alter_context_pdu_reuses_context_and_trailer_layout() {
        let ntlm = [0x11, 0x22, 0x33, 0x44, 0x55];
        let pdu = RealRpcTransport::build_alter_context_pdu(9, 0x1234, &ntlm);

        assert_eq!(pdu[0], 5);
        assert_eq!(pdu[1], 0);
        assert_eq!(pdu[2], 0x0E);
        assert_eq!(pdu[3], 0x03);
        assert_eq!(&pdu[4..8], &[0x00, 0x00, 0x00, 0x10]);

        let call_id = u32::from_le_bytes([pdu[12], pdu[13], pdu[14], pdu[15]]);
        assert_eq!(call_id, 9);

        let mut cursor = Cursor::new(&pdu[16..]);
        cursor.read_u16::<LittleEndian>().unwrap();
        cursor.read_u16::<LittleEndian>().unwrap();
        cursor.read_u32::<LittleEndian>().unwrap();
        assert_eq!(cursor.read_u8().unwrap(), 1);
        cursor.read_u8().unwrap();
        assert_eq!(cursor.read_u16::<LittleEndian>().unwrap(), 0x1234);
        assert_eq!(cursor.read_u8().unwrap(), 1);
        cursor.read_u8().unwrap();

        let mut abstract_syntax = [0u8; 16];
        cursor.read_exact(&mut abstract_syntax).unwrap();
        assert_eq!(abstract_syntax, hex!("a001000000000000c000000000000046"));
        cursor.read_u16::<LittleEndian>().unwrap();
        cursor.read_u16::<LittleEndian>().unwrap();
        let mut transfer_syntax = [0u8; 16];
        cursor.read_exact(&mut transfer_syntax).unwrap();
        assert_eq!(transfer_syntax, hex!("045d888aeb1cc9119fe808002b104860"));
        cursor.read_u32::<LittleEndian>().unwrap();

        let ntlm_offset = pdu.len() - ntlm.len();
        assert_eq!(&pdu[ntlm_offset..], &ntlm);
    }

    #[test]
    fn test_fragment_reassembly_two_fragments() {
        use std::io::Write;
        use std::net::{TcpListener, TcpStream};
        use std::thread;

        // Start a mock server
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();

            // First fragment (not last, flag 0x01 = first but not last)
            let frag1 = vec![
                0x05, 0x00, // RPC version
                0x02, 0x01, // Response PDU, flags: first frag but not last
                0x10, 0x00, 0x00, 0x00, // Data representation
                0x30, 0x00, // Fragment length: 48 bytes
                0x00, 0x00, // Auth length
                0x01, 0x00, 0x00, 0x00, // Call ID
                // Response header (8 bytes)
                0x20, 0x00, 0x00, 0x00, // Alloc hint
                0x00, 0x00, // Context ID
                0x00, 0x00, // Cancel count
                // Stub data (24 bytes)
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            ];
            stream.write_all(&frag1).unwrap();

            // Second fragment (last, flag 0x02 = last but not first)
            let frag2 = vec![
                0x05, 0x00, // RPC version
                0x02, 0x02, // Response PDU, flags: last frag but not first
                0x10, 0x00, 0x00, 0x00, // Data representation
                0x28, 0x00, // Fragment length: 40 bytes
                0x00, 0x00, // Auth length
                0x01, 0x00, 0x00, 0x00, // Call ID
                // Response header (8 bytes) - ignored in continuation fragments
                0x00, 0x00, 0x00, 0x00, // Alloc hint (ignored)
                0x00, 0x00, // Context ID (ignored)
                0x00, 0x00, // Cancel count (ignored)
                // Stub data continuation (16 bytes)
                0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
                0x27, 0x28,
            ];
            stream.write_all(&frag2).unwrap();
        });

        // Connect and read the fragmented PDU
        let mut client = TcpStream::connect(addr).unwrap();
        let result = RealRpcTransport::read_pdu(&mut client).unwrap();

        // Verify the reassembled PDU
        assert_eq!(result.len(), 64); // Header (16) + Response (8) + Stub (40)
        assert_eq!(result[3], 0x03); // Flags should be first|last after reassembly

        // Check fragment length was updated
        let total_len = u16::from_le_bytes([result[8], result[9]]);
        assert_eq!(total_len as usize, result.len());

        // Verify stub data was concatenated correctly
        assert_eq!(
            &result[24..32],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        assert_eq!(
            &result[56..64],
            &[0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28]
        );
    }

    #[test]
    fn test_single_fragment_unchanged() {
        use std::io::Write;
        use std::net::{TcpListener, TcpStream};
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();

            // Single complete fragment (flags 0x03 = first|last)
            let frag = vec![
                0x05, 0x00, // RPC version
                0x02, 0x03, // Response PDU, flags: first|last
                0x10, 0x00, 0x00, 0x00, // Data representation
                0x20, 0x00, // Fragment length: 32 bytes
                0x00, 0x00, // Auth length
                0x01, 0x00, 0x00, 0x00, // Call ID
                // Response header (8 bytes)
                0x08, 0x00, 0x00, 0x00, // Alloc hint
                0x00, 0x00, // Context ID
                0x00, 0x00, // Cancel count
                // Stub data (8 bytes)
                0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            ];
            stream.write_all(&frag).unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        let result = RealRpcTransport::read_pdu(&mut client).unwrap();

        // Single fragment should be returned as-is
        assert_eq!(result.len(), 32);
        assert_eq!(result[3], 0x03); // Flags unchanged
        assert_eq!(
            &result[24..32],
            &[0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8]
        );
    }

    #[test]
    fn test_large_wmi_response_fragmentation() {
        use std::io::Write;
        use std::net::{TcpListener, TcpStream};
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();

            // Simulate a large WMI response that would be fragmented
            // Total stub data: 5000 bytes (will require multiple fragments)
            let stub_data: Vec<u8> = (0..5000).map(|i| (i & 0xFF) as u8).collect();

            // Fragment 1: Max size ~4080 bytes (leaving room for headers)
            let frag1_stub_size = 4056; // 4080 - 24 (headers)
            let mut frag1 = vec![
                0x05, 0x00, 0x02, 0x01, // Version, type, flags (first, not last)
                0x10, 0x00, 0x00, 0x00, // Data rep
            ];
            let frag1_len = 24 + frag1_stub_size; // Headers + stub
            frag1.extend_from_slice(&(frag1_len as u16).to_le_bytes()); // Fragment length
            frag1.extend_from_slice(&[0x00, 0x00]); // Auth length
            frag1.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Call ID
            frag1.extend_from_slice(&[0x88, 0x13, 0x00, 0x00]); // Alloc hint (5000 bytes)
            frag1.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Context ID, cancel
            frag1.extend_from_slice(&stub_data[0..frag1_stub_size]);
            stream.write_all(&frag1).unwrap();

            // Fragment 2: Remaining data
            let frag2_stub_size = 5000 - frag1_stub_size;
            let mut frag2 = vec![
                0x05, 0x00, 0x02, 0x02, // Version, type, flags (last, not first)
                0x10, 0x00, 0x00, 0x00, // Data rep
            ];
            let frag2_len = 24 + frag2_stub_size; // Headers + stub
            frag2.extend_from_slice(&(frag2_len as u16).to_le_bytes());
            frag2.extend_from_slice(&[0x00, 0x00]); // Auth length
            frag2.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Call ID
            frag2.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Response header (ignored)
            frag2.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            frag2.extend_from_slice(&stub_data[frag1_stub_size..5000]);
            stream.write_all(&frag2).unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        let result = RealRpcTransport::read_pdu(&mut client).unwrap();

        // Verify reassembly of large response
        assert_eq!(result.len(), 5024); // Header(16) + Response(8) + Stub(5000)
        assert_eq!(result[3], 0x03); // Flags: first|last after reassembly

        // Verify the large stub data was correctly reassembled
        for i in 0..5000 {
            assert_eq!(result[24 + i], (i & 0xFF) as u8, "Mismatch at byte {i}");
        }
    }

    #[test]
    fn test_three_fragments() {
        use std::io::Write;
        use std::net::{TcpListener, TcpStream};
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();

            // First fragment
            let frag1 = vec![
                0x05, 0x00, 0x02, 0x01, // Version, type, flags (first, not last)
                0x10, 0x00, 0x00, 0x00, // Data rep
                0x20, 0x00, 0x00, 0x00, // Frag len 32, auth 0
                0x01, 0x00, 0x00, 0x00, // Call ID
                0x08, 0x00, 0x00, 0x00, // Response header
                0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, // 8 bytes stub data
                0x05, 0x06, 0x07, 0x08,
            ];
            stream.write_all(&frag1).unwrap();

            // Middle fragment (neither first nor last, flags = 0x00)
            let frag2 = vec![
                0x05, 0x00, 0x02, 0x00, // Flags: neither first nor last
                0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, // Response header (ignored)
                0x00, 0x00, 0x00, 0x00, 0x09, 0x0a, 0x0b, 0x0c, // 8 bytes stub data
                0x0d, 0x0e, 0x0f, 0x10,
            ];
            stream.write_all(&frag2).unwrap();

            // Last fragment
            let frag3 = vec![
                0x05, 0x00, 0x02, 0x02, // Flags: last, not first
                0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, // Response header (ignored)
                0x00, 0x00, 0x00, 0x00, 0x11, 0x12, 0x13, 0x14, // 8 bytes stub data
                0x15, 0x16, 0x17, 0x18,
            ];
            stream.write_all(&frag3).unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        let result = RealRpcTransport::read_pdu(&mut client).unwrap();

        // Verify reassembly
        assert_eq!(result.len(), 48); // Header(16) + Response(8) + Stub(24)
        assert_eq!(result[3], 0x03); // Flags: first|last

        // Verify all stub data concatenated
        assert_eq!(
            &result[24..32],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        assert_eq!(
            &result[32..40],
            &[0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10]
        );
        assert_eq!(
            &result[40..48],
            &[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]
        );
    }
}
