use crate::auth::{AuthProvider, Credentials, NtlmV2Client};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde_json;
use socket2::{Domain, Protocol, Socket, Type};
use std::io::{Cursor, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, error, instrument, warn};

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

/// Default no-op transport used by the current stubs.
#[derive(Default)]
pub struct StubTransport;

impl RpcTransport for StubTransport {
    fn name(&self) -> &'static str {
        "stub-transport"
    }

    fn invoke(&mut self, _opnum: u16, _payload: &[u8]) -> Result<Vec<u8>, TransportError> {
        // The stub simply returns an empty buffer. Real transports will marshal and send the
        // payload to a remote endpoint before returning the response.
        Ok(Vec::new())
    }
}

/// Configuration that will be consumed by the real transport implementation once the
/// EPM and bind logic is in place.
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct RealTransportConfig {
    pub host: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub domain: Option<String>,
}

/// Placeholder for the authenticated RPC transport that will speak to real WMI services.
#[allow(dead_code)]
#[derive(Debug)]
pub struct RealRpcTransport {
    stream: std::net::TcpStream,
    context_id: u16,
    call_id: u32,
    causality_id: u32,  // ORPC causality tracking
    session_key: Vec<u8>,
    auth_level: u8,
    max_xmit: u16,
    max_recv: u16,
}

#[allow(dead_code)]
impl RealRpcTransport {
    /// Creates a new transport after resolving the dynamic endpoint via EPM and performing the
    /// NTLM authenticated bind.  The detailed network logic will be filled in during the
    /// subsequent iterations of Step 1.
    #[instrument(level = "debug", skip(config), fields(host = %config.host))]
    pub fn connect(config: RealTransportConfig) -> Result<Self, TransportError> {
        let host = &config.host;
        let creds = Credentials {
            username: config.username.clone().unwrap_or_default(),
            password: config.password.clone().unwrap_or_default(),
            domain: config.domain.clone().unwrap_or_default(),
            workstation: host.clone(),
        };

        let mut auth = NtlmV2Client::new(creds.clone())
            .map_err(|err| TransportError::Failure(err.to_string()))?;

        let port = crate::dcom::resolve_wmi_port(host, Some(&creds)).map_err(|err| {
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
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|err| TransportError::Failure(err.to_string()))?;
        socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|err| TransportError::Failure(err.to_string()))?;
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
            causality_id: 0,  // Initialize to 0, will increment on new object calls
            session_key,
            auth_level: 6, // Packet Privacy
            max_xmit,
            max_recv,
        })
    }

    fn build_bind_pdu(call_id: u32, ntlm: &[u8]) -> Vec<u8> {
        const MAX_XMIT_RECV: u16 = 0x10B8;
        const AUTH_TYPE_NTLM: u8 = 0x0A;
        const AUTH_LEVEL_PRIVACY: u8 = 0x06;

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
        for _ in 0..pad {
            body.push(0);
        }

        body.push(AUTH_TYPE_NTLM);
        body.push(AUTH_LEVEL_PRIVACY);
        body.push(pad as u8);
        body.push(0);
        body.write_u32::<LittleEndian>(0).unwrap(); // auth context id
        for _ in 0..pad {
            body.push(0);
        }
        body.extend_from_slice(ntlm);

        let frag_len = (16 + body.len()) as u16;
        let auth_len = ntlm.len() as u16;

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
        const MAX_XMIT_RECV: u16 = 0x10B8;
        const AUTH_TYPE_NTLM: u8 = 0x0A;
        const AUTH_LEVEL_PRIVACY: u8 = 0x06;

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
        for _ in 0..pad {
            body.push(0);
        }

        body.push(AUTH_TYPE_NTLM);
        body.push(AUTH_LEVEL_PRIVACY);
        body.push(pad as u8);
        body.push(0);
        body.write_u32::<LittleEndian>(0).unwrap();
        for _ in 0..pad {
            body.push(0);
        }
        body.extend_from_slice(ntlm);

        let frag_len = (16 + body.len()) as u16;
        let auth_len = ntlm.len() as u16;

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
        let mut cursor = Cursor::new(pdu);
        let _version = cursor.read_u8()?;
        let _minor = cursor.read_u8()?;
        let ptype = cursor.read_u8()?;
        if ptype != 0x0C {
            return Err(TransportError::Failure(
                "Unexpected PDU type in bind_ack".into(),
            ));
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

        let marker = b"NTLMSSP\0";
        let ntlm_offset = pdu
            .windows(marker.len())
            .position(|window| window == marker)
            .ok_or_else(|| {
                TransportError::Failure("bind_ack missing NTLM challenge marker".into())
            })?;
        if ntlm_offset < 8 {
            return Err(TransportError::Failure(
                "bind_ack malformed: security trailer truncated".into(),
            ));
        }
        let trailer_start = ntlm_offset - 8;
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

        if auth_type != 0x0A {
            return Err(TransportError::Failure(format!(
                "Unexpected auth type in bind_ack: 0x{auth_type:02x}"
            )));
        }

        match crate::auth::parse_type2_message(&blob) {
            Ok(challenge) => {
                debug!(
                    flags = format_args!("0x{:#x}", challenge.flags),
                    "parsed NTLM challenge"
                );
            }
            Err(err) => warn!(?err, "failed to parse NTLM challenge from bind_ack"),
        }

        Ok((context_id, blob, max_xmit, max_recv))
    }

    pub(crate) fn parse_alter_ack(pdu: &[u8]) -> Result<(), TransportError> {
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

    fn build_request_pdu(call_id: u32, context_id: u16, opnum: u16, stub: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.write_u32::<LittleEndian>(0).unwrap(); // alloc_hint
        body.write_u16::<LittleEndian>(context_id).unwrap();
        body.write_u16::<LittleEndian>(opnum).unwrap();
        body.extend_from_slice(stub);

        let frag_len = (16 + body.len()) as u16;

        let mut pdu = Vec::with_capacity(frag_len as usize);
        pdu.write_u8(5).unwrap(); // version
        pdu.write_u8(0).unwrap(); // minor
        pdu.write_u8(0x00).unwrap(); // ptype=request
        pdu.write_u8(0x03).unwrap(); // flags first|last
        pdu.write_u32::<LittleEndian>(0x10_00_00_00).unwrap(); // data rep LE
        pdu.write_u16::<LittleEndian>(frag_len).unwrap();
        pdu.write_u16::<LittleEndian>(0).unwrap(); // auth_len (no auth yet)
        pdu.write_u32::<LittleEndian>(call_id).unwrap();
        pdu.extend_from_slice(&body);
        pdu
    }

    fn parse_response_pdu(pdu: &[u8]) -> Result<Vec<u8>, TransportError> {
        if pdu.len() < 24 {
            return Err(TransportError::Failure("response PDU too short".into()));
        }

        let mut cursor = Cursor::new(pdu);
        let _version = cursor.read_u8()?;
        let _minor = cursor.read_u8()?;
        let ptype = cursor.read_u8()?;

        if ptype == 0x03 {
            // Fault response
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

    fn read_pdu(stream: &mut TcpStream) -> Result<Vec<u8>, TransportError> {
        let span = tracing::trace_span!("read_pdu");
        let _enter = span.enter();

        // Read the first fragment
        let mut header = [0u8; 16];
        stream.read_exact(&mut header).map_err(|err| {
            error!(?err, "failed to read RPC PDU header");
            TransportError::Failure(err.to_string())
        })?;

        let flags = header[3];
        let mut frag_len = u16::from_le_bytes([header[8], header[9]]) as usize;
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

        // Multi-fragment response, need to reassemble
        debug!(flags, frag_len, "reading multi-fragment RPC PDU");
        let mut fragments = vec![buffer];
        let mut total_stub_len = if frag_len > 24 { frag_len - 24 } else { 0 }; // Header (16) + auth (8) = 24

        // Read remaining fragments
        loop {
            // Read next fragment header
            let mut frag_header = [0u8; 16];
            stream.read_exact(&mut frag_header).map_err(|err| {
                error!(?err, "failed to read fragment header");
                TransportError::Failure(err.to_string())
            })?;

            let frag_flags = frag_header[3];
            frag_len = u16::from_le_bytes([frag_header[8], frag_header[9]]) as usize;

            if frag_len < 16 {
                return Err(TransportError::Failure(format!(
                    "invalid fragment length {frag_len}"
                )));
            }

            // Read the rest of the fragment
            let mut frag_buffer = vec![0u8; frag_len];
            frag_buffer[..16].copy_from_slice(&frag_header);

            offset = 16;
            while offset < frag_len {
                match stream.read(&mut frag_buffer[offset..]) {
                    Ok(0) => {
                        return Err(TransportError::Failure(
                            "connection closed while reading fragment".into(),
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
                            error!(?err, "fragment read timed out");
                            return Err(TransportError::Failure("RPC fragment timed out".into()));
                        }
                        std::thread::sleep(std::time::Duration::from_millis(25));
                        continue;
                    }
                    Err(err) => {
                        error!(?err, "failed to read fragment body");
                        return Err(TransportError::Failure(err.to_string()));
                    }
                }
            }

            fragments.push(frag_buffer);
            total_stub_len += if frag_len > 24 { frag_len - 24 } else { 0 };

            // Check if this is the last fragment
            if (frag_flags & PFC_LAST_FRAG) != 0 {
                debug!(
                    fragment_count = fragments.len(),
                    total_stub_len,
                    "reassembling fragmented RPC response"
                );
                break;
            }

            // Safety check: prevent infinite loops
            if fragments.len() > 1000 {
                return Err(TransportError::Failure(
                    "too many RPC fragments (>1000)".into(),
                ));
            }
        }

        // Reassemble the PDU from fragments
        // Keep the header from the first fragment, concatenate stub data from all
        let mut reassembled = fragments[0][..24].to_vec(); // Header + response header

        for fragment in &fragments {
            // Skip the header (16 bytes) and response header (8 bytes) for each fragment
            // Just append the stub data
            if fragment.len() > 24 {
                reassembled.extend_from_slice(&fragment[24..]);
            }
        }

        // Update the fragment length in the reassembled PDU header to reflect total size
        let total_len = reassembled.len();
        reassembled[8] = (total_len & 0xFF) as u8;
        reassembled[9] = ((total_len >> 8) & 0xFF) as u8;

        // Set the flags to indicate this is now a complete PDU
        reassembled[3] = 0x03; // PFC_FIRST_FRAG | PFC_LAST_FRAG

        debug!(
            total_len,
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
        if opnum == 9 {
            return Self::stub_exec_query(payload);
        }

        let request_pdu = Self::build_request_pdu(self.call_id, self.context_id, opnum, payload);
        self.call_id += 1;

        debug!(
            opnum,
            call_id = self.call_id - 1,
            payload_len = payload.len(),
            "sending RPC request"
        );

        self.stream.write_all(&request_pdu)?;
        let response = Self::read_pdu(&mut self.stream)?;
        let stub_data = Self::parse_response_pdu(&response)?;

        debug!(opnum, stub_len = stub_data.len(), "received RPC response");

        Ok(stub_data)
    }
}

impl RealRpcTransport {
    fn stub_exec_query(payload: &[u8]) -> Result<Vec<u8>, TransportError> {
        let mut cursor = std::io::Cursor::new(payload);
        let language = crate::ndr::read_bstr(&mut cursor).unwrap_or_else(|| "".into());
        let query = crate::ndr::read_bstr(&mut cursor).unwrap_or_else(|| "".into());
        debug!(%language, %query, "stub exec_query over real transport");

        let values = crate::ndr::stub_results_for_query(&query).unwrap_or_default();
        serde_json::to_vec(&values).map_err(|err| TransportError::Failure(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dcom::{self, DcomError};
    use crate::ndr::NdrCodec;
    use byteorder::{LittleEndian, ReadBytesExt};
    use hex_literal::hex;
    use serde_json::Value;
    use std::io::{Cursor, Read};

    #[test]
    fn stub_transport_invoke_returns_empty() {
        let mut transport = StubTransport::default();
        let result = transport.invoke(9, &[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn real_transport_stub_exec_query_emits_json() {
        let codec = crate::ndr::StubNdrCodec::default();
        let payload = codec
            .encode_exec_query("WQL", "SELECT * FROM Win32_ComputerSystem")
            .expect("encode");
        let response = RealRpcTransport::stub_exec_query(&payload).expect("stub response");
        let values: Vec<Value> = serde_json::from_slice(&response).expect("json parse");
        assert_eq!(values.len(), 1);
        assert_eq!(values[0]["Name"], "STUB-PC");
    }

    #[test]
    fn epm_request_pdu_matches_expected_layout() {
        let tower = crate::tower::build_wmi_tower();
        let pdu = crate::rpc_fixtures::epm_request_pdu(42, &tower);

        assert_eq!(pdu[0], 5, "RPC version");
        assert_eq!(pdu[1], 0, "RPC minor version");
        assert_eq!(pdu[2], 0x00, "PDU type: request");
        assert_eq!(pdu[3], 0x03, "Flags should indicate first|last frag");
        assert_eq!(
            &pdu[4..8],
            &[0x10, 0x00, 0x00, 0x00],
            "little-endian data rep"
        );

        let frag_len = u16::from_le_bytes([pdu[8], pdu[9]]) as usize;
        assert_eq!(frag_len, pdu.len());
        let auth_len = u16::from_le_bytes([pdu[10], pdu[11]]);
        assert_eq!(auth_len, 0, "EPM request should not include auth data");

        let call_id = u32::from_le_bytes([pdu[12], pdu[13], pdu[14], pdu[15]]);
        assert_eq!(call_id, 42);

        let context_id = u16::from_le_bytes([pdu[20], pdu[21]]);
        let opnum = u16::from_le_bytes([pdu[22], pdu[23]]);
        assert_eq!(context_id, 0);
        assert_eq!(opnum, 3);

        // PDU should now be dynamically sized based on tower
        assert!(pdu.len() > 24, "PDU should have header + stub");
        assert!(pdu.len() < 200, "PDU shouldn't be too large");
    }

    #[test]
    fn parse_epm_response_extracts_tcp_port() {
        let tower = crate::tower::sample_epm_response_stub();
        let pdu = build_epm_response_pdu(tower);
        let port = dcom::parse_epm_response(&pdu).unwrap();
        assert_eq!(port, 0xc002);
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
        let pdu = RealRpcTransport::build_request_pdu(42, 1, 9, b"test_stub");

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

        let stub = RealRpcTransport::parse_response_pdu(&pdu).unwrap();
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

        let err = RealRpcTransport::parse_response_pdu(&pdu).unwrap_err();
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
    fn parse_epm_response_errors_when_missing_tcp_floor() {
        let tower = &[0u8, 0u8];
        let pdu = build_epm_response_pdu(tower);
        let err = dcom::parse_epm_response(&pdu).unwrap_err();
        assert!(matches!(err, DcomError::Port | DcomError::Tower));
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
        assert_eq!(auth_len, ntlm.len() as u16);

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
        let ntlm_offset = pdu.len() - ntlm.len();
        assert_eq!(&pdu[ntlm_offset..], ntlm);

        let trailer_search_end = ntlm_offset;
        let trailer_signature = [0x0A, 0x06];
        let auth_type_offset = pdu
            .windows(2)
            .take(trailer_search_end.saturating_sub(1))
            .rposition(|window| window == trailer_signature)
            .expect("auth trailer not present");
        assert!(auth_type_offset + 8 <= trailer_search_end);

        let auth_pad_len = pdu[auth_type_offset + 2] as usize;
        let auth_context_id = u32::from_le_bytes([
            pdu[auth_type_offset + 4],
            pdu[auth_type_offset + 5],
            pdu[auth_type_offset + 6],
            pdu[auth_type_offset + 7],
        ]);
        assert_eq!(auth_context_id, 0);

        let pad_slice = &pdu[auth_type_offset + 8..trailer_search_end];
        assert_eq!(pad_slice.len(), auth_pad_len);
        assert!(pad_slice.iter().all(|b| *b == 0));
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
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
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
                0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
                0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
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
        assert_eq!(&result[24..32], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(&result[56..64], &[0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28]);
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
        assert_eq!(&result[24..32], &[0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8]);
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
            assert_eq!(result[24 + i], (i & 0xFF) as u8, "Mismatch at byte {}", i);
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
                0x00, 0x00, 0x00, 0x00,
                0x01, 0x02, 0x03, 0x04, // 8 bytes stub data
                0x05, 0x06, 0x07, 0x08,
            ];
            stream.write_all(&frag1).unwrap();

            // Middle fragment (neither first nor last, flags = 0x00)
            let frag2 = vec![
                0x05, 0x00, 0x02, 0x00, // Flags: neither first nor last
                0x10, 0x00, 0x00, 0x00,
                0x20, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, // Response header (ignored)
                0x00, 0x00, 0x00, 0x00,
                0x09, 0x0a, 0x0b, 0x0c, // 8 bytes stub data
                0x0d, 0x0e, 0x0f, 0x10,
            ];
            stream.write_all(&frag2).unwrap();

            // Last fragment
            let frag3 = vec![
                0x05, 0x00, 0x02, 0x02, // Flags: last, not first
                0x10, 0x00, 0x00, 0x00,
                0x20, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, // Response header (ignored)
                0x00, 0x00, 0x00, 0x00,
                0x11, 0x12, 0x13, 0x14, // 8 bytes stub data
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
        assert_eq!(&result[24..32], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(&result[32..40], &[0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10]);
        assert_eq!(&result[40..48], &[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]);
    }
}

#[cfg(test)]
fn build_epm_response_pdu(tower: &[u8]) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(&0u32.to_le_bytes());
    stub.extend_from_slice(&(tower.len() as u32).to_le_bytes());
    stub.extend_from_slice(&1u32.to_le_bytes());
    stub.extend_from_slice(&(tower.len() as u32).to_le_bytes());
    stub.extend_from_slice(tower);
    let pad = (4 - (stub.len() % 4)) % 4;
    stub.extend(std::iter::repeat(0u8).take(pad));

    let frag_len = (16 + 8 + stub.len()) as u16;
    let mut pdu = Vec::new();
    pdu.extend_from_slice(&[5, 0, 0x02, 0x03]);
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);
    pdu.extend_from_slice(&frag_len.to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes());
    pdu.extend_from_slice(&1u32.to_le_bytes());
    pdu.extend_from_slice(&(stub.len() as u32).to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes());
    pdu.push(0);
    pdu.push(0);
    pdu.extend_from_slice(&stub);
    pdu
}
