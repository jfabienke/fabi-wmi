use std::io::{Cursor, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use thiserror::Error;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::auth::{AuthProvider, Credentials, NtlmV2Client};
use crate::spnego;
use crate::transport::RealRpcTransport;

/// Object reference returned from OXID resolver
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ObjectReference {
    pub ipid: [u8; 16],   // Interface Pointer ID
    pub std_flags: u32,   // Standard flags
    pub public_refs: u32, // Public reference count
    pub oxid: [u8; 8],    // Object Exporter ID
    pub oid: [u8; 8],     // Object ID
}

#[derive(Error, Debug)]
pub enum DcomError {
    #[error("Endpoint mapper connection failed")]
    Connect,
    #[error("Invalid tower response")]
    Tower,
    #[error("Endpoint mapper returned fault {status:#010x} (reason={reason:#010x})")]
    Fault { status: u32, reason: u32 },
    #[error("Port resolution failed")]
    Port,
    #[error("Send operation failed")]
    Send,
    #[error("Receive operation failed")]
    Recv,
    #[error("Protocol error")]
    Protocol,
    #[error("Access denied (0x80070005)")]
    AccessDenied,
    #[error("RPC server unavailable (0x800706BA)")]
    ServerUnavailable,
    #[error("Remote procedure call failed (0x800706BE)")]
    RemoteProcedureCallFailed,
    #[error("Operation failed (hr={hr:#010x})")]
    Hresult { hr: u32 },
}

/// Map a COM HRESULT / error_status_t to a `DcomError`, preserving the code.
fn hresult_to_err(hr: u32) -> DcomError {
    match hr {
        0x8007_0005 => DcomError::AccessDenied,
        0x8007_06BA => DcomError::ServerUnavailable,
        0x8007_06BE => DcomError::RemoteProcedureCallFailed,
        other => DcomError::Hresult { hr: other },
    }
}

#[instrument(level = "debug", skip_all, fields(host))]
pub fn resolve_wmi_port(host: &str, creds: Option<&Credentials>) -> Result<u16, DcomError> {
    // Step 1: Check for hardcoded port (highest priority)
    if let Ok(port_str) = std::env::var("LINUX_WMI_PORT") {
        match port_str.trim().parse::<u16>() {
            Ok(port) if port > 0 => {
                info!("Using hardcoded WMI port from LINUX_WMI_PORT: {}", port);
                return Ok(port);
            }
            Ok(_) => {
                warn!(
                    "Invalid LINUX_WMI_PORT value '{}': port must be > 0",
                    port_str
                );
            }
            Err(e) => {
                warn!("Failed to parse LINUX_WMI_PORT value '{}': {}", port_str, e);
            }
        }
    }

    // Step 2: Check if we should skip EPM/DCOM entirely (legacy behavior)
    if let Ok(value) = std::env::var("LINUX_WMI_SKIP_EPM") {
        if value.trim() == "1" {
            warn!("LINUX_WMI_SKIP_EPM set; returning port 135");
            return Ok(135);
        }
    }

    // Step 3: Try anonymous DCOM activation first (works even with NTLM blocked)
    match activate_wmi_dcom_anonymous(host) {
        Ok((port, _oxid)) => {
            info!("Anonymous DCOM activation succeeded, WMI port: {}", port);
            return Ok(port);
        }
        Err(err) => {
            debug!(
                ?err,
                "Anonymous DCOM activation failed, trying authenticated"
            );
        }
    }

    // Step 4: Try authenticated DCOM activation if we have credentials
    if let Some(creds) = creds {
        match activate_wmi_dcom(host, creds) {
            Ok((port, _oxid)) => {
                info!(
                    "Authenticated DCOM activation succeeded, WMI port: {}",
                    port
                );
                return Ok(port);
            }
            Err(err) => {
                warn!(?err, "Authenticated DCOM activation failed");
            }
        }
    } else {
        debug!("No credentials provided for authenticated DCOM");
    }

    // Step 5: All methods failed
    error!("Failed to resolve WMI port. Set LINUX_WMI_PORT or check Windows DCOM/NTLM settings");
    Err(DcomError::Port)
}

/// Resolve OXID to get object reference using IObjectExporter
#[instrument(level = "debug", skip_all, fields(host, port))]
pub fn resolve_oxid(
    host: &str,
    port: u16,
    creds: &Credentials,
    oxid: &[u8; 8],
) -> Result<ObjectReference, DcomError> {
    debug!("Resolving OXID {} on port {}", hex::encode(oxid), port);

    // Try Kerberos first if feature is enabled
    #[cfg(feature = "kerberos")]
    {
        let realm = if !creds.domain.is_empty() {
            creds.domain.to_uppercase()
        } else {
            host.split('.')
                .skip(1)
                .collect::<Vec<_>>()
                .join(".")
                .to_uppercase()
        };

        if !realm.is_empty() && realm.contains('.') {
            debug!("Trying Kerberos for OXID resolution with realm: {}", realm);
            #[cfg(feature = "kerberos")]
            {
                use crate::kerberos_adapter::KerberosClient;
                let kerberos_config = crate::kerberos_adapter::KerberosConfig::new(&realm);
                match KerberosClient::new(host, kerberos_config, creds.clone()) {
                    Ok(kerberos_client) => {
                        match resolve_oxid_with_auth(host, port, Box::new(kerberos_client), oxid) {
                            Ok(result) => {
                                info!("OXID resolution succeeded with Kerberos");
                                return Ok(result);
                            }
                            Err(err) => {
                                debug!(
                                    ?err,
                                    "Kerberos failed for OXID resolution, falling back to NTLM"
                                );
                            }
                        }
                    }
                    Err(err) => {
                        debug!(?err, "Failed to create Kerberos client for OXID resolution");
                    }
                }
            }
        }
    }

    // Fall back to NTLM
    debug!("Using NTLM for OXID resolution");
    let ntlm_client = NtlmV2Client::new(creds.clone()).map_err(|_| DcomError::Protocol)?;
    resolve_oxid_with_auth(host, port, Box::new(ntlm_client), oxid)
}

/// Internal function to resolve OXID with a generic auth provider
fn resolve_oxid_with_auth(
    host: &str,
    port: u16,
    mut auth_client: Box<dyn AuthProvider>,
    oxid: &[u8; 8],
) -> Result<ObjectReference, DcomError> {
    // Connect to dynamic port
    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect_timeout(
        &addr
            .to_socket_addrs()
            .map_err(|_| DcomError::Connect)?
            .next()
            .ok_or(DcomError::Connect)?,
        Duration::from_secs(5),
    )
    .map_err(|e| {
        error!(%e, "failed to connect to OXID resolver");
        DcomError::Connect
    })?;

    stream
        .set_read_timeout(Some(RPC_IO_TIMEOUT))
        .map_err(|_| DcomError::Connect)?;
    stream
        .set_write_timeout(Some(RPC_IO_TIMEOUT))
        .map_err(|_| DcomError::Connect)?;

    // IObjectExporter UUID
    let object_exporter_uuid: [u8; 16] =
        hex_literal::hex!("c4 fe 9f 99 60 52 1b 10 bb cb 00 aa 00 21 34 7a");

    // Bind to IObjectExporter with auth
    let negotiate_token = auth_client.negotiate().map_err(|_| DcomError::Protocol)?;
    let bind_pdu = build_scm_bind_pdu(1, &object_exporter_uuid, &negotiate_token);
    stream.write_all(&bind_pdu).map_err(|_| DcomError::Send)?;

    let bind_ack = read_rpc_pdu(&mut stream)?;
    let (context_id, challenge_blob, _, _) =
        RealRpcTransport::parse_bind_ack(&bind_ack).map_err(|_| DcomError::Protocol)?;

    // Complete auth with alter_context
    let response_token = auth_client
        .respond(&challenge_blob)
        .map_err(|_| DcomError::Protocol)?;
    let alter_pdu =
        build_scm_alter_context_pdu(2, context_id, &object_exporter_uuid, &response_token);
    stream.write_all(&alter_pdu).map_err(|_| DcomError::Send)?;

    let alter_ack = read_rpc_pdu(&mut stream)?;
    RealRpcTransport::parse_alter_ack(&alter_ack).map_err(|_| DcomError::Protocol)?;

    // Build ResolveOxid request (opnum=0)
    let stub = build_resolve_oxid_stub(oxid)?;
    let req_pdu = build_request_pdu(3, context_id, 0, &stub)?; // opnum=0

    debug!("Sending ResolveOxid request, len={}", req_pdu.len());
    stream.write_all(&req_pdu).map_err(|_| DcomError::Send)?;

    let resp_pdu = read_rpc_pdu(&mut stream)?;
    parse_resolve_oxid_response(&resp_pdu, oxid)
}

/// Build ResolveOxid request stub
fn build_resolve_oxid_stub(oxid: &[u8; 8]) -> Result<Vec<u8>, DcomError> {
    let mut stub = Vec::new();

    // ORPCTHIS header (same as RemoteActivation)
    stub.write_u32::<LittleEndian>(0x00000001)
        .map_err(|_| DcomError::Protocol)?; // version
    stub.write_u32::<LittleEndian>(0)
        .map_err(|_| DcomError::Protocol)?; // flags
    stub.write_u32::<LittleEndian>(0)
        .map_err(|_| DcomError::Protocol)?; // reserved1
    stub.extend_from_slice(&[0u8; 16]); // causality ID
    stub.write_u32::<LittleEndian>(0)
        .map_err(|_| DcomError::Protocol)?; // no extensions

    // ResolveOxid parameters
    stub.extend_from_slice(oxid); // OXID to resolve
    stub.write_u16::<LittleEndian>(0)
        .map_err(|_| DcomError::Protocol)?; // cRequestedProtseqs
    stub.write_u32::<LittleEndian>(0)
        .map_err(|_| DcomError::Protocol)?; // pRequestedProtseqs (null)

    Ok(stub)
}

/// Parse ResolveOxid response
fn parse_resolve_oxid_response(pdu: &[u8], oxid: &[u8; 8]) -> Result<ObjectReference, DcomError> {
    if pdu.len() < 24 {
        return Err(DcomError::Protocol);
    }

    let ptype = pdu[2];
    if ptype == 0x03 {
        // RPC fault
        if pdu.len() >= 28 {
            let status = u32::from_le_bytes([pdu[24], pdu[25], pdu[26], pdu[27]]);
            error!("ResolveOxid fault: 0x{:08x}", status);

            // Map common HRESULT errors
            match status {
                0x80070005 => return Err(DcomError::AccessDenied),
                0x800706BA => return Err(DcomError::ServerUnavailable),
                0x800706BE => return Err(DcomError::RemoteProcedureCallFailed),
                _ => return Err(DcomError::Fault { status, reason: 0 }),
            }
        }
        return Err(DcomError::Protocol);
    }

    if ptype != 0x02 {
        return Err(DcomError::Protocol);
    }

    // Skip to stub data (after RPC header)
    let stub_data = &pdu[24..];
    let mut cursor = Cursor::new(stub_data);

    // Parse ORPCTHAT header
    let _flags = cursor
        .read_u32::<LittleEndian>()
        .map_err(|_| DcomError::Protocol)?;

    // Parse HRESULT
    let hresult = cursor
        .read_u32::<LittleEndian>()
        .map_err(|_| DcomError::Protocol)?;
    if hresult != 0 {
        error!("ResolveOxid failed with HRESULT: 0x{:08x}", hresult);
        match hresult {
            0x80070005 => return Err(DcomError::AccessDenied),
            0x800706BA => return Err(DcomError::ServerUnavailable),
            _ => {
                return Err(DcomError::Fault {
                    status: hresult,
                    reason: 0,
                })
            }
        }
    }

    // Parse ppRemUnknown (pointer to IRemUnknown interface)
    let rem_unknown_ptr = cursor
        .read_u32::<LittleEndian>()
        .map_err(|_| DcomError::Protocol)?;

    let ipid = if rem_unknown_ptr != 0 {
        // Parse IPID (16 bytes)
        let mut ipid = [0u8; 16];
        cursor
            .read_exact(&mut ipid)
            .map_err(|_| DcomError::Protocol)?;
        trace!("Extracted IPID: {:?}", hex::encode(ipid));
        ipid
    } else {
        trace!("No IPID in RemUnknown pointer");
        [0u8; 16]
    };

    // Parse standard flags
    let std_flags = cursor
        .read_u32::<LittleEndian>()
        .map_err(|_| DcomError::Protocol)?;

    // Parse public references
    let public_refs = cursor
        .read_u32::<LittleEndian>()
        .map_err(|_| DcomError::Protocol)?;

    // Parse OID (8 bytes)
    let mut oid = [0u8; 8];
    cursor
        .read_exact(&mut oid)
        .map_err(|_| DcomError::Protocol)?;

    // Parse pAuthnHint
    let _authn_hint = cursor
        .read_u32::<LittleEndian>()
        .map_err(|_| DcomError::Protocol)?;

    // Parse pServerVersion pointer
    let server_version_ptr = cursor
        .read_u32::<LittleEndian>()
        .map_err(|_| DcomError::Protocol)?;
    if server_version_ptr != 0 {
        // Skip server version if present
        let _ = cursor.read_u32::<LittleEndian>(); // major.minor version
    }

    debug!(
        "ResolveOxid succeeded: IPID={:?}, OID={:?}, refs={}",
        hex::encode(ipid),
        hex::encode(oid),
        public_refs
    );

    Ok(ObjectReference {
        ipid,
        std_flags,
        public_refs,
        oxid: *oxid,
        oid,
    })
}

/// Activate WMI via anonymous DCOM (IRemoteSCMActivator::RemoteActivation without auth)
/// Returns (port, OXID) tuple
#[instrument(level = "debug", skip_all, fields(host))]
pub fn activate_wmi_dcom_anonymous(host: &str) -> Result<(u16, [u8; 8]), DcomError> {
    info!("Attempting anonymous DCOM activation for WMI port resolution");

    // Connect to SCM on port 135
    let addr = format!("{host}:135");
    let mut stream = TcpStream::connect_timeout(
        &addr
            .to_socket_addrs()
            .map_err(|e| {
                error!(%e, "failed to resolve host");
                DcomError::Connect
            })?
            .next()
            .ok_or(DcomError::Connect)?,
        Duration::from_secs(5),
    )
    .map_err(|e| {
        error!(%e, "failed to connect to SCM");
        DcomError::Connect
    })?;

    stream
        .set_read_timeout(Some(RPC_IO_TIMEOUT))
        .map_err(|_| DcomError::Connect)?;
    stream
        .set_write_timeout(Some(RPC_IO_TIMEOUT))
        .map_err(|_| DcomError::Connect)?;

    let scm_uuid: [u8; 16] = hex_literal::hex!("a0 01 00 00 00 00 00 00 c0 00 00 00 00 00 00 46");

    // Build anonymous bind PDU (no auth trailer)
    let bind_pdu = build_anonymous_bind_pdu(1, &scm_uuid);

    debug!("Sending anonymous SCM bind PDU, len: {}", bind_pdu.len());
    stream.write_all(&bind_pdu).map_err(|e| {
        error!(%e, "failed to send bind PDU");
        DcomError::Send
    })?;

    // Read bind_ack
    let mut header = [0u8; 16];
    stream.read_exact(&mut header).map_err(|e| {
        error!(%e, "failed to read bind_ack header");
        DcomError::Recv
    })?;

    let ptype = header[2];
    if ptype == 0x0d {
        // bind_nak - need to read the full PDU to get the reason
        let frag_len = u16::from_le_bytes([header[8], header[9]]) as usize;
        if frag_len > 16 {
            let mut full_pdu = vec![0u8; frag_len];
            full_pdu[..16].copy_from_slice(&header);
            let _ = stream.read_exact(&mut full_pdu[16..]);
            let reason = if full_pdu.len() > 20 {
                full_pdu[20]
            } else {
                0xff
            };
            error!(
                "Anonymous bind rejected (bind_nak), reason: 0x{:02x}",
                reason
            );
        } else {
            error!("Anonymous bind rejected (bind_nak)");
        }
        return Err(DcomError::Protocol);
    }

    if ptype != 0x0c {
        error!(
            "Unexpected PDU type 0x{:02x}, expected bind_ack (0x0c)",
            ptype
        );
        return Err(DcomError::Protocol);
    }

    let frag_len = u16::from_le_bytes([header[8], header[9]]) as usize;
    let mut pdu = vec![0u8; frag_len];
    pdu[..16].copy_from_slice(&header);
    stream.read_exact(&mut pdu[16..]).map_err(|e| {
        error!(%e, "failed to read bind_ack body");
        DcomError::Recv
    })?;

    debug!("Received anonymous bind_ack, len: {}", pdu.len());

    // Extract context_id from bind_ack
    let context_id = if pdu.len() >= 24 {
        u16::from_le_bytes([pdu[22], pdu[23]])
    } else {
        0
    };

    // Build RemoteActivation request stub
    // IWbemLocator CLSID: {dc12a687-737f-11cf-884d-00aa004b2e24}
    let clsid = hex_literal::hex!("87a612dc7f73cf11884d00aa004b2e24"); // IWbemLocator (little-endian)
    let iid = clsid; // Same as CLSID for IWbemLocator

    let stub = build_remote_activation_stub(&clsid, &iid).map_err(|e| {
        error!(%e, "failed to build activation stub");
        DcomError::Protocol
    })?;

    // Build request PDU without auth
    let req_pdu = build_anonymous_request_pdu(2, context_id, 4, &stub); // opnum=4 for RemoteActivation

    debug!(
        "Sending anonymous RemoteActivation request, len: {}",
        req_pdu.len()
    );
    stream.write_all(&req_pdu).map_err(|e| {
        error!(%e, "failed to send request");
        DcomError::Send
    })?;

    // Read response
    let mut resp_header = [0u8; 16];
    stream.read_exact(&mut resp_header).map_err(|e| {
        error!(%e, "failed to read response header");
        DcomError::Recv
    })?;

    let resp_type = resp_header[2];
    if resp_type == 0x03 {
        // Fault
        error!("RemoteActivation returned fault");
        return Err(DcomError::Protocol);
    }

    let resp_len = u16::from_le_bytes([resp_header[8], resp_header[9]]) as usize;
    let mut response = vec![0u8; resp_len];
    response[..16].copy_from_slice(&resp_header);
    stream.read_exact(&mut response[16..]).map_err(|e| {
        error!(%e, "failed to read response body");
        DcomError::Recv
    })?;

    debug!(
        "Received anonymous RemoteActivation response, len: {}",
        response.len()
    );

    let activation = parse_remote_activation_response(&response, None)?;
    let port = activation.port().ok_or(DcomError::Protocol)?;
    Ok((port, activation.oxid))
}

/// Activate WMI via DCOM (IRemoteSCMActivator::RemoteActivation)
/// Returns (port, OXID) tuple
#[instrument(level = "debug", skip_all, fields(host))]
pub fn activate_wmi_dcom(host: &str, creds: &Credentials) -> Result<(u16, [u8; 8]), DcomError> {
    info!("Using DCOM activation for WMI port resolution");

    // Try Kerberos first if feature is enabled
    #[cfg(feature = "kerberos")]
    {
        // Determine realm from credentials or host
        let realm = if !creds.domain.is_empty() {
            creds.domain.to_uppercase()
        } else {
            // Extract domain from FQDN if available
            host.split('.')
                .skip(1)
                .collect::<Vec<_>>()
                .join(".")
                .to_uppercase()
        };

        // Only try Kerberos if we have a proper realm
        if !realm.is_empty() && realm.contains('.') {
            debug!("Trying Kerberos authentication with realm: {}", realm);

            #[cfg(feature = "kerberos")]
            {
                use crate::kerberos_adapter::KerberosClient;
                let kerberos_config = crate::kerberos_adapter::KerberosConfig::new(&realm);
                match KerberosClient::new(host, kerberos_config, creds.clone()) {
                    Ok(kerberos_client) => {
                        match activate_wmi_dcom_with_auth(host, Box::new(kerberos_client)) {
                            Ok((port, activation)) => {
                                info!("DCOM activation succeeded with Kerberos");
                                return Ok((port, activation.oxid));
                            }
                            Err(err) => {
                                warn!(?err, "Kerberos authentication failed, falling back to NTLM");
                            }
                        }
                    }
                    Err(err) => {
                        debug!(
                            ?err,
                            "Failed to create Kerberos client, falling back to NTLM"
                        );
                    }
                }
            }
        } else {
            debug!("Skipping Kerberos: no proper realm available");
        }
    }

    // Fall back to NTLM
    debug!("Using NTLM authentication for DCOM activation");
    activate_level1_login(host, creds).map(|(port, activation)| (port, activation.oxid))
}

/// Activate CLSID_WbemLevel1Login with NTLM and return the WMI port together
/// with the full activation result (OXID, IWbemLevel1Login IPID, bindings).
pub(crate) fn activate_level1_login(
    host: &str,
    creds: &Credentials,
) -> Result<(u16, ActivationResponse), DcomError> {
    let ntlm_client = crate::sspi_ntlm::SspiNtlmClient::new(creds, &format!("host/{host}"))
        .map_err(|err| {
            error!(%err, "failed to set up NTLM client");
            DcomError::Protocol
        })?;
    activate_wmi_dcom_with_auth(host, Box::new(ntlm_client))
}

/// Internal function that performs DCOM activation with a generic auth provider
fn activate_wmi_dcom_with_auth(
    host: &str,
    mut auth_client: Box<dyn AuthProvider>,
) -> Result<(u16, ActivationResponse), DcomError> {
    // Connect to SCM on port 135
    let addr = format!("{host}:135");
    let mut stream = TcpStream::connect_timeout(
        &addr
            .to_socket_addrs()
            .map_err(|e| {
                error!(%e, "failed to resolve host");
                DcomError::Connect
            })?
            .next()
            .ok_or(DcomError::Connect)?,
        Duration::from_secs(5),
    )
    .map_err(|e| {
        error!(%e, "failed to connect to SCM");
        DcomError::Connect
    })?;

    stream
        .set_read_timeout(Some(RPC_IO_TIMEOUT))
        .map_err(|_| DcomError::Connect)?;
    stream
        .set_write_timeout(Some(RPC_IO_TIMEOUT))
        .map_err(|_| DcomError::Connect)?;

    // IActivation {4d9f4ab8-7d1c-11cf-861e-0020af6e7c57}: RemoteActivation is opnum 0.
    let scm_uuid: [u8; 16] = hex_literal::hex!("b84a9f4d1c7dcf11861e0020af6e7c57");

    // Step 1: Bind with auth type 1 (negotiate)
    let negotiate_token = auth_client.negotiate().map_err(|_| DcomError::Protocol)?;
    let bind_pdu = build_scm_bind_pdu(1, &scm_uuid, &negotiate_token);
    debug!(
        len = bind_pdu.len(),
        hex = %hex::encode(&bind_pdu),
        "Sending SCM bind PDU"
    );
    stream.write_all(&bind_pdu).map_err(|_| DcomError::Send)?;

    let bind_ack = read_rpc_pdu(&mut stream)?;
    debug!(len = bind_ack.len(), hex = %hex::encode(&bind_ack), "SCM bind_ack raw");
    let (context_id, challenge_blob, max_xmit, max_recv) =
        RealRpcTransport::parse_bind_ack(&bind_ack).map_err(|err| {
            debug!(?err, "SCM bind_ack parse failure");
            DcomError::Protocol
        })?;
    debug!(context_id, max_xmit, max_recv, "SCM bind accepted");

    // Step 2: Send auth response via alter_context
    let response_token = auth_client
        .respond(&challenge_blob)
        .map_err(|_| DcomError::Protocol)?;
    let alter_pdu = build_scm_alter_context_pdu(2, context_id, &scm_uuid, &response_token);
    debug!(len = alter_pdu.len(), hex = %hex::encode(&alter_pdu), "Sending SCM alter_context");
    stream.write_all(&alter_pdu).map_err(|_| DcomError::Send)?;

    let alter_ack = read_rpc_pdu(&mut stream)?;
    debug!(len = alter_ack.len(), hex = %hex::encode(&alter_ack), "SCM alter_ack raw");
    RealRpcTransport::parse_alter_ack(&alter_ack).map_err(|err| {
        debug!(?err, "SCM alter_ack parse failure");
        DcomError::Protocol
    })?;
    debug!("SCM security context established");

    // MS-WMI 3.2.3: activate CLSID_WbemLevel1Login for IID_IWbemLevel1Login.
    let clsid_level1_login = hex_literal::hex!("5ef0c38b6bd8d011a07500c04fb68820");
    let iid_level1_login = hex_literal::hex!("18ad09f36ad8d011a07500c04fb68820");
    let stub = build_remote_activation_stub(&clsid_level1_login, &iid_level1_login)?;
    let req_pdu = build_sealed_request_pdu(auth_client.as_mut(), 3, context_id, 0, &stub, 0)
        .map_err(|err| {
            error!(%err, "failed to seal RemoteActivation");
            DcomError::Protocol
        })?;

    debug!("Sending RemoteActivation, len={}", req_pdu.len());
    stream.write_all(&req_pdu).map_err(|_| DcomError::Send)?;

    let resp_pdu = read_rpc_pdu(&mut stream)?;
    let resp_pdu = unseal_response_pdu(auth_client.as_mut(), &resp_pdu).map_err(|err| {
        error!(%err, "RemoteActivation response rejected");
        DcomError::Protocol
    })?;
    let activation = parse_remote_activation_response(&resp_pdu, Some(&iid_level1_login))?;
    let port = activation.port().ok_or_else(|| {
        error!("RemoteActivation response advertised no TCP binding");
        DcomError::Protocol
    })?;
    info!(
        "DCOM activation successful, WMI port={}, OXID={}, IPID={}",
        port,
        hex::encode(activation.oxid),
        hex::encode(activation.ipid)
    );

    Ok((port, activation))
}

use crate::transport::{
    build_sealed_request_pdu, unseal_response_pdu, write_context_list, AUTH_TYPE_NTLM,
    AUTH_TYPE_SPNEGO, DATA_REP, RPC_IO_TIMEOUT,
};
const AUTH_LEVEL_PRIVACY: u8 = 0x06; // Packet Privacy for encrypted communication
const MAX_XMIT_RECV: u16 = 0x10B8;

fn build_scm_bind_pdu(call_id: u32, abstract_syntax: &[u8; 16], negotiate: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.write_u16::<LittleEndian>(MAX_XMIT_RECV).unwrap();
    body.write_u16::<LittleEndian>(MAX_XMIT_RECV).unwrap();
    body.write_u32::<LittleEndian>(0).unwrap();
    write_context_list(&mut body, 0, abstract_syntax);

    let auth_len = if negotiate.is_empty() {
        0
    } else {
        // Wrap NTLM in SPNEGO for modern Windows compatibility
        let (auth_blob, auth_type) =
            if let Ok(wrapped) = spnego::wrap_in_spnego_init(negotiate, true) {
                (wrapped, AUTH_TYPE_SPNEGO)
            } else {
                // Fallback to raw NTLM if wrapping fails
                (negotiate.to_vec(), AUTH_TYPE_NTLM)
            };

        // Pad body to 4-byte alignment before auth trailer
        let pad = (4 - (body.len() % 4)) % 4;
        body.extend(std::iter::repeat_n(0u8, pad));

        // Auth trailer header
        body.push(auth_type);
        body.push(AUTH_LEVEL_PRIVACY);
        body.push(pad as u8); // pad_len field records the padding already applied
        body.push(0); // reserved
        body.write_u32::<LittleEndian>(0).unwrap(); // auth_context_id

        // No second padding - extend auth blob directly
        body.extend_from_slice(&auth_blob);
        auth_blob.len() as u16
    };

    let frag_len = (16 + body.len()) as u16;

    let mut pdu = Vec::with_capacity(frag_len as usize);
    pdu.write_u8(5).unwrap();
    pdu.write_u8(0).unwrap();
    pdu.write_u8(0x0B).unwrap();
    pdu.write_u8(0x03).unwrap();
    pdu.write_u32::<LittleEndian>(0x10).unwrap();
    pdu.write_u16::<LittleEndian>(frag_len).unwrap();
    pdu.write_u16::<LittleEndian>(auth_len).unwrap();
    pdu.write_u32::<LittleEndian>(call_id).unwrap();
    pdu.extend_from_slice(&body);
    pdu
}

fn build_scm_alter_context_pdu(
    call_id: u32,
    context_id: u16,
    abstract_syntax: &[u8; 16],
    authenticate: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.write_u16::<LittleEndian>(MAX_XMIT_RECV).unwrap();
    body.write_u16::<LittleEndian>(MAX_XMIT_RECV).unwrap();
    body.write_u32::<LittleEndian>(0).unwrap();
    write_context_list(&mut body, context_id, abstract_syntax);

    // Wrap NTLM in SPNEGO for modern Windows compatibility
    let (auth_blob, auth_type) =
        if let Ok(wrapped) = spnego::wrap_in_spnego_init(authenticate, true) {
            (wrapped, AUTH_TYPE_SPNEGO)
        } else {
            // Fallback to raw NTLM if wrapping fails
            (authenticate.to_vec(), AUTH_TYPE_NTLM)
        };

    // Pad body to 4-byte alignment before auth trailer
    let pad = (4 - (body.len() % 4)) % 4;
    body.extend(std::iter::repeat_n(0u8, pad));

    // Auth trailer header
    body.push(auth_type);
    body.push(AUTH_LEVEL_PRIVACY);
    body.push(pad as u8); // pad_len field records the padding already applied
    body.push(0); // reserved
    body.write_u32::<LittleEndian>(0).unwrap(); // auth_context_id

    // No second padding - extend auth blob directly
    body.extend_from_slice(&auth_blob);

    let frag_len = (16 + body.len()) as u16;
    let auth_len = auth_blob.len() as u16;

    let mut pdu = Vec::with_capacity(frag_len as usize);
    pdu.write_u8(5).unwrap();
    pdu.write_u8(0).unwrap();
    pdu.write_u8(0x0E).unwrap();
    pdu.write_u8(0x03).unwrap();
    pdu.write_u32::<LittleEndian>(0x10).unwrap();
    pdu.write_u16::<LittleEndian>(frag_len).unwrap();
    pdu.write_u16::<LittleEndian>(auth_len).unwrap();
    pdu.write_u32::<LittleEndian>(call_id).unwrap();
    pdu.extend_from_slice(&body);
    pdu
}

/// Build RemoteActivation request stub with proper NDR encoding
/// IActivation::RemoteActivation request stub (MS-DCOM 3.1.2.5.1.1), NDR20.
fn build_remote_activation_stub(clsid: &[u8; 16], iid: &[u8; 16]) -> Result<Vec<u8>, DcomError> {
    const RPC_C_IMP_LEVEL_IMPERSONATE: u32 = 3;
    const PROTSEQ_NCACN_IP_TCP: u16 = 0x0007;
    const UNIQUE_REFERENT: u32 = 0x0002_0000;

    let mut stub = Vec::new();

    // ORPCTHIS (MS-DCOM 2.2.13.1)
    stub.extend_from_slice(&[5, 0, 7, 0]); // COMVERSION 5.7
    stub.write_u32::<LittleEndian>(0).unwrap(); // flags
    stub.write_u32::<LittleEndian>(0).unwrap(); // reserved1
    stub.extend_from_slice(uuid::Uuid::new_v4().as_bytes()); // cid (causality ID)
    stub.write_u32::<LittleEndian>(0).unwrap(); // extensions: null

    stub.extend_from_slice(clsid); // Clsid
    stub.write_u32::<LittleEndian>(0).unwrap(); // pwszObjectName: null
    stub.write_u32::<LittleEndian>(0).unwrap(); // pObjectStorage: null
    stub.write_u32::<LittleEndian>(RPC_C_IMP_LEVEL_IMPERSONATE)
        .unwrap(); // ClientImpLevel
    stub.write_u32::<LittleEndian>(0).unwrap(); // Mode
    stub.write_u32::<LittleEndian>(1).unwrap(); // Interfaces

    // [unique, size_is(Interfaces)] IID* pIIDs: referent, then conformant array
    stub.write_u32::<LittleEndian>(UNIQUE_REFERENT).unwrap();
    stub.write_u32::<LittleEndian>(1).unwrap(); // max_count
    stub.extend_from_slice(iid);

    // [size_is(cRequestedProtseqs)] unsigned short aRequestedProtseqs[]: inline conformant array
    stub.write_u16::<LittleEndian>(1).unwrap(); // cRequestedProtseqs
    stub.extend_from_slice(&[0, 0]); // align max_count to 4
    stub.write_u32::<LittleEndian>(1).unwrap(); // max_count
    stub.write_u16::<LittleEndian>(PROTSEQ_NCACN_IP_TCP)
        .unwrap();

    Ok(stub)
}

/// Build RPC request PDU
fn build_request_pdu(
    call_id: u32,
    context_id: u16,
    opnum: u16,
    stub: &[u8],
) -> Result<Vec<u8>, DcomError> {
    let mut pdu = Vec::new();

    // RPC header
    pdu.write_u8(5).map_err(|_| DcomError::Protocol)?; // version
    pdu.write_u8(0).map_err(|_| DcomError::Protocol)?; // minor
    pdu.write_u8(0x00).map_err(|_| DcomError::Protocol)?; // ptype = request
    pdu.write_u8(0x03).map_err(|_| DcomError::Protocol)?; // flags
    pdu.write_u32::<LittleEndian>(0x10)
        .map_err(|_| DcomError::Protocol)?; // data_rep

    let frag_len = (24 + stub.len()) as u16;
    pdu.write_u16::<LittleEndian>(frag_len)
        .map_err(|_| DcomError::Protocol)?;
    pdu.write_u16::<LittleEndian>(0)
        .map_err(|_| DcomError::Protocol)?; // auth_len
    pdu.write_u32::<LittleEndian>(call_id)
        .map_err(|_| DcomError::Protocol)?;

    // Request body
    pdu.write_u32::<LittleEndian>(0)
        .map_err(|_| DcomError::Protocol)?; // alloc_hint
    pdu.write_u16::<LittleEndian>(context_id)
        .map_err(|_| DcomError::Protocol)?;
    pdu.write_u16::<LittleEndian>(opnum)
        .map_err(|_| DcomError::Protocol)?;

    pdu.extend_from_slice(stub);
    Ok(pdu)
}

/// Read a complete RPC PDU from the stream
fn read_rpc_pdu(stream: &mut TcpStream) -> Result<Vec<u8>, DcomError> {
    let mut header = [0u8; 16];
    stream
        .read_exact(&mut header)
        .map_err(|_| DcomError::Recv)?;

    let frag_len = u16::from_le_bytes([header[8], header[9]]) as usize;
    if frag_len < 16 {
        return Err(DcomError::Protocol);
    }

    let mut pdu = vec![0u8; frag_len];
    pdu[..16].copy_from_slice(&header);

    if frag_len > 16 {
        stream
            .read_exact(&mut pdu[16..])
            .map_err(|_| DcomError::Recv)?;
    }

    Ok(pdu)
}

/// IActivation::RemoteActivation output (MS-DCOM 3.1.2.5.1.1).
#[derive(Debug, Clone)]
pub(crate) struct ActivationResponse {
    pub oxid: [u8; 8],
    /// IPID of the activated interface, read from the returned OBJREF_STANDARD.
    pub ipid: [u8; 16],
    /// IPID of the OXID's IRemUnknown, needed later to release references.
    #[allow(dead_code)] // consumed once reference release (IRemUnknown) is implemented
    pub ipid_rem_unknown: [u8; 16],
    /// ncacn_ip_tcp bindings the server advertised, as (host, port). Under NAT
    /// these name the server's own view (e.g. DC01, 10.0.2.15); the caller keeps
    /// connecting to the address it dialed and only takes the port from here.
    pub tcp_bindings: Vec<(String, u16)>,
}

impl ActivationResponse {
    /// The WMI port to connect to (all advertised bindings share one endpoint).
    pub fn port(&self) -> Option<u16> {
        self.tcp_bindings.first().map(|&(_, port)| port)
    }
}

fn parse_remote_activation_response(
    pdu: &[u8],
    expected_iid: Option<&[u8; 16]>,
) -> Result<ActivationResponse, DcomError> {
    if pdu.len() < 24 {
        return Err(DcomError::Protocol);
    }
    match pdu[2] {
        0x02 => {}
        0x03 => {
            if pdu.len() >= 28 {
                let status = u32::from_le_bytes([pdu[24], pdu[25], pdu[26], pdu[27]]);
                error!("RPC fault: 0x{:08x}", status);
            }
            return Err(DcomError::Protocol);
        }
        other => {
            warn!("unexpected PDU type 0x{:02x} in activation response", other);
            return Err(DcomError::Protocol);
        }
    }

    // Trim to just the NDR stub: drop the 24-byte response header and, when the
    // PDU is authenticated, the trailing auth padding, sec_trailer (8 bytes) and
    // auth_value. error_status_t is then genuinely the last 4 bytes of the stub.
    let frag_len = u16::from_le_bytes([pdu[8], pdu[9]]) as usize;
    let auth_len = u16::from_le_bytes([pdu[10], pdu[11]]) as usize;
    if frag_len != pdu.len() {
        return Err(DcomError::Protocol);
    }
    let stub_end = if auth_len == 0 {
        frag_len
    } else {
        let trailer_at = frag_len
            .checked_sub(auth_len + 8)
            .filter(|&at| at >= 24)
            .ok_or(DcomError::Protocol)?;
        let auth_pad = pdu[trailer_at + 2] as usize;
        trailer_at
            .checked_sub(auth_pad)
            .filter(|&e| e >= 24)
            .ok_or(DcomError::Protocol)?
    };
    parse_activation_stub(&pdu[24..stub_end], expected_iid)
}

/// Parse the NDR stub of a RemoteActivation response.
fn parse_activation_stub(
    stub: &[u8],
    expected_iid: Option<&[u8; 16]>,
) -> Result<ActivationResponse, DcomError> {
    let mut c = Cursor::new(stub);
    let rd32 = |c: &mut Cursor<&[u8]>| {
        c.read_u32::<LittleEndian>()
            .map_err(|_| DcomError::Protocol)
    };
    let rd16 = |c: &mut Cursor<&[u8]>| {
        c.read_u16::<LittleEndian>()
            .map_err(|_| DcomError::Protocol)
    };

    // The call's return value (error_status_t) is the last 4 bytes of the stub.
    let ret = stub
        .len()
        .checked_sub(4)
        .and_then(|o| stub.get(o..o + 4))
        .ok_or(DcomError::Protocol)?;
    let ret = u32::from_le_bytes([ret[0], ret[1], ret[2], ret[3]]);
    if ret != 0 {
        error!("RemoteActivation returned error_status_t=0x{:08x}", ret);
        return Err(hresult_to_err(ret));
    }

    // ORPCTHAT: flags, then a pointer to the extension array (null in practice).
    let _flags = rd32(&mut c)?;
    if rd32(&mut c)? != 0 {
        warn!("ORPCTHAT carries extensions; unsupported");
        return Err(DcomError::Protocol);
    }

    // pOxid, passed by value.
    let mut oxid = [0u8; 8];
    c.read_exact(&mut oxid).map_err(|_| DcomError::Protocol)?;

    // ppdsaOxidBindings: a unique pointer to a DUALSTRINGARRAY (MS-DCOM 2.2.19.1).
    if rd32(&mut c)? == 0 {
        return Err(DcomError::Protocol);
    }
    // The conformant array's max_count must equal the struct's wNumEntries.
    let max_count = rd32(&mut c)? as usize;
    let num_entries = rd16(&mut c)? as usize;
    let security_offset = rd16(&mut c)? as usize;
    if max_count != num_entries || security_offset > num_entries {
        return Err(DcomError::Protocol);
    }
    let mut words = Vec::with_capacity(num_entries);
    for _ in 0..num_entries {
        words.push(rd16(&mut c)?);
    }
    let tcp_bindings = parse_string_bindings(&words[..security_offset]);

    // NDR aligns the next field (ipidRemUnknown) to 4 bytes.
    let pos = c.position() as usize;
    c.set_position(((pos + 3) & !3) as u64);
    let mut ipid_rem_unknown = [0u8; 16];
    c.read_exact(&mut ipid_rem_unknown)
        .map_err(|_| DcomError::Protocol)?;
    let _authn_hint = rd32(&mut c)?;
    let _com_version = rd32(&mut c)?; // COMVERSION { major: u16, minor: u16 }
    let phr = rd32(&mut c)?;
    if phr != 0 {
        error!("RemoteActivation hr=0x{:08x}", phr);
        return Err(hresult_to_err(phr));
    }

    // The activated interface comes back (in ppInterfaceData, after phr) as an
    // MInterfacePointer wrapping an OBJREF_STANDARD; its std.ipid is what later
    // ORPC calls target. The OBJREF starts with the "MEOW" signature (MS-DCOM
    // 2.2.18). Scan only the bytes after phr so a "MEOW" inside the random OXID
    // or ipidRemUnknown cannot be mistaken for it.
    let ipid = find_objref_ipid(stub, c.position() as usize, &oxid, expected_iid)?;

    debug!(
        oxid = %hex::encode(oxid),
        ipid = %hex::encode(ipid),
        ?tcp_bindings,
        "parsed RemoteActivation response"
    );
    Ok(ActivationResponse {
        oxid,
        ipid,
        ipid_rem_unknown,
        tcp_bindings,
    })
}

/// Parse STRINGBINDING entries (MS-DCOM 2.2.19.3): each is a u16 tower id
/// followed by a NUL-terminated UTF-16LE address; a lone 0x0000 ends the list.
fn parse_string_bindings(words: &[u16]) -> Vec<(String, u16)> {
    const TOWER_NCACN_IP_TCP: u16 = 0x0007;
    let mut bindings = Vec::new();
    let mut i = 0;
    while i < words.len() {
        let tower_id = words[i];
        i += 1;
        if tower_id == 0 {
            break;
        }
        let start = i;
        while i < words.len() && words[i] != 0 {
            i += 1;
        }
        let name = String::from_utf16_lossy(&words[start..i]);
        if i < words.len() {
            i += 1; // consume NUL
        }
        if tower_id == TOWER_NCACN_IP_TCP {
            if let Some(pair) = split_host_port(&name) {
                bindings.push(pair);
            }
        }
    }
    bindings
}

/// Split a "host[port]" network address into its parts.
fn split_host_port(addr: &str) -> Option<(String, u16)> {
    let (host, rest) = addr.split_once('[')?;
    let port = rest.strip_suffix(']')?.parse::<u16>().ok()?;
    (port > 0).then(|| (host.to_string(), port))
}

/// Locate the OBJREF_STANDARD (MS-DCOM 2.2.18) at or after `scan_from`, and
/// return std.ipid. Verifies the signature region is OBJREF_STANDARD, that its
/// IID matches `expected_iid` (when given), and that std.oxid matches the
/// activation's OXID.
fn find_objref_ipid(
    stub: &[u8],
    scan_from: usize,
    expected_oxid: &[u8; 8],
    expected_iid: Option<&[u8; 16]>,
) -> Result<[u8; 16], DcomError> {
    // OBJREF layout: signature(4) flags(4) iid(16) then STDOBJREF
    // { flags(4) cPublicRefs(4) oxid(8) oid(8) ipid(16) }.
    const FLAGS_OFFSET: usize = 4;
    const IID_OFFSET: usize = 8;
    const OXID_OFFSET: usize = 4 + 4 + 16 + 4 + 4; // 32
    const IPID_OFFSET: usize = OXID_OFFSET + 8 + 8; // 48
    const OBJREF_END: usize = IPID_OFFSET + 16; // 64
    const OBJREF_STANDARD: u32 = 0x1;

    let region = stub.get(scan_from..).ok_or(DcomError::Protocol)?;
    let meow = scan_from
        + region
            .windows(4)
            .position(|w| w == b"MEOW")
            .ok_or(DcomError::Protocol)?;
    let objref = stub
        .get(meow..meow + OBJREF_END)
        .ok_or(DcomError::Protocol)?;

    let flags = u32::from_le_bytes(objref[FLAGS_OFFSET..FLAGS_OFFSET + 4].try_into().unwrap());
    if flags != OBJREF_STANDARD {
        warn!("OBJREF flags 0x{:08x} is not OBJREF_STANDARD", flags);
        return Err(DcomError::Protocol);
    }
    if let Some(iid) = expected_iid {
        if &objref[IID_OFFSET..IID_OFFSET + 16] != iid {
            warn!("OBJREF IID does not match the activated interface");
            return Err(DcomError::Protocol);
        }
    }
    if &objref[OXID_OFFSET..OXID_OFFSET + 8] != expected_oxid {
        warn!("OBJREF oxid does not match activation oxid");
        return Err(DcomError::Protocol);
    }
    let mut ipid = [0u8; 16];
    ipid.copy_from_slice(&objref[IPID_OFFSET..IPID_OFFSET + 16]);
    Ok(ipid)
}

/// Build an anonymous RPC bind PDU (no authentication)
fn build_anonymous_bind_pdu(call_id: u32, interface_uuid: &[u8; 16]) -> Vec<u8> {
    use byteorder::WriteBytesExt;

    let mut pdu = Vec::new();

    // RPC header
    pdu.write_u8(5).unwrap(); // version major
    pdu.write_u8(0).unwrap(); // version minor
    pdu.write_u8(0x0B).unwrap(); // ptype: BIND
    pdu.write_u8(0x03).unwrap(); // flags: first+last fragment
    pdu.extend_from_slice(&DATA_REP);

    // Fragment length (will update later)
    let frag_len_offset = pdu.len();
    pdu.write_u16::<LittleEndian>(0).unwrap(); // placeholder

    // Auth length = 0 for anonymous
    pdu.write_u16::<LittleEndian>(0).unwrap();

    // Call ID
    pdu.write_u32::<LittleEndian>(call_id).unwrap();

    // Bind body
    pdu.write_u16::<LittleEndian>(0x10B8).unwrap(); // max_xmit_frag
    pdu.write_u16::<LittleEndian>(0x10B8).unwrap(); // max_recv_frag
    pdu.write_u32::<LittleEndian>(0).unwrap(); // assoc_group

    write_context_list(&mut pdu, 0, interface_uuid);

    // NO auth trailer for anonymous bind

    // Update fragment length
    let frag_len = pdu.len() as u16;
    pdu[frag_len_offset..frag_len_offset + 2].copy_from_slice(&frag_len.to_le_bytes());

    pdu
}

/// Build an anonymous RPC request PDU (no authentication)
fn build_anonymous_request_pdu(call_id: u32, context_id: u16, opnum: u16, stub: &[u8]) -> Vec<u8> {
    use byteorder::WriteBytesExt;

    let mut pdu = Vec::new();

    // RPC header
    pdu.write_u8(5).unwrap(); // version major
    pdu.write_u8(0).unwrap(); // version minor
    pdu.write_u8(0x00).unwrap(); // ptype: REQUEST
    pdu.write_u8(0x03).unwrap(); // flags: first+last fragment
    pdu.extend_from_slice(&DATA_REP);

    // Fragment length (will update later)
    let frag_len_offset = pdu.len();
    pdu.write_u16::<LittleEndian>(0).unwrap(); // placeholder

    // Auth length = 0 for anonymous
    pdu.write_u16::<LittleEndian>(0).unwrap();

    // Call ID
    pdu.write_u32::<LittleEndian>(call_id).unwrap();

    // Request body
    pdu.write_u32::<LittleEndian>(stub.len() as u32).unwrap(); // alloc_hint
    pdu.write_u16::<LittleEndian>(context_id).unwrap(); // p_cont_id
    pdu.write_u16::<LittleEndian>(opnum).unwrap(); // opnum

    // Stub data
    pdu.extend_from_slice(stub);

    // NO auth trailer for anonymous request

    // Update fragment length
    let frag_len = pdu.len() as u16;
    pdu[frag_len_offset..frag_len_offset + 2].copy_from_slice(&frag_len.to_le_bytes());

    pdu
}

#[allow(dead_code)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_level_privacy_in_bind_pdu() {
        // Test that bind PDU uses privacy auth level
        let negotiate = vec![0x4E, 0x54, 0x4C, 0x4D]; // "NTLM"
        let pdu = build_scm_bind_pdu(
            1,
            &[
                0x99, 0xFC, 0xFE, 0xC4, 0x52, 0x60, 0x10, 0x1B, 0xBB, 0xCB, 0x00, 0xAA, 0x00, 0x21,
                0x34, 0x7A,
            ],
            &negotiate,
        );

        // Find auth header in PDU
        // Auth trailer comes after the main body, before the auth blob
        // Now using SPNEGO (0x09) instead of raw NTLM (0x0A)
        let mut found_auth_level = false;
        for i in 0..pdu.len() - 1 {
            if pdu[i] == AUTH_TYPE_SPNEGO && i + 1 < pdu.len() {
                assert_eq!(
                    pdu[i + 1],
                    AUTH_LEVEL_PRIVACY,
                    "Auth level should be PRIVACY (0x06)"
                );
                found_auth_level = true;
                break;
            }
        }
        assert!(found_auth_level, "Should find auth level in bind PDU");
    }

    #[test]
    fn test_auth_level_privacy_in_alter_context_pdu() {
        // Test that alter context PDU uses privacy auth level
        let authenticate = vec![0x4E, 0x54, 0x4C, 0x4D]; // "NTLM"
        let pdu = build_scm_alter_context_pdu(
            2, // call_id
            0, // context_id
            &[
                0x99, 0xFC, 0xFE, 0xC4, 0x52, 0x60, 0x10, 0x1B, 0xBB, 0xCB, 0x00, 0xAA, 0x00, 0x21,
                0x34, 0x7A,
            ],
            &authenticate,
        );

        // Find auth header in PDU
        // Now using SPNEGO (0x09) instead of raw NTLM (0x0A)
        let mut found_auth_level = false;
        for i in 0..pdu.len() - 1 {
            if pdu[i] == AUTH_TYPE_SPNEGO && i + 1 < pdu.len() {
                assert_eq!(
                    pdu[i + 1],
                    AUTH_LEVEL_PRIVACY,
                    "Auth level should be PRIVACY (0x06)"
                );
                found_auth_level = true;
                break;
            }
        }
        assert!(
            found_auth_level,
            "Should find auth level in alter context PDU"
        );
    }

    #[test]
    fn remote_activation_stub_matches_ms_dcom_ndr_layout() {
        let clsid = hex_literal::hex!("5ef0c38b6bd8d011a07500c04fb68820");
        let iid = hex_literal::hex!("18ad09f36ad8d011a07500c04fb68820");
        let stub = build_remote_activation_stub(&clsid, &iid).unwrap();

        assert_eq!(&stub[0..4], &[5, 0, 7, 0], "ORPCTHIS COMVERSION 5.7");
        assert_eq!(&stub[4..12], &[0; 8], "flags, reserved1");
        // stub[12..28] is the random causality ID
        assert_eq!(&stub[28..32], &[0; 4], "extensions: null");
        assert_eq!(&stub[32..48], &clsid);
        let words: Vec<u32> = stub[48..72]
            .chunks(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        // pwszObjectName, pObjectStorage, ClientImpLevel, Mode, Interfaces, pIIDs referent
        assert_eq!(&words[..5], &[0, 0, 3, 0, 1]);
        assert_ne!(words[5], 0, "pIIDs referent");
        assert_eq!(&stub[72..76], &1u32.to_le_bytes(), "pIIDs max_count");
        assert_eq!(&stub[76..92], &iid);
        assert_eq!(&stub[92..94], &1u16.to_le_bytes(), "cRequestedProtseqs");
        assert_eq!(&stub[94..96], &[0, 0], "alignment");
        assert_eq!(
            &stub[96..100],
            &1u32.to_le_bytes(),
            "aRequestedProtseqs max_count"
        );
        assert_eq!(&stub[100..102], &7u16.to_le_bytes(), "ncacn_ip_tcp");
        assert_eq!(stub.len(), 102);
    }

    /// Decrypted IActivation::RemoteActivation response captured from a Windows
    /// Server 2022 DC activating CLSID_WbemLevel1Login (behind QEMU user-mode
    /// NAT, so it advertises its internal names). Non-sensitive protocol data.
    const WINDOWS_ACTIVATION_STUB: &[u8] =
        include_bytes!("testdata/remote_activation_response_stub.bin");

    const IID_WBEM_LEVEL1_LOGIN: [u8; 16] = hex_literal::hex!("18ad09f36ad8d011a07500c04fb68820");
    /// Byte offset of phr within WINDOWS_ACTIVATION_STUB (after the string array).
    const PHR_OFFSET: usize = 388;

    #[test]
    fn parse_activation_stub_matches_windows_response() {
        let r =
            parse_activation_stub(WINDOWS_ACTIVATION_STUB, Some(&IID_WBEM_LEVEL1_LOGIN)).unwrap();
        assert_eq!(hex::encode(r.oxid), "889959be75b91cd7");
        assert_eq!(hex::encode(r.ipid), "1a7c0000e8090000b541859917e7b564");
        assert_eq!(
            hex::encode(r.ipid_rem_unknown),
            "00a40000e809000023bfdc109049aa7d"
        );
        assert_eq!(
            r.tcp_bindings,
            vec![
                ("DC01".to_string(), 24158),
                ("10.0.2.15".to_string(), 24158),
            ]
        );
        assert_eq!(r.port(), Some(24158));
    }

    #[test]
    fn parse_activation_stub_rejects_nonzero_phr() {
        let mut stub = WINDOWS_ACTIVATION_STUB.to_vec();
        stub[PHR_OFFSET..PHR_OFFSET + 4].copy_from_slice(&0x8007_0005u32.to_le_bytes());
        assert!(matches!(
            parse_activation_stub(&stub, None),
            Err(DcomError::AccessDenied)
        ));
    }

    #[test]
    fn parse_activation_stub_rejects_nonzero_return_value() {
        let mut stub = WINDOWS_ACTIVATION_STUB.to_vec();
        let n = stub.len();
        stub[n - 4..].copy_from_slice(&0x0000_0005u32.to_le_bytes());
        assert!(parse_activation_stub(&stub, None).is_err());
    }

    #[test]
    fn parse_activation_stub_rejects_wrong_iid() {
        let wrong = [0xAAu8; 16];
        assert!(parse_activation_stub(WINDOWS_ACTIVATION_STUB, Some(&wrong)).is_err());
    }

    #[test]
    fn parse_activation_stub_rejects_max_count_mismatch() {
        // DUALSTRINGARRAY conformant max_count is at offset 20 (after 24-byte
        // RPC header would be 44; here the stub has no RPC header).
        let mut stub = WINDOWS_ACTIVATION_STUB.to_vec();
        stub[20..24].copy_from_slice(&9999u32.to_le_bytes());
        assert!(parse_activation_stub(&stub, None).is_err());
    }

    #[test]
    fn parse_activation_stub_handles_truncation_without_panic() {
        // Callers only ever pass a length-validated PDU, but a truncated buffer
        // must never panic (it either errors or returns the data it could read).
        for n in 0..WINDOWS_ACTIVATION_STUB.len() {
            let _ = parse_activation_stub(&WINDOWS_ACTIVATION_STUB[..n], None);
        }
        // A prefix too short to hold the OBJREF cannot yield an IPID.
        assert!(parse_activation_stub(&WINDOWS_ACTIVATION_STUB[..100], None).is_err());
    }

    /// Wrap a stub in a response PDU with a sec_trailer + auth_value, as the
    /// sealed path delivers it after decryption.
    fn authenticated_response_pdu(stub: &[u8], auth_value_len: usize) -> Vec<u8> {
        let pad = (16 - stub.len() % 16) % 16;
        let frag_len = 24 + stub.len() + pad + 8 + auth_value_len;
        let mut pdu = vec![5, 0, 0x02, 0x03, 0x10, 0, 0, 0];
        pdu.extend_from_slice(&(frag_len as u16).to_le_bytes());
        pdu.extend_from_slice(&(auth_value_len as u16).to_le_bytes());
        pdu.extend_from_slice(&3u32.to_le_bytes()); // call_id
        pdu.extend_from_slice(&(stub.len() as u32).to_le_bytes()); // alloc_hint
        pdu.extend_from_slice(&[0, 0, 0, 0]); // p_cont_id, cancel_count, reserved
        pdu.extend_from_slice(stub);
        pdu.extend(std::iter::repeat_n(0u8, pad));
        pdu.extend_from_slice(&[0x0a, 0x06, pad as u8, 0, 0, 0, 0, 0]); // sec_trailer
        pdu.extend(std::iter::repeat_n(0xFFu8, auth_value_len)); // auth_value
        pdu
    }

    #[test]
    fn parse_remote_activation_response_strips_auth_trailer() {
        // The error_status_t check must read the real last stub word, not the
        // trailing auth signature. Without trimming, the 0xFF auth bytes would
        // look like a non-zero return value and this would wrongly fail.
        let pdu = authenticated_response_pdu(WINDOWS_ACTIVATION_STUB, 16);
        let r = parse_remote_activation_response(&pdu, Some(&IID_WBEM_LEVEL1_LOGIN)).unwrap();
        assert_eq!(r.port(), Some(24158));
        assert_eq!(hex::encode(r.ipid), "1a7c0000e8090000b541859917e7b564");
    }

    #[test]
    fn parse_remote_activation_response_rejects_fault_pdu() {
        // ptype=0x03 (fault), status E_ACCESSDENIED at offset 24.
        let mut pdu = vec![5, 0, 0x03, 0x03, 0x10, 0, 0, 0, 32, 0, 0, 0, 1, 0, 0, 0];
        pdu.extend_from_slice(&[0u8; 8]); // alloc_hint, cancel_count, reserved
        pdu.extend_from_slice(&0x8007_0005u32.to_le_bytes());
        assert!(parse_remote_activation_response(&pdu, None).is_err());
    }

    #[test]
    fn split_host_port_parses_binding() {
        assert_eq!(split_host_port("DC01[24158]"), Some(("DC01".into(), 24158)));
        assert_eq!(
            split_host_port("10.0.2.15[24158]"),
            Some(("10.0.2.15".into(), 24158))
        );
        assert_eq!(split_host_port("no-port"), None);
        assert_eq!(split_host_port("host[0]"), None);
    }

    /// First 72 bytes of the IRemoteSCMActivator bind impacket 0.13.1 sent to a
    /// Windows Server 2022 DC (accepted with bind_ack): header + p_cont_list.
    /// frag_length/auth_length (bytes 8..12) belong to its NTLM trailer.
    const IMPACKET_SCM_BIND_PREFIX: [u8; 72] = hex_literal::hex!(
        "05000b03100000007000200001000000b810b81000000000"
        "0100000000000100a001000000000000c000000000000046"
        "00000000045d888aeb1cc9119fe808002b10486002000000"
    );
    const IREMOTESCMACTIVATOR: [u8; 16] = hex_literal::hex!("a001000000000000c000000000000046");

    fn assert_matches_windows_bind(pdu: &[u8]) {
        assert_eq!(&pdu[..8], &IMPACKET_SCM_BIND_PREFIX[..8], "header/drep");
        assert_eq!(
            &pdu[12..72],
            &IMPACKET_SCM_BIND_PREFIX[12..],
            "call_id/context list"
        );
        let frag_len = u16::from_le_bytes([pdu[8], pdu[9]]) as usize;
        assert_eq!(frag_len, pdu.len(), "frag_length must equal PDU size");
    }

    #[test]
    fn anonymous_bind_matches_windows_accepted_bind() {
        let pdu = build_anonymous_bind_pdu(1, &IREMOTESCMACTIVATOR);
        assert_eq!(pdu.len(), 72);
        assert_matches_windows_bind(&pdu);
    }

    #[test]
    fn authenticated_bind_matches_windows_accepted_bind() {
        let pdu = build_scm_bind_pdu(1, &IREMOTESCMACTIVATOR, b"NTLMSSP\0\x01\0\0\0");
        assert_matches_windows_bind(&pdu);
        // Context list ends 4-aligned, so the sec_trailer follows with no padding.
        assert_eq!(pdu[74], 0, "auth_pad_length");
    }
}
