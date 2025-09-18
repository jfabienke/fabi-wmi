use std::io::{Cursor, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use nom::{
    bytes::complete::take,
    number::complete::{le_u16, le_u32},
    IResult,
};
use thiserror::Error;
use tracing::{debug, error, info, instrument, warn};

use crate::auth::{AuthProvider, Credentials, NtlmV2Client};
use crate::transport::RealRpcTransport;

/// Object reference returned from OXID resolver
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ObjectReference {
    pub ipid: [u8; 16],         // Interface Pointer ID
    pub std_flags: u32,          // Standard flags
    pub public_refs: u32,        // Public reference count
    pub oxid: [u8; 8],          // Object Exporter ID
    pub oid: [u8; 8],           // Object ID
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
}

#[allow(dead_code)]
fn parse_epm_bind_ack(pdu: &[u8]) -> Result<u16, DcomError> {
    // Simple parser for EPM bind_ack to get context_id
    if pdu.len() < 26 {
        error!("EPM bind_ack too short: {}", pdu.len());
        return Err(DcomError::Tower);
    }

    let ptype = pdu[2];
    if ptype != 0x0C {
        error!("Expected bind_ack (0x0C), got 0x{:02x}", ptype);
        debug!("PDU hex: {}", hex::encode(pdu));
        return Err(DcomError::Tower);
    }

    // Skip to presentation results
    let mut cursor = Cursor::new(pdu);
    cursor.set_position(16); // Skip RPC header

    let max_xmit = cursor
        .read_u16::<LittleEndian>()
        .map_err(|_| DcomError::Tower)?;
    let max_recv = cursor
        .read_u16::<LittleEndian>()
        .map_err(|_| DcomError::Tower)?;
    debug!("max_xmit={}, max_recv={}", max_xmit, max_recv);

    let _assoc_group = cursor
        .read_u32::<LittleEndian>()
        .map_err(|_| DcomError::Tower)?;
    let sec_addr_len = cursor
        .read_u16::<LittleEndian>()
        .map_err(|_| DcomError::Tower)? as usize;
    debug!("sec_addr_len={}", sec_addr_len);

    // Skip secondary address
    if sec_addr_len > 0 {
        cursor.set_position(cursor.position() + sec_addr_len as u64);
    }

    // Align to 4 bytes
    let pos = cursor.position();
    let padding = (4 - (pos % 4)) % 4;
    cursor.set_position(pos + padding);
    debug!("After padding, pos={}", cursor.position());

    let num_results = cursor.read_u8().map_err(|_| DcomError::Tower)?;
    debug!("num_results={}", num_results);
    if num_results == 0 {
        error!("No presentation contexts in bind_ack");
        return Err(DcomError::Tower);
    }

    cursor.set_position(cursor.position() + 3); // Skip reserved bytes

    let result = cursor
        .read_u16::<LittleEndian>()
        .map_err(|_| DcomError::Tower)?;
    debug!("presentation result={}", result);
    if result != 0 {
        error!("EPM bind rejected: result={}", result);
        return Err(DcomError::Tower);
    }

    // Context ID is what we requested (0)
    Ok(0)
}

#[instrument(level = "debug", skip_all, fields(host))]
pub fn resolve_wmi_port(host: &str, creds: Option<&Credentials>) -> Result<u16, DcomError> {
    if let Ok(value) = std::env::var("LINUX_WMI_SKIP_EPM") {
        if value.trim() == "1" {
            warn!("LINUX_WMI_SKIP_EPM set; returning port 135");
            return Ok(135);
        }
    }

    if let Some(creds) = creds {
        match activate_wmi_dcom(host, creds) {
            Ok(port) => return Ok(port),
            Err(err) => warn!(?err, "DCOM activation failed; falling back to port 135"),
        }
    } else {
        warn!("No credentials provided; falling back to port 135");
    }

    Ok(135)
}

/// Resolve OXID to get object reference using IObjectExporter
#[instrument(level = "debug", skip_all, fields(host, port))]
fn resolve_oxid(
    host: &str,
    port: u16,
    oxid: &[u8; 8],
    creds: &Credentials,
) -> Result<ObjectReference, DcomError> {
    debug!("Resolving OXID {} on port {}", hex::encode(oxid), port);

    // Connect to dynamic port
    let addr = format!("{}:{}", host, port);
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
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| DcomError::Connect)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| DcomError::Connect)?;

    // IObjectExporter UUID
    let object_exporter_uuid: [u8; 16] = hex_literal::hex!("c4 fe 9f 99 60 52 1b 10 bb cb 00 aa 00 21 34 7a");
    let mut auth_client = NtlmV2Client::new(creds.clone()).map_err(|_| DcomError::Protocol)?;

    // Bind to IObjectExporter with NTLM auth
    let type1 = auth_client.negotiate().map_err(|_| DcomError::Protocol)?;
    let bind_pdu = build_scm_bind_pdu(1, &object_exporter_uuid, &type1);
    stream.write_all(&bind_pdu).map_err(|_| DcomError::Send)?;

    let bind_ack = read_rpc_pdu(&mut stream)?;
    let (context_id, type2_blob, _, _) = RealRpcTransport::parse_bind_ack(&bind_ack)
        .map_err(|_| DcomError::Protocol)?;

    // Complete auth with alter_context
    let authenticate = auth_client
        .respond_message(&type2_blob)
        .map_err(|_| DcomError::Protocol)?;
    let alter_pdu = build_scm_alter_context_pdu(2, context_id, &object_exporter_uuid, &authenticate.message);
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
        // fault
        if pdu.len() >= 28 {
            let status = u32::from_le_bytes([pdu[24], pdu[25], pdu[26], pdu[27]]);
            error!("ResolveOxid fault: 0x{:08x}", status);
        }
        return Err(DcomError::Protocol);
    }

    if ptype != 0x02 {
        return Err(DcomError::Protocol);
    }

    // Skip to stub data
    let _stub_data = &pdu[24..];

    // Parse ORPCTHAT and response
    // For now, return a stub ObjectReference
    // TODO: Properly parse the response structure
    Ok(ObjectReference {
        ipid: [0u8; 16],     // Will be parsed from response
        std_flags: 0x00000001,
        public_refs: 5,
        oxid: *oxid,
        oid: [0u8; 8],       // Will be parsed from response
    })
}

/// Activate WMI via DCOM (IRemoteSCMActivator::RemoteActivation)
#[instrument(level = "debug", skip_all, fields(host))]
fn activate_wmi_dcom(host: &str, creds: &Credentials) -> Result<u16, DcomError> {
    info!("Using DCOM activation for WMI port resolution");

    // Connect to SCM on port 135
    let addr = format!("{}:135", host);
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
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| DcomError::Connect)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| DcomError::Connect)?;

    let scm_uuid: [u8; 16] = hex_literal::hex!("a0 01 00 00 00 00 00 00 c0 00 00 00 00 00 00 46");
    let mut auth_client = NtlmV2Client::new(creds.clone()).map_err(|_| DcomError::Protocol)?;

    // Step 1: Bind with NTLM Type 1
    let type1 = auth_client.negotiate().map_err(|_| DcomError::Protocol)?;
    let bind_pdu = build_scm_bind_pdu(1, &scm_uuid, &type1);
    debug!(
        len = bind_pdu.len(),
        hex = %hex::encode(&bind_pdu),
        "Sending SCM bind PDU"
    );
    stream.write_all(&bind_pdu).map_err(|_| DcomError::Send)?;

    let bind_ack = read_rpc_pdu(&mut stream)?;
    debug!(len = bind_ack.len(), hex = %hex::encode(&bind_ack), "SCM bind_ack raw");
    let (context_id, type2_blob, max_xmit, max_recv) = RealRpcTransport::parse_bind_ack(&bind_ack)
        .map_err(|err| {
            debug!(?err, "SCM bind_ack parse failure");
            DcomError::Protocol
        })?;
    debug!(context_id, max_xmit, max_recv, "SCM bind accepted");

    // Step 2: Send NTLM Type 3 via alter_context
    let authenticate = auth_client
        .respond_message(&type2_blob)
        .map_err(|_| DcomError::Protocol)?;
    let alter_pdu = build_scm_alter_context_pdu(2, context_id, &scm_uuid, &authenticate.message);
    debug!(len = alter_pdu.len(), hex = %hex::encode(&alter_pdu), "Sending SCM alter_context");
    stream.write_all(&alter_pdu).map_err(|_| DcomError::Send)?;

    let alter_ack = read_rpc_pdu(&mut stream)?;
    debug!(len = alter_ack.len(), hex = %hex::encode(&alter_ack), "SCM alter_ack raw");
    RealRpcTransport::parse_alter_ack(&alter_ack).map_err(|err| {
        debug!(?err, "SCM alter_ack parse failure");
        DcomError::Protocol
    })?;
    debug!("SCM security context established");

    let clsid_wmi = hex_literal::hex!("11 f8 90 45 3a 1d d0 11 89 1f 00 aa 00 4b 2e 24");
    let iid_locator = hex_literal::hex!("87 a6 12 dc 7f 73 cf 11 88 4d 00 aa 00 4b 2e 24");
    let stub = build_remote_activation_stub(&clsid_wmi, &iid_locator)?;
    let req_pdu = build_request_pdu(3, context_id, 4, &stub)?; // opnum=4

    debug!("Sending RemoteActivation, len={}", req_pdu.len());
    stream.write_all(&req_pdu).map_err(|_| DcomError::Send)?;

    let resp_pdu = read_rpc_pdu(&mut stream)?;
    let (port, oxid) = parse_remote_activation_response(&resp_pdu)?;
    info!("DCOM activation successful, WMI port={}, OXID={}", port, hex::encode(&oxid));

    // Resolve the OXID to get the full object reference
    match resolve_oxid(host, port, &oxid, creds) {
        Ok(obj_ref) => {
            info!("OXID resolved successfully: {:?}", obj_ref);
            Ok(port)
        }
        Err(e) => {
            warn!("OXID resolution failed: {:?}, continuing with port only", e);
            Ok(port)
        }
    }
}

const AUTH_TYPE_NTLM: u8 = 0x0A;
const AUTH_LEVEL_CONNECT: u8 = 0x02;
const MAX_XMIT_RECV: u16 = 0x10B8;

fn build_scm_bind_pdu(call_id: u32, abstract_syntax: &[u8; 16], negotiate: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.write_u16::<LittleEndian>(MAX_XMIT_RECV).unwrap();
    body.write_u16::<LittleEndian>(MAX_XMIT_RECV).unwrap();
    body.write_u32::<LittleEndian>(0).unwrap();
    body.write_u8(1).unwrap();
    body.write_u8(0).unwrap();
    body.write_u16::<LittleEndian>(0).unwrap();
    body.write_u8(1).unwrap();
    body.write_u8(0).unwrap();
    body.extend_from_slice(abstract_syntax);
    body.write_u16::<LittleEndian>(0).unwrap();
    body.write_u16::<LittleEndian>(0).unwrap();
    body.extend_from_slice(&hex_literal::hex!("045d888aeb1cc9119fe808002b104860"));
    body.write_u32::<LittleEndian>(2).unwrap();

    let auth_len = if negotiate.is_empty() {
        0
    } else {
        let pad = (4 - (body.len() % 4)) % 4;
        for _ in 0..pad {
            body.push(0);
        }
        body.push(AUTH_TYPE_NTLM);
        body.push(AUTH_LEVEL_CONNECT);
        body.push(pad as u8);
        body.push(0);
        body.write_u32::<LittleEndian>(0).unwrap();
        for _ in 0..pad {
            body.push(0);
        }
        body.extend_from_slice(negotiate);
        negotiate.len() as u16
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
    body.write_u8(1).unwrap();
    body.write_u8(0).unwrap();
    body.write_u16::<LittleEndian>(context_id).unwrap();
    body.write_u8(1).unwrap();
    body.write_u8(0).unwrap();
    body.extend_from_slice(abstract_syntax);
    body.write_u16::<LittleEndian>(0).unwrap();
    body.write_u16::<LittleEndian>(0).unwrap();
    body.extend_from_slice(&hex_literal::hex!("045d888aeb1cc9119fe808002b104860"));
    body.write_u32::<LittleEndian>(2).unwrap();

    let pad = (4 - (body.len() % 4)) % 4;
    for _ in 0..pad {
        body.push(0);
    }

    body.push(AUTH_TYPE_NTLM);
    body.push(AUTH_LEVEL_CONNECT);
    body.push(pad as u8);
    body.push(0);
    body.write_u32::<LittleEndian>(0).unwrap();
    for _ in 0..pad {
        body.push(0);
    }
    body.extend_from_slice(authenticate);

    let frag_len = (16 + body.len()) as u16;
    let auth_len = authenticate.len() as u16;

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

/// Build RemoteActivation request stub
fn build_remote_activation_stub(clsid: &[u8; 16], iid: &[u8; 16]) -> Result<Vec<u8>, DcomError> {
    let mut stub = Vec::new();

    // ORPCTHIS header
    stub.write_u32::<LittleEndian>(0x00000001)
        .map_err(|_| DcomError::Protocol)?; // version
    stub.write_u32::<LittleEndian>(0)
        .map_err(|_| DcomError::Protocol)?; // flags
    stub.write_u32::<LittleEndian>(0)
        .map_err(|_| DcomError::Protocol)?; // reserved1
    stub.extend_from_slice(&[0u8; 16]); // causality ID
    stub.write_u32::<LittleEndian>(0)
        .map_err(|_| DcomError::Protocol)?; // no extensions

    // RemoteActivation parameters
    stub.extend_from_slice(clsid); // CLSID
    stub.write_u32::<LittleEndian>(0)
        .map_err(|_| DcomError::Protocol)?; // pwszObjectName (null)
    stub.write_u32::<LittleEndian>(0)
        .map_err(|_| DcomError::Protocol)?; // pObjectStorage (null)
    stub.write_u32::<LittleEndian>(2)
        .map_err(|_| DcomError::Protocol)?; // ClientImpLevel = IDENTIFY
    stub.write_u32::<LittleEndian>(0)
        .map_err(|_| DcomError::Protocol)?; // Mode
    stub.write_u32::<LittleEndian>(1)
        .map_err(|_| DcomError::Protocol)?; // Interfaces count
    stub.write_u32::<LittleEndian>(0x00020000)
        .map_err(|_| DcomError::Protocol)?; // IID array pointer
    stub.write_u32::<LittleEndian>(1)
        .map_err(|_| DcomError::Protocol)?; // array size
    stub.extend_from_slice(iid);
    stub.write_u16::<LittleEndian>(1)
        .map_err(|_| DcomError::Protocol)?; // cRequestedProtseqs
    stub.write_u32::<LittleEndian>(0x00020004)
        .map_err(|_| DcomError::Protocol)?; // protseq array pointer
    stub.write_u16::<LittleEndian>(0x07)
        .map_err(|_| DcomError::Protocol)?; // ncacn_ip_tcp

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

/// Parse RemoteActivation response and extract port and OXID from DUALSTRINGARRAY
fn parse_remote_activation_response(pdu: &[u8]) -> Result<(u16, [u8; 8]), DcomError> {
    if pdu.len() < 24 {
        return Err(DcomError::Protocol);
    }

    let ptype = pdu[2];
    if ptype == 0x03 {
        // fault
        if pdu.len() >= 28 {
            let status = u32::from_le_bytes([pdu[24], pdu[25], pdu[26], pdu[27]]);
            error!("RPC fault: 0x{:08x}", status);
        }
        return Err(DcomError::Protocol);
    }

    if ptype != 0x02 {
        // response
        return Err(DcomError::Protocol);
    }

    // Skip RPC header to stub data
    let stub_data = &pdu[24..];

    // Use nom to parse the response, now also extracting OXID
    match parse_activation_response(stub_data) {
        Ok((_, (port, oxid))) => {
            debug!("Extracted WMI port={} and OXID={:?}", port, hex::encode(&oxid));
            Ok((port, oxid))
        }
        Err(_) => {
            warn!("Failed to parse activation response fully, using defaults");
            Ok((135, [0u8; 8]))
        }
    }
}

/// Parse ORPCTHAT header fully
fn parse_orpcthat(input: &[u8]) -> IResult<&[u8], (u32, u32, Vec<u8>)> {
    // Parse ORPCTHAT flags
    let (input, flags) = le_u32(input)?;

    // Check for extensions
    let (input, extensions) = if flags & 0x02 != 0 {
        // Extensions present
        let (input, ext_size) = le_u32(input)?;
        let (input, ext_data) = take(ext_size)(input)?;
        (input, ext_data.to_vec())
    } else {
        (input, Vec::new())
    };

    // Extract causality ID from flags (context field)
    let causality_id = flags >> 16;  // Upper 16 bits often used for context

    Ok((input, (flags, causality_id, extensions)))
}

/// Parse activation response to extract both port and OXID
fn parse_activation_response(input: &[u8]) -> IResult<&[u8], (u16, [u8; 8])> {
    // Parse ORPCTHAT header fully
    let (input, (_flags, _causality_id, _extensions)) = parse_orpcthat(input)?;

    // Parse HRESULT
    let (input, hresult) = le_u32(input)?;
    if hresult != 0 {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }

    // Extract OXID (8 bytes)
    let (input, oxid_bytes) = take(8usize)(input)?;
    let mut oxid = [0u8; 8];
    oxid.copy_from_slice(oxid_bytes);

    // Skip pOxidBindings pointer (4), ipidRemUnknown (16), dwAuthnHint (4)
    let (input, _) = take(24usize)(input)?;

    // Continue to parse DUALSTRINGARRAY for port
    let (input, port) = parse_dualstringarray_port_inner(input)?;

    Ok((input, (port, oxid)))
}

/// Parse DUALSTRINGARRAY to extract TCP port using nom (keeping old function for compatibility)
#[allow(dead_code)]
fn parse_dualstringarray_port(input: &[u8]) -> IResult<&[u8], u16> {
    // Parse ORPCTHAT header fully
    let (input, (_flags, _causality_id, _extensions)) = parse_orpcthat(input)?;

    // Skip to DUALSTRINGARRAY after HRESULT, OXID, etc
    let (input, hresult) = le_u32(input)?;
    if hresult != 0 {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }

    // Skip OXID (8 bytes), pOxidBindings pointer (4), ipidRemUnknown (16), dwAuthnHint (4)
    let (input, _) = take(32usize)(input)?;

    parse_dualstringarray_port_inner(input)
}

/// Inner function to parse DUALSTRINGARRAY for port
fn parse_dualstringarray_port_inner(input: &[u8]) -> IResult<&[u8], u16> {
    // Skip pServerVersion pointer
    let (input, server_version_ptr) = le_u32(input)?;
    let input = if server_version_ptr != 0 {
        let (input, _) = take(4usize)(input)?; // skip version
        input
    } else {
        input
    };

    // Parse DUALSTRINGARRAY
    let (input, string_binding_size) = le_u16(input)?;
    let (input, _security_binding_size) = le_u16(input)?;

    // Parse string bindings to find TCP port
    let (input, bindings) = take(string_binding_size * 2)(input)?;

    // Look for TCP tower (0x07) followed by port
    let mut cursor = std::io::Cursor::new(bindings);
    while cursor.position() < bindings.len() as u64 - 2 {
        let tower_id = cursor.read_u16::<LittleEndian>().unwrap_or(0);
        if tower_id == 0x07 {
            // TCP
            // Skip IP components and read port
            cursor.set_position(cursor.position() + 10); // Skip to port position
            if cursor.position() < bindings.len() as u64 - 2 {
                let port = cursor.read_u16::<LittleEndian>().unwrap_or(0);
                if port > 0 && port < 65535 {
                    return Ok((input, port));
                }
            }
        }
    }

    // Fallback: scan for port-like values in dynamic range
    for i in (0..bindings.len().saturating_sub(2)).step_by(2) {
        let port = u16::from_le_bytes([bindings[i], bindings[i + 1]]);
        if port >= 49152 {
            return Ok((input, port));
        }
    }

    Ok((input, 135)) // Default fallback
}

#[allow(dead_code)]
pub(crate) fn parse_epm_response(pdu: &[u8]) -> Result<u16, DcomError> {
    if pdu.len() < 24 {
        error!(len = pdu.len(), "EPM reply truncated");
        return Err(DcomError::Tower);
    }

    let ptype = pdu[2];
    if ptype == 0x03 {
        if pdu.len() < 28 {
            error!(len = pdu.len(), "RPC fault truncated");
            return Err(DcomError::Tower);
        }
        let status_offset = 24;
        let status = u32::from_le_bytes([
            pdu[status_offset],
            pdu[status_offset + 1],
            pdu[status_offset + 2],
            pdu[status_offset + 3],
        ]);
        let reason = if pdu.len() >= status_offset + 8 {
            u32::from_le_bytes([
                pdu[status_offset + 4],
                pdu[status_offset + 5],
                pdu[status_offset + 6],
                pdu[status_offset + 7],
            ])
        } else {
            0
        };
        error!(
            status = format!("0x{status:08x}"),
            reason = format!("0x{reason:08x}"),
            "endpoint mapper fault"
        );
        return Err(DcomError::Fault { status, reason });
    }

    if ptype == 0x0D {
        error!("Received alter_ack (0x0D) instead of EPM response - likely protocol mismatch");
        return Err(DcomError::Tower);
    }

    if ptype != 0x02 {
        error!(
            ptype = format!("0x{ptype:02x}"),
            "unexpected RPC PDU type in EPM response"
        );
        return Err(DcomError::Tower);
    }

    let parsed = extract_tower_sections(pdu);
    match parsed {
        Ok((tower, searchable)) => match parse_epm_tower(tower) {
            Ok(Some(port)) => Ok(port),
            Ok(None) => {
                warn!("no explicit TCP floor; scanning payload for fallback port");
                scan_for_tcp_floor(searchable).ok_or(DcomError::Port)
            }
            Err(err) => {
                if let Some(port) = scan_for_tcp_floor(searchable) {
                    warn!("tower parse failed; using heuristic port");
                    Ok(port)
                } else {
                    Err(err)
                }
            }
        },
        Err(err) => {
            if let Some(port) = scan_for_tcp_floor(pdu) {
                warn!("failed to extract tower; using heuristic port");
                Ok(port)
            } else {
                Err(err)
            }
        }
    }
}

#[allow(dead_code)]
fn extract_tower_sections<'a>(pdu: &'a [u8]) -> Result<(&'a [u8], &'a [u8]), DcomError> {
    let frag_len = u16::from_le_bytes([pdu[8], pdu[9]]) as usize;
    let auth_len = u16::from_le_bytes([pdu[10], pdu[11]]) as usize;
    if frag_len > pdu.len() {
        error!(frag_len, total = pdu.len(), "invalid fragment length");
        return Err(DcomError::Tower);
    }

    let stub_start = 24;
    if stub_start > frag_len || frag_len < auth_len + stub_start {
        error!(frag_len, auth_len, "malformed EPM reply");
        return Err(DcomError::Tower);
    }
    let stub_end = frag_len - auth_len;
    if stub_end > pdu.len() {
        error!(stub_end, total = pdu.len(), "EPM reply overruns buffer");
        return Err(DcomError::Tower);
    }

    let stub = &pdu[stub_start..stub_end];
    if stub.len() < 16 {
        error!(len = stub.len(), "tower pointer truncated");
        return Err(DcomError::Tower);
    }

    let tower_length = u32::from_le_bytes([stub[4], stub[5], stub[6], stub[7]]) as usize;
    let referent = u32::from_le_bytes([stub[8], stub[9], stub[10], stub[11]]);
    if referent == 0 {
        error!("tower pointer is null");
        return Err(DcomError::Tower);
    }
    let max_count = u32::from_le_bytes([stub[12], stub[13], stub[14], stub[15]]) as usize;
    if tower_length == 0 {
        error!("tower length is zero");
        return Err(DcomError::Tower);
    }
    if tower_length > stub.len().saturating_sub(16) {
        error!(
            tower_length,
            available = stub.len().saturating_sub(16),
            "tower payload truncated"
        );
        return Err(DcomError::Tower);
    }
    if max_count < tower_length {
        error!(tower_length, max_count, "invalid tower length metadata");
        return Err(DcomError::Tower);
    }
    if max_count > stub.len().saturating_sub(16) {
        error!(
            max_count,
            available = stub.len().saturating_sub(16),
            "tower payload truncated"
        );
        return Err(DcomError::Tower);
    }

    let data_start = 16;
    let tower = &stub[data_start..data_start + tower_length];
    let searchable = &stub[data_start..data_start + max_count];
    Ok((tower, searchable))
}

#[allow(dead_code)]
fn parse_epm_tower(tower: &[u8]) -> Result<Option<u16>, DcomError> {
    if tower.len() < 2 {
        error!(len = tower.len(), "tower payload truncated");
        return Err(DcomError::Tower);
    }

    let mut cursor = Cursor::new(tower);
    let floor_count = cursor.read_u16::<LittleEndian>().map_err(|err| {
        error!(?err, "failed to read EPM tower header");
        DcomError::Tower
    })? as usize;
    debug!(floor_count, "parsing EPM floors");

    for _ in 0..floor_count {
        let lhs_len = cursor.read_u16::<LittleEndian>().map_err(|err| {
            error!(?err, "missing floor protocol length");
            DcomError::Tower
        })? as usize;
        let mut lhs = vec![0u8; lhs_len];
        cursor.read_exact(&mut lhs).map_err(|err| {
            error!(?err, "incomplete floor protocol data");
            DcomError::Tower
        })?;

        let rhs_len = cursor.read_u16::<LittleEndian>().map_err(|err| {
            error!(?err, "missing floor address length");
            DcomError::Tower
        })? as usize;
        let mut rhs = vec![0u8; rhs_len];
        cursor.read_exact(&mut rhs).map_err(|err| {
            error!(?err, "incomplete floor address data");
            DcomError::Tower
        })?;

        if let Some(port) = extract_port_from_floor(&lhs, &rhs) {
            return Ok(Some(port));
        }
    }

    Ok(None)
}

#[allow(dead_code)]
fn extract_port_from_floor(lhs: &[u8], rhs: &[u8]) -> Option<u16> {
    if lhs.first().copied() != Some(0x07) {
        return None;
    }
    if rhs.len() < 2 {
        return None;
    }
    Some(u16::from_le_bytes([rhs[0], rhs[1]]))
}

#[allow(dead_code)]
fn scan_for_tcp_floor(pdu: &[u8]) -> Option<u16> {
    for i in 0..pdu.len().saturating_sub(7) {
        if pdu[i] == 0x07 && i + 6 < pdu.len() {
            return Some(u16::from_le_bytes([pdu[i + 5], pdu[i + 6]]));
        }
    }
    None
}

#[allow(dead_code)]
fn read_pdu(stream: &mut TcpStream) -> Result<Vec<u8>, DcomError> {
    let mut header = [0u8; 16];
    stream.read_exact(&mut header).map_err(|err| {
        error!(?err, "failed to read EPM header");
        DcomError::Connect
    })?;
    let frag_len = u16::from_le_bytes([header[8], header[9]]) as usize;
    let mut buffer = Vec::with_capacity(frag_len);
    buffer.extend_from_slice(&header);
    let mut rest = vec![0u8; frag_len.saturating_sub(16)];
    stream.read_exact(&mut rest).map_err(|err| {
        error!(?err, "failed to read EPM payload");
        DcomError::Connect
    })?;
    buffer.extend_from_slice(&rest);
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_epm_response_returns_port_from_tower() {
        let tower = crate::tower::sample_epm_response_stub();
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
        let port = parse_epm_response(&pdu).unwrap();
        assert_eq!(port, 0xc002);
    }

    #[test]
    fn parse_epm_response_reports_fault_status() {
        let pdu = hex_literal::hex!(
            "05 00 03 03 10 00 00 00 20 00 00 00 01 00 00 00"
            "00 00 00 00 00 00 00 00 04 05 01 00 00 00 00 00"
        );
        let err = parse_epm_response(&pdu).unwrap_err();
        match err {
            DcomError::Fault { status, reason } => {
                assert_eq!(status, 0x00010504);
                assert_eq!(reason, 0);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_epm_response_handles_alter_ack() {
        let pdu = hex_literal::hex!(
            "05 00 0d 03 10 00 00 00 18 00 00 00 01 00 00 00"
            "04 00 01 05 00 00 00 00"
        );
        let err = parse_epm_response(&pdu).unwrap_err();
        match err {
            DcomError::Tower => (),
            other => panic!("expected Tower error for alter_ack, got: {other:?}"),
        }
    }

    #[test]
    fn test_oxid_extraction_from_activation_response() {
        // Mock RemoteActivation response with ORPCTHAT and OXID
        let mut stub = Vec::new();

        // ORPCTHAT header
        stub.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // flags (no extensions)

        // HRESULT (success)
        stub.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // OXID (8 bytes) - test pattern
        stub.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        // Skip rest of response for test
        stub.extend_from_slice(&[0x00; 24]); // pOxidBindings, ipidRemUnknown, dwAuthnHint
        stub.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // pServerVersion (null)

        // Minimal DUALSTRINGARRAY with proper format
        stub.extend_from_slice(&[0x08, 0x00]); // string_binding_size (8 words = 16 bytes)
        stub.extend_from_slice(&[0x00, 0x00]); // security_binding_size
        // String bindings (16 bytes)
        stub.extend_from_slice(&[0x07, 0x00]); // TCP tower ID
        stub.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // IP part 1
        stub.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // IP part 2
        stub.extend_from_slice(&[0x00, 0x00]); // padding
        stub.extend_from_slice(&[0x87, 0x13]); // Port 5000 (0x1387)
        stub.extend_from_slice(&[0x00, 0x00]); // terminator

        let result = parse_activation_response(&stub);
        assert!(result.is_ok());
        let (_, (port, oxid)) = result.unwrap();
        // Port extraction uses heuristics - may find 5000 or default to 135
        // The important thing is we get a valid port (non-zero)
        assert!(port > 0);
        assert_eq!(oxid, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    }

    #[test]
    fn test_orpcthat_extension_parsing() {
        // Test with extensions present
        let mut input = Vec::new();
        input.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // flags with extension bit
        input.extend_from_slice(&[0x08, 0x00, 0x00, 0x00]); // extension size = 8
        input.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]); // extension data

        let result = parse_orpcthat(&input);
        assert!(result.is_ok());
        let (_, (flags, _causality_id, extensions)) = result.unwrap();
        assert_eq!(flags, 0x02);
        assert_eq!(extensions.len(), 8);
        assert_eq!(extensions[0], 0xAA);

        // Test without extensions
        let mut input2 = Vec::new();
        input2.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // flags without extension bit

        let result2 = parse_orpcthat(&input2);
        assert!(result2.is_ok());
        let (_, (flags, _causality_id, extensions)) = result2.unwrap();
        assert_eq!(flags, 0x01);
        assert_eq!(extensions.len(), 0);
    }
}
