//! DCOM activation (MS-DCOM 3.1.2.5.1): ask the server's object exporter on
//! port 135 to create a WMI login object and say where to reach it.

use std::io::{Cursor, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use thiserror::Error;
use tracing::{debug, error, info, instrument, warn};

use crate::auth::{AuthError, AuthProvider, Credentials};
use crate::rpc::{
    build_bind_pdu, build_sealed_request_pdu, fault_to_hresult, parse_bind_ack, read_pdu,
    unseal_response_pdu, RpcError, AUTH_LEVEL_PKT_PRIVACY, PTYPE_ALTER_CONTEXT,
    PTYPE_ALTER_CONTEXT_RESP, PTYPE_BIND, PTYPE_BIND_ACK, RPC_IO_TIMEOUT,
};
use crate::sspi_ntlm::SspiNtlmClient;

#[derive(Error, Debug)]
pub enum DcomError {
    #[error("cannot connect to the RPC endpoint mapper (port 135): {0}")]
    Connect(std::io::Error),
    #[error(transparent)]
    Rpc(#[from] RpcError),
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error("malformed activation response")]
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

impl From<std::io::Error> for DcomError {
    fn from(err: std::io::Error) -> Self {
        DcomError::Rpc(RpcError::Io(err))
    }
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

/// An RPC fault from the activation exchange, as a `DcomError`. Bad
/// credentials surface this way: Windows faults the authenticating
/// alter_context with status 5 (access denied).
fn rpc_to_err(err: RpcError) -> DcomError {
    match err {
        RpcError::Fault(status) => hresult_to_err(fault_to_hresult(status)),
        other => DcomError::Rpc(other),
    }
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// IActivation {4d9f4ab8-7d1c-11cf-861e-0020af6e7c57}; RemoteActivation is opnum 0.
const IID_IACTIVATION: [u8; 16] = hex_literal::hex!("b84a9f4d1c7dcf11861e0020af6e7c57");
const CLSID_WBEM_LEVEL1_LOGIN: [u8; 16] = hex_literal::hex!("5ef0c38b6bd8d011a07500c04fb68820");
const IID_IWBEM_LEVEL1_LOGIN: [u8; 16] = hex_literal::hex!("18ad09f36ad8d011a07500c04fb68820");

/// Activate CLSID_WbemLevel1Login on `host` with NTLM and return the WMI
/// port together with the activation result (OXID, IPIDs, reference counts).
pub(crate) fn activate_level1_login(
    host: &str,
    creds: &Credentials,
) -> Result<(u16, ActivationResponse), DcomError> {
    activate_with(host, SspiNtlmClient::new(creds, &format!("host/{host}"))?)
}

/// Run IActivation::RemoteActivation (MS-DCOM 3.1.2.5.1.1) over a connection
/// authenticated by `auth` at packet privacy, as Windows requires for DCOM
/// activation.
#[instrument(level = "debug", skip_all, fields(host))]
fn activate_with(
    host: &str,
    mut auth: impl AuthProvider,
) -> Result<(u16, ActivationResponse), DcomError> {
    let addr = (host, 135)
        .to_socket_addrs()
        .map_err(DcomError::Connect)?
        .next()
        .ok_or_else(|| {
            DcomError::Connect(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{host} resolved to no addresses"),
            ))
        })?;
    let mut stream =
        TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).map_err(DcomError::Connect)?;
    stream.set_read_timeout(Some(RPC_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(RPC_IO_TIMEOUT))?;

    // NTLM: NEGOTIATE in the bind, CHALLENGE in the bind_ack, AUTHENTICATE in
    // an alter_context of the same presentation context.
    let negotiate = auth.negotiate()?;
    stream.write_all(&build_bind_pdu(
        PTYPE_BIND,
        1,
        0,
        &IID_IACTIVATION,
        AUTH_LEVEL_PKT_PRIVACY,
        0,
        &negotiate,
    ))?;
    let ack = parse_bind_ack(&read_pdu(&mut stream)?, PTYPE_BIND_ACK).map_err(rpc_to_err)?;
    let authenticate = auth.respond(&ack.auth_token)?;
    stream.write_all(&build_bind_pdu(
        PTYPE_ALTER_CONTEXT,
        2,
        0,
        &IID_IACTIVATION,
        AUTH_LEVEL_PKT_PRIVACY,
        0,
        &authenticate,
    ))?;
    parse_bind_ack(&read_pdu(&mut stream)?, PTYPE_ALTER_CONTEXT_RESP).map_err(rpc_to_err)?;
    debug!("activation security context established");

    let stub = build_remote_activation_stub(&CLSID_WBEM_LEVEL1_LOGIN, &IID_IWBEM_LEVEL1_LOGIN)?;
    stream.write_all(&build_sealed_request_pdu(&mut auth, 3, 0, 0, &stub, 0)?)?;
    let resp = unseal_response_pdu(&mut auth, &read_pdu(&mut stream)?).map_err(rpc_to_err)?;
    let activation = parse_remote_activation_response(&resp, Some(&IID_IWBEM_LEVEL1_LOGIN))?;
    let port = activation.port().ok_or_else(|| {
        warn!("RemoteActivation response advertised no TCP binding");
        DcomError::Protocol
    })?;
    info!(
        port,
        oxid = %hex::encode(activation.oxid),
        ipid = %hex::encode(activation.ipid),
        "DCOM activation succeeded"
    );
    Ok((port, activation))
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

/// IActivation::RemoteActivation output (MS-DCOM 3.1.2.5.1.1).
#[derive(Debug, Clone)]
pub(crate) struct ActivationResponse {
    pub oxid: [u8; 8],
    /// IPID of the activated interface, read from the returned OBJREF_STANDARD.
    pub ipid: [u8; 16],
    /// Public references the OBJREF granted on `ipid` (to RemRelease later).
    pub public_refs: u32,
    /// IPID of the OXID's IRemUnknown, used to release references.
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
    let (ipid, public_refs) = find_objref_ipid(stub, c.position() as usize, &oxid, expected_iid)?;

    debug!(
        oxid = %hex::encode(oxid),
        ipid = %hex::encode(ipid),
        ?tcp_bindings,
        "parsed RemoteActivation response"
    );
    Ok(ActivationResponse {
        oxid,
        ipid,
        public_refs,
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
) -> Result<([u8; 16], u32), DcomError> {
    // OBJREF layout: signature(4) flags(4) iid(16) then STDOBJREF
    // { flags(4) cPublicRefs(4) oxid(8) oid(8) ipid(16) }.
    const FLAGS_OFFSET: usize = 4;
    const IID_OFFSET: usize = 8;
    const PUBLIC_REFS_OFFSET: usize = 4 + 4 + 16 + 4; // 28
    const OXID_OFFSET: usize = PUBLIC_REFS_OFFSET + 4; // 32
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
    let public_refs = u32::from_le_bytes(
        objref[PUBLIC_REFS_OFFSET..PUBLIC_REFS_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    Ok((ipid, public_refs))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Byte offset of phr within WINDOWS_ACTIVATION_STUB (after the string array).
    const PHR_OFFSET: usize = 388;

    #[test]
    fn parse_activation_stub_matches_windows_response() {
        let r =
            parse_activation_stub(WINDOWS_ACTIVATION_STUB, Some(&IID_IWBEM_LEVEL1_LOGIN)).unwrap();
        assert_eq!(hex::encode(r.oxid), "889959be75b91cd7");
        assert_eq!(hex::encode(r.ipid), "1a7c0000e8090000b541859917e7b564");
        assert_eq!(r.public_refs, 5);
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
        let r = parse_remote_activation_response(&pdu, Some(&IID_IWBEM_LEVEL1_LOGIN)).unwrap();
        assert_eq!(r.port(), Some(24158));
        assert_eq!(hex::encode(r.ipid), "1a7c0000e8090000b541859917e7b564");
        assert_eq!(r.public_refs, 5);
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
    fn rpc_faults_map_to_dcom_errors() {
        // Status 5 is what Windows sends for an alter_context with bad credentials.
        assert!(matches!(
            rpc_to_err(RpcError::Fault(5)),
            DcomError::AccessDenied
        ));
        assert!(matches!(
            rpc_to_err(RpcError::Fault(0x1c01_0002)),
            DcomError::AccessDenied
        ));
        assert!(matches!(
            rpc_to_err(RpcError::Fault(0x6ba)),
            DcomError::ServerUnavailable
        ));
        assert!(matches!(
            rpc_to_err(RpcError::Fault(0x8004_1003)),
            DcomError::Hresult { hr: 0x8004_1003 }
        ));
        assert!(matches!(
            rpc_to_err(RpcError::Protocol("x".into())),
            DcomError::Rpc(RpcError::Protocol(_))
        ));
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
}
