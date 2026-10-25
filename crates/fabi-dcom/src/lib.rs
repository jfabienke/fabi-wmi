//! MS-DCOM wire marshaling (`ORPCTHIS`/`ORPCTHAT`, `OBJREF`, `STDOBJREF`,
//! `MInterfacePointer`, `DUALSTRINGARRAY`), `IActivation::RemoteActivation`,
//! `IObjectExporter::ResolveOxid`, and `IRemUnknown::RemRelease`.

use std::io::{Cursor, Read};
use std::time::Duration;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use thiserror::Error;
use tracing::{debug, error, info, instrument, warn};

use fabi_dcerpc::{
    fault_to_hresult, AuthError, AuthProvider, Credentials, HandshakeStyle, RpcConnection,
    RpcError, SspiNtlmClient, AUTH_LEVEL_PKT_PRIVACY, RPC_IO_TIMEOUT,
};

#[derive(Error, Debug)]
pub enum DcomError {
    #[error("cannot connect to the RPC endpoint mapper (port 135): {0}")]
    Connect(std::io::Error),
    #[error(transparent)]
    Rpc(#[from] RpcError),
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error("malformed DCOM response")]
    Protocol,
    #[error("response returned an unexpected interface")]
    WrongInterface,
    #[error("unexpected custom marshaler CLSID")]
    UnexpectedClsid,
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
pub fn hresult_to_err(hr: u32) -> DcomError {
    match hr {
        0x8007_0005 => DcomError::AccessDenied,
        0x8007_06BA => DcomError::ServerUnavailable,
        0x8007_06BE => DcomError::RemoteProcedureCallFailed,
        other => DcomError::Hresult { hr: other },
    }
}

/// An RPC fault from the activation/exporter exchange, as a `DcomError`. Bad
/// credentials surface this way: Windows faults the authenticating
/// alter_context with status 5 (access denied).
pub fn rpc_to_err(err: RpcError) -> DcomError {
    match err {
        RpcError::Fault(status) => hresult_to_err(fault_to_hresult(status)),
        other => DcomError::Rpc(other),
    }
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// IActivation {4d9f4ab8-7d1c-11cf-861e-0020af6e7c57}; RemoteActivation is opnum 0.
pub const IID_IACTIVATION: [u8; 16] = hex_literal::hex!("b84a9f4d1c7dcf11861e0020af6e7c57");
/// IObjectExporter {99fcfec4-5260-101b-bbcb-00aa0021347a}; ResolveOxid is opnum 0.
pub const IID_IOBJECT_EXPORTER: [u8; 16] = hex_literal::hex!("c4fe9f9960521b10bbcb00aa0021347a");
/// IID of IRemUnknown, the OXID object used to release references.
pub const IID_IREMUNKNOWN: [u8; 16] = hex_literal::hex!("3101000000000000c000000000000046");
/// IRemUnknown::RemRelease opnum.
pub const OPNUM_REM_RELEASE: u16 = 5;

/// COMVERSION used by current Windows: 5.7.
pub const COMVERSION: [u8; 4] = [5, 0, 7, 0];

/// Encode an ORPCTHIS header (MS-DCOM 2.2.13.1): COMVERSION, flags, reserved,
/// causality id, and a null extensions pointer. 32 bytes.
pub fn encode_orpcthis(buf: &mut Vec<u8>, causality_id: &[u8; 16]) {
    buf.extend_from_slice(&COMVERSION);
    buf.write_u32::<LittleEndian>(0).unwrap(); // flags
    buf.write_u32::<LittleEndian>(0).unwrap(); // reserved1
    buf.extend_from_slice(causality_id); // cid
    buf.write_u32::<LittleEndian>(0).unwrap(); // extensions: null
}

fn align4(buf: &mut Vec<u8>, fill: u8) {
    while !buf.len().is_multiple_of(4) {
        buf.push(fill);
    }
}

/// An interface pointer returned by the server: the IPID to address calls to
/// and the public references held on it (released with RemRelease).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceRef {
    pub ipid: [u8; 16],
    pub public_refs: u32,
}

/// Encode the IRemUnknown::RemRelease (opnum 5) request stub (MS-DCOM
/// 3.1.1.5.6.1.3): ORPCTHIS, cInterfaceRefs, then a conformant array of
/// REMINTERFACEREF { ipid, cPublicRefs, cPrivateRefs }.
pub fn encode_rem_release(causality_id: &[u8; 16], refs: &[InterfaceRef]) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_orpcthis(&mut buf, causality_id);
    buf.write_u16::<LittleEndian>(refs.len() as u16).unwrap();
    align4(&mut buf, 0);
    buf.write_u32::<LittleEndian>(refs.len() as u32).unwrap(); // max_count
    for r in refs {
        buf.extend_from_slice(&r.ipid);
        buf.write_u32::<LittleEndian>(r.public_refs).unwrap();
        buf.write_u32::<LittleEndian>(0).unwrap(); // cPrivateRefs
    }
    buf
}

/// Check a RemRelease response stub (ORPCTHAT, HRESULT).
pub fn parse_rem_release_response(stub: &[u8]) -> Result<(), DcomError> {
    let hr = stub
        .len()
        .checked_sub(4)
        .filter(|&o| o >= 8)
        .map(|o| u32::from_le_bytes(stub[o..o + 4].try_into().unwrap()))
        .ok_or(DcomError::Protocol)?;
    if hr != 0 {
        return Err(hresult_to_err(hr));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Consolidated OBJREF / STDOBJREF / MInterfacePointer / DUALSTRINGARRAY
// ---------------------------------------------------------------------------

pub const OBJREF_SIGNATURE: &[u8; 4] = b"MEOW";
pub const OBJREF_STANDARD: u32 = 0x1;
pub const OBJREF_CUSTOM: u32 = 0x4;

/// Standard object reference body (`STDOBJREF`, MS-DCOM 2.2.18.1, 40 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StdObjRef {
    pub flags: u32,
    pub public_refs: u32,
    pub oxid: [u8; 8],
    pub oid: [u8; 8],
    pub ipid: [u8; 16],
}

impl StdObjRef {
    pub fn as_interface_ref(&self) -> InterfaceRef {
        InterfaceRef {
            ipid: self.ipid,
            public_refs: self.public_refs,
        }
    }
}

/// A parsed `OBJREF` (MS-DCOM 2.2.18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjRef<'a> {
    Standard {
        iid: [u8; 16],
        std: StdObjRef,
    },
    Custom {
        iid: [u8; 16],
        clsid: [u8; 16],
        data: &'a [u8],
    },
}

fn rd_u32(b: &[u8], off: usize) -> Result<u32, DcomError> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .ok_or(DcomError::Protocol)
}

impl<'a> ObjRef<'a> {
    /// Parse an `OBJREF` starting at offset 0 of `objref` (`"MEOW"` signature).
    pub fn parse(objref: &'a [u8]) -> Result<Self, DcomError> {
        if objref.get(0..4) != Some(OBJREF_SIGNATURE) {
            return Err(DcomError::Protocol);
        }
        let flags = rd_u32(objref, 4)?;
        let iid: [u8; 16] = objref
            .get(8..24)
            .ok_or(DcomError::Protocol)?
            .try_into()
            .unwrap();
        match flags {
            OBJREF_STANDARD => {
                // signature(4) + flags(4) + iid(16) + STDOBJREF(40) = 64 bytes
                if objref.len() < 64 {
                    return Err(DcomError::Protocol);
                }
                let std = StdObjRef {
                    flags: rd_u32(objref, 24)?,
                    public_refs: rd_u32(objref, 28)?,
                    oxid: objref[32..40].try_into().unwrap(),
                    oid: objref[40..48].try_into().unwrap(),
                    ipid: objref[48..64].try_into().unwrap(),
                };
                Ok(ObjRef::Standard { iid, std })
            }
            OBJREF_CUSTOM => {
                // signature(4) + flags(4) + iid(16) + clsid(16) + cbExtension(4) + size(4) + pData[size]
                if objref.len() < 48 {
                    return Err(DcomError::Protocol);
                }
                let clsid: [u8; 16] = objref[24..40].try_into().unwrap();
                let size = rd_u32(objref, 44)? as usize;
                let data = objref.get(48..48 + size).ok_or(DcomError::Protocol)?;
                Ok(ObjRef::Custom { iid, clsid, data })
            }
            _ => {
                warn!("unsupported OBJREF flags 0x{flags:08x}");
                Err(DcomError::Protocol)
            }
        }
    }
}

/// Parse an NDR `MInterfacePointer` (`{ max_count, ulCntData, abData }`,
/// MS-DCOM 2.2.16) at `off` in `buf`, returning the parsed [`ObjRef`] and the
/// unaligned end offset (`off + 8 + ulCntData`).
pub fn parse_m_interface_pointer(buf: &[u8], off: usize) -> Result<(ObjRef<'_>, usize), DcomError> {
    let max_count = rd_u32(buf, off)? as usize;
    let cnt = rd_u32(buf, off + 4)? as usize;
    if max_count != cnt {
        return Err(DcomError::Protocol);
    }
    let end = off
        .checked_add(8)
        .and_then(|s| s.checked_add(cnt))
        .filter(|&e| e <= buf.len())
        .ok_or(DcomError::Protocol)?;
    let objref = ObjRef::parse(&buf[off + 8..end])?;
    Ok((objref, end))
}

/// Append an NDR `MInterfacePointer` wrapping an `OBJREF_CUSTOM` (`iid`,
/// `clsid`, and `data`) to `buf` (MS-DCOM 2.2.14 / 2.2.18.6).
pub fn encode_custom_m_interface_pointer(
    buf: &mut Vec<u8>,
    iid: &[u8; 16],
    clsid: &[u8; 16],
    data: &[u8],
) {
    let objref_len = (48 + data.len()) as u32;
    buf.write_u32::<LittleEndian>(objref_len).unwrap(); // max_count
    buf.write_u32::<LittleEndian>(objref_len).unwrap(); // ulCntData
    buf.extend_from_slice(OBJREF_SIGNATURE);
    buf.write_u32::<LittleEndian>(OBJREF_CUSTOM).unwrap();
    buf.extend_from_slice(iid);
    buf.extend_from_slice(clsid);
    buf.write_u32::<LittleEndian>(0).unwrap(); // cbExtension
    buf.write_u32::<LittleEndian>(data.len() as u32).unwrap(); // size
    buf.extend_from_slice(data);
}

/// Locate an `OBJREF_STANDARD` wrapped in an `MInterfacePointer` at or after
/// `scan_from` in `stub`, validate `expected_iid` (and `expected_oxid` when
/// given), and return its [`StdObjRef`].
pub fn find_std_objref(
    stub: &[u8],
    scan_from: usize,
    expected_oxid: Option<&[u8; 8]>,
    expected_iid: Option<&[u8; 16]>,
    require_wrapper_bounds: bool,
) -> Result<StdObjRef, DcomError> {
    let region = stub.get(scan_from..).ok_or(DcomError::Protocol)?;
    let meow = scan_from
        + region
            .windows(4)
            .position(|w| w == OBJREF_SIGNATURE)
            .ok_or(DcomError::Protocol)?;
    if require_wrapper_bounds {
        if meow < 8 {
            return Err(DcomError::Protocol);
        }
        let max_count = rd_u32(stub, meow - 8)? as usize;
        let cnt_data = rd_u32(stub, meow - 4)? as usize;
        if max_count != cnt_data || cnt_data < 64 || meow + cnt_data > stub.len() {
            return Err(DcomError::Protocol);
        }
    }
    match ObjRef::parse(stub.get(meow..).ok_or(DcomError::Protocol)?)? {
        ObjRef::Standard { iid, std } => {
            if let Some(exp_iid) = expected_iid {
                if &iid != exp_iid {
                    return Err(DcomError::WrongInterface);
                }
            }
            if let Some(exp_oxid) = expected_oxid {
                if &std.oxid != exp_oxid {
                    return Err(DcomError::Protocol);
                }
            }
            Ok(std)
        }
        ObjRef::Custom { .. } => Err(DcomError::Protocol),
    }
}

/// Parse an NDR-marshaled `DUALSTRINGARRAY` (`max_count: u32`, `wNumEntries: u16`,
/// `wSecurityOffset: u16`, `aStringArray: [u16; wNumEntries]`, MS-DCOM 2.2.19.1)
/// and return its `(host, port)` TCP string bindings.
pub fn parse_dual_string_array(c: &mut Cursor<&[u8]>) -> Result<Vec<(String, u16)>, DcomError> {
    let rd32 = |c: &mut Cursor<&[u8]>| {
        c.read_u32::<LittleEndian>()
            .map_err(|_| DcomError::Protocol)
    };
    let rd16 = |c: &mut Cursor<&[u8]>| {
        c.read_u16::<LittleEndian>()
            .map_err(|_| DcomError::Protocol)
    };
    let max_count = rd32(c)? as usize;
    let num_entries = rd16(c)? as usize;
    let security_offset = rd16(c)? as usize;
    if max_count != num_entries || security_offset > num_entries {
        return Err(DcomError::Protocol);
    }
    let mut words = Vec::with_capacity(num_entries);
    for _ in 0..num_entries {
        words.push(rd16(c)?);
    }
    Ok(parse_string_bindings(&words[..security_offset]))
}

/// Parse STRINGBINDING entries (MS-DCOM 2.2.19.3): each is a u16 tower id
/// followed by a NUL-terminated UTF-16LE address; a lone 0x0000 ends the list.
pub fn parse_string_bindings(words: &[u16]) -> Vec<(String, u16)> {
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
pub fn split_host_port(addr: &str) -> Option<(String, u16)> {
    let (host, rest) = addr.split_once('[')?;
    let port = rest.strip_suffix(']')?.parse::<u16>().ok()?;
    (port > 0).then(|| (host.to_string(), port))
}

// ---------------------------------------------------------------------------
// IActivation::RemoteActivation (generalized to any CLSID / IID)
// ---------------------------------------------------------------------------

/// Activate `clsid` requesting interface `iid` on `host` with NTLM at packet
/// privacy, returning the object exporter's TCP port and [`ActivationResponse`].
pub fn activate(
    host: &str,
    creds: &Credentials,
    clsid: &[u8; 16],
    iid: &[u8; 16],
) -> Result<(u16, ActivationResponse), DcomError> {
    activate_with(
        host,
        clsid,
        iid,
        SspiNtlmClient::new(creds, &format!("host/{host}"))?,
    )
}

/// Run `IActivation::RemoteActivation` (MS-DCOM 3.1.2.5.1.1) for `clsid` and
/// `iid` over a connection authenticated by `auth` at packet privacy.
pub fn activate_with(
    host: &str,
    clsid: &[u8; 16],
    iid: &[u8; 16],
    auth: impl AuthProvider + 'static,
) -> Result<(u16, ActivationResponse), DcomError> {
    activate_with_level(host, clsid, iid, auth, AUTH_LEVEL_PKT_PRIVACY)
}

/// [`activate_with`] at `auth_level`, e.g. `AUTH_LEVEL_PKT_INTEGRITY` for a
/// security provider that can sign DCE/RPC PDUs but not seal them. Windows'
/// DCOM hardening (KB5004442) requires at least packet integrity.
#[instrument(level = "debug", skip_all, fields(host = %host, auth_level = auth_level))]
pub fn activate_with_level(
    host: &str,
    clsid: &[u8; 16],
    iid: &[u8; 16],
    auth: impl AuthProvider + 'static,
    auth_level: u8,
) -> Result<(u16, ActivationResponse), DcomError> {
    let mut conn = RpcConnection::connect(host, 135, CONNECT_TIMEOUT, RPC_IO_TIMEOUT).map_err(
        |e| match e {
            RpcError::Io(io) => DcomError::Connect(io),
            other => rpc_to_err(other),
        },
    )?;
    let mut ctx = conn
        .bind_context(
            "IActivation",
            &IID_IACTIVATION,
            auth_level,
            HandshakeStyle::AlterContext,
            Box::new(auth),
        )
        .map_err(rpc_to_err)?;
    debug!("activation security context established");

    let stub = build_remote_activation_stub(clsid, iid)?;
    let resp_stub = conn.call(&mut ctx, 0, None, &stub).map_err(rpc_to_err)?;
    let activation = parse_activation_stub(&resp_stub, Some(iid))?;
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

/// Build `IActivation::RemoteActivation` request stub (MS-DCOM 3.1.2.5.1.1), NDR20.
pub fn build_remote_activation_stub(
    clsid: &[u8; 16],
    iid: &[u8; 16],
) -> Result<Vec<u8>, DcomError> {
    const RPC_C_IMP_LEVEL_IMPERSONATE: u32 = 3;
    const PROTSEQ_NCACN_IP_TCP: u16 = 0x0007;
    const UNIQUE_REFERENT: u32 = 0x0002_0000;

    let mut stub = Vec::new();
    encode_orpcthis(&mut stub, uuid::Uuid::new_v4().as_bytes());

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
pub struct ActivationResponse {
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
    /// The dynamic RPC port to connect to (all advertised bindings share one endpoint).
    pub fn port(&self) -> Option<u16> {
        self.tcp_bindings.first().map(|&(_, port)| port)
    }
}

/// Parse the NDR stub of a `RemoteActivation` response.
pub fn parse_activation_stub(
    stub: &[u8],
    expected_iid: Option<&[u8; 16]>,
) -> Result<ActivationResponse, DcomError> {
    let mut c = Cursor::new(stub);
    let rd32 = |c: &mut Cursor<&[u8]>| {
        c.read_u32::<LittleEndian>()
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
    let tcp_bindings = parse_dual_string_array(&mut c)?;

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
    // ORPC calls target.
    let std = find_std_objref(
        stub,
        c.position() as usize,
        Some(&oxid),
        expected_iid,
        false,
    )
    .map_err(|e| match e {
        DcomError::WrongInterface => DcomError::Protocol,
        other => other,
    })?;

    debug!(
        oxid = %hex::encode(oxid),
        ipid = %hex::encode(std.ipid),
        ?tcp_bindings,
        "parsed RemoteActivation response"
    );
    Ok(ActivationResponse {
        oxid,
        ipid: std.ipid,
        public_refs: std.public_refs,
        ipid_rem_unknown,
        tcp_bindings,
    })
}

// ---------------------------------------------------------------------------
// IObjectExporter::ResolveOxid (MS-DCOM 3.1.2.5.1.1)
// ---------------------------------------------------------------------------

/// Output of `IObjectExporter::ResolveOxid`: the TCP string bindings for the
/// object exporter that owns `oxid`, plus its `IRemUnknown` IPID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OxidResolution {
    pub tcp_bindings: Vec<(String, u16)>,
    pub ipid_rem_unknown: [u8; 16],
    pub authn_hint: u32,
}

impl OxidResolution {
    pub fn port(&self) -> Option<u16> {
        self.tcp_bindings.first().map(|&(_, port)| port)
    }
}

/// Resolve `oxid` via `IObjectExporter::ResolveOxid` (opnum 0) on port 135
/// using NTLM at packet privacy.
pub fn resolve_oxid(
    host: &str,
    creds: &Credentials,
    oxid: &[u8; 8],
) -> Result<OxidResolution, DcomError> {
    resolve_oxid_with(
        host,
        oxid,
        SspiNtlmClient::new(creds, &format!("host/{host}"))?,
    )
}

/// Resolve `oxid` via `IObjectExporter::ResolveOxid` (opnum 0) on port 135
/// using `auth` at packet privacy.
#[instrument(level = "debug", skip_all, fields(host, oxid = %hex::encode(oxid)))]
pub fn resolve_oxid_with(
    host: &str,
    oxid: &[u8; 8],
    auth: impl AuthProvider + 'static,
) -> Result<OxidResolution, DcomError> {
    let mut conn = RpcConnection::connect(host, 135, CONNECT_TIMEOUT, RPC_IO_TIMEOUT).map_err(
        |e| match e {
            RpcError::Io(io) => DcomError::Connect(io),
            other => rpc_to_err(other),
        },
    )?;
    let mut ctx = conn
        .bind_context(
            "IObjectExporter",
            &IID_IOBJECT_EXPORTER,
            AUTH_LEVEL_PKT_PRIVACY,
            HandshakeStyle::AlterContext,
            Box::new(auth),
        )
        .map_err(rpc_to_err)?;
    let stub = build_resolve_oxid_stub(oxid);
    let resp_stub = conn.call(&mut ctx, 0, None, &stub).map_err(rpc_to_err)?;
    parse_resolve_oxid_stub(&resp_stub)
}

/// Build `IObjectExporter::ResolveOxid` (opnum 0) request stub (MS-DCOM
/// 3.1.2.5.1.1): `[in] OXID* pOxid`, `[in] u16 cRequestedProtseqs`,
/// `[in, size_is(cRequestedProtseqs)] u16 arRequestedProtseqs[]`.
/// (`IObjectExporter` is a pure RPC interface, so no `ORPCTHIS` header is sent.)
pub fn build_resolve_oxid_stub(oxid: &[u8; 8]) -> Vec<u8> {
    const PROTSEQ_NCACN_IP_TCP: u16 = 0x0007;
    let mut stub = Vec::with_capacity(18);
    stub.extend_from_slice(oxid); // pOxid (8 bytes)
    stub.write_u16::<LittleEndian>(1).unwrap(); // cRequestedProtseqs = 1
    stub.extend_from_slice(&[0, 0]); // align conformant max_count to 4 bytes
    stub.write_u32::<LittleEndian>(1).unwrap(); // max_count = 1
    stub.write_u16::<LittleEndian>(PROTSEQ_NCACN_IP_TCP)
        .unwrap();
    stub
}

/// Parse `IObjectExporter::ResolveOxid` response stub:
/// `ppdsaOxidBindings` (`DUALSTRINGARRAY*`), `pipidRemUnknown` (`IPID`),
/// `pAuthnHint` (`u32`), and `error_status_t` (`u32`).
pub fn parse_resolve_oxid_stub(stub: &[u8]) -> Result<OxidResolution, DcomError> {
    let ret = stub
        .len()
        .checked_sub(4)
        .and_then(|o| stub.get(o..o + 4))
        .ok_or(DcomError::Protocol)?;
    let ret = u32::from_le_bytes([ret[0], ret[1], ret[2], ret[3]]);
    if ret != 0 {
        return Err(hresult_to_err(ret));
    }

    let mut c = Cursor::new(stub);
    let referent = c
        .read_u32::<LittleEndian>()
        .map_err(|_| DcomError::Protocol)?;
    if referent == 0 {
        return Err(DcomError::Protocol);
    }
    let tcp_bindings = parse_dual_string_array(&mut c)?;
    let pos = c.position() as usize;
    c.set_position(((pos + 3) & !3) as u64);
    let mut ipid_rem_unknown = [0u8; 16];
    c.read_exact(&mut ipid_rem_unknown)
        .map_err(|_| DcomError::Protocol)?;
    let authn_hint = c
        .read_u32::<LittleEndian>()
        .map_err(|_| DcomError::Protocol)?;
    Ok(OxidResolution {
        tcp_bindings,
        ipid_rem_unknown,
        authn_hint,
    })
}

#[cfg(test)]
fn parse_remote_activation_response(
    pdu: &[u8],
    expected_iid: Option<&[u8; 16]>,
) -> Result<ActivationResponse, DcomError> {
    if pdu.len() < 24 || pdu[2] != 0x02 {
        return Err(DcomError::Protocol);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const IID_IWBEM_LEVEL1_LOGIN: [u8; 16] = hex_literal::hex!("18ad09f36ad8d011a07500c04fb68820");

    #[test]
    fn remote_activation_stub_matches_ms_dcom_ndr_layout() {
        let clsid = hex_literal::hex!("5ef0c38b6bd8d011a07500c04fb68820");
        let iid = IID_IWBEM_LEVEL1_LOGIN;
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
        let pdu = authenticated_response_pdu(WINDOWS_ACTIVATION_STUB, 16);
        let r = parse_remote_activation_response(&pdu, Some(&IID_IWBEM_LEVEL1_LOGIN)).unwrap();
        assert_eq!(r.port(), Some(24158));
        assert_eq!(hex::encode(r.ipid), "1a7c0000e8090000b541859917e7b564");
        assert_eq!(r.public_refs, 5);
    }

    #[test]
    fn parse_remote_activation_response_rejects_fault_pdu() {
        let mut pdu = vec![5, 0, 0x03, 0x03, 0x10, 0, 0, 0, 32, 0, 0, 0, 1, 0, 0, 0];
        pdu.extend_from_slice(&[0u8; 8]);
        pdu.extend_from_slice(&0x8007_0005u32.to_le_bytes());
        assert!(parse_remote_activation_response(&pdu, None).is_err());
    }

    #[test]
    fn rpc_faults_map_to_dcom_errors() {
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

    #[test]
    fn resolve_oxid_stub_and_response_round_trip() {
        let oxid = [0x88, 0x99, 0x59, 0xbe, 0x75, 0xb9, 0x1c, 0xd7];
        let req = build_resolve_oxid_stub(&oxid);
        assert_eq!(req.len(), 18);
        assert_eq!(&req[..8], &oxid);
        assert_eq!(&req[8..10], &1u16.to_le_bytes());
        assert_eq!(&req[16..18], &7u16.to_le_bytes());

        // Slice the DUALSTRINGARRAY + ipidRemUnknown + authnHint out of the
        // captured Windows activation response (starts at offset 16: referent +
        // DUALSTRINGARRAY + pad + ipidRemUnknown + authnHint) and append S_OK.
        let mut resp = WINDOWS_ACTIVATION_STUB[16..PHR_OFFSET - 4].to_vec();
        resp.extend_from_slice(&0u32.to_le_bytes());
        let resolved = parse_resolve_oxid_stub(&resp).unwrap();
        assert_eq!(resolved.port(), Some(24158));
        assert_eq!(
            hex::encode(resolved.ipid_rem_unknown),
            "00a40000e809000023bfdc109049aa7d"
        );
    }

    #[test]
    fn custom_m_interface_pointer_round_trips() {
        let iid = [0x11u8; 16];
        let clsid = [0x22u8; 16];
        let payload = b"wmio-encoding-unit";
        let mut buf = Vec::new();
        encode_custom_m_interface_pointer(&mut buf, &iid, &clsid, payload);
        let (parsed, end) = parse_m_interface_pointer(&buf, 0).unwrap();
        assert_eq!(end, buf.len());
        assert_eq!(
            parsed,
            ObjRef::Custom {
                iid,
                clsid,
                data: payload,
            }
        );
    }

    /// Everything here parses stubs a server sent: whatever the bytes, the
    /// parsers must return (Ok or Err), never panic or abort.
    mod properties {
        use super::*;
        use fabi_testkit::{bytes, config, mutated};
        use proptest::prelude::*;

        /// The ResolveOxid reply carried inside the activation response, as in
        /// `resolve_oxid_stub_and_response_round_trip`.
        fn resolve_oxid_reply() -> Vec<u8> {
            let mut resp = WINDOWS_ACTIVATION_STUB[16..PHR_OFFSET - 4].to_vec();
            resp.extend_from_slice(&0u32.to_le_bytes());
            resp
        }

        fn activation_stub() -> impl Strategy<Value = Vec<u8>> {
            prop_oneof![bytes(512), mutated(WINDOWS_ACTIVATION_STUB)]
        }

        proptest! {
            #![proptest_config(config())]

            #[test]
            fn activation_replies_never_panic(stub in activation_stub()) {
                let _ = parse_activation_stub(&stub, None);
                let _ = parse_activation_stub(&stub, Some(&IID_IWBEM_LEVEL1_LOGIN));
            }

            #[test]
            fn resolve_oxid_replies_never_panic(
                stub in prop_oneof![bytes(512), mutated(resolve_oxid_reply())],
            ) {
                let _ = parse_resolve_oxid_stub(&stub);
            }

            #[test]
            fn rem_release_replies_never_panic(stub in bytes(64)) {
                let _ = parse_rem_release_response(&stub);
            }

            /// The marshaled-object parsers take a start offset into the
            /// stub; try every offset, including ones past the end.
            #[test]
            fn object_reference_parsers_never_panic(
                stub in activation_stub(),
                at in any::<usize>(),
                require_wrapper_bounds in any::<bool>(),
            ) {
                let at = at % (stub.len() + 16);
                let _ = parse_m_interface_pointer(&stub, at);
                let _ = find_std_objref(&stub, at, None, None, require_wrapper_bounds);
                let _ = find_std_objref(
                    &stub,
                    at,
                    Some(&[0; 8]),
                    Some(&IID_IWBEM_LEVEL1_LOGIN),
                    require_wrapper_bounds,
                );
                let _ = ObjRef::parse(stub.get(at..).unwrap_or_default());
                let mut cursor = Cursor::new(stub.as_slice());
                cursor.set_position(at as u64);
                let _ = parse_dual_string_array(&mut cursor);
            }
        }
    }
}
