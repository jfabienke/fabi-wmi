//! ORPC request-stub encoders for the WMI interfaces (MS-WMI), NDR20.
//!
//! These build the cleartext stub (ORPCTHIS + marshaled [in] parameters) that
//! goes inside a DCE/RPC request. Framing, object UUID and auth live in the
//! transport layer.
//!
//! Encoders are validated by golden tests and consumed by the WMI connection
//! path as it is built out.
#![allow(dead_code)]

use byteorder::{LittleEndian, WriteBytesExt};
use fabi_dcom::{
    encode_custom_m_interface_pointer, find_std_objref, parse_m_interface_pointer, DcomError,
    ObjRef,
};
use thiserror::Error;

pub(crate) use fabi_dcom::{encode_orpcthis, encode_rem_release, InterfaceRef, IID_IREMUNKNOWN};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WmiProtoError {
    #[error("malformed WMI response stub")]
    Malformed,
    #[error("response returned an unexpected interface")]
    WrongInterface,
    #[error("unexpected custom marshaler CLSID")]
    NotWbemObject,
    #[error("WMI call failed (hr={0:#010x})")]
    Hresult(u32),
}

/// CLSID of WbemLevel1Login {8bc3f05e-d86b-11d0-a075-00c04fb68820}.
pub(crate) const CLSID_WBEM_LEVEL1_LOGIN: [u8; 16] =
    hex_literal::hex!("5ef0c38b6bd8d011a07500c04fb68820");
/// IID of IWbemLevel1Login (activated from CLSID_WbemLevel1Login).
pub(crate) const IID_IWBEM_LEVEL1_LOGIN: [u8; 16] =
    hex_literal::hex!("18ad09f36ad8d011a07500c04fb68820");
/// IID of IWbemServices (returned by IWbemLevel1Login::NTLMLogin).
pub(crate) const IID_IWBEM_SERVICES: [u8; 16] =
    hex_literal::hex!("99dc56958c82cf11a37e00aa003240c7");
/// IID of IEnumWbemClassObject (returned by IWbemServices::ExecQuery).
pub(crate) const IID_IENUM_WBEM_CLASS_OBJECT: [u8; 16] =
    hex_literal::hex!("e147790231d7ce11a357000000000001");
/// IID of IWbemClassObject {dc12a681-737f-11cf-884d-00aa004b2e24}.
pub(crate) const IID_IWBEM_CLASS_OBJECT: [u8; 16] =
    hex_literal::hex!("81a612dc7f73cf11884d00aa004b2e24");

/// Base NDR referent id for the first unique pointer in a stub. The exact
/// value is immaterial to the server as long as referents are non-zero and
/// distinct within a call; later pointers use REFERENT_BASE + 4*n.
const REFERENT_BASE: u32 = 0x0002_0000;

/// Pad `buf` to a 4-byte NDR boundary with the given fill byte.
fn align4(buf: &mut Vec<u8>, fill: u8) {
    while !buf.len().is_multiple_of(4) {
        buf.push(fill);
    }
}

/// Encode a `[in, string] LPCWSTR` as a unique pointer to an NDR
/// conformant+varying wide string (referent, max_count, offset, actual_count,
/// UTF-16LE chars incl. NUL), then pad to a 4-byte boundary.
fn encode_wstr_ptr(buf: &mut Vec<u8>, referent: u32, s: &str) {
    debug_assert!(referent != 0, "a unique-pointer referent must be non-zero");
    let mut units: Vec<u16> = s.encode_utf16().collect();
    units.push(0); // NUL
    let count = units.len() as u32;
    buf.write_u32::<LittleEndian>(referent).unwrap();
    buf.write_u32::<LittleEndian>(count).unwrap(); // max_count
    buf.write_u32::<LittleEndian>(0).unwrap(); // offset
    buf.write_u32::<LittleEndian>(count).unwrap(); // actual_count
    for u in units {
        buf.write_u16::<LittleEndian>(u).unwrap();
    }
    align4(buf, 0);
}

/// Encode the IWbemLevel1Login::NTLMLogin (opnum 6) request stub (MS-WMI
/// 3.1.4.1): ORPCTHIS, wszNetworkResource (the namespace), null
/// wszPreferredLocale, lFlags, null pCtx. The [out] ppNamespace takes no input.
///
pub(crate) fn encode_ntlm_login(causality_id: &[u8; 16], namespace: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_orpcthis(&mut buf, causality_id);
    encode_wstr_ptr(&mut buf, REFERENT_BASE, namespace);
    buf.write_u32::<LittleEndian>(0).unwrap(); // wszPreferredLocale: null ptr
    buf.write_u32::<LittleEndian>(0).unwrap(); // lFlags
    buf.write_u32::<LittleEndian>(0).unwrap(); // pCtx: null ptr
    buf
}

/// Encode a `BSTR` [in] parameter: a unique pointer to a FLAGGED_WORD_BLOB
/// (MS-OAUT 2.2.23.2 / 2.2.23.1 wire form) — referent, max_count, cBytes,
/// clSize, then UTF-16LE data incl. NUL — then pad to a 4-byte boundary.
///
/// All three counts include the terminating NUL here, matching the reference
/// capture Windows accepted (MS-OAUT defines cBytes/clSize over the data; the
/// WMI server tolerates counting the NUL).
fn encode_bstr(buf: &mut Vec<u8>, referent: u32, s: &str) {
    debug_assert!(referent != 0, "a unique-pointer referent must be non-zero");
    let mut units: Vec<u16> = s.encode_utf16().collect();
    units.push(0); // NUL
    let count = units.len() as u32;
    buf.write_u32::<LittleEndian>(referent).unwrap();
    buf.write_u32::<LittleEndian>(count).unwrap(); // max_count
    buf.write_u32::<LittleEndian>(count * 2).unwrap(); // cBytes
    buf.write_u32::<LittleEndian>(count).unwrap(); // clSize
    for u in units {
        buf.write_u16::<LittleEndian>(u).unwrap();
    }
    align4(buf, 0);
}

/// Encode the IWbemServices::ExecQuery (opnum 20) request stub (MS-WMI
/// 3.1.4.3.18): ORPCTHIS, strQueryLanguage ("WQL"), strQuery (the WQL),
/// lFlags, null pCtx. The [out] ppEnum takes no input.
pub(crate) fn encode_exec_query(causality_id: &[u8; 16], wql: &str, lflags: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_orpcthis(&mut buf, causality_id);
    encode_bstr(&mut buf, REFERENT_BASE, "WQL");
    encode_bstr(&mut buf, REFERENT_BASE + 4, wql);
    buf.write_u32::<LittleEndian>(lflags).unwrap();
    buf.write_u32::<LittleEndian>(0).unwrap(); // pCtx: null ptr
    buf
}

/// Encode an `[in, out, unique] IWbemClassObject**` that asks for an object
/// back: a non-NULL outer pointer to a NULL interface pointer. A NULL outer
/// pointer tells the server the caller does not want the object, so it runs
/// the call and returns S_OK with no object.
fn encode_object_out_ptr(buf: &mut Vec<u8>, referent: u32) {
    debug_assert!(referent != 0, "a unique-pointer referent must be non-zero");
    buf.write_u32::<LittleEndian>(referent).unwrap();
    buf.write_u32::<LittleEndian>(0).unwrap(); // *ppObject: NULL on input
}

/// Encode the IWbemServices::GetObject (opnum 6) request stub (MS-WMI
/// 3.1.4.3.4): ORPCTHIS, strObjectPath, lFlags, null pCtx, ppObject (pointer
/// to a NULL object), null ppCallResult.
pub(crate) fn encode_get_object(
    causality_id: &[u8; 16],
    object_path: &str,
    lflags: u32,
) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_orpcthis(&mut buf, causality_id);
    encode_bstr(&mut buf, REFERENT_BASE, object_path);
    buf.write_u32::<LittleEndian>(lflags).unwrap();
    buf.write_u32::<LittleEndian>(0).unwrap(); // pCtx: null ptr
    encode_object_out_ptr(&mut buf, REFERENT_BASE + 4); // ppObject
    buf.write_u32::<LittleEndian>(0).unwrap(); // ppCallResult: null (synchronous call)
    buf
}

/// Encode the IWbemServices::ExecMethod (opnum 24) request stub (MS-WMI
/// 3.1.4.3.22): ORPCTHIS, strObjectPath, strMethodName, lFlags, null pCtx,
/// pInParams (null or MInterfacePointer wrapping OBJREF_CUSTOM), ppOutParams
/// (pointer to a NULL object), null ppCallResult.
pub(crate) fn encode_exec_method(
    causality_id: &[u8; 16],
    object_path: &str,
    method_name: &str,
    lflags: u32,
    in_params_wmio: Option<&[u8]>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_orpcthis(&mut buf, causality_id);
    encode_bstr(&mut buf, REFERENT_BASE, object_path);
    encode_bstr(&mut buf, REFERENT_BASE + 4, method_name);
    buf.write_u32::<LittleEndian>(lflags).unwrap();
    buf.write_u32::<LittleEndian>(0).unwrap(); // pCtx: null ptr
    match in_params_wmio {
        Some(wmio) => {
            buf.write_u32::<LittleEndian>(REFERENT_BASE + 8).unwrap();
            encode_custom_m_interface_pointer(
                &mut buf,
                &IID_IWBEM_CLASS_OBJECT,
                &CLSID_WBEM_CLASS_OBJECT,
                wmio,
            );
            align4(&mut buf, 0);
        }
        None => {
            buf.write_u32::<LittleEndian>(0).unwrap(); // pInParams: null ptr
        }
    }
    encode_object_out_ptr(&mut buf, REFERENT_BASE + 12); // ppOutParams
    buf.write_u32::<LittleEndian>(0).unwrap(); // ppCallResult: null (synchronous call)
    buf
}

/// WBEM_INFINITE: wait indefinitely for the next objects.
pub(crate) const WBEM_INFINITE: i32 = -1;

/// Encode the IEnumWbemClassObject::Next (opnum 4) request stub (MS-WMI
/// 3.1.4.4.3): ORPCTHIS, lTimeout, uCount. The [out] objects take no input.
pub(crate) fn encode_enum_next(causality_id: &[u8; 16], timeout: i32, count: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_orpcthis(&mut buf, causality_id);
    buf.write_i32::<LittleEndian>(timeout).unwrap();
    buf.write_u32::<LittleEndian>(count).unwrap();
    buf
}

/// Parse a response whose [out] parameter is an interface pointer (NTLMLogin,
/// ExecQuery): confirm the call's HRESULT (last 4 bytes) is success, locate the
/// returned OBJREF_STANDARD by its "MEOW" signature, check it is standard and
/// carries `expected_iid`, and return its std.ipid and std.cPublicRefs.
pub(crate) fn parse_interface_response(
    stub: &[u8],
    expected_iid: &[u8; 16],
) -> Result<InterfaceRef, WmiProtoError> {
    let hr = stub
        .len()
        .checked_sub(4)
        .and_then(|o| stub.get(o..o + 4))
        .ok_or(WmiProtoError::Malformed)?;
    let hr = u32::from_le_bytes(hr.try_into().unwrap());
    if hr != 0 {
        return Err(WmiProtoError::Hresult(hr));
    }

    // Scan past ORPCTHAT (>= 8 bytes) so a "MEOW" in its flags/extensions
    // pointer cannot be mistaken for the OBJREF.
    const ORPCTHAT_MIN: usize = 8;
    let std =
        find_std_objref(stub, ORPCTHAT_MIN, None, Some(expected_iid), true).map_err(
            |e| match e {
                DcomError::WrongInterface => WmiProtoError::WrongInterface,
                _ => WmiProtoError::Malformed,
            },
        )?;
    Ok(std.as_interface_ref())
}

/// Check a RemRelease response stub (ORPCTHAT, HRESULT).
pub(crate) fn parse_rem_release_response(stub: &[u8]) -> Result<(), WmiProtoError> {
    let hr = stub
        .len()
        .checked_sub(4)
        .filter(|&o| o >= 8)
        .map(|o| u32::from_le_bytes(stub[o..o + 4].try_into().unwrap()))
        .ok_or(WmiProtoError::Malformed)?;
    if hr != 0 {
        return Err(WmiProtoError::Hresult(hr));
    }
    Ok(())
}

/// HRESULT from IEnumWbemClassObject::Next when fewer objects than requested
/// were returned, i.e. the enumeration is complete (MS-WMI 2.2.11).
const WBEM_S_FALSE: u32 = 0x0000_0001;

/// CLSID_WbemClassObject {4590F812-1D3A-11D0-891F-00AA004B2E24}, little-endian.
const CLSID_WBEM_CLASS_OBJECT: [u8; 16] = hex_literal::hex!("12f890453a1dd011891f00aa004b2e24");

fn rd_u32(b: &[u8], off: usize) -> Result<u32, WmiProtoError> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .ok_or(WmiProtoError::Malformed)
}

/// One IWbemClassObject returned from Next, as its raw MS-WMIO encoding unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WmioBlob {
    pub data: Vec<u8>,
}

/// Extract the WMIO encoding units of every object in an
/// IEnumWbemClassObject::Next response stub (ORPCTHAT, apObjects array,
/// puReturned, HRESULT). Each object is an OBJREF_CUSTOM wrapping the WMIO data.
pub(crate) fn parse_next_response(stub: &[u8]) -> Result<Vec<WmioBlob>, WmiProtoError> {
    // The call's HRESULT is the last 4 bytes; WBEM_S_FALSE ends the
    // enumeration and is not an error.
    let hr = stub
        .len()
        .checked_sub(4)
        .map(|o| rd_u32(stub, o))
        .ok_or(WmiProtoError::Malformed)??;
    if hr != 0 && hr != WBEM_S_FALSE {
        return Err(WmiProtoError::Hresult(hr));
    }

    // ORPCTHAT: flags, extensions pointer (null in practice).
    let mut off = 8usize;
    // apObjects: conformant+varying array of unique pointers.
    let _max_count = rd_u32(stub, off)?;
    off += 4;
    let _offset = rd_u32(stub, off)?;
    off += 4;
    let actual = rd_u32(stub, off)? as usize;
    off += 4;
    // Each referent is 4 bytes. A count the stub can't hold is malformed, and
    // would otherwise size an allocation straight from the wire.
    if actual > stub.len().saturating_sub(off) / 4 {
        return Err(WmiProtoError::Malformed);
    }

    let mut referents = Vec::with_capacity(actual);
    for _ in 0..actual {
        referents.push(rd_u32(stub, off)?);
        off += 4;
    }

    let mut blobs = Vec::new();
    for referent in referents {
        if referent == 0 {
            continue;
        }
        let (objref, end) =
            parse_m_interface_pointer(stub, off).map_err(|_| WmiProtoError::Malformed)?;
        // NDR aligns the next pointee to 4 bytes.
        off = (end + 3) & !3;
        let data = expect_wbem_custom(objref)?;
        blobs.push(WmioBlob {
            data: data.to_vec(),
        });
    }
    Ok(blobs)
}

/// Parse a synchronous `IWbemServices::GetObject` or `IWbemServices::ExecMethod`
/// response stub (ORPCTHAT, `[in, out, unique] ppObject`/`ppOutParams`,
/// `[in, out, unique] ppCallResult`, HRESULT). The object comes as two
/// referents (the outer pointer, then the interface pointer) followed by the
/// MInterfacePointer. Returns `Ok(None)` when either pointer is NULL (e.g. a
/// method with no output parameters).
pub(crate) fn parse_single_object_response(stub: &[u8]) -> Result<Option<WmioBlob>, WmiProtoError> {
    if stub.len() < 20 {
        return Err(WmiProtoError::Malformed);
    }
    let hr = rd_u32(stub, stub.len() - 4)?;
    if hr != 0 {
        return Err(WmiProtoError::Hresult(hr));
    }
    // ORPCTHAT: flags(4), extensions pointer(4).
    if rd_u32(stub, 8)? == 0 || rd_u32(stub, 12)? == 0 {
        return Ok(None);
    }
    let (objref, _) = parse_m_interface_pointer(stub, 16).map_err(|_| WmiProtoError::Malformed)?;
    let data = expect_wbem_custom(objref)?;
    Ok(Some(WmioBlob {
        data: data.to_vec(),
    }))
}

/// Validate an OBJREF_CUSTOM for IWbemClassObject and return its WMIO payload.
fn parse_objref_custom(objref: &[u8]) -> Result<&[u8], WmiProtoError> {
    expect_wbem_custom(ObjRef::parse(objref).map_err(|_| WmiProtoError::Malformed)?)
}

fn expect_wbem_custom(objref: ObjRef<'_>) -> Result<&[u8], WmiProtoError> {
    match objref {
        ObjRef::Custom { clsid, data, .. } => {
            if clsid != CLSID_WBEM_CLASS_OBJECT {
                return Err(WmiProtoError::NotWbemObject);
            }
            Ok(data)
        }
        ObjRef::Standard { .. } => Err(WmiProtoError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fabi_dcom::{OBJREF_CUSTOM, OBJREF_SIGNATURE};

    /// IWbemLevel1Login::NTLMLogin("//./root/cimv2") request stub impacket sent
    /// to a Windows Server 2022 DC (cleartext, accepted). Non-sensitive.
    const NTLMLOGIN_STUB: &[u8] = include_bytes!("testdata/ntlmlogin_request_stub.bin");

    /// Zero the given byte ranges in a copy so bytes that are arbitrary on the
    /// wire (referent ids, NDR pad) don't affect a byte-for-byte comparison.
    fn mask(bytes: &[u8], ranges: &[std::ops::Range<usize>]) -> Vec<u8> {
        let mut v = bytes.to_vec();
        for r in ranges {
            v[r.clone()].fill(0);
        }
        v
    }

    #[test]
    fn encode_ntlm_login_matches_windows_reference() {
        // The causality id is a caller-chosen opaque id; take the reference's.
        let cid: [u8; 16] = NTLMLOGIN_STUB[12..28].try_into().unwrap();
        let stub = encode_ntlm_login(&cid, "//./root/cimv2");

        // The string referent (32..36) and the one pad region (78..80) are
        // arbitrary on the wire; compare everything else byte-for-byte.
        let masked = [32..36, 78..80];
        assert_eq!(mask(&stub, &masked), mask(NTLMLOGIN_STUB, &masked));
        assert_eq!(
            &stub[32..36],
            &REFERENT_BASE.to_le_bytes(),
            "non-zero referent"
        );
    }

    #[test]
    fn encode_ntlm_login_empty_namespace_is_well_formed() {
        // ORPCTHIS(32) + wstr{referent,max,off,act = 16}{just NUL = 2}{pad 2}
        // + locale(4) + lFlags(4) + pCtx(4)
        let stub = encode_ntlm_login(&[0; 16], "");
        assert_eq!(stub.len(), 32 + 16 + 2 + 2 + 12);
        assert_eq!(&stub[32..36], &REFERENT_BASE.to_le_bytes());
        assert_eq!(
            &stub[36..40],
            &1u32.to_le_bytes(),
            "max_count = 1 (just NUL)"
        );
    }

    /// IWbemServices::ExecQuery request stub impacket sent and the DC accepted.
    const EXECQUERY_STUB: &[u8] = include_bytes!("testdata/execquery_request_stub.bin");

    #[test]
    fn encode_exec_query_matches_windows_reference() {
        let cid: [u8; 16] = EXECQUERY_STUB[12..28].try_into().unwrap();
        let stub = encode_exec_query(
            &cid,
            "SELECT Name, Domain, Manufacturer, Model FROM Win32_ComputerSystem",
            0,
        );

        // Mask the two BSTR referents (32..36, and 56..60 after the "WQL\0"
        // BSTR) and the two pad bytes after strQuery (206..208).
        let masked = [32..36, 56..60, 206..208];
        assert_eq!(mask(&stub, &masked), mask(EXECQUERY_STUB, &masked));
        assert_eq!(&stub[32..36], &REFERENT_BASE.to_le_bytes());
        assert_eq!(&stub[56..60], &(REFERENT_BASE + 4).to_le_bytes());
    }

    /// IEnumWbemClassObject::Next request stub impacket sent and the DC accepted.
    const NEXT_STUB: &[u8] = include_bytes!("testdata/next_request_stub.bin");

    #[test]
    fn encode_enum_next_matches_windows_reference() {
        let cid: [u8; 16] = NEXT_STUB[12..28].try_into().unwrap();
        let stub = encode_enum_next(&cid, WBEM_INFINITE, 1);
        assert_eq!(stub, NEXT_STUB);
    }

    const NTLMLOGIN_RESP: &[u8] = include_bytes!("testdata/ntlmlogin_response_stub.bin");
    const EXECQUERY_RESP: &[u8] = include_bytes!("testdata/execquery_response_stub.bin");

    #[test]
    fn parse_interface_response_extracts_iwbemservices_ipid() {
        let r = parse_interface_response(NTLMLOGIN_RESP, &IID_IWBEM_SERVICES).unwrap();
        assert_eq!(hex::encode(r.ipid), "0c7000007c060000b7af6bab62096d93");
        assert_eq!(r.public_refs, 5);
    }

    #[test]
    fn parse_interface_response_extracts_ienum_ipid() {
        let r = parse_interface_response(EXECQUERY_RESP, &IID_IENUM_WBEM_CLASS_OBJECT).unwrap();
        assert_eq!(hex::encode(r.ipid), "159c00007c060000b632e12bd5007b97");
        assert_eq!(r.public_refs, 5);
    }

    #[test]
    fn parse_interface_response_rejects_wrong_iid() {
        assert_eq!(
            parse_interface_response(NTLMLOGIN_RESP, &IID_IENUM_WBEM_CLASS_OBJECT),
            Err(WmiProtoError::WrongInterface)
        );
    }

    #[test]
    fn parse_interface_response_rejects_failure_hresult() {
        let mut stub = NTLMLOGIN_RESP.to_vec();
        let n = stub.len();
        stub[n - 4..].copy_from_slice(&0x8004_1001u32.to_le_bytes()); // WBEM_E_FAILED
        assert_eq!(
            parse_interface_response(&stub, &IID_IWBEM_SERVICES),
            Err(WmiProtoError::Hresult(0x8004_1001))
        );
    }

    #[test]
    fn parse_interface_response_rejects_inconsistent_wrapper() {
        // Corrupt the MInterfacePointer max_count (8 bytes before MEOW) so it
        // disagrees with ulCntData; the structural check must reject it.
        let meow = NTLMLOGIN_RESP
            .windows(4)
            .position(|w| w == b"MEOW")
            .unwrap();
        let mut stub = NTLMLOGIN_RESP.to_vec();
        stub[meow - 8..meow - 4].copy_from_slice(&0x9999u32.to_le_bytes());
        assert_eq!(
            parse_interface_response(&stub, &IID_IWBEM_SERVICES),
            Err(WmiProtoError::Malformed)
        );
    }

    #[test]
    fn parse_interface_response_ignores_meow_in_orpcthat() {
        // A stray "MEOW" in the ORPCTHAT header (offset 0) must not shadow the
        // real OBJREF further on: the parser still returns the true IPID.
        let mut stub = NTLMLOGIN_RESP.to_vec();
        stub[0..4].copy_from_slice(b"MEOW"); // ORPCTHAT flags
        let r = parse_interface_response(&stub, &IID_IWBEM_SERVICES).unwrap();
        assert_eq!(hex::encode(r.ipid), "0c7000007c060000b7af6bab62096d93");
    }

    /// IRemUnknown::RemRelease request impacket sent (1 public ref on the
    /// IWbemLevel1Login IPID) and Windows accepted.
    const REM_RELEASE_STUB: [u8; 64] = hex_literal::hex!(
        "0500070000000000000000005919bc025b44841a7e8a2e4899ca040b000000000100cece010000000f6000007c060000309fbbb3b07c6c4c0100000000000000"
    );

    #[test]
    fn encode_rem_release_matches_windows_reference() {
        let cid: [u8; 16] = REM_RELEASE_STUB[12..28].try_into().unwrap();
        let r = InterfaceRef {
            ipid: REM_RELEASE_STUB[40..56].try_into().unwrap(),
            public_refs: 1,
        };
        let stub = encode_rem_release(&cid, &[r]);
        // Bytes 34..36 are NDR alignment pad (arbitrary on the wire).
        let masked = std::slice::from_ref(&(34..36));
        assert_eq!(mask(&stub, masked), mask(&REM_RELEASE_STUB, masked));
    }

    #[test]
    fn encode_rem_release_lists_every_ref() {
        let refs = [
            InterfaceRef {
                ipid: [1; 16],
                public_refs: 5,
            },
            InterfaceRef {
                ipid: [2; 16],
                public_refs: 3,
            },
        ];
        let stub = encode_rem_release(&[0; 16], &refs);
        assert_eq!(stub.len(), 32 + 4 + 4 + 2 * 24);
        assert_eq!(&stub[32..34], &2u16.to_le_bytes());
        assert_eq!(&stub[36..40], &2u32.to_le_bytes());
        assert_eq!(&stub[64..80], &[2; 16]);
        assert_eq!(&stub[80..84], &3u32.to_le_bytes());
    }

    #[test]
    fn parse_rem_release_response_checks_hresult() {
        assert_eq!(parse_rem_release_response(&[0; 12]), Ok(()));
        let mut bad = [0u8; 12];
        bad[8..].copy_from_slice(&0x8001_0105u32.to_le_bytes()); // RPC_E_SERVERFAULT
        assert_eq!(
            parse_rem_release_response(&bad),
            Err(WmiProtoError::Hresult(0x8001_0105))
        );
        assert_eq!(
            parse_rem_release_response(&[0; 4]),
            Err(WmiProtoError::Malformed)
        );
    }

    #[test]
    fn encode_orpcthis_is_32_bytes_comversion_5_7() {
        let mut buf = Vec::new();
        encode_orpcthis(&mut buf, &[0xAB; 16]);
        assert_eq!(buf.len(), 32);
        assert_eq!(&buf[0..4], &[5, 0, 7, 0]);
        assert_eq!(&buf[12..28], &[0xAB; 16]);
        assert_eq!(&buf[28..32], &[0, 0, 0, 0]); // null extensions
    }

    /// IEnumWbemClassObject::Next response the DC sent for the one-row query
    /// SELECT ... FROM Win32_ComputerSystem (cleartext stub). Non-sensitive.
    const NEXT_RESULT: &[u8] = include_bytes!("testdata/next_response_result.bin");
    const WMIO_RESULT: &[u8] = include_bytes!("../crates/fabi-wmio/src/testdata/wmio_result.bin");

    #[test]
    fn parse_next_response_extracts_one_wmio_object() {
        let blobs = parse_next_response(NEXT_RESULT).unwrap();
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].data, WMIO_RESULT);
    }

    /// Next response that ended the enumeration: no objects, WBEM_S_FALSE.
    const NEXT_END: [u8; 28] =
        hex_literal::hex!("00000000000000000100000000000000000000000000000001000000");

    #[test]
    fn parse_next_response_end_of_enumeration_is_empty() {
        assert_eq!(parse_next_response(&NEXT_END).unwrap(), vec![]);
    }

    #[test]
    fn parse_next_response_accepts_wbem_s_false_with_objects() {
        // A batch request that got fewer objects than asked for: S_FALSE.
        let mut stub = NEXT_RESULT.to_vec();
        let at = stub.len() - 4;
        stub[at..].copy_from_slice(&1u32.to_le_bytes()); // WBEM_S_FALSE on the wire
        assert_eq!(parse_next_response(&stub).unwrap().len(), 1);
    }

    #[test]
    fn parse_next_response_reports_failure_hresult() {
        let mut stub = NEXT_END;
        stub[24..].copy_from_slice(&0x8004_1010u32.to_le_bytes()); // WBEM_E_INVALID_CLASS
        assert_eq!(
            parse_next_response(&stub),
            Err(WmiProtoError::Hresult(0x8004_1010))
        );
    }

    #[test]
    fn parse_next_response_aligns_between_objects() {
        // Two copies of the fixture object. Its OBJREF length is not a multiple
        // of 4, so the second MInterfacePointer starts after NDR alignment pad.
        let cnt = rd_u32(NEXT_RESULT, 28).unwrap() as usize;
        assert_ne!(cnt % 4, 0, "fixture must exercise the pad");
        let pointee = &NEXT_RESULT[24..32 + cnt];
        let pad = vec![0u8; (4 - cnt % 4) % 4];
        let mut stub = NEXT_RESULT[..8].to_vec(); // ORPCTHAT
        for v in [2u32, 0, 2, 0x0002_0000, 0x0002_0004] {
            stub.extend_from_slice(&v.to_le_bytes()); // max, offset, actual, referents
        }
        for _ in 0..2 {
            stub.extend_from_slice(pointee);
            stub.extend_from_slice(&pad);
        }
        stub.extend_from_slice(&2u32.to_le_bytes()); // puReturned
        stub.extend_from_slice(&0u32.to_le_bytes()); // S_OK
        let blobs = parse_next_response(&stub).unwrap();
        assert_eq!(blobs.len(), 2);
        assert_eq!(blobs[0], blobs[1]);
        assert_eq!(blobs[0].data, WMIO_RESULT);
    }

    #[test]
    fn parse_objref_custom_rejects_wrong_clsid() {
        let mut objref = vec![0u8; 48];
        objref[0..4].copy_from_slice(OBJREF_SIGNATURE);
        objref[4..8].copy_from_slice(&OBJREF_CUSTOM.to_le_bytes());
        // leave clsid zeroed -> not WbemClassObject
        assert_eq!(
            parse_objref_custom(&objref),
            Err(WmiProtoError::NotWbemObject)
        );
    }

    #[test]
    fn encode_get_object_and_exec_method_are_well_formed() {
        let cid = [0x11u8; 16];
        // ppObject / ppOutParams must be a non-NULL pointer to a NULL object:
        // with a NULL outer pointer Windows returns S_OK and no object.
        let get_stub = encode_get_object(&cid, "Win32_Process", 0);
        // ORPCTHIS(32) + BSTR("Win32_Process\0": 16 + 14*2 = 44) + lFlags(4) + pCtx(4)
        // + ppObject(4 + 4) + ppCallResult(4) = 96
        assert_eq!(get_stub.len(), 96);
        assert_eq!(&get_stub[32..36], &REFERENT_BASE.to_le_bytes());
        assert_eq!(&get_stub[76..84], &[0u8; 8]); // lFlags, pCtx
        assert_eq!(&get_stub[84..88], &(REFERENT_BASE + 4).to_le_bytes());
        assert_eq!(&get_stub[88..96], &[0u8; 8]); // *ppObject, ppCallResult

        let exec_no_in = encode_exec_method(&cid, "Win32_Process", "Create", 0, None);
        // ORPCTHIS(32) + BSTR("Win32_Process\0": 44) + BSTR("Create\0": 16 + 14 + 2 pad = 32)
        // + lFlags(4) + pCtx(4) + pInParams(4) + ppOutParams(4 + 4) + ppCallResult(4) = 132
        assert_eq!(exec_no_in.len(), 132);
        assert_eq!(&exec_no_in[108..120], &[0u8; 12]); // lFlags, pCtx, pInParams
        assert_eq!(&exec_no_in[120..124], &(REFERENT_BASE + 12).to_le_bytes());
        assert_eq!(&exec_no_in[124..132], &[0u8; 8]); // *ppOutParams, ppCallResult

        let exec_with_in =
            encode_exec_method(&cid, "Win32_Process", "Create", 0, Some(WMIO_RESULT));
        assert_eq!(&exec_with_in[116..120], &(REFERENT_BASE + 8).to_le_bytes());
        let (objref, end) = parse_m_interface_pointer(&exec_with_in, 120).unwrap();
        assert_eq!(expect_wbem_custom(objref).unwrap(), WMIO_RESULT);
        let aligned_end = (end + 3) & !3;
        let mut tail = (REFERENT_BASE + 12).to_le_bytes().to_vec();
        tail.extend_from_slice(&[0u8; 8]); // *ppOutParams, ppCallResult
        assert_eq!(&exec_with_in[aligned_end..], &tail[..]);
    }

    /// `StdRegProv.GetStringValue(HKLM, "SOFTWARE\Microsoft\Windows NT\CurrentVersion",
    /// "ProductName")` response stub from Windows Server 2025; matches
    /// Invoke-CimMethod on the same host. Non-sensitive lab data.
    const GETSTRINGVALUE_RESPONSE: &[u8] =
        include_bytes!("testdata/execmethod_getstringvalue_response_stub.bin");
    /// `__SystemSecurity.GetSD()` (no input parameters) response stub from the
    /// same host: root\cimv2's security descriptor, well-known SIDs only.
    const GETSD_RESPONSE: &[u8] = include_bytes!("testdata/execmethod_getsd_response_stub.bin");

    #[test]
    fn parse_single_object_response_decodes_captured_exec_method_results() {
        // Both carry two referents (0x00020000, 0x00020004) before the
        // MInterfacePointer; reading only one misparses the object.
        let blob = parse_single_object_response(GETSTRINGVALUE_RESPONSE)
            .unwrap()
            .unwrap();
        assert_eq!(
            fabi_wmio::decode_object(&blob.data).unwrap(),
            serde_json::json!({
                "ReturnValue": 0,
                "sValue": "Windows Server 2025 Standard Evaluation",
            })
        );

        let blob = parse_single_object_response(GETSD_RESPONSE)
            .unwrap()
            .unwrap();
        let out = fabi_wmio::decode_object(&blob.data).unwrap();
        assert_eq!(out["ReturnValue"], 0);
        let sd = out["SD"].as_array().unwrap();
        // Self-relative SECURITY_DESCRIPTOR: revision 1, control SE_SELF_RELATIVE | SE_DACL_PRESENT.
        assert_eq!(sd.len(), 180);
        assert_eq!(sd[..4], [1, 0, 4, 0x80]);
    }

    #[test]
    fn parse_single_object_response_extracts_wmio_or_none() {
        // Build a synthetic ExecMethod/GetObject response wrapping WMIO_RESULT.
        let mut resp = vec![0u8; 8]; // ORPCTHAT
        resp.extend_from_slice(&REFERENT_BASE.to_le_bytes()); // ppOutParams referent
        resp.extend_from_slice(&(REFERENT_BASE + 4).to_le_bytes()); // *ppOutParams referent
        encode_custom_m_interface_pointer(
            &mut resp,
            &IID_IWBEM_CLASS_OBJECT,
            &CLSID_WBEM_CLASS_OBJECT,
            WMIO_RESULT,
        );
        align4(&mut resp, 0);
        resp.extend_from_slice(&0u32.to_le_bytes()); // ppCallResult = NULL
        resp.extend_from_slice(&0u32.to_le_bytes()); // S_OK
        let blob = parse_single_object_response(&resp).unwrap().unwrap();
        assert_eq!(blob.data, WMIO_RESULT);

        // Null ppOutParams (void method with no output object).
        let mut empty_resp = vec![0u8; 16]; // ORPCTHAT(8) + ppOutParams(4) + ppCallResult(4)
        empty_resp.extend_from_slice(&0u32.to_le_bytes()); // S_OK
        assert_eq!(parse_single_object_response(&empty_resp).unwrap(), None);

        // Failure HRESULT.
        let mut err_resp = vec![0u8; 16];
        err_resp.extend_from_slice(&0x8004_102Eu32.to_le_bytes()); // WBEM_E_INVALID_METHOD
        assert_eq!(
            parse_single_object_response(&err_resp),
            Err(WmiProtoError::Hresult(0x8004_102E))
        );
    }

    /// Everything here parses stubs a server sent: whatever the bytes, the
    /// parsers must return (Ok or Err), never panic or abort.
    mod properties {
        use super::*;
        use fabi_testkit::{bytes, config, mutated, mutated_any};
        use proptest::prelude::*;

        const INTERFACE_REPLIES: &[&[u8]] = &[NTLMLOGIN_RESP, EXECQUERY_RESP];
        const OBJECT_REPLIES: &[&[u8]] = &[GETSTRINGVALUE_RESPONSE, GETSD_RESPONSE];

        proptest! {
            #![proptest_config(config())]

            #[test]
            fn interface_replies_never_panic(
                stub in prop_oneof![bytes(256), mutated_any(INTERFACE_REPLIES)],
            ) {
                for iid in [&IID_IWBEM_SERVICES, &IID_IENUM_WBEM_CLASS_OBJECT] {
                    let _ = parse_interface_response(&stub, iid);
                }
                let _ = parse_rem_release_response(&stub);
            }

            /// The query path end to end: Next reply, then each object in it.
            #[test]
            fn next_replies_never_panic(
                stub in prop_oneof![bytes(512), mutated(NEXT_RESULT)],
            ) {
                if let Ok(blobs) = parse_next_response(&stub) {
                    for blob in blobs {
                        let _ = fabi_wmio::decode_object(&blob.data);
                    }
                }
            }

            #[test]
            fn object_replies_never_panic(
                stub in prop_oneof![bytes(512), mutated_any(OBJECT_REPLIES)],
            ) {
                if let Ok(Some(blob)) = parse_single_object_response(&stub) {
                    let _ = fabi_wmio::decode_object(&blob.data);
                }
            }
        }
    }
}
