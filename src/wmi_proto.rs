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
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WmiProtoError {
    #[error("malformed WMI response stub")]
    Malformed,
    #[error("response returned an unexpected interface")]
    WrongInterface,
    #[error("WMI call failed (hr={0:#010x})")]
    Hresult(u32),
}

/// IID of IWbemLevel1Login (activated from CLSID_WbemLevel1Login).
pub(crate) const IID_IWBEM_LEVEL1_LOGIN: [u8; 16] =
    hex_literal::hex!("18ad09f36ad8d011a07500c04fb68820");
/// IID of IWbemServices (returned by IWbemLevel1Login::NTLMLogin).
pub(crate) const IID_IWBEM_SERVICES: [u8; 16] =
    hex_literal::hex!("99dc56958c82cf11a37e00aa003240c7");
/// IID of IEnumWbemClassObject (returned by IWbemServices::ExecQuery).
pub(crate) const IID_IENUM_WBEM_CLASS_OBJECT: [u8; 16] =
    hex_literal::hex!("e147790231d7ce11a357000000000001");

/// COMVERSION used by current Windows: 5.7.
const COMVERSION: [u8; 4] = [5, 0, 7, 0];

/// Base NDR referent id for the first unique pointer in a stub. The exact
/// value is immaterial to the server as long as referents are non-zero and
/// distinct within a call; later pointers use REFERENT_BASE + 4*n.
const REFERENT_BASE: u32 = 0x0002_0000;

/// Encode an ORPCTHIS header (MS-DCOM 2.2.13.1): COMVERSION, flags, reserved,
/// causality id, and a null extensions pointer. 32 bytes.
pub(crate) fn encode_orpcthis(buf: &mut Vec<u8>, causality_id: &[u8; 16]) {
    buf.extend_from_slice(&COMVERSION);
    buf.write_u32::<LittleEndian>(0).unwrap(); // flags
    buf.write_u32::<LittleEndian>(0).unwrap(); // reserved1
    buf.extend_from_slice(causality_id); // cid
    buf.write_u32::<LittleEndian>(0).unwrap(); // extensions: null
}

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
/// carries `expected_iid`, and return its std.ipid for subsequent ORPC calls.
pub(crate) fn parse_interface_response(
    stub: &[u8],
    expected_iid: &[u8; 16],
) -> Result<[u8; 16], WmiProtoError> {
    const FLAGS_OFF: usize = 4;
    const IID_OFF: usize = 8;
    const IPID_OFF: usize = 48; // sig(4)+flags(4)+iid(16)+std{flags(4)+crefs(4)+oxid(8)+oid(8)}
    const OBJREF_END: usize = IPID_OFF + 16;
    const OBJREF_STANDARD: u32 = 1;

    let hr = stub
        .len()
        .checked_sub(4)
        .and_then(|o| stub.get(o..o + 4))
        .ok_or(WmiProtoError::Malformed)?;
    let hr = u32::from_le_bytes(hr.try_into().unwrap());
    if hr != 0 {
        return Err(WmiProtoError::Hresult(hr));
    }

    // The OBJREF sits inside an MInterfacePointer wrapper (referent, max_count,
    // ulCntData) that follows ORPCTHAT. Scan past ORPCTHAT (>= 8 bytes) so a
    // "MEOW" in its flags/extensions pointer cannot be mistaken for the OBJREF.
    const ORPCTHAT_MIN: usize = 8;
    let scan = stub.get(ORPCTHAT_MIN..).ok_or(WmiProtoError::Malformed)?;
    let meow = ORPCTHAT_MIN
        + scan
            .windows(4)
            .position(|w| w == b"MEOW")
            .ok_or(WmiProtoError::Malformed)?;
    // Validate the MInterfacePointer: max_count and ulCntData (the 8 bytes
    // before the OBJREF) must agree and bound the OBJREF within the stub.
    if meow < 8 {
        return Err(WmiProtoError::Malformed);
    }
    let max_count = u32::from_le_bytes(stub[meow - 8..meow - 4].try_into().unwrap()) as usize;
    let cnt_data = u32::from_le_bytes(stub[meow - 4..meow].try_into().unwrap()) as usize;
    if max_count != cnt_data || cnt_data < OBJREF_END || meow + cnt_data > stub.len() {
        return Err(WmiProtoError::Malformed);
    }
    let objref = &stub[meow..meow + OBJREF_END];
    if u32::from_le_bytes(objref[FLAGS_OFF..FLAGS_OFF + 4].try_into().unwrap()) != OBJREF_STANDARD {
        return Err(WmiProtoError::Malformed);
    }
    if &objref[IID_OFF..IID_OFF + 16] != expected_iid {
        return Err(WmiProtoError::WrongInterface);
    }
    Ok(objref[IPID_OFF..IPID_OFF + 16].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let ipid = parse_interface_response(NTLMLOGIN_RESP, &IID_IWBEM_SERVICES).unwrap();
        assert_eq!(hex::encode(ipid), "0c7000007c060000b7af6bab62096d93");
    }

    #[test]
    fn parse_interface_response_extracts_ienum_ipid() {
        let ipid = parse_interface_response(EXECQUERY_RESP, &IID_IENUM_WBEM_CLASS_OBJECT).unwrap();
        assert_eq!(hex::encode(ipid), "159c00007c060000b632e12bd5007b97");
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
        let ipid = parse_interface_response(&stub, &IID_IWBEM_SERVICES).unwrap();
        assert_eq!(hex::encode(ipid), "0c7000007c060000b7af6bab62096d93");
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
}
