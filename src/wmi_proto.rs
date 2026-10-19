//! ORPC request-stub encoders for the WMI interfaces (MS-WMI), NDR20.
//!
//! These build the cleartext stub (ORPCTHIS + marshaled [in] parameters) that
//! goes inside a DCE/RPC request. Framing, object UUID and auth live in the
//! transport layer.
//!
// Encoders are validated by golden tests now and consumed by the WMI
// connection path as it is built out.
#![allow(dead_code)]

use byteorder::{LittleEndian, WriteBytesExt};

/// COMVERSION used by current Windows: 5.7.
const COMVERSION: [u8; 4] = [5, 0, 7, 0];

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
/// `namespace_referent` is any non-zero NDR referent id for the string pointer.
pub(crate) fn encode_ntlm_login(
    causality_id: &[u8; 16],
    namespace: &str,
    namespace_referent: u32,
) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_orpcthis(&mut buf, causality_id);
    encode_wstr_ptr(&mut buf, namespace_referent, namespace);
    buf.write_u32::<LittleEndian>(0).unwrap(); // wszPreferredLocale: null ptr
    buf.write_u32::<LittleEndian>(0).unwrap(); // lFlags
    buf.write_u32::<LittleEndian>(0).unwrap(); // pCtx: null ptr
    buf
}

/// Encode a `BSTR` [in] parameter: a unique pointer to a FLAGGED_WORD_BLOB
/// (MS-OAUT 2.2.23.2 / 2.2.23.1 wire form) — referent, max_count, cBytes,
/// clSize, then UTF-16LE data incl. NUL — then pad to a 4-byte boundary. All
/// three counts include the terminator, matching what Windows accepts here.
fn encode_bstr(buf: &mut Vec<u8>, referent: u32, s: &str) {
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
pub(crate) fn encode_exec_query(
    causality_id: &[u8; 16],
    wql: &str,
    lflags: u32,
    lang_referent: u32,
    query_referent: u32,
) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_orpcthis(&mut buf, causality_id);
    encode_bstr(&mut buf, lang_referent, "WQL");
    encode_bstr(&mut buf, query_referent, wql);
    buf.write_u32::<LittleEndian>(lflags).unwrap();
    buf.write_u32::<LittleEndian>(0).unwrap(); // pCtx: null ptr
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IWbemLevel1Login::NTLMLogin("//./root/cimv2") request stub impacket sent
    /// to a Windows Server 2022 DC (cleartext, accepted). Non-sensitive.
    const NTLMLOGIN_STUB: &[u8] = include_bytes!("testdata/ntlmlogin_request_stub.bin");

    #[test]
    fn encode_ntlm_login_matches_windows_reference() {
        // The causality id and string referent are caller-chosen opaque ids;
        // take the reference's so the comparison is byte-exact.
        let cid: [u8; 16] = NTLMLOGIN_STUB[12..28].try_into().unwrap();
        let referent = u32::from_le_bytes(NTLMLOGIN_STUB[32..36].try_into().unwrap());

        let stub = encode_ntlm_login(&cid, "//./root/cimv2", referent);

        // The one pad byte region (after the 15-wchar string) is arbitrary on
        // the wire; impacket fills 0xBF, we fill 0x00. Normalize before compare.
        let mut expected = NTLMLOGIN_STUB.to_vec();
        for b in &mut expected[78..80] {
            *b = 0;
        }
        assert_eq!(stub, expected);
    }

    /// IWbemServices::ExecQuery request stub impacket sent and the DC accepted.
    const EXECQUERY_STUB: &[u8] = include_bytes!("testdata/execquery_request_stub.bin");

    #[test]
    fn encode_exec_query_matches_windows_reference() {
        let cid: [u8; 16] = EXECQUERY_STUB[12..28].try_into().unwrap();
        let lang_ref = u32::from_le_bytes(EXECQUERY_STUB[32..36].try_into().unwrap());
        // strQuery referent follows the WQL BSTR (16-byte header + "WQL\0" = 8).
        let query_ref = u32::from_le_bytes(EXECQUERY_STUB[56..60].try_into().unwrap());

        let stub = encode_exec_query(
            &cid,
            "SELECT Name, Domain, Manufacturer, Model FROM Win32_ComputerSystem",
            0,
            lang_ref,
            query_ref,
        );

        // Two pad bytes after strQuery (offset 206..208) are arbitrary.
        let mut expected = EXECQUERY_STUB.to_vec();
        for b in &mut expected[206..208] {
            *b = 0;
        }
        assert_eq!(stub, expected);
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
