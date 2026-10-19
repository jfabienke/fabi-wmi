//! MS-WMIO decoding: turn the objects returned by
//! IEnumWbemClassObject::Next into JSON.
//!
//! Built from the outside in. This first layer unwraps the Next response's
//! OBJREF_CUSTOM-marshaled IWbemClassObjects and validates each one's WMIO
//! ENCODING_UNIT / OBJECT_BLOCK header; the class/instance body decoding is
//! added on top.
#![allow(dead_code)]

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum WmioError {
    #[error("malformed WMIO data")]
    Malformed,
    #[error("unexpected custom marshaler CLSID")]
    NotWbemObject,
    #[error("bad WMIO signature {0:#010x}")]
    BadSignature(u32),
}

const OBJREF_SIGNATURE: &[u8; 4] = b"MEOW";
const OBJREF_CUSTOM: u32 = 0x4;
/// CLSID_WbemClassObject {4590F812-1D3A-11D0-891F-00AA004B2E24}, little-endian.
const CLSID_WBEM_CLASS_OBJECT: [u8; 16] = hex_literal::hex!("12f890453a1dd011891f00aa004b2e24");
/// MS-WMIO 2.2.1 encoding-unit signature.
const WMIO_SIGNATURE: u32 = 0x1234_5678;

fn rd_u32(b: &[u8], off: usize) -> Result<u32, WmioError> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .ok_or(WmioError::Malformed)
}

/// One IWbemClassObject returned from Next, as its raw MS-WMIO encoding unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WmioBlob {
    pub data: Vec<u8>,
}

/// Extract the WMIO encoding units of every object in an
/// IEnumWbemClassObject::Next response stub (ORPCTHAT, apObjects array,
/// puReturned, HRESULT). Each object is an OBJREF_CUSTOM wrapping the WMIO data.
pub(crate) fn parse_next_response(stub: &[u8]) -> Result<Vec<WmioBlob>, WmioError> {
    // The call's HRESULT is the last 4 bytes; WBEM_S_FALSE (0x40001) ends the
    // enumeration and is not an error.
    let hr = stub
        .len()
        .checked_sub(4)
        .map(|o| rd_u32(stub, o))
        .ok_or(WmioError::Malformed)??;
    if hr != 0 && hr != 0x0004_0001 {
        return Err(WmioError::Malformed);
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
        // MInterfacePointer: conformant struct { max_count, ulCntData, abData }.
        let _mp_max = rd_u32(stub, off)?;
        off += 4;
        let cnt = rd_u32(stub, off)? as usize;
        off += 4;
        let objref = stub.get(off..off + cnt).ok_or(WmioError::Malformed)?;
        off += cnt;
        blobs.push(WmioBlob {
            data: parse_objref_custom(objref)?.to_vec(),
        });
    }
    Ok(blobs)
}

/// Validate an OBJREF_CUSTOM for IWbemClassObject and return its WMIO payload.
fn parse_objref_custom(objref: &[u8]) -> Result<&[u8], WmioError> {
    // signature(4) flags(4) iid(16) clsid(16) cbExtension(4) size(4) pData[size]
    if objref.get(0..4) != Some(OBJREF_SIGNATURE) || rd_u32(objref, 4)? != OBJREF_CUSTOM {
        return Err(WmioError::Malformed);
    }
    if objref.get(24..40) != Some(&CLSID_WBEM_CLASS_OBJECT) {
        return Err(WmioError::NotWbemObject);
    }
    let size = rd_u32(objref, 44)? as usize;
    objref.get(48..48 + size).ok_or(WmioError::Malformed)
}

/// The parsed header of a WMIO encoding unit (MS-WMIO 2.2.1–2.2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ObjectHeader {
    /// False when the object is a CIM class definition (ObjectFlags bit 0x01).
    pub is_instance: bool,
    /// Whether a Decoration block (server/namespace) precedes the body.
    pub has_decoration: bool,
    /// Offset of the ObjectBlock body after ObjectFlags (and decoration).
    pub body_offset: usize,
}

/// Parse the ENCODING_UNIT and OBJECT_BLOCK flags of one WMIO blob.
pub(crate) fn parse_object_header(wmio: &[u8]) -> Result<ObjectHeader, WmioError> {
    let signature = rd_u32(wmio, 0)?;
    if signature != WMIO_SIGNATURE {
        return Err(WmioError::BadSignature(signature));
    }
    let _object_encoding_length = rd_u32(wmio, 4)?;
    let object_flags = *wmio.get(8).ok_or(WmioError::Malformed)?;
    let has_decoration = object_flags & 0x04 != 0;
    let is_instance = object_flags & 0x01 == 0;
    // ObjectFlags is one byte; the Decoration block, when present, follows.
    Ok(ObjectHeader {
        is_instance,
        has_decoration,
        body_offset: 9,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IEnumWbemClassObject::Next response the DC sent for the one-row query
    /// SELECT ... FROM Win32_ComputerSystem (cleartext stub). Non-sensitive.
    const NEXT_RESULT: &[u8] = include_bytes!("testdata/next_response_result.bin");

    #[test]
    fn parse_next_response_extracts_one_wmio_object() {
        let blobs = parse_next_response(NEXT_RESULT).unwrap();
        assert_eq!(blobs.len(), 1);
        // The WMIO encoding unit starts with the 0x12345678 signature.
        assert_eq!(&blobs[0].data[0..4], &WMIO_SIGNATURE.to_le_bytes());
        assert_eq!(blobs[0].data.len(), 12010);
    }

    #[test]
    fn parse_object_header_reports_instance() {
        let blobs = parse_next_response(NEXT_RESULT).unwrap();
        let hdr = parse_object_header(&blobs[0].data).unwrap();
        assert!(hdr.is_instance, "the result row is a CIM instance");
        assert!(!hdr.has_decoration);
    }

    #[test]
    fn parse_object_header_rejects_bad_signature() {
        let mut wmio = vec![0u8; 16];
        wmio[0..4].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        assert_eq!(
            parse_object_header(&wmio),
            Err(WmioError::BadSignature(0xdead_beef))
        );
    }

    #[test]
    fn parse_objref_custom_rejects_wrong_clsid() {
        let mut objref = vec![0u8; 48];
        objref[0..4].copy_from_slice(OBJREF_SIGNATURE);
        objref[4..8].copy_from_slice(&OBJREF_CUSTOM.to_le_bytes());
        // leave clsid zeroed -> not WbemClassObject
        assert_eq!(parse_objref_custom(&objref), Err(WmioError::NotWbemObject));
    }
}
