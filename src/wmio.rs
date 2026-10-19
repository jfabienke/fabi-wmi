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

/// Read an ENCODED_STRING (MS-WMIO 2.2.77) at `off` in a heap: a flag byte
/// (0 = ASCII, 1 = UTF-16LE) then a NUL-terminated string.
fn encoded_string(heap: &[u8], off: usize) -> Result<String, WmioError> {
    let flag = *heap.get(off).ok_or(WmioError::Malformed)?;
    let rest = heap.get(off + 1..).ok_or(WmioError::Malformed)?;
    match flag {
        0 => {
            let end = rest
                .iter()
                .position(|&b| b == 0)
                .ok_or(WmioError::Malformed)?;
            Ok(String::from_utf8_lossy(&rest[..end]).into_owned())
        }
        1 => {
            let (pairs, _) = rest.as_chunks::<2>();
            let units: Vec<u16> = pairs
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .take_while(|&u| u != 0)
                .collect();
            Ok(String::from_utf16_lossy(&units))
        }
        _ => Err(WmioError::Malformed),
    }
}

/// A property as described by the class part (MS-WMIO 2.2.19/2.2.21).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PropertyDesc {
    pub name: String,
    /// CIM type with the array/inherited flags masked off.
    pub cim_type: u16,
    /// Byte offset of this property's value within the ValueTable.
    pub value_table_offset: usize,
}

/// The decoded class part: the class name, its properties, and the two tables
/// an instance needs to read values (the class heap and the value-table region).
#[derive(Debug, Clone)]
pub(crate) struct ClassPart {
    pub class_name: String,
    pub properties: Vec<PropertyDesc>,
    pub nd_value_table_len: usize,
    /// Byte length of the whole class part (from ClassHeader.EncodingLength).
    pub encoding_length: usize,
}

/// CIM types we decode so far (MS-WMIO 2.2.7). Flags 0x2000 (array) and 0x4000
/// (BYREF)/inherited are masked off by the caller.
pub(crate) const CIM_STRING: u16 = 8;

/// Parse a CLASS_PART (MS-WMIO 2.2.15) at `start` within the WMIO blob.
fn parse_class_part(wmio: &[u8], start: usize) -> Result<ClassPart, WmioError> {
    let encoding_length = rd_u32(wmio, start)? as usize;
    let class_name_ref = rd_u32(wmio, start + 5)? as usize;
    let nd_value_table_len = rd_u32(wmio, start + 9)? as usize;

    let mut off = start + 13;
    // DerivationList and ClassQualifierSet are length-prefixed; skip them.
    for _ in 0..2 {
        let len = rd_u32(wmio, off)? as usize;
        off = off
            .checked_add(len)
            .filter(|&o| o <= wmio.len())
            .ok_or(WmioError::Malformed)?;
    }
    // PropertyLookupTable: count, then count * { NameRef, PropInfoRef }.
    let property_count = rd_u32(wmio, off)? as usize;
    off += 4;
    let mut lookups = Vec::with_capacity(property_count);
    for _ in 0..property_count {
        let name_ref = rd_u32(wmio, off)? as usize;
        let info_ref = rd_u32(wmio, off + 4)? as usize;
        off += 8;
        lookups.push((name_ref, info_ref));
    }
    // Skip NdTable+ValueTable to reach the ClassHeap.
    off = off
        .checked_add(nd_value_table_len)
        .filter(|&o| o <= wmio.len())
        .ok_or(WmioError::Malformed)?;
    let heap_len = (rd_u32(wmio, off)? & 0x7fff_ffff) as usize;
    off += 4;
    let heap = wmio.get(off..off + heap_len).ok_or(WmioError::Malformed)?;

    let class_name = encoded_string(heap, class_name_ref)?;
    let mut properties = Vec::with_capacity(property_count);
    for (name_ref, info_ref) in lookups {
        let name = encoded_string(heap, name_ref)?;
        // PropertyInfo: Type(4), DeclarationOrder(2), ValueTableOffset(4), ...
        let raw_type = rd_u32(heap, info_ref)?;
        let value_table_offset = rd_u32(heap, info_ref + 6)? as usize;
        properties.push(PropertyDesc {
            name,
            cim_type: (raw_type & 0x1fff) as u16,
            value_table_offset,
        });
    }
    Ok(ClassPart {
        class_name,
        properties,
        nd_value_table_len,
        encoding_length,
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
    fn parse_class_part_decodes_win32_computersystem() {
        let blobs = parse_next_response(NEXT_RESULT).unwrap();
        // Instance: ENCODING_UNIT(8) + ObjectFlags(1); CurrentClass.ClassPart at 9.
        let cp = parse_class_part(&blobs[0].data, 9).unwrap();
        assert_eq!(cp.class_name, "Win32_ComputerSystem");
        let got: Vec<(&str, u16, usize)> = cp
            .properties
            .iter()
            .map(|p| (p.name.as_str(), p.cim_type, p.value_table_offset))
            .collect();
        assert_eq!(
            got,
            vec![
                ("Domain", CIM_STRING, 0),
                ("Manufacturer", CIM_STRING, 4),
                ("Model", CIM_STRING, 8),
                ("Name", CIM_STRING, 12),
            ]
        );
    }

    #[test]
    fn encoded_string_reads_ascii_and_unicode() {
        let ascii = [0u8, b'A', b'B', b'C', 0];
        assert_eq!(encoded_string(&ascii, 0).unwrap(), "ABC");
        let uni = [1u8, b'A', 0, b'B', 0, 0, 0];
        assert_eq!(encoded_string(&uni, 0).unwrap(), "AB");
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
