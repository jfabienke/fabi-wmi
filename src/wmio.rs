//! MS-WMIO decoding: turn the objects returned by
//! IEnumWbemClassObject::Next into JSON.
//!
//! Each returned IWbemClassObject is an OBJREF_CUSTOM wrapping a WMIO encoding
//! unit. Instances are decoded, decorated or not, with scalar and array values
//! of every CIM type, embedded objects, and NULL / class-default handling from
//! the NdTable. Class definitions and per-property instance qualifiers are
//! rejected as unsupported rather than guessed at.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WmioError {
    #[error("malformed WMIO data")]
    Malformed,
    #[error("unexpected custom marshaler CLSID")]
    NotWbemObject,
    #[error("bad WMIO signature {0:#010x}")]
    BadSignature(u32),
    #[error("WMIO object has an unsupported shape (decoration or per-property qualifiers)")]
    Unsupported,
    #[error("CIM type {0:#06x} not yet decoded")]
    UnsupportedType(u16),
    #[error("enumeration failed (hr={0:#010x})")]
    Hresult(u32),
}

/// HRESULT from IEnumWbemClassObject::Next when fewer objects than requested
/// were returned, i.e. the enumeration is complete (MS-WMI 2.2.11).
const WBEM_S_FALSE: u32 = 0x0000_0001;

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
    // The call's HRESULT is the last 4 bytes; WBEM_S_FALSE ends the
    // enumeration and is not an error.
    let hr = stub
        .len()
        .checked_sub(4)
        .map(|o| rd_u32(stub, o))
        .ok_or(WmioError::Malformed)??;
    if hr != 0 && hr != WBEM_S_FALSE {
        return Err(WmioError::Hresult(hr));
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
        // NDR aligns the next pointee to 4 bytes.
        off = (off + cnt + 3) & !3;
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

const OBJECT_FLAG_INSTANCE: u8 = 0x02;
const OBJECT_FLAG_DECORATED: u8 = 0x04;
/// Nesting limit for embedded objects (CIM_OBJECT values), so a hostile
/// response cannot exhaust the stack.
const MAX_OBJECT_DEPTH: usize = 8;

/// The parsed header of an ObjectBlock (MS-WMIO 2.2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ObjectHeader {
    /// ObjectFlags 0x02: the object is a CIM instance (0x01 would be a class).
    pub is_instance: bool,
    /// ObjectFlags 0x04: a Decoration (server and namespace names) follows.
    pub has_decoration: bool,
    /// Offset of the class part, after ObjectFlags and any Decoration.
    pub body_offset: usize,
}

/// Parse the ENCODING_UNIT of one WMIO blob and the header of its ObjectBlock.
pub(crate) fn parse_object_header(wmio: &[u8]) -> Result<ObjectHeader, WmioError> {
    let signature = rd_u32(wmio, 0)?;
    if signature != WMIO_SIGNATURE {
        return Err(WmioError::BadSignature(signature));
    }
    let object_encoding_length = rd_u32(wmio, 4)? as usize;
    if object_encoding_length != wmio.len() - 8 {
        return Err(WmioError::Malformed);
    }
    parse_object_block_header(wmio, 8)
}

/// Parse ObjectFlags at `at` and skip the Decoration (MS-WMIO 2.2.7: two
/// ENCODED_STRINGs, DecServerName and DecNamespaceName) when present.
fn parse_object_block_header(buf: &[u8], at: usize) -> Result<ObjectHeader, WmioError> {
    let flags = *buf.get(at).ok_or(WmioError::Malformed)?;
    let has_decoration = flags & OBJECT_FLAG_DECORATED != 0;
    let mut body_offset = at + 1;
    if has_decoration {
        body_offset = skip_encoded_string(buf, body_offset)?;
        body_offset = skip_encoded_string(buf, body_offset)?;
    }
    Ok(ObjectHeader {
        is_instance: flags & OBJECT_FLAG_INSTANCE != 0,
        has_decoration,
        body_offset,
    })
}

/// Offset just past the ENCODED_STRING at `off` (flag byte, characters, NUL).
fn skip_encoded_string(buf: &[u8], off: usize) -> Result<usize, WmioError> {
    let rest = buf.get(off + 1..).ok_or(WmioError::Malformed)?;
    let consumed = match buf[off] {
        0 => rest.iter().position(|&b| b == 0).map(|n| n + 1),
        1 => rest
            .as_chunks::<2>()
            .0
            .iter()
            .position(|c| *c == [0, 0])
            .map(|n| 2 * n + 2),
        _ => None,
    };
    Ok(off + 1 + consumed.ok_or(WmioError::Malformed)?)
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
    /// CIM base type with the array/inherited flags masked off.
    pub cim_type: u16,
    /// Whether the property is an array (CIM type flag 0x2000).
    pub is_array: bool,
    /// Declaration order, used to index the NdTable null/default bits.
    pub order: usize,
    /// Byte offset of this property's value within the ValueTable.
    pub value_table_offset: usize,
}

/// The decoded class part: the class name, its properties, and the two tables
/// an instance needs to read values (the class heap and the value-table region).
#[derive(Debug, Clone)]
pub(crate) struct ClassPart {
    #[allow(dead_code)] // not emitted in rows yet (no __CLASS); asserted by tests
    pub class_name: String,
    pub properties: Vec<PropertyDesc>,
    pub nd_value_table_len: usize,
    /// Byte length of the whole class part (from ClassHeader.EncodingLength).
    pub encoding_length: usize,
    /// Offset of the class NdTable + ValueTable (the class's default values).
    pub nd_value_table_at: usize,
    /// Offset and length of the ClassHeap the default values refer into.
    pub heap_at: usize,
    pub heap_len: usize,
}

/// CIM base types (MS-WMIO 2.2.7). Flags 0x2000 (array) and 0x4000 (BYREF)/
/// inherited are masked off by the caller.
pub(crate) const CIM_SINT16: u16 = 2;
pub(crate) const CIM_SINT32: u16 = 3;
pub(crate) const CIM_REAL32: u16 = 4;
pub(crate) const CIM_REAL64: u16 = 5;
pub(crate) const CIM_STRING: u16 = 8;
pub(crate) const CIM_BOOLEAN: u16 = 11;
pub(crate) const CIM_OBJECT: u16 = 13;
pub(crate) const CIM_SINT8: u16 = 16;
pub(crate) const CIM_UINT8: u16 = 17;
pub(crate) const CIM_UINT16: u16 = 18;
pub(crate) const CIM_UINT32: u16 = 19;
pub(crate) const CIM_SINT64: u16 = 20;
pub(crate) const CIM_UINT64: u16 = 21;
pub(crate) const CIM_DATETIME: u16 = 101;
pub(crate) const CIM_REFERENCE: u16 = 102;
pub(crate) const CIM_CHAR16: u16 = 103;

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
    let nd_value_table_at = off;
    off = off
        .checked_add(nd_value_table_len)
        .filter(|&o| o <= wmio.len())
        .ok_or(WmioError::Malformed)?;
    let heap_len = (rd_u32(wmio, off)? & 0x7fff_ffff) as usize;
    off += 4;
    let heap_at = off;
    let heap = wmio.get(off..off + heap_len).ok_or(WmioError::Malformed)?;

    let class_name = encoded_string(heap, class_name_ref)?;
    let mut properties = Vec::with_capacity(property_count);
    for (name_ref, info_ref) in lookups {
        let name = encoded_string(heap, name_ref)?;
        // PropertyInfo: Type(4), DeclarationOrder(2), ValueTableOffset(4), ...
        let raw_type = rd_u32(heap, info_ref)?;
        let order = u16::from_le_bytes(
            heap.get(info_ref + 4..info_ref + 6)
                .ok_or(WmioError::Malformed)?
                .try_into()
                .unwrap(),
        ) as usize;
        let value_table_offset = rd_u32(heap, info_ref + 6)? as usize;
        properties.push(PropertyDesc {
            name,
            cim_type: (raw_type & 0x1fff) as u16,
            is_array: raw_type & 0x2000 != 0,
            order,
            value_table_offset,
        });
    }
    Ok(ClassPart {
        class_name,
        properties,
        nd_value_table_len,
        encoding_length,
        nd_value_table_at,
        heap_at,
        heap_len,
    })
}

/// Decode every object returned by an IEnumWbemClassObject::Next response into
/// one JSON object per row — the entry point the WMI client calls on each batch.
pub(crate) fn decode_next_response(stub: &[u8]) -> Result<Vec<serde_json::Value>, WmioError> {
    parse_next_response(stub)?
        .iter()
        .map(|blob| decode_object(&blob.data))
        .collect()
}

/// Decode one WMIO encoding unit (a CIM instance) into a JSON object of its
/// property values. System properties (`__SERVER`, ...) are not included.
pub(crate) fn decode_object(wmio: &[u8]) -> Result<serde_json::Value, WmioError> {
    let header = parse_object_header(wmio)?;
    decode_instance(wmio, header, 0)
}

/// Decode the instance whose ObjectBlock header is `header`, within `buf`.
fn decode_instance(
    buf: &[u8],
    header: ObjectHeader,
    depth: usize,
) -> Result<serde_json::Value, WmioError> {
    if !header.is_instance {
        return Err(WmioError::Unsupported);
    }
    let class = parse_class_part(buf, header.body_offset)?;
    let class_heap = &buf[class.heap_at..class.heap_at + class.heap_len];

    // InstanceType: EncodingLength(4), InstanceFlags(1), InstanceClassName(4),
    // then NdTable + ValueTable, InstanceQualifierSet, InstanceHeap.
    let instance_start = header.body_offset + class.encoding_length;
    let nd_value_table_start = instance_start + 9;
    let nd_size = (class.properties.len().saturating_sub(1)) / 4 + 1;
    let value_table_start = nd_value_table_start + nd_size;
    let nd_table = buf
        .get(nd_value_table_start..nd_value_table_start + nd_size)
        .ok_or(WmioError::Malformed)?;
    let class_nd_table = buf
        .get(class.nd_value_table_at..class.nd_value_table_at + nd_size)
        .ok_or(WmioError::Malformed)?;

    // InstanceQualifierSet = QualifierSet (length-prefixed) + a 1-byte
    // InstancePropQualifierSet flag (2 would carry per-property qualifiers).
    let after_nd_value_table = nd_value_table_start + class.nd_value_table_len;
    let qualifier_set_len = rd_u32(buf, after_nd_value_table)? as usize;
    let prop_qual_flag = *buf
        .get(after_nd_value_table + qualifier_set_len)
        .ok_or(WmioError::Malformed)?;
    if prop_qual_flag == 2 {
        return Err(WmioError::Unsupported);
    }
    let heap_start = after_nd_value_table + qualifier_set_len + 1;
    let heap_len = (rd_u32(buf, heap_start)? & 0x7fff_ffff) as usize;
    let instance_heap = buf
        .get(heap_start + 4..heap_start + 4 + heap_len)
        .ok_or(WmioError::Malformed)?;

    // NdTable (MS-WMIO 2.2.26): two bits per property in declaration order;
    // 0b01 = the value is NULL, 0b10 = the value is the class default.
    let nd_bits = |table: &[u8], order: usize| (table[order / 4] >> (2 * (order % 4))) & 0b11;
    let mut map = serde_json::Map::with_capacity(class.properties.len());
    for p in &class.properties {
        if p.order >= class.properties.len() {
            return Err(WmioError::Malformed);
        }
        let nd = nd_bits(nd_table, p.order);
        let value = if nd & 0b01 != 0 {
            serde_json::Value::Null
        } else if nd & 0b10 != 0 {
            if nd_bits(class_nd_table, p.order) & 0b01 != 0 {
                serde_json::Value::Null
            } else {
                let at = class.nd_value_table_at + nd_size + p.value_table_offset;
                decode_value(p.cim_type, p.is_array, buf, at, class_heap, depth)?
            }
        } else {
            let at = value_table_start + p.value_table_offset;
            decode_value(p.cim_type, p.is_array, buf, at, instance_heap, depth)?
        };
        map.insert(p.name.clone(), value);
    }
    Ok(serde_json::Value::Object(map))
}

/// Read a fixed-size little-endian value from the ValueTable.
fn vt_bytes<const N: usize>(wmio: &[u8], at: usize) -> Result<[u8; N], WmioError> {
    wmio.get(at..at + N)
        .map(|s| s.try_into().unwrap())
        .ok_or(WmioError::Malformed)
}

fn json_f64(v: f64) -> serde_json::Value {
    serde_json::Number::from_f64(v).map_or(serde_json::Value::Null, serde_json::Value::Number)
}

/// Size of one value of `cim_type` in a ValueTable or array body: the inline
/// size for numbers, 4 for heap references (strings, datetimes, references,
/// embedded objects). None for types this decoder does not know.
fn value_size(cim_type: u16) -> Option<usize> {
    match cim_type {
        CIM_SINT8 | CIM_UINT8 => Some(1),
        CIM_SINT16 | CIM_UINT16 | CIM_BOOLEAN | CIM_CHAR16 => Some(2),
        CIM_SINT32 | CIM_UINT32 | CIM_REAL32 => Some(4),
        CIM_STRING | CIM_DATETIME | CIM_REFERENCE | CIM_OBJECT => Some(4),
        CIM_SINT64 | CIM_UINT64 | CIM_REAL64 => Some(8),
        _ => None,
    }
}

/// Decode one property value. `value_at` is its offset within `buf` (a
/// ValueTable); heap references resolve against `heap`. An array is a heap
/// reference to a count followed by that many values laid out as in a
/// ValueTable, whose own references point into the same heap.
fn decode_value(
    cim_type: u16,
    is_array: bool,
    buf: &[u8],
    value_at: usize,
    heap: &[u8],
    depth: usize,
) -> Result<serde_json::Value, WmioError> {
    if !is_array {
        return decode_scalar(cim_type, buf, value_at, heap, depth);
    }
    let size = value_size(cim_type).ok_or(WmioError::UnsupportedType(0x2000 | cim_type))?;
    let array_at = rd_u32(buf, value_at)? as usize;
    let count = rd_u32(heap, array_at)? as usize;
    let first = array_at + 4;
    count
        .checked_mul(size)
        .and_then(|n| n.checked_add(first))
        .filter(|&end| end <= heap.len())
        .ok_or(WmioError::Malformed)?;
    (0..count)
        .map(|i| decode_scalar(cim_type, heap, first + i * size, heap, depth))
        .collect::<Result<Vec<_>, _>>()
        .map(serde_json::Value::Array)
}

/// Decode a single (non-array) value of `cim_type` stored at `at` in `buf`.
fn decode_scalar(
    cim_type: u16,
    buf: &[u8],
    at: usize,
    heap: &[u8],
    depth: usize,
) -> Result<serde_json::Value, WmioError> {
    use serde_json::Value;
    let v = match cim_type {
        CIM_BOOLEAN => Value::Bool(u16::from_le_bytes(vt_bytes(buf, at)?) != 0),
        CIM_SINT8 => Value::from(i8::from_le_bytes(vt_bytes(buf, at)?)),
        CIM_UINT8 => Value::from(u8::from_le_bytes(vt_bytes(buf, at)?)),
        CIM_SINT16 => Value::from(i16::from_le_bytes(vt_bytes(buf, at)?)),
        CIM_UINT16 => Value::from(u16::from_le_bytes(vt_bytes(buf, at)?)),
        CIM_SINT32 => Value::from(i32::from_le_bytes(vt_bytes(buf, at)?)),
        CIM_UINT32 => Value::from(u32::from_le_bytes(vt_bytes(buf, at)?)),
        CIM_SINT64 => Value::from(i64::from_le_bytes(vt_bytes(buf, at)?)),
        CIM_UINT64 => Value::from(u64::from_le_bytes(vt_bytes(buf, at)?)),
        CIM_REAL32 => json_f64(f32::from_le_bytes(vt_bytes(buf, at)?) as f64),
        CIM_REAL64 => json_f64(f64::from_le_bytes(vt_bytes(buf, at)?)),
        CIM_CHAR16 => {
            let c = u16::from_le_bytes(vt_bytes(buf, at)?);
            Value::String(String::from_utf16_lossy(&[c]))
        }
        // Heap-referenced scalars: the value is a 4-byte heap offset.
        CIM_STRING | CIM_DATETIME | CIM_REFERENCE => {
            let heap_ref = rd_u32(buf, at)? as usize;
            Value::String(encoded_string(heap, heap_ref)?)
        }
        // Embedded object: a heap offset to ObjectEncodingLength + ObjectBlock.
        CIM_OBJECT => {
            if depth >= MAX_OBJECT_DEPTH {
                return Err(WmioError::Malformed);
            }
            let heap_ref = rd_u32(buf, at)? as usize;
            let len = rd_u32(heap, heap_ref)? as usize;
            let block = heap
                .get(heap_ref + 4..heap_ref + 4 + len)
                .ok_or(WmioError::Malformed)?;
            decode_instance(block, parse_object_block_header(block, 0)?, depth + 1)?
        }
        other => return Err(WmioError::UnsupportedType(other)),
    };
    Ok(v)
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
        assert_eq!(decode_next_response(&stub).unwrap().len(), 1);
    }

    #[test]
    fn parse_next_response_reports_failure_hresult() {
        let mut stub = NEXT_END;
        stub[24..].copy_from_slice(&0x8004_1010u32.to_le_bytes()); // WBEM_E_INVALID_CLASS
        assert_eq!(
            parse_next_response(&stub),
            Err(WmioError::Hresult(0x8004_1010))
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
        let rows = decode_next_response(&stub).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], rows[1]);
    }

    #[test]
    fn decode_next_response_returns_one_row_per_object() {
        let rows = decode_next_response(NEXT_RESULT).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["Name"], "DC01");
        assert_eq!(rows[0]["Domain"], "test.local");
    }

    #[test]
    fn decode_object_produces_the_query_row_json() {
        let blobs = parse_next_response(NEXT_RESULT).unwrap();
        let value = decode_object(&blobs[0].data).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "Domain": "test.local",
                "Manufacturer": "QEMU",
                "Model": "Standard PC (Q35 + ICH9, 2009)",
                "Name": "DC01",
            })
        );
    }

    /// `SELECT * FROM Win32_Service WHERE Name = "Winmgmt"` from Windows Server
    /// 2022: a decorated instance (ObjectFlags 0x06). Non-sensitive lab data.
    const NEXT_SERVICE: &[u8] = include_bytes!("testdata/next_response_service.bin");
    /// `SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE`
    /// from the same lab VM (QEMU NAT addressing): string and integer arrays.
    const NEXT_NIC: &[u8] = include_bytes!("testdata/next_response_nic.bin");

    fn only_row(stub: &[u8]) -> serde_json::Value {
        let mut rows = decode_next_response(stub).unwrap();
        assert_eq!(rows.len(), 1);
        rows.pop().unwrap()
    }

    #[test]
    fn parse_object_header_skips_decoration() {
        let blobs = parse_next_response(NEXT_SERVICE).unwrap();
        let hdr = parse_object_header(&blobs[0].data).unwrap();
        assert!(hdr.is_instance && hdr.has_decoration);
        // ObjectFlags at 8, then "\0WIN2022WMI\0" and "\0root\\cimv2\0".
        assert_eq!(hdr.body_offset, 9 + 12 + 12);
    }

    #[test]
    fn decode_object_decodes_decorated_select_star_instance() {
        // Values cross-checked against Get-WmiObject on the same host.
        let row = only_row(NEXT_SERVICE);
        assert_eq!(row.as_object().unwrap().len(), 26);
        assert_eq!(row["Name"], "Winmgmt");
        assert_eq!(row["State"], "Running");
        assert_eq!(row["StartMode"], "Auto");
        assert_eq!(
            row["PathName"],
            r"C:\Windows\system32\svchost.exe -k winmgmt"
        );
        assert_eq!(row["ProcessId"], 1784);
        assert_eq!(row["AcceptStop"], true);
        assert_eq!(row["DelayedAutoStart"], false);
        assert_eq!(row["InstallDate"], serde_json::Value::Null);
        assert_eq!(row["SystemName"], "WIN2022WMI");
    }

    #[test]
    fn decode_object_decodes_arrays() {
        use serde_json::json;
        let row = only_row(NEXT_NIC);
        assert_eq!(row.as_object().unwrap().len(), 61);
        assert_eq!(
            row["IPAddress"],
            json!([
                "10.0.2.15",
                "fe80::fc58:d11d:18fe:55b3",
                "fec0::fc58:d11d:18fe:55b3"
            ])
        );
        assert_eq!(row["IPSubnet"], json!(["255.255.255.0", "64", "64"]));
        assert_eq!(row["DefaultIPGateway"], json!(["10.0.2.2", "fe80::2"]));
        assert_eq!(row["GatewayCostMetric"], json!([0, 256])); // uint16[]
        assert_eq!(row["IPSecPermitTCPPorts"], json!([])); // empty string[]
        assert_eq!(row["IPXFrameType"], json!(null)); // NULL uint32[]
        assert_eq!(row["DHCPLeaseObtained"], "20261019223402.000000+120");
        assert_eq!(row["MACAddress"], "52:54:00:12:34:56");
        assert_eq!(row["IPEnabled"], true);
        assert_eq!(row["Index"], 1);
    }

    /// `SELECT * FROM __Win32Provider WHERE Name = "CIMWin32"`: three
    /// properties (Pure, PerLocale-/PerUserInitialization) carry NdTable 0b10,
    /// i.e. take their value from the class default rather than the instance.
    const NEXT_PROVIDER: &[u8] = include_bytes!("testdata/next_response_provider.bin");

    #[test]
    fn decode_object_takes_class_defaults() {
        // Matches Get-WmiObject on the same host, field for field.
        let expected = serde_json::json!({
            "CLSID": "{d63a5850-8f16-11cf-9f47-00aa00bf345c}",
            "ClientLoadableCLSID": null, "Concurrency": null, "DefaultMachineName": null,
            "Enabled": null, "HostingModel": "NetworkServiceHost", "ImpersonationLevel": 1,
            "InitializationReentrancy": 0, "InitializationTimeoutInterval": null,
            "InitializeAsAdminFirst": null, "Name": "CIMWin32",
            "OperationTimeoutInterval": null, "PerLocaleInitialization": false,
            "PerUserInitialization": false, "Pure": true, "SecurityDescriptor": null,
            "SupportsExplicitShutdown": null, "SupportsExtendedStatus": null,
            "SupportsQuotas": null, "SupportsSendStatus": null, "SupportsShutdown": null,
            "SupportsThrottling": null, "UnloadTimeout": null, "Version": null,
        });
        assert_eq!(only_row(NEXT_PROVIDER), expected);
    }

    #[test]
    fn decode_value_decodes_embedded_object() {
        // A CIM_OBJECT value is a heap ref to ObjectEncodingLength + ObjectBlock.
        // Embed the service instance's ObjectBlock and expect the same row.
        let blobs = parse_next_response(NEXT_SERVICE).unwrap();
        let block = &blobs[0].data[8..];
        let mut heap = vec![0u8; 3]; // embedded object not at heap offset 0
        heap.extend_from_slice(&(block.len() as u32).to_le_bytes());
        heap.extend_from_slice(block);
        let value = decode_value(CIM_OBJECT, false, &3u32.to_le_bytes(), 0, &heap, 0).unwrap();
        assert_eq!(value, only_row(NEXT_SERVICE));
        assert_eq!(
            decode_value(
                CIM_OBJECT,
                false,
                &3u32.to_le_bytes(),
                0,
                &heap,
                MAX_OBJECT_DEPTH
            ),
            Err(WmioError::Malformed)
        );
    }

    #[test]
    fn decode_value_rejects_array_running_past_heap() {
        // count = 3 uint32s but the heap holds only one.
        let mut heap = 3u32.to_le_bytes().to_vec();
        heap.extend_from_slice(&7u32.to_le_bytes());
        assert_eq!(
            decode_value(CIM_UINT32, true, &0u32.to_le_bytes(), 0, &heap, 0),
            Err(WmioError::Malformed)
        );
        heap[0] = 1;
        assert_eq!(
            decode_value(CIM_UINT32, true, &0u32.to_le_bytes(), 0, &heap, 0),
            Ok(serde_json::json!([7]))
        );
    }

    #[test]
    fn decoders_never_panic_on_truncated_objects() {
        // Windows zero-pads an instance encoding past the end of its heap
        // (service: data ends at 6271 of 6611 bytes, NIC: 12184 of 12263), so
        // cuts inside that padding still decode; any cut into data must error.
        for (stub, data_end) in [(NEXT_SERVICE, 6271), (NEXT_NIC, 12184)] {
            let blob = &parse_next_response(stub).unwrap()[0].data;
            for len in 8..blob.len() {
                let mut cut = blob[..len].to_vec();
                cut[4..8].copy_from_slice(&((len - 8) as u32).to_le_bytes());
                let decoded = decode_object(&cut);
                assert_eq!(decoded.is_ok(), len >= data_end, "len {len}");
            }
        }
    }

    fn decode_inline(cim_type: u16, bytes: &[u8]) -> serde_json::Value {
        decode_value(cim_type, false, bytes, 0, &[], 0).unwrap()
    }

    #[test]
    fn decode_value_handles_inline_scalars() {
        use serde_json::json;
        assert_eq!(decode_inline(CIM_BOOLEAN, &[0xff, 0xff]), json!(true));
        assert_eq!(decode_inline(CIM_BOOLEAN, &[0x00, 0x00]), json!(false));
        assert_eq!(decode_inline(CIM_SINT8, &[0xfe]), json!(-2));
        assert_eq!(decode_inline(CIM_UINT8, &[0xfe]), json!(254));
        assert_eq!(
            decode_inline(CIM_SINT16, &0i16.wrapping_sub(5).to_le_bytes()),
            json!(-5)
        );
        assert_eq!(
            decode_inline(CIM_UINT32, &4_000_000_000u32.to_le_bytes()),
            json!(4_000_000_000u64)
        );
        assert_eq!(
            decode_inline(CIM_SINT32, &(-1_000_000i32).to_le_bytes()),
            json!(-1_000_000)
        );
        assert_eq!(
            decode_inline(CIM_UINT64, &u64::MAX.to_le_bytes()),
            json!(u64::MAX)
        );
        assert_eq!(decode_inline(CIM_REAL64, &1.5f64.to_le_bytes()), json!(1.5));
        assert_eq!(
            decode_inline(CIM_CHAR16, &(b'Z' as u16).to_le_bytes()),
            json!("Z")
        );
    }

    #[test]
    fn decode_value_rejects_unknown_types() {
        assert_eq!(
            decode_value(0x63, false, &[0; 8], 0, &[], 0),
            Err(WmioError::UnsupportedType(0x63))
        );
        assert_eq!(
            decode_value(0x63, true, &[0; 4], 0, &[0; 4], 0),
            Err(WmioError::UnsupportedType(0x2063))
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
