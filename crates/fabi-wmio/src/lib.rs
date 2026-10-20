//! MS-WMIO decoding: turn raw MS-WMIO encoding units (`IWbemClassObject`
//! payloads) into JSON.
//!
//! Instances are decoded, decorated or not, with scalar and array values
//! of every CIM type, embedded objects, and NULL / class-default handling from
//! the NdTable. Class definitions and per-property instance qualifiers are
//! rejected as unsupported rather than guessed at.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WmioError {
    #[error("malformed WMIO data")]
    Malformed,
    #[error("bad WMIO signature {0:#010x}")]
    BadSignature(u32),
    #[error("WMIO object has an unsupported shape (decoration or per-property qualifiers)")]
    Unsupported,
    #[error("CIM type {0:#06x} not yet decoded")]
    UnsupportedType(u16),
}

/// MS-WMIO 2.2.1 encoding-unit signature.
pub const WMIO_SIGNATURE: u32 = 0x1234_5678;

fn rd_u32(b: &[u8], off: usize) -> Result<u32, WmioError> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .ok_or(WmioError::Malformed)
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
pub const CIM_SINT16: u16 = 2;
pub const CIM_SINT32: u16 = 3;
pub const CIM_REAL32: u16 = 4;
pub const CIM_REAL64: u16 = 5;
pub const CIM_STRING: u16 = 8;
pub const CIM_BOOLEAN: u16 = 11;
pub const CIM_OBJECT: u16 = 13;
pub const CIM_SINT8: u16 = 16;
pub const CIM_UINT8: u16 = 17;
pub const CIM_UINT16: u16 = 18;
pub const CIM_UINT32: u16 = 19;
pub const CIM_SINT64: u16 = 20;
pub const CIM_UINT64: u16 = 21;
pub const CIM_DATETIME: u16 = 101;
pub const CIM_REFERENCE: u16 = 102;
pub const CIM_CHAR16: u16 = 103;

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

/// Decode one WMIO encoding unit (a CIM instance) into a JSON object of its
/// property values. System properties (`__SERVER`, ...) are not included.
pub fn decode_object(wmio: &[u8]) -> Result<serde_json::Value, WmioError> {
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

/// Write an `ENCODED_STRING` (MS-WMIO 2.2.77) to `heap` and return its offset.
/// Uses compact ASCII (flag `0`) when every character is non-NUL ASCII, else
/// UTF-16LE (flag `1`).
fn push_encoded_string(heap: &mut Vec<u8>, s: &str) -> u32 {
    let offset = heap.len() as u32;
    if s.bytes().all(|b| b != 0 && b < 0x80) {
        heap.push(0);
        heap.extend_from_slice(s.as_bytes());
        heap.push(0);
    } else {
        heap.push(1);
        for u in s.encode_utf16() {
            heap.extend_from_slice(&u.to_le_bytes());
        }
        heap.extend_from_slice(&0u16.to_le_bytes());
    }
    offset
}

/// Encode a scalar JSON value of `cim_type` into `slot` (in a ValueTable or
/// array body) and `heap`.
fn encode_scalar(
    cim_type: u16,
    val: &serde_json::Value,
    slot: &mut [u8],
    heap: &mut Vec<u8>,
) -> Result<(), WmioError> {
    let as_i64 = |v: &serde_json::Value| {
        v.as_i64()
            .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
    };
    let as_u64 = |v: &serde_json::Value| {
        v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
    };
    let as_f64 = |v: &serde_json::Value| {
        v.as_f64()
            .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
    };

    match cim_type {
        CIM_BOOLEAN => {
            let b = val.as_bool().ok_or(WmioError::UnsupportedType(cim_type))?;
            let word: u16 = if b { 0xffff } else { 0x0000 };
            slot[..2].copy_from_slice(&word.to_le_bytes());
        }
        CIM_SINT8 => {
            let n = as_i64(val)
                .and_then(|v| i8::try_from(v).ok())
                .ok_or(WmioError::UnsupportedType(cim_type))?;
            slot[..1].copy_from_slice(&n.to_le_bytes());
        }
        CIM_UINT8 => {
            let n = as_u64(val)
                .and_then(|v| u8::try_from(v).ok())
                .ok_or(WmioError::UnsupportedType(cim_type))?;
            slot[..1].copy_from_slice(&n.to_le_bytes());
        }
        CIM_SINT16 => {
            let n = as_i64(val)
                .and_then(|v| i16::try_from(v).ok())
                .ok_or(WmioError::UnsupportedType(cim_type))?;
            slot[..2].copy_from_slice(&n.to_le_bytes());
        }
        CIM_UINT16 => {
            let n = as_u64(val)
                .and_then(|v| u16::try_from(v).ok())
                .ok_or(WmioError::UnsupportedType(cim_type))?;
            slot[..2].copy_from_slice(&n.to_le_bytes());
        }
        CIM_SINT32 => {
            let n = as_i64(val)
                .and_then(|v| i32::try_from(v).ok())
                .ok_or(WmioError::UnsupportedType(cim_type))?;
            slot[..4].copy_from_slice(&n.to_le_bytes());
        }
        CIM_UINT32 => {
            let n = as_u64(val)
                .and_then(|v| u32::try_from(v).ok())
                .ok_or(WmioError::UnsupportedType(cim_type))?;
            slot[..4].copy_from_slice(&n.to_le_bytes());
        }
        CIM_SINT64 => {
            let n = as_i64(val).ok_or(WmioError::UnsupportedType(cim_type))?;
            slot[..8].copy_from_slice(&n.to_le_bytes());
        }
        CIM_UINT64 => {
            let n = as_u64(val).ok_or(WmioError::UnsupportedType(cim_type))?;
            slot[..8].copy_from_slice(&n.to_le_bytes());
        }
        CIM_REAL32 => {
            let n = as_f64(val).ok_or(WmioError::UnsupportedType(cim_type))? as f32;
            slot[..4].copy_from_slice(&n.to_le_bytes());
        }
        CIM_REAL64 => {
            let n = as_f64(val).ok_or(WmioError::UnsupportedType(cim_type))?;
            slot[..8].copy_from_slice(&n.to_le_bytes());
        }
        CIM_CHAR16 => {
            let ch = if let Some(s) = val.as_str() {
                let mut it = s.encode_utf16();
                let first = it.next().ok_or(WmioError::UnsupportedType(cim_type))?;
                if it.next().is_some() {
                    return Err(WmioError::UnsupportedType(cim_type));
                }
                first
            } else {
                as_u64(val)
                    .and_then(|v| u16::try_from(v).ok())
                    .ok_or(WmioError::UnsupportedType(cim_type))?
            };
            slot[..2].copy_from_slice(&ch.to_le_bytes());
        }
        CIM_STRING | CIM_DATETIME | CIM_REFERENCE => {
            let s = val.as_str().ok_or(WmioError::UnsupportedType(cim_type))?;
            let heap_ref = push_encoded_string(heap, s);
            slot[..4].copy_from_slice(&heap_ref.to_le_bytes());
        }
        other => return Err(WmioError::UnsupportedType(other)),
    }
    Ok(())
}

/// Encode a property value (scalar or array) into `value_table` at `value_at`.
fn encode_value(
    cim_type: u16,
    is_array: bool,
    val: &serde_json::Value,
    value_table: &mut [u8],
    value_at: usize,
    heap: &mut Vec<u8>,
) -> Result<(), WmioError> {
    let elem_size = value_size(cim_type).ok_or(WmioError::UnsupportedType(if is_array {
        0x2000 | cim_type
    } else {
        cim_type
    }))?;
    if !is_array {
        let slot = value_table
            .get_mut(value_at..value_at + elem_size)
            .ok_or(WmioError::Malformed)?;
        return encode_scalar(cim_type, val, slot, heap);
    }
    let arr = val
        .as_array()
        .ok_or(WmioError::UnsupportedType(0x2000 | cim_type))?;
    let total_elems_bytes = arr
        .len()
        .checked_mul(elem_size)
        .ok_or(WmioError::Malformed)?;
    let array_ref = heap.len() as u32;
    let slot = value_table
        .get_mut(value_at..value_at + 4)
        .ok_or(WmioError::Malformed)?;
    slot.copy_from_slice(&array_ref.to_le_bytes());

    // Reserve array header + elements in `heap` first so any string elements
    // appended afterwards land after the array body.
    heap.extend_from_slice(&(arr.len() as u32).to_le_bytes());
    let body_start = heap.len();
    heap.resize(body_start + total_elems_bytes, 0);
    for (i, item) in arr.iter().enumerate() {
        let mut elem_slot = vec![0u8; elem_size];
        encode_scalar(cim_type, item, &mut elem_slot, heap)?;
        let at = body_start + i * elem_size;
        heap[at..at + elem_size].copy_from_slice(&elem_slot);
    }
    Ok(())
}

/// Build an MS-WMIO instance `EncodingUnit` from any class or template instance
/// `EncodingUnit` (`template_wmio`), setting the properties present in `props`
/// (matched case-insensitively) and marking unspecified properties as
/// class-default (`0b11`).
pub fn spawn_instance(
    template_wmio: &[u8],
    props: &serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<u8>, WmioError> {
    let header = parse_object_header(template_wmio)?;
    let class = parse_class_part(template_wmio, header.body_offset)?;
    let class_part_bytes = template_wmio
        .get(header.body_offset..header.body_offset + class.encoding_length)
        .ok_or(WmioError::Malformed)?;

    let nd_size = if class.properties.is_empty() {
        0
    } else {
        (class.properties.len() - 1) / 4 + 1
    };
    let value_table_len = class
        .nd_value_table_len
        .checked_sub(nd_size)
        .ok_or(WmioError::Malformed)?;
    let mut nd_table = vec![0u8; nd_size];
    let mut value_table = vec![0u8; value_table_len];
    let mut instance_heap = Vec::new();
    let class_name_ref = push_encoded_string(&mut instance_heap, &class.class_name);

    let set_nd_bits = |table: &mut [u8], order: usize, bits: u8| {
        let shift = 2 * (order % 4);
        table[order / 4] = (table[order / 4] & !(0b11 << shift)) | ((bits & 0b11) << shift);
    };

    for p in &class.properties {
        if p.order >= class.properties.len() {
            return Err(WmioError::Malformed);
        }
        let found = props.get(&p.name).or_else(|| {
            props
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(&p.name))
                .map(|(_, v)| v)
        });
        match found {
            None => set_nd_bits(&mut nd_table, p.order, 0b11), // NULL + inherited default
            Some(serde_json::Value::Null) => set_nd_bits(&mut nd_table, p.order, 0b01), // NULL
            Some(val) => {
                set_nd_bits(&mut nd_table, p.order, 0b00);
                encode_value(
                    p.cim_type,
                    p.is_array,
                    val,
                    &mut value_table,
                    p.value_table_offset,
                    &mut instance_heap,
                )?;
            }
        }
    }

    // InstanceType (MS-WMIO 2.2.54):
    // EncodingLength(4) + InstanceFlags(1) + InstanceClassName(4) +
    // NdTable + ValueTable + InstanceQualifierSet(4 + 1) + InstanceHeap(4 + len).
    let instance_encoding_len = 9 + class.nd_value_table_len + 4 + 1 + 4 + instance_heap.len();
    let object_encoding_len = 1 + class_part_bytes.len() + instance_encoding_len;
    let mut out = Vec::with_capacity(8 + object_encoding_len);
    out.extend_from_slice(&WMIO_SIGNATURE.to_le_bytes());
    out.extend_from_slice(&(object_encoding_len as u32).to_le_bytes());
    out.push(OBJECT_FLAG_INSTANCE);
    out.extend_from_slice(class_part_bytes);
    out.extend_from_slice(&(instance_encoding_len as u32).to_le_bytes());
    out.push(0); // InstanceFlags
    out.extend_from_slice(&class_name_ref.to_le_bytes());
    out.extend_from_slice(&nd_table);
    out.extend_from_slice(&value_table);
    out.extend_from_slice(&4u32.to_le_bytes()); // empty QualifierSet
    out.push(1); // InstancePropQualifierSet flag = 1 (no per-property qualifiers)
    out.extend_from_slice(&((instance_heap.len() as u32) | 0x8000_0000).to_le_bytes());
    out.extend_from_slice(&instance_heap);
    Ok(out)
}

/// Extract the `InputSignature` class `EncodingUnit` for `method_name` from a
/// CIM class `EncodingUnit` (`class_wmio`, returned by `IWbemServices::GetObject`).
/// Returns `Ok(None)` when the method exists but takes no input parameters.
pub fn extract_method_in_params(
    class_wmio: &[u8],
    method_name: &str,
) -> Result<Option<Vec<u8>>, WmioError> {
    let header = parse_object_header(class_wmio)?;
    if header.is_instance {
        return Err(WmioError::Unsupported);
    }
    let class = parse_class_part(class_wmio, header.body_offset)?;
    // MethodsPart (MS-WMIO 2.2.41): EncodingLength(4), MethodCount(2),
    // MethodCountPadding(2), MethodCount * MethodDescription(24), MethodHeap.
    let methods_start = header
        .body_offset
        .checked_add(class.encoding_length)
        .ok_or(WmioError::Malformed)?;
    let _methods_len = rd_u32(class_wmio, methods_start)?;
    let method_count = u16::from_le_bytes(
        class_wmio
            .get(methods_start + 4..methods_start + 6)
            .ok_or(WmioError::Malformed)?
            .try_into()
            .unwrap(),
    ) as usize;
    let descs_start = methods_start + 8;
    let descs_len = method_count.checked_mul(24).ok_or(WmioError::Malformed)?;
    let heap_hdr_at = descs_start
        .checked_add(descs_len)
        .ok_or(WmioError::Malformed)?;
    let heap_len = (rd_u32(class_wmio, heap_hdr_at)? & 0x7fff_ffff) as usize;
    let method_heap = class_wmio
        .get(heap_hdr_at + 4..heap_hdr_at + 4 + heap_len)
        .ok_or(WmioError::Malformed)?;

    for i in 0..method_count {
        let desc_at = descs_start + i * 24;
        let name_ref = (rd_u32(class_wmio, desc_at)? & 0x7fff_ffff) as usize;
        let name = encoded_string(method_heap, name_ref)?;
        if !name.eq_ignore_ascii_case(method_name) {
            continue;
        }
        // InputSignature is at offset 16 of MethodDescription (0xffff_ffff = none).
        let input_sig = rd_u32(class_wmio, desc_at + 16)?;
        if input_sig == 0xffff_ffff {
            return Ok(None);
        }
        let sig_off = (input_sig & 0x7fff_ffff) as usize;
        let block_len = rd_u32(method_heap, sig_off)? as usize;
        if block_len == 0 {
            return Ok(None);
        }
        let object_block = method_heap
            .get(sig_off + 4..sig_off + 4 + block_len)
            .ok_or(WmioError::Malformed)?;
        let mut unit = Vec::with_capacity(8 + block_len);
        unit.extend_from_slice(&WMIO_SIGNATURE.to_le_bytes());
        unit.extend_from_slice(&(block_len as u32).to_le_bytes());
        unit.extend_from_slice(object_block);
        return Ok(Some(unit));
    }
    Err(WmioError::Malformed)
}

/// Build the `pInParams` WMIO instance `EncodingUnit` for `method_name` on
/// `class_wmio` populated with `params`. Returns `Ok(None)` if the method has
/// no `InputSignature`.
pub fn encode_method_in_params(
    class_wmio: &[u8],
    method_name: &str,
    params: &serde_json::Map<String, serde_json::Value>,
) -> Result<Option<Vec<u8>>, WmioError> {
    match extract_method_in_params(class_wmio, method_name)? {
        Some(in_sig_wmio) => spawn_instance(&in_sig_wmio, params).map(Some),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WMIO encoding unit for the one-row query
    /// `SELECT ... FROM Win32_ComputerSystem`. Non-sensitive.
    const WMIO_RESULT: &[u8] = include_bytes!("testdata/wmio_result.bin");
    /// `SELECT * FROM Win32_Service WHERE Name = "Winmgmt"` from Windows Server
    /// 2022: a decorated instance (ObjectFlags 0x06). Non-sensitive lab data.
    const WMIO_SERVICE: &[u8] = include_bytes!("testdata/wmio_service.bin");
    /// `SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE`
    /// from the same lab VM (QEMU NAT addressing): string and integer arrays.
    const WMIO_NIC: &[u8] = include_bytes!("testdata/wmio_nic.bin");
    /// `SELECT * FROM __Win32Provider WHERE Name = "CIMWin32"`: three
    /// properties (Pure, PerLocale-/PerUserInitialization) carry NdTable 0b10,
    /// i.e. take their value from the class default rather than the instance.
    const WMIO_PROVIDER: &[u8] = include_bytes!("testdata/wmio_provider.bin");

    #[test]
    fn parse_object_header_reports_instance() {
        let hdr = parse_object_header(WMIO_RESULT).unwrap();
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
        // Instance: ENCODING_UNIT(8) + ObjectFlags(1); CurrentClass.ClassPart at 9.
        let cp = parse_class_part(WMIO_RESULT, 9).unwrap();
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
    fn decode_object_produces_the_query_row_json() {
        let value = decode_object(WMIO_RESULT).unwrap();
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

    #[test]
    fn parse_object_header_skips_decoration() {
        let hdr = parse_object_header(WMIO_SERVICE).unwrap();
        assert!(hdr.is_instance && hdr.has_decoration);
        // ObjectFlags at 8, then "\0WIN2022WMI\0" and "\0root\\cimv2\0".
        assert_eq!(hdr.body_offset, 9 + 12 + 12);
    }

    #[test]
    fn decode_object_decodes_decorated_select_star_instance() {
        // Values cross-checked against Get-WmiObject on the same host.
        let row = decode_object(WMIO_SERVICE).unwrap();
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
        let row = decode_object(WMIO_NIC).unwrap();
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
        assert_eq!(decode_object(WMIO_PROVIDER).unwrap(), expected);
    }

    #[test]
    fn decode_value_decodes_embedded_object() {
        // A CIM_OBJECT value is a heap ref to ObjectEncodingLength + ObjectBlock.
        // Embed the service instance's ObjectBlock and expect the same row.
        let block = &WMIO_SERVICE[8..];
        let mut heap = vec![0u8; 3]; // embedded object not at heap offset 0
        heap.extend_from_slice(&(block.len() as u32).to_le_bytes());
        heap.extend_from_slice(block);
        let value = decode_value(CIM_OBJECT, false, &3u32.to_le_bytes(), 0, &heap, 0).unwrap();
        assert_eq!(value, decode_object(WMIO_SERVICE).unwrap());
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
        for (blob, data_end) in [(WMIO_SERVICE, 6271), (WMIO_NIC, 12184)] {
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
    fn spawn_instance_matches_windows_reference_bytes() {
        let orig = decode_object(WMIO_RESULT).unwrap();
        let spawned = spawn_instance(WMIO_RESULT, orig.as_object().unwrap()).unwrap();
        // WMIO_RESULT has 885 bytes of EncodingUnit header + ObjectFlags +
        // ClassPart(763) + InstanceType(113), followed by zero padding.
        // Byte 8 in WMIO_RESULT has flag 0x10 set alongside OBJECT_FLAG_INSTANCE (0x02);
        // everything from ClassPart (9..885) matches byte-for-byte.
        assert_eq!(spawned.len(), 885);
        assert_eq!(&spawned[9..], &WMIO_RESULT[9..885]);
        assert_eq!(decode_object(&spawned).unwrap(), orig);
    }

    #[test]
    fn spawn_instance_round_trips_scalars_arrays_nulls_and_defaults() {
        use serde_json::json;
        let props = json!({
            "IPAddress": ["192.0.2.1", "2001:db8::1"],
            "GatewayCostMetric": [10, 20],
            "IPEnabled": true,
            "Index": 42,
            "MACAddress": null,
        });
        let spawned = spawn_instance(WMIO_NIC, props.as_object().unwrap()).unwrap();
        let decoded = decode_object(&spawned).unwrap();
        assert_eq!(decoded["IPAddress"], json!(["192.0.2.1", "2001:db8::1"]));
        assert_eq!(decoded["GatewayCostMetric"], json!([10, 20]));
        assert_eq!(decoded["IPEnabled"], json!(true));
        assert_eq!(decoded["Index"], json!(42));
        assert_eq!(decoded["MACAddress"], json!(null));
    }

    #[test]
    fn encode_method_in_params_builds_valid_parameter_instance() {
        use serde_json::json;
        // Build a synthetic class EncodingUnit whose MethodsPart has one method
        // "Create" taking WMIO_RESULT's ClassPart as its InputSignature.
        let cp = parse_class_part(WMIO_RESULT, 9).unwrap();
        let class_part = &WMIO_RESULT[9..9 + cp.encoding_length];

        // InputSignature ObjectBlock: ObjectFlags(0x01 = class) + ClassPart + empty MethodsPart.
        let mut sig_object_block = Vec::new();
        sig_object_block.push(0x01); // ObjectFlags = class
        sig_object_block.extend_from_slice(class_part);
        sig_object_block.extend_from_slice(&12u32.to_le_bytes()); // MethodsPart EncodingLength
        sig_object_block.extend_from_slice(&0u16.to_le_bytes()); // MethodCount = 0
        sig_object_block.extend_from_slice(&0u16.to_le_bytes()); // Padding
        sig_object_block.extend_from_slice(&0x8000_0000u32.to_le_bytes()); // empty MethodHeap

        let mut method_heap = Vec::new();
        let name_ref = push_encoded_string(&mut method_heap, "Create");
        let sig_ref = method_heap.len() as u32;
        method_heap.extend_from_slice(&(sig_object_block.len() as u32).to_le_bytes());
        method_heap.extend_from_slice(&sig_object_block);

        let methods_len = 8 + 24 + 4 + method_heap.len();
        let mut methods_part = Vec::new();
        methods_part.extend_from_slice(&(methods_len as u32).to_le_bytes());
        methods_part.extend_from_slice(&1u16.to_le_bytes()); // 1 method
        methods_part.extend_from_slice(&0u16.to_le_bytes()); // padding
                                                             // MethodDescription (24 bytes): Name(4), Flags(1), Pad(3), Origin(4), Quals(4), InSig(4), OutSig(4)
        methods_part.extend_from_slice(&name_ref.to_le_bytes());
        methods_part.extend_from_slice(&[0, 0, 0, 0]);
        methods_part.extend_from_slice(&0u32.to_le_bytes());
        methods_part.extend_from_slice(&0u32.to_le_bytes());
        methods_part.extend_from_slice(&sig_ref.to_le_bytes());
        methods_part.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        methods_part.extend_from_slice(&((method_heap.len() as u32) | 0x8000_0000).to_le_bytes());
        methods_part.extend_from_slice(&method_heap);

        let obj_len = 1 + class_part.len() + methods_part.len();
        let mut class_wmio = Vec::new();
        class_wmio.extend_from_slice(&WMIO_SIGNATURE.to_le_bytes());
        class_wmio.extend_from_slice(&(obj_len as u32).to_le_bytes());
        class_wmio.push(0x01); // ObjectFlags = class
        class_wmio.extend_from_slice(class_part);
        class_wmio.extend_from_slice(&methods_part);

        let params = json!({
            "Name": "SERVER01",
            "Domain": "corp.example",
        });
        let in_params = encode_method_in_params(&class_wmio, "create", params.as_object().unwrap())
            .unwrap()
            .expect("Create has an InputSignature");
        let decoded = decode_object(&in_params).unwrap();
        assert_eq!(decoded["Name"], "SERVER01");
        assert_eq!(decoded["Domain"], "corp.example");
    }
}
