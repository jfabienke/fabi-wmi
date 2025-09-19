use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use nom::{
    bytes::complete::take,
    number::complete::{le_u16, le_u32},
    IResult,
};
use serde::{Deserialize, Serialize};
use std::io::Cursor;

/// HRESULT status codes per MS-ERREF
pub type HResult = u32;

// Common WMI HRESULT values
pub const S_OK: HResult = 0x00000000;
pub const S_FALSE: HResult = 0x00000001;
pub const WBEM_E_FAILED: HResult = 0x80041001;
pub const WBEM_E_NOT_FOUND: HResult = 0x80041002;
pub const WBEM_E_ACCESS_DENIED: HResult = 0x80041003;
pub const WBEM_E_INVALID_QUERY: HResult = 0x80041017;
pub const WBEM_E_INVALID_QUERY_TYPE: HResult = 0x80041018;
pub const WBEM_E_INVALID_CLASS: HResult = 0x80041010;
pub const WBEM_E_INVALID_PARAMETER: HResult = 0x80041008;
pub const WBEM_E_CALL_CANCELLED: HResult = 0x8004100E;
pub const WBEM_E_TRANSPORT_FAILURE: HResult = 0x80041015;

/// HRESULT error mapping for better diagnostics
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HResultError {
    Success,
    False,
    Failed,
    NotFound,
    AccessDenied,
    InvalidQuery,
    InvalidQueryType,
    InvalidClass,
    InvalidParameter,
    CallCancelled,
    TransportFailure,
    Unknown(HResult),
}

impl HResultError {
    /// Convert from raw HRESULT code
    pub fn from_code(code: HResult) -> Self {
        match code {
            S_OK => HResultError::Success,
            S_FALSE => HResultError::False,
            WBEM_E_FAILED => HResultError::Failed,
            WBEM_E_NOT_FOUND => HResultError::NotFound,
            WBEM_E_ACCESS_DENIED => HResultError::AccessDenied,
            WBEM_E_INVALID_QUERY => HResultError::InvalidQuery,
            WBEM_E_INVALID_QUERY_TYPE => HResultError::InvalidQueryType,
            WBEM_E_INVALID_CLASS => HResultError::InvalidClass,
            WBEM_E_INVALID_PARAMETER => HResultError::InvalidParameter,
            WBEM_E_CALL_CANCELLED => HResultError::CallCancelled,
            WBEM_E_TRANSPORT_FAILURE => HResultError::TransportFailure,
            _ => HResultError::Unknown(code),
        }
    }

    /// Check if this is a success code
    #[allow(dead_code)]
    pub fn is_success(&self) -> bool {
        matches!(self, HResultError::Success | HResultError::False)
    }

    /// Get the raw HRESULT code
    #[allow(dead_code)]
    pub fn code(&self) -> HResult {
        match self {
            HResultError::Success => S_OK,
            HResultError::False => S_FALSE,
            HResultError::Failed => WBEM_E_FAILED,
            HResultError::NotFound => WBEM_E_NOT_FOUND,
            HResultError::AccessDenied => WBEM_E_ACCESS_DENIED,
            HResultError::InvalidQuery => WBEM_E_INVALID_QUERY,
            HResultError::InvalidQueryType => WBEM_E_INVALID_QUERY_TYPE,
            HResultError::InvalidClass => WBEM_E_INVALID_CLASS,
            HResultError::InvalidParameter => WBEM_E_INVALID_PARAMETER,
            HResultError::CallCancelled => WBEM_E_CALL_CANCELLED,
            HResultError::TransportFailure => WBEM_E_TRANSPORT_FAILURE,
            HResultError::Unknown(code) => *code,
        }
    }
}

impl std::fmt::Display for HResultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HResultError::Success => write!(f, "The operation completed successfully"),
            HResultError::False => write!(f, "The operation completed with S_FALSE"),
            HResultError::Failed => write!(f, "The operation failed"),
            HResultError::NotFound => write!(f, "The specified object was not found"),
            HResultError::AccessDenied => write!(f, "Access denied to WMI namespace or class"),
            HResultError::InvalidQuery => write!(f, "The WQL query is syntactically invalid"),
            HResultError::InvalidQueryType => write!(f, "The query type is not supported"),
            HResultError::InvalidClass => write!(f, "The specified class does not exist"),
            HResultError::InvalidParameter => write!(f, "One or more parameters are invalid"),
            HResultError::CallCancelled => write!(f, "The operation was cancelled"),
            HResultError::TransportFailure => {
                write!(f, "The transport or network connection failed")
            }
            HResultError::Unknown(code) => write!(f, "Unknown HRESULT error: 0x{code:08X}"),
        }
    }
}

impl From<HResult> for HResultError {
    fn from(code: HResult) -> Self {
        HResultError::from_code(code)
    }
}

/// VARIANT type discriminators per MS-OAUT §2.2.29
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum VarType {
    Empty = 0x0000,
    Null = 0x0001,
    I2 = 0x0002,       // 16-bit signed int
    I4 = 0x0003,       // 32-bit signed int
    R4 = 0x0004,       // 32-bit float
    R8 = 0x0005,       // 64-bit double
    Date = 0x0007,     // OLE Automation date (f64)
    Bstr = 0x0008,     // BSTR string
    Bool = 0x000B,     // VARIANT_BOOL
    I1 = 0x0010,       // 8-bit signed int
    UI1 = 0x0011,      // 8-bit unsigned int
    UI2 = 0x0012,      // 16-bit unsigned int
    UI4 = 0x0013,      // 32-bit unsigned int
    I8 = 0x0014,       // 64-bit signed int
    UI8 = 0x0015,      // 64-bit unsigned int
    Record = 0x0024,   // User-defined type
    FileTime = 0x0040, // Windows FILETIME (u64)
    Array = 0x2000,    // VT_ARRAY flag
}

/// BSTR (Basic String) per MS-OAUT §2.2.23
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bstr {
    pub value: String,
}

impl Bstr {
    #[allow(dead_code)]
    pub fn new(s: &str) -> Self {
        Bstr {
            value: s.to_string(),
        }
    }

    /// Encode BSTR to NDR format: length(u32) + UTF-16LE chars + null terminator
    #[allow(dead_code)]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let utf16: Vec<u16> = self.value.encode_utf16().collect();

        // Write byte length (not char count)
        buf.write_u32::<LittleEndian>(utf16.len() as u32 * 2)
            .expect("write bstr length");

        // Write UTF-16LE characters
        for unit in utf16 {
            buf.write_u16::<LittleEndian>(unit)
                .expect("write bstr char");
        }

        // Write null terminator
        buf.write_u16::<LittleEndian>(0).expect("write bstr null");

        buf
    }

    /// Decode BSTR from NDR format using nom
    #[allow(dead_code)]
    pub fn decode(input: &[u8]) -> IResult<&[u8], Bstr> {
        let (input, byte_len) = le_u32(input)?;
        let char_count = (byte_len / 2) as usize;

        let (input, char_bytes) = take(byte_len)(input)?;
        let (input, _null) = le_u16(input)?; // Skip null terminator

        // Parse UTF-16LE chars
        let mut chars = Vec::with_capacity(char_count);
        let mut cursor = Cursor::new(char_bytes);
        for _ in 0..char_count {
            chars.push(cursor.read_u16::<LittleEndian>().unwrap());
        }

        let value = String::from_utf16_lossy(&chars);
        Ok((input, Bstr { value }))
    }
}

/// VARIANT per MS-OAUT §2.2.29
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum Variant {
    #[serde(rename = "empty")]
    Empty,
    #[serde(rename = "null")]
    Null,
    #[serde(rename = "i4")]
    I4(i32),
    #[serde(rename = "r8")]
    R8(f64), // 64-bit double
    #[serde(rename = "date")]
    Date(f64), // OLE date (days since 1899-12-30)
    #[serde(rename = "bstr")]
    Bstr(Bstr),
    #[serde(rename = "bool")]
    Bool(bool),
    #[serde(rename = "ui4")]
    UI4(u32),
    #[serde(rename = "i8")]
    I8(i64),
    #[serde(rename = "ui8")]
    UI8(u64),
    #[serde(rename = "filetime")]
    FileTime(u64), // Windows FILETIME (100ns intervals since 1601-01-01)
    #[serde(rename = "array")]
    Array(Box<SafeArray>),
}

impl Variant {
    /// Convert VARIANT to serde_json::Value for JSON output
    #[allow(dead_code)]
    pub fn to_json_value(&self) -> serde_json::Value {
        match self {
            Variant::Empty => serde_json::Value::Null,
            Variant::Null => serde_json::Value::Null,
            Variant::I4(n) => serde_json::json!(n),
            Variant::R8(f) => serde_json::json!(f),
            Variant::Date(d) => serde_json::json!(d), // Could convert to ISO8601 string
            Variant::Bstr(s) => serde_json::json!(s.value),
            Variant::Bool(b) => serde_json::json!(b),
            Variant::UI4(n) => serde_json::json!(n),
            Variant::I8(n) => serde_json::json!(n),
            Variant::UI8(n) => serde_json::json!(n),
            Variant::FileTime(ft) => serde_json::json!(ft), // Could convert to ISO8601
            Variant::Array(arr) => {
                let values: Vec<serde_json::Value> =
                    arr.elements.iter().map(|v| v.to_json_value()).collect();
                serde_json::json!(values)
            }
        }
    }

    /// Get the variant type discriminator
    #[allow(dead_code)]
    pub fn var_type(&self) -> VarType {
        match self {
            Variant::Empty => VarType::Empty,
            Variant::Null => VarType::Null,
            Variant::I4(_) => VarType::I4,
            Variant::R8(_) => VarType::R8,
            Variant::Date(_) => VarType::Date,
            Variant::Bstr(_) => VarType::Bstr,
            Variant::Bool(_) => VarType::Bool,
            Variant::UI4(_) => VarType::UI4,
            Variant::I8(_) => VarType::I8,
            Variant::UI8(_) => VarType::UI8,
            Variant::FileTime(_) => VarType::FileTime,
            Variant::Array(_) => VarType::Array,
        }
    }

    /// Encode VARIANT to NDR format
    #[allow(dead_code)]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Write type discriminator
        buf.write_u16::<LittleEndian>(self.var_type() as u16)
            .expect("write variant type");

        // Write 6 bytes of reserved/padding
        buf.extend_from_slice(&[0u8; 6]);

        // Write data (8 byte union)
        match self {
            Variant::Empty | Variant::Null => {
                buf.extend_from_slice(&[0u8; 8]);
            }
            Variant::I4(val) => {
                buf.write_i32::<LittleEndian>(*val).expect("write i4");
                buf.extend_from_slice(&[0u8; 4]); // Pad to 8 bytes
            }
            Variant::R8(val) | Variant::Date(val) => {
                buf.write_f64::<LittleEndian>(*val).expect("write f64");
            }
            Variant::Bool(val) => {
                // VARIANT_BOOL: 0xFFFF for true, 0x0000 for false
                buf.write_u16::<LittleEndian>(if *val { 0xFFFF } else { 0x0000 })
                    .expect("write bool");
                buf.extend_from_slice(&[0u8; 6]); // Pad to 8 bytes
            }
            Variant::UI4(val) => {
                buf.write_u32::<LittleEndian>(*val).expect("write ui4");
                buf.extend_from_slice(&[0u8; 4]); // Pad to 8 bytes
            }
            Variant::I8(val) => {
                buf.write_i64::<LittleEndian>(*val).expect("write i8");
            }
            Variant::UI8(val) | Variant::FileTime(val) => {
                buf.write_u64::<LittleEndian>(*val)
                    .expect("write ui8/filetime");
            }
            Variant::Bstr(_bstr) => {
                // For BSTR in VARIANT, store pointer reference (will be marshaled separately)
                // This is a simplification - real implementation needs referent tracking
                buf.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Non-null pointer
                buf.extend_from_slice(&[0x00; 4]); // Padding
            }
            Variant::Array(_) => {
                // Arrays need special handling with SAFEARRAY
                buf.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // Non-null pointer
                buf.extend_from_slice(&[0x00; 4]); // Padding
            }
        }

        // Append referent data for complex types
        match self {
            Variant::Bstr(bstr) => {
                buf.extend_from_slice(&bstr.encode());
            }
            Variant::Array(arr) => {
                buf.extend_from_slice(&arr.encode());
            }
            _ => {}
        }

        buf
    }

    /// Decode VARIANT from NDR format
    #[allow(dead_code)]
    pub fn decode(input: &[u8]) -> IResult<&[u8], Variant> {
        let (input, vt) = le_u16(input)?;
        let (input, _reserved) = take(6usize)(input)?;

        match vt {
            0x0000 => {
                let (input, _) = take(8usize)(input)?;
                Ok((input, Variant::Empty))
            }
            0x0001 => {
                let (input, _) = take(8usize)(input)?;
                Ok((input, Variant::Null))
            }
            0x0003 => {
                let (input, val) = le_u32(input)?;
                let (input, _) = take(4usize)(input)?; // Skip padding
                Ok((input, Variant::I4(val as i32)))
            }
            0x0005 => {
                // R8 - 64-bit double
                let mut cursor = Cursor::new(&input[..8]);
                let val = cursor.read_f64::<LittleEndian>().unwrap();
                let (input, _) = take(8usize)(input)?;
                Ok((input, Variant::R8(val)))
            }
            0x0007 => {
                // Date - OLE date as f64
                let mut cursor = Cursor::new(&input[..8]);
                let val = cursor.read_f64::<LittleEndian>().unwrap();
                let (input, _) = take(8usize)(input)?;
                Ok((input, Variant::Date(val)))
            }
            0x0008 => {
                // BSTR - has pointer then referent
                let (input, ptr) = le_u32(input)?;
                let (input, _) = take(4usize)(input)?; // Skip padding
                if ptr != 0 {
                    let (input, bstr) = Bstr::decode(input)?;
                    Ok((input, Variant::Bstr(bstr)))
                } else {
                    Ok((input, Variant::Null))
                }
            }
            0x000B => {
                let (input, val) = le_u16(input)?;
                let (input, _) = take(6usize)(input)?; // Skip padding
                Ok((input, Variant::Bool(val != 0)))
            }
            0x0013 => {
                let (input, val) = le_u32(input)?;
                let (input, _) = take(4usize)(input)?; // Skip padding
                Ok((input, Variant::UI4(val)))
            }
            0x0014 => {
                // I8 - 64-bit signed int
                let mut cursor = Cursor::new(&input[..8]);
                let val = cursor.read_i64::<LittleEndian>().unwrap();
                let (input, _) = take(8usize)(input)?;
                Ok((input, Variant::I8(val)))
            }
            0x0015 => {
                // UI8 - 64-bit unsigned int
                let mut cursor = Cursor::new(&input[..8]);
                let val = cursor.read_u64::<LittleEndian>().unwrap();
                let (input, _) = take(8usize)(input)?;
                Ok((input, Variant::UI8(val)))
            }
            0x0040 => {
                // FileTime - Windows FILETIME as u64
                let mut cursor = Cursor::new(&input[..8]);
                let val = cursor.read_u64::<LittleEndian>().unwrap();
                let (input, _) = take(8usize)(input)?;
                Ok((input, Variant::FileTime(val)))
            }
            _ => {
                // Unknown type - skip data
                let (input, _) = take(8usize)(input)?;
                Ok((input, Variant::Null))
            }
        }
    }
}

/// Conformant array per MS-RPCE §14.3.7
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConformantArray<T> {
    pub elements: Vec<T>,
}

impl<T> ConformantArray<T> {
    #[allow(dead_code)]
    pub fn new(elements: Vec<T>) -> Self {
        ConformantArray { elements }
    }
}

impl ConformantArray<Variant> {
    /// Encode conformant array of VARIANTs
    #[allow(dead_code)]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Write conformance info
        let count = self.elements.len() as u32;
        buf.write_u32::<LittleEndian>(count)
            .expect("write max_count");
        buf.write_u32::<LittleEndian>(0).expect("write offset");
        buf.write_u32::<LittleEndian>(count)
            .expect("write actual_count");

        // Write elements
        for element in &self.elements {
            buf.extend_from_slice(&element.encode());
        }

        buf
    }

    /// Decode conformant array of VARIANTs with validation
    #[allow(dead_code)]
    pub fn decode(input: &[u8]) -> IResult<&[u8], ConformantArray<Variant>> {
        let (input, max_count) = le_u32(input)?;
        let (input, _offset) = le_u32(input)?;
        let (input, actual_count) = le_u32(input)?;

        // Validate conformance
        if actual_count > max_count {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Verify,
            )));
        }

        // Limit array size to prevent excessive memory allocation (1MB limit)
        const MAX_ARRAY_SIZE: usize = 1_048_576; // 1MB
        let estimated_size = actual_count as usize * 16; // Minimum VARIANT size
        if estimated_size > MAX_ARRAY_SIZE {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::TooLarge,
            )));
        }

        let mut elements = Vec::with_capacity(actual_count as usize);
        let mut remaining = input;

        for _ in 0..actual_count {
            let (new_remaining, variant) = Variant::decode(remaining)?;
            elements.push(variant);
            remaining = new_remaining;
        }

        Ok((remaining, ConformantArray { elements }))
    }
}

/// SAFEARRAY for VT_ARRAY variants (simplified)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SafeArray {
    pub dimensions: u16,
    pub features: u16,
    pub element_size: u32,
    pub elements: Vec<Variant>,
}

impl SafeArray {
    #[allow(dead_code)]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Simplified SAFEARRAY encoding
        buf.write_u16::<LittleEndian>(self.dimensions)
            .expect("write dims");
        buf.write_u16::<LittleEndian>(self.features)
            .expect("write features");
        buf.write_u32::<LittleEndian>(self.element_size)
            .expect("write elem_size");

        // Write bounds (simplified for 1D)
        buf.write_u32::<LittleEndian>(self.elements.len() as u32)
            .expect("write count");
        buf.write_u32::<LittleEndian>(0).expect("write lbound");

        // Write elements
        for element in &self.elements {
            buf.extend_from_slice(&element.encode());
        }

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_variant_serde_serialization() {
        let variant = Variant::I4(42);
        let json_value = serde_json::to_value(&variant).unwrap();
        assert_eq!(json_value, json!({"type": "i4", "value": 42}));

        let variant = Variant::Bstr(Bstr::new("test"));
        let json_value = serde_json::to_value(&variant).unwrap();
        assert_eq!(
            json_value,
            json!({"type": "bstr", "value": {"value": "test"}})
        );
    }

    #[test]
    fn test_variant_to_json_value() {
        let variant = Variant::I4(42);
        assert_eq!(variant.to_json_value(), json!(42));

        let variant = Variant::Bstr(Bstr::new("hello"));
        assert_eq!(variant.to_json_value(), json!("hello"));

        let variant = Variant::Bool(true);
        assert_eq!(variant.to_json_value(), json!(true));

        let variant = Variant::Null;
        assert_eq!(variant.to_json_value(), json!(null));
    }

    #[test]
    fn test_hresult_error_mapping() {
        let error = HResultError::from_code(0x80041003);
        assert_eq!(error, HResultError::AccessDenied);
        assert!(!error.is_success());
        assert_eq!(error.to_string(), "Access denied to WMI namespace or class");

        let error = HResultError::from_code(0x00000000);
        assert_eq!(error, HResultError::Success);
        assert!(error.is_success());
    }

    #[test]
    fn test_bstr_roundtrip() {
        let original = Bstr::new("Hello WMI");
        let encoded = original.encode();
        let (remaining, decoded) = Bstr::decode(&encoded).unwrap();

        assert!(remaining.is_empty());
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_variant_i4_encoding() {
        let variant = Variant::I4(42);
        let encoded = variant.encode();

        // Check type discriminator
        assert_eq!(encoded[0], 0x03); // VT_I4
        assert_eq!(encoded[1], 0x00);

        // Check value (at offset 8)
        let value = i32::from_le_bytes([encoded[8], encoded[9], encoded[10], encoded[11]]);
        assert_eq!(value, 42);
    }

    #[test]
    fn test_variant_bool_encoding() {
        let variant_true = Variant::Bool(true);
        let encoded = variant_true.encode();

        assert_eq!(encoded[0], 0x0B); // VT_BOOL
        assert_eq!(encoded[8], 0xFF); // VARIANT_BOOL true
        assert_eq!(encoded[9], 0xFF);

        let variant_false = Variant::Bool(false);
        let encoded = variant_false.encode();
        assert_eq!(encoded[8], 0x00); // VARIANT_BOOL false
        assert_eq!(encoded[9], 0x00);
    }

    #[test]
    fn test_advanced_variant_types() {
        // Test Date encoding
        let date = Variant::Date(43831.0); // Example OLE date
        let encoded = date.encode();
        assert_eq!(encoded[0..2], [0x07, 0x00]); // VT_DATE

        // Test FileTime encoding
        let ft = Variant::FileTime(132514848000000000u64); // Example Windows FILETIME
        let encoded = ft.encode();
        assert_eq!(encoded[0..2], [0x40, 0x00]); // VT_FILETIME

        // Test R8 encoding
        let r8 = Variant::R8(std::f64::consts::PI);
        let encoded = r8.encode();
        assert_eq!(encoded[0..2], [0x05, 0x00]); // VT_R8

        // Test JSON conversion
        assert_eq!(date.to_json_value(), serde_json::json!(43831.0));
        assert_eq!(ft.to_json_value(), serde_json::json!(132514848000000000u64));
        assert_eq!(r8.to_json_value(), serde_json::json!(std::f64::consts::PI));
    }

    #[test]
    fn test_conformant_array_validation() {
        // Test invalid conformance (actual > max)
        let bad_data = vec![
            0x01, 0x00, 0x00, 0x00, // max_count = 1
            0x00, 0x00, 0x00, 0x00, // offset = 0
            0x02, 0x00, 0x00, 0x00, // actual_count = 2 (invalid!)
        ];
        let result = ConformantArray::<Variant>::decode(&bad_data);
        assert!(result.is_err());

        // Test size limit
        let large_data = vec![
            0xFF, 0xFF, 0xFF, 0x0F, // max_count = large
            0x00, 0x00, 0x00, 0x00, // offset = 0
            0xFF, 0xFF, 0xFF, 0x0F, // actual_count = large (too big!)
        ];
        let result = ConformantArray::<Variant>::decode(&large_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_conformant_array_encoding() {
        let array = ConformantArray::new(vec![Variant::I4(1), Variant::I4(2), Variant::I4(3)]);

        let encoded = array.encode();

        // Check conformance header
        let max_count = u32::from_le_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        assert_eq!(max_count, 3);

        let actual_count = u32::from_le_bytes([encoded[8], encoded[9], encoded[10], encoded[11]]);
        assert_eq!(actual_count, 3);
    }
}
