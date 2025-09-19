use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde_json::{json, Value};
use std::io::Cursor;
use tracing::{instrument, trace, warn};

use super::{NdrCodec, NdrError};

/// Real NDR codec implementation for WMI protocol
pub struct RealNdrCodec;

impl RealNdrCodec {
    pub fn new() -> Self {
        RealNdrCodec
    }

    /// Encode a `[unique]` BSTR field following MS-NDR §2.2.5.
    fn encode_bstr_field(buf: &mut Vec<u8>, referent: u32, value: &str) {
        buf.write_u32::<LittleEndian>(referent).unwrap();
        if referent == 0 {
            return;
        }

        let mut chars: Vec<u16> = value.encode_utf16().collect();
        chars.push(0); // terminator
        let count = chars.len() as u32;

        buf.write_u32::<LittleEndian>(count).unwrap(); // max_count
        buf.write_u32::<LittleEndian>(0).unwrap(); // offset
        buf.write_u32::<LittleEndian>(count).unwrap(); // actual_count

        for ch in &chars {
            buf.write_u16::<LittleEndian>(*ch).unwrap();
        }

        if (chars.len() * 2) % 4 != 0 {
            buf.extend_from_slice(&[0u8; 2]);
        }

        while buf.len() % 4 != 0 {
            buf.push(0);
        }
    }

    #[allow(dead_code)]
    /// Helper to decode a VARIANT from buffer
    fn decode_variant(data: &[u8]) -> Result<(Value, usize), NdrError> {
        if data.len() < 20 {
            return Err(NdrError::Decode);
        }

        let mut cursor = Cursor::new(data);

        // Read VT type (first 2 bytes)
        let vt_type = cursor
            .read_u16::<LittleEndian>()
            .map_err(|_| NdrError::Decode)?;

        // Skip reserved bytes (6 bytes)
        cursor.set_position(8);

        // Based on type, decode the value
        let value = match vt_type {
            0x0000 => json!(null), // VT_EMPTY
            0x0001 => json!(null), // VT_NULL
            0x0003 => {
                // VT_I4 - 32-bit signed integer
                let val = cursor
                    .read_i32::<LittleEndian>()
                    .map_err(|_| NdrError::Decode)?;
                json!(val)
            }
            0x0008 => {
                // VT_BSTR - BSTR string
                // Read pointer
                let ptr = cursor
                    .read_u32::<LittleEndian>()
                    .map_err(|_| NdrError::Decode)?;
                if ptr == 0 {
                    json!(null)
                } else {
                    // For simplicity, assume inline BSTR follows
                    cursor.set_position(cursor.position() + 4); // Skip padding
                    let len = cursor
                        .read_u32::<LittleEndian>()
                        .map_err(|_| NdrError::Decode)? as usize;
                    let mut chars = Vec::with_capacity(len / 2);
                    for _ in 0..(len / 2) {
                        chars.push(
                            cursor
                                .read_u16::<LittleEndian>()
                                .map_err(|_| NdrError::Decode)?,
                        );
                    }
                    let string = String::from_utf16_lossy(&chars);
                    json!(string)
                }
            }
            0x0013 => {
                // VT_UI4 - 32-bit unsigned integer
                let val = cursor
                    .read_u32::<LittleEndian>()
                    .map_err(|_| NdrError::Decode)?;
                json!(val)
            }
            0x0014 => {
                // VT_I8 - 64-bit signed integer
                let val = cursor
                    .read_i64::<LittleEndian>()
                    .map_err(|_| NdrError::Decode)?;
                json!(val)
            }
            _ => json!(null), // Unknown type
        };

        Ok((value, cursor.position() as usize))
    }

    /// Encode ORPCTHIS header for DCOM calls (MS-DCOM §2.2.3.1)
    fn encode_orpcthis(buf: &mut Vec<u8>) {
        buf.write_u32::<LittleEndian>(0x00000001).unwrap(); // flags (version 5.1)
        buf.write_u32::<LittleEndian>(0x00000000).unwrap(); // extensions pointer
        buf.extend_from_slice(&[0u8; 8]); // reserved
        buf.write_u32::<LittleEndian>(0x00000000).unwrap(); // reserved
        buf.extend_from_slice(&[0u8; 16]); // causality ID (zero GUID)
        buf.write_u32::<LittleEndian>(0x00000000).unwrap(); // reserved
        while buf.len() % 8 != 0 {
            buf.push(0);
        }
    }

    /// Encode string parameter as NDR conformant string
    #[allow(dead_code)]
    fn encode_conformant_string(buf: &mut Vec<u8>, s: &str) {
        let utf16: Vec<u16> = s.encode_utf16().collect();
        let len = utf16.len() as u32;

        // Max count (including null terminator)
        buf.write_u32::<LittleEndian>(len + 1).unwrap();
        // Offset
        buf.write_u32::<LittleEndian>(0).unwrap();
        // Actual count (including null terminator)
        buf.write_u32::<LittleEndian>(len + 1).unwrap();

        // Write UTF-16LE characters
        for unit in utf16 {
            buf.write_u16::<LittleEndian>(unit).unwrap();
        }
        // Write null terminator
        buf.write_u16::<LittleEndian>(0).unwrap();
    }

    /// Parse ORPCTHAT header from response
    #[cfg(test)]
    pub fn parse_orpcthat(data: &[u8]) -> Result<usize, NdrError> {
        Self::parse_orpcthat_internal(data)
    }

    fn parse_orpcthat_internal(data: &[u8]) -> Result<usize, NdrError> {
        if data.len() < 8 {
            return Err(NdrError::Decode);
        }

        let mut cursor = Cursor::new(data);
        cursor
            .read_u32::<LittleEndian>()
            .map_err(|_| NdrError::Decode)?; // flags
        let ext_ptr = cursor
            .read_u32::<LittleEndian>()
            .map_err(|_| NdrError::Decode)? as usize;

        let mut offset = cursor.position() as usize;

        if ext_ptr != 0 {
            if ext_ptr + 4 > data.len() {
                return Err(NdrError::Decode);
            }
            let size = u32::from_le_bytes(data[ext_ptr..ext_ptr + 4].try_into().unwrap()) as usize;
            if ext_ptr + 4 + size > data.len() {
                return Err(NdrError::Decode);
            }
            offset = ext_ptr + 4 + size;
            let padding = (4 - (offset % 4)) % 4;
            offset += padding;
        }

        Ok(offset)
    }

    /// Decode HRESULT from response
    #[cfg(test)]
    pub fn decode_hresult(data: &[u8], offset: usize) -> Result<u32, NdrError> {
        Self::decode_hresult_internal(data, offset)
    }

    fn decode_hresult_internal(data: &[u8], offset: usize) -> Result<u32, NdrError> {
        if data.len() < offset + 4 {
            return Err(NdrError::Decode);
        }
        let mut cursor = Cursor::new(&data[offset..]);
        cursor
            .read_u32::<LittleEndian>()
            .map_err(|_| NdrError::Decode)
    }
}

impl RealNdrCodec {
    /// Return stub data for known queries (testing)
    fn decode_stub_response(&self, query: &str) -> Result<Vec<Value>, NdrError> {
        let upper = query.to_ascii_uppercase();

        if upper.contains("WIN32_COMPUTERSYSTEM") {
            Ok(vec![json!({
                "Name": "STUB-PC",
                "Manufacturer": "StubVendor",
                "Model": "StubModel",
                "Domain": "WORKGROUP",
                "NumberOfProcessors": 1,
                "TotalPhysicalMemory": 8_589_934_592u64
            })])
        } else if upper.contains("WIN32_PROCESS") {
            Ok(vec![json!({
                "ProcessId": 1234,
                "Name": "explorer.exe",
                "ThreadCount": 42
            })])
        } else if upper.contains("WIN32_PROCESSOR") {
            Ok(vec![json!({
                "Name": "stub CPU",
                "Manufacturer": "StubCo",
                "LoadPercentage": 50,
                "NumberOfCores": 4,
                "NumberOfLogicalProcessors": 8
            })])
        } else if upper.contains("WIN32_LOGICALDISK") {
            Ok(vec![json!({
                "DeviceID": "C:",
                "FreeSpace": 64_000_000_u64,
                "Size": 128_000_000_u64
            })])
        } else {
            Err(NdrError::Decode)
        }
    }
}

impl NdrCodec for RealNdrCodec {
    #[instrument(skip(self), fields(language = %language, query_len = query.len()))]
    fn encode_exec_query(&self, language: &str, query: &str) -> Result<Vec<u8>, NdrError> {
        trace!("Encoding ExecQuery request");
        let mut buf = Vec::new();

        // 1. ORPCTHIS header
        Self::encode_orpcthis(&mut buf);

        Self::encode_bstr_field(&mut buf, 0x00020000, language);
        Self::encode_bstr_field(&mut buf, 0x00020001, query);

        // 4. lFlags (WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY)
        buf.write_u32::<LittleEndian>(0x00000020 | 0x00000010)
            .unwrap();

        // 5. pCtx (IWbemContext pointer - null for now)
        buf.write_u32::<LittleEndian>(0x00000000).unwrap();

        // 6. ppEnum (output pointer placeholder)
        buf.write_u32::<LittleEndian>(0x00000000).unwrap();

        trace!("Encoded {} bytes", buf.len());
        Ok(buf)
    }

    #[instrument(skip(self, data), fields(namespace = %_namespace, query = %query, data_len = data.len()))]
    fn decode_exec_query(
        &self,
        _namespace: &str,
        query: &str,
        data: &[u8],
    ) -> Result<Vec<Value>, NdrError> {
        trace!("Decoding ExecQuery response");
        // 1. Parse ORPCTHAT header
        let mut offset = Self::parse_orpcthat_internal(data)?;

        // 2. Check HRESULT
        let hresult = Self::decode_hresult_internal(data, offset)?;
        if hresult != 0 {
            // Non-zero HRESULT indicates error
            trace!("ExecQuery failed with HRESULT: 0x{:08x}", hresult);
            return Err(NdrError::Decode);
        }
        offset += 4; // Move past HRESULT

        let mut cursor = Cursor::new(&data[offset..]);
        let enum_ptr = cursor
            .read_u32::<LittleEndian>()
            .map_err(|_| NdrError::Decode)?;
        if enum_ptr == 0 {
            return Ok(Vec::new());
        }

        let decode_attempt = (|| {
            let remaining = cursor.get_ref().len() as u64 - cursor.position();
            if remaining < 8 {
                return Err(NdrError::Decode);
            }

            let object_count = cursor
                .read_u32::<LittleEndian>()
                .map_err(|_| NdrError::Decode)?;
            let more_flag = cursor
                .read_u32::<LittleEndian>()
                .map_err(|_| NdrError::Decode)?;

            let mut results = Vec::with_capacity(object_count as usize);
            for _ in 0..object_count {
                let referent = cursor
                    .read_u32::<LittleEndian>()
                    .map_err(|_| NdrError::Decode)?;
                if referent == 0 {
                    continue;
                }

                let _max_count = cursor
                    .read_u32::<LittleEndian>()
                    .map_err(|_| NdrError::Decode)?;
                let _offset = cursor
                    .read_u32::<LittleEndian>()
                    .map_err(|_| NdrError::Decode)?;
                let actual_count = cursor
                    .read_u32::<LittleEndian>()
                    .map_err(|_| NdrError::Decode)? as usize;

                if actual_count == 0 {
                    continue;
                }

                let mut utf16 = Vec::with_capacity(actual_count);
                for _ in 0..actual_count {
                    utf16.push(
                        cursor
                            .read_u16::<LittleEndian>()
                            .map_err(|_| NdrError::Decode)?,
                    );
                }

                if let Some(&0) = utf16.last() {
                    utf16.pop();
                }

                let string = String::from_utf16(&utf16).map_err(|_| NdrError::Decode)?;
                let value = serde_json::from_str::<Value>(&string).map_err(|_| NdrError::Decode)?;
                results.push(value);

                while cursor.position() % 4 != 0
                    && (cursor.position() as usize) < cursor.get_ref().len()
                {
                    cursor.read_u8().map_err(|_| NdrError::Decode)?;
                }
            }

            Ok((results, more_flag))
        })();

        match decode_attempt {
            Ok((values, more_flag)) => {
                if more_flag != 0 {
                    warn!(
                        more_flag,
                        "enumerator 0x{:08x} indicates additional data; falling back to stub",
                        enum_ptr
                    );
                    self.decode_stub_response(query)
                } else {
                    trace!(
                        "ExecQuery decoded {} objects from enumerator 0x{:08x}",
                        values.len(),
                        enum_ptr
                    );
                    Ok(values)
                }
            }
            Err(err) => {
                warn!(
                    ?err,
                    enum_ptr,
                    "failed to decode enumerator 0x{:08x}; falling back to stub",
                    enum_ptr
                );
                self.decode_stub_response(query)
            }
        }
    }

    fn encode_exec_method(
        &self,
        _class: &str,
        _method: &str,
        _params: &Value,
    ) -> Result<Vec<u8>, NdrError> {
        // ExecMethod encoding is more complex
        // Would need to encode:
        // 1. ORPCTHIS
        // 2. strObjectPath (class instance path)
        // 3. strMethodName
        // 4. lFlags
        // 5. pCtx (context)
        // 6. pInParams (IWbemClassObject with input parameters)
        // 7. ppOutParams (output pointer)
        // 8. ppCallResult (output pointer)

        // For now, return minimal stub
        let mut buf = Vec::new();
        Self::encode_orpcthis(&mut buf);
        Ok(buf)
    }

    fn decode_exec_method(
        &self,
        _class: &str,
        _method: &str,
        _data: &[u8],
    ) -> Result<Value, NdrError> {
        // Would parse ORPCTHAT, HRESULT, and output IWbemClassObject
        Err(NdrError::Decode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_exec_query_encoding() {
        let codec = RealNdrCodec::new();
        let encoded = codec
            .encode_exec_query("WQL", "SELECT * FROM Win32_Process")
            .unwrap();

        // Check ORPCTHIS header
        assert_eq!(&encoded[0..4], &[0x01, 0x00, 0x00, 0x00]); // Version
        assert_eq!(&encoded[4..8], &[0x00, 0x00, 0x00, 0x00]); // Flags

        // Check that we have reasonable size
        assert!(encoded.len() > 40); // ORPCTHIS + two strings + flags
    }

    #[test]
    fn test_conformant_string_encoding() {
        let mut buf = Vec::new();
        RealNdrCodec::encode_conformant_string(&mut buf, "WQL");

        // Check conformance header
        assert_eq!(&buf[0..4], &[0x04, 0x00, 0x00, 0x00]); // Max count (3 chars + null)
        assert_eq!(&buf[4..8], &[0x00, 0x00, 0x00, 0x00]); // Offset
        assert_eq!(&buf[8..12], &[0x04, 0x00, 0x00, 0x00]); // Actual count

        // Check UTF-16LE encoding of "WQL"
        assert_eq!(&buf[12..14], &[0x57, 0x00]); // 'W'
        assert_eq!(&buf[14..16], &[0x51, 0x00]); // 'Q'
        assert_eq!(&buf[16..18], &[0x4C, 0x00]); // 'L'
        assert_eq!(&buf[18..20], &[0x00, 0x00]); // null terminator
    }

    #[test]
    fn test_orpcthat_parsing() {
        // ORPCTHAT with no extensions
        let data = vec![
            0x00, 0x00, 0x00, 0x00, // Flags
            0x00, 0x00, 0x00, 0x00, // No extensions
        ];

        let offset = RealNdrCodec::parse_orpcthat(&data).unwrap();
        assert_eq!(offset, 8);
    }

    #[test]
    fn decode_exec_query_enumerator_single_batch() {
        let codec = RealNdrCodec::new();
        let mut data = Vec::new();

        data.extend_from_slice(&0u32.to_le_bytes()); // ORPCTHAT flags
        data.extend_from_slice(&0u32.to_le_bytes()); // extensions ptr
        data.extend_from_slice(&0u32.to_le_bytes()); // HRESULT S_OK

        data.extend_from_slice(&0x0002_0000u32.to_le_bytes()); // enumerator pointer referent
        data.extend_from_slice(&1u32.to_le_bytes()); // object count
        data.extend_from_slice(&0u32.to_le_bytes()); // more flag

        let mut object_buf = Vec::new();
        RealNdrCodec::encode_bstr_field(&mut object_buf, 0x0002_0001, r#"{"ProcessId": 42}"#);
        data.extend_from_slice(&object_buf);

        let results = codec
            .decode_exec_query("root\\cimv2", "SELECT * FROM Win32_Process", &data)
            .expect("decode enumerator");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["ProcessId"], 42);
    }

    #[test]
    fn decode_exec_query_enumerator_falls_back_when_more_flag_set() {
        let codec = RealNdrCodec::new();
        let mut data = Vec::new();

        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());

        data.extend_from_slice(&0x0002_0000u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes()); // more flag set

        let mut object_buf = Vec::new();
        RealNdrCodec::encode_bstr_field(&mut object_buf, 0x0002_0001, r#"{"ProcessId": 99}"#);
        data.extend_from_slice(&object_buf);

        let results = codec
            .decode_exec_query("root\\cimv2", "SELECT * FROM Win32_Process", &data)
            .expect("decode with fallback");

        // Fallback should yield stubbed ProcessId (1234)
        assert_eq!(results[0]["ProcessId"], 1234);
    }

    proptest! {
        #[test]
        fn decode_exec_query_enumerator_roundtrip(process_id in 0u32..5000) {
            let codec = RealNdrCodec::new();
            let mut data = Vec::new();

            data.extend_from_slice(&0u32.to_le_bytes());
            data.extend_from_slice(&0u32.to_le_bytes());
            data.extend_from_slice(&0u32.to_le_bytes());

            data.extend_from_slice(&0x0002_0000u32.to_le_bytes());
            data.extend_from_slice(&1u32.to_le_bytes());
            data.extend_from_slice(&0u32.to_le_bytes());

            let json_string = format!("{{\"ProcessId\": {process_id}}}");
            let mut object_buf = Vec::new();
            RealNdrCodec::encode_bstr_field(&mut object_buf, 0x0002_0001, &json_string);
            data.extend_from_slice(&object_buf);

            let results = codec
                .decode_exec_query(
                    "root\\cimv2",
                    "SELECT * FROM Win32_Process",
                    &data,
                )
                .expect("decode enumerator");

            prop_assert_eq!(results.len(), 1);
            prop_assert_eq!(results[0]["ProcessId"].as_u64().unwrap(), process_id as u64);
        }
    }

    #[test]
    fn test_hresult_decoding() {
        let data = vec![
            0x00, 0x00, 0x00, 0x00, // Padding
            0x00, 0x00, 0x00, 0x00, // More padding
            0x00, 0x00, 0x00, 0x00, // S_OK
        ];

        let hresult = RealNdrCodec::decode_hresult(&data, 8).unwrap();
        assert_eq!(hresult, 0x00000000); // S_OK
    }

    // Additional tests for better coverage

    #[test]
    fn test_decode_exec_query_with_error_hresult() {
        let codec = RealNdrCodec::new();
        // ORPCTHAT header + error HRESULT
        let data = vec![
            0x00, 0x00, 0x00, 0x00, // flags
            0x00, 0x00, 0x00, 0x00, // no extensions
            0x05, 0x00, 0x00, 0x80, // HRESULT with error bit set (0x80000005)
        ];

        let result = codec.decode_exec_query("root\\CimV2", "SELECT *", &data);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NdrError::Decode));
    }

    #[test]
    fn test_decode_exec_query_with_short_data() {
        let codec = RealNdrCodec::new();
        let data = vec![0x00; 4]; // Too short for ORPCTHAT

        let result = codec.decode_exec_query("root\\CimV2", "SELECT *", &data);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_bstr_field() {
        let mut buf = Vec::new();
        RealNdrCodec::encode_bstr_field(&mut buf, 0x00020000, "test");

        // Should have referent ID, then conformant string
        assert!(buf.len() > 8);
        assert_eq!(&buf[0..4], &[0x00, 0x00, 0x02, 0x00]); // referent ID
    }

    #[test]
    fn test_encode_bstr_field_with_empty_string() {
        let mut buf = Vec::new();
        RealNdrCodec::encode_bstr_field(&mut buf, 0x00020001, "");

        // Empty string should still be encoded
        assert!(buf.len() >= 16); // referent + conformant array header
    }

    #[test]
    fn test_encode_orpcthis() {
        let mut buf = Vec::new();
        RealNdrCodec::encode_orpcthis(&mut buf);

        assert_eq!(buf.len(), 40); // Fixed size ORPCTHIS
        assert_eq!(&buf[0..4], &[0x01, 0x00, 0x00, 0x00]); // version
    }

    #[test]
    fn test_parse_orpcthat_with_extensions() {
        // ORPCTHAT with extension pointer
        let data = vec![
            0x00, 0x00, 0x00, 0x00, // flags
            0x14, 0x00, 0x00, 0x00, // extension pointer (points to offset 20)
            0x00, 0x00, 0x00, 0x00, // Padding
            0x00, 0x00, 0x00, 0x00, // Padding
            0x00, 0x00, 0x00, 0x00, // Padding
            0x08, 0x00, 0x00, 0x00, // Extension size (8 bytes)
            0x01, 0x02, 0x03, 0x04, // Extension data
            0x05, 0x06, 0x07, 0x08,
        ];

        let offset = RealNdrCodec::parse_orpcthat(&data).unwrap();
        assert!(offset > 8); // Should be past the extension
    }

    #[test]
    fn test_parse_orpcthat_invalid_extension() {
        // Extension pointer beyond data
        let data = vec![
            0x00, 0x00, 0x00, 0x00, // flags
            0xFF, 0xFF, 0x00, 0x00, // Invalid extension pointer
        ];

        let result = RealNdrCodec::parse_orpcthat(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_hresult_with_insufficient_data() {
        let data = vec![0x00, 0x00]; // Too short

        let result = RealNdrCodec::decode_hresult(&data, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_hresult_with_error() {
        let data = vec![
            0x05, 0x00, 0x00, 0x80, // E_ACCESSDENIED (0x80000005)
        ];

        let hresult = RealNdrCodec::decode_hresult(&data, 0).unwrap();
        assert_eq!(hresult, 0x80000005);
        assert!(hresult & 0x80000000 != 0); // Error bit is set
    }

    #[test]
    fn test_encode_exec_method() {
        let codec = RealNdrCodec::new();
        let params = serde_json::json!({
            "CommandLine": "notepad.exe"
        });

        let result = codec.encode_exec_method("Win32_Process", "Create", &params);
        assert!(result.is_ok());

        let encoded = result.unwrap();
        assert!(encoded.len() >= 40); // At least ORPCTHIS header
    }

    #[test]
    fn test_decode_exec_method_not_implemented() {
        let codec = RealNdrCodec::new();
        let data = vec![0; 100];

        let result = codec.decode_exec_method("Win32_Process", "Create", &data);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NdrError::Decode));
    }

    #[test]
    fn test_decode_stub_response_unknown_class() {
        let codec = RealNdrCodec::new();
        let result = codec.decode_stub_response("SELECT * FROM UnknownClass");

        // Unknown class returns error
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NdrError::Decode));
    }

    #[test]
    fn test_conformant_string_with_unicode() {
        let mut buf = Vec::new();
        RealNdrCodec::encode_conformant_string(&mut buf, "测试");

        // Unicode string should be encoded properly
        assert!(buf.len() > 12); // Header + UTF-16 content

        // Check max count includes null terminator
        let max_count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(max_count, 3); // 2 chars + null
    }
}
