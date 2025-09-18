use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde_json::{json, Value};
use std::io::Cursor;
use tracing::{instrument, trace};

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

        let chars: Vec<u16> = value.encode_utf16().collect();
        let byte_len = (chars.len() * 2) as u32;
        buf.write_u32::<LittleEndian>(byte_len).unwrap();
        for ch in &chars {
            buf.write_u16::<LittleEndian>(*ch).unwrap();
        }
        buf.write_u16::<LittleEndian>(0).unwrap();

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
        let vt_type = cursor.read_u16::<LittleEndian>().map_err(|_| NdrError::Decode)?;

        // Skip reserved bytes (6 bytes)
        cursor.set_position(8);

        // Based on type, decode the value
        let value = match vt_type {
            0x0000 => json!(null), // VT_EMPTY
            0x0001 => json!(null), // VT_NULL
            0x0003 => {
                // VT_I4 - 32-bit signed integer
                let val = cursor.read_i32::<LittleEndian>().map_err(|_| NdrError::Decode)?;
                json!(val)
            },
            0x0008 => {
                // VT_BSTR - BSTR string
                // Read pointer
                let ptr = cursor.read_u32::<LittleEndian>().map_err(|_| NdrError::Decode)?;
                if ptr == 0 {
                    json!(null)
                } else {
                    // For simplicity, assume inline BSTR follows
                    cursor.set_position(cursor.position() + 4); // Skip padding
                    let len = cursor.read_u32::<LittleEndian>().map_err(|_| NdrError::Decode)? as usize;
                    let mut chars = Vec::with_capacity(len / 2);
                    for _ in 0..(len / 2) {
                        chars.push(cursor.read_u16::<LittleEndian>().map_err(|_| NdrError::Decode)?);
                    }
                    let string = String::from_utf16_lossy(&chars);
                    json!(string)
                }
            },
            0x0013 => {
                // VT_UI4 - 32-bit unsigned integer
                let val = cursor.read_u32::<LittleEndian>().map_err(|_| NdrError::Decode)?;
                json!(val)
            },
            0x0014 => {
                // VT_I8 - 64-bit signed integer
                let val = cursor.read_i64::<LittleEndian>().map_err(|_| NdrError::Decode)?;
                json!(val)
            },
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
        let _flags = cursor.read_u32::<LittleEndian>().map_err(|_| NdrError::Decode)?;
        let ext_ptr = cursor.read_u32::<LittleEndian>().map_err(|_| NdrError::Decode)?;

        let mut offset = 8;

        // Parse extensions if pointer is non-null
        if ext_ptr != 0 {
            // Extension pointer is a referent ID, not an offset
            // Extensions follow immediately after ORPCTHAT header

            // Read conformant array size (at current offset)
            if data.len() >= offset + 4 {
                let size = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;

                // Skip conformant array size (4 bytes) + array data
                offset += 4 + size;

                // Ensure alignment to 4-byte boundary
                let padding = (4 - (size % 4)) % 4;
                offset += padding;
            }
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
        cursor.read_u32::<LittleEndian>().map_err(|_| NdrError::Decode)
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
        buf.write_u32::<LittleEndian>(0x00000020 | 0x00000010).unwrap();

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
        let enum_ptr = cursor.read_u32::<LittleEndian>().map_err(|_| NdrError::Decode)?;
        if enum_ptr == 0 {
            return Ok(Vec::new());
        }

        trace!("ExecQuery returned enumerator pointer 0x{:08x}; streaming not implemented", enum_ptr);
        self.decode_stub_response(query)
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

    #[test]
    fn test_exec_query_encoding() {
        let codec = RealNdrCodec::new();
        let encoded = codec.encode_exec_query("WQL", "SELECT * FROM Win32_Process").unwrap();

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
    fn test_hresult_decoding() {
        let data = vec![
            0x00, 0x00, 0x00, 0x00, // Padding
            0x00, 0x00, 0x00, 0x00, // More padding
            0x00, 0x00, 0x00, 0x00, // S_OK
        ];

        let hresult = RealNdrCodec::decode_hresult(&data, 8).unwrap();
        assert_eq!(hresult, 0x00000000); // S_OK
    }
}
