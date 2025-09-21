pub mod codec;
pub mod types;

#[cfg(test)]
mod golden_tests;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde_json::{json, Value};
use thiserror::Error;

pub use codec::RealNdrCodec;

#[cfg(feature = "async")]
use std::sync::Arc;
#[cfg(feature = "async")]
use tokio::task::spawn_blocking;

/// Errors produced by the NDR codec while encoding or decoding payloads.
#[derive(Debug, Error)]
pub enum NdrError {
    #[error("encoding not implemented")]
    Encode,
    #[error("decoding not implemented")]
    Decode,
    #[error("invalid conformance: max_count ({max}) < actual_count ({actual})")]
    InvalidConformance { max: u32, actual: u32 },
    #[error("array size exceeds limit: {size} bytes (max: {max})")]
    ArrayTooLarge { size: usize, max: usize },
}

/// Abstraction over the NDR encoder/decoder used for RPC payloads.
pub trait NdrCodec: Send + Sync {
    /// Encode an ExecQuery call into a binary payload.
    fn encode_exec_query(&self, language: &str, query: &str) -> Result<Vec<u8>, NdrError>;

    /// Decode the ExecQuery response into JSON values.
    fn decode_exec_query(
        &self,
        _namespace: &str,
        query: &str,
        data: &[u8],
    ) -> Result<Vec<Value>, NdrError>;

    /// Encode an ExecMethod call with arbitrary parameters.
    fn encode_exec_method(
        &self,
        class: &str,
        method: &str,
        params: &Value,
    ) -> Result<Vec<u8>, NdrError>;

    /// Decode the ExecMethod response into JSON values.
    fn decode_exec_method(&self, class: &str, method: &str, data: &[u8])
        -> Result<Value, NdrError>;
}

/// Stub codec that mirrors the current hard-coded behaviour.
#[derive(Default)]
pub struct StubNdrCodec;

#[cfg(feature = "async")]
#[derive(Clone)]
#[allow(dead_code)]
pub struct AsyncNdrCodec {
    inner: Arc<dyn NdrCodec + Send + Sync>,
}

#[cfg(feature = "async")]
impl AsyncNdrCodec {
    #[allow(dead_code)]
    pub fn new(inner: Arc<dyn NdrCodec + Send + Sync>) -> Self {
        Self { inner }
    }

    pub async fn encode_exec_query(
        &self,
        language: &str,
        query: &str,
    ) -> Result<Vec<u8>, NdrError> {
        let language_owned = language.to_owned();
        let query_owned = query.to_owned();
        let inner = Arc::clone(&self.inner);

        spawn_blocking(move || inner.encode_exec_query(&language_owned, &query_owned))
            .await
            .map_err(|_| NdrError::Encode)?
    }

    pub async fn decode_exec_query(
        &self,
        namespace: &str,
        query: &str,
        data: &[u8],
    ) -> Result<Vec<Value>, NdrError> {
        let namespace_owned = namespace.to_owned();
        let query_owned = query.to_owned();
        let payload = data.to_vec();
        let inner = Arc::clone(&self.inner);

        spawn_blocking(move || inner.decode_exec_query(&namespace_owned, &query_owned, &payload))
            .await
            .map_err(|_| NdrError::Decode)?
    }
}

pub(crate) fn write_bstr(buf: &mut Vec<u8>, value: &str) {
    let utf16: Vec<u16> = value.encode_utf16().collect();
    buf.write_u32::<LittleEndian>(utf16.len() as u32)
        .expect("write bstr length");
    for unit in utf16 {
        buf.write_u16::<LittleEndian>(unit)
            .expect("write bstr data");
    }
    buf.write_u16::<LittleEndian>(0)
        .expect("write bstr terminator");
}

#[allow(dead_code)]
pub(crate) fn read_bstr(cursor: &mut std::io::Cursor<&[u8]>) -> Option<String> {
    let len = cursor.read_u32::<LittleEndian>().ok()? as usize;
    let mut data = Vec::with_capacity(len);
    for _ in 0..len {
        data.push(cursor.read_u16::<LittleEndian>().ok()?);
    }
    let _ = cursor.read_u16::<LittleEndian>().ok()?; // terminator
    String::from_utf16(&data).ok()
}

pub(crate) fn stub_results_for_query(query: &str) -> Option<Vec<Value>> {
    let upper = query.to_ascii_uppercase();
    let class = upper
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .find_map(|pair| {
            if pair[0] == "FROM" {
                Some(pair[1])
            } else {
                None
            }
        })?;

    match class {
        "WIN32_PROCESS" => Some(vec![json!({
            "ProcessId": 1234,
            "Name": "explorer.exe",
            "ThreadCount": 42
        })]),
        "WIN32_PROCESSOR" => Some(vec![json!({
            "Name": "stub CPU",
            "Manufacturer": "StubCo",
            "LoadPercentage": 50,
            "NumberOfCores": 4,
            "NumberOfLogicalProcessors": 8
        })]),
        "WIN32_LOGICALDISK" => Some(vec![json!({
            "DeviceID": "C:",
            "FreeSpace": 64_000_000_u64,
            "Size": 128_000_000_u64
        })]),
        "WIN32_COMPUTERSYSTEM" => Some(vec![json!({
            "Name": "STUB-PC",
            "Manufacturer": "StubVendor",
            "Model": "StubModel",
            "Domain": "WORKGROUP",
            "NumberOfProcessors": 1,
            "TotalPhysicalMemory": 8_589_934_592u64
        })]),
        _ => None,
    }
}

impl NdrCodec for StubNdrCodec {
    fn encode_exec_query(&self, language: &str, query: &str) -> Result<Vec<u8>, NdrError> {
        let mut buf = Vec::new();
        write_bstr(&mut buf, language);
        write_bstr(&mut buf, query);
        Ok(buf)
    }

    fn decode_exec_query(
        &self,
        _namespace: &str,
        query: &str,
        _data: &[u8],
    ) -> Result<Vec<Value>, NdrError> {
        if !_data.is_empty() {
            if let Ok(values) = serde_json::from_slice::<Vec<Value>>(_data) {
                return Ok(values);
            }
        }

        stub_results_for_query(query).ok_or(NdrError::Decode)
    }

    fn encode_exec_method(
        &self,
        _class: &str,
        _method: &str,
        _params: &Value,
    ) -> Result<Vec<u8>, NdrError> {
        Ok(Vec::new())
    }

    fn decode_exec_method(
        &self,
        _class: &str,
        method: &str,
        _data: &[u8],
    ) -> Result<Value, NdrError> {
        match method {
            "GetOwner" => Ok(json!({
                "Domain": "CONTOSO",
                "User": "SYSTEM",
                "ReturnValue": 0
            })),
            _ => Err(NdrError::Decode),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_exec_query_emits_bstrs() {
        let codec = StubNdrCodec;
        let payload = codec
            .encode_exec_query("WQL", "SELECT * FROM Win32_ComputerSystem")
            .expect("encode");
        let mut cursor = std::io::Cursor::new(payload.as_slice());
        let language = read_bstr(&mut cursor).expect("language bstr");
        let query = read_bstr(&mut cursor).expect("query bstr");
        assert_eq!(language, "WQL");
        assert_eq!(query, "SELECT * FROM Win32_ComputerSystem");
    }

    #[test]
    fn stub_results_for_known_query_matches_decode() {
        let codec = StubNdrCodec;
        let query = "SELECT * FROM Win32_ComputerSystem";
        let payload = codec.encode_exec_query("WQL", query).expect("encode");
        let results = codec
            .decode_exec_query("root\\cimv2", query, &payload)
            .expect("decode");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["Name"], "STUB-PC");
    }
}
