use serde_json::{json, Value};
use thiserror::Error;

/// Errors produced by the NDR codec while encoding or decoding payloads.
#[derive(Debug, Error)]
pub enum NdrError {
    #[error("encoding not implemented")]
    Encode,
    #[error("decoding not implemented")]
    Decode,
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

impl NdrCodec for StubNdrCodec {
    fn encode_exec_query(&self, _language: &str, _query: &str) -> Result<Vec<u8>, NdrError> {
        // Stubs do not emit any wire payload yet.
        Ok(Vec::new())
    }

    fn decode_exec_query(
        &self,
        _namespace: &str,
        query: &str,
        _data: &[u8],
    ) -> Result<Vec<Value>, NdrError> {
        // Preserve the existing behaviour by inspecting the query and returning canned results.
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
            })
            .ok_or(NdrError::Decode)?;

        let values = match class {
            "WIN32_PROCESS" => vec![json!({
                "ProcessId": 1234,
                "Name": "explorer.exe",
                "ThreadCount": 42
            })],
            "WIN32_PROCESSOR" => vec![json!({
                "Name": "stub CPU",
                "Manufacturer": "StubCo",
                "LoadPercentage": 50,
                "NumberOfCores": 4,
                "NumberOfLogicalProcessors": 8
            })],
            "WIN32_LOGICALDISK" => vec![json!({
                "DeviceID": "C:",
                "FreeSpace": 64_000_000_u64,
                "Size": 128_000_000_u64
            })],
            _ => vec![],
        };

        if values.is_empty() {
            Err(NdrError::Decode)
        } else {
            Ok(values)
        }
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
