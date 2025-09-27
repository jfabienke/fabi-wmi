//! Stub NDR codec for testing
//!
//! Provides mock WMI responses for testing without a real Windows host.

use crate::ndr::{write_bstr, NdrCodec, NdrError};
use serde_json::{json, Value};

/// TEST INFRASTRUCTURE - DO NOT DELETE
///
/// Mock NDR codec that returns hardcoded WMI responses.
/// This is used for:
/// - Unit tests that need predictable WMI responses
/// - Integration tests when LINUX_WMI_USE_STUB=1
/// - Testing WMI query parsing logic
pub struct StubNdrCodec;

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
        class: &str,
        method: &str,
        _data: &[u8],
    ) -> Result<Value, NdrError> {
        // Return appropriate responses based on method
        match (
            class.to_uppercase().as_str(),
            method.to_uppercase().as_str(),
        ) {
            ("WIN32_PROCESS", "GETOWNER") => Ok(json!({
                "User": "SYSTEM",
                "Domain": "NT AUTHORITY",
                "ReturnValue": 0
            })),
            ("WIN32_PROCESS", "UNKNOWN") => {
                // Return error for unknown methods
                Err(NdrError::Decode)
            }
            _ => {
                // Default success response for other methods
                Ok(json!({
                    "ReturnValue": 0,
                    "Status": "Success"
                }))
            }
        }
    }
}

/// Generate stub results based on the WQL query
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
