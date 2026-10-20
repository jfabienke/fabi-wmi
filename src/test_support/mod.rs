//! In-process stand-in for a WMI server, used by the C ABI when
//! `LINUX_WMI_USE_STUB=1` (requires the `test-support` feature). It lets the
//! FFI and .NET plumbing be tested without a Windows host; it is not a model of
//! WMI semantics beyond a few canned classes.

use serde_json::{json, Value};

use crate::client::Error;
use crate::wmi_proto::WmiProtoError;

/// WBEM_E_INVALID_CLASS, what Windows returns for an unknown class.
const WBEM_E_INVALID_CLASS: u32 = 0x8004_1010;

/// Canned rows for `SELECT ... FROM <class>`, keyed on the class name.
pub(crate) fn query(wql: &str) -> Result<Vec<Value>, Error> {
    let upper = wql.to_ascii_uppercase();
    let class = upper
        .split_once(" FROM ")
        .map(|(_, rest)| rest.split_whitespace().next().unwrap_or(""))
        .unwrap_or("");
    let rows = match class {
        "WIN32_PROCESS" => vec![
            json!({"Name": "System Idle Process", "ProcessId": 0, "ThreadCount": 8}),
            json!({"Name": "System", "ProcessId": 4, "ThreadCount": 91}),
        ],
        "WIN32_COMPUTERSYSTEM" => vec![json!({
            "Name": "STUB-PC",
            "Domain": "WORKGROUP",
            "Manufacturer": "Stub",
            "Model": "Stub Model",
        })],
        "WIN32_OPERATINGSYSTEM" => vec![json!({
            "Caption": "Stub Windows",
            "BuildNumber": "20348",
            "InstallDate": "20260101120000.000000+000",
        })],
        _ => return Err(Error::Wmi(WmiProtoError::Hresult(WBEM_E_INVALID_CLASS))),
    };
    Ok(rows)
}
