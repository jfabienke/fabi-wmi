//! In-process stand-in for a WMI server, used by the C ABI when
//! `LINUX_WMI_USE_STUB=1` (requires the `test-support` feature). It lets the
//! FFI and .NET plumbing be tested without a Windows host; it is not a model of
//! WMI semantics beyond a few canned classes.

use serde_json::{json, Value};

use crate::client::Error;
use crate::wmi_proto::WmiProtoError;

/// WBEM_E_INVALID_CLASS, what Windows returns for an unknown class.
const WBEM_E_INVALID_CLASS: u32 = 0x8004_1010;
/// WBEM_E_METHOD_NOT_IMPLEMENTED, what Windows returns for an unknown method.
const WBEM_E_METHOD_NOT_IMPLEMENTED: u32 = 0x8004_1055;

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

/// Canned output parameters for `ExecMethod(object_path, method, params)`.
pub(crate) fn exec_method(
    object_path: &str,
    method: &str,
    _params: &Value,
) -> Result<Value, Error> {
    let class = crate::client::class_name_from_path(object_path).to_ascii_uppercase();
    let method_upper = method.to_ascii_uppercase();
    match (class.as_str(), method_upper.as_str()) {
        ("WIN32_PROCESS", "GETOWNER") => Ok(json!({
            "ReturnValue": 0,
            "User": "SYSTEM",
            "Domain": "NT AUTHORITY",
        })),
        ("WIN32_PROCESS", "CREATE") => Ok(json!({
            "ReturnValue": 0,
            "ProcessId": 4242,
        })),
        ("WIN32_PROCESS", "TERMINATE") => Ok(json!({
            "ReturnValue": 0,
        })),
        ("WIN32_PROCESS" | "WIN32_COMPUTERSYSTEM" | "WIN32_OPERATINGSYSTEM", _) => Err(Error::Wmi(
            WmiProtoError::Hresult(WBEM_E_METHOD_NOT_IMPLEMENTED),
        )),
        _ => Err(Error::Wmi(WmiProtoError::Hresult(WBEM_E_INVALID_CLASS))),
    }
}
