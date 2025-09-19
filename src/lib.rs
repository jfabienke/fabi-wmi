use std::alloc::{alloc, dealloc, Layout};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::sync::{Arc, Mutex};

use serde_json::Value;
use thiserror::Error;
use tracing::debug;

mod auth;
mod crypto;
mod dcom;
mod ndr;
#[cfg(feature = "async")]
mod pool;
mod rpc;
mod transport; // Used internally by dcom and lib
mod wmi; // Re-exported types below

// Export auth module for examples
pub mod auth_exports {
    pub use crate::auth::{
        AuthError, AuthenticateMessage, Credentials, NegotiateMessage, NtlmV2Client,
    };
}

pub use auth::AuthError;
pub use dcom::{activate_wmi_dcom, resolve_oxid, DcomError, ObjectReference};
#[cfg(feature = "async")]
pub use pool::{
    AsyncTransportManager, PoolAcquireError, PoolBuildError, PooledTransport, WmiConnectionPool,
    WmiConnectionPoolBuilder,
};
pub use rpc::RpcError;
pub use wmi::{IWbemLocator, IWbemServices, WmiError};

#[derive(Error, Debug)]
pub enum WmiClientError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Dcom error: {0}")]
    Dcom(#[from] DcomError),
    #[error("RPC error: {0}")]
    Rpc(#[from] RpcError),
    #[error("WMI error: {0}")]
    Wmi(#[from] WmiError),
    #[error("Auth error: {0}")]
    Auth(#[from] AuthError),
    #[error("Invalid input: {0}")]
    Invalid(String),
    #[error("Alloc failed")]
    Alloc,
}

type Result<T> = std::result::Result<T, WmiClientError>;

#[repr(C)]
pub struct WmiSession {
    inner: *mut InnerSession,
}

pub struct InnerSession {
    _host: String,
    _port: u16,
    locator: wmi::IWbemLocator,
    services: Option<wmi::IWbemServices>,
    credentials: Option<auth::Credentials>,
    _codec: Arc<dyn ndr::NdrCodec + Send + Sync>,
    _transport: Arc<Mutex<Box<dyn transport::RpcTransport + Send>>>,
    _auth_level: u32,
}

impl Drop for WmiSession {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            unsafe {
                drop(Box::from_raw(self.inner));
            }
            self.inner = ptr::null_mut();
        }
    }
}

impl WmiSession {
    fn inner(&self) -> Result<&InnerSession> {
        unsafe {
            self.inner
                .as_ref()
                .ok_or_else(|| WmiClientError::Invalid("Session not initialised".into()))
        }
    }

    fn inner_mut(&mut self) -> Result<&mut InnerSession> {
        unsafe {
            self.inner
                .as_mut()
                .ok_or_else(|| WmiClientError::Invalid("Session not initialised".into()))
        }
    }
}

impl InnerSession {
    fn new(
        host: &str,
        username: Option<&str>,
        password: Option<&str>,
        domain: Option<&str>,
        auth_level: u32,
    ) -> Result<Self> {
        let username = username.filter(|s| !s.is_empty()).map(|s| s.to_string());
        let password = password.filter(|s| !s.is_empty()).map(|s| s.to_string());
        let domain_owned = domain.unwrap_or("").to_string();

        let base_creds =
            if let (Some(ref user), Some(ref pass)) = (username.as_ref(), password.as_ref()) {
                Some(auth::Credentials {
                    username: user.to_string(),
                    password: pass.to_string(),
                    domain: domain_owned.clone(),
                    workstation: host.to_string(),
                })
            } else {
                None
            };

        let port = dcom::resolve_wmi_port(host, base_creds.as_ref())
            .map_err(|err| WmiClientError::Invalid(format!("Port resolution failed: {err}")))?;

        // Allow stub transport only when explicitly enabled via environment variable
        // This is for testing purposes only
        let use_stub = std::env::var("LINUX_WMI_USE_STUB").as_deref() == Ok("1");

        // Choose NDR codec based on environment variable
        // Use stub codec in test mode with stub transport, otherwise use real codec
        let codec: Arc<dyn ndr::NdrCodec + Send + Sync> = if use_stub {
            debug!("Using StubNdrCodec for test mode");
            Arc::new(ndr::StubNdrCodec)
        } else {
            debug!("Using RealNdrCodec for NDR marshaling");
            Arc::new(ndr::RealNdrCodec::new())
        };

        let (user, pass) = match (username.as_ref(), password.as_ref()) {
            (Some(u), Some(p)) => (u.to_string(), p.to_string()),
            _ if use_stub => ("stub".to_string(), "stub".to_string()),
            _ => {
                return Err(WmiClientError::Invalid(
                    "Username and password are required for WMI connections".to_string()
                ));
            }
        };

        let config = transport::RealTransportConfig {
            host: host.to_string(),
            username: Some(user),
            password: Some(pass),
            domain: Some(domain_owned.clone()),
            read_timeout: None,
            write_timeout: None,
        };

        let transport: Arc<Mutex<Box<dyn transport::RpcTransport + Send>>> = if use_stub {
            Arc::new(Mutex::new(Box::new(transport::StubTransport)))
        } else {
            match transport::RealRpcTransport::connect(config) {
                Ok(real_transport) => Arc::new(Mutex::new(
                    Box::new(real_transport) as Box<dyn transport::RpcTransport + Send>
                )),
                Err(err) => {
                    return Err(WmiClientError::Invalid(format!(
                        "Failed to establish transport connection: {err}"
                    )));
                }
            }
        };

        let credentials = base_creds.clone();

        debug!(
            "Session created: host={}, port={}, auth_level={}",
            host, port, auth_level
        );

        Ok(Self {
            _host: host.to_string(),
            _port: port,
            locator: wmi::IWbemLocator::with_components(host, codec.clone(), transport.clone()),
            services: None,
            credentials,
            _codec: codec,
            _transport: transport,
            _auth_level: auth_level,
        })
    }

    fn open_namespace(&mut self, namespace: &str) -> Result<()> {
        let (username, password, domain) = if let Some(creds) = &self.credentials {
            (
                Some(creds.username.as_str()),
                Some(creds.password.as_str()),
                Some(creds.domain.as_str()),
            )
        } else {
            (None, None, None)
        };
        let services = self
            .locator
            .connect_server(namespace, username, password, domain)?;
        self.services = Some(services);
        Ok(())
    }

    fn services(&self) -> Result<&wmi::IWbemServices> {
        self.services
            .as_ref()
            .ok_or_else(|| WmiClientError::Invalid("Namespace not opened".into()))
    }

    fn exec_query(&self, wql: &str) -> Result<String> {
        let services = self.services()?;
        let values = services.exec_query(wql)?;
        serde_json::to_string(&values)
            .map_err(|err| WmiClientError::Invalid(format!("Serialize query result failed: {err}")))
    }

    fn exec_method(&self, class: &str, method: &str, params: &Value) -> Result<String> {
        let services = self.services()?;
        let value = services.exec_method(class, method, params)?;
        serde_json::to_string(&value).map_err(|err| {
            WmiClientError::Invalid(format!("Serialize method result failed: {err}"))
        })
    }
}

impl Drop for InnerSession {
    fn drop(&mut self) {
        if let Some(creds) = &mut self.credentials {
            creds.zeroize();
        }
    }
}

fn set_error(out_err: *mut *mut c_char, message: Option<String>) {
    if out_err.is_null() {
        return;
    }

    unsafe {
        if let Some(msg) = message {
            match CString::new(msg) {
                Ok(cstr) => {
                    *out_err = cstr.into_raw();
                }
                Err(_) => {
                    *out_err = ptr::null_mut();
                }
            }
        } else {
            *out_err = ptr::null_mut();
        }
    }
}

unsafe fn copy_json_to_out(
    out_json: *mut *mut u8,
    out_len: *mut usize,
    out_err: *mut *mut c_char,
    json: &str,
) -> i32 {
    if out_json.is_null() || out_len.is_null() {
        set_error(out_err, Some("Invalid output pointers".into()));
        return -1;
    }

    match CString::new(json) {
        Ok(cstr) => {
            let bytes = cstr.into_bytes_with_nul();
            let layout = match Layout::array::<u8>(bytes.len()) {
                Ok(layout) => layout,
                Err(_) => {
                    set_error(out_err, Some("Allocation layout error".into()));
                    return -1;
                }
            };
            let json_ptr = alloc(layout);
            if json_ptr.is_null() {
                set_error(out_err, Some("Alloc failed".into()));
                return -1;
            }
            ptr::copy_nonoverlapping(bytes.as_ptr(), json_ptr, bytes.len());
            *out_json = json_ptr;
            *out_len = bytes.len().saturating_sub(1);
            set_error(out_err, None);
            0
        }
        Err(_) => {
            set_error(out_err, Some("JSON contained NUL byte".into()));
            -1
        }
    }
}

#[no_mangle]
/// Create a new WMI session.
///
/// # Safety
///
/// Callers must pass valid C-style strings (or null pointers) for all string
/// parameters and a valid, writable pointer for `out_sess`. The resulting
/// session pointer must later be freed with `wmi_session_free`.
pub unsafe extern "C" fn wmi_session_new(
    host: *const c_char,
    username: *const c_char,
    password: *const c_char,
    domain: *const c_char,
    auth_flags: u32,
    out_sess: *mut *mut WmiSession,
    out_err: *mut *mut c_char,
) -> i32 {
    if out_sess.is_null() {
        set_error(out_err, Some("out_sess pointer was null".into()));
        return -1;
    }

    set_error(out_err, None);

    let host = if !host.is_null() {
        CStr::from_ptr(host).to_string_lossy().to_string()
    } else {
        "localhost".to_string()
    };
    let username = if !username.is_null() {
        Some(CStr::from_ptr(username).to_string_lossy().into_owned())
    } else {
        None
    };
    let password = if !password.is_null() {
        Some(CStr::from_ptr(password).to_string_lossy().into_owned())
    } else {
        None
    };
    let domain = if !domain.is_null() {
        Some(CStr::from_ptr(domain).to_string_lossy().into_owned())
    } else {
        None
    };

    match InnerSession::new(
        &host,
        username.as_deref(),
        password.as_deref(),
        domain.as_deref(),
        auth_flags,
    ) {
        Ok(inner) => {
            let boxed_inner = Box::new(inner);
            let inner_ptr = Box::into_raw(boxed_inner);
            let session = Box::new(WmiSession { inner: inner_ptr });
            *out_sess = Box::into_raw(session);
            0
        }
        Err(err) => {
            *out_sess = ptr::null_mut();
            set_error(out_err, Some(format!("Session new failed: {err}")));
            -1
        }
    }
}

#[no_mangle]
/// Release a session created with `wmi_session_new`.
///
/// # Safety
///
/// `sess` must be either null or a pointer obtained from `wmi_session_new` that
/// has not already been freed.
pub unsafe extern "C" fn wmi_session_free(sess: *mut WmiSession) {
    if sess.is_null() {
        return;
    }
    drop(Box::from_raw(sess));
}

#[no_mangle]
/// Bind an existing session to a namespace.
///
/// # Safety
///
/// `sess` must point to a valid session. `ns` must be a UTF-8 encoded,
/// null-terminated string.
pub unsafe extern "C" fn wmi_namespace_open(
    sess: *mut WmiSession,
    ns: *const c_char,
    out_err: *mut *mut c_char,
) -> i32 {
    if sess.is_null() {
        set_error(out_err, Some("Session pointer was null".into()));
        return -1;
    }
    let namespace = if !ns.is_null() {
        CStr::from_ptr(ns).to_string_lossy().to_string()
    } else {
        set_error(out_err, Some("Namespace pointer was null".into()));
        return -1;
    };

    let session = &mut *sess;
    match session
        .inner_mut()
        .and_then(|inner| inner.open_namespace(&namespace))
    {
        Ok(()) => {
            set_error(out_err, None);
            0
        }
        Err(err) => {
            set_error(out_err, Some(format!("Namespace open failed: {err}")));
            -1
        }
    }
}

#[no_mangle]
/// Execute a WQL query and return the JSON payload.
///
/// # Safety
///
/// `sess` must be a valid session pointer. `wql` must be a valid UTF-8 C string.
/// The caller is responsible for freeing the returned JSON buffer with
/// `wmi_free_json`.
pub unsafe extern "C" fn wmi_exec_query_json(
    sess: *mut WmiSession,
    wql: *const c_char,
    _timeout_ms: u32,
    out_json: *mut *mut u8,
    out_len: *mut usize,
    out_err: *mut *mut c_char,
) -> i32 {
    if sess.is_null() || wql.is_null() {
        set_error(out_err, Some("Invalid session or WQL".into()));
        return -1;
    }

    let wql = CStr::from_ptr(wql).to_string_lossy().to_string();
    let session = &mut *sess;
    let inner = match session.inner() {
        Ok(inner) => inner,
        Err(err) => {
            set_error(out_err, Some(format!("Query failed: {err}")));
            return -1;
        }
    };

    let result = match inner.exec_query(&wql) {
        Ok(json) => json,
        Err(err) => {
            set_error(out_err, Some(format!("Query failed: {err}")));
            return -1;
        }
    };
    copy_json_to_out(out_json, out_len, out_err, &result)
}

#[no_mangle]
/// Execute a WMI method and return the JSON payload.
///
/// # Safety
///
/// `sess` must be valid. `class`, `method`, and `in_params_json` must be
/// UTF-8 C strings (the params pointer may be null to imply `{}`). The caller
/// must free the returned JSON buffer with `wmi_free_json`.
pub unsafe extern "C" fn wmi_exec_method_json(
    sess: *mut WmiSession,
    class: *const c_char,
    method: *const c_char,
    in_params_json: *const c_char,
    _timeout_ms: u32,
    out_json: *mut *mut u8,
    out_len: *mut usize,
    out_err: *mut *mut c_char,
) -> i32 {
    if sess.is_null() || class.is_null() || method.is_null() {
        set_error(out_err, Some("Invalid session or method inputs".into()));
        return -1;
    }

    let class = CStr::from_ptr(class).to_string_lossy().to_string();
    let method = CStr::from_ptr(method).to_string_lossy().to_string();
    let params_json = if !in_params_json.is_null() {
        CStr::from_ptr(in_params_json).to_string_lossy().to_string()
    } else {
        "{}".to_string()
    };
    let params: Value = match serde_json::from_str(&params_json) {
        Ok(value) => value,
        Err(err) => {
            set_error(out_err, Some(format!("Invalid JSON parameters: {err}")));
            return -1;
        }
    };

    let session = &mut *sess;
    let inner = match session.inner() {
        Ok(inner) => inner,
        Err(err) => {
            set_error(out_err, Some(format!("Method failed: {err}")));
            return -1;
        }
    };

    let result = match inner.exec_method(&class, &method, &params) {
        Ok(json) => json,
        Err(err) => {
            set_error(out_err, Some(format!("Method failed: {err}")));
            return -1;
        }
    };
    copy_json_to_out(out_json, out_len, out_err, &result)
}

#[no_mangle]
/// Free a JSON buffer returned from `wmi_exec_query_json` or
/// `wmi_exec_method_json`.
///
/// # Safety
///
/// `ptr` must be the pointer returned by one of the exec functions, and `len`
/// must match the reported length.
pub unsafe extern "C" fn wmi_free_json(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    if let Ok(layout) = Layout::array::<u8>(len.saturating_add(1)) {
        dealloc(ptr, layout);
    }
}

#[no_mangle]
/// Free an error string returned via the FFI.
///
/// # Safety
///
/// `ptr` must be the pointer previously returned in an error out-parameter and
/// not yet freed.
pub unsafe extern "C" fn wmi_free_err(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    drop(CString::from_raw(ptr));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Once;

    fn enable_epm_stub() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            std::env::set_var("LINUX_WMI_SKIP_EPM", "1");
            std::env::set_var("LINUX_WMI_USE_STUB", "1");
        });
    }

    #[test]
    fn set_error_writes_message() {
        let mut err_ptr: *mut c_char = ptr::null_mut();
        set_error(&mut err_ptr, Some("hello".into()));
        assert!(!err_ptr.is_null());
        unsafe {
            let msg = CString::from_raw(err_ptr).into_string().unwrap();
            assert_eq!(msg, "hello");
        }
    }

    #[test]
    fn set_error_ignores_null_pointer() {
        set_error(ptr::null_mut(), Some("ignored".into()));
    }

    #[test]
    fn copy_json_to_out_round_trip() {
        let mut json_ptr: *mut u8 = ptr::null_mut();
        let mut json_len: usize = 0;
        let mut err_ptr: *mut c_char = ptr::null_mut();
        let json = "[{}]";
        let rc = unsafe { copy_json_to_out(&mut json_ptr, &mut json_len, &mut err_ptr, json) };
        assert_eq!(rc, 0);
        assert!(err_ptr.is_null());
        unsafe {
            let slice = std::slice::from_raw_parts(json_ptr, json_len);
            assert_eq!(slice, json.as_bytes());
            wmi_free_json(json_ptr, json_len);
        }
    }

    #[test]
    fn copy_json_to_out_rejects_nul() {
        let mut json_ptr: *mut u8 = ptr::null_mut();
        let mut json_len: usize = 0;
        let mut err_ptr: *mut c_char = ptr::null_mut();
        let json = "bad\0json";
        let rc = unsafe { copy_json_to_out(&mut json_ptr, &mut json_len, &mut err_ptr, json) };
        assert_eq!(rc, -1);
        assert!(json_ptr.is_null());
        unsafe {
            if !err_ptr.is_null() {
                let _ = CString::from_raw(err_ptr);
            }
        }
    }

    #[test]
    fn copy_json_to_out_null_outputs() {
        let mut err_ptr: *mut c_char = ptr::null_mut();
        let rc = unsafe { copy_json_to_out(ptr::null_mut(), ptr::null_mut(), &mut err_ptr, "{}") };
        assert_eq!(rc, -1);
        unsafe {
            if !err_ptr.is_null() {
                let _ = CString::from_raw(err_ptr);
            }
        }
    }

    #[test]
    fn inner_session_new_extracts_credentials() {
        enable_epm_stub();
        let session =
            InnerSession::new("host", Some("user"), Some("pass"), Some("domain"), 0).unwrap();
        assert!(session.credentials.is_some());

        let session = InnerSession::new("host", Some("user"), Some(""), None, 0).unwrap();
        assert!(session.credentials.is_none());
    }

    #[test]
    fn inner_session_query_and_method_success() {
        enable_epm_stub();
        let mut session = InnerSession::new("host", None, None, None, 0).unwrap();
        session.open_namespace("CimV2").unwrap();

        let json = session.exec_query("SELECT * FROM Win32_Process").unwrap();
        assert!(json.contains("ThreadCount"));

        let response = session
            .exec_method("Win32_Process", "GetOwner", &json!({"Handle": 1}))
            .unwrap();
        assert!(response.contains("SYSTEM"));
    }

    #[test]
    fn inner_session_exec_query_error_propagates() {
        enable_epm_stub();
        let mut session = InnerSession::new("host", None, None, None, 0).unwrap();
        session.open_namespace("CimV2").unwrap();
        let err = session
            .exec_query("SELECT * FROM Win32_Unknown")
            .unwrap_err();
        assert!(matches!(err, WmiClientError::Wmi(_)));
    }
}
