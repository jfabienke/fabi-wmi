//! WMI client for Linux and macOS: WQL queries and method calls against Windows
//! hosts over DCOM / MS-RPC, with no Windows components.
//!
//! ```no_run
//! use fabi_wmi::{Credentials, WmiClient};
//!
//! let creds = Credentials::new("Administrator", "secret");
//! let mut wmi = WmiClient::connect("192.0.2.10", &creds, r"root\cimv2")?;
//! for row in wmi.query("SELECT Name, ProcessId FROM Win32_Process")? {
//!     println!("{} {}", row["ProcessId"], row["Name"]);
//! }
//! # Ok::<(), fabi_wmi::Error>(())
//! ```
//!
//! With the `ffi` feature enabled (default), the crate also exports a C ABI
//! (`include/linux_wmi.h`) used by the .NET shim in `shim/wmi_shim.cs`.

mod client;
#[cfg(feature = "kerberos")]
mod kerberos_adapter;
#[cfg(all(feature = "ffi", any(test, feature = "test-support")))]
mod test_support;
mod wmi_proto;

pub use client::{exec_method, query, Auth, Error, WmiClient, DEFAULT_TIMEOUT};
pub use fabi_dcerpc::{AuthError, Credentials, RpcError};
pub use fabi_dcom::DcomError;
pub use fabi_wmio::WmioError;
#[cfg(feature = "kerberos")]
pub use kerberos_adapter::{KerberosCacheBackend, KerberosClient, KerberosConfig, KerberosError};
pub use wmi_proto::WmiProtoError;

#[cfg(feature = "ffi")]
mod ffi {
    use std::alloc::{alloc, dealloc, Layout};
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;
    use std::ptr;
    use std::sync::Mutex;

    use serde_json::Value;
    use tracing::debug;

    #[cfg(any(test, feature = "test-support"))]
    use crate::test_support;
    use crate::{Credentials, Error, WmiClient, DEFAULT_TIMEOUT};

    /// Errors at the C ABI boundary: a WMI failure, or bad input from the caller.
    #[derive(thiserror::Error, Debug)]
    pub(super) enum FfiError {
        #[error("{0}")]
        Wmi(#[from] Error),
        #[error("Invalid input: {0}")]
        Invalid(String),
    }

    impl FfiError {
        /// The status an FFI call returns for this error: the server's HRESULT
        /// when there is one (e.g. 0x80070005 for bad credentials), else -1.
        pub(super) fn status(&self) -> i32 {
            match self {
                FfiError::Wmi(err) => err.hresult().map_or(-1, |hr| hr as i32),
                FfiError::Invalid(_) => -1,
            }
        }
    }

    type Result<T> = std::result::Result<T, FfiError>;

    /// 0 on success. On failure, the server's HRESULT when one is known (e.g.
    /// 0x80070005 E_ACCESSDENIED, 0x8004100E WBEM_E_INVALID_NAMESPACE, read as a
    /// negative int32), otherwise -1; `*out_err` then holds a message to free
    /// with `wmi_free_err`.
    #[allow(non_camel_case_types)]
    pub type wmi_status_t = i32;

    /// Requested DCOM authentication level (the .NET shim passes its
    /// `WmiAuthLevel`). Only logged: activation runs at packet privacy and WMI
    /// calls at packet integrity.
    #[allow(non_camel_case_types)]
    pub type wmi_auth_flags_t = u32;

    /// Opaque session handle for the C ABI.
    pub struct WmiSession {
        inner: *mut InnerSession,
    }

    impl Drop for WmiSession {
        fn drop(&mut self) {
            if !self.inner.is_null() {
                // SAFETY: `inner` came from Box::into_raw in wmi_session_new and is
                // freed exactly once, here.
                unsafe {
                    drop(Box::from_raw(self.inner));
                }
                self.inner = ptr::null_mut();
            }
        }
    }

    impl WmiSession {
        fn inner(&self) -> Result<&InnerSession> {
            // SAFETY: `inner` is null or a live Box pointer owned by this session.
            unsafe {
                self.inner
                    .as_ref()
                    .ok_or_else(|| FfiError::Invalid("Session not initialised".into()))
            }
        }

        fn inner_mut(&mut self) -> Result<&mut InnerSession> {
            // SAFETY: as in `inner`; `&mut self` guarantees exclusive access.
            unsafe {
                self.inner
                    .as_mut()
                    .ok_or_else(|| FfiError::Invalid("Session not initialised".into()))
            }
        }
    }

    pub(super) struct InnerSession {
        pub(super) host: String,
        pub(super) credentials: Option<Credentials>,
        pub(super) backend: Backend,
    }

    pub(super) enum Backend {
        /// `LINUX_WMI_USE_STUB=1`: canned in-process results (tests only).
        #[cfg(any(test, feature = "test-support"))]
        Stub { namespace: Option<String> },
        /// Real DCOM/WMI: a logged-in [`WmiClient`] per opened namespace, reused
        /// by queries and replaced when an error leaves its connection unusable.
        Dcom {
            namespace: Option<String>,
            client: Mutex<Option<Box<WmiClient>>>,
        },
    }

    impl InnerSession {
        pub(super) fn new(
            host: &str,
            username: Option<&str>,
            password: Option<&str>,
            domain: Option<&str>,
            auth_level: u32,
        ) -> Result<Self> {
            if host.trim().is_empty() {
                return Err(FfiError::Invalid("Host must not be empty".into()));
            }
            // The stub backend is for tests only and must be enabled explicitly.
            let use_stub = std::env::var("LINUX_WMI_USE_STUB").as_deref() == Ok("1");
            let credentials = match (
                username.filter(|s| !s.is_empty()),
                password.filter(|s| !s.is_empty()),
            ) {
                (Some(user), Some(pass)) => {
                    Some(Credentials::new(user, pass).with_domain(domain.unwrap_or("")))
                }
                _ => None,
            };
            let backend = if use_stub {
                Self::stub_backend()?
            } else if credentials.is_some() {
                // No network I/O yet: wmi_namespace_open activates and logs in, so
                // bad hosts, credentials and namespaces all surface there.
                Backend::Dcom {
                    namespace: None,
                    client: Mutex::new(None),
                }
            } else {
                return Err(FfiError::Invalid(
                    "Username and password are required for WMI connections".to_string(),
                ));
            };
            debug!(host, auth_level, stub = use_stub, "session created");
            Ok(Self {
                host: host.to_string(),
                credentials,
                backend,
            })
        }

        #[cfg(any(test, feature = "test-support"))]
        fn stub_backend() -> Result<Backend> {
            Ok(Backend::Stub { namespace: None })
        }

        #[cfg(not(any(test, feature = "test-support")))]
        fn stub_backend() -> Result<Backend> {
            Err(FfiError::Invalid(
                "LINUX_WMI_USE_STUB=1 requires a build with the test-support feature".into(),
            ))
        }

        fn credentials(&self) -> &Credentials {
            self.credentials
                .as_ref()
                .expect("DCOM sessions are only created with credentials")
        }

        pub(super) fn open_namespace(&mut self, namespace: &str) -> Result<()> {
            if namespace.trim().is_empty() {
                return Err(FfiError::Invalid("Namespace must not be empty".into()));
            }
            let connected = match &self.backend {
                #[cfg(any(test, feature = "test-support"))]
                Backend::Stub { .. } => None,
                Backend::Dcom { .. } => Some(WmiClient::connect(
                    &self.host,
                    self.credentials(),
                    namespace,
                )?),
            };
            match &mut self.backend {
                #[cfg(any(test, feature = "test-support"))]
                Backend::Stub { namespace: ns } => *ns = Some(namespace.to_string()),
                Backend::Dcom {
                    namespace: ns,
                    client,
                } => {
                    // Replacing a previous client drops it, releasing its references.
                    *client.get_mut().unwrap_or_else(|p| p.into_inner()) = connected.map(Box::new);
                    *ns = Some(namespace.to_string());
                }
            }
            Ok(())
        }

        fn with_dcom_client<T>(
            &self,
            namespace: &Option<String>,
            client_slot: &Mutex<Option<Box<WmiClient>>>,
            timeout_ms: u32,
            f: impl FnOnce(&mut WmiClient) -> std::result::Result<T, Error>,
        ) -> Result<T> {
            let namespace = namespace
                .as_deref()
                .ok_or_else(|| FfiError::Invalid("Namespace not opened".into()))?;
            let timeout = match timeout_ms {
                0 => DEFAULT_TIMEOUT,
                ms => std::time::Duration::from_millis(u64::from(ms)),
            };
            let mut slot = client_slot.lock().unwrap_or_else(|p| p.into_inner());
            // Reconnect if an earlier error left the connection unusable.
            if slot.as_deref().is_none_or(WmiClient::is_broken) {
                *slot = None;
                *slot = Some(Box::new(WmiClient::connect_with_timeout(
                    &self.host,
                    self.credentials(),
                    namespace,
                    timeout,
                )?));
            }
            let client = slot.as_mut().expect("connected above");
            client.set_timeout(timeout)?;
            Ok(f(client)?)
        }

        /// Run `wql`; `timeout_ms` bounds each network read/write, and each
        /// request-response exchange to four times that (0 = default).
        pub(super) fn exec_query(&self, wql: &str, timeout_ms: u32) -> Result<String> {
            let values = match &self.backend {
                #[cfg(any(test, feature = "test-support"))]
                Backend::Stub { namespace } => {
                    namespace
                        .as_ref()
                        .ok_or_else(|| FfiError::Invalid("Namespace not opened".into()))?;
                    test_support::query(wql)?
                }
                Backend::Dcom { namespace, client } => {
                    self.with_dcom_client(namespace, client, timeout_ms, |c| c.query(wql))?
                }
            };
            serde_json::to_string(&values)
                .map_err(|err| FfiError::Invalid(format!("Serialize query result failed: {err}")))
        }

        /// Invoke `method` on `class` with `params`; `timeout_ms` as for
        /// [`Self::exec_query`].
        pub(super) fn exec_method(
            &self,
            class: &str,
            method: &str,
            params: &Value,
            timeout_ms: u32,
        ) -> Result<String> {
            let out = match &self.backend {
                #[cfg(any(test, feature = "test-support"))]
                Backend::Stub { namespace } => {
                    namespace
                        .as_ref()
                        .ok_or_else(|| FfiError::Invalid("Namespace not opened".into()))?;
                    test_support::exec_method(class, method, params)?
                }
                Backend::Dcom { namespace, client } => {
                    self.with_dcom_client(namespace, client, timeout_ms, |c| {
                        c.exec_method(class, method, params)
                    })?
                }
            };
            serde_json::to_string(&out)
                .map_err(|err| FfiError::Invalid(format!("Serialize method result failed: {err}")))
        }
    }

    pub(super) fn set_error(out_err: *mut *mut c_char, message: Option<String>) {
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

    pub(super) unsafe fn copy_json_to_out(
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
    /// Creates a session; does no network I/O.
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
        auth_flags: wmi_auth_flags_t,
        out_sess: *mut *mut WmiSession,
        out_err: *mut *mut c_char,
    ) -> wmi_status_t {
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
    /// Activates WMI on the host and logs in to the namespace (e.g.
    /// "root\\cimv2"); bad hosts, credentials and namespaces fail here.
    ///
    /// # Safety
    ///
    /// `sess` must point to a valid session. `ns` must be a UTF-8 encoded,
    /// null-terminated string.
    pub unsafe extern "C" fn wmi_namespace_open(
        sess: *mut WmiSession,
        ns: *const c_char,
        out_err: *mut *mut c_char,
    ) -> wmi_status_t {
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
                err.status()
            }
        }
    }

    #[no_mangle]
    /// Runs a WQL query; `*out_json` is a JSON array with one object per row.
    /// `timeout_ms` bounds each network read/write (0 = default, 30 s), and
    /// each request to the server must be answered within four times that.
    ///
    /// # Safety
    ///
    /// `sess` must be a valid session pointer. `wql` must be a valid UTF-8 C string.
    /// The caller is responsible for freeing the returned JSON buffer with
    /// `wmi_free_json`.
    pub unsafe extern "C" fn wmi_exec_query_json(
        sess: *mut WmiSession,
        wql: *const c_char,
        timeout_ms: u32,
        out_json: *mut *mut u8,
        out_len: *mut usize,
        out_err: *mut *mut c_char,
    ) -> wmi_status_t {
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

        let result = match inner.exec_query(&wql, timeout_ms) {
            Ok(json) => json,
            Err(err) => {
                set_error(out_err, Some(format!("Query failed: {err}")));
                return err.status();
            }
        };
        copy_json_to_out(out_json, out_len, out_err, &result)
    }

    #[no_mangle]
    /// Calls a method on a class (e.g. "StdRegProv") or an instance path (e.g.
    /// "Win32_Service.Name=\"Winmgmt\""). `in_params_json` is a JSON object of
    /// input parameters (NULL = none); `*out_json` is the output parameters,
    /// including ReturnValue. `timeout_ms` as for `wmi_exec_query_json`.
    ///
    /// # Safety
    ///
    /// `sess` must be valid. `path_or_class`, `method`, and `in_params_json`
    /// must be UTF-8 C strings (the params pointer may be null to imply `{}`).
    /// The caller must free the returned JSON buffer with `wmi_free_json`.
    pub unsafe extern "C" fn wmi_exec_method_json(
        sess: *mut WmiSession,
        path_or_class: *const c_char,
        method: *const c_char,
        in_params_json: *const c_char,
        timeout_ms: u32,
        out_json: *mut *mut u8,
        out_len: *mut usize,
        out_err: *mut *mut c_char,
    ) -> wmi_status_t {
        if sess.is_null() || path_or_class.is_null() || method.is_null() {
            set_error(out_err, Some("Invalid session or method inputs".into()));
            return -1;
        }

        let class = CStr::from_ptr(path_or_class).to_string_lossy().to_string();
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

        let result = match inner.exec_method(&class, &method, &params, timeout_ms) {
            Ok(json) => json,
            Err(err) => {
                set_error(out_err, Some(format!("Method failed: {err}")));
                return err.status();
            }
        };
        copy_json_to_out(out_json, out_len, out_err, &result)
    }

    #[no_mangle]
    /// Releases the session and the server-side references it holds.
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
        use crate::{DcomError, RpcError, WmiProtoError};
        use serde_json::json;
        use std::sync::Once;

        fn enable_stub() {
            static INIT: Once = Once::new();
            INIT.call_once(|| std::env::set_var("LINUX_WMI_USE_STUB", "1"));
        }

        fn dcom_session() -> InnerSession {
            InnerSession {
                host: "host".into(),
                credentials: Some(Credentials::new("user", "pass")),
                backend: Backend::Dcom {
                    namespace: None,
                    client: Mutex::new(None),
                },
            }
        }

        #[test]
        fn dcom_session_requires_an_open_namespace() {
            let err = dcom_session().exec_query("SELECT * FROM Win32_Process", 0);
            assert!(
                matches!(err, Err(FfiError::Invalid(msg)) if msg.contains("Namespace not opened"))
            );
            let err = dcom_session().exec_method("Win32_Process", "Create", &json!({}), 0);
            assert!(
                matches!(err, Err(FfiError::Invalid(msg)) if msg.contains("Namespace not opened"))
            );
        }

        #[test]
        fn dcom_session_rejects_empty_namespace() {
            assert!(dcom_session().open_namespace("  ").is_err());
        }

        #[test]
        fn error_status_carries_the_hresult() {
            let invalid_class = FfiError::Wmi(Error::Wmi(WmiProtoError::Hresult(0x8004_1010)));
            assert_eq!(invalid_class.status(), 0x8004_1010u32 as i32);
            let denied = FfiError::Wmi(Error::Activation(DcomError::AccessDenied));
            assert_eq!(denied.status(), 0x8007_0005u32 as i32);
            let fault = FfiError::Wmi(Error::Rpc(RpcError::Fault(5)));
            assert_eq!(fault.status(), 0x8007_0005u32 as i32);
            assert_eq!(FfiError::Invalid("x".into()).status(), -1);
            let lost = FfiError::Wmi(Error::Protocol("desync".into()));
            assert_eq!(lost.status(), -1);
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
            let rc =
                unsafe { copy_json_to_out(ptr::null_mut(), ptr::null_mut(), &mut err_ptr, "{}") };
            assert_eq!(rc, -1);
            unsafe {
                if !err_ptr.is_null() {
                    let _ = CString::from_raw(err_ptr);
                }
            }
        }

        #[test]
        fn inner_session_new_extracts_credentials() {
            enable_stub();
            let session =
                InnerSession::new("host", Some("user"), Some("pass"), Some("domain"), 0).unwrap();
            assert!(session.credentials.is_some());

            let session = InnerSession::new("host", Some("user"), Some(""), None, 0).unwrap();
            assert!(session.credentials.is_none());
        }

        #[test]
        fn inner_session_stub_query_and_method() {
            enable_stub();
            let mut session = InnerSession::new("host", None, None, None, 0).unwrap();
            session.open_namespace("CimV2").unwrap();

            let json = session
                .exec_query("SELECT * FROM Win32_Process", 0)
                .unwrap();
            assert!(json.contains("ThreadCount"));

            let out = session
                .exec_method("Win32_Process", "GetOwner", &json!({}), 0)
                .unwrap();
            assert!(out.contains("SYSTEM"));

            let err = session
                .exec_method("Win32_Process", "UnknownMethod", &json!({}), 0)
                .unwrap_err();
            assert_eq!(err.status(), 0x8004_1055u32 as i32);
        }

        #[test]
        fn inner_session_exec_query_error_propagates() {
            enable_stub();
            let mut session = InnerSession::new("host", None, None, None, 0).unwrap();
            session.open_namespace("CimV2").unwrap();
            let err = session
                .exec_query("SELECT * FROM Win32_Unknown", 0)
                .unwrap_err();
            assert!(matches!(err, FfiError::Wmi(_)));
            assert_eq!(err.status(), 0x8004_1010u32 as i32);
        }
    }
}

#[cfg(feature = "ffi")]
pub use ffi::*;
