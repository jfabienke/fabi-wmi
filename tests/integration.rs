use linux_wmi::{
    wmi_exec_method_json, wmi_exec_query_json, wmi_free_err, wmi_free_json, wmi_namespace_open,
    wmi_session_free, wmi_session_new, WmiSession,
};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

fn new_session() -> (*mut WmiSession, Vec<CString>) {
    std::env::set_var("LINUX_WMI_USE_STUB", "1");
    let host = CString::new("localhost").unwrap();
    let mut session_ptr: *mut WmiSession = ptr::null_mut();
    let mut err_ptr: *mut c_char = ptr::null_mut();

    let rc = unsafe {
        wmi_session_new(
            host.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            0,
            &mut session_ptr,
            &mut err_ptr,
        )
    };
    assert_eq!(rc, 0, "session creation failed");
    if !err_ptr.is_null() {
        unsafe { wmi_free_err(err_ptr) };
    }
    assert!(!session_ptr.is_null());

    (session_ptr, vec![host])
}

#[test]
fn ffi_query_flow_returns_stub_data() {
    let (session_ptr, cstrings) = new_session();
    let namespace = CString::new("root\\CimV2").unwrap();
    let mut err_ptr: *mut c_char = ptr::null_mut();

    let rc = unsafe { wmi_namespace_open(session_ptr, namespace.as_ptr(), &mut err_ptr) };
    assert_eq!(rc, 0, "namespace open failed");
    if !err_ptr.is_null() {
        unsafe { wmi_free_err(err_ptr) };
    }

    let query = CString::new("SELECT Name FROM Win32_Process").unwrap();
    let mut json_ptr: *mut u8 = ptr::null_mut();
    let mut json_len: usize = 0;
    let mut err_ptr: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        wmi_exec_query_json(
            session_ptr,
            query.as_ptr(),
            1_000,
            &mut json_ptr,
            &mut json_len,
            &mut err_ptr,
        )
    };
    assert_eq!(rc, 0, "query should succeed");
    assert!(err_ptr.is_null());
    assert!(!json_ptr.is_null());

    let json = unsafe { std::slice::from_raw_parts(json_ptr, json_len) };
    let json_str = std::str::from_utf8(json).unwrap();
    assert!(json_str.contains("ProcessId"));

    unsafe { wmi_free_json(json_ptr, json_len) };
    unsafe { wmi_session_free(session_ptr) };
    drop(cstrings);
}

#[test]
fn ffi_method_reports_not_implemented() {
    let (session_ptr, _strings) = new_session();
    let namespace = CString::new("root\\CimV2").unwrap();
    let mut err_ptr: *mut c_char = ptr::null_mut();
    let rc = unsafe { wmi_namespace_open(session_ptr, namespace.as_ptr(), &mut err_ptr) };
    assert_eq!(rc, 0);
    if !err_ptr.is_null() {
        unsafe { wmi_free_err(err_ptr) };
    }

    let class = CString::new("Win32_Process").unwrap();
    let method = CString::new("GetOwner").unwrap();
    let params = CString::new("{\"Handle\": 1234}").unwrap();
    let mut json_ptr: *mut u8 = ptr::null_mut();
    let mut json_len: usize = 0;
    let mut err_ptr: *mut c_char = ptr::null_mut();

    let rc = unsafe {
        wmi_exec_method_json(
            session_ptr,
            class.as_ptr(),
            method.as_ptr(),
            params.as_ptr(),
            5_000,
            &mut json_ptr,
            &mut json_len,
            &mut err_ptr,
        )
    };
    // ExecMethod is now unsupported and should return error
    assert_eq!(rc, -1, "method should return unsupported");
    assert!(!err_ptr.is_null());

    // Check error message indicates it's unsupported
    let err_msg = unsafe { CStr::from_ptr(err_ptr).to_string_lossy() };
    assert!(err_msg.contains("not implemented") || err_msg.contains("not yet implemented"));

    unsafe { wmi_free_err(err_ptr) };
    unsafe { wmi_session_free(session_ptr) };
}

#[test]
fn ffi_namespace_open_error_propagates() {
    let (session_ptr, _strings) = new_session();
    let mut err_ptr: *mut c_char = ptr::null_mut();
    let rc = unsafe { wmi_namespace_open(session_ptr, ptr::null(), &mut err_ptr) };
    assert_eq!(rc, -1);
    assert!(!err_ptr.is_null());
    unsafe { wmi_free_err(err_ptr) };
    unsafe { wmi_session_free(session_ptr) };
}

#[test]
fn ffi_method_with_null_params_reaches_the_backend() {
    let (session_ptr, _strings) = new_session();
    let namespace = CString::new("root\\CimV2").unwrap();
    let mut err_ptr: *mut c_char = ptr::null_mut();
    let rc = unsafe { wmi_namespace_open(session_ptr, namespace.as_ptr(), &mut err_ptr) };
    assert_eq!(rc, 0);
    if !err_ptr.is_null() {
        unsafe { wmi_free_err(err_ptr) };
    }

    // A null params pointer means "{}": the call gets past parameter parsing
    // and is answered by the backend (ExecMethod is not implemented yet).
    let class = CString::new("Win32_Process").unwrap();
    let method = CString::new("GetOwner").unwrap();
    let mut json_ptr: *mut u8 = ptr::null_mut();
    let mut json_len: usize = 0;
    let mut err_ptr: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        wmi_exec_method_json(
            session_ptr,
            class.as_ptr(),
            method.as_ptr(),
            ptr::null(),
            1_000,
            &mut json_ptr,
            &mut json_len,
            &mut err_ptr,
        )
    };
    assert_eq!(rc, -1);
    assert!(json_ptr.is_null());
    unsafe {
        let err_msg = CStr::from_ptr(err_ptr).to_string_lossy().into_owned();
        assert!(err_msg.contains("not implemented"), "{err_msg}");
        assert!(!err_msg.contains("Invalid JSON"));
        wmi_free_err(err_ptr);
        wmi_session_free(session_ptr);
    }
}

#[test]
fn ffi_query_unknown_class_returns_the_hresult() {
    let (session_ptr, _strings) = new_session();
    let namespace = CString::new("root\\CimV2").unwrap();
    let mut err_ptr: *mut c_char = ptr::null_mut();
    let rc = unsafe { wmi_namespace_open(session_ptr, namespace.as_ptr(), &mut err_ptr) };
    assert_eq!(rc, 0);

    let wql = CString::new("SELECT * FROM Win32_NoSuchClass").unwrap();
    let mut json_ptr: *mut u8 = ptr::null_mut();
    let mut json_len: usize = 0;
    let rc = unsafe {
        wmi_exec_query_json(
            session_ptr,
            wql.as_ptr(),
            0,
            &mut json_ptr,
            &mut json_len,
            &mut err_ptr,
        )
    };
    assert_eq!(rc as u32, 0x8004_1010, "WBEM_E_INVALID_CLASS");
    assert!(json_ptr.is_null());
    unsafe {
        wmi_free_err(err_ptr);
        wmi_session_free(session_ptr);
    }
}

#[test]
fn ffi_method_rejects_invalid_params_json() {
    let (session_ptr, _strings) = new_session();
    let namespace = CString::new("root\\CimV2").unwrap();
    let mut err_ptr: *mut c_char = ptr::null_mut();
    let rc = unsafe { wmi_namespace_open(session_ptr, namespace.as_ptr(), &mut err_ptr) };
    assert_eq!(rc, 0);
    if !err_ptr.is_null() {
        unsafe { wmi_free_err(err_ptr) };
    }

    let class = CString::new("Win32_Process").unwrap();
    let method = CString::new("GetOwner").unwrap();
    let params = CString::new("{invalid json").unwrap();
    let mut json_ptr: *mut u8 = ptr::null_mut();
    let mut json_len: usize = 0;
    let mut err_ptr: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        wmi_exec_method_json(
            session_ptr,
            class.as_ptr(),
            method.as_ptr(),
            params.as_ptr(),
            1_000,
            &mut json_ptr,
            &mut json_len,
            &mut err_ptr,
        )
    };
    assert_eq!(rc, -1);
    assert!(json_ptr.is_null());
    unsafe {
        if !err_ptr.is_null() {
            wmi_free_err(err_ptr);
        }
        wmi_session_free(session_ptr);
    }
}

#[test]
fn ffi_query_without_namespace_fails() {
    let (session_ptr, _strings) = new_session();
    let query = CString::new("SELECT * FROM Win32_Process").unwrap();
    let mut json_ptr: *mut u8 = ptr::null_mut();
    let mut json_len: usize = 0;
    let mut err_ptr: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        wmi_exec_query_json(
            session_ptr,
            query.as_ptr(),
            1_000,
            &mut json_ptr,
            &mut json_len,
            &mut err_ptr,
        )
    };
    assert_eq!(rc, -1);
    assert!(json_ptr.is_null());
    unsafe {
        if !err_ptr.is_null() {
            wmi_free_err(err_ptr);
        }
        wmi_session_free(session_ptr);
    }
}

#[test]
fn ffi_exec_method_null_session() {
    let class = CString::new("Win32_Process").unwrap();
    let method = CString::new("GetOwner").unwrap();
    let mut json_ptr: *mut u8 = ptr::null_mut();
    let mut json_len: usize = 0;
    let mut err_ptr: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        wmi_exec_method_json(
            ptr::null_mut(),
            class.as_ptr(),
            method.as_ptr(),
            ptr::null(),
            1_000,
            &mut json_ptr,
            &mut json_len,
            &mut err_ptr,
        )
    };
    assert_eq!(rc, -1);
    assert!(json_ptr.is_null());
    unsafe {
        if !err_ptr.is_null() {
            wmi_free_err(err_ptr);
        }
    }
}

#[test]
fn ffi_session_new_requires_out_pointer() {
    let host = CString::new("localhost").unwrap();
    let mut err_ptr: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        wmi_session_new(
            host.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            0,
            ptr::null_mut(),
            &mut err_ptr,
        )
    };
    assert_eq!(rc, -1);
    unsafe {
        if !err_ptr.is_null() {
            wmi_free_err(err_ptr);
        }
    }
}

#[test]
fn ffi_exec_query_null_wql() {
    let (session_ptr, _strings) = new_session();
    let mut json_ptr: *mut u8 = ptr::null_mut();
    let mut json_len: usize = 0;
    let mut err_ptr: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        wmi_exec_query_json(
            session_ptr,
            ptr::null(),
            1_000,
            &mut json_ptr,
            &mut json_len,
            &mut err_ptr,
        )
    };
    assert_eq!(rc, -1);
    assert!(json_ptr.is_null());
    unsafe {
        if !err_ptr.is_null() {
            wmi_free_err(err_ptr);
        }
        wmi_session_free(session_ptr);
    }
}
