use linux_wmi::{
    wmi_exec_query_json, wmi_free_json, wmi_namespace_open, wmi_session_free, wmi_session_new,
    WmiSession,
};
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run --example test_connect <host>");
        std::process::exit(1);
    }
    let host_c = CString::new(args[1].clone()).expect("host must not contain NUL");

    let mut session_ptr: *mut WmiSession = ptr::null_mut();
    let mut err_ptr: *mut c_char = ptr::null_mut();

    let rc = unsafe {
        wmi_session_new(
            host_c.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            0,
            &mut session_ptr,
            &mut err_ptr,
        )
    };
    if rc != 0 {
        let err = unsafe { take_err(err_ptr) };
        eprintln!("Failed to create session: {err}");
        std::process::exit(1);
    }

    let namespace = CString::new("root\\CimV2").unwrap();
    let rc = unsafe { wmi_namespace_open(session_ptr, namespace.as_ptr(), &mut err_ptr) };
    if rc != 0 {
        let err = unsafe { take_err(err_ptr) };
        eprintln!("Failed to open namespace: {err}");
        unsafe { wmi_session_free(session_ptr) };
        std::process::exit(1);
    }

    println!("Connected to {}", args[1]);

    let query = CString::new("SELECT * FROM Win32_Process").unwrap();
    let mut json_ptr: *mut u8 = ptr::null_mut();
    let mut json_len: usize = 0;
    let rc = unsafe {
        wmi_exec_query_json(
            session_ptr,
            query.as_ptr(),
            5_000,
            &mut json_ptr,
            &mut json_len,
            &mut err_ptr,
        )
    };

    if rc != 0 {
        let err = unsafe { take_err(err_ptr) };
        eprintln!("Query failed: {err}");
    } else {
        let slice = unsafe { std::slice::from_raw_parts(json_ptr, json_len) };
        let json = String::from_utf8_lossy(slice);
        println!("Sample response: {json}");
        unsafe { wmi_free_json(json_ptr, json_len) };
    }

    unsafe { wmi_session_free(session_ptr) };
}

unsafe fn take_err(err_ptr: *mut c_char) -> String {
    if err_ptr.is_null() {
        return "unknown error".to_string();
    }
    let cstring = CString::from_raw(err_ptr);
    cstring
        .into_string()
        .unwrap_or_else(|_| "error".to_string())
}
