use linux_wmi::{
    wmi_exec_query_json, wmi_free_json, wmi_namespace_open, wmi_session_free, wmi_session_new,
    WmiSession,
};
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;
use tracing_subscriber::fmt::time::UtcTime;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

fn main() {
    init_tracing();
    let args: Vec<String> = std::env::args().collect();
    let config = match Config::from_args(&args) {
        Ok(cfg) => cfg,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    };

    let host_c = CString::new(config.host.clone()).expect("host must not contain NUL");
    let user_c = (!config.user.is_empty())
        .then(|| CString::new(config.user.clone()).expect("user contained NUL"));
    let pass_c = (!config.pass.is_empty())
        .then(|| CString::new(config.pass.clone()).expect("password contained NUL"));
    let domain_c = (!config.domain.is_empty())
        .then(|| CString::new(config.domain.clone()).expect("domain contained NUL"));

    let user_ptr = user_c.as_ref().map_or(ptr::null(), |s| s.as_ptr());
    let pass_ptr = pass_c.as_ref().map_or(ptr::null(), |s| s.as_ptr());
    let domain_ptr = domain_c.as_ref().map_or(ptr::null(), |s| s.as_ptr());

    let mut session_ptr: *mut WmiSession = ptr::null_mut();
    let mut err_ptr: *mut c_char = ptr::null_mut();

    let rc = unsafe {
        wmi_session_new(
            host_c.as_ptr(),
            user_ptr,
            pass_ptr,
            domain_ptr,
            config.auth_level,
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

    println!(
        "Connected to {} as {} (domain: {})",
        config.host,
        if config.user.is_empty() {
            "anonymous"
        } else {
            &config.user
        },
        if config.domain.is_empty() {
            "<local>"
        } else {
            &config.domain
        }
    );

    let query_c = CString::new(config.query.clone()).expect("query contained NUL");
    let mut json_ptr: *mut u8 = ptr::null_mut();
    let mut json_len: usize = 0;
    let rc = unsafe {
        wmi_exec_query_json(
            session_ptr,
            query_c.as_ptr(),
            config.timeout_ms,
            &mut json_ptr,
            &mut json_len,
            &mut err_ptr,
        )
    };

    if rc != 0 {
        let err = unsafe { take_err(err_ptr) };
        eprintln!("Query failed: {err}");
        unsafe { wmi_session_free(session_ptr) };
        std::process::exit(1);
    }

    let slice = unsafe { std::slice::from_raw_parts(json_ptr, json_len) };
    let json = String::from_utf8_lossy(slice);
    println!("Query result: {json}");
    if json.trim() == "[]" {
        eprintln!("Warning: query returned empty result set");
    }
    unsafe { wmi_free_json(json_ptr, json_len) };
    unsafe { wmi_session_free(session_ptr) };
}

struct Config {
    host: String,
    user: String,
    pass: String,
    domain: String,
    query: String,
    timeout_ms: u32,
    auth_level: u32,
}

impl Config {
    fn from_args(args: &[String]) -> Result<Self, String> {
        if args.len() < 2 {
            return Err(format!(
                "Usage: {} <host> [--user <user>] [--pass <pass>] [--domain <domain>] [--query <wql>] [--timeout <ms>]",
                args.get(0).map(String::as_str).unwrap_or("test_connect")
            ));
        }

        Ok(Self {
            host: args[1].clone(),
            user: parse_arg(args, "--user").unwrap_or_else(|| "wmi-test".to_string()),
            pass: parse_arg(args, "--pass").unwrap_or_else(|| "P@ssw0rd123".to_string()),
            domain: parse_arg(args, "--domain").unwrap_or_default(),
            query: parse_arg(args, "--query")
                .unwrap_or_else(|| "SELECT * FROM Win32_ComputerSystem".to_string()),
            timeout_ms: parse_arg(args, "--timeout")
                .and_then(|t| t.parse().ok())
                .unwrap_or(30_000),
            auth_level: 5, // PacketPrivacy by default
        })
    }
}

fn parse_arg(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
}

fn init_tracing() {
    let _ = tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(
            fmt::layer()
                .json()
                .with_current_span(true)
                .with_timer(UtcTime::rfc_3339())
                .with_ansi(false),
        )
        .try_init();
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
