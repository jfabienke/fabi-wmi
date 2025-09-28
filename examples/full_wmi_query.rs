use linux_wmi::auth_exports::Credentials;
use linux_wmi::wmi_session_free;
use linux_wmi::{
    activate_wmi_dcom, resolve_oxid, wmi_exec_method_json, wmi_exec_query_json, wmi_free_err,
    wmi_free_json, wmi_namespace_open, wmi_session_new, DcomError, WmiSession,
};
use serde_json::Value;
use std::env;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use tracing::{error, info};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            env::var("RUST_LOG").unwrap_or_else(|_| "info,linux_wmi=debug".to_string()),
        )
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <host> <username> <password> [domain]", args[0]);
        eprintln!(
            "Example: {} 192.168.1.100 Administrator Password123 WORKGROUP",
            args[0]
        );
        return Ok(());
    }

    let host = &args[1];
    let username = &args[2];
    let password = &args[3];
    let domain = args.get(4).map(|s| s.as_str()).unwrap_or("");

    info!("Starting Phase 4 WMI query demonstration");
    info!("Host: {}, User: {}@{}", host, username, domain);

    // Create credentials
    let creds = Credentials::new(
        username.to_string(),
        password.to_string(),
        domain.to_string(),
        "LINUX-WMI".to_string(),
    );

    // Phase 1-2: DCOM activation to get dynamic port and OXID
    info!("Phase 1-2: Performing DCOM activation...");
    match activate_wmi_dcom(host, &creds) {
        Ok((port, oxid)) => {
            info!("✓ DCOM activation successful");
            info!("  Dynamic port: {}", port);
            info!("  OXID: {:?}", hex::encode(oxid));

            // Phase 3-4: OXID resolution to get IPID
            info!("\nPhase 3-4: Resolving OXID to get IPID...");
            match resolve_oxid(host, port, &creds, &oxid) {
                Ok(obj_ref) => {
                    info!("✓ OXID resolution successful");
                    info!("  IPID: {:?}", hex::encode(obj_ref.ipid));
                    info!("  OID: {:?}", hex::encode(obj_ref.oid));
                    info!("  Public refs: {}", obj_ref.public_refs);
                    info!("  Std flags: 0x{:08x}", obj_ref.std_flags);

                    // At this point we have everything needed for WMI queries
                    info!("\n✅ Phase 4 complete! Ready for WMI queries with:");
                    info!("  - Authenticated transport (NTLM session key)");
                    info!("  - IPID for object calls");
                    info!("  - Signing/sealing support (PRIVACY level)");
                    info!("  - Multi-fragment support");

                    // TODO: In next phase, actually execute a WMI query
                    info!("\nExecuting Win32_Process query and GetOwner method...");
                    if let Err(err) = run_query_and_method(host, username, password, domain) {
                        error!("Failed to run WMI operations: {err}");
                    }
                }
                Err(e) => {
                    error!("❌ OXID resolution failed: {}", e);
                    match e {
                        DcomError::AccessDenied => {
                            error!("  Access denied - check credentials and permissions");
                        }
                        DcomError::ServerUnavailable => {
                            error!("  Server unavailable - check if RPC service is running");
                        }
                        _ => {
                            error!("  {}", e);
                        }
                    }
                }
            }
        }
        Err(e) => {
            error!("❌ DCOM activation failed: {}", e);
            error!("  Make sure:");
            error!("  - Windows host {} is reachable", host);
            error!("  - Port 135 (RPC endpoint mapper) is open");
            error!("  - Credentials are valid");
            error!("  - WMI service is running on the target");
        }
    }

    Ok(())
}

fn run_query_and_method(
    host: &str,
    username: &str,
    password: &str,
    domain: &str,
) -> Result<(), String> {
    unsafe {
        let host_c = CString::new(host).map_err(|e| e.to_string())?;
        let user_c = CString::new(username).map_err(|e| e.to_string())?;
        let pass_c = CString::new(password).map_err(|e| e.to_string())?;
        let domain_ptr = if domain.is_empty() {
            ptr::null()
        } else {
            CString::new(domain).map_err(|e| e.to_string())?.into_raw() as *const c_char
        };

        let mut session_ptr: *mut WmiSession = ptr::null_mut();
        let mut err_ptr: *mut c_char = ptr::null_mut();

        let rc = wmi_session_new(
            host_c.as_ptr(),
            user_c.as_ptr(),
            pass_c.as_ptr(),
            domain_ptr,
            0,
            &mut session_ptr,
            &mut err_ptr,
        );

        if !domain_ptr.is_null() {
            // Reconstruct CString so it gets freed
            drop(CString::from_raw(domain_ptr as *mut c_char));
        }

        if rc != 0 {
            let msg = if err_ptr.is_null() {
                "session creation failed".to_string()
            } else {
                let message = CStr::from_ptr(err_ptr).to_string_lossy().into_owned();
                wmi_free_err(err_ptr);
                message
            };
            return Err(msg);
        }

        let namespace = CString::new("root\\CimV2").map_err(|e| e.to_string())?;
        let mut err_ptr: *mut c_char = ptr::null_mut();
        let rc = wmi_namespace_open(session_ptr, namespace.as_ptr(), &mut err_ptr);
        if rc != 0 {
            let msg = if err_ptr.is_null() {
                "namespace open failed".to_string()
            } else {
                let message = CStr::from_ptr(err_ptr).to_string_lossy().into_owned();
                wmi_free_err(err_ptr);
                message
            };
            wmi_session_free(session_ptr);
            return Err(msg);
        }

        let query = CString::new("SELECT * FROM Win32_Process").map_err(|e| e.to_string())?;
        let mut json_ptr: *mut u8 = ptr::null_mut();
        let mut json_len: usize = 0;
        let mut err_ptr: *mut c_char = ptr::null_mut();
        let rc = wmi_exec_query_json(
            session_ptr,
            query.as_ptr(),
            30_000,
            &mut json_ptr,
            &mut json_len,
            &mut err_ptr,
        );

        if rc != 0 {
            let msg = if err_ptr.is_null() {
                "ExecQuery failed".to_string()
            } else {
                let message = CStr::from_ptr(err_ptr).to_string_lossy().into_owned();
                wmi_free_err(err_ptr);
                message
            };
            wmi_session_free(session_ptr);
            return Err(msg);
        }

        let processes: Vec<Value> = {
            let slice = std::slice::from_raw_parts(json_ptr, json_len);
            let json_str = std::str::from_utf8(slice).map_err(|e| e.to_string())?;
            serde_json::from_str(json_str).map_err(|e| e.to_string())?
        };
        wmi_free_json(json_ptr, json_len);
        info!("Retrieved {} processes", processes.len());
        if let Some(first) = processes.first() {
            info!("First process entry: {first:#}");
        }

        let class = CString::new("Win32_Process").map_err(|e| e.to_string())?;
        let method = CString::new("GetOwner").map_err(|e| e.to_string())?;
        let mut json_ptr: *mut u8 = ptr::null_mut();
        let mut json_len: usize = 0;
        let mut err_ptr: *mut c_char = ptr::null_mut();

        let rc = wmi_exec_method_json(
            session_ptr,
            class.as_ptr(),
            method.as_ptr(),
            ptr::null(),
            30_000,
            &mut json_ptr,
            &mut json_len,
            &mut err_ptr,
        );

        if rc != 0 {
            let msg = if err_ptr.is_null() {
                "ExecMethod failed".to_string()
            } else {
                let message = CStr::from_ptr(err_ptr).to_string_lossy().into_owned();
                wmi_free_err(err_ptr);
                message
            };
            wmi_session_free(session_ptr);
            return Err(msg);
        }

        let method_result: Value = {
            let slice = std::slice::from_raw_parts(json_ptr, json_len);
            let json_str = std::str::from_utf8(slice).map_err(|e| e.to_string())?;
            serde_json::from_str(json_str).map_err(|e| e.to_string())?
        };
        wmi_free_json(json_ptr, json_len);
        info!("Win32_Process.GetOwner -> {method_result:#}");

        wmi_session_free(session_ptr);
    }

    Ok(())
}
