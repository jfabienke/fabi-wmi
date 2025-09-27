// Transport tests - most transport types are not exported publicly
// We test transport functionality through the session API

use std::sync::{Mutex, OnceLock};

fn env_mutex() -> &'static Mutex<()> {
    static ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
    ENV_MUTEX.get_or_init(|| Mutex::new(()))
}

#[test]
fn session_creation_with_invalid_host_fails() {
    let _guard = env_mutex().lock().unwrap();
    // Session creation should fail with invalid host
    std::env::remove_var("LINUX_WMI_USE_STUB"); // Ensure real transport
    std::env::set_var("LINUX_WMI_SKIP_EPM", "1"); // Skip EPM to avoid network calls

    let result = unsafe {
        linux_wmi::wmi_session_new(
            "\0".as_ptr() as *const i8, // Empty host
            "user\0".as_ptr() as *const i8,
            "pass\0".as_ptr() as *const i8,
            "DOMAIN\0".as_ptr() as *const i8,
            0,
            &mut std::ptr::null_mut(),
            &mut std::ptr::null_mut(),
        )
    };

    assert_ne!(result, 0); // Should fail

    // Clean up
    std::env::remove_var("LINUX_WMI_SKIP_EPM");
}

#[test]
fn session_requires_credentials_in_production_mode() {
    let _guard = env_mutex().lock().unwrap();
    std::env::remove_var("LINUX_WMI_USE_STUB"); // Ensure production mode
    std::env::set_var("LINUX_WMI_SKIP_EPM", "1"); // Skip EPM to avoid network calls

    let result = unsafe {
        linux_wmi::wmi_session_new(
            "test-host\0".as_ptr() as *const i8,
            std::ptr::null(), // No username
            std::ptr::null(), // No password
            std::ptr::null(), // No domain
            0,
            &mut std::ptr::null_mut(),
            &mut std::ptr::null_mut(),
        )
    };

    assert_ne!(result, 0); // Should fail without credentials

    // Clean up
    std::env::remove_var("LINUX_WMI_SKIP_EPM");
}

#[test]
#[cfg(feature = "test-support")]
fn session_with_stub_transport_succeeds() {
    let _guard = env_mutex().lock().unwrap();
    std::env::set_var("LINUX_WMI_USE_STUB", "1"); // Enable stub for testing
    std::env::set_var("LINUX_WMI_SKIP_EPM", "1"); // Skip EPM to avoid network calls

    let mut session_ptr = std::ptr::null_mut();
    let mut err_ptr = std::ptr::null_mut();

    let result = unsafe {
        linux_wmi::wmi_session_new(
            "test-host\0".as_ptr() as *const i8,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            &mut session_ptr,
            &mut err_ptr,
        )
    };

    assert_eq!(result, 0); // Should succeed with stub

    if !session_ptr.is_null() {
        unsafe {
            linux_wmi::wmi_session_free(session_ptr);
        }
    }

    // Clean up
    std::env::remove_var("LINUX_WMI_USE_STUB");
    std::env::remove_var("LINUX_WMI_SKIP_EPM");

    if !err_ptr.is_null() {
        unsafe {
            linux_wmi::wmi_free_err(err_ptr);
        }
    }
}
