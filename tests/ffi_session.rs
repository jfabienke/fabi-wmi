//! Session creation through the C ABI: input validation and backend choice.

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

    let result = unsafe {
        linux_wmi::wmi_session_new(
            c"".as_ptr(), // Empty host
            c"user".as_ptr(),
            c"pass".as_ptr(),
            c"DOMAIN".as_ptr(),
            0,
            &mut std::ptr::null_mut(),
            &mut std::ptr::null_mut(),
        )
    };

    assert_ne!(result, 0); // Should fail
}

#[test]
fn session_requires_credentials_in_production_mode() {
    let _guard = env_mutex().lock().unwrap();
    std::env::remove_var("LINUX_WMI_USE_STUB"); // Ensure production mode

    let result = unsafe {
        linux_wmi::wmi_session_new(
            c"test-host".as_ptr(),
            std::ptr::null(), // No username
            std::ptr::null(), // No password
            std::ptr::null(), // No domain
            0,
            &mut std::ptr::null_mut(),
            &mut std::ptr::null_mut(),
        )
    };

    assert_ne!(result, 0); // Should fail without credentials
}

#[test]
#[cfg(feature = "test-support")]
fn session_with_stub_transport_succeeds() {
    let _guard = env_mutex().lock().unwrap();
    std::env::set_var("LINUX_WMI_USE_STUB", "1"); // Enable stub for testing

    let mut session_ptr = std::ptr::null_mut();
    let mut err_ptr = std::ptr::null_mut();

    let result = unsafe {
        linux_wmi::wmi_session_new(
            c"test-host".as_ptr(),
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

    if !err_ptr.is_null() {
        unsafe {
            linux_wmi::wmi_free_err(err_ptr);
        }
    }
}
