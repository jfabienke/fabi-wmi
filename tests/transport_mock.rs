// Transport tests - most transport types are not exported publicly
// We test transport functionality through the session API

#[test]
fn session_creation_with_invalid_host_fails() {
    // Session creation should fail with invalid host
    std::env::set_var("LINUX_WMI_USE_STUB", "0"); // Ensure real transport

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
}

#[test]
fn session_requires_credentials_in_production_mode() {
    std::env::remove_var("LINUX_WMI_USE_STUB"); // Ensure production mode

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
}

#[test]
fn session_with_stub_transport_succeeds() {
    std::env::set_var("LINUX_WMI_USE_STUB", "1"); // Enable stub for testing

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

    if !err_ptr.is_null() {
        unsafe {
            linux_wmi::wmi_free_err(err_ptr);
        }
    }
}