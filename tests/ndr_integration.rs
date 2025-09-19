use linux_wmi::IWbemLocator;

/// Test that RealNdrCodec can be used with IWbemServices
#[test]
fn test_real_ndr_codec_integration() {
    // Set environment variable to use real NDR codec
    std::env::set_var("LINUX_WMI_USE_REAL_NDR", "1");
    std::env::set_var("LINUX_WMI_SKIP_EPM", "1"); // Use stub transport

    // Create locator and services using the real codec
    let locator = IWbemLocator::new("test-host");
    let services = locator
        .connect_server("root\\CimV2", None, None, None)
        .expect("connect to namespace");

    // Execute a query - should use RealNdrCodec with stub response
    let results = services
        .exec_query("SELECT * FROM Win32_ComputerSystem")
        .expect("exec query");

    // Verify we get expected stub response from RealNdrCodec
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["Name"], "STUB-PC");
}

/// Test that stub codec still works when env var not set
#[test]
fn test_stub_codec_fallback() {
    // Clear the environment variable
    std::env::remove_var("LINUX_WMI_USE_REAL_NDR");
    std::env::set_var("LINUX_WMI_SKIP_EPM", "1"); // Use stub transport

    let locator = IWbemLocator::new("test-host");
    let services = locator
        .connect_server("root\\CimV2", None, None, None)
        .expect("connect to namespace");

    // Should use StubNdrCodec
    let results = services
        .exec_query("SELECT * FROM Win32_Processor")
        .expect("exec query");

    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["Name"], "stub CPU");
}
