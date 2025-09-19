use linux_wmi::{activate_wmi_dcom, resolve_oxid, DcomError, auth_exports::Credentials};

#[test]
fn activate_wmi_dcom_with_invalid_host_fails() {
    let creds = Credentials {
        username: "test".to_string(),
        password: "pass".to_string(),
        domain: "DOMAIN".to_string(),
        workstation: "WORKSTATION".to_string(),
    };

    // Empty hostname should fail
    let result = activate_wmi_dcom("", &creds);
    assert!(result.is_err());

    // Invalid hostname 0.0.0.0
    let result = activate_wmi_dcom("0.0.0.0", &creds);
    assert!(result.is_err());
}

#[test]
fn activate_wmi_dcom_with_empty_username_fails() {
    let creds = Credentials {
        username: "".to_string(),
        password: "pass".to_string(),
        domain: "DOMAIN".to_string(),
        workstation: "WORKSTATION".to_string(),
    };

    let result = activate_wmi_dcom("test-host", &creds);
    assert!(result.is_err());
}

#[test]
fn activate_wmi_dcom_with_empty_password_fails() {
    let creds = Credentials {
        username: "user".to_string(),
        password: "".to_string(),
        domain: "DOMAIN".to_string(),
        workstation: "WORKSTATION".to_string(),
    };

    let result = activate_wmi_dcom("test-host", &creds);
    assert!(result.is_err());
}

#[test]
fn resolve_oxid_with_invalid_port_fails() {
    let creds = Credentials {
        username: "user".to_string(),
        password: "pass".to_string(),
        domain: "DOMAIN".to_string(),
        workstation: "WORKSTATION".to_string(),
    };

    // Port 0 is invalid
    let result = resolve_oxid("test-host", 0, &creds, &[0; 8]);
    assert!(result.is_err());
}

#[test]
fn resolve_oxid_with_unreachable_host_fails() {
    let creds = Credentials {
        username: "user".to_string(),
        password: "pass".to_string(),
        domain: "DOMAIN".to_string(),
        workstation: "WORKSTATION".to_string(),
    };

    // Use an invalid IP that will fail to connect
    let result = resolve_oxid("0.0.0.0", 135, &creds, &[0x01; 8]);
    assert!(result.is_err());
}

#[test]
fn credentials_with_unicode_characters() {
    let creds = Credentials {
        username: "用户名".to_string(),
        password: "密码123".to_string(),
        domain: "域".to_string(),
        workstation: "工作站".to_string(),
    };

    // Should handle UTF-8 credentials properly
    let result = activate_wmi_dcom("test-host", &creds);
    // Will fail to connect but should handle Unicode properly
    assert!(result.is_err());
}

#[test]
fn credentials_with_special_characters() {
    let creds = Credentials {
        username: "user@domain".to_string(),
        password: "p@$$w0rd!".to_string(),
        domain: "CORP\\DOMAIN".to_string(),
        workstation: "WORKSTATION".to_string(),
    };

    // Should handle special characters in credentials
    let result = activate_wmi_dcom("test-host", &creds);
    assert!(result.is_err());
}

#[test]
fn very_long_hostname_handled_properly() {
    let long_host = "a".repeat(256); // 256 character hostname
    let creds = Credentials {
        username: "user".to_string(),
        password: "pass".to_string(),
        domain: "DOMAIN".to_string(),
        workstation: "WORKSTATION".to_string(),
    };

    let result = activate_wmi_dcom(&long_host, &creds);
    // Should handle long hostnames without panicking
    assert!(result.is_err());
}

#[test]
fn ipv6_address_as_hostname() {
    let creds = Credentials {
        username: "user".to_string(),
        password: "pass".to_string(),
        domain: "DOMAIN".to_string(),
        workstation: "WORKSTATION".to_string(),
    };

    // Test with IPv6 address
    let result = activate_wmi_dcom("::1", &creds);
    // Should handle IPv6 addresses
    assert!(result.is_err());
}

#[test]
fn dotted_hostname_resolution() {
    let creds = Credentials {
        username: "user".to_string(),
        password: "pass".to_string(),
        domain: "DOMAIN".to_string(),
        workstation: "WORKSTATION".to_string(),
    };

    // Test with FQDN
    let result = activate_wmi_dcom("host.domain.local", &creds);
    assert!(result.is_err());
}

#[test]
fn oxid_with_all_zeros() {
    let creds = Credentials {
        username: "user".to_string(),
        password: "pass".to_string(),
        domain: "DOMAIN".to_string(),
        workstation: "WORKSTATION".to_string(),
    };

    // OXID of all zeros might have special meaning
    let result = resolve_oxid("test-host", 135, &creds, &[0x00; 8]);
    assert!(result.is_err());
}

#[test]
fn oxid_with_all_ones() {
    let creds = Credentials {
        username: "user".to_string(),
        password: "pass".to_string(),
        domain: "DOMAIN".to_string(),
        workstation: "WORKSTATION".to_string(),
    };

    // OXID of all ones might be invalid
    let result = resolve_oxid("test-host", 135, &creds, &[0xFF; 8]);
    assert!(result.is_err());
}