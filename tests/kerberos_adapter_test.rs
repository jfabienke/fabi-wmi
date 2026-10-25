//! Public API of the Kerberos (kerbsec) client: configuration and the checks
//! that run before any KDC traffic.

#![cfg(feature = "kerberos")]

use fabi_dcerpc::{AuthError, AuthProvider, AUTH_TYPE_KERBEROS};
use fabi_wmi::{Credentials, KerberosClient, KerberosConfig, KerberosError};

#[test]
fn config_builder_records_realm_and_spn() {
    let config = KerberosConfig::new("EXAMPLE.COM")
        .with_spn("host/server.example.com")
        .with_keytab_path("/etc/krb5.keytab");

    assert_eq!(config.realm, "EXAMPLE.COM");
    assert_eq!(
        config.spn_override,
        Some("host/server.example.com".to_string())
    );
}

#[test]
fn ip_address_target_requires_an_explicit_spn() {
    let creds = Credentials::new("testuser", "TestPass123!").with_domain("EXAMPLE.COM");

    // An IP address cannot be turned into a service principal name.
    let result = KerberosClient::new("192.0.2.1", KerberosConfig::new("EXAMPLE.COM"), creds);
    assert!(matches!(result, Err(KerberosError::SpnResolution(_))));
}

#[test]
fn kerberos_client_implements_dcerpc_auth_provider() {
    let creds = Credentials::new("testuser", "TestPass123!").with_domain("EXAMPLE.COM");
    let config = KerberosConfig::new("EXAMPLE.COM").with_caching(false);
    let mut client = KerberosClient::new("server.example.com", config, creds).unwrap();

    assert_eq!(client.auth_type(), AUTH_TYPE_KERBEROS);
    // Before establishment: the MS-KILE AES sizes (sealed tokens carry one block
    // of EC). Sealing needs DCE IOV (Linux); elsewhere a sealed size is an error.
    if KerberosClient::supports_privacy() {
        assert_eq!(client.auth_value_len(true, 32).unwrap(), 76);
        assert!(client.auth_value_len(true, 12).is_err());
    } else {
        assert!(client.auth_value_len(true, 32).is_err());
    }
    assert_eq!(client.auth_value_len(false, 12).unwrap(), 28);

    // Protection calls must reject unestablished context
    let mut stub = [0u8; 16];
    assert!(client.seal_rpc(&[0u8; 24], &mut stub, &[0u8; 8]).is_err());
    assert!(client.sign_rpc(&[0u8; 24], &stub, &[0u8; 8]).is_err());
}

#[test]
fn handshake_errors_keep_their_cause() {
    let creds = Credentials::new("", "");
    let config = KerberosConfig::new("EXAMPLE.COM").with_caching(false);
    let mut client = KerberosClient::new("server.example.com", config, creds).unwrap();

    // An AP-REP before the AP-REQ fails inside kerbsec, without touching GSS-API.
    // The cause must reach the caller, not a generic "username and password are
    // required".
    let err = client.respond(b"not an AP-REP").expect_err("out of order");
    assert!(
        matches!(&err, AuthError::Protection(why) if why.contains("before initial_token")),
        "{err:?}"
    );
}
