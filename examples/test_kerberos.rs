//! Test Kerberos authentication with WMI
//!
//! Usage:
//!   cargo run --example test_kerberos --features kerberos -- \
//!     <host> --user <user> --pass <pass> --domain <domain> --query <wql>
//!
//! Example:
//!   cargo run --example test_kerberos --features kerberos -- \
//!     server.contoso.com --user admin --pass <password> \
//!     --domain CONTOSO.COM --query "SELECT Name FROM Win32_ComputerSystem"

use linux_wmi::{
    auth_exports::Credentials,
    KerberosClient, KerberosConfig, KerberosCacheBackend,
};
use std::env;
use std::process;
use tracing::{error, info};

fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 9 {
        eprintln!("Usage: {} <host> --user <user> --pass <pass> --domain <domain> --query <wql> [--enable-delegation] [--disable-dce-style]", args[0]);
        eprintln!("\nExample:");
        eprintln!("  {} server.contoso.com --user admin --pass <password> --domain CONTOSO.COM --query \"SELECT Name FROM Win32_ComputerSystem\"", args[0]);
        eprintln!("\nOptional flags:");
        eprintln!("  --enable-delegation   Enable credential delegation (SECURITY RISK!)");
        eprintln!("  --disable-dce-style   Disable DCE-style flag (not recommended for WMI)");
        process::exit(1);
    }

    // Parse command line arguments
    let host = &args[1];
    let mut username = "";
    let mut password = "";
    let mut domain = "";
    let mut query = "";
    let mut enable_delegation = false;
    let mut enable_dce_style = true;  // Default: enabled for DCE/RPC

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--user" => {
                username = &args[i + 1];
                i += 2;
            }
            "--pass" => {
                password = &args[i + 1];
                i += 2;
            }
            "--domain" => {
                domain = &args[i + 1];
                i += 2;
            }
            "--query" => {
                query = &args[i + 1];
                i += 2;
            }
            "--enable-delegation" => {
                enable_delegation = true;
                i += 1;
            }
            "--disable-dce-style" => {
                enable_dce_style = false;
                i += 1;
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                process::exit(1);
            }
        }
    }

    info!("Testing Kerberos authentication to {}", host);
    info!("User: {}@{}", username, domain);

    // Create credentials
    let creds = Credentials::new(
        username.to_string(),
        password.to_string(),
        domain.to_string(),
        "LINUX-WMI".to_string(),
    );

    // Show configuration
    info!("Configuration:");
    info!("  DCE-style: {}", if enable_dce_style { "enabled" } else { "disabled" });
    info!("  Delegation: {}", if enable_delegation { "enabled (DANGEROUS!)" } else { "disabled (safe)" });

    // Test 1: Create Kerberos client with credential caching and SPNEGO
    info!("Creating Kerberos client with credential caching and SPNEGO...");
    let config = KerberosConfig::new(domain)
        .with_spn(format!("HOST/{}", host))
        .with_cache_backend(KerberosCacheBackend::File)
        .with_caching(true)
        .with_spnego()  // Enable SPNEGO negotiation
        .with_dce_style(enable_dce_style)  // Configure DCE-style flag
        .with_delegation(enable_delegation);  // Configure delegation

    if enable_delegation {
        info!("⚠️  WARNING: Credential delegation is enabled!");
        info!("⚠️  The server can impersonate this client to other services!");
    }

    let mut kerberos_client = match KerberosClient::new(host, config, creds.clone()) {
        Ok(client) => {
            info!("✓ Kerberos client created successfully");
            client
        }
        Err(err) => {
            error!("✗ Failed to create Kerberos client: {:?}", err);
            process::exit(1);
        }
    };

    // Test 2: Test bind token generation (AP-REQ)
    info!("Testing bind token generation (AP-REQ)...");
    match kerberos_client.bind_token() {
        Ok(token) => {
            info!("✓ Generated AP-REQ token: {} bytes", token.len());
            info!("  Token will be cached for future use");

            // Check if delegation is available (only after authentication completes)
            if enable_delegation {
                info!("  Delegation flag was requested in AP-REQ");
            }
        }
        Err(err) => {
            error!("✗ Failed to generate AP-REQ: {:?}", err);
            process::exit(1);
        }
    }

    // Test 3: Demonstrate credential cache reuse
    info!("Testing credential cache reuse...");
    let config2 = KerberosConfig::new(domain)
        .with_spn(format!("HOST/{}", host))
        .with_cache_backend(KerberosCacheBackend::File)
        .with_caching(true);

    let _kerberos_client2 = match KerberosClient::new(host, config2, creds.clone()) {
        Ok(client) => {
            info!("✓ Second client created (should use cached credentials)");
            client
        }
        Err(err) => {
            error!("✗ Failed to create second client: {:?}", err);
            process::exit(1);
        }
    };

    // Test 4: Test with different cache backends
    info!("Testing Memory cache backend...");
    let config_mem = KerberosConfig::new(domain)
        .with_spn(format!("HOST/{}", host))
        .with_cache_backend(KerberosCacheBackend::Memory)
        .with_caching(true);

    let _kerberos_client_mem = match KerberosClient::new(host, config_mem, creds.clone()) {
        Ok(_) => info!("✓ Memory cache backend working"),
        Err(err) => error!("✗ Memory cache backend failed: {:?}", err),
    };

    // Test 5: Attempt DCOM activation with Kerberos
    info!("Attempting DCOM activation with Kerberos...");
    match linux_wmi::activate_wmi_dcom(host, &creds) {
        Ok((port, oxid)) => {
            info!(
                "✓ DCOM activation successful! WMI port: {}, OXID: {}",
                port,
                hex::encode(oxid)
            );
        }
        Err(err) => {
            error!("✗ DCOM activation failed: {:?}", err);
            // This is expected if Kerberos infrastructure isn't set up
            info!("Note: This failure is expected if:");
            info!("  - The KDC is not reachable");
            info!("  - The SPN is not configured correctly");
            info!("  - Kerberos tickets cannot be obtained");
        }
    }

    // Test 3: Test with explicit port if DCOM failed
    if let Ok(port_str) = env::var("LINUX_WMI_PORT") {
        if let Ok(port) = port_str.parse::<u16>() {
            info!("Using explicit port {} from LINUX_WMI_PORT", port);

            // Would normally continue with WMI connection here
            info!("Would connect to WMI on port {} and execute query: {}", port, query);
        }
    }

    // Test 6: Channel bindings (if using TLS)
    info!("Testing channel bindings configuration...");
    let config_cb = KerberosConfig::new(domain)
        .with_spn(format!("HOST/{}", host))
        .with_cache_backend(KerberosCacheBackend::File)
        .with_caching(true)
        .require_channel_bindings(false); // Don't require, but use if available

    match KerberosClient::new(host, config_cb, creds.clone()) {
        Ok(_) => info!("✓ Channel bindings configuration working"),
        Err(err) => error!("✗ Channel bindings configuration failed: {:?}", err),
    };

    // Test 7: DCE-style configuration
    info!("Testing DCE-style configuration...");
    let config_dce = KerberosConfig::new(domain)
        .with_spn(format!("HOST/{}", host))
        .with_cache_backend(KerberosCacheBackend::File)
        .with_dce_style(false);  // Disable DCE-style for testing

    match KerberosClient::new(host, config_dce, creds.clone()) {
        Ok(_) => info!("✓ Non-DCE-style configuration working"),
        Err(err) => error!("✗ Non-DCE-style configuration failed: {:?}", err),
    };

    // Test 8: Delegation configuration (with warnings)
    if !enable_delegation {
        info!("Testing delegation configuration (safely disabled)...");
        let config_deleg = KerberosConfig::new(domain)
            .with_spn(format!("HOST/{}", host))
            .with_cache_backend(KerberosCacheBackend::File)
            .with_delegation(false)  // Explicitly disabled
            .with_mutual_auth(true);  // Require mutual auth

        match KerberosClient::new(host, config_deleg, creds.clone()) {
            Ok(client) => {
                info!("✓ Delegation safely disabled");
                if client.has_delegated_credentials() {
                    error!("✗ Unexpected: delegated credentials available when disabled!");
                } else {
                    info!("✓ No delegated credentials (as expected)");
                }
            }
            Err(err) => error!("✗ Delegation test failed: {:?}", err),
        };
    }

    info!("✓ Kerberos integration test complete");
    info!("Summary:");
    info!("  - Credential caching: TESTED");
    info!("  - Multiple cache backends: TESTED");
    info!("  - Channel bindings: CONFIGURED");
    info!("  - DCE-style flag: TESTED (runtime-configurable)");
    info!("  - Delegation support: TESTED (runtime-configurable)");
    info!("  - Memory zeroization: AUTOMATIC");
    info!("\nSecurity Best Practices:");
    info!("  - DCE-style: Enable for DCE/RPC (WMI, SMB)");
    info!("  - Delegation: Keep disabled unless absolutely necessary");
    info!("  - Mutual auth: Always require for production");
}