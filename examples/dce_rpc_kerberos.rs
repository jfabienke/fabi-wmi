//! Example demonstrating proper DCE/RPC Kerberos configuration
//!
//! This example shows best practices for configuring Kerberos authentication
//! for DCE/RPC protocols like WMI and SMB, using the runtime-configurable
//! GSS flags available in kerbsec v0.2.0+.
//!
//! Usage:
//!   cargo run --example dce_rpc_kerberos --features kerberos -- \
//!     <host> --user <user> --pass <pass> --domain <domain>
//!
//! Optional flags:
//!   --trusted-server      Enable delegation for this trusted server
//!   --disable-mutual      Disable mutual authentication (NOT recommended)
//!
//! Example:
//!   cargo run --example dce_rpc_kerberos --features kerberos -- \
//!     dc01.contoso.com --user admin --pass <password> --domain CONTOSO.COM

use linux_wmi::{auth_exports::Credentials, KerberosCacheBackend, KerberosClient, KerberosConfig};
use std::env;
use std::process;
use tracing::{error, info, warn};

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
        eprintln!("DCE/RPC Kerberos Configuration Example");
        eprintln!("=======================================");
        eprintln!();
        eprintln!(
            "Usage: {} <host> --user <user> --pass <pass> --domain <domain> [options]",
            args[0]
        );
        eprintln!();
        eprintln!("Required arguments:");
        eprintln!("  <host>               Target server hostname or IP");
        eprintln!("  --user <user>        Username for authentication");
        eprintln!("  --pass <pass>        Password for authentication");
        eprintln!("  --domain <domain>    Kerberos realm/domain");
        eprintln!();
        eprintln!("Optional flags:");
        eprintln!(
            "  --trusted-server     Enable delegation (DANGEROUS - only for trusted servers!)"
        );
        eprintln!("  --disable-mutual     Disable mutual authentication (NOT recommended)");
        eprintln!();
        eprintln!("Example:");
        eprintln!(
            "  {} dc01.contoso.com --user admin --pass <password> --domain CONTOSO.COM",
            args[0]
        );
        process::exit(1);
    }

    // Parse command line arguments
    let host = &args[1];
    let mut username = "";
    let mut password = "";
    let mut domain = "";
    let mut enable_delegation = false;
    let mut require_mutual = true;

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
            "--trusted-server" => {
                enable_delegation = true;
                i += 1;
            }
            "--disable-mutual" => {
                require_mutual = false;
                i += 1;
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                process::exit(1);
            }
        }
    }

    info!("=== DCE/RPC Kerberos Configuration Demo ===");
    info!("Target: {}", host);
    info!("User: {}@{}", username, domain);
    info!("");

    // Create credentials
    let creds = Credentials::new(
        username.to_string(),
        password.to_string(),
        domain.to_string(),
        "LINUX-WMI".to_string(),
    );

    // ===== SCENARIO 1: Standard DCE/RPC Configuration (Recommended) =====
    info!("Scenario 1: Standard DCE/RPC Configuration");
    info!("==========================================");

    let standard_config = KerberosConfig::new(domain)
        .with_spn(format!("HOST/{}", host))
        .with_cache_backend(KerberosCacheBackend::File)
        .with_caching(true)
        .with_dce_style(true) // ENABLED: Required for DCE/RPC
        .with_delegation(false) // DISABLED: Security best practice
        .with_mutual_auth(true); // ENABLED: Security best practice

    info!("Configuration:");
    info!("  ✓ DCE-style: ENABLED (required for DCE/RPC sequence handling)");
    info!("  ✓ Delegation: DISABLED (security best practice)");
    info!("  ✓ Mutual auth: ENABLED (verify server identity)");
    info!("  ✓ Auth level: Packet Privacy (encrypted)");

    match KerberosClient::new(host, standard_config, creds.clone()) {
        Ok(mut client) => {
            info!("✓ Standard DCE/RPC client created successfully");

            // Generate AP-REQ
            match client.bind_token() {
                Ok(token) => {
                    info!("✓ AP-REQ token generated: {} bytes", token.len());
                    info!("  - DCE-style flag included in GSS context");
                    info!("  - Sequence checking disabled (DCE handles it)");
                    info!("  - Out-of-order message processing allowed");
                }
                Err(err) => {
                    error!("✗ Failed to generate AP-REQ: {:?}", err);
                }
            }

            // Verify no delegation
            if client.has_delegated_credentials() {
                error!("✗ Unexpected: delegated credentials present!");
            } else {
                info!("✓ No delegated credentials (as expected)");
            }
        }
        Err(err) => {
            error!("✗ Failed to create standard client: {:?}", err);
        }
    }
    info!("");

    // ===== SCENARIO 2: Trusted Server with Delegation (Use with caution!) =====
    if enable_delegation {
        warn!("Scenario 2: Trusted Server with Delegation");
        warn!("===========================================");
        warn!("⚠️  WARNING: Delegation allows server impersonation!");
        warn!("⚠️  Only use with completely trusted servers!");

        let delegation_config = KerberosConfig::new(domain)
            .with_spn(format!("HOST/{}", host))
            .with_cache_backend(KerberosCacheBackend::File)
            .with_caching(true)
            .with_dce_style(true) // ENABLED: Required for DCE/RPC
            .with_delegation(true) // ENABLED: For S4U2Self/S4U2Proxy
            .with_mutual_auth(true); // ENABLED: Always verify server

        warn!("Configuration:");
        warn!("  ✓ DCE-style: ENABLED (required for DCE/RPC)");
        warn!("  ⚠️  Delegation: ENABLED (security risk!)");
        warn!("  ✓ Mutual auth: ENABLED (critical with delegation)");

        match KerberosClient::new(host, delegation_config, creds.clone()) {
            Ok(mut client) => {
                warn!("✓ Delegation-enabled client created");

                // Generate AP-REQ with delegation flag
                match client.bind_token() {
                    Ok(token) => {
                        warn!("✓ AP-REQ with GSS_C_DELEG_FLAG: {} bytes", token.len());
                        warn!("  - Server can now impersonate this client");
                        warn!("  - Use for S4U2Self/S4U2Proxy scenarios");
                    }
                    Err(err) => {
                        error!("✗ Failed to generate AP-REQ: {:?}", err);
                    }
                }

                // After authentication completes, delegated credentials may be available
                info!("  Delegated credentials will be available after authentication");
            }
            Err(err) => {
                error!("✗ Failed to create delegation client: {:?}", err);
            }
        }
        info!("");
    }

    // ===== SCENARIO 3: High-Performance Configuration (Less secure) =====
    info!("Scenario 3: High-Performance Configuration");
    info!("===========================================");

    let perf_config = KerberosConfig::new(domain)
        .with_spn(format!("HOST/{}", host))
        .with_cache_backend(KerberosCacheBackend::Memory) // In-memory for speed
        .with_caching(true)
        .with_dce_style(true) // ENABLED: Required for DCE/RPC
        .with_delegation(false) // DISABLED: Security
        .with_mutual_auth(require_mutual); // Configurable

    info!("Configuration:");
    info!("  ✓ DCE-style: ENABLED (required for DCE/RPC)");
    info!("  ✓ Delegation: DISABLED");
    info!(
        "  {} Mutual auth: {}",
        if require_mutual { "✓" } else { "⚠️" },
        if require_mutual {
            "ENABLED"
        } else {
            "DISABLED (faster but less secure)"
        }
    );
    info!("  ✓ Cache: Memory-based (faster, not persistent)");
    info!("  ✓ Auth level: Packet Integrity (no encryption, faster)");

    match KerberosClient::new(host, perf_config, creds.clone()) {
        Ok(_) => {
            info!("✓ High-performance client created");
            info!("  - Optimized for speed over security");
            info!("  - Use only in trusted networks");
        }
        Err(err) => {
            error!("✗ Failed to create performance client: {:?}", err);
        }
    }
    info!("");

    // ===== SCENARIO 4: Legacy/Non-DCE Configuration (Not for WMI/SMB) =====
    info!("Scenario 4: Legacy/Non-DCE Configuration");
    info!("=========================================");
    info!("(For comparison - NOT recommended for WMI/SMB)");

    let legacy_config = KerberosConfig::new(domain)
        .with_spn(format!("HOST/{}", host))
        .with_cache_backend(KerberosCacheBackend::File)
        .with_caching(true)
        .with_dce_style(false) // DISABLED: Use standard GSS-API
        .with_delegation(false)
        .with_mutual_auth(true);

    info!("Configuration:");
    info!("  ✗ DCE-style: DISABLED (will use GSS sequence checking)");
    info!("  ✓ Delegation: DISABLED");
    info!("  ✓ Mutual auth: ENABLED");
    info!("  Note: This configuration may NOT work correctly with WMI/SMB!");

    match KerberosClient::new(host, legacy_config, creds.clone()) {
        Ok(_) => {
            info!("✓ Legacy client created");
            warn!("  ⚠️  May experience sequence number issues with DCE/RPC");
            warn!("  ⚠️  Not recommended for WMI or SMB connections");
        }
        Err(err) => {
            error!("✗ Failed to create legacy client: {:?}", err);
        }
    }
    info!("");

    // ===== Summary and Best Practices =====
    info!("========================================");
    info!("DCE/RPC Kerberos Best Practices Summary");
    info!("========================================");
    info!("");
    info!("For WMI connections:");
    info!("  ✓ ALWAYS enable DCE-style flag");
    info!("  ✓ NEVER enable delegation unless absolutely necessary");
    info!("  ✓ ALWAYS require mutual authentication in production");
    info!("  ✓ Use Packet Privacy (encryption) for sensitive data");
    info!("");
    info!("GSS Flag Effects:");
    info!("  GSS_C_DCE_STYLE (0x1000):");
    info!("    - Disables GSS sequence number checking");
    info!("    - Allows out-of-order message processing");
    info!("    - Required for DCE/RPC protocols");
    info!("");
    info!("  GSS_C_DELEG_FLAG (0x01):");
    info!("    - Allows server to impersonate client");
    info!("    - Use only with completely trusted servers");
    info!("    - Required for S4U2Self/S4U2Proxy scenarios");
    info!("");
    info!("  GSS_C_MUTUAL_FLAG:");
    info!("    - Verifies server's identity");
    info!("    - Prevents man-in-the-middle attacks");
    info!("    - Should always be enabled in production");
    info!("");
    info!("✓ Demo complete!");
}
