use linux_wmi::auth_exports::Credentials;
use linux_wmi::{activate_wmi_dcom, resolve_oxid, DcomError};
use std::env;
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
        eprintln!("Example: {} 192.168.1.100 Administrator Password123 WORKGROUP", args[0]);
        return Ok(());
    }

    let host = &args[1];
    let username = &args[2];
    let password = &args[3];
    let domain = args.get(4).map(|s| s.as_str()).unwrap_or("");

    info!("Starting Phase 4 WMI query demonstration");
    info!("Host: {}, User: {}@{}", host, username, domain);

    // Create credentials
    let creds = Credentials {
        username: username.to_string(),
        password: password.to_string(),
        domain: domain.to_string(),
        workstation: "LINUX-WMI".to_string(),
    };

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
                    info!("\nNext: Execute 'SELECT * FROM Win32_Process' using authenticated transport");
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