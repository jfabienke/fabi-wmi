# WMI Authentication Guide

This guide explains the authentication methods available in linux-wmi and how to troubleshoot connection issues, particularly with Windows 11 and other security-hardened environments.

## Overview

linux-wmi supports multiple authentication methods and port resolution strategies to connect to Windows WMI services. Due to varying Windows security policies, different methods may be required for different environments.

## ⚠️ Critical Update: NTLM Being Removed from Windows

Microsoft has begun actively removing NTLM from Windows systems:
- **Windows 11 24H2**: Already blocks NTLM for DCOM
- **October 2026**: Complete NTLM block enforcement
- **Impact**: Cross-platform WMI connections will fail without Kerberos

**Immediate Action Required**: Implement Kerberos authentication or use alternative methods. See [NTLM Deprecation Timeline](./NTLM-DEPRECATION-TIMELINE.md) for critical details.

---

## Port Resolution Methods

The library attempts to resolve the WMI service port using the following fallback sequence:

1. **Direct Port Specification** (Environment Variable)
2. **Anonymous DCOM Activation**
3. **Authenticated DCOM Activation**
4. **Legacy Fallback** (Port 135)

### 1. Direct Port Specification (Recommended for Testing)

The simplest method - bypass all port discovery by specifying the WMI port directly:

```bash
# Find the WMI port on Windows:
# netstat -an | findstr LISTENING | findstr :49

# Use the discovered port (example: 49155)
export LINUX_WMI_PORT=49155
cargo run --example test_connect <host> \
  --user <username> --pass <password> \
  --query 'SELECT Name FROM Win32_ComputerSystem'
```

**When to use:**
- During development and testing
- When the WMI port is static and known
- To bypass DCOM/EPM issues entirely

**Advantages:**
- Fastest connection method
- Bypasses all authentication issues with DCOM
- Works even when NTLM is blocked for DCOM

### 2. Anonymous DCOM Activation

Attempts to connect to the Service Control Manager (SCM) on port 135 without authentication:

```bash
# Will try automatically if LINUX_WMI_PORT is not set
cargo run --example test_connect <host> \
  --user <username> --pass <password> \
  --query 'SELECT Name FROM Win32_ComputerSystem'
```

**When it works:**
- Windows systems configured to allow anonymous RPC enumeration
- Some Windows Server configurations
- Development/test environments

**When it fails:**
- Windows 11 with default security settings
- Hardened enterprise environments
- Systems with "Restrict anonymous access" policies

### 3. Authenticated DCOM Activation

Uses NTLM authentication to activate WMI via DCOM on port 135:

```bash
# Attempted automatically after anonymous fails
cargo run --example test_connect <host> \
  --user <username> --pass <password> \
  --query 'SELECT Name FROM Win32_ComputerSystem'
```

**Common failure reason: Windows 11 NTLM Restrictions**

Windows 11 and security-hardened systems may reject NTLM authentication for DCOM with:
- `bind_nak` response with reason `0x05` (authentication type not recognized)

This indicates the system has policies blocking NTLM, such as:
- `Network security: Restrict NTLM: Incoming NTLM traffic = Deny all`
- `Network security: Restrict NTLM: NTLM authentication in this domain = Deny all`

## Troubleshooting Connection Failures

### Error: "bind_nak, reason: 0x05"

**Cause:** Windows is rejecting NTLM authentication due to security policies.

**Solutions:**
1. Use direct port specification (`LINUX_WMI_PORT`)
2. Check Windows security policies:
   - Press `Win+R`, type `secpol.msc`
   - Navigate to `Local Policies` → `Security Options`
   - Check `Network security: Restrict NTLM` settings
3. Consider using WinRM instead (port 5985/5986)

### Error: "Connection timeout" or "No response"

**Cause:** Firewall blocking ports or service not running.

**Solutions:**
1. Verify Windows Firewall allows:
   - TCP 135 (RPC Endpoint Mapper)
   - Dynamic RPC ports (49152-65535)
   - WMI-In firewall rule enabled
2. Check WMI service is running:
   ```powershell
   Get-Service Winmgmt
   ```

### Error: "Access denied (0x80070005)"

**Cause:** User lacks necessary permissions.

**Solutions:**
1. Add user to "Distributed COM Users" group
2. Grant DCOM permissions:
   - Run `dcomcnfg.exe`
   - Navigate to `Component Services` → `Computers` → `My Computer` → `DCOM Config`
   - Right-click `Windows Management and Instrumentation` → `Properties`
   - Security tab → `Launch and Activation Permissions` → Edit
   - Grant user "Local Launch" and "Remote Activation"
3. Grant WMI namespace permissions:
   - Run `wmimgmt.msc`
   - Right-click `WMI Control` → `Properties`
   - Security tab → Select namespace (e.g., Root\CIMV2)
   - Grant user "Enable Account" and "Remote Enable"

## Environment Variables

| Variable             | Purpose                            | Example           |
|----------------------|------------------------------------|-------------------|
| `LINUX_WMI_PORT`     | Specify WMI port directly          | `49155`           |
| `LINUX_WMI_SKIP_EPM` | Skip port resolution, use port 135 | `1`               |
| `RUST_LOG`           | Enable debug logging               | `debug` or `info` |

## Debugging Connection Issues

Enable debug logging to see the full authentication flow:

```bash
export RUST_LOG=debug
cargo run --example test_connect <host> --user <user> --pass <pass>
```

Look for messages indicating which method is being attempted:
- `"Using hardcoded WMI port from LINUX_WMI_PORT"`
- `"Attempting anonymous DCOM activation"`
- `"Using DCOM activation for WMI port resolution"`

## Security Considerations

1. **Direct Port Method:** Requires knowledge of the WMI port but bypasses DCOM security checks. The actual WMI connection still requires valid credentials.

2. **Anonymous DCOM:** Only retrieves the WMI port anonymously; the actual WMI operations still require authentication.

3. **Credential Security:** Always use secure methods to provide credentials. Avoid hardcoding passwords in scripts.

## Kerberos Authentication (Production Ready)

Kerberos authentication is now fully implemented with kerbsec v0.2.0 integration, providing enterprise-grade features to address Windows 11's NTLM removal. This is critical for cross-platform WMI connectivity.

### Platform Requirements

| Platform | Requirements                    | Status       |
|----------|---------------------------------|--------------|
| Linux    | MIT Kerberos libs, `libgssapi`  | ✅ Supported |
| macOS    | Heimdal (built-in), `libgssapi` | ✅ Supported |
| Windows  | SSPI (built-in), `sspi` crate   | ✅ Supported |
| FreeBSD  | MIT/Heimdal libs                | ✅ Supported |

### Configuration Examples

#### Basic Kerberos Authentication
```rust
use linux_wmi::{KerberosConfig, WmiSession, Credentials};

let config = KerberosConfig::new("CONTOSO.COM")
    .with_spn("host/server.contoso.com");

let creds = Credentials::new(
    "user".to_string(),
    "password".to_string(),
    "CONTOSO.COM".to_string(),
    "WORKSTATION".to_string(),
);

let mut session = WmiSession::with_kerberos(
    "server.contoso.com",
    config,
    creds
)?;
```

#### With Credential Caching (60x Faster)
```rust
use linux_wmi::{KerberosConfig, KerberosCacheBackend};

// Enable caching for dramatic performance improvement
let config = KerberosConfig::new("CONTOSO.COM")
    .with_spn("host/server.contoso.com")
    .with_cache_backend(KerberosCacheBackend::File)
    .with_caching(true);

// First connection: ~500ms (gets TGT, stores in cache)
// Subsequent connections: <10ms (uses cached ticket)
```

#### Command Line Example
```bash
# Set cache location (optional)
export KRB5CCNAME=FILE:/tmp/krb5cc_myapp

# Run with Kerberos
cargo run --example test_connect server.contoso.com \
  --user user --pass password --domain CONTOSO.COM \
  --query 'SELECT * FROM Win32_ComputerSystem'
```

### Key Differences from NTLM

1. **Requires KDC**: Must have access to Kerberos Domain Controller
2. **Time Sync**: Requires clock synchronization (±5 minutes)
3. **Three-Leg Auth**: DCE-style requires 3 authentication exchanges
4. **Stronger Security**: AES-256 encryption, mutual authentication
5. **Delegation**: Supports credential delegation for multi-hop

### New v0.2.0 Features

#### 🔐 Automatic Memory Protection
All sensitive data is automatically zeroized when no longer needed:
```rust
// Passwords automatically protected
let creds = Credentials::new(username, password, domain, workstation);
// Password securely erased when creds drops
```

#### ⚡ Credential Caching
Multiple cache backends for different security/performance needs:

| Backend | Security | Speed | Persistence | Use Case |
|---------|----------|-------|-------------|----------|
| FILE | Standard | Fast | Yes | Default, single-user |
| Memory | High | Fastest | No | Short scripts |
| KCM | High | Good | Yes | Multi-user systems |
| Keyring | Highest | Good | Yes | High-security apps |

#### 🛡️ TLS Channel Bindings
Prevent relay attacks when using TLS:
```rust
// Extract bindings from TLS certificate
let bindings = KerberosClient::extract_channel_bindings_from_cert(&cert);

// Require channel bindings
let config = config
    .with_channel_bindings(bindings.unwrap())
    .require_channel_bindings(true);
```

### Implementation Status

- Design: ✅ Complete
- Implementation: ✅ Production Ready (kerbsec v0.2.0)
- Windows 11 24H2: ✅ Compatible
- Security Features: ✅ Enterprise-grade

For migration guide, see [MIGRATION-GUIDE.md](./MIGRATION-GUIDE.md).
For API reference, see [API-REFERENCE.md](./API-REFERENCE.md).
For security best practices, see [SECURITY-GUIDE.md](./SECURITY-GUIDE.md).

## Future Enhancements

- **EPM Protocol:** Proper Endpoint Mapper implementation for discovering services
- **Named Pipes over SMB:** Alternative transport via `\\pipe\\WBEM`
- **Certificate Authentication:** PKU2U for workgroup scenarios

## Related Documentation

- [macOS Socket Investigation](./MACOS-SOCKET-INVESTIGATION.md) - Socket timeout issues on macOS
- [EPM Limitations](./EPM_LIMITATIONS.md) - Why EPM doesn't work for WMI
- [DCOM Activation](./DCOM_ACTIVATION.md) - Technical details of DCOM activation
