# Kerberos Configuration Guide for linux-wmi

This guide documents all Kerberos configuration options available in linux-wmi, including the new runtime-configurable GSS flags introduced with kerbsec v0.2.0+.

## Table of Contents

- [Basic Configuration](#basic-configuration)
- [GSS Flags Configuration](#gss-flags-configuration)
- [Authentication Levels](#authentication-levels)
- [Credential Caching](#credential-caching)
- [Channel Bindings](#channel-bindings)
- [Common Scenarios](#common-scenarios)
- [Security Best Practices](#security-best-practices)

## Basic Configuration

### Minimal Configuration

```rust
use linux_wmi::{KerberosConfig, KerberosClient, Credentials};

let config = KerberosConfig::new("CONTOSO.COM")
    .with_spn("HOST/server.contoso.com");

let creds = Credentials::new(
    "username".to_string(),
    "password".to_string(),
    "CONTOSO.COM".to_string(),
    "WORKSTATION".to_string(),
);

let client = KerberosClient::new("server.contoso.com", config, creds)?;
```

### Default Configuration Values

| Setting                | Default Value   | Description                    |
|------------------------|-----------------|--------------------------------|
| `auth_level`           | `PacketPrivacy` | Full encryption and integrity  |
| `enable_dce_style`     | `true`          | DCE/RPC compatibility mode     |
| `enable_delegation`    | `false`         | Credential delegation disabled |
| `require_mutual_auth`  | `true`          | Server authentication required |
| `enable_cache`         | `true`          | Credential caching enabled     |
| `cache_backend`        | `File`          | File-based credential cache    |
| `use_dns_discovery`    | `true`          | DNS-based KDC discovery        |
| `udp_fallback_to_tcp`  | `true`          | TCP fallback for large tickets |
| `clock_skew_tolerance` | 300 seconds     | Kerberos clock skew tolerance  |

## GSS Flags Configuration

### DCE-Style Flag (GSS_C_DCE_STYLE)

The DCE-style flag (0x1000) is **critical for DCE/RPC protocols** like WMI and SMB:

```rust
let config = KerberosConfig::new("CONTOSO.COM")
    .with_spn("HOST/server.contoso.com")
    .with_dce_style(true);  // Default: true for DCE/RPC
```

**What DCE-style does:**
- Disables GSS sequence number checking (DCE/RPC has its own)
- Allows out-of-order message processing
- Prevents GSS replay cache from interfering with DCE/RPC

**When to use:**
- ✅ **Always** for WMI connections
- ✅ **Always** for SMB connections
- ✅ **Always** for any DCE/RPC protocol
- ❌ **Never** for pure GSS-API applications

### Delegation Flag (GSS_C_DELEG_FLAG)

Credential delegation allows the server to impersonate the client:

```rust
let config = KerberosConfig::new("CONTOSO.COM")
    .with_spn("HOST/trusted-server.contoso.com")
    .with_delegation(true);  // Default: false - DANGEROUS!
```

**⚠️ SECURITY WARNING:**
- Delegation allows the server to act as the client to any service
- Only enable for **completely trusted** servers
- Disabled by default for security

**Valid use cases:**
- S4U2Self (service acting on behalf of user)
- S4U2Proxy (constrained delegation)
- Multi-tier authentication scenarios

**Checking for delegated credentials:**
```rust
if client.has_delegated_credentials() {
    // Server received delegated credentials
    let creds = client.export_delegated_credentials()?;
    // Use carefully - these allow impersonation!
}
```

### Mutual Authentication Flag (GSS_C_MUTUAL_FLAG)

Mutual authentication verifies the server's identity:

```rust
let config = KerberosConfig::new("CONTOSO.COM")
    .with_spn("HOST/server.contoso.com")
    .with_mutual_auth(true);  // Default: true for security
```

**When to disable (NOT recommended):**
- Testing environments only
- Legacy servers that don't support it
- Performance-critical scenarios in trusted networks

## Authentication Levels

### Packet Privacy (Default)

Full encryption and integrity protection:

```rust
use linux_wmi::AuthLevel;

let config = KerberosConfig::new("CONTOSO.COM")
    .with_spn("HOST/server.contoso.com")
    .with_auth_level(AuthLevel::PacketPrivacy);  // Default
```

### Packet Integrity

Message integrity without encryption (faster but less secure):

```rust
let config = KerberosConfig::new("CONTOSO.COM")
    .with_spn("HOST/server.contoso.com")
    .with_auth_level(AuthLevel::PacketIntegrity);
```

### None

No protection (authentication only - NOT recommended):

```rust
let config = KerberosConfig::new("CONTOSO.COM")
    .with_spn("HOST/server.contoso.com")
    .with_auth_level(AuthLevel::None);
```

## Credential Caching

### File-Based Cache (Default)

Persistent cache using MIT Kerberos ccache format:

```rust
use linux_wmi::KerberosCacheBackend;

let config = KerberosConfig::new("CONTOSO.COM")
    .with_spn("HOST/server.contoso.com")
    .with_cache_backend(KerberosCacheBackend::File)
    .with_cache_path("/tmp/krb5cc_custom");  // Optional custom path
```

### Memory Cache

Non-persistent, in-memory cache (faster but not shared):

```rust
let config = KerberosConfig::new("CONTOSO.COM")
    .with_spn("HOST/server.contoso.com")
    .with_cache_backend(KerberosCacheBackend::Memory);
```

### KCM Cache

Kerberos Credential Manager daemon (shared, secure):

```rust
let config = KerberosConfig::new("CONTOSO.COM")
    .with_spn("HOST/server.contoso.com")
    .with_cache_backend(KerberosCacheBackend::Kcm);
```

### Keyring Cache

Linux kernel keyring (secure, persistent):

```rust
let config = KerberosConfig::new("CONTOSO.COM")
    .with_spn("HOST/server.contoso.com")
    .with_cache_backend(KerberosCacheBackend::Keyring);
```

## Channel Bindings

Channel bindings tie Kerberos to the transport layer (e.g., TLS):

```rust
// Get TLS unique data from your TLS connection
let tls_unique = get_tls_unique_from_connection();

let config = KerberosConfig::new("CONTOSO.COM")
    .with_spn("HOST/server.contoso.com")
    .with_channel_bindings(tls_unique)
    .require_channel_bindings(true);
```

## Common Scenarios

### Standard WMI Connection

Best configuration for WMI over DCE/RPC:

```rust
let config = KerberosConfig::new("CONTOSO.COM")
    .with_spn("HOST/wmi-server.contoso.com")
    .with_dce_style(true)        // Required for DCE/RPC
    .with_delegation(false)      // Security best practice
    .with_mutual_auth(true)      // Verify server identity
    .with_auth_level(AuthLevel::PacketPrivacy)  // Encrypt data
    .with_cache_backend(KerberosCacheBackend::File)
    .with_spnego();  // Enable SPNEGO negotiation
```

### Trusted Internal Server

Configuration for completely trusted servers requiring delegation:

```rust
let config = KerberosConfig::new("CONTOSO.COM")
    .with_spn("HOST/trusted-dc.contoso.com")
    .with_dce_style(true)
    .with_delegation(true)       // ⚠️ DANGEROUS - only for trusted!
    .with_mutual_auth(true)      // Critical with delegation
    .with_auth_level(AuthLevel::PacketPrivacy);
```

### High-Performance Configuration

Optimized for speed in trusted networks:

```rust
let config = KerberosConfig::new("CONTOSO.COM")
    .with_spn("HOST/internal-server.contoso.com")
    .with_dce_style(true)
    .with_delegation(false)
    .with_mutual_auth(false)     // Skip for performance
    .with_auth_level(AuthLevel::PacketIntegrity)  // No encryption
    .with_cache_backend(KerberosCacheBackend::Memory);  // Faster
```

### IP Address Target

When connecting to an IP address, you must provide an SPN:

```rust
let config = KerberosConfig::new("CONTOSO.COM")
    .with_spn("HOST/server.contoso.com")  // Required for IP!
    .with_dce_style(true);

let client = KerberosClient::new("192.168.1.100", config, creds)?;
```

## Security Best Practices

### For Production Environments

1. **Always enable DCE-style for DCE/RPC protocols**
   ```rust
   .with_dce_style(true)  // Required for WMI/SMB
   ```

2. **Never enable delegation unless absolutely necessary**
   ```rust
   .with_delegation(false)  // Default - keep it!
   ```

3. **Always require mutual authentication**
   ```rust
   .with_mutual_auth(true)  // Verify server identity
   ```

4. **Use Packet Privacy for sensitive data**
   ```rust
   .with_auth_level(AuthLevel::PacketPrivacy)
   ```

5. **Use persistent credential caching**
   ```rust
   .with_cache_backend(KerberosCacheBackend::File)
   ```

### Security Checklist

- [ ] DCE-style enabled for DCE/RPC protocols
- [ ] Delegation disabled (unless required and server is trusted)
- [ ] Mutual authentication enabled
- [ ] Appropriate authentication level selected
- [ ] Credential cache configured appropriately
- [ ] Channel bindings enabled if using TLS
- [ ] SPN correctly specified (especially for IP addresses)

## Troubleshooting

### Common Issues

**"SPN resolution failed"**
- Ensure SPN is provided for IP addresses
- Check DNS resolution for hostnames
- Verify SPN format: `SERVICE/hostname@REALM`

**"Invalid authentication state"**
- Check that Kerberos tickets are available (`klist`)
- Verify realm and domain configuration
- Ensure time synchronization (within 5 minutes)

**"Sequence number errors" with DCE/RPC**
- Ensure `with_dce_style(true)` is set
- This is required for WMI and SMB

**"Delegation not working"**
- Verify `with_delegation(true)` is set
- Check server is configured for delegation
- Ensure account has delegation privileges

### Debug Logging

Enable detailed logging to troubleshoot:

```bash
RUST_LOG=linux_wmi=debug,kerbsec=debug cargo run --example test_kerberos
```

## Migration Guide

### From Pre-v0.2.0

Before (hardcoded behavior):
```rust
// DCE-style and delegation were not configurable
let config = KerberosConfig::new("CONTOSO.COM")
    .with_spn("HOST/server.contoso.com");
```

After (runtime-configurable):
```rust
// Now you can configure GSS flags at runtime
let config = KerberosConfig::new("CONTOSO.COM")
    .with_spn("HOST/server.contoso.com")
    .with_dce_style(true)        // Configurable
    .with_delegation(false)      // Configurable
    .with_mutual_auth(true);     // Configurable
```

## Examples

See the following examples for practical usage:

- `examples/test_kerberos.rs` - Basic Kerberos testing with all features
- `examples/dce_rpc_kerberos.rs` - DCE/RPC best practices and scenarios

Run examples with:
```bash
cargo run --example dce_rpc_kerberos --features kerberos -- \
    server.contoso.com --user admin --pass <password> --domain CONTOSO.COM
```

---

*Configuration guide for linux-wmi with kerbsec v0.2.0+*
