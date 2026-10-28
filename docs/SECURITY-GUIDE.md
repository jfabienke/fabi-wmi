# Security Guide - fabi-wmi with kerbsec v0.2.0

## Overview

This guide covers security features, best practices, and threat mitigation strategies for fabi-wmi with the enhanced kerbsec v0.2.0 integration.

## Table of Contents

- [Security Features](#security-features)
- [Threat Model](#threat-model)
- [Best Practices](#best-practices)
- [Configuration Hardening](#configuration-hardening)
- [Credential Management](#credential-management)
- [Cache Security](#cache-security)
- [Channel Bindings](#channel-bindings)
- [Audit and Monitoring](#audit-and-monitoring)
- [Incident Response](#incident-response)

## Security Features

### 1. Automatic Memory Zeroization

All sensitive data is automatically cleared from memory using the `zeroize` crate.

**Protected Data:**
- Passwords (via `SecureString`)
- Session keys (16-byte arrays)
- Kerberos tickets
- NTLM response hashes
- Authentication tokens

**Implementation:**
```rust
// Automatic protection - no manual intervention needed
let creds = Credentials::new(
    username,
    password,  // Automatically wrapped in SecureString
    domain,
    workstation
);
// Password zeroized when creds drops
```

**Verification:**
```bash
# Build with debug symbols
cargo build --features kerberos

# Use memory debugger to verify zeroization
gdb ./target/debug/my_app
(gdb) break after_credentials_drop
(gdb) x/32x $memory_address  # Should show zeros
```

### 2. Credential Cache Protection

Multiple cache backends with different security profiles:

| Backend | File Permissions | User Isolation | Encryption | Persistence |
|---------|-----------------|----------------|------------|-------------|
| FILE | 0600 (user-only) | Per-user | No* | Yes |
| Memory | N/A | Per-process | No | No |
| KCM | Via socket | Yes | No | Yes |
| Keyring | Kernel-enforced | Yes | Kernel | Yes |

*Can be encrypted at filesystem level

### 3. Channel Binding Support

Prevents credential relay attacks by binding authentication to TLS channel:

```rust
// Enable channel bindings
let config = KerberosConfig::new(realm)
    .with_channel_bindings(tls_binding_data)
    .require_channel_bindings(true);  // Enforce
```

**Protection Against:**
- Man-in-the-middle attacks
- Credential forwarding
- Relay attacks
- Session hijacking

## Threat Model

### Threats and Mitigations

| Threat | Risk Level | Mitigation | Implementation |
|--------|------------|------------|----------------|
| **Memory Disclosure** | High | Automatic zeroization | `ZeroizeOnDrop` trait |
| **Credential Theft** | High | Secure cache, permissions | Cache backends, 0600 perms |
| **Relay Attacks** | Medium | Channel bindings | TLS binding verification |
| **Cache Poisoning** | Medium | File integrity | Atomic writes, checksums |
| **Timing Attacks** | Low | Constant-time operations | Via libgssapi |
| **Replay Attacks** | Medium | Sequence numbers | Built into Kerberos/NTLM |

### Attack Scenarios

#### Scenario 1: Memory Dump Attack
**Attack:** Attacker obtains memory dump containing credentials

**Defense:**
```rust
// Credentials automatically zeroized
{
    let creds = Credentials::new(...);
    authenticate(&creds);
} // Memory cleared here

// Even on panic, Drop trait ensures cleanup
```

#### Scenario 2: Cache File Theft
**Attack:** Attacker steals credential cache file

**Defense:**
```bash
# Proper permissions automatically set
$ ls -la /tmp/krb5cc_*
-rw------- 1 user user 4096 /tmp/krb5cc_1000

# Use keyring for enhanced security
export KRB5CCNAME=KEYRING:persistent
```

#### Scenario 3: Network Relay
**Attack:** Attacker relays authentication to different service

**Defense:**
```rust
// Require channel bindings
let config = config
    .require_channel_bindings(true);
// Authentication fails if TLS channel doesn't match
```

## Best Practices

### 1. Credential Handling

**DO:**
```rust
// Use constructor - automatic protection
let creds = Credentials::new(
    username,
    password,
    domain,
    workstation
);

// Let credentials go out of scope naturally
{
    let creds = get_credentials();
    perform_authentication(&creds);
} // Automatic cleanup
```

**DON'T:**
```rust
// Don't store passwords in regular strings
let password = String::from("secret");  // Not protected!

// Don't clone credentials unnecessarily
let creds2 = creds.clone();  // Increases exposure
```

### 2. Cache Configuration

**Production Setup:**
```rust
// Long-running service
let config = KerberosConfig::new(realm)
    .with_cache_backend(KerberosCacheBackend::File)
    .with_cache_path("/var/lib/myapp/krb5cc")
    .with_caching(true);

// High-security environment
let config = KerberosConfig::new(realm)
    .with_cache_backend(KerberosCacheBackend::Keyring)
    .with_caching(true);
```

**Development Setup:**
```rust
// Temporary, no persistence needed
let config = KerberosConfig::new(realm)
    .with_cache_backend(KerberosCacheBackend::Memory)
    .with_caching(true);
```

### 3. Error Handling

**Never log sensitive data:**
```rust
// GOOD: Log error without credentials
match authenticate(&creds) {
    Err(e) => log::error!("Auth failed for user {}: {}",
                         creds.username, e),  // Username only
    Ok(_) => log::info!("Auth successful"),
}

// BAD: Don't log passwords
log::debug!("Authenticating with {:?}", creds);  // May expose password!
```

## Configuration Hardening

### 1. Enforce Strong Authentication

```rust
// Require packet privacy (encryption)
let config = KerberosConfig::new(realm)
    .with_auth_level(AuthLevel::PacketPrivacy);

// Require channel bindings
let config = config.require_channel_bindings(true);

// Disable weak crypto
// (Configured in krb5.conf, not in code)
```

### 2. Restrict Cache Access

```bash
# Set restrictive umask
umask 077

# Use dedicated cache directory
mkdir -p /var/cache/myapp
chmod 700 /var/cache/myapp

# Configure app to use it
export KRB5CCNAME=FILE:/var/cache/myapp/krb5cc
```

### 3. Limit Credential Lifetime

```bash
# In krb5.conf
[libdefaults]
    ticket_lifetime = 10h
    renew_lifetime = 7d

# Programmatically
let config = config
    .with_ticket_lifetime(Duration::from_hours(4));
```

## Credential Management

### Storage Guidelines

| Credential Type | Storage Method | Lifetime | Notes |
|----------------|---------------|----------|-------|
| User Password | `SecureString` | Session | Never persist |
| Kerberos Ticket | Cache file | 10 hours | Auto-renew if possible |
| Session Key | Memory only | Connection | Zeroized after use |
| Service Ticket | Cache file | Service-specific | Reuse for performance |

### Rotation Strategy

```rust
// Implement credential rotation
struct CredentialManager {
    current: Credentials,
    next: Option<Credentials>,
    rotation_time: Instant,
}

impl CredentialManager {
    fn should_rotate(&self) -> bool {
        Instant::now() > self.rotation_time
    }

    fn rotate(&mut self) {
        if let Some(next) = self.next.take() {
            self.current = next;
            self.rotation_time = Instant::now() + Duration::from_hours(8);
        }
    }
}
```

## Cache Security

### File Cache Hardening

```bash
#!/bin/bash
# Secure cache setup script

CACHE_DIR="/var/cache/myapp"
CACHE_FILE="${CACHE_DIR}/krb5cc"

# Create secure directory
mkdir -p "${CACHE_DIR}"
chmod 700 "${CACHE_DIR}"
chown $USER:$USER "${CACHE_DIR}"

# Set SELinux context (if applicable)
if command -v semanage &> /dev/null; then
    semanage fcontext -a -t user_tmp_t "${CACHE_DIR}"
    restorecon -v "${CACHE_DIR}"
fi

# Export for application
export KRB5CCNAME="FILE:${CACHE_FILE}"
```

### Cache Monitoring

```rust
// Monitor cache usage
use std::fs;
use std::time::SystemTime;

fn check_cache_security(path: &Path) -> Result<(), SecurityError> {
    let metadata = fs::metadata(path)?;

    // Check permissions (Unix)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(SecurityError::InsecurePermissions);
        }
    }

    // Check age
    let age = SystemTime::now()
        .duration_since(metadata.modified()?)
        .unwrap_or_default();

    if age > Duration::from_hours(24) {
        return Err(SecurityError::StaleCache);
    }

    Ok(())
}
```

## Channel Bindings

### Implementation

```rust
// Full channel binding setup
struct SecureWmiClient {
    tls_stream: TlsStream,
    kerberos_config: KerberosConfig,
}

impl SecureWmiClient {
    fn connect(host: &str, creds: Credentials) -> Result<Self> {
        // 1. Establish TLS
        let tls_stream = TlsStream::connect(host)?;

        // 2. Extract bindings
        let cert = tls_stream.peer_certificate()?;
        let bindings = KerberosClient::extract_channel_bindings_from_cert(&cert)
            .ok_or(SecurityError::NoBindings)?;

        // 3. Configure with bindings
        let config = KerberosConfig::new(get_realm(host))
            .with_channel_bindings(bindings)
            .require_channel_bindings(true);

        Ok(Self { tls_stream, kerberos_config: config })
    }
}
```

### Verification

```bash
# Enable debug logging to verify bindings
RUST_LOG=kerbsec=debug cargo run

# Look for:
# "Channel bindings configured with N bytes"
# "Channel binding verification successful"
```

## Audit and Monitoring

### Logging Configuration

```rust
// Setup security logging
use tracing::{info, warn, error};

fn setup_security_logging() {
    tracing_subscriber::fmt()
        .with_env_filter("fabi_wmi=info,kerbsec=info")
        .with_target(true)
        .with_timestamp(true)
        .json()  // For SIEM ingestion
        .init();
}

// Log security events
fn log_auth_attempt(user: &str, host: &str, success: bool) {
    if success {
        info!(
            user = user,
            host = host,
            event = "auth_success",
            "Authentication successful"
        );
    } else {
        warn!(
            user = user,
            host = host,
            event = "auth_failure",
            "Authentication failed"
        );
    }
}
```

### Metrics Collection

```rust
// Track security metrics
struct SecurityMetrics {
    auth_attempts: Counter,
    auth_failures: Counter,
    cache_hits: Counter,
    cache_misses: Counter,
    relay_attempts: Counter,
}

impl SecurityMetrics {
    fn record_auth(&self, success: bool) {
        self.auth_attempts.inc();
        if !success {
            self.auth_failures.inc();
        }
    }
}
```

## Incident Response

### Detection Indicators

| Indicator | Detection Method | Response |
|-----------|-----------------|----------|
| Repeated auth failures | Log monitoring | Block IP, alert |
| Cache tampering | File integrity monitoring | Regenerate cache |
| Memory disclosure | Core dump analysis | Rotate credentials |
| Relay attempt | Channel binding failure | Alert, investigate |
| Unusual access pattern | Anomaly detection | Review, possible breach |

### Response Procedures

```rust
// Automated response to security events
async fn handle_security_event(event: SecurityEvent) {
    match event {
        SecurityEvent::RepeatedAuthFailure { ip, count } => {
            if count > 5 {
                firewall::block_ip(ip).await;
                alert::send("Blocked IP after repeated failures", &ip).await;
            }
        },
        SecurityEvent::CacheTampered { path } => {
            // Delete compromised cache
            fs::remove_file(path).ok();
            // Force re-authentication
            force_reauth().await;
        },
        SecurityEvent::RelayAttempt { source } => {
            log::error!("Relay attack detected from {:?}", source);
            alert::send_critical("Relay attack detected", &source).await;
        },
        _ => log::warn!("Unhandled security event: {:?}", event),
    }
}
```

## Security Checklist

### Development
- [ ] Use `Credentials::new()` constructor
- [ ] Enable credential caching appropriately
- [ ] Configure channel bindings for TLS
- [ ] Implement proper error handling
- [ ] Never log passwords or session keys

### Deployment
- [ ] Set restrictive file permissions (0600)
- [ ] Use dedicated cache directory
- [ ] Configure ticket lifetime limits
- [ ] Enable security logging
- [ ] Monitor authentication failures

### Operations
- [ ] Regular credential rotation
- [ ] Cache cleanup policy
- [ ] Security event monitoring
- [ ] Incident response plan
- [ ] Regular security audits

## Compliance

### Standards Compliance

| Standard | Requirement | Implementation |
|----------|------------|----------------|
| **NIST 800-63B** | Memorized secret verifier | Zeroization, secure storage |
| **PCI DSS 3.2.1** | Protect stored credentials | Encryption, access control |
| **ISO 27001** | Access control | Authentication, authorization |
| **GDPR** | Data protection | Encryption, zeroization |

### Audit Requirements

```bash
# Generate compliance report
./scripts/security-audit.sh

# Verify zeroization
valgrind --tool=memcheck ./target/debug/my_app

# Check cache permissions
find /tmp -name "krb5cc_*" -exec ls -la {} \;
```

## Support

For security issues:
1. **Do NOT** file public GitHub issues
2. Email security concerns to: security@example.com
3. Include:
   - Description of issue
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

---

*Security is a shared responsibility. This guide provides tools and practices, but proper implementation and monitoring are essential.*