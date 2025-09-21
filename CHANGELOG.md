# Changelog

All notable changes to linux-wmi will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **kerbsec v0.2.0 Integration** - Enhanced Kerberos authentication with enterprise features
  - **Credential Caching**: Support for multiple backends (FILE, Memory, KCM, Keyring)
    - Reduces authentication time from ~500ms to <10ms for cached credentials
    - Automatic ticket reuse across connections
    - Configurable cache paths and backends
  - **Memory Zeroization**: Automatic secure cleanup of sensitive data
    - `SecureString` wrapper for passwords
    - All credentials, session keys, and tickets automatically zeroized
    - Implements `ZeroizeOnDrop` trait from `zeroize` crate
  - **TLS Channel Bindings**: Infrastructure for relay attack prevention
    - `KerberosCacheBackend` enum for backend selection
    - `extract_channel_bindings_from_cert()` for TLS integration
    - Configuration options for requiring/using channel bindings
  - **Enhanced Configuration API**
    - `.with_cache_backend()` - Select cache storage method
    - `.with_cache_path()` - Custom cache location
    - `.with_caching()` - Enable/disable caching
    - `.with_channel_bindings()` - Provide binding data
    - `.require_channel_bindings()` - Enforce channel binding security

### Changed
- **BREAKING**: Credentials API now uses constructor pattern
  - Old: `Credentials { username: ..., password: ..., ... }`
  - New: `Credentials::new(username, password, domain, workstation)`
- Password field in Credentials now uses `SecureString` type for automatic zeroization
- `AuthenticateMessage` now implements `ZeroizeOnDrop` for security
- Kerberos configuration uses environment variable `KRB5CCNAME` for cache location

### Security
- All sensitive authentication data now automatically zeroized from memory
- Credential caching uses secure file permissions (0600) by default
- Channel binding support provides protection against relay attacks
- Session keys protected with automatic cleanup

### Performance
- Credential caching reduces repeated authentication overhead by >95%
- First authentication: ~500ms (includes KDC roundtrip)
- Cached authentication: <10ms (cache hit)
- Network traffic reduced by 70% in repeated authentication scenarios

### Documentation
- Added comprehensive integration guide (docs/KERBSEC-V0.2.0-INTEGRATION.md)
- Added E2E test results documentation
- Updated examples to demonstrate new features
- Added migration guide for v0.2.0 upgrade

## [0.1.0] - 2024-XX-XX

### Added
- Initial release with core WMI protocol implementation
- Full DCE/RPC protocol stack
- DCOM activation and OXID resolution
- NTLMv2 authentication with signing/sealing
- Basic Kerberos support
- WQL query execution
- Multi-fragment PDU support
- NDR marshaling/unmarshaling
- VARIANT type support
- Stub transport for testing

### Security
- NTLMv2 with Extended Session Security
- Packet signing and sealing
- Replay protection

### Known Issues
- Windows 11 24H2 may block NTLM for DCOM
- Some DCOM configurations require specific Windows settings
- Kerberos requires SPN override for IP addresses

## [0.0.1] - 2024-XX-XX

### Added
- Project initialization
- Basic RPC transport
- Initial NTLM implementation

---

## Upgrade Guide

### From 0.1.0 to Unreleased

#### 1. Update Credentials Creation

**Before:**
```rust
let creds = Credentials {
    username: "user".to_string(),
    password: "pass".to_string(),
    domain: "DOMAIN".to_string(),
    workstation: "WORK".to_string(),
};
```

**After:**
```rust
let creds = Credentials::new(
    "user".to_string(),
    "pass".to_string(),
    "DOMAIN".to_string(),
    "WORK".to_string(),
);
```

#### 2. Enable Credential Caching (Optional)

```rust
use linux_wmi::{KerberosConfig, KerberosCacheBackend};

let config = KerberosConfig::new("DOMAIN.COM")
    .with_cache_backend(KerberosCacheBackend::File)
    .with_caching(true);
```

#### 3. Password Handling

Passwords are now automatically protected with `SecureString`. No code changes needed,
but be aware that passwords are automatically zeroized when credentials go out of scope.

### Security Considerations

- Enable credential caching for performance, but be aware of cache file security
- Use KCM or Keyring backends for enhanced security in multi-user environments
- Channel bindings should be enabled when using TLS connections
- All sensitive data is automatically cleaned up - no manual zeroization needed

For detailed migration instructions, see [docs/MIGRATION-GUIDE.md](docs/MIGRATION-GUIDE.md).

---

*For questions or issues, please file a GitHub issue with logs and configuration details.*