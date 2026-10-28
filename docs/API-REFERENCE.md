# API Reference - fabi-wmi with kerbsec v0.2.0

## Table of Contents

- [Authentication Types](#authentication-types)
- [Kerberos Configuration](#kerberos-configuration)
- [Credential Management](#credential-management)
- [Cache Backends](#cache-backends)
- [Channel Bindings](#channel-bindings)
- [WMI Session](#wmi-session)
- [Error Types](#error-types)

## Authentication Types

### `Credentials`

Secure credential storage with automatic memory zeroization.

```rust
pub struct Credentials {
    pub username: String,
    pub password: SecureString,  // Automatically zeroized
    pub domain: String,
    pub workstation: String,
}

impl Credentials {
    /// Create new credentials (password will be protected)
    pub fn new(
        username: String,
        password: String,
        domain: String,
        workstation: String
    ) -> Self;

    /// Validate credentials are not empty
    pub fn validate(&self) -> Result<(), AuthError>;
}
```

**Example:**
```rust
let creds = Credentials::new(
    "administrator".to_string(),
    "SecurePass123!".to_string(),
    "CORP".to_string(),
    "WORKSTATION".to_string(),
);
// Password automatically zeroized when creds goes out of scope
```

### `SecureString`

Protected string that zeroizes on drop.

```rust
pub struct SecureString(String);

impl SecureString {
    pub fn new(s: String) -> Self;
    pub fn as_str(&self) -> &str;
    pub fn is_empty(&self) -> bool;
}
```

## Kerberos Configuration

### `KerberosConfig`

Enhanced configuration with caching and channel binding support.

```rust
pub struct KerberosConfig {
    pub realm: String,
    pub kdc_address: Option<String>,
    pub use_dns_discovery: bool,
    pub use_keytab: bool,
    pub keytab_path: Option<PathBuf>,
    pub spn_override: Option<String>,
    pub clock_skew_tolerance: Duration,
    pub udp_fallback_to_tcp: bool,
    pub auth_level: AuthLevel,
    pub prefer_spnego: bool,
    // New in v0.2.0
    pub cache_backend: KerberosCacheBackend,
    pub cache_path: Option<PathBuf>,
    pub enable_cache: bool,
    pub require_channel_bindings: bool,
    pub channel_binding_data: Option<Vec<u8>>,
}
```

### Builder Methods

```rust
impl KerberosConfig {
    /// Create new config with realm
    pub fn new(realm: impl Into<String>) -> Self;

    /// Set SPN override (required for IP addresses)
    pub fn with_spn(self, spn: impl Into<String>) -> Self;

    /// Set keytab path for Kerberos
    pub fn with_keytab_path(self, path: impl Into<String>) -> Self;

    // New in v0.2.0

    /// Set credential cache backend
    pub fn with_cache_backend(self, backend: KerberosCacheBackend) -> Self;

    /// Set credential cache path
    pub fn with_cache_path(self, path: impl Into<PathBuf>) -> Self;

    /// Enable or disable credential caching
    pub fn with_caching(self, enable: bool) -> Self;

    /// Enable channel bindings with data
    pub fn with_channel_bindings(self, data: Vec<u8>) -> Self;

    /// Require channel bindings for enhanced security
    pub fn require_channel_bindings(self, require: bool) -> Self;
}
```

**Example:**
```rust
let config = KerberosConfig::new("CORP.EXAMPLE.COM")
    .with_spn("host/server.example.com")
    .with_cache_backend(KerberosCacheBackend::File)
    .with_cache_path("/tmp/my_krb_cache")
    .with_caching(true)
    .require_channel_bindings(false);
```

## Cache Backends

### `KerberosCacheBackend`

Available credential cache storage backends.

```rust
#[derive(Debug, Clone, Copy)]
pub enum KerberosCacheBackend {
    /// FILE backend - MIT Kerberos ccache format
    File,
    /// Memory backend - In-memory cache (not persistent)
    Memory,
    /// KCM backend - Kerberos Credential Manager daemon
    Kcm,
    /// Keyring backend - Linux kernel keyring
    Keyring,
}
```

### Backend Characteristics

| Backend   | Persistent | Security | Performance | Use Case                  |
|-----------|------------|----------|-------------|---------------------------|
| `File`    | ✅ Yes     | Standard | Fast        | Default, single-user apps |
| `Memory`  | ❌ No       | High     | Fastest     | Short-lived processes     |
| `Kcm`     | ✅ Yes     | High     | Good        | Multi-user systems        |
| `Keyring` | ✅ Yes     | Highest  | Good        | Security-critical apps    |

**Example:**
```rust
// Persistent file cache
let config = KerberosConfig::new("DOMAIN")
    .with_cache_backend(KerberosCacheBackend::File);

// Ephemeral memory cache
let config = KerberosConfig::new("DOMAIN")
    .with_cache_backend(KerberosCacheBackend::Memory);

// Secure kernel keyring (Linux only)
let config = KerberosConfig::new("DOMAIN")
    .with_cache_backend(KerberosCacheBackend::Keyring);
```

## Channel Bindings

### `KerberosClient::extract_channel_bindings_from_cert`

Extract channel binding data from TLS certificate.

```rust
impl KerberosClient {
    /// Extract TLS channel bindings from server certificate
    /// Returns binding data for use with channel binding configuration
    #[cfg(feature = "kerberos")]
    pub fn extract_channel_bindings_from_cert(
        server_cert: &[u8]
    ) -> Option<Vec<u8>>;
}
```

**Example:**
```rust
// During TLS connection establishment
let server_cert = get_server_certificate(); // Your TLS code
let bindings = KerberosClient::extract_channel_bindings_from_cert(&server_cert);

if let Some(binding_data) = bindings {
    let config = KerberosConfig::new("DOMAIN")
        .with_channel_bindings(binding_data)
        .require_channel_bindings(true);
}
```

## WMI Session

### `WmiSession`

Main entry point for WMI operations.

```rust
pub struct WmiSession {
    // Internal fields
}

impl WmiSession {
    /// Create new session with NTLM authentication
    pub fn new(
        host: &str,
        username: Option<&str>,
        password: Option<&str>,
        domain: Option<&str>,
    ) -> Result<Self, WmiError>;

    /// Create session with Kerberos (using config)
    pub fn with_kerberos(
        host: &str,
        config: KerberosConfig,
        creds: Credentials,
    ) -> Result<Self, WmiError>;

    /// Open WMI namespace
    pub fn open_namespace(&mut self, namespace: &str) -> Result<(), WmiError>;

    /// Execute WQL query
    pub fn exec_query(&mut self, query: &str) -> Result<Vec<WmiObject>, WmiError>;
}
```

**Example:**
```rust
// NTLM authentication
let mut session = WmiSession::new(
    "192.168.1.100",
    Some("admin"),
    Some("password"),
    Some("DOMAIN"),
)?;

// Kerberos with caching
let config = KerberosConfig::new("DOMAIN.COM")
    .with_cache_backend(KerberosCacheBackend::File)
    .with_caching(true);

let creds = Credentials::new(
    "admin".to_string(),
    "password".to_string(),
    "DOMAIN.COM".to_string(),
    "WORKSTATION".to_string(),
);

let mut session = WmiSession::with_kerberos("server.domain.com", config, creds)?;

// Execute query
session.open_namespace("root\\CimV2")?;
let results = session.exec_query("SELECT * FROM Win32_Process")?;
```

## Error Types

### `AuthError`

Authentication-related errors.

```rust
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("NTLM unsupported")]
    Ntlm,
    #[error("Invalid credentials")]
    Creds,
    #[error("Type2 message invalid")]
    InvalidType2,
}
```

### `KerberosError`

Kerberos-specific errors.

```rust
#[derive(Error, Debug)]
pub enum KerberosError {
    #[error("SPN resolution failed: {0}")]
    SpnResolution(String),
    #[error("Invalid authentication state")]
    InvalidState,
    #[error("Authentication failed: {0}")]
    AuthFailure(String),
}
```

### `WmiError`

WMI operation errors.

```rust
#[derive(Error, Debug)]
pub enum WmiError {
    #[error("Connection failed")]
    Connect,
    #[error("Query failed: {0}")]
    Query(String),
    #[error("Authentication error: {0}")]
    Auth(#[from] AuthError),
    #[error("Transport error: {0}")]
    Transport(String),
}
```

## Environment Variables

### `KRB5CCNAME`

Controls credential cache location.

```bash
# Use custom file cache
export KRB5CCNAME=FILE:/tmp/my_cache

# Use memory cache
export KRB5CCNAME=MEMORY:

# Use KCM daemon
export KRB5CCNAME=KCM:

# Use kernel keyring
export KRB5CCNAME=KEYRING:persistent
```

### `LINUX_WMI_PORT`

Bypass DCOM activation with direct port.

```bash
# Use specific WMI port
export LINUX_WMI_PORT=49664
cargo run --example test_connect -- server.example.com
```

## Feature Flags

```toml
[features]
default = ["kerberos"]
kerberos = ["kerbsec"]  # Enable Kerberos support
async = ["tokio"]       # Async runtime support
```

## Best Practices

### 1. Credential Management
```rust
// Credentials are automatically protected
let creds = Credentials::new(...);
// No manual cleanup needed - automatic zeroization on drop
```

### 2. Cache Configuration
```rust
// Long-running service: use persistent cache
let config = KerberosConfig::new("DOMAIN")
    .with_cache_backend(KerberosCacheBackend::File);

// Short script: use memory cache
let config = KerberosConfig::new("DOMAIN")
    .with_cache_backend(KerberosCacheBackend::Memory);
```

### 3. Security
```rust
// Enable channel bindings when using TLS
let config = KerberosConfig::new("DOMAIN")
    .with_channel_bindings(tls_binding_data)
    .require_channel_bindings(true);
```

### 4. Error Handling
```rust
match session.exec_query(query) {
    Ok(results) => process_results(results),
    Err(WmiError::Auth(e)) => handle_auth_error(e),
    Err(WmiError::Transport(e)) => handle_network_error(e),
    Err(e) => log::error!("Query failed: {}", e),
}
```

---

*For complete examples, see the `examples/` directory in the repository.*
