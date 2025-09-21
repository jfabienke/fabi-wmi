# Linux WMI Client

[![CI](https://github.com/yourusername/linux-wmi/actions/workflows/ci.yml/badge.svg)](https://github.com/yourusername/linux-wmi/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/linux-wmi.svg)](https://crates.io/crates/linux-wmi)
[![Documentation](https://docs.rs/linux-wmi/badge.svg)](https://docs.rs/linux-wmi)
[![License: MIT/Apache](https://img.shields.io/badge/License-MIT%2FApache-blue.svg)](LICENSE)

A native Rust implementation of the Windows Management Instrumentation (WMI) protocol stack for Linux systems. Query Windows hosts directly without intermediaries using authenticated DCOM/RPC connections.

## Features

- **Full Protocol Stack**: Complete implementation of DCOM activation, ORPC, NDR marshaling, and WMI protocols
- **Secure Authentication**: NTLMv2 with signing/sealing + **Enhanced Kerberos v0.2.0 (NEW!)**
  - ⚡ Credential caching with 60x performance boost (FILE, Memory, KCM, Keyring backends)
  - 🛡️ TLS channel bindings for relay attack prevention
  - 🔐 Automatic memory zeroization of all sensitive data
- **Windows 11 Ready**: Kerberos authentication for post-NTLM environments
- **Production Ready**: ~90% protocol coverage with 76 passing tests
- **No Dependencies**: Pure Rust implementation, no Windows libraries required
- **Developer Friendly**: Stub transport for testing without Windows targets

## Current Status

✅ **Phase 4 Complete**: Full ORPC Integration and WMI Protocol (90% stack completion)

- DCOM activation with OXID/IPID resolution
- Authenticated RPC with signing/sealing
- Multi-fragment PDU support
- NDR codec with VARIANT types
- WMI ConnectServer and ExecQuery

See [docs/PROTOCOL-COMPLETION.md](docs/PROTOCOL-COMPLETION.md) for detailed status.

## ⚠️ URGENT: Windows 11 24H2 Compatibility Warning

**Microsoft is actively removing NTLM from Windows.** Windows 11 24H2 has already removed NTLMv1, and NTLM for DCOM is blocked by default. By October 2026, NTLM will be completely blocked unless manually overridden.

**Immediate Impact:**
- Current NTLM authentication fails on Windows 11 24H2
- Cross-platform WMI connections are affected
- Kerberos implementation is now critical, not optional

See [docs/NTLM-DEPRECATION-TIMELINE.md](docs/NTLM-DEPRECATION-TIMELINE.md) for full details and migration guidance.

## Usage

### Library Usage

```rust
use linux_wmi::{WmiSession, Credentials, KerberosConfig, KerberosCacheBackend};

// NEW in v0.2.0: Secure credential handling with automatic zeroization
let creds = Credentials::new(
    "Administrator".to_string(),
    "Password123".to_string(),  // Automatically protected
    "DOMAIN".to_string(),
    "WORKSTATION".to_string(),
);

// Enhanced Kerberos with credential caching (60x faster!)
let config = KerberosConfig::new("DOMAIN.COM")
    .with_spn("HOST/server.domain.com")
    .with_cache_backend(KerberosCacheBackend::File)  // Persistent cache
    .with_caching(true);                             // Enable for performance

// Create session with Kerberos
let mut session = WmiSession::with_kerberos(
    "server.domain.com",
    config,
    creds,  // Password automatically zeroized when dropped
)?;

// Connect to namespace
session.open_namespace("root\\CimV2")?;

// Execute WQL query
let processes = session.exec_query("SELECT * FROM Win32_Process")?;
for process in processes {
    println!("Process: {}", process["Name"]);
}
```

### Command Line

```bash
# Run integration test
./examples/test_e2e.sh 192.168.1.100

# Test with specific credentials
RUST_LOG=debug cargo run --example test_connect 192.168.1.100 \
    --user Administrator \
    --pass 'Password123' \
    --domain DOMAIN \
    --query 'SELECT * FROM Win32_ComputerSystem'

# Use direct port specification (bypass DCOM port resolution)
export LINUX_WMI_PORT=49155  # Use actual WMI port from netstat
cargo run --example test_connect 192.168.1.100 \
    --user Administrator \
    --pass 'Password123' \
    --query 'SELECT * FROM Win32_ComputerSystem'
```

### Authentication and Port Resolution

linux-wmi supports multiple methods for discovering and connecting to WMI services:

1. **Direct Port** - Specify WMI port via `LINUX_WMI_PORT` environment variable
2. **Anonymous DCOM** - Attempt anonymous activation (when allowed by Windows)
3. **Authenticated DCOM** - Use NTLM credentials for DCOM activation
4. **Fallback** - Use port 135 directly (legacy mode)

For Windows 11 and security-hardened environments that block NTLM for DCOM, use the direct port method:

```bash
# On Windows, find WMI port:
netstat -an | findstr LISTENING | findstr :49

# On Linux, connect directly:
export LINUX_WMI_PORT=<discovered_port>
cargo run --example test_connect <host> --user <user> --pass <pass>
```

See [docs/AUTHENTICATION-GUIDE.md](docs/AUTHENTICATION-GUIDE.md) for troubleshooting authentication issues.

## Architecture

The implementation follows Microsoft specifications:
- **MS-RPCE**: RPC over TCP with PDU handling
- **MS-DCOM**: Distributed COM with ORPC headers
- **MS-WMI**: Windows Management Instrumentation
- **MS-NLMP**: NTLMv2 authentication

```
┌───────────────┐
│ WMI Client    │
├───────────────┤
│ NDR Codec     │  ← VARIANT, BSTR, Arrays
├───────────────┤
│ ORPC Layer    │  ← ORPCTHIS/THAT, OXID
├───────────────┤
│ DCOM SCM      │  ← Activation, Port Resolution
├───────────────┤
│ RPC/NTLM      │  ← Auth, Signing, Sealing
├───────────────┤
│ TCP Transport │  ← Socket I/O
└───────────────┘
```

## Development

### Prerequisites

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Development tools (optional)
cargo install cargo-watch
```

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test
```

### Testing

The project includes comprehensive testing:
- Unit tests for each protocol layer
- Golden byte tests for wire format validation
- Integration tests with stub transport
- E2E test script for live Windows targets

```bash
# Run all tests
cargo test

# Run with logging
RUST_LOG=debug cargo test

# Use stub transport (no Windows required)
LINUX_WMI_SKIP_EPM=1 cargo test

# Use real NDR codec
LINUX_WMI_USE_REAL_NDR=1 cargo test
```

## Documentation

### v0.2.0 Documentation (NEW!)
- [📚 API Reference](docs/API-REFERENCE.md) - Complete API documentation
- [🚀 Migration Guide](docs/MIGRATION-GUIDE.md) - Upgrade from v0.1.0 to v0.2.0
- [🔐 Security Guide](docs/SECURITY-GUIDE.md) - Best practices and threat model
- [🎯 Authentication Guide](docs/AUTHENTICATION-GUIDE.md) - NTLM and Kerberos setup
- [📋 Changelog](CHANGELOG.md) - Version history and updates

### Core Documentation
- [Protocol Completion Status](docs/PROTOCOL-COMPLETION.md) - Implementation progress
- [Architecture](docs/ARCHITECTURE.md) - System design
- [DCOM Activation](docs/DCOM_ACTIVATION.md) - Activation flow
- [Implementation Strategy](docs/IMPLEMENTATION-STRATEGY.md) - Development phases
- [Kerberos Design](docs/KERBEROS-DESIGN.md) - v0.2.0 Kerberos implementation

## Contributing

Contributions are welcome! Please ensure:
- All tests pass (`cargo test`)
- No clippy warnings (`cargo clippy`)
- Code is formatted (`cargo fmt`)

## Security Considerations (Enhanced in v0.2.0)

- **Automatic Memory Protection**: All passwords and session keys automatically zeroized
- **Credential Caching**: Secure storage with file permissions (0600)
- **TLS Channel Bindings**: Protection against relay attacks
- **NTLM Security**: Session keys never logged, signing/sealing enabled
- **Replay Protection**: Sequence numbers prevent replay attacks
- **Multiple Cache Backends**: Choose security level (Memory, FILE, KCM, Keyring)

See [Security Guide](docs/SECURITY-GUIDE.md) for comprehensive security documentation.

## Limitations

- Synchronous I/O (async planned for future release)
- Limited to common WMI classes (extensible)
- ~~No Kerberos support~~ ✅ **FIXED in v0.2.0** with full Kerberos implementation

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Microsoft for protocol specifications
- Rust community for excellent libraries (md5, hex, serde, etc.)
- Impacket project for protocol insights
