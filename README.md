# Linux WMI Client

A native Rust implementation of the Windows Management Instrumentation (WMI) protocol stack for Linux systems. Query Windows hosts directly without intermediaries using authenticated DCOM/RPC connections.

## Features

- **Full Protocol Stack**: Complete implementation of DCOM activation, ORPC, NDR marshaling, and WMI protocols
- **Secure Authentication**: NTLMv2 with signing (HMAC-MD5) and sealing (RC4 encryption)
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

## Usage

### Library Usage

```rust
use linux_wmi::{WmiSession, Credentials};

// Create authenticated session
let mut session = WmiSession::new(
    "192.168.1.100",
    Some("Administrator"),
    Some("Password123"),
    Some("DOMAIN"),
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
```

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

- [Protocol Completion Status](docs/PROTOCOL-COMPLETION.md) - Implementation progress
- [Architecture](docs/ARCHITECTURE.md) - System design
- [DCOM Activation](docs/DCOM_ACTIVATION.md) - Activation flow
- [Implementation Strategy](docs/IMPLEMENTATION-STRATEGY.md) - Development phases
- [Requirements Specification](docs/REQUIREMENTS-SPECIFICATION.md) - Project goals

## Contributing

Contributions are welcome! Please ensure:
- All tests pass (`cargo test`)
- No clippy warnings (`cargo clippy`)
- Code is formatted (`cargo fmt`)

## Security Considerations

- Credentials are zeroed on drop using `zeroize`
- NTLM session keys are never logged
- Signing/sealing prevents tampering and eavesdropping
- Sequence numbers prevent replay attacks

## Limitations

- Synchronous I/O (async planned for Phase 5)
- Limited to common WMI classes (extensible)
- No Kerberos support (NTLMv2 only)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Microsoft for protocol specifications
- Rust community for excellent libraries (md5, hex, serde, etc.)
- Impacket project for protocol insights
