# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust implementation of a Windows Management Instrumentation (WMI) client for Linux/Unix systems. The project enables querying Windows hosts from non-Windows systems using the MS-RPC/DCOM/WMI protocols over TCP/IP, providing a FFI-compatible library for integration with existing C#/.NET applications.

## Architecture

The project implements a layered protocol stack:
1. **Transport Layer** (`transport.rs`) - TCP socket management, MS-EPMR endpoint mapper resolution
2. **Authentication** (`auth.rs`) - NTLMv2 authentication with session key management
3. **RPC Layer** (`dcom.rs`) - MS-RPCE protocol handling, PDU construction/parsing
4. **NDR Codec** (`ndr.rs`) - Network Data Representation marshaling/unmarshaling
5. **WMI Layer** (`wmi.rs`, `lib.rs`) - IWbemServices interface, query execution, FFI exports

Key protocols implemented:
- MS-EPMR (Endpoint Mapper)
- MS-RPCE (RPC Extensions)
- MS-DCOM (Distributed COM)
- MS-WMI (Windows Management Instrumentation)
- MS-NLMP (NTLM Authentication)

## Development Commands

### Build
```bash
cargo build                    # Debug build
cargo build --release          # Release build
```

### Test
```bash
cargo test                     # Run all tests
cargo test --lib               # Library tests only
cargo test --test integration  # Integration tests
RUST_LOG=linux_wmi=debug cargo test  # With debug logging
```

### Run Examples
```bash
# Test connection to Windows host (with EPM resolution)
cargo run --example test_connect <host> --user <user> --pass <password> --domain <domain>

# Skip EPM lookup (for testing)
LINUX_WMI_SKIP_EPM=1 cargo run --example test_connect <host>

# End-to-end test script
./examples/test_e2e.sh <host> <user> <pass> <domain> <query>
```

### Debugging
```bash
# Enable structured debug logging
RUST_LOG=linux_wmi=debug cargo run --example test_connect <host> | jq '.'

# Format code
cargo fmt

# Check for issues
cargo clippy
```

## Key Implementation Details

### Current Implementation Status
- **Phase 1** (✅): EPM resolution - Dynamic port lookup via MS-EPMR TowerInquiry
- **Phase 2** (~): RPC Bind & NTLM Auth - Authenticated bind flow with NTLMv2
- **Phase 3** ( ): NDR Codec & ExecQuery - WQL query execution
- **Phase 4** ( ): ExecMethod & FFI Polish - Method invocation, error handling
- **Phase 5** ( ): Testing & Release - Comprehensive tests, OS fallbacks

### Test Environment Variables
- `LINUX_WMI_SKIP_EPM=1` - Skip EPM lookup and bind (uses stub transport)
- `RUST_LOG=linux_wmi=debug` - Enable debug logging with tracing

### FFI Interface
The library exposes C-compatible functions in `lib.rs`:
- `wmi_connect()` - Create authenticated WMI session
- `wmi_query()` - Execute WQL queries
- `wmi_free_*()` - Memory cleanup functions

### Testing Strategy
- Unit tests use fixture data to avoid network dependencies
- Integration tests require `LINUX_WMI_SKIP_EPM=1` unless testing against real host
- E2E testing via `test_e2e.sh` script validates against live Windows hosts

### Important Constants & Verification
See `docs/VERIFIED_CONSTANTS.md` for verified protocol constants (UUIDs, opcodes, tower IDs) cross-referenced against MS specifications and Wireshark captures.

## Common Tasks

### Adding New WMI Query Support
1. Define NDR encoding in `ndr.rs` for query parameters
2. Implement marshaling in relevant opnum handler
3. Add JSON deserialization for results
4. Update FFI exports if needed

### Debugging Network Issues
1. Enable debug logging: `RUST_LOG=linux_wmi=debug`
2. Check firewall rules on Windows host (TCP 135, dynamic RPC ports)
3. Verify user has "Distributed COM Users" and WMI namespace permissions
4. Capture Wireshark traces with filter: `dcerpc`

### Testing Against Windows Host
1. Configure Windows target:
   - Enable DCOM
   - Add test user to "Distributed COM Users" group
   - Grant WMI namespace permissions (root\CIMV2)
   - Allow RPC through firewall
2. Run E2E test: `./examples/test_e2e.sh <host> <user> <pass>`