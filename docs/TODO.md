# linux-wmi TODO List

This document consolidates all TODO items from the codebase for better tracking and visibility.

## Kerberos Enhancements

### ✅ GSS_C_DCE_STYLE Flag - RESOLVED
- **Status**: ✅ Resolved with kerbsec v0.2.0+
- **Location**: src/kerberos_adapter.rs
- **Description**: Critical for proper DCE/RPC sequence number handling.
- **Resolution**: Now runtime-configurable via `enable_dce_style` configuration option.
- **Impact**: Full DCE/RPC protocol compliance achieved

### ✅ Credentials Delegation - RESOLVED
- **Status**: ✅ Resolved with kerbsec v0.2.0+
- **Location**: src/kerberos_adapter.rs
- **Description**: Support for GSS_C_DELEG_FLAG for multi-hop scenarios (S4U2Self/S4U2Proxy).
- **Resolution**: Now runtime-configurable via `enable_delegation` configuration option.
- **Impact**: Full support for delegated authentication scenarios
- **Security Note**: Disabled by default for security. Only enable for trusted servers!

## Examples

### full_wmi_query.rs
- **Status**: Incomplete
- **Location**: examples/full_wmi_query.rs
- **Description**: Currently contains placeholder comment "TODO: In next phase, actually execute a WMI query"
- **Action**: Implement actual WMI query execution using async API

## Async API Completion

### Async WmiSession
- **Status**: Not started
- **Description**: Need async wrapper for WmiSession with async_new() and async exec_query()
- **Impact**: Enable fully async WMI operations

### Kerberos Async Integration
- **Status**: Partially implemented
- **Description**: connect_with_kerberos() exists but needs to be truly async (currently may block)
- **Impact**: Non-blocking Kerberos authentication
- **Note**: This is a transport-layer issue, not related to kerbsec

## Future Enhancements

### EPM Protocol
- **Status**: Research phase
- **Description**: Proper Endpoint Mapper implementation for discovering services
- **Impact**: Dynamic service discovery

### Named Pipes over SMB
- **Status**: Not planned
- **Description**: Alternative transport via `\\pipe\\WBEM`
- **Impact**: Alternative connection method

### Certificate Authentication
- **Status**: Not planned
- **Description**: PKU2U for workgroup scenarios
- **Impact**: Non-domain authentication

## Completed Items
Items that have been completed should be moved here with completion date:
- ✅ SPNEGO wrapping for NTLMv2 (2024-01)
- ✅ Basic async transport implementation (2024-01)
- ✅ GSS-API IOV Support - Resolved with kerbsec v0.2.0 `iov` feature (2024-01)
- ✅ Channel Bindings - Implemented using kerbsec's `channel-bindings` feature (2024-01)
- ✅ wrap_size_limit Calculation - Provided by kerbsec's IOV implementation (2024-01)
- ✅ Native Credential Caching - Using kerbsec's `ccache` feature instead of kinit (2024-01)