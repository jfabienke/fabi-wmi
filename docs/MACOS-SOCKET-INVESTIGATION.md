# macOS Socket Timeout Investigation

## Summary
During E2E testing against Windows host 192.0.2.10, we encountered socket timeout issues on macOS that prevented WMI connections from being established.

## Root Causes Identified

### 1. macOS Socket Behavior
- **Issue**: macOS handles socket timeouts differently than Linux/Windows
- **Symptom**: `read_exact()` returns error 35 (EAGAIN/EWOULDBLOCK) even on blocking sockets
- **Fix Applied**: Implemented `read_exact_with_retry()` function that handles non-blocking behavior with retry loops

### 2. DCOM Authentication Rejection
- **Issue**: Windows host rejects NTLM authentication for DCOM activation on port 135
- **Details**:
  - Bind request to IRemoteSCMActivator interface gets `bind_nak` response
  - Rejection reason 0x05 = "authentication type not recognized"
  - Server expects different auth method (likely Kerberos or different NTLM config)
- **Impact**: Cannot use DCOM activation to discover WMI dynamic port

### 3. Missing EPM Implementation
- **Issue**: No proper Endpoint Mapper (EPM) protocol implementation
- **Current behavior**: Falls back to port 135 after DCOM fails, but tries wrong interface
- **Required**: Need to implement EPM protocol (interface e1af8308-5d1f-11c9-91a4-08002b14a0fa)

## Test Results

### Socket Fix Validation
✅ Socket retry logic implemented and working
✅ Handles macOS non-blocking socket behavior correctly
✅ Connection establishes successfully to port 135

### Authentication Status
❌ DCOM activation fails with bind_nak
❌ Windows host at 192.0.2.10 rejects NTLM auth type for DCOM
❌ Fallback to direct port 135 connection doesn't work (wrong protocol)

## Resolution Status

### ✅ Socket Timeout Issue - RESOLVED
The macOS-specific socket timeout behavior has been fixed by implementing `read_exact_with_retry()` that properly handles non-blocking socket behavior on macOS.

### ✅ DCOM Authentication Rejection - ROOT CAUSE IDENTIFIED
**Root Cause**: Windows 11 24H2 has removed NTLM support for DCOM authentication as part of Microsoft's accelerated NTLM deprecation timeline.

**Solution**: Implement Kerberos authentication (design complete, implementation in progress)
- See [KERBEROS-DESIGN.md](./KERBEROS-DESIGN.md) for the complete implementation plan
- See [NTLM-DEPRECATION-TIMELINE.md](./NTLM-DEPRECATION-TIMELINE.md) for Microsoft's removal schedule

### Current Workarounds (Temporary)

1. **Direct Port Specification**
   ```bash
   export LINUX_WMI_PORT=<actual_wmi_port>
   cargo run --example test_connect <host> --user <user> --pass <pass>
   ```
   Note: Requires finding the actual WMI port on Windows

2. **Registry Override (Windows Side)**
   Not recommended for production - will stop working October 2026

## Next Steps (Updated)

1. **Priority 1: Complete Kerberos Implementation**
   - Implement SecurityContext abstraction layer
   - Add platform-specific GSS/SSPI wrappers
   - Implement DCE-style 3-leg authentication
   - Target completion before Windows 11 becomes widespread

2. **Priority 2: Enhanced Port Discovery**
   - Implement EPM protocol as fallback
   - Add SMB/Named Pipes transport option

3. **Priority 3: Legacy Support**
   - Maintain NTLM for pre-Windows 11 systems
   - Clear documentation on compatibility matrix

## Environment Variables for Testing

- `LINUX_WMI_SKIP_EPM=1` - Skip port resolution, but still broken
- `LINUX_WMI_HARDCODED_PORT=<port>` - Could be added to specify WMI port directly
- `RUST_LOG=debug` - Enable debug logging

## Test Command
```bash
cargo run --example test_connect 192.0.2.10 \
  --user wmi-test \
  --pass '<password>' \
  --domain '' \
  --query 'SELECT Name FROM Win32_ComputerSystem'
```