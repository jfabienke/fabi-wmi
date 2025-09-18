# DCOM Activation and DUALSTRINGARRAY Parsing

## Overview

WMI services cannot be resolved via the traditional RPC Endpoint Mapper (EPM). When requesting WMI endpoints via EPM, the server returns fault `EPT_S_NOT_REGISTERED` (0x1c00001a), indicating that WMI doesn't register its dynamic endpoints with EPM.

Instead, WMI requires DCOM activation through the `IRemoteSCMActivator` interface on port 135.

**Current Implementation Status (v0.2.0)**:
- ✅ EPM approach confirmed non-viable for WMI (returns 0x1c00001a)
- ✅ DCOM activation infrastructure complete with NTLM auth
- ✅ DUALSTRINGARRAY parsing implemented with nom, extracts port and OXID
- ✅ OXID resolver implementation (IObjectExporter::ResolveOxid)
- ✅ ORPCTHIS/ORPCTHAT headers with extension support
- ✅ Causality ID tracking in transport layer
- ⚠️ Full activation requires Windows-side DCOM permissions
- ✅ Fallback: `LINUX_WMI_SKIP_EPM=1` uses fixed port 135 for development

## Implementation

### IRemoteSCMActivator::RemoteActivation

The RemoteActivation method (opnum=4) activates a DCOM object and returns binding information including the dynamic port.

**Interface Details:**
- UUID: `{000001A0-0000-0000-C000-000000000046}`
- Port: 135 (SCM/DCOM activator)
- Method: RemoteActivation (opnum=4)

**Required CLSIDs for WMI:**
- CLSID_WbemLocator: `{4590F811-1D3A-11D0-891F-00AA004B2E24}`
- IID_IWbemLocator: `{dc12a687-737f-11cf-884d-00aa004b2e24}`

### Request Structure

```rust
// ORPCTHIS header (required for all DCOM calls)
struct ORPCTHIS {
    version: u32,        // 0x00000001 (COM version 5.1)
    flags: u32,          // 0x00000000
    reserved1: u32,      // 0x00000000
    causality_id: [u8; 16], // Tracking GUID (can be zeros)
    extensions: u32,     // 0x00000000 (no extensions)
}

// RemoteActivation parameters
struct RemoteActivationRequest {
    clsid: [u8; 16],     // CLSID_WbemLocator
    object_name: Option<String>, // null
    object_storage: Option<Vec<u8>>, // null
    client_imp_level: u32, // 2 (RPC_C_IMP_LEVEL_IDENTIFY)
    mode: u32,           // 0
    interfaces: Vec<[u8; 16]>, // [IID_IWbemLocator]
    requested_protseqs: Vec<u16>, // [0x07] for ncacn_ip_tcp
}
```

### Response Structure

The response contains:
1. ORPCTHAT header (DCOM response header)
2. HRESULT status
3. OXID (Object Exporter ID)
4. Binding information in a DUALSTRINGARRAY

### DUALSTRINGARRAY Parsing

The DUALSTRINGARRAY (MS-DCOM §2.2.4) contains string and security binding information:

```rust
struct DUALSTRINGARRAY {
    string_binding_size: u16,   // Size of string bindings in u16 units
    security_binding_size: u16, // Size of security bindings in u16 units
    string_bindings: Vec<u16>,  // Tower IDs and addresses
    security_bindings: Vec<u16>, // Security information
}
```

**String Binding Format for TCP/IP:**
- Tower ID: `0x07` (ncacn_ip_tcp)
- IP Address: 4 bytes (often in non-standard order)
- TCP Port: 2 bytes (little-endian)

### Port Extraction Algorithm

```rust
fn parse_dualstringarray_port(bindings: &[u8]) -> u16 {
    // 1. Look for TCP tower ID (0x07)
    for i in 0..bindings.len()/2 {
        let tower_id = u16::from_le_bytes([bindings[i*2], bindings[i*2+1]]);
        if tower_id == 0x07 {
            // 2. Skip past IP components to port
            // Port is typically 10-12 bytes after tower ID
            let port_offset = i + 5; // Adjust based on format
            if port_offset < bindings.len()/2 {
                let port = u16::from_le_bytes([
                    bindings[port_offset*2],
                    bindings[port_offset*2+1]
                ]);
                if port > 0 && port < 65535 {
                    return port;
                }
            }
        }
    }

    // 3. Fallback: scan for port-like values in dynamic range
    for i in 0..bindings.len()/2 {
        let port = u16::from_le_bytes([bindings[i*2], bindings[i*2+1]]);
        if port >= 49152 { // Dynamic port range
            return port;
        }
    }

    135 // Default fallback
}
```

## Authentication Requirements

RemoteActivation requires proper DCOM permissions:
- Anonymous bind to IRemoteSCMActivator succeeds but is insufficient for activation
- RemoteActivation call requires authenticated user with DCOM permissions
- The implementation includes full NTLM authentication (Type1/2/3 handshake)

### Common Errors
- `0x00000005` (ACCESS_DENIED): User lacks DCOM Launch/Activation permissions
- `0x1c01000b`: NTLM authentication failure during alter_context
- `0x1c00001a` (EPT_S_NOT_REGISTERED): WMI not registered with EPM (expected)
- OS error 35 (WouldBlock): Network timeout during read operations

### Granting DCOM Permissions (Windows Host)
1. Run `dcomcnfg.exe` as Administrator
2. Navigate: Component Services → Computers → My Computer → DCOM Config
3. Find "Windows Management and Instrumentation"
4. Right-click → Properties → Security tab
5. Grant "Remote Launch" and "Remote Activation" to the user
6. Also check WMI permissions in `wmimgmt.msc`

## Testing

Use the `dcom_activation` example to test:
```bash
cargo run --example dcom_activation <host> <user> <pass> <domain>
```

Environment variables:
- `SKIP_ALTER=1`: Skip alter_context (test with bind auth only)
- `USE_DCOM_ACTIVATION=1`: Use DCOM instead of EPM in main library

## Integration with WMI

Once the dynamic port is obtained:
1. Connect to the resolved port
2. Bind to IWbemServices with NTLM auth
3. Execute WQL queries via ExecQuery (opnum=9)

### Current Workaround
For development and testing without DCOM permissions:
```bash
# Use environment variable to skip port resolution
LINUX_WMI_SKIP_EPM=1 cargo run --example test_connect 192.0.2.10 \
  --user wmi-test --pass '<password>' --domain '' \
  --query 'SELECT * FROM Win32_ComputerSystem'
```

This bypasses both EPM and DCOM activation, using the fixed port 135 directly.

## Production Recommendations

1. **Modern Windows (2012+)**: Consider WinRM (port 5985) as the primary protocol
   - Better authentication model with Kerberos support
   - More consistent permissions model
   - Available by default on newer systems

2. **Legacy Windows (2008/XP)**: Use DCOM/WMI with proper permissions
   - Requires careful DCOM configuration
   - May need Administrator privileges
   - Document permission requirements clearly

3. **Detection**: Use anonymous RPC probe for Windows detection
   - Bind to EPM without auth returns bind_ack on Windows
   - Score 0.9 confidence for Windows presence
   - See `examples/wmi_probe.rs` for implementation

## References

- MS-DCOM §3.1.1.5.4.1: RemoteActivation method
- MS-DCOM §2.2.4: DUALSTRINGARRAY structure
- MS-WMI §1.9: WMI CLSIDs and IIDs
- MS-RPCE: RPC protocol specification
- MS-EPMR §2.2.3.4.1: EPT_S_NOT_REGISTERED fault code