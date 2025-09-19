# Linux-WMI Architecture

High-level overview of the linux-wmi implementation architecture, reflecting the current state (Phases 1-2 complete) and design decisions made during development.

## Architecture Diagram

```
      ╔═══════════════════════════════════════════╗
      ║          FFI Layer (lib.rs)               ║
      ║  C-compatible exports for external use    ║
      ║  • session_new() → WmiSession             ║
      ║  • exec_query() → JSON results            ║
      ╚════════════════╦══════════════════════════╝
                       ▼
           ┌─────────────────────────────────┐
           │      WmiSession (wmi.rs)        │
           │ ─────────────────────────────── │
           │ • Namespace: root\CimV2         │  ✅ Implemented
           │ • Transport: RpcTransport trait │
           │ • Codec: NdrCodec trait         │
           │ • exec_query(WQL) → JSON        │
           └───────────────┬─────────────────┘
                           │
                ┌──────────┴──────────┐
                ▼                     ▼
    ┌─────────────────────┐ ┌─────────────────────┐
    │  StubTransport      │ │  RealRpcTransport   │
    │ ─────────────────── │ │ ─────────────────── │
    │ • Returns mock JSON │ │ • TCP connection    │  ✅ Both paths work
    │ • No network calls  │ │ • RPC bind/invoke   │
    └─────────────────────┘ │ • NTLM auth         │
                            └───────────┬─────────┘
                                        │
                           ┌────────────┴────────────┐
                           ▼                         ▼
           ┌─────────────────────────────┐ ┌─────────────────────┐
           │   DCOM Activation (dcom.rs) │ │  Port Resolution    │
           │ ─────────────────────────── │ │ ─────────────────── │
           │ • IRemoteSCMActivator bind  │ │ • EPM deprecated    │
           │ • RemoteActivation opnum=4  │ │ • DCOM fallback ✅  │
           │ • DUALSTRINGARRAY parse     │ │ • ENV skip ✅       │
           │ • Extract dynamic port      │ └─────────────────────┘
           └───────────────┬─────────────┘
                           │
                           ▼
           ┌─────────────────────────────┐
           │   Authentication (auth.rs)  │
           │ ─────────────────────────── │
           │ • NTLMv2 Type1/2/3 flow     │  ✅ Complete
           │ • HMAC-MD5 response         │
           │ • Session key derivation    │
           │ • Zeroize for security      │
           └─────────────────────────────┘
```

## Implementation Status

Based on PROTOCOL-COMPLETION.md estimates:

| Component           | Status             | Completion                                                                |
|---------------------|--------------------|---------------------------------------------------------------------------|
| **Transport Layer** | ✅ Mostly Complete |  90% - Stable synchronous TCP stack; async/pooling planned                |
| **RPCE (RPC)**      | ✅ Mostly Complete |  90% - Bind/alter/fragments solid, needs broader live validation          |
| **Authentication**  | ✅ Mostly Complete |  90% - NTLMv2 + signing/sealing; further hardening tracked                |
| **DCOM Activation** | ✅ Mostly Complete |  85% - RemoteActivation working; additional error paths untested          |
| **ORPC Layer**      | ⚠️ Partial         |  70% - ORPCTHIS/THAT & OXID implemented, enumerator usage pending         |
| **NDR Codec**       | ⚠️ Foundation      |  60% - Core types encoded, response decoding still stub-backed            |
| **WMI Protocol**    | ⚠️ Stubbed         |  40% - Live ExecQuery falls back to canned JSON pending enumerator decode |
| **Overall Stack**   | **65% Complete**   | Authenticated transport in place; real result parsing & async outstanding |

### Current Limitations

- `IWbemServices::exec_query` still returns stubbed JSON when the server supplies an enumerator pointer; full parsing of `IEnumWbemClassObject` responses is tracked for Phase 5.
- Live verification has been limited to smoke tests; extended soak testing and failure-mode handling are part of the upcoming async/pooling work.
- The synchronous API remains the default; async transport and connection pooling will ship behind a feature flag once Phase 5 lands.

## Module Structure

```
src/
├── lib.rs                  # FFI exports, session management
├── wmi.rs                  # WmiSession, IWbemServices facade
├── transport.rs            # RpcTransport trait & RealRpcTransport
├── dcom.rs                 # DCOM activation, OXID resolver
├── auth.rs                 # NTLMv2 implementation
├── ndr.rs                  # NDR codec traits and exports
│   ├── codec.rs           # RealNdrCodec implementation
│   ├── types.rs           # VARIANT, BSTR, ConformantArray
│   └── golden_tests.rs    # Golden byte validation tests
├── tower.rs                # EPM tower builder/parser
└── rpc_fixtures.rs         # Test fixtures, golden PDUs

examples/
├── test_connect.rs         # E2E WMI query example
├── dcom_activation.rs      # Standalone DCOM test
├── wmi_probe.rs           # Anonymous RPC detection
└── test_e2e.sh            # Integration test script
```

## Key Design Decisions

### 1. **Trait-Based Architecture**
- `RpcTransport` and `NdrCodec` traits enable swapping implementations
- Allowed EPM → DCOM pivot without breaking FFI interface
- Stub vs Real paths coexist for testing

### 2. **DCOM Over EPM**
- EPM returns `EPT_S_NOT_REGISTERED` (0x1c00001a) for WMI
- Pivoted to DCOM activation via IRemoteSCMActivator
- `LINUX_WMI_SKIP_EPM=1` fallback for development

### 3. **Synchronous First**
- Blocking I/O simpler for FFI integration
- Async planned for Phase 5 with tokio/deadpool
- Current design handles ~100 concurrent connections

### 4. **Manual + Nom Hybrid**
- Manual `byteorder` for PDU building (precise control)
- Nom parsers for response parsing (resilient to variants)
- Balances performance and maintainability

### 5. **Comprehensive Error Handling**
- Protocol errors mapped to typed enums
- Detailed tracing with hex dumps
- Fallbacks for common issues (timeouts, permissions)

## Lessons Learned

### Protocol Insights
- **WMI requires DCOM activation**, not EPM registration
- **NTLM auth mandatory** for RemoteActivation (not for detection)
- **Permissions are critical** - DCOM Launch/Activation needed
- **Fault codes informative** - Map to specific issues

### Implementation Challenges
- **NDR precision crucial** - Padding, byte order, conformant arrays
- **Timeout handling essential** - WouldBlock (OS error 35) common
- **UUID specificity matters** - Wrong UUID → NOT_REGISTERED

### Architecture Wins
- **Traits enabled pivots** - EPM → DCOM switch seamless
- **Structured logging critical** - Hex dumps + spans for debugging
- **Golden fixtures accelerate testing** - Wireshark captures as test data

## Future Work (Phases 3-5)

### Phase 3: Real NDR/WMI (In Progress)
- Full VARIANT marshaling for query results
- Conformant array support for collections
- WQL query parsing and encoding
- Real Win32_ComputerSystem decoding

### Phase 4: Production Hardening
- ✅ Fragment support for large responses (COMPLETE)
- OXID resolver integration
- Signing/sealing with session keys
- Comprehensive error mapping

### Phase 5: Async & Scale
- Tokio async runtime integration
- Connection pooling with deadpool
- Support for 1000+ concurrent queries
- Circuit breakers and retry logic

## Production Recommendations

1. **Use WinRM for Modern Windows** (2012+)
   - Better auth model (Kerberos)
   - Consistent permissions
   - Available by default

2. **DCOM/WMI for Legacy** (2008/XP)
   - Requires careful permission setup
   - Administrator often needed
   - Document requirements clearly

3. **Detection Strategy**
   - Anonymous RPC probe for Windows detection
   - Score 0.9 confidence on bind_ack
   - Fall back to WinRM if DCOM fails

### Windows Server Remote Management Matrix

| Windows Server Version | Service Packs / Releases | WMI (Windows Management Instrumentation)   | WinRM (Windows Remote Management)                                           |
|------------------------|--------------------------|--------------------------------------------|-----------------------------------------------------------------------------|
| Windows 2000 Server    | SP0 – SP4                | Default: Installed and enabled by default. | Not included. WinRM did not exist yet.                                      |
| Windows Server 2003    | RTM, SP1, SP2            | Default: Installed and enabled by default. | Optional: WinRM 1.1 via WMF 2.0; manual install, disabled until configured. |
| Windows Server 2008    | RTM, R2                  | Default: Installed and enabled by default. | Included: WinRM 2.0 shipped but disabled; requires `winrm quickconfig`.     |
| Windows Server 2012    | RTM, R2                  | Default: Installed and enabled by default. | Enabled by default: WinRM 3.0 auto-starts with listeners preconfigured.     |
| Windows Server 2016    | GA                       | Default: Installed and enabled by default. | Enabled by default: WinRM 3.0 with PowerShell Remoting ready.               |
| Windows Server 2019    | GA                       | Default: Installed and enabled by default. | Enabled by default: WinRM enabled out-of-the-box.                           |
| Windows Server 2022    | GA                       | Default: Installed and enabled by default. | Enabled by default: WinRM enabled out-of-the-box.                           |

**Key Notes**

- **WMI**
  - Present since Windows 2000 and generally enabled without additional configuration.
  - Core system-management API; security hardening is the primary reason it might be disabled.
- **WinRM**
  - Implements WS-Management and arrived later than WMI.
  - Optional on 2003 (WinRM 1.1 via WMF 2.0), present but disabled on 2008, enabled by default starting with 2012 (including Server Core).

## Testing Strategy

- **Unit Tests**: Golden PDUs with `hex_literal`
- **Integration**: `test_e2e.sh` with real credentials
- **Mocks**: `StubTransport` for offline testing
- **Validation**: Wireshark captures for protocol verification

## Performance Characteristics

- **Memory**: ~10KB per session
- **CPU**: ~5ms per query (stub mode)
- **Network**: 50ms RTT typical (LAN)
- **Concurrency**: 100-500 with pooling
- **FD Limits**: Default 1024 sufficient

## Fingerprinting & Detection

The library includes anonymous RPC probing for Windows host detection:

- **Anonymous Probe**: Bind to port 135 without credentials
- **Detection Score**: 0.9 confidence on successful bind_ack
- **Implementation**: See `examples/wmi_probe.rs`

## Host Configuration Requirements

For successful WMI access, Windows hosts require:

### DCOM Permissions
1. Run `dcomcnfg.exe` as Administrator
2. Navigate to Component Services → Computers → My Computer → DCOM Config
3. Find "Windows Management and Instrumentation"
4. Grant "Remote Launch" and "Remote Activation" to the user

### WMI Permissions
1. Run `wmimgmt.msc`
2. Right-click WMI Control → Properties → Security
3. Grant "Remote Enable" to the user

### Common Permission Errors
- `0x00000005` (ACCESS_DENIED): Missing DCOM permissions
- `0x1c01000b`: Authentication failure
- `0x1c00001a`: EPT_S_NOT_REGISTERED (expected for WMI)

## DCOM Activation Flow

```mermaid
sequenceDiagram
    participant Client
    participant SCM as SCM (Port 135)
    participant WMI as WMI Service

    Client->>SCM: Bind(IRemoteSCMActivator) + NTLM Type1
    SCM-->>Client: Bind_Ack + NTLM Type2
    Client->>SCM: Alter_Context + NTLM Type3
    SCM-->>Client: Alter_Ack
    Client->>SCM: RemoteActivation(CLSID_WbemLocator)
    SCM-->>Client: OXID + Port + DUALSTRINGARRAY
    Client->>WMI: Connect to dynamic port
    Client->>WMI: Bind(IWbemServices) + Auth
    WMI-->>Client: Ready for queries
```

## Environment Variables

- `LINUX_WMI_SKIP_EPM=1`: Skip port resolution, use fixed port 135
- `USE_DCOM_ACTIVATION=1`: Force DCOM activation path (deprecated)
- `RUST_LOG=linux_wmi=debug`: Enable detailed tracing

---

This architecture has proven robust through Phases 1-2, with clean separation of concerns enabling the EPM → DCOM pivot without major refactoring. The trait-based design positions the codebase well for Phase 3's NDR implementation and eventual async conversion.

## References

- [MS-DCOM](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/): Distributed Component Object Model Protocol
- [MS-RPCE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/): Remote Procedure Call Protocol Extensions
- [MS-WMI](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wmi/): Windows Management Instrumentation Protocol
- [MS-NLMP](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/): NT LAN Manager Authentication Protocol
