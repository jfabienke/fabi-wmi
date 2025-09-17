High-level overview of the modules and how much code each area will likely require. This makes it easier to plan resources and see where the complexity lies.

# Proposed Architecture

```
      ╔═══════════════════════════════════════════╗
      ║           WMI Session API Design          ║
      ║                                           ║
      ║  FFI Entrypoints → WmiSession →           ║
      ║               IWbemServices/IWbemLocator  ║
      ╚════════════════════╦══════════════════════╝
                           ▼
           ┌─────────────────────────────────┐
           │      IWbemServices Facade       │
           │ ─────────────────────────────── │
           │ • Namespace Management          │
           │ • Codec: Arc<NdrCodec>          │
           │ • Transport: Arc<Mutex<RPC>>    │
           │ ◦ exec_query()                  │
           │ ◦ exec_method()                 │
           └───────────────┬─────────────────┘
                           │
                           ▼ Marshal/Unmarshal
           ┌─────────────────────────────────┐
           │         NDR Codec (Trait)       │
           │ ─────────────────────────────── │
           │ • encode_exec_query()           │
           │ • decode_exec_query()           │
           │ • encode_exec_method()          │
           │ • decode_exec_method()          │
           └───────────────┬─────────────────┘
                           │
                           ▼ Stub Implementation
           ┌─────────────────────────────────┐
           │       StubNdrCodec              │
           │ • Returns Canned JSON           │
           └───────────────┬─────────────────┘
                           │
                           ▼ Wire Payloads
           ┌─────────────────────────────────┐
           │      RPC Transport (Trait)      │
           │ ─────────────────────────────── │
           │ • invoke(opnum, payload)        │
           └───────────────┬─────────────────┘
                           │
                           ▼ Current Stub
           ┌─────────────────────────────────┐
           │        StubTransport            │
           │ • Ignores Payload               │
           │ • Returns Empty Vec<u8>         │
           └───────────────┬─────────────────┘
                           │
                           ▼ Future Integration
           ┌─────────────────────────────────┐
           │      Authentication Provider    │
           │ ─────────────────────────────── │
           │ • negotiate()                   │
           │ • respond()                     │
           │ • session_key()                 │
           └───────────────┬─────────────────┘
                           │
                           ▼ Current Implementation
           ┌─────────────────────────────────┐
           │         NTLMv2 Client           │
           │ • Tracks Session Key            │
           │ • Produces NTLM Messages        │
           └─────────────────────────────────┘
```

  This diagram shows how the Rust layers interlock: IWbemServices talks to an NdrCodec to marshal/unmarshal WMI payloads, the codec relies on an RpcTransport to ship raw PDUs, and the
  transport can consult an AuthProvider (currently NtlmV2Client) for authentication material. The existing stub implementations keep the old hard-coded behaviour but sit behind these new
  traits, so we can later swap in real RPC/NDR components without disturbing the outer layers.

# WMI Rust Project Structure

## Project Layout

```
src/
├── lib.rs                  # Module wiring and global configurations
├── transport/
│   ├── mod.rs              # Transport module root
│   ├── real.rs             # Core transport implementation
│   │   - Endpoint Mapper (EPM) lookup
│   │   - Binding logic
│   │   - RPC invocation skeleton
│   └── tests.rs            # Transport-related unit tests
├── tower.rs                # Response parsing and tower construction
│   - Builds RPC request/response tower
│   - Handles complex response parsing
├── rpc_pdu.rs              # Protocol Data Unit (PDU) handling
│   - Defines PDU structs
│   - Implements PDU builder and parser
└── auth/
    ├── mod.rs              # Authentication module root
    ├── ntlm.rs             # NTLM authentication integration
    │   - Session key management
    │   - NTLM authentication flow
    └── tests.rs            # Authentication-related unit tests
```

## Module Responsibilities

### `lib.rs`
- Central module for project configuration
- Manages module visibility and exports
- Defines global settings and constants

### `transport/`
#### `mod.rs`
- Defines transport-related traits
- Provides common transport abstractions

#### `real.rs`
- Concrete implementation of transport mechanisms
- Handles low-level RPC communication details
- Implements:
  - Endpoint Mapper (EPM) lookup
  - RPC binding
  - Invocation primitives

### `tower.rs`
- Responsible for constructing the RPC request/response processing pipeline
- Handles complex response parsing and transformation
- Implements tower-based middleware pattern for RPC interactions

### `rpc_pdu.rs`
- Defines Protocol Data Unit (PDU) structures
- Provides builders and parsers for RPC PDUs
- Ensures type-safe PDU construction and deconstruction

### `auth/`
#### `mod.rs`
- Authentication module root
- Defines authentication-related traits
- Provides common authentication abstractions

#### `ntlm.rs`
- Integrates NTLM authentication
- Manages authentication session keys
- Implements NTLM authentication flow

## Key Design Principles
- Modular architecture
- Clear separation of concerns
- Type-safe PDU handling
- Flexible authentication mechanisms
- Comprehensive test coverage

———

## ✅ Additional Notes

  - Keep using rustfmt (it shaves ~15% off manual formatting).
  - While golden Wireshark data helps stabilize the tests, it's optional if you can confirm against a real host.
  - Try to source a test environment early so you can flush out integration issues by Stage B.

To deliver a trustworthy Step 1 implementation, I’d need:

### 1. A live target or captured traffic

  - Access to a Windows machine running WMI so I can connect during development or
  - Wireshark/tcpdump captures (full RPC frames) of a successful EPM lookup and bind for IObjectExporter, including all three bind handshake PDUs.

### 2. Credentials & security parameters

  - Test credentials with enough privilege for WMI.
  - Any non-default domain, workstation, or NTLM flags we must accommodate.

### 3. Behavior constraints

  - Whether to support PacketPrivacy sealing immediately or signing-only is acceptable.
  - Any timeouts, retry rules, or context teardown behavior expected.

  With those artifacts (especially captures showing the exact tower and bind exchange) plus a target endpoint to validate against, I can implement and verify the EPM lookup, RPC bind, and
  NTLM handshake without guessing.
