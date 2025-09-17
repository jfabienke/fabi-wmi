# Strategy: Minimal Functionality First, But Designed for Full Protocols

  To keep forward progress manageable and avoid painting ourselves into a corner, I’d approach the stack in two layers:

  ———

  ## 1. Immediate Goal: “Minimal Viable” Path

  Target the smallest slice of functionality that unblocks real queries:

  Scope * ExecQuery + ExecMethod (GetOwner)
  Features

  - Endpoint mapper: TowerConnect → port resolution
  - RPC bind + NTLMv2: sign/seal enough to keep the server happy
  - RPC request/reply: single-fragment PDUs (no fragmentation yet)
  - NDR support: just the types we need today
      - BSTR (for namespace, WQL, class/method names)
      - VARIANT (VT_I4, VT_BSTR)
      - Conformant array for a single enumerator response
  - Decode reply into JSON (enough for our API)
  - Error handling for the most common HRESULTs (WBEM_E_INVALID_CLASS, etc.)

  Testing

  - Golden Wireshark traces for ExecQuery/GetOwner
  - Mock RPC transport that replays recorded replies
  - Optional: integration check against a reference implementation (Wine or Windows COM via FFI) to compare JSON outputs

  This gives us a working round-trip with real data, replacing the stub responses we have now.

  ———

  ## 2. Architectural Hooks for the “Full” Version

  While we build the minimal slice, design the interfaces so we can expand later without rewrites:

  | Layer           | Minimal Implementation          | Future Hook                                   | Notes                                                                          |
  |-----------------|---------------------------------|-----------------------------------------------|--------------------------------------------------------------------------------|
  | Endpoint Mapper | synchronous TowerConnect        | allow alternative resolver (e.g. WinRPC FFI)  | Keep a trait EndpointResolver                                                  |
  | Transport / RPC | single-fragment, sync           | fragmentation, async, multiple auth providers | Expose RpcTransport trait with pluggable backends                              |
  | Authentication  | NTLMv2 only                     | Kerberos, CredSSP                             | Make AuthProvider trait; store session key for PacketPrivacy                   |
  | NDR             | only the types we use           | full VARIANT, SAFEARRAY, complex structs      | Factor into NdrCodec trait; our implementation can grow type support over time |
  | Marshaling      | hard-coded ExecQuery/ExecMethod | general IDL-driven stubs                      | Keep method descriptors (opnum, signature) in data structures                  |
  | Error Mapping   | common codes                    | full HRESULT table, WMI-specific errors       | Map raw status to typed errors, extend later                                   |

  By committing to these interfaces early, “future us” can swap in a more complete codec or transport without touching the rest of the stack.

  ———

  ## 3. Recommended Order of Work

  1. Module Skeleton – Define the traits/structs (RpcTransport, AuthProvider, NdrCodec) and wire current stubs to use them.
  2. Endpoint Mapper + Bind – Make sure we can reach the WMI endpoint (resolve port, complete RPC bind) doing nothing else.
  3. Minimal NDR Codec – Implement the specific encoding/decoding we need for ExecQuery/GetOwner.
  4. ExecQuery – Marshal the request, validate against captured traffic, decode the response into JSON.
  5. ExecMethod (GetOwner) – Same as ExecQuery but with the method parameters and response.
  6. Integration – Tie into WmiSession FFI functions and update tests to ensure we’re no longer returning stubs.
  7. Optional Baseline – Add instrumentation to compare our output with a reference (A/B switch) for confidence.

  ———

  ## 4. When You’re Ready to Expand

  With those abstractions in place, future additions become mostly incremental:

  - Fragmentation – Implement a reassembly buffer in RpcTransport.
  - More NDR Types – Expand the codec (SAFEARRAY, VT_DATE, complex structs) and register them.
  - Kerberos/Other Auth – Add new AuthProvider implementations; swap via config or negotiation.
  - Async/Parallel RPC – Introduce an async transport or reuse the same traits with different implementations.
  - More WMI methods – Describe the type signatures, plug them into the same marshaling pipeline.

  ———

  ### Summary

  Build the minimum functionality you need today—just enough to run credentialed ExecQuery/GetOwner end-to-end. At the same time, lock in clean interfaces for the RPC transport, auth,
  and marshaling layers so you can grow into the full specification later without refactoring everything. That approach keeps the immediate effort tractable, gives you usable results, and
  leaves a clear path to “production-grade” coverage when you’re ready.
