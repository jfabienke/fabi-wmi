# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Rust WMI client for Linux/macOS: queries Windows hosts over raw MS-RPCE/DCOM/WMI on TCP, with NTLMv2 and Kerberos (SPNEGO) auth. Builds as a `cdylib` + `rlib` (`liblinux_wmi`) exposing a C ABI. The C# P/Invoke shim (`shim/wmi_shim.cs`) emulates a subset of the .NET **ORMi** API (`WMIHelper.Query<T>`, `QueryFirstOrDefault<T>`, `ExecuteStaticMethod<T>`) so existing .NET code can run off-Windows. Results cross the FFI boundary as JSON.

## Build & Test

Cargo features: `kerberos` (**default**, pulls in `kerbsec` via path dep `../kerbsec`, which needs the system GSS-API and runs bindgen through `libgssapi-sys`), `test-support` (stub transport/codec), `async` (tokio transport + `pool.rs`), `test-gss-mock`.

```bash
cargo build                                              # default (kerberos) build
cargo build --lib --release                              # what CI builds
cargo test --features test-support                       # full Rust suite
cargo test --no-default-features --features test-support # no Kerberos/GSS-API toolchain needed
cargo test --features test-support <test_name>           # single test (substring match)
cargo test --features test-support --test integration    # single integration-test file
cargo fmt && cargo clippy --all-targets
```

- If the build fails in `libgssapi-sys` with `'inttypes.h' file not found`, bindgen's libclang can't see the platform SDK headers; build with `--no-default-features` to work on non-Kerberos code.
- `kerberos`-gated examples (`test_kerberos`, `dce_rpc_kerberos`) and `tests/kerberos_adapter_test.rs` (`test-gss-mock`, some `#[ignore]`) need the matching features.
- .NET E2E suite: `tests/e2e-dotnet` (net8.0, xUnit). Mock mode: `WMI_TEST_SKIPNETWORKTESTS=true WMI_TEST_SKIPAUTHTESTS=true dotnet test`. Live mode reads `WMI_TEST_DEFAULTHOST/USERNAME/PASSWORD/DOMAIN`. CI (`.github/workflows/e2e-tests.yml`) copies `liblinux_wmi.so` into the test output dir.

### Running against a live host

```bash
RUST_LOG=linux_wmi=debug cargo run --example test_connect <host> \
  --user <user> --pass <pass> --domain <domain> --query 'SELECT Name FROM Win32_ComputerSystem'
./examples/test_e2e.sh <host> <user> <pass> <domain> <query>
```

### Environment variables

| Variable | Effect |
|---|---|
| `LINUX_WMI_USE_STUB=1` | Session uses `StubTransport` + `StubNdrCodec` (no network). Requires `test-support` feature or it panics. |
| `LINUX_WMI_PORT=<n>` | Skip DCOM activation for port resolution and use this port (workaround when NTLM-for-DCOM is blocked). |
| `LINUX_WMI_SKIP_EPM=1` | Port resolution returns 135 without activation. Does **not** enable the stub transport. |
| `RUST_LOG=linux_wmi=debug` | `tracing` output (JSON-capable). |

## Architecture

Request flow (spans several files):

1. **FFI** (`src/lib.rs`): `wmi_session_new` → `InnerSession::new`, `wmi_namespace_open`, `wmi_exec_query_json`, `wmi_exec_method_json`, and `wmi_session_free` / `wmi_free_json` / `wmi_free_err`. Must stay in sync with `include/linux_wmi.h` and the `DllImport`s in `shim/wmi_shim.cs`.
2. **Port resolution** (`dcom.rs::resolve_wmi_port`): `LINUX_WMI_PORT` → `LINUX_WMI_SKIP_EPM` → anonymous DCOM activation → authenticated activation.
3. **Namespace open** (`wmi.rs::IWbemLocator::connect_server`): with credentials, does DCOM `RemoteActivation` (`dcom::activate_wmi_dcom`) to get port + OXID, then `transport::RealRpcTransport::connect_with_oxid`. That transport, not the one created in `InnerSession::new`, carries the queries. Without credentials it silently keeps the session's existing transport.
4. **Transport** (`transport.rs`): bind/alter-context, NTLM (`auth.rs`) or Kerberos/SPNEGO (`kerberos_adapter.rs`, `spnego.rs`; Kerberos is tried first when the feature is on, falling back to NTLM), PDU sign/seal (`crypto.rs`; `crypto_v2/` is the newer RustCrypto-based module), fragment reassembly. `AsyncRealRpcTransport` is the `async`-feature variant.
5. **NDR** (`ndr/codec.rs` `RealNdrCodec`, `ndr/types.rs`) behind the `NdrCodec` trait: ExecQuery is opnum 9, ExecMethod is opnum 25. Golden wire-format tests are in `ndr/golden_tests.rs`.

**Gotcha:** `RealNdrCodec` falls back to canned stub results (`decode_stub_response` / `decode_stub_method`, e.g. `"Name": "STUB-PC"`) when decoding fails, the enumerator's "more" flag is set, or ExecMethod returns no output. A query that "succeeds" with stub-looking data did not actually decode a real response.

Test doubles live in `src/test_support/` (compiled under `cfg(test)` or `test-support`). `IWbemLocator::new` only works with `test-support`; production code uses `with_components`.

## References

- `docs/VERIFIED_CONSTANTS.md`: protocol UUIDs/opnums/tower IDs cross-checked against specs and captures.
- `docs/refs/`: MS-RPCE, MS-DCOM, MS-WMI, MS-NLMP, MS-KILE, MS-SPNG and Kerberos/GSS RFC PDFs.
- `docs/NTLM-DEPRECATION-TIMELINE.md`: why Kerberos matters (Windows 11 24H2 blocks NTLM for DCOM).
- `docs/INTEGRATION_TESTING.md`: Windows target setup (DCOM enabled, user in "Distributed COM Users", `root\CIMV2` permissions, RPC firewall rules; capture with Wireshark filter `dcerpc`).

## Conventions (from AGENTS.md)

- Imperative commit subjects, one concern per commit.
- Keep `unsafe` minimal and annotated.
- When changing FFI signatures, update `include/linux_wmi.h` and `shim/wmi_shim.cs` together.
- Never commit real credentials or host details.
