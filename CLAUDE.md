# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Rust WMI client workspace (`fabi-*` crates) for Linux/macOS: queries and invokes methods on Windows hosts over raw MS-RPCE/DCOM/WMI on TCP, with NTLMv2 auth (via `sspi-rs`) and Kerberos GSS-API IOV support (`fabi-kerbsec`). The root `fabi-wmi` crate builds as `cdylib` + `rlib` (`libfabi_wmi`), with the C ABI gated under the `ffi` feature (enabled by default). The C# P/Invoke shim (`shim/wmi_shim.cs`) emulates a subset of the .NET **ORMi** API (`WMIHelper.Query<T>`, `QueryFirstOrDefault<T>`, `ExecuteStaticMethod<T>`) so existing .NET code can run off-Windows. Results cross the FFI boundary as JSON.

### Workspace Crates

| Crate | Path | Responsibility |
|---|---|---|
| `fabi-wmio` | `crates/fabi-wmio` | MS-WMIO binary object block decoder (`decode_object_block`) and method input instance encoder (`spawn_instance`, `extract_method_in_params`, `encode_method_in_params`) |
| `fabi-dcerpc` | `crates/fabi-dcerpc` | DCE/RPC connection-oriented PDU framing, request/response fragmentation, `RpcConnection`, generalized `AuthProvider` SSP trait, and `SspiNtlmClient` |
| `fabi-dcom` | `crates/fabi-dcom` | OXID resolution (`resolve_oxid`, `IOXIDResolver::ResolveOxid`), generalized `remote_activation` (`IRemoteSCMActivator` / `IActivation`), consolidated `ObjRef`/`StdObjRef`/`MInterfacePointer`/`DualStringArray` marshaling (`encode_custom_m_interface_pointer`), and `encode_rem_release` (`IRemUnknown::RemRelease`) |
| `fabi-kerbsec` | `../kerbsec` | GSS-API Kerberos v5 security context with 4-buffer `GSS_C_DCE_STYLE` IOV protection (`SIGN_ONLY` header/trailer, `DATA` stub, `HEADER` `auth_value`) |
| `fabi-wmi` | `.` (root) | High-level `WmiClient` (`query`, `query_as`, `exec_method`, `exec_method_as`), MS-WMI ORPC encoders/decoders (`src/wmi_proto.rs`), `KerberosClient` (`AuthProvider` bridge), C ABI (`src/lib.rs`, `ffi` feature), and .NET shim (`shim/wmi_shim.cs`) |

## Build & Test

Cargo features on `fabi-wmi`: `ffi` (**default**, C ABI exports), `kerberos` (**default**, pulls in `fabi-kerbsec` via path dep `../kerbsec`), `test-support` (in-process stub backend for the C ABI).

```bash
cargo build --workspace                                  # default (ffi + kerberos) build
cargo build --lib --release                              # what CI builds
cargo test --workspace --features test-support           # full Rust workspace suite
cargo test --no-default-features                         # pure Rust rlib without ffi or kerberos
cargo test --features test-support <test_name>           # single test (substring match)
cargo test --features test-support --test integration    # single integration-test file
cargo fmt --all && cargo clippy --workspace --all-targets
```

- `.cargo/config.toml` (same in kerbsec) sets `BINDGEN_EXTRA_CLANG_ARGS_<apple target>` to the Command Line Tools SDK. Without it, a non-Apple libclang on `PATH` (Homebrew/Zerobrew LLVM) fails in `libgssapi-sys` with `'inttypes.h' file not found`. If your SDK lives elsewhere, set the variable in your environment.
- `tests/kerberos_adapter_test.rs` needs the `kerberos` feature.
- .NET E2E suite: `tests/e2e-dotnet` (net8.0, xUnit). Mock mode: `WMI_TEST_SKIPNETWORKTESTS=true WMI_TEST_SKIPAUTHTESTS=true dotnet test`. Live mode reads `WMI_TEST_DEFAULTHOST/USERNAME/PASSWORD/DOMAIN`. CI (`.github/workflows/e2e-tests.yml`) copies `libfabi_wmi.so` into the test output dir.

### Running against a live host

```bash
cargo run --no-default-features --example wmi_query <host> <user> <pass> <domain|""> '<WQL>' ['<WQL>' ...]
# WMI_NAMESPACE=root/StandardCimv2 to change namespace; RUST_LOG=fabi_wmi=debug for protocol steps,
# RUST_LOG=fabi_wmi::client=trace to dump every response stub as hex (how fixtures are captured).
```

The .NET suite runs live with `WMI_TEST_DEFAULTHOST/USERNAME/PASSWORD` (and `WMI_TEST_TESTHOSTS_PRIMARY_*`) after copying `target/release/libfabi_wmi.{so,dylib}` into its output dir; with only a newer .NET runtime installed, set `DOTNET_ROLL_FORWARD=Major`.

### Environment variables

| Variable | Effect |
|---|---|
| `LINUX_WMI_USE_STUB=1` | The C ABI uses the canned `test_support` backend (no network). Without the `test-support` feature, session creation fails. |
| `RUST_LOG=linux_wmi=debug` | `tracing` output. |

## Architecture

Public Rust API (`src/lib.rs` re-exports): `WmiClient` (`connect`, `connect_with_timeout`, `query`, `query_as<T>`, `exec_method`, `exec_method_as<T>`), `query()`, `exec_method()`, `Credentials`, `Error` (with `hresult()`), `DcomError`, `RpcError`, `WmiProtoError`, `WmioError`, `DEFAULT_TIMEOUT`; plus `KerberosClient`/`KerberosConfig` under `kerberos`.

Request flow (C ABI → `client::WmiClient`):

1. **FFI** (`src/lib.rs`, gated under `ffi` feature): `wmi_session_new` only validates input (no I/O). `wmi_namespace_open` calls `WmiClient::connect`, so bad hosts/credentials/namespaces fail there. `wmi_exec_query_json` and `wmi_exec_method_json` reuse the client (reconnecting if an earlier error broke the connection); `timeout_ms` bounds each network read/write. Non-zero status = the server's HRESULT when known, else -1. Must stay in sync with `include/linux_wmi.h` and `shim/wmi_shim.cs`.
2. **Activation** (`fabi_dcom::activate_level1_login` / `remote_activation`): port 135, `IActivation::RemoteActivation` of `CLSID_WbemLevel1Login` (or arbitrary CLSID/IID), NTLM via `fabi_dcerpc::SspiNtlmClient` at `PKT_PRIVACY` (sealed). Returns port, IPIDs, and reference counts; `resolve_oxid` resolves an OXID via `IOXIDResolver::ResolveOxid` when needed.
3. **WMI connection** (`client.rs`, PDU framing and fragmentation in `fabi_dcerpc`): one TCP connection (`RpcConnection`) to the dynamic port at `PKT_INTEGRITY` (signed, cleartext). Every interface gets its own presentation context **and** its own SSP context (bind or alter_context → challenge → auth3). Requests carry the IPID as object UUID. Calls: `NTLMLogin` (6) → `ExecQuery` (20) + `Next` (4, batches of 32 until `WBEM_S_FALSE = 1`), or `GetObject` (6) + `ExecMethod` (24). Every interface reference is released through `IRemUnknown::RemRelease` (5).
4. **Encoders** (`src/wmi_proto.rs`) and **MS-WMIO codec** (`crates/fabi-wmio`, objects ↔ JSON). Both are golden-tested against bytes captured from Windows in `src/testdata/`. `fabi-wmio::spawn_instance` encodes method input instances (`pInParams`) from a class definition's `MethodPart` `InputSignature` and JSON parameters, wrapped in an `OBJREF_CUSTOM` `MInterfacePointer` (`fabi_dcom::encode_custom_m_interface_pointer`).

`src/test_support/` is the canned backend used by the C ABI when `LINUX_WMI_USE_STUB=1` (requires `test-support`); `tests/integration.rs` exercises the FFI plumbing through it.

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
