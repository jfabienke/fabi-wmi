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
cargo run --no-default-features --example wmi_query <host> <user> <pass> <domain|""> '<WQL>' ['<WQL>' ...]
# WMI_NAMESPACE=root/StandardCimv2 to change namespace; RUST_LOG=linux_wmi=debug for protocol steps,
# RUST_LOG=linux_wmi::wmi_conn=trace to dump every response stub as hex (how fixtures are captured).
```

The .NET suite runs live with `WMI_TEST_DEFAULTHOST/USERNAME/PASSWORD` (and `WMI_TEST_TESTHOSTS_PRIMARY_*`) after copying `target/release/liblinux_wmi.{so,dylib}` into its output dir; with only a newer .NET runtime installed, set `DOTNET_ROLL_FORWARD=Major`.

### Environment variables

| Variable | Effect |
|---|---|
| `LINUX_WMI_USE_STUB=1` | Session uses the canned `StubTransport` + `StubNdrCodec` backend (no network). Without the `test-support` feature, session creation fails. |
| `LINUX_WMI_PORT` / `LINUX_WMI_SKIP_EPM` | Only read by the legacy `dcom::resolve_wmi_port`; not on the FFI path. |
| `RUST_LOG=linux_wmi=debug` | `tracing` output. |

## Architecture

The working path (FFI → `wmi_conn::WmiClient`):

1. **FFI** (`src/lib.rs`): `wmi_session_new` only validates input (no I/O). `wmi_namespace_open` calls `WmiClient::connect`, so bad hosts/credentials/namespaces fail there. `wmi_exec_query_json` reuses the client (reconnecting if an earlier error broke the connection); `timeout_ms` bounds each network read/write. Non-zero status = the server's HRESULT when known, else -1. Must stay in sync with `include/linux_wmi.h` and `shim/wmi_shim.cs`.
2. **Activation** (`dcom::activate_level1_login`): port 135, IActivation::RemoteActivation of CLSID_WbemLevel1Login, NTLM via `sspi_ntlm::SspiNtlmClient` at PKT_PRIVACY (sealed). Returns port, IPIDs, and reference counts. Bindings advertised by the server are ignored except for the port (they are NAT-internal names); the client keeps dialing the host it was given.
3. **WMI connection** (`wmi_conn.rs`): one TCP connection to that port at PKT_INTEGRITY (signed, cleartext). Every interface gets its own presentation context **and** its own NTLM context (bind or alter_context → challenge → auth3). Requests carry the IPID as object UUID. Calls: NTLMLogin (6) → ExecQuery (20) → Next (4, batches of 32 until WBEM_S_FALSE = 1). Every interface reference is released through IRemUnknown::RemRelease (5).
4. **Encoders** (`wmi_proto.rs`) and **MS-WMIO decoder** (`wmio.rs`, objects → JSON). Both are golden-tested against bytes captured from Windows in `src/testdata/`. Values stay as WMI gives them (DMTF datetime strings, uint64 as numbers); the C# shim converts DMTF datetimes/intervals for typed models and returns `ExpandoObject`s for `Query<dynamic>`.

**Legacy stack, not on the FFI path:** `transport.rs` `RealRpcTransport`/`AsyncRealRpcTransport`, `ndr/` (`RealNdrCodec`, which silently returns canned `"STUB-PC"` data when decoding fails), `wmi.rs` `IWbemLocator`/`IWbemServices`, `pool.rs`. These are still exported from the Rust API, but they never completed a real query. Don't build on them.

ExecMethod is not implemented on the DCOM path yet (`wmi_exec_method_json` returns an error).

Test doubles live in `src/test_support/` (compiled under `cfg(test)` or `test-support`).

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
