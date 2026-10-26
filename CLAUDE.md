# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Rust WMI client workspace (`fabi-*` crates) for Linux/macOS: queries and invokes methods on Windows hosts over raw MS-RPCE/DCOM/WMI on TCP, with NTLMv2 auth (via `sspi-rs`) and Kerberos GSS-API IOV support (`fabi-kerbsec`). The root `fabi-wmi` crate builds as `cdylib` + `rlib` (`libfabi_wmi`), with the C ABI gated under the `ffi` feature (enabled by default). The C# P/Invoke shim (`shim/wmi_shim.cs`) emulates a subset of the .NET **ORMi** API (`WMIHelper.Query<T>`, `QueryFirstOrDefault<T>`, `ExecuteStaticMethod<T>`) so existing .NET code can run off-Windows. Results cross the FFI boundary as JSON.

### Workspace Crates

| Crate | Path | Responsibility |
|---|---|---|
| `fabi-wmio` | `crates/fabi-wmio` | MS-WMIO object decoder (`decode_object`) and method input instance encoder (`spawn_instance`, `extract_method_in_params`, `encode_method_in_params`) |
| `fabi-dcerpc` | `crates/fabi-dcerpc` | DCE/RPC connection-oriented PDU framing, request/response fragmentation, `RpcConnection`, generalized `AuthProvider` SSP trait, and `SspiNtlmClient` |
| `fabi-dcom` | `crates/fabi-dcom` | OXID resolution (`resolve_oxid`, `IOXIDResolver::ResolveOxid`), remote activation (`activate`, `activate_with`; `IRemoteSCMActivator` / `IActivation`), consolidated `ObjRef`/`StdObjRef`/`MInterfacePointer`/`DualStringArray` marshaling (`encode_custom_m_interface_pointer`), and `encode_rem_release` (`IRemUnknown::RemRelease`) |
| `fabi-kerbsec` | `../kerbsec` | GSS-API Kerberos v5 security context with 4-buffer `GSS_C_DCE_STYLE` IOV protection (`SIGN_ONLY` header/trailer, `DATA` stub, `HEADER` `auth_value`); native IOV needs Linux with its `iov` feature |
| `fabi-wmi` | `.` (root) | High-level `WmiClient` (`query`, `query_as`, `exec_method`, `exec_method_as`), MS-WMI ORPC encoders/decoders (`src/wmi_proto.rs`), `KerberosClient` (`AuthProvider` bridge), C ABI (`src/lib.rs`, `ffi` feature), and .NET shim (`shim/wmi_shim.cs`) |
| `fabi-testkit` | `crates/fabi-testkit` | Dev-only: proptest strategies (random bytes, mutated captures) for the parsers' never-panic properties |

## Build & Test

Cargo features on `fabi-wmi`: `ffi` (**default**, C ABI exports), `kerberos` (**default**, pulls in `fabi-kerbsec` via path dep `../kerbsec`), `test-support` (in-process stub backend for the C ABI).

```bash
cargo build --workspace                                  # default (ffi + kerberos) build
cargo build --lib --release                              # what CI builds
cargo test --workspace --features test-support           # full Rust workspace suite
cargo test --no-default-features                         # pure Rust rlib without ffi or kerberos
cargo test --features test-support <test_name>           # single test (substring match)
PROPTEST_CASES=100000 cargo test --workspace properties   # deeper run of the parser never-panic properties (default 1000 cases)
cargo test --features test-support --test integration    # single integration-test file
cargo fmt && cargo clippy --workspace --all-targets      # not `fmt --all`: see below
cargo deny check                                         # advisories, licenses, banned crates (deny.toml)
```

- Dependency policy: no third-party C compiled into the build. OS libraries are used only where the OS holds the credentials (the system GSS-API for Kerberos); everything else is pure Rust. `deny.toml` bans the crates that compile C (`cc`, `cmake`, `ring`, `aws-lc-*`, `openssl-sys`) and bindgen; CI (`.github/workflows/rust.yml`) runs fmt, clippy, tests and cargo-deny.

- Plain `cargo fmt` formats every workspace member. `cargo fmt --all` also formats the local path dependency `../kerbsec`.

- Building needs no Kerberos packages: kerbsec loads the system GSS-API at run time (its `src/ffi`). Running Kerberos needs `libgssapi-krb5-2` (Debian/Ubuntu), `krb5-libs` (Fedora/RHEL) or macOS's GSS.framework; without it, `Auth::Kerberos` fails at connect with "GSS-API unavailable". `KERBSEC_GSSAPI_LIBRARY` overrides the library.
- `tests/kerberos_adapter_test.rs` needs the `kerberos` feature.
- .NET E2E suite: `tests/e2e-dotnet` (net10.0, xUnit). Mock mode: `WMI_TEST_SKIPNETWORKTESTS=true WMI_TEST_SKIPAUTHTESTS=true dotnet test`. Live mode reads `WMI_TEST_DEFAULTHOST/USERNAME/PASSWORD/DOMAIN`. CI (`.github/workflows/e2e-tests.yml`) copies `libfabi_wmi.so` into the test output dir.

### Running against a live host

```bash
cargo run --no-default-features --example wmi_query <host> <user> <pass> <domain|""> '<WQL>' ['<WQL>' ...]
cargo run --no-default-features --example wmi_method <host> <user> <pass> <domain|""> <object-path> <method> ['<in-params JSON>']
# WMI_NAMESPACE=root/StandardCimv2 to change namespace; RUST_LOG=fabi_wmi=debug for protocol steps,
# RUST_LOG=fabi_dcerpc=trace to dump every response stub as hex (how fixtures are captured).
kinit <user>@<REALM> && cargo run --example wmi_query_kerberos <host-fqdn> <REALM> '<WQL>' ['<WQL>' ...]
```

Kerberos runs on Linux and macOS. Activation is sealed where kerbsec can seal DCE/RPC PDUs (Linux: MIT or Heimdal, which have the IOV functions) and signed elsewhere (macOS: GSS.framework lacks them); WMI calls are signed either way. The ticket comes from `KRB5CCNAME` (on macOS, `/usr/bin/kinit --password-file=STDIN` works with a `KRB5_CONFIG` file), and the SPN is `host/<host-fqdn>`, so the name must resolve to the server (an `/etc/hosts` entry is enough), or set `WMI_SPN=host/<fqdn>` and pass the IP address. If the KDC is only reachable over TCP, set `udp_preference_limit = 1` in MIT's `krb5.conf` or write `kdc = tcp/<host>` for Heimdal.

Read-only methods for live checks: `__SystemSecurity GetSD` (no input parameters) and `StdRegProv GetStringValue '{"hDefKey":2147483650,"sSubKeyName":"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion","sValueName":"ProductName"}'` (GetObject + input object + ExecMethod). Ground truth: `Invoke-CimMethod` over WinRM.

The .NET suite runs live with `WMI_TEST_DEFAULTHOST/USERNAME/PASSWORD` (and `WMI_TEST_TESTHOSTS_PRIMARY_*`) after copying `target/release/libfabi_wmi.{so,dylib}` into its output dir; with only a newer .NET runtime installed, set `DOTNET_ROLL_FORWARD=Major`.

### Environment variables

| Variable | Effect |
|---|---|
| `LINUX_WMI_USE_STUB=1` | The C ABI uses the canned `test_support` backend (no network). Without the `test-support` feature, session creation fails. |
| `RUST_LOG=fabi_wmi=debug` | `tracing` output. |

## Architecture

Public Rust API (`src/lib.rs` re-exports): `WmiClient` (`connect`, `connect_with_timeout`, `connect_with(host, &Auth, namespace, timeout)`, `query`, `query_as<T>`, `exec_method`, `exec_method_as<T>`), `Auth` (`Ntlm(Credentials)` or, under `kerberos`, `Kerberos(KerberosConfig)`), `query()`, `exec_method()`, `Credentials`, `Error` (with `hresult()`), `DcomError`, `RpcError`, `WmiProtoError`, `WmioError`, `DEFAULT_TIMEOUT`; plus `KerberosClient`/`KerberosConfig` under `kerberos`.

Request flow (C ABI → `client::WmiClient`):

1. **FFI** (`src/lib.rs`, gated under `ffi` feature): `wmi_session_new` only validates input (no I/O). `wmi_namespace_open` calls `WmiClient::connect`, so bad hosts/credentials/namespaces fail there. `wmi_exec_query_json` and `wmi_exec_method_json` reuse the client (reconnecting if an earlier error broke the connection); `timeout_ms` bounds each network read/write, and `RpcConnection` also limits each request-response exchange to four times that and a response to 32 MiB (`MAX_RESPONSE_LEN`). Non-zero status = the server's HRESULT when known, else -1. `include/linux_wmi.h` is generated from these declarations by cbindgen (`cbindgen.toml`); `shim/wmi_shim.cs` must match by hand.
2. **Activation** (`fabi_dcom::activate` / `activate_with`): port 135, `IActivation::RemoteActivation` of `CLSID_WbemLevel1Login` (or arbitrary CLSID/IID) at `PKT_PRIVACY` (sealed): NTLM via `fabi_dcerpc::SspiNtlmClient`, or any `AuthProvider` through `activate_with`; `activate_with_level` takes the level, and Kerberos uses `PKT_INTEGRITY` when it cannot seal (`KerberosClient::supports_privacy`, false on macOS), which Windows' DCOM hardening accepts. Returns port, IPIDs, and reference counts; `resolve_oxid` resolves an OXID via `IOXIDResolver::ResolveOxid` when needed.
3. **WMI connection** (`client.rs`, PDU framing and fragmentation in `fabi_dcerpc`): one TCP connection (`RpcConnection`) to the dynamic port at `PKT_INTEGRITY` (signed, cleartext). Every interface gets its own presentation context **and** its own SSP context (bind or alter_context → challenge → auth3), NTLM or Kerberos per `Auth`. The first authenticated bind on a connection offers `PFC_SUPPORT_HEADER_SIGN` and the server's echo settles header signing (`AuthProvider::set_header_signing`): NTLM always signs the whole PDU, Kerberos signs the header and `sec_trailer` only when it was agreed. Kerberos integrity is a MIC (`get_mic`), privacy a 4-buffer DCE IOV wrap; the integrity-only wrap token has the same 28-byte length but Windows rejects it. Requests carry the IPID as object UUID. Calls: `NTLMLogin` (6) → `ExecQuery` (20) + `Next` (4, batches of 32 until `WBEM_S_FALSE = 1`), or `GetObject` (6) + `ExecMethod` (24). Every interface reference is released through `IRemUnknown::RemRelease` (5). `ppObject`/`ppOutParams` are `[in, out, unique]`: requests send a non-NULL pointer to a NULL object (a NULL outer pointer gets `S_OK` and no object back), and replies carry two referents before the `MInterfacePointer`. A class object (from GetObject, or a method's signature) starts with its ParentClass (`ClassPart` + `MethodsPart`, empty for a root class); its own properties and methods are on CurrentClass.
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
- When changing FFI signatures, regenerate the header (`cbindgen -o include/linux_wmi.h`; CI runs `--verify`) and update `shim/wmi_shim.cs` to match.
- Never commit real credentials or host details.
