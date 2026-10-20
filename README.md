# Linux WMI Client

Query Windows Management Instrumentation (WMI) on Windows hosts from Linux or
macOS, in Rust, without Windows components or agents: DCOM activation and
MS-RPC over TCP, NTLMv2 authentication, and an MS-WMIO decoder that turns
WMI objects into JSON.

A C ABI and a C# shim emulating part of the .NET ORMi API
(`WMIHelper.Query<T>`, `QueryFirstOrDefault<T>`) let existing .NET code run
off Windows.

## Status

Verified live against Windows Server 2022 and 2025:

- WQL queries in any namespace, including `SELECT *`, association classes and
  multi-batch result sets; one login reused across queries. Long queries are
  split across RPC fragments.
- Every CIM type, arrays, embedded objects, NULL and class-default values,
  checked field-for-field against `Get-WmiObject` on the same host.
- WMI methods (`ExecMethod`), with or without input parameters; the input
  object is built from the method's signature in the class definition.
  Checked against `Invoke-CimMethod` with `StdRegProv.GetStringValue` and
  `__SystemSecurity.GetSD`.
- Errors carry the Windows HRESULT (e.g. `0x80070005` bad credentials,
  `0x8004100E` invalid namespace, `0x80041010` invalid class,
  `0x8004102E` invalid method).
- Server-side references are released (IRemUnknown::RemRelease).

Not yet:

- **Kerberos.** `WmiClient` authenticates with NTLMv2 only. The
  `fabi-kerbsec`-based `KerberosClient` implements the RPC authentication
  seam, including DCE-style signing and sealing, but `WmiClient` does not use
  it and it has not run against a KDC. NTLM for DCOM is being phased out of
  Windows; see [docs/NTLM-DEPRECATION-TIMELINE.md](docs/NTLM-DEPRECATION-TIMELINE.md).

## Usage

```rust
use fabi_wmi::{Credentials, WmiClient};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Process {
    name: String,
    process_id: u32,
}

let creds = Credentials::new("Administrator", "secret"); // .with_domain("CORP") for a domain account
let mut wmi = WmiClient::connect("192.0.2.10", &creds, r"root\cimv2")?;

for p in wmi.query_as::<Process>("SELECT Name, ProcessId FROM Win32_Process")? {
    println!("{} {}", p.process_id, p.name);
}
let rows = wmi.query("SELECT * FROM Win32_OperatingSystem")?; // Vec<serde_json::Value>

let out = wmi.exec_method("StdRegProv", "GetStringValue", &serde_json::json!({
    "hDefKey": 2147483650u32, // HKEY_LOCAL_MACHINE
    "sSubKeyName": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
    "sValueName": "ProductName",
}))?; // output parameters as JSON: {"ReturnValue": 0, "sValue": "..."}
# Ok::<(), fabi_wmi::Error>(())
```

Values are as WMI returns them: DMTF datetimes stay strings
(`20261019223402.000000+120`); the C# shim converts them for typed models.

From the command line:

```bash
cargo run --example wmi_query -- <host> <user> <password> <domain|""> 'SELECT Name FROM Win32_Service'
cargo run --example wmi_method -- <host> <user> <password> <domain|""> __SystemSecurity GetSD
```

## Building

```bash
cargo build                                   # default: the C ABI (`ffi`) and `kerberos` (system GSS-API)
cargo build --no-default-features             # Rust API only, NTLM only, no GSS-API toolchain needed
cargo test --workspace --features test-support  # full test suite (golden tests against captured Windows bytes)
```

The `kerberos` feature builds `fabi-kerbsec` from `../kerbsec` and binds the
system GSS-API with bindgen. Cargo reads `../kerbsec/Cargo.toml` even with the
feature off, so check out kerbsec next to this repository. `.cargo/config.toml`
points bindgen at the macOS Command Line Tools SDK, so a Homebrew/Zerobrew
LLVM on `PATH` works.

Windows targets need DCOM enabled, the account in "Distributed COM Users" (or
an administrator), WMI namespace permissions, and the firewall open for RPC
(135) and the WMI endpoint; see [docs/INTEGRATION_TESTING.md](docs/INTEGRATION_TESTING.md).

## Documentation

- [CLAUDE.md](CLAUDE.md): architecture and request flow.
- [docs/VERIFIED_CONSTANTS.md](docs/VERIFIED_CONSTANTS.md) and `docs/refs/`
  (MS-RPCE, MS-DCOM, MS-WMI, MS-NLMP, ...): protocol references.
- Other files in `docs/` are historical design notes from earlier iterations
  and may describe APIs that no longer exist.

## License

MIT; see [LICENSE](LICENSE).
