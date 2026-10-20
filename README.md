# Linux WMI Client

Query Windows Management Instrumentation (WMI) on Windows hosts from Linux or
macOS, in Rust, without Windows components or agents: DCOM activation and
MS-RPC over TCP, NTLMv2 authentication, and an MS-WMIO decoder that turns
WMI objects into JSON.

A C ABI and a C# shim emulating part of the .NET ORMi API
(`WMIHelper.Query<T>`, `QueryFirstOrDefault<T>`) let existing .NET code run
off Windows.

## Status

Verified live against Windows Server 2022:

- WQL queries in any namespace, including `SELECT *`, association classes and
  multi-batch result sets; one login reused across queries.
- Every CIM type, arrays, embedded objects, NULL and class-default values,
  checked field-for-field against `Get-WmiObject` on the same host.
- Errors carry the Windows HRESULT (e.g. `0x80070005` bad credentials,
  `0x8004100E` invalid namespace, `0x80041010` invalid class).
- Server-side references are released (IRemUnknown::RemRelease).

Not yet:

- **Kerberos.** Authentication is NTLMv2 only. The kerbsec-based
  `KerberosClient` performs the handshake but is not wired into `WmiClient`.
  NTLM for DCOM is being phased out of Windows; see
  [docs/NTLM-DEPRECATION-TIMELINE.md](docs/NTLM-DEPRECATION-TIMELINE.md).
- **ExecMethod** (`ExecuteStaticMethod` in the shim) returns "not implemented".
- WQL longer than one RPC fragment (~2,000 characters) is rejected.

## Usage

```rust
use linux_wmi::{Credentials, WmiClient};
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
# Ok::<(), linux_wmi::Error>(())
```

Values are as WMI returns them: DMTF datetimes stay strings
(`20261019223402.000000+120`); the C# shim converts them for typed models.

From the command line:

```bash
cargo run --example wmi_query -- <host> <user> <password> <domain|""> 'SELECT Name FROM Win32_Service'
```

## Building

```bash
cargo build                               # default: includes the `kerberos` feature (system GSS-API)
cargo build --no-default-features         # NTLM only, no GSS-API toolchain needed
cargo test --features test-support        # full test suite (golden tests against captured Windows bytes)
```

The `kerberos` feature builds `kerbsec` (`../kerbsec`) and binds the system
GSS-API with bindgen. `.cargo/config.toml` points bindgen at the macOS Command
Line Tools SDK, so a Homebrew/Zerobrew LLVM on `PATH` works.

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
