# End-to-End Tests for linux-wmi

xUnit tests that drive the .NET shim (`shim/wmi_shim.cs`) through the C ABI of
`libfabi_wmi`. They run in one of two modes:

- **Stub backend**: the library answers from canned data (`src/test_support`),
  so the P/Invoke marshalling, JSON binding and error codes are tested without
  a Windows host. This is what CI runs.
- **Live**: against a Windows host over DCOM.

Each test skips itself unless its mode is configured, so a plain `dotnet test`
with nothing set skips everything.

## Running

```bash
# Stub backend: build the library with test-support and set LINUX_WMI_USE_STUB
../../examples/run_dotnet_tests.sh --stub

# Live: any Windows host that allows remote WMI
../../examples/run_dotnet_tests.sh --host <host> --user <user> --pass <password> [--domain <domain>]
```

By hand: build the library (`cargo build --lib`, plus `--features test-support`
for the stub), `dotnet build`, copy `target/debug/libfabi_wmi.{so,dylib}` into
`bin/Debug/net10.0/`, then `dotnet test --no-build`. With only a newer .NET
runtime installed, set `DOTNET_ROLL_FORWARD=Major`.

## Configuration

Settings come from the `TestConfiguration` section of `appsettings.json`; a
`WMI_TEST_<NAME>` environment variable overrides each one:

| Variable | Meaning |
|---|---|
| `WMI_TEST_DEFAULTHOST` | Windows host for live tests; live tests skip when empty |
| `WMI_TEST_DEFAULTUSERNAME`, `WMI_TEST_DEFAULTPASSWORD` | Account (an administrator, for the method tests) |
| `WMI_TEST_DEFAULTDOMAIN` | Domain, empty for a local account |
| `WMI_TEST_DEFAULTTIMEOUT` | Network timeout, default `00:00:30` |
| `WMI_TEST_SKIPNETWORKTESTS`, `WMI_TEST_SKIPAUTHTESTS` | Skip live tests, or only the credential tests |
| `LINUX_WMI_USE_STUB=1` | Stub mode: stub tests run, live tests skip |

## Tests

Filter by class trait, e.g. `dotnet test --filter Category=Priority0`:

| Category | Class | Covers |
|---|---|---|
| `Priority0` | `Priority0_ConnectionTests` | Connecting, repeated connections, auth levels (accepted, only logged), disposal |
| `Priority0` | `Priority0_BasicQueryTests` | WQL queries, typed rows, WHERE, selected properties; ORDER BY is rejected (WQL has none) |
| `Priority0` | `Priority0_MethodTests` | Static methods on a class, instance methods on an object path, output parameters |
| `Priority1` | `Priority1_ErrorHandlingTests` | Bad credentials, unreachable host, invalid WQL, class and namespace, timeouts |
| `Priority2` | `Priority2_DataHandlingTests` | Empty results, CIM types, large result sets, Unicode, nulls, uint64, arrays |
| `Stub` | `StubBackendTests` | The shim and C ABI against the stub backend |

Live tests assume a Windows Server host and an administrator account: the
method tests start and terminate processes (`cmd.exe`, `notepad.exe`) and read
the namespace's security descriptor.

`WmiException.Code` is the server's HRESULT when it sent one and -1 otherwise;
`Infrastructure/WmiStatus.cs` names the codes the tests expect.

## Troubleshooting

- **Library not found**: copy `libfabi_wmi.so` (Linux) or `libfabi_wmi.dylib`
  (macOS) into the test output directory.
- **"Stub tests need LINUX_WMI_USE_STUB=1"**: the variable must be set before
  `dotnet test` starts; setting it from inside the tests has no effect.
- **Access denied**: the account needs DCOM remote launch and activation
  rights and access to `root\cimv2` (see `docs/INTEGRATION_TESTING.md`).
- **Network errors**: the host must accept TCP 135 and the WMI service's
  dynamic port.
