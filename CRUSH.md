# Linux WMI Project

## Overview
Rust native library (liblinux_wmi) implementing DCOM/WMI client for cross-platform .NET WMI access (Linux/macOS). Exposes C ABI for P/Invoke shim mimicking ORMi subset.

## Architecture
- **Rust Core**: DCOM RPC (MS-DCOM/RPCE/WMI specs), NTLM auth, WQL execution, JSON marshaling.
- **FFI Surface**: wmi_session_new/open/ exec_query_json/exec_method_json/free.
- **C# Shim**: Arqitekta.WmiShim.WMIHelper with Query<T>, ExecuteStaticMethod, etc. (wmi_shim.cs).
- **Packaging**: RID-specific NuGet (linux-x64/arm64, osx-arm64).

## ORMi Emulation
Mimics: WMIHelper(scope), Query<T>(wql), QueryFirstOrDefault<T>, ExecuteStaticMethod<T>(class, method, params).

Sample ORMi usage (to replace):
```csharp
var helper = new WMIHelper(@"CimV2", creds, "remotehost");
var procs = helper.Query<ProcessModel>("SELECT ProcessId, Name FROM Win32_Process WHERE Name LIKE 'explorer.exe'");
var owner = helper.ExecuteStaticMethod<ProcessOwner>("Win32_Process", "GetOwner", new { Handle = 1234 });
```

## ORMi Compatibility Matrix
| ORMi Feature                                           | Supported in Shim                    | Notes                                                |
|--------------------------------------------------------|--------------------------------------|------------------------------------------------------|
| WMIHelper ctors (scope, host/creds)                    | Yes                                  | Matches ORMi; forwards to Rust session_new.          |
| Query<T>(), Query<T>(wql), QueryFirstOrDefault<T>(wql) | Yes                                  | JSON deserializes to existing models.                |
| WMIMethod.ExecuteMethod<T>(instance/class)             | Yes (static via ExecuteStaticMethod) | For GetOwner etc.; instance calls stubbed if unused. |
| IWMIHelper interface                                   | Stub (if DI used)                    | Implement if injected; else omit.                    |
| Async variants (QueryAsync etc.)                       | No (add if needed)                   | Sync only for MVP; await not required per spec.      |
| CRUD (Add/Update/RemoveInstance)                       | No                                   | Read-only scope; throw NotSupportedException.        |
| WMIWatcher/Eventing                                    | No                                   | Not in requirements; stub types if referenced.       |
| Model attributes (WMIClass/Property)                   | Compatible                           | JSON binds to prop names; keep existing attrs.       |

## C# Shim Skeleton (wmi_shim_skeleton.cs)
```csharp
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Arqitekta.WmiShim
{
    public enum WmiAuthLevel { PacketPrivacy = 5 /* ... */ }

    public class WmiException : Exception { public int HResult { get; } /* ... */ }

    internal sealed class SafeSessionHandle : SafeHandleZeroOrMinusOneIsInvalid { /* P/Invoke frees */ }

    internal static partial class NativeMethods { /* DllImport stubs for wmi_* functions */ }

    public sealed class WMIHelper : IDisposable
    {
        private SafeSessionHandle? _session;
        private readonly string _namespace;

        public WMIHelper(string scope, string? host = "localhost", string? username = null, string? password = null, string? domain = null, WmiAuthLevel auth = WmiAuthLevel.PacketPrivacy)
        {
            _namespace = $"root\\{scope.TrimStart('\\', '/').Replace('/', '\\')}";
            // NativeMethods.WmiSessionNew(host ?? "localhost", username, password, domain, auth, out _session, out var err);
            // if (_session == null) throw new WmiException(-1, err ?? "Failed");
            // NativeMethods.WmiNamespaceOpen(_session, _namespace, out err); // validate
            _session = new SafeSessionHandle();  // stub
        }

        public IEnumerable<T> Query<T>() where T : class, new()
        {
            string className = typeof(T).Name;  // e.g., "Win32_Process"
            return Query<T>($"SELECT * FROM {className}");
        }

        public IEnumerable<T> Query<T>(string wql) where T : class, new()
        {
            // string json; NativeMethods.WmiExecQueryJson(_session!, wql, 30000, out json, out var err);
            // if (!string.IsNullOrEmpty(err)) throw new WmiException(-1, err);
            // var list = JsonSerializer.Deserialize<List<T>>(json ?? "[]") ?? new();
            yield break;  // stub: yield empty for compile
        }

        public T? QueryFirstOrDefault<T>(string wql) where T : class, new()
        {
            var list = Query<T>(wql);
            return list.FirstOrDefault();
        }

        public T ExecuteStaticMethod<T>(string className, string methodName, object? inParams = null)
        {
            // string inJson = inParams != null ? JsonSerializer.Serialize(inParams) : "{}";
            // string json; NativeMethods.WmiExecMethodJson(_session!, className, methodName, inJson, 30000, out json, out var err);
            // if (!string.IsNullOrEmpty(err)) throw new WmiException(-1, err);
            // return JsonSerializer.Deserialize<T>(json) ?? throw new InvalidOperationException();
            throw new NotImplementedException("Stub: Implement via Rust FFI");
        }

        public void Dispose() { _session?.Dispose(); _session = null; }
    }

    public static class WMIMethod
    {
        public static T ExecuteMethod<T>(object instanceOrClass) where T : class, new()
        {
            // Parse instance/class to call ExecuteStaticMethod; stub for now
            throw new NotSupportedException("Instance methods: use static via WMIHelper if needed");
        }
    }

    // Stub IWMIHelper if used in DI
    public interface IWMIHelper { IEnumerable<T> Query<T>(string wql); /* ... */ }
    // public sealed class WMIHelper : IWMIHelper { /* impl above */ }
}
```
Compile this skeleton in your .NET project to verify compatibility; replace stubs with real P/Invoke as Rust progresses.

## Commands
- Build: `cargo build --lib --release`
- Headers: `cbindgen --lang c --output include/linux_wmi.h`
- Test: Run C# unit tests with shim vs ORMi on Windows.

## Implementation Plan
Phase 1: DCOM Endpoint Mapper (TCP 135, TowerConnect for IWbemLocator UUID, port resolution).
- Mod: dcom.rs (errors, connect/parse).
- Status: Stubbed in session_new; connects to 135, sends basic Tower, parses port (full per MS-EPMR 2.2).

Phase 2: RPC Bind (MS-RPCE over dynamic port, bind to WMI service UUID).
- Mod: rpc.rs (PDU build/bind/auth negotiate).
- Auth: NTLMv2 (auth.rs stub with HMAC/MD5; full challenge-response).

Phase 3: WMI Protocol (MS-WMI: ConnectServer to namespace, ExecQuery WQL).
- Mod: wmi.rs (IWbemServices proxy, WQL parser, CIM result marshal to JSON).
- Queries: Support spec WQL (SELECT fields FROM class WHERE...); fallbacks (e.g., Win32_Volume).

Phase 4: FFI Integration & Errors (HRESULT mapping, timeouts, JSON schemas per class).
- Errors: Map to spec HRESULT (e.g., 0x800706BA RPC_S_SERVER_UNAVAILABLE).
- JSON: Exact prop names/types from spec schemas (e.g., Win32_Processor.Name string).

Phase 5: Testing (unit for protocols, integration with C# shim on Windows target).
- Golden: Match ORMi JSON output.
- Fallbacks: OS detection via OS query, netstat stub for old TCP connections.

Current: Phase 1 stub; builds, connects to 135, logs port (test with real Windows host).

## Code Style
- Rust: snake_case, safe wrappers over unsafe FFI.
- C#: Match ORMi signatures; JsonPropertyName for props.
- No comments unless requested.

## Compatibility
Follow spec: Namespaces (root/CimV2+), auth levels, HRESULT errors, OS fallbacks (2003+).
