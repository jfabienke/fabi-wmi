// Arqitekta.WmiShim/WMIHelper.cs
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Arqitekta.WmiShim
{
    public enum WmiAuthLevel
    {
        Default = 0,
        None = 1,
        Connect = 2,
        Call = 3,
        Packet = 4,
        PacketPrivacy = 5
    }

    public class WmiException : Exception
    {
        public int Code { get; }
        public WmiException(int code, string message) : base(message)
        {
            Code = code;
        }
    }

    internal sealed class SafeSessionHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeSessionHandle() : base(true) { }

        internal static SafeSessionHandle? Create(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
            {
                return null;
            }

            var handle = new SafeSessionHandle();
            handle.SetHandle(ptr);
            return handle;
        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.WmiSessionFree(handle);
            return true;
        }
    }

    internal static class NativeMethods
    {
        private const string LibName = "linux_wmi";

        [DllImport(LibName, EntryPoint = "wmi_session_new", CallingConvention = CallingConvention.Cdecl)]
        private static extern int wmi_session_new_internal(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string host,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string username,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string password,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string domain,
            uint authFlags,
            out IntPtr session,
            out IntPtr errPtr);

        [DllImport(LibName, EntryPoint = "wmi_namespace_open", CallingConvention = CallingConvention.Cdecl)]
        private static extern int wmi_namespace_open_internal(IntPtr session, [MarshalAs(UnmanagedType.LPUTF8Str)] string ns, out IntPtr errPtr);

        [DllImport(LibName, EntryPoint = "wmi_exec_query_json", CallingConvention = CallingConvention.Cdecl)]
        private static extern int wmi_exec_query_json_internal(
            IntPtr session,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string wql,
            uint timeoutMs,
            out IntPtr jsonPtr,
            out UIntPtr jsonLen,
            out IntPtr errPtr);

        [DllImport(LibName, EntryPoint = "wmi_exec_method_json", CallingConvention = CallingConvention.Cdecl)]
        private static extern int wmi_exec_method_json_internal(
            IntPtr session,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string pathOrClass,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string method,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string inParamsJson,
            uint timeoutMs,
            out IntPtr jsonPtr,
            out UIntPtr jsonLen,
            out IntPtr errPtr);

        [DllImport(LibName, EntryPoint = "wmi_session_free", CallingConvention = CallingConvention.Cdecl)]
        private static extern void wmi_session_free_internal(IntPtr session);

        [DllImport(LibName, EntryPoint = "wmi_free_json", CallingConvention = CallingConvention.Cdecl)]
        private static extern void wmi_free_json_internal(IntPtr ptr, UIntPtr len);

        [DllImport(LibName, EntryPoint = "wmi_free_err", CallingConvention = CallingConvention.Cdecl)]
        private static extern void wmi_free_err_internal(IntPtr ptr);

        private static string PtrToStringUtf8(IntPtr ptr, UIntPtr len)
        {
            if (ptr == IntPtr.Zero)
            {
                return string.Empty;
            }

            if (len == UIntPtr.Zero)
            {
                return Marshal.PtrToStringUTF8(ptr) ?? string.Empty;
            }

            ulong length = len.ToUInt64();
            if (length == 0)
            {
                return string.Empty;
            }

            if (length > int.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(len), "JSON payload too large to marshal");
            }

            return Marshal.PtrToStringUTF8(ptr, (int)length) ?? string.Empty;
        }

        private static void FreeUtf8(IntPtr ptr)
        {
            if (ptr != IntPtr.Zero)
            {
                wmi_free_err_internal(ptr);
            }
        }

        internal static int WmiSessionNew(string host, string? username, string? password, string? domain, WmiAuthLevel auth, out SafeSessionHandle? session, out string? error)
        {
            IntPtr sessionPtr;
            IntPtr errPtr;
            int rc = wmi_session_new_internal(
                host,
                username ?? string.Empty,
                password ?? string.Empty,
                domain ?? string.Empty,
                (uint)auth,
                out sessionPtr,
                out errPtr);

            error = PtrToStringUtf8(errPtr, UIntPtr.Zero);
            FreeUtf8(errPtr);
            session = SafeSessionHandle.Create(sessionPtr);
            if (rc != 0 && session != null)
            {
                session.Dispose();
                session = null;
            }
            return rc;
        }

        internal static int WmiNamespaceOpen(SafeSessionHandle session, string ns, out string? error)
        {
            IntPtr errPtr;
            int rc = wmi_namespace_open_internal(session.DangerousGetHandle(), ns, out errPtr);
            error = PtrToStringUtf8(errPtr, UIntPtr.Zero);
            FreeUtf8(errPtr);
            return rc;
        }

        internal static int WmiExecQueryJson(SafeSessionHandle session, string wql, uint timeoutMs, out string json, out string? error)
        {
            IntPtr jsonPtr;
            UIntPtr jsonLen;
            IntPtr errPtr;
            int rc = wmi_exec_query_json_internal(session.DangerousGetHandle(), wql, timeoutMs, out jsonPtr, out jsonLen, out errPtr);
            json = PtrToStringUtf8(jsonPtr, jsonLen);
            error = PtrToStringUtf8(errPtr, UIntPtr.Zero);
            if (jsonPtr != IntPtr.Zero)
            {
                wmi_free_json_internal(jsonPtr, jsonLen);
            }
            FreeUtf8(errPtr);
            return rc;
        }

        internal static int WmiExecMethodJson(SafeSessionHandle session, string pathOrClass, string method, string? inParamsJson, uint timeoutMs, out string json, out string? error)
        {
            IntPtr jsonPtr;
            UIntPtr jsonLen;
            IntPtr errPtr;
            int rc = wmi_exec_method_json_internal(
                session.DangerousGetHandle(),
                pathOrClass,
                method,
                inParamsJson ?? string.Empty,
                timeoutMs,
                out jsonPtr,
                out jsonLen,
                out errPtr);
            json = PtrToStringUtf8(jsonPtr, jsonLen);
            error = PtrToStringUtf8(errPtr, UIntPtr.Zero);
            if (jsonPtr != IntPtr.Zero)
            {
                wmi_free_json_internal(jsonPtr, jsonLen);
            }
            FreeUtf8(errPtr);
            return rc;
        }

        internal static void WmiSessionFree(IntPtr session)
        {
            if (session != IntPtr.Zero)
            {
                wmi_session_free_internal(session);
            }
        }
    }

    public sealed class WMIHelper : IDisposable
    {
        private SafeSessionHandle? _session;
        private readonly string _namespace;
        private readonly JsonSerializerOptions _jsonOptions = new() { PropertyNameCaseInsensitive = true };
        private readonly uint _timeoutMs;

        public WMIHelper(
            string scope,
            string? host = "localhost",
            string? username = null,
            string? password = null,
            string? domain = null,
            WmiAuthLevel auth = WmiAuthLevel.PacketPrivacy,
            TimeSpan? timeout = null)
        {
            if (string.IsNullOrWhiteSpace(scope))
            {
                throw new ArgumentException("Scope must be provided", nameof(scope));
            }

            scope = scope.TrimStart('\\', '/');
            _namespace = $"root\\{scope.Replace('/', '\\')}";
            _timeoutMs = (uint)(timeout?.TotalMilliseconds ?? 30_000);

            int rc = NativeMethods.WmiSessionNew(host ?? "localhost", username, password, domain, auth, out _session, out var err);
            if (rc != 0 || _session == null)
            {
                throw new WmiException(rc, err ?? "Failed to create session");
            }

            rc = NativeMethods.WmiNamespaceOpen(_session, _namespace, out err);
            if (rc != 0)
            {
                _session.Dispose();
                _session = null;
                throw new WmiException(rc, err ?? "Failed to open namespace");
            }
        }

        public IEnumerable<T> Query<T>() where T : class
        {
            string className = typeof(T).Name;
            return Query<T>($"SELECT * FROM {className}");
        }

        public IEnumerable<T> Query<T>(string wql) where T : class
        {
            EnsureSession();
            int rc = NativeMethods.WmiExecQueryJson(_session!, wql, _timeoutMs, out var json, out var err);
            if (rc != 0)
            {
                throw new WmiException(rc, err ?? "Query failed");
            }

            if (string.IsNullOrWhiteSpace(json))
            {
                yield break;
            }

            var items = JsonSerializer.Deserialize<List<T>>(json, _jsonOptions) ?? new List<T>();
            foreach (var item in items)
            {
                yield return item;
            }
        }

        public T? QueryFirstOrDefault<T>(string wql) where T : class
        {
            foreach (var item in Query<T>(wql))
            {
                return item;
            }
            return null;
        }

        public T ExecuteStaticMethod<T>(string className, string methodName, object? inParams = null)
        {
            EnsureSession();
            string payload = inParams != null ? JsonSerializer.Serialize(inParams) : "{}";
            int rc = NativeMethods.WmiExecMethodJson(_session!, className, methodName, payload, _timeoutMs, out var json, out var err);
            if (rc != 0)
            {
                throw new WmiException(rc, err ?? "Method execution failed");
            }

            return JsonSerializer.Deserialize<T>(json, _jsonOptions)
                   ?? throw new InvalidOperationException("Method returned no payload");
        }

        private void EnsureSession()
        {
            if (_session == null || _session.IsInvalid)
            {
                throw new ObjectDisposedException(nameof(WMIHelper));
            }
        }

        public void Dispose()
        {
            _session?.Dispose();
            _session = null;
        }
    }
}
