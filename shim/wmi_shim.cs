// Arqitekta.WmiShim/WMIHelper.cs
using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
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
        private readonly JsonSerializerOptions _jsonOptions = WmiJson.CreateOptions();
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

            if (typeof(T) == typeof(object))
            {
                // Query<dynamic>: rows become ExpandoObjects so members bind by name.
                using var doc = JsonDocument.Parse(json);
                foreach (var row in doc.RootElement.EnumerateArray())
                {
                    yield return (T)WmiJson.ToDynamic(row)!;
                }
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
    /// JSON handling that matches what ORMi hands back on Windows: WMI's
    /// DMTF datetimes and intervals bind to DateTime/DateTimeOffset/TimeSpan,
    /// numbers WMI types as strings (e.g. BuildNumber) bind to numeric
    /// properties, and dynamic rows are ExpandoObjects.
    internal static class WmiJson
    {
        internal static JsonSerializerOptions CreateOptions()
        {
            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                NumberHandling = JsonNumberHandling.AllowReadingFromString,
            };
            options.Converters.Add(new DmtfDateTimeConverter());
            options.Converters.Add(new DmtfDateTimeOffsetConverter());
            options.Converters.Add(new DmtfTimeSpanConverter());
            return options;
        }

        internal static object? ToDynamic(JsonElement element)
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.Object:
                    IDictionary<string, object?> obj = new ExpandoObject();
                    foreach (var prop in element.EnumerateObject())
                    {
                        obj[prop.Name] = ToDynamic(prop.Value);
                    }
                    return obj;
                case JsonValueKind.Array:
                    var list = new List<object?>();
                    foreach (var item in element.EnumerateArray())
                    {
                        list.Add(ToDynamic(item));
                    }
                    return list;
                case JsonValueKind.String:
                    return element.GetString();
                case JsonValueKind.Number:
                    if (element.TryGetInt64(out var l)) return l;
                    if (element.TryGetUInt64(out var ul)) return ul;
                    return element.GetDouble();
                case JsonValueKind.True:
                    return true;
                case JsonValueKind.False:
                    return false;
                default:
                    return null;
            }
        }
    }

    /// DMTF CIM_DATETIME / interval parsing (yyyymmddHHMMSS.mmmmmmsUUU and
    /// ddddddddHHMMSS.mmmmmm:000).
    internal static class Dmtf
    {
        internal static bool TryParseDateTime(string s, out DateTimeOffset value)
        {
            value = default;
            if (s.Length != 25 || s[14] != '.' || (s[21] != '+' && s[21] != '-'))
                return false;
            if (!DateTime.TryParseExact(s.Substring(0, 14), "yyyyMMddHHmmss",
                    CultureInfo.InvariantCulture, DateTimeStyles.None, out var dt))
                return false;
            if (!int.TryParse(s.AsSpan(15, 6), NumberStyles.None, CultureInfo.InvariantCulture, out var micros) ||
                !int.TryParse(s.AsSpan(22, 3), NumberStyles.None, CultureInfo.InvariantCulture, out var offsetMinutes))
                return false;
            if (s[21] == '-')
                offsetMinutes = -offsetMinutes;
            value = new DateTimeOffset(dt.AddTicks(micros * 10L), TimeSpan.FromMinutes(offsetMinutes));
            return true;
        }

        internal static bool TryParseInterval(string s, out TimeSpan value)
        {
            value = default;
            if (s.Length != 25 || s[14] != '.' || s[21] != ':')
                return false;
            var inv = CultureInfo.InvariantCulture;
            if (!int.TryParse(s.AsSpan(0, 8), NumberStyles.None, inv, out var days) ||
                !int.TryParse(s.AsSpan(8, 2), NumberStyles.None, inv, out var hours) ||
                !int.TryParse(s.AsSpan(10, 2), NumberStyles.None, inv, out var minutes) ||
                !int.TryParse(s.AsSpan(12, 2), NumberStyles.None, inv, out var seconds) ||
                !int.TryParse(s.AsSpan(15, 6), NumberStyles.None, inv, out var micros))
                return false;
            value = new TimeSpan(days, hours, minutes, seconds) + TimeSpan.FromTicks(micros * 10L);
            return true;
        }
    }

    internal sealed class DmtfDateTimeConverter : JsonConverter<DateTime>
    {
        public override DateTime Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            var s = reader.GetString() ?? throw new JsonException("Expected a datetime string");
            // ORMi (ManagementDateTimeConverter.ToDateTime) yields local time.
            return Dmtf.TryParseDateTime(s, out var dmtf)
                ? dmtf.LocalDateTime
                : DateTime.Parse(s, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
        }

        public override void Write(Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options) =>
            writer.WriteStringValue(value);
    }

    internal sealed class DmtfDateTimeOffsetConverter : JsonConverter<DateTimeOffset>
    {
        public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            var s = reader.GetString() ?? throw new JsonException("Expected a datetime string");
            return Dmtf.TryParseDateTime(s, out var dmtf)
                ? dmtf
                : DateTimeOffset.Parse(s, CultureInfo.InvariantCulture);
        }

        public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options) =>
            writer.WriteStringValue(value);
    }

    internal sealed class DmtfTimeSpanConverter : JsonConverter<TimeSpan>
    {
        public override TimeSpan Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            var s = reader.GetString() ?? throw new JsonException("Expected an interval string");
            return Dmtf.TryParseInterval(s, out var interval)
                ? interval
                : TimeSpan.Parse(s, CultureInfo.InvariantCulture);
        }

        public override void Write(Utf8JsonWriter writer, TimeSpan value, JsonSerializerOptions options) =>
            writer.WriteStringValue(value.ToString("c", CultureInfo.InvariantCulture));
    }
}
