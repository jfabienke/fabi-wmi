using System;
using System.Collections.Generic;
using System.Linq;
using System.Dynamic;
using Arqitekta.WmiShim;

namespace LinuxWmi.E2ETests.Infrastructure
{
    /// <summary>
    /// Mock implementation of IWMIHelper for testing without a Windows host
    /// </summary>
    public class MockWMIHelper : IWMIHelper
    {
        private readonly Dictionary<string, Func<object>> _queryResponses = new();
        private readonly Dictionary<string, object> _methodResponses = new();
        private bool _disposed = false;

        public MockWMIHelper()
        {
            SetupDefaultResponses();
        }

        private void SetupDefaultResponses()
        {
            // Default Win32_Process responses
            _queryResponses["Win32_Process"] = () => new[]
            {
                new { Name = "System", ProcessId = 4u, ParentProcessId = 0u, HandleCount = 1500u },
                new { Name = "services.exe", ProcessId = 688u, ParentProcessId = 520u, HandleCount = 500u },
                new { Name = "svchost.exe", ProcessId = 1024u, ParentProcessId = 688u, HandleCount = 300u }
            };

            // Default Win32_ComputerSystem response
            _queryResponses["Win32_ComputerSystem"] = () => new[]
            {
                new
                {
                    Name = "MOCK-PC",
                    Domain = "WORKGROUP",
                    Manufacturer = "Mock Manufacturer",
                    Model = "Mock Model",
                    NumberOfProcessors = 4u,
                    TotalPhysicalMemory = 8589934592ul // 8GB
                }
            };

            // Default Win32_OperatingSystem response
            _queryResponses["Win32_OperatingSystem"] = () => new[]
            {
                new
                {
                    Name = "Microsoft Windows 10 Pro",
                    Version = "10.0.19043",
                    BuildNumber = "19043",
                    CSName = "MOCK-PC",
                    InstallDate = DateTime.Now.AddDays(-180),
                    LastBootUpTime = DateTime.Now.AddHours(-24)
                }
            };

            // Default method responses
            _methodResponses["Win32_Process.GetOwner"] = new { ReturnValue = 0u, Domain = "NT AUTHORITY", User = "SYSTEM" };
            _methodResponses["Win32_Process.Create"] = new { ReturnValue = 0u, ProcessId = 9999u };
            _methodResponses["Win32_Process.Terminate"] = new { ReturnValue = 0u };
        }

        public void ConfigureQueryResponse(string className, Func<object> responseGenerator)
        {
            _queryResponses[className] = responseGenerator;
        }

        public void ConfigureMethodResponse(string methodKey, object response)
        {
            _methodResponses[methodKey] = response;
        }

        public IEnumerable<T> Query<T>() where T : class
        {
            EnsureNotDisposed();
            string className = typeof(T).Name;
            return Query<T>($"SELECT * FROM {className}");
        }

        public IEnumerable<T> Query<T>(string wql) where T : class
        {
            EnsureNotDisposed();

            // Parse the class name from WQL (simplified)
            var className = ExtractClassNameFromWql(wql);

            if (_queryResponses.TryGetValue(className, out var responseGenerator))
            {
                var response = responseGenerator();
                if (response is IEnumerable<object> enumerable)
                {
                    // Apply WHERE clause filtering if present (simplified)
                    var filtered = ApplyWhereClause(enumerable, wql);

                    // Convert to requested type
                    if (typeof(T) == typeof(object) || typeof(T) == typeof(ExpandoObject))
                    {
                        return filtered.Cast<T>();
                    }

                    // Convert anonymous types to T using JSON serialization
                    var json = System.Text.Json.JsonSerializer.Serialize(filtered);
                    var result = System.Text.Json.JsonSerializer.Deserialize<List<T>>(json,
                        new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    return result ?? new List<T>();
                }
            }

            return Enumerable.Empty<T>();
        }

        public T? QueryFirstOrDefault<T>(string wql) where T : class
        {
            return Query<T>(wql).FirstOrDefault();
        }

        public T ExecuteStaticMethod<T>(string className, string methodName, object? inParams = null)
        {
            EnsureNotDisposed();

            var methodKey = $"{className}.{methodName}";
            if (_methodResponses.TryGetValue(methodKey, out var response))
            {
                if (typeof(T) == typeof(object) || typeof(T) == typeof(ExpandoObject))
                {
                    return (T)response;
                }

                // Convert to requested type using JSON serialization
                var json = System.Text.Json.JsonSerializer.Serialize(response);
                var result = System.Text.Json.JsonSerializer.Deserialize<T>(json,
                    new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                if (result == null)
                    throw new InvalidOperationException($"Method {methodKey} returned null");

                return result;
            }

            throw new WmiException(-1, $"Mock method {methodKey} not configured");
        }

        public T ExecuteInstanceMethod<T>(string objectPath, string methodName, object? inParams = null)
        {
            // For simplicity, treat as static method in mock
            var className = objectPath.Split('.')[0];
            return ExecuteStaticMethod<T>(className, methodName, inParams);
        }

        private string ExtractClassNameFromWql(string wql)
        {
            // Simple extraction - finds class name after FROM keyword
            var upperWql = wql.ToUpperInvariant();
            var fromIndex = upperWql.IndexOf("FROM ");
            if (fromIndex >= 0)
            {
                var startIndex = fromIndex + 5;
                var endIndex = upperWql.IndexOfAny(new[] { ' ', '\r', '\n', '\t' }, startIndex);
                if (endIndex < 0) endIndex = upperWql.Length;

                var className = wql.Substring(startIndex, endIndex - startIndex);
                return className.Trim();
            }

            throw new ArgumentException($"Invalid WQL query: {wql}");
        }

        private IEnumerable<object> ApplyWhereClause(IEnumerable<object> data, string wql)
        {
            // Simplified WHERE clause handling
            var upperWql = wql.ToUpperInvariant();
            if (!upperWql.Contains("WHERE"))
                return data;

            // For mock purposes, just return first few items or filter by specific known conditions
            if (upperWql.Contains("PROCESSID = 4"))
            {
                return data.Where(item =>
                {
                    var propInfo = item.GetType().GetProperty("ProcessId");
                    if (propInfo != null)
                    {
                        var value = propInfo.GetValue(item);
                        return value?.Equals(4u) ?? false;
                    }
                    return false;
                });
            }

            if (upperWql.Contains("NAME = 'SERVICES.EXE'"))
            {
                return data.Where(item =>
                {
                    var propInfo = item.GetType().GetProperty("Name");
                    if (propInfo != null)
                    {
                        var value = propInfo.GetValue(item)?.ToString();
                        return string.Equals(value, "services.exe", StringComparison.OrdinalIgnoreCase);
                    }
                    return false;
                });
            }

            // Check for non-existent process filter
            if (upperWql.Contains("THIS_PROCESS_DEFINITELY_DOES_NOT_EXIST") ||
                upperWql.Contains("NONEXISTENT_PROCESS"))
            {
                return Enumerable.Empty<object>();
            }

            return data;
        }

        private void EnsureNotDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(MockWMIHelper));
        }

        public void Dispose()
        {
            _disposed = true;
        }
    }
}