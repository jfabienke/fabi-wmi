using System;
using System.Collections.Generic;

namespace LinuxWmi.E2ETests.Infrastructure
{
    /// <summary>
    /// Interface for WMI operations to enable mocking in tests
    /// </summary>
    public interface IWMIHelper : IDisposable
    {
        /// <summary>
        /// Query WMI for all instances of a class
        /// </summary>
        IEnumerable<T> Query<T>() where T : class;

        /// <summary>
        /// Query WMI with a custom WQL query
        /// </summary>
        IEnumerable<T> Query<T>(string wql) where T : class;

        /// <summary>
        /// Query WMI and return the first result or null
        /// </summary>
        T? QueryFirstOrDefault<T>(string wql) where T : class;

        /// <summary>
        /// Execute a static method on a WMI class
        /// </summary>
        T ExecuteStaticMethod<T>(string className, string methodName, object? inParams = null);

        /// <summary>
        /// Execute an instance method on a WMI object
        /// </summary>
        T ExecuteInstanceMethod<T>(string objectPath, string methodName, object? inParams = null);
    }
}