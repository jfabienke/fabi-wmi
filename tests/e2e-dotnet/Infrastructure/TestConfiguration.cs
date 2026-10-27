using Microsoft.Extensions.Configuration;
using System;

namespace LinuxWmi.E2ETests.Infrastructure
{
    /// <summary>
    /// Settings from the TestConfiguration section of appsettings.json, each
    /// overridable by a WMI_TEST_&lt;NAME&gt; environment variable (for example
    /// WMI_TEST_DEFAULTHOST).
    /// </summary>
    public class TestConfiguration
    {
        private readonly IConfiguration _configuration = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: true, reloadOnChange: false)
            .Build();

        public string Host => GetValue("DefaultHost", "");
        public string Username => GetValue("DefaultUsername", "");
        public string Password => GetValue("DefaultPassword", "");
        public string Domain => GetValue("DefaultDomain", "");
        public TimeSpan DefaultTimeout => TimeSpan.Parse(GetValue("DefaultTimeout", "00:00:30"));
        public bool SkipNetworkTests => bool.Parse(GetValue("SkipNetworkTests", "false"));
        public bool SkipAuthTests => bool.Parse(GetValue("SkipAuthTests", "false"));
        public bool VerboseLogging => bool.Parse(GetValue("VerboseLogging", "true"));

        private string GetValue(string key, string defaultValue)
        {
            var value = Environment.GetEnvironmentVariable($"WMI_TEST_{key.ToUpperInvariant()}");
            if (string.IsNullOrEmpty(value))
            {
                value = _configuration[$"TestConfiguration:{key}"];
            }
            return string.IsNullOrEmpty(value) ? defaultValue : value;
        }
    }
}
