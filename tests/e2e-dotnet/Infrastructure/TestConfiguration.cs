using Microsoft.Extensions.Configuration;
using System;
using System.IO;

namespace LinuxWmi.E2ETests.Infrastructure
{
    public class TestConfiguration
    {
        private readonly IConfiguration _configuration;

        public TestConfiguration()
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: false)
                .AddEnvironmentVariables(prefix: "WMI_TEST_");

            _configuration = builder.Build();
        }

        public string DefaultHost => GetValue("DefaultHost", "localhost");
        public string DefaultUsername => GetValue("DefaultUsername", "wmi-test");
        public string DefaultPassword => GetValue("DefaultPassword", "P@ssw0rd123");
        public string DefaultDomain => GetValue("DefaultDomain", "");
        public TimeSpan DefaultTimeout => TimeSpan.Parse(GetValue("DefaultTimeout", "00:00:30"));
        public bool SkipNetworkTests => bool.Parse(GetValue("SkipNetworkTests", "false"));
        public bool SkipAuthTests => bool.Parse(GetValue("SkipAuthTests", "false"));
        public bool VerboseLogging => bool.Parse(GetValue("VerboseLogging", "true"));

        public TestHost GetPrimaryHost()
        {
            return new TestHost
            {
                Host = GetValue("TestHosts:Primary:Host", DefaultHost),
                Username = GetValue("TestHosts:Primary:Username", DefaultUsername),
                Password = GetValue("TestHosts:Primary:Password", DefaultPassword),
                Domain = GetValue("TestHosts:Primary:Domain", DefaultDomain)
            };
        }

        public TestHost GetSecondaryHost()
        {
            return new TestHost
            {
                Host = GetValue("TestHosts:Secondary:Host", "192.168.1.101"),
                Username = GetValue("TestHosts:Secondary:Username", "admin"),
                Password = GetValue("TestHosts:Secondary:Password", "AdminPass123"),
                Domain = GetValue("TestHosts:Secondary:Domain", "TESTDOMAIN")
            };
        }

        private string GetValue(string key, string defaultValue)
        {
            // First check environment variables with WMI_TEST_ prefix
            var envKey = $"WMI_TEST_{key.Replace(":", "_").ToUpper()}";
            var envValue = Environment.GetEnvironmentVariable(envKey);
            if (!string.IsNullOrEmpty(envValue))
                return envValue;

            // Then check configuration
            var configValue = _configuration[$"TestConfiguration:{key}"];
            return string.IsNullOrEmpty(configValue) ? defaultValue : configValue;
        }
    }

    public class TestHost
    {
        public string Host { get; set; } = "localhost";
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";
        public string Domain { get; set; } = "";
    }
}