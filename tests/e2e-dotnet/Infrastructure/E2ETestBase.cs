using System;
using Xunit;
using Xunit.Abstractions;
using Arqitekta.WmiShim;

namespace LinuxWmi.E2ETests.Infrastructure
{
    public abstract class E2ETestBase : IDisposable
    {
        protected readonly ITestOutputHelper Output;
        protected readonly TestConfiguration Config;
        protected WMIHelper? WmiHelper;

        protected E2ETestBase(ITestOutputHelper output)
        {
            Output = output;
            Config = new TestConfiguration();

            if (Config.VerboseLogging)
            {
                Output.WriteLine($"Test Configuration:");
                Output.WriteLine($"  Host: {Config.DefaultHost}");
                Output.WriteLine($"  Username: {Config.DefaultUsername}");
                Output.WriteLine($"  Domain: {Config.DefaultDomain ?? "<local>"}");
                Output.WriteLine($"  Timeout: {Config.DefaultTimeout}");
            }
        }

        protected WMIHelper CreateWmiHelper(TestHost? host = null)
        {
            host ??= Config.GetPrimaryHost();

            Output.WriteLine($"Connecting to {host.Host} as {host.Username}...");

            return new WMIHelper(
                scope: "CimV2",
                host: host.Host,
                username: host.Username,
                password: host.Password,
                domain: host.Domain,
                auth: WmiAuthLevel.PacketPrivacy,
                timeout: Config.DefaultTimeout
            );
        }

        protected void SkipIfNetworkTestsDisabled()
        {
            Skip.If(Config.SkipNetworkTests, "Network tests are disabled in configuration");
        }

        protected void SkipIfAuthTestsDisabled()
        {
            Skip.If(Config.SkipAuthTests, "Authentication tests are disabled in configuration");
        }

        protected void AssertWmiException(Action action, int? expectedCode = null, string? messageContains = null)
        {
            var exception = Assert.Throws<WmiException>(action);

            if (expectedCode.HasValue)
            {
                Assert.Equal(expectedCode.Value, exception.Code);
            }

            if (!string.IsNullOrEmpty(messageContains))
            {
                Assert.Contains(messageContains, exception.Message, StringComparison.OrdinalIgnoreCase);
            }

            Output.WriteLine($"Caught expected WmiException: Code={exception.Code}, Message={exception.Message}");
        }

        public virtual void Dispose()
        {
            WmiHelper?.Dispose();
        }
    }
}