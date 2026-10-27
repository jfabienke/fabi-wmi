using System;
using Xunit;
using Xunit.Abstractions;
using Arqitekta.WmiShim;

namespace LinuxWmi.E2ETests.Infrastructure
{
    public abstract class E2ETestBase
    {
        protected readonly ITestOutputHelper Output;
        protected readonly TestConfiguration Config;

        protected E2ETestBase(ITestOutputHelper output)
        {
            Output = output;
            Config = new TestConfiguration();

            if (Config.VerboseLogging)
            {
                Output.WriteLine($"Test Configuration:");
                Output.WriteLine($"  Host: {Config.Host}");
                Output.WriteLine($"  Username: {Config.Username}");
                Output.WriteLine($"  Domain: {(string.IsNullOrEmpty(Config.Domain) ? "<local>" : Config.Domain)}");
                Output.WriteLine($"  Timeout: {Config.DefaultTimeout}");
            }
        }

        /// <summary>A helper on root\cimv2 of the configured host.</summary>
        protected WMIHelper CreateWmiHelper()
        {
            Output.WriteLine($"Connecting to {Config.Host} as {Config.Username}...");

            return new WMIHelper(
                scope: "CimV2",
                host: Config.Host,
                username: Config.Username,
                password: Config.Password,
                domain: Config.Domain,
                auth: WmiAuthLevel.PacketPrivacy,
                timeout: Config.DefaultTimeout
            );
        }

        /// <summary>
        /// Live tests need a Windows host: they are skipped when none is
        /// configured or when network tests are disabled.
        /// </summary>
        protected void SkipIfNetworkTestsDisabled()
        {
            Skip.If(Config.SkipNetworkTests, "Network tests are disabled in configuration");
            Skip.If(string.IsNullOrEmpty(Config.Host), "No test host: set WMI_TEST_DEFAULTHOST and its credentials");
        }

        protected void SkipIfAuthTestsDisabled()
        {
            SkipIfNetworkTestsDisabled();
            Skip.If(Config.SkipAuthTests, "Authentication tests are disabled in configuration");
        }

        protected WmiException AssertWmiException(Action action, int? expectedCode = null, string? messageContains = null)
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

            Output.WriteLine($"Caught expected WmiException: Code=0x{exception.Code:x8}, Message={exception.Message}");
            return exception;
        }
    }
}
