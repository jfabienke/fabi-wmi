using Xunit;
using Xunit.Abstractions;
using FluentAssertions;
using Arqitekta.WmiShim;
using LinuxWmi.E2ETests.Infrastructure;

namespace LinuxWmi.E2ETests.Tests
{
    /// <summary>
    /// Priority 0: Critical Path - Connection and Authentication Tests
    /// These tests verify that the client can connect to the WMI endpoint and authenticate successfully.
    /// </summary>
    [Trait("Category", "Priority0")]
    public class Priority0_ConnectionTests : E2ETestBase
    {
        public Priority0_ConnectionTests(ITestOutputHelper output) : base(output) { }

        [SkippableFact]
        public void Test001_SuccessfulConnection_WithValidCredentials()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();

            // Act
            WMIHelper? helper = null;
            var exception = Record.Exception(() =>
            {
                helper = CreateWmiHelper();
            });

            // Assert
            exception.Should().BeNull("connection with valid credentials should succeed");
            helper.Should().NotBeNull();

            Output.WriteLine("✅ Successfully connected and authenticated to WMI endpoint");

            // Cleanup
            helper?.Dispose();
        }

        [SkippableFact]
        public void Test003_MultipleConnectionsSequential_Succeed()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();

            // Act & Assert
            for (int i = 1; i <= 3; i++)
            {
                Output.WriteLine($"Creating connection #{i}...");

                using var helper = CreateWmiHelper();
                helper.Should().NotBeNull($"connection #{i} should succeed");

                Output.WriteLine($"✅ Connection #{i} succeeded");
            }
        }

        /// <summary>
        /// ORMi callers pass an authentication level; the library accepts every
        /// value and only logs it (activation is always sealed, WMI calls are
        /// always signed).
        /// </summary>
        [SkippableFact]
        public void Test004_EveryAuthLevel_IsAccepted()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();

            var authLevels = new[]
            {
                WmiAuthLevel.Default,
                WmiAuthLevel.Connect,
                WmiAuthLevel.Call,
                WmiAuthLevel.Packet,
                WmiAuthLevel.PacketPrivacy
            };

            // Act & Assert
            foreach (var authLevel in authLevels)
            {
                Output.WriteLine($"Testing connection with auth level: {authLevel}");

                using var helper = new WMIHelper(
                    scope: "CimV2",
                    host: Config.Host,
                    username: Config.Username,
                    password: Config.Password,
                    domain: Config.Domain,
                    auth: authLevel,
                    timeout: Config.DefaultTimeout
                );

                helper.Should().NotBeNull($"connection with {authLevel} auth level should succeed");
                Output.WriteLine($"✅ Connection with {authLevel} auth level succeeded");
            }
        }

        [SkippableFact]
        public void Test005_ConnectionDisposal_CanBeCalledMultipleTimes()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            var helper = CreateWmiHelper();

            // Act & Assert
            var exception = Record.Exception(() =>
            {
                helper.Dispose();
                helper.Dispose(); // Second dispose should not throw
                helper.Dispose(); // Third dispose should not throw
            });

            exception.Should().BeNull("multiple Dispose calls should not throw");
            Output.WriteLine("✅ Multiple Dispose calls handled gracefully");
        }
    }
}
