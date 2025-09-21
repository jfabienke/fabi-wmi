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
    public class Priority0_ConnectionTests : E2ETestBase
    {
        public Priority0_ConnectionTests(ITestOutputHelper output) : base(output) { }

        [Fact]
        public void Test001_SuccessfulConnection_WithValidCredentials()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            var host = Config.GetPrimaryHost();

            // Act
            WMIHelper? helper = null;
            var exception = Record.Exception(() =>
            {
                helper = CreateWmiHelper(host);
            });

            // Assert
            exception.Should().BeNull("connection with valid credentials should succeed");
            helper.Should().NotBeNull();

            Output.WriteLine("✅ Successfully connected and authenticated to WMI endpoint");

            // Cleanup
            helper?.Dispose();
        }

        [Fact]
        public void Test002_ConnectionCreation_DoesNotThrow()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();

            // Act & Assert
            using var helper = CreateWmiHelper();

            // If we got here without exception, the test passed
            Output.WriteLine("✅ WMIHelper instance created successfully without throwing");
        }

        [Fact]
        public void Test003_MultipleConnectionsSequential_Succeed()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            var host = Config.GetPrimaryHost();

            // Act & Assert
            for (int i = 1; i <= 3; i++)
            {
                Output.WriteLine($"Creating connection #{i}...");

                using var helper = CreateWmiHelper(host);
                helper.Should().NotBeNull($"connection #{i} should succeed");

                Output.WriteLine($"✅ Connection #{i} succeeded");
            }
        }

        [Fact]
        public void Test004_ConnectionWithDifferentAuthLevels_Succeed()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            var host = Config.GetPrimaryHost();

            var authLevels = new[]
            {
                (WmiAuthLevel.Connect, "Connect"),
                (WmiAuthLevel.Call, "Call"),
                (WmiAuthLevel.Packet, "Packet"),
                (WmiAuthLevel.PacketPrivacy, "PacketPrivacy")
            };

            // Act & Assert
            foreach (var (authLevel, name) in authLevels)
            {
                Output.WriteLine($"Testing connection with auth level: {name}");

                using var helper = new WMIHelper(
                    scope: "CimV2",
                    host: host.Host,
                    username: host.Username,
                    password: host.Password,
                    domain: host.Domain,
                    auth: authLevel,
                    timeout: Config.DefaultTimeout
                );

                helper.Should().NotBeNull($"connection with {name} auth level should succeed");
                Output.WriteLine($"✅ Connection with {name} auth level succeeded");
            }
        }

        [Fact]
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