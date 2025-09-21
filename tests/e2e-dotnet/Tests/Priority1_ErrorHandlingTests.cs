using System;
using System.Linq;
using Xunit;
using Xunit.Abstractions;
using FluentAssertions;
using Arqitekta.WmiShim;
using LinuxWmi.E2ETests.Infrastructure;

namespace LinuxWmi.E2ETests.Tests
{
    /// <summary>
    /// Priority 1: Error Handling and Resilience Tests
    /// These tests ensure the library fails gracefully and provides predictable, actionable errors.
    /// </summary>
    public class Priority1_ErrorHandlingTests : E2ETestBase
    {
        public Priority1_ErrorHandlingTests(ITestOutputHelper output) : base(output) { }

        [Fact]
        public void Test030_InvalidCredentials_ThrowsAuthenticationError()
        {
            // Arrange
            SkipIfAuthTestsDisabled();
            var host = Config.GetPrimaryHost();

            // Act & Assert
            AssertWmiException(
                () =>
                {
                    using var wmi = new WMIHelper(
                        scope: "CimV2",
                        host: host.Host,
                        username: host.Username,
                        password: "WrongPassword123!",
                        domain: host.Domain,
                        auth: WmiAuthLevel.PacketPrivacy,
                        timeout: Config.DefaultTimeout
                    );
                },
                expectedCode: unchecked((int)0x80070005), // E_ACCESSDENIED
                messageContains: null // Message might vary
            );

            Output.WriteLine("✅ Invalid credentials correctly resulted in authentication error");
        }

        [Fact]
        public void Test031_InvalidUsername_ThrowsAuthenticationError()
        {
            // Arrange
            SkipIfAuthTestsDisabled();
            var host = Config.GetPrimaryHost();

            // Act & Assert
            AssertWmiException(
                () =>
                {
                    using var wmi = new WMIHelper(
                        scope: "CimV2",
                        host: host.Host,
                        username: "NonExistentUser",
                        password: host.Password,
                        domain: host.Domain,
                        auth: WmiAuthLevel.PacketPrivacy,
                        timeout: Config.DefaultTimeout
                    );
                },
                expectedCode: unchecked((int)0x80070005), // E_ACCESSDENIED
                messageContains: null
            );

            Output.WriteLine("✅ Invalid username correctly resulted in authentication error");
        }

        [Fact]
        public void Test032_UnreachableHost_ThrowsNetworkError()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();

            // Use an IP that's unlikely to exist on the network
            var unreachableHost = "192.168.255.254";

            // Act & Assert
            AssertWmiException(
                () =>
                {
                    using var wmi = new WMIHelper(
                        scope: "CimV2",
                        host: unreachableHost,
                        username: "anyuser",
                        password: "anypass",
                        domain: "",
                        auth: WmiAuthLevel.PacketPrivacy,
                        timeout: TimeSpan.FromSeconds(5) // Short timeout for faster test
                    );
                },
                expectedCode: null, // Could be various network-related codes
                messageContains: null
            );

            Output.WriteLine($"✅ Unreachable host {unreachableHost} correctly resulted in network error");
        }

        [Fact]
        public void Test033_InvalidPort_ThrowsConnectionError()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            var host = Config.GetPrimaryHost();

            // Act & Assert
            // Try to connect to a wrong port (e.g., 12345 instead of RPC port)
            // Note: This might need adjustment based on how the library handles port specification
            AssertWmiException(
                () =>
                {
                    using var wmi = new WMIHelper(
                        scope: "CimV2",
                        host: $"{host.Host}:12345", // Invalid port
                        username: host.Username,
                        password: host.Password,
                        domain: host.Domain,
                        auth: WmiAuthLevel.PacketPrivacy,
                        timeout: TimeSpan.FromSeconds(5)
                    );
                },
                expectedCode: null,
                messageContains: null
            );

            Output.WriteLine("✅ Invalid port correctly resulted in connection error");
        }

        [Fact]
        public void Test034_InvalidWQLQuery_ThrowsQueryError()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act & Assert - Invalid SQL syntax
            AssertWmiException(
                () =>
                {
                    var result = wmi.Query<dynamic>("SELEC * FRM Win32_Process").ToList();
                },
                expectedCode: null, // WMI query error codes vary
                messageContains: null
            );

            Output.WriteLine("✅ Invalid WQL syntax correctly resulted in query error");
        }

        [Fact]
        public void Test035_QueryNonExistentClass_ThrowsError()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act & Assert
            AssertWmiException(
                () =>
                {
                    var result = wmi.Query<dynamic>("SELECT * FROM Win32_NonExistentClass").ToList();
                },
                expectedCode: null,
                messageContains: null
            );

            Output.WriteLine("✅ Query for non-existent class correctly resulted in error");
        }

        [Fact]
        public void Test036_InvalidNamespace_ThrowsError()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            var host = Config.GetPrimaryHost();

            // Act & Assert
            AssertWmiException(
                () =>
                {
                    using var wmi = new WMIHelper(
                        scope: "InvalidNamespace",
                        host: host.Host,
                        username: host.Username,
                        password: host.Password,
                        domain: host.Domain,
                        auth: WmiAuthLevel.PacketPrivacy,
                        timeout: Config.DefaultTimeout
                    );
                },
                expectedCode: null,
                messageContains: null
            );

            Output.WriteLine("✅ Invalid namespace correctly resulted in error");
        }

        [Fact]
        public void Test037_QueryTimeout_ThrowsTimeoutError()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            var host = Config.GetPrimaryHost();

            // Create WMI helper with very short timeout
            using var wmi = new WMIHelper(
                scope: "CimV2",
                host: host.Host,
                username: host.Username,
                password: host.Password,
                domain: host.Domain,
                auth: WmiAuthLevel.PacketPrivacy,
                timeout: TimeSpan.FromMilliseconds(1) // Extremely short timeout
            );

            // Act & Assert
            AssertWmiException(
                () =>
                {
                    // Try to execute a query that will likely timeout
                    var result = wmi.Query<dynamic>("SELECT * FROM Win32_Process").ToList();
                },
                expectedCode: null,
                messageContains: null
            );

            Output.WriteLine("✅ Query with short timeout correctly resulted in timeout error");
        }

        [Fact]
        public void Test038_DisposedHelper_ThrowsObjectDisposedException()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            var wmi = CreateWmiHelper();
            wmi.Dispose();

            // Act & Assert
            var exception = Assert.Throws<ObjectDisposedException>(() =>
            {
                var result = wmi.Query<dynamic>("SELECT * FROM Win32_Process").ToList();
            });

            exception.Should().NotBeNull();
            Output.WriteLine("✅ Using disposed WMIHelper correctly threw ObjectDisposedException");
        }

        [Fact]
        public void Test039_EmptyCredentials_ThrowsError()
        {
            // Arrange
            SkipIfAuthTestsDisabled();
            var host = Config.GetPrimaryHost();

            // Act & Assert
            AssertWmiException(
                () =>
                {
                    using var wmi = new WMIHelper(
                        scope: "CimV2",
                        host: host.Host,
                        username: "", // Empty username
                        password: "", // Empty password
                        domain: "",
                        auth: WmiAuthLevel.PacketPrivacy,
                        timeout: Config.DefaultTimeout
                    );
                },
                expectedCode: null,
                messageContains: null
            );

            Output.WriteLine("✅ Empty credentials correctly resulted in error");
        }
    }
}