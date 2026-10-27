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
    [Trait("Category", "Priority1")]
    public class Priority1_ErrorHandlingTests : E2ETestBase
    {
        public Priority1_ErrorHandlingTests(ITestOutputHelper output) : base(output) { }

        [SkippableFact]
        public void Test030_InvalidCredentials_ThrowsAuthenticationError()
        {
            // Arrange
            SkipIfAuthTestsDisabled();

            // Act & Assert
            AssertWmiException(
                () =>
                {
                    using var wmi = new WMIHelper(
                        scope: "CimV2",
                        host: Config.Host,
                        username: Config.Username,
                        password: "WrongPassword123!",
                        domain: Config.Domain,
                        auth: WmiAuthLevel.PacketPrivacy,
                        timeout: Config.DefaultTimeout
                    );
                },
                expectedCode: WmiStatus.AccessDenied
            );

            Output.WriteLine("✅ Invalid credentials correctly resulted in authentication error");
        }

        [SkippableFact]
        public void Test031_InvalidUsername_ThrowsAuthenticationError()
        {
            // Arrange
            SkipIfAuthTestsDisabled();

            // Act & Assert
            AssertWmiException(
                () =>
                {
                    using var wmi = new WMIHelper(
                        scope: "CimV2",
                        host: Config.Host,
                        username: "NonExistentUser",
                        password: Config.Password,
                        domain: Config.Domain,
                        auth: WmiAuthLevel.PacketPrivacy,
                        timeout: Config.DefaultTimeout
                    );
                },
                expectedCode: WmiStatus.AccessDenied
            );

            Output.WriteLine("✅ Invalid username correctly resulted in authentication error");
        }

        [SkippableFact]
        public void Test032_UnreachableHost_ThrowsNetworkError()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();

            // TEST-NET-1 (RFC 5737): reserved for documentation, never routed
            var unreachableHost = "192.0.2.1";

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
                expectedCode: WmiStatus.NoHresult,
                messageContains: "endpoint mapper"
            );

            Output.WriteLine($"✅ Unreachable host {unreachableHost} correctly resulted in network error");
        }

        [SkippableFact]
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
                expectedCode: WmiStatus.InvalidQuery
            );

            Output.WriteLine("✅ Invalid WQL syntax correctly resulted in query error");
        }

        [SkippableFact]
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
                expectedCode: WmiStatus.InvalidClass
            );

            Output.WriteLine("✅ Query for non-existent class correctly resulted in error");
        }

        [SkippableFact]
        public void Test036_InvalidNamespace_ThrowsError()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();

            // Act & Assert
            AssertWmiException(
                () =>
                {
                    using var wmi = new WMIHelper(
                        scope: "InvalidNamespace",
                        host: Config.Host,
                        username: Config.Username,
                        password: Config.Password,
                        domain: Config.Domain,
                        auth: WmiAuthLevel.PacketPrivacy,
                        timeout: Config.DefaultTimeout
                    );
                },
                expectedCode: WmiStatus.InvalidNamespace
            );

            Output.WriteLine("✅ Invalid namespace correctly resulted in error");
        }

        [SkippableFact]
        public void Test037_QueryTimeout_ThrowsTimeoutError()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();

            // Create WMI helper with very short timeout
            using var wmi = new WMIHelper(
                scope: "CimV2",
                host: Config.Host,
                username: Config.Username,
                password: Config.Password,
                domain: Config.Domain,
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
                expectedCode: WmiStatus.NoHresult
            );

            Output.WriteLine("✅ Query with short timeout correctly resulted in timeout error");
        }

        [SkippableFact]
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

        [SkippableFact]
        public void Test039_EmptyCredentials_ThrowsError()
        {
            // Arrange
            SkipIfAuthTestsDisabled();

            // Act & Assert
            AssertWmiException(
                () =>
                {
                    using var wmi = new WMIHelper(
                        scope: "CimV2",
                        host: Config.Host,
                        username: "", // Empty username
                        password: "", // Empty password
                        domain: "",
                        auth: WmiAuthLevel.PacketPrivacy,
                        timeout: Config.DefaultTimeout
                    );
                },
                expectedCode: WmiStatus.NoHresult,
                messageContains: "required"
            );

            Output.WriteLine("✅ Empty credentials correctly resulted in error");
        }
    }
}