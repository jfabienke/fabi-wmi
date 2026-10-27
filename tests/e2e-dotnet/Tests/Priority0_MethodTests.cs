using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using Xunit;
using Xunit.Abstractions;
using FluentAssertions;
using LinuxWmi.E2ETests.Infrastructure;

namespace LinuxWmi.E2ETests.Tests
{
    /// <summary>
    /// Priority 0: Critical Path - Method Execution Tests
    /// Static methods are called on a class ("Win32_Process"), instance methods
    /// on an object path ("Win32_Process.Handle=\"736\""). WMIHelper's one
    /// entry point, ExecuteStaticMethod, passes either to the library.
    /// </summary>
    [Trait("Category", "Priority0")]
    public class Priority0_MethodTests : E2ETestBase
    {
        public Priority0_MethodTests(ITestOutputHelper output) : base(output) { }

        // Method input/output classes
        public class GetOwnerOutput
        {
            public uint ReturnValue { get; set; }
            public string? Domain { get; set; }
            public string? User { get; set; }
        }

        public class CreateInput
        {
            public string? CommandLine { get; set; }
            public string? CurrentDirectory { get; set; }
        }

        public class CreateOutput
        {
            public uint ReturnValue { get; set; }
            /// <summary>Unset (null) when Create fails.</summary>
            public uint? ProcessId { get; set; }
        }

        public class TerminateInput
        {
            public uint Reason { get; set; }
        }

        public class TerminateOutput
        {
            public uint ReturnValue { get; set; }
        }

        public class GetSDOutput
        {
            public uint ReturnValue { get; set; }
            public List<byte>? SD { get; set; }
        }

        public class ProcessRow
        {
            public uint ProcessId { get; set; }
        }

        private static string ProcessPath(uint processId) => $"Win32_Process.Handle=\"{processId}\"";

        [SkippableFact]
        public void Test020_GetOwner_OfServicesProcess_ReturnsSystem()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();
            // services.exe always runs as SYSTEM. (The System process, PID 4,
            // has no owner to report: GetOwner returns 2 there.)
            var services = wmi.QueryFirstOrDefault<ProcessRow>(
                "SELECT ProcessId FROM Win32_Process WHERE Name = 'services.exe'");
            services.Should().NotBeNull("services.exe always runs");

            // Act - GetOwner is an instance method
            var result = wmi.ExecuteStaticMethod<GetOwnerOutput>(ProcessPath(services!.ProcessId), "GetOwner");

            // Assert
            result.ReturnValue.Should().Be(0, "GetOwner should succeed for services.exe");
            result.User.Should().Be("SYSTEM");
            result.Domain.Should().Be("NT AUTHORITY");

            Output.WriteLine($"✅ GetOwner for services.exe (PID {services.ProcessId}): {result.Domain}\\{result.User}");
        }

        [SkippableFact]
        public void Test021_Create_SimpleProcess_ReturnsProcessId()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act - Create a simple process (cmd.exe that exits immediately)
            var input = new CreateInput
            {
                CommandLine = "cmd.exe /c echo WMI_TEST_PROCESS && exit",
                CurrentDirectory = @"C:\Windows\System32"
            };

            var result = wmi.ExecuteStaticMethod<CreateOutput>(
                "Win32_Process",
                "Create",
                input
            );

            // Assert
            result.Should().NotBeNull();
            result.ReturnValue.Should().Be(0, "Create should succeed");
            result.ProcessId.Should().BeGreaterThan(0, "should return valid process ID");

            Output.WriteLine($"✅ Process creation succeeded:");
            Output.WriteLine($"   ProcessId: {result.ProcessId}");
            Output.WriteLine($"   ReturnValue: {result.ReturnValue}");
        }

        [SkippableFact]
        public void Test022_Create_InvalidPath_ReturnsPathNotFound()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act - Try to create a process with invalid executable
            var input = new CreateInput
            {
                CommandLine = @"C:\NonExistent\Program.exe",
                CurrentDirectory = @"C:\Windows\System32"
            };

            var result = wmi.ExecuteStaticMethod<CreateOutput>(
                "Win32_Process",
                "Create",
                input
            );

            // Assert
            result.Should().NotBeNull();
            result.ReturnValue.Should().Be(9, "9 is Create's 'path not found'");
            result.ProcessId.Should().BeNull("Windows leaves ProcessId unset when Create fails");

            Output.WriteLine($"✅ Invalid process creation failed as expected:");
            Output.WriteLine($"   ReturnValue: {result.ReturnValue} (path not found)");
        }

        [SkippableFact]
        public void Test023_Terminate_NonExistentProcess_ThrowsNotFound()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act & Assert - Windows process IDs are multiples of 4, so 99999
            // never exists, and WMI cannot find the object to call Terminate on.
            AssertWmiException(
                () => wmi.ExecuteStaticMethod<TerminateOutput>(ProcessPath(99999), "Terminate", new TerminateInput()),
                expectedCode: WmiStatus.NotFound
            );

            Output.WriteLine($"✅ Terminate on a non-existent process failed with WBEM_E_NOT_FOUND");
        }

        [SkippableFact]
        public void Test024_MethodWithoutParameters_Succeeds()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act - __SystemSecurity.GetSD takes no input parameters and only
            // reads the namespace's security descriptor
            var result = wmi.ExecuteStaticMethod<GetSDOutput>("__SystemSecurity", "GetSD");

            // Assert
            result.ReturnValue.Should().Be(0, "GetSD should succeed for an administrator");
            result.SD.Should().NotBeNullOrEmpty("GetSD returns the security descriptor as a byte array");

            Output.WriteLine($"✅ GetSD returned a {result.SD!.Count}-byte security descriptor");
        }

        [SkippableFact]
        public void Test025_CreateAndTerminate_ProcessLifecycle()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act - Create a process
            var createInput = new CreateInput
            {
                CommandLine = "notepad.exe",
                CurrentDirectory = @"C:\Windows\System32"
            };

            var createResult = wmi.ExecuteStaticMethod<CreateOutput>(
                "Win32_Process",
                "Create",
                createInput
            );

            // Assert creation succeeded
            createResult.ReturnValue.Should().Be(0, "Create should succeed");
            createResult.ProcessId.Should().BeGreaterThan(0);
            var processId = createResult.ProcessId!.Value;

            Output.WriteLine($"✅ Created process with PID: {processId}");

            // Now terminate it - Terminate is an instance method
            var terminateResult = wmi.ExecuteStaticMethod<TerminateOutput>(
                ProcessPath(processId),
                "Terminate",
                new TerminateInput()
            );

            // Assert termination succeeded and the process is gone
            terminateResult.ReturnValue.Should().Be(0, "Terminate should succeed");
            var query = $"SELECT ProcessId FROM Win32_Process WHERE ProcessId = {processId}";
            var stopwatch = Stopwatch.StartNew();
            while (wmi.QueryFirstOrDefault<ProcessRow>(query) != null && stopwatch.Elapsed < TimeSpan.FromSeconds(10))
            {
                Thread.Sleep(250);
            }
            wmi.QueryFirstOrDefault<ProcessRow>(query).Should().BeNull("the terminated process should be gone");

            Output.WriteLine($"✅ Successfully terminated process {processId}");
        }
    }
}
