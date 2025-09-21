using System;
using System.Linq;
using Xunit;
using Xunit.Abstractions;
using FluentAssertions;
using LinuxWmi.E2ETests.Infrastructure;

namespace LinuxWmi.E2ETests.Tests
{
    /// <summary>
    /// Priority 0: Critical Path - Static Method Execution Tests
    /// These tests verify that static WMI methods can be called with parameters and return expected results.
    /// </summary>
    public class Priority0_StaticMethodTests : E2ETestBase
    {
        public Priority0_StaticMethodTests(ITestOutputHelper output) : base(output) { }

        // Method input/output classes
        public class GetOwnerInput
        {
            public uint ProcessId { get; set; }
        }

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
            public uint ProcessId { get; set; }
        }

        public class TerminateInput
        {
            public uint ProcessId { get; set; }
            public uint Reason { get; set; }
        }

        public class TerminateOutput
        {
            public uint ReturnValue { get; set; }
        }

        [Fact]
        public void Test020_GetOwner_ForSystemProcess_ReturnsSystemUser()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act - Get owner of System process (PID 4)
            var input = new GetOwnerInput { ProcessId = 4 };
            var result = wmi.ExecuteStaticMethod<GetOwnerOutput>(
                "Win32_Process",
                "GetOwner",
                input
            );

            // Assert
            result.Should().NotBeNull();
            result.ReturnValue.Should().Be(0, "GetOwner should succeed for System process");

            // System process typically runs as "SYSTEM" in "NT AUTHORITY" domain
            result.User.Should().NotBeNullOrEmpty();
            result.Domain.Should().NotBeNullOrEmpty();

            Output.WriteLine($"✅ GetOwner for PID 4 succeeded:");
            Output.WriteLine($"   Domain: {result.Domain}");
            Output.WriteLine($"   User: {result.User}");
            Output.WriteLine($"   ReturnValue: {result.ReturnValue}");
        }

        [Fact]
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

            // Note: The process will exit immediately, so we don't need to clean it up
        }

        [Fact]
        public void Test022_Create_InvalidPath_ReturnsError()
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
            result.ReturnValue.Should().NotBe(0, "Create should fail for non-existent executable");
            result.ProcessId.Should().Be(0, "no process should be created");

            Output.WriteLine($"✅ Invalid process creation failed as expected:");
            Output.WriteLine($"   ReturnValue: {result.ReturnValue} (non-zero indicates failure)");
        }

        [Fact]
        public void Test023_Terminate_NonExistentProcess_ReturnsError()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act - Try to terminate a non-existent process
            var input = new TerminateInput
            {
                ProcessId = 99999, // Very unlikely to exist
                Reason = 0
            };

            var result = wmi.ExecuteStaticMethod<TerminateOutput>(
                "Win32_Process",
                "Terminate",
                input
            );

            // Assert
            result.Should().NotBeNull();
            result.ReturnValue.Should().NotBe(0, "Terminate should fail for non-existent process");

            Output.WriteLine($"✅ Terminate non-existent process failed as expected:");
            Output.WriteLine($"   ReturnValue: {result.ReturnValue} (non-zero indicates failure)");
        }

        [Fact]
        public void Test024_StaticMethod_WithoutParameters_Succeeds()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act - Call a method without parameters
            // Win32_OperatingSystem.Reboot() - but we'll use a safer method
            // Note: We won't actually call Reboot as it would restart the system!
            // Instead, we'll test with Win32_Process.GetAvailableVirtualSize which takes no params

            var result = wmi.ExecuteStaticMethod<dynamic>(
                "Win32_Process",
                "GetAvailableVirtualSize",
                null
            );

            // Assert
            result.Should().NotBeNull();

            Output.WriteLine($"✅ Static method without parameters succeeded");
        }

        [Fact]
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
            createResult.Should().NotBeNull();
            createResult.ReturnValue.Should().Be(0, "Create should succeed");
            var processId = createResult.ProcessId;
            processId.Should().BeGreaterThan(0);

            Output.WriteLine($"✅ Created process with PID: {processId}");

            // Give the process a moment to start
            System.Threading.Thread.Sleep(500);

            // Now terminate it
            var terminateInput = new TerminateInput
            {
                ProcessId = processId,
                Reason = 0
            };

            var terminateResult = wmi.ExecuteStaticMethod<TerminateOutput>(
                "Win32_Process",
                "Terminate",
                terminateInput
            );

            // Assert termination succeeded
            terminateResult.Should().NotBeNull();
            terminateResult.ReturnValue.Should().Be(0, "Terminate should succeed");

            Output.WriteLine($"✅ Successfully terminated process {processId}");
        }
    }
}