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
    /// The shim and the C ABI against the library's canned stub backend
    /// (src/test_support), so CI covers P/Invoke marshalling, JSON binding and
    /// error codes without a Windows host. Needs a library built with
    /// --features test-support and LINUX_WMI_USE_STUB=1.
    /// </summary>
    [Trait("Category", "Stub")]
    public class StubBackendTests : E2ETestBase
    {
        public StubBackendTests(ITestOutputHelper output) : base(output) { }

        public class Win32_Process
        {
            public string? Name { get; set; }
            public uint ProcessId { get; set; }
            public uint ThreadCount { get; set; }
        }

        public class Win32_OperatingSystem
        {
            public string? Caption { get; set; }
            public uint BuildNumber { get; set; }
            public DateTimeOffset InstallDate { get; set; }
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
        }

        public class CreateOutput
        {
            public uint ReturnValue { get; set; }
            public uint? ProcessId { get; set; }
        }

        private static WMIHelper CreateStubHelper() => new WMIHelper(scope: "CimV2", host: "stub");

        [SkippableFact]
        public void Test100_TypedQuery_BindsEveryRow()
        {
            SkipUnlessStubBackend();
            using var wmi = CreateStubHelper();

            var processes = wmi.Query<Win32_Process>("SELECT Name, ProcessId, ThreadCount FROM Win32_Process").ToList();

            processes.Select(p => p.ProcessId).Should().Equal(0u, 4u);
            processes[1].Name.Should().Be("System");
            processes[1].ThreadCount.Should().Be(91);
        }

        [SkippableFact]
        public void Test101_DynamicQuery_ReturnsRowsWithNamedMembers()
        {
            SkipUnlessStubBackend();
            using var wmi = CreateStubHelper();

            var systems = wmi.Query<dynamic>("SELECT * FROM Win32_ComputerSystem").ToList();

            systems.Should().HaveCount(1);
            string name = systems[0].Name;
            name.Should().Be("STUB-PC");
        }

        [SkippableFact]
        public void Test102_NumericStringsAndDmtfDatetimes_Bind()
        {
            SkipUnlessStubBackend();
            using var wmi = CreateStubHelper();

            // BuildNumber is a string in WMI and InstallDate a DMTF datetime
            var os = wmi.QueryFirstOrDefault<Win32_OperatingSystem>("SELECT * FROM Win32_OperatingSystem");

            os.Should().NotBeNull();
            os!.BuildNumber.Should().Be(20348);
            os.InstallDate.Should().Be(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        }

        [SkippableFact]
        public void Test103_UnknownClass_ThrowsInvalidClass()
        {
            SkipUnlessStubBackend();
            using var wmi = CreateStubHelper();

            AssertWmiException(
                () => wmi.Query<dynamic>("SELECT * FROM Win32_NoSuchClass").ToList(),
                expectedCode: WmiStatus.InvalidClass
            );
        }

        [SkippableFact]
        public void Test104_StaticMethod_ReturnsOutputParameters()
        {
            SkipUnlessStubBackend();
            using var wmi = CreateStubHelper();

            var result = wmi.ExecuteStaticMethod<CreateOutput>(
                "Win32_Process", "Create", new CreateInput { CommandLine = "notepad.exe" });

            result.ReturnValue.Should().Be(0);
            result.ProcessId.Should().Be(4242);
        }

        [SkippableFact]
        public void Test105_InstancePath_ReachesItsClass()
        {
            SkipUnlessStubBackend();
            using var wmi = CreateStubHelper();

            var result = wmi.ExecuteStaticMethod<GetOwnerOutput>("Win32_Process.Handle=\"4\"", "GetOwner");

            result.ReturnValue.Should().Be(0);
            result.User.Should().Be("SYSTEM");
            result.Domain.Should().Be("NT AUTHORITY");
        }

        [SkippableFact]
        public void Test106_UnknownMethod_ThrowsMethodNotImplemented()
        {
            SkipUnlessStubBackend();
            using var wmi = CreateStubHelper();

            AssertWmiException(
                () => wmi.ExecuteStaticMethod<object>("Win32_Process", "NoSuchMethod"),
                expectedCode: WmiStatus.MethodNotImplemented
            );
        }

        [SkippableFact]
        public void Test107_EmptyHost_IsRejected()
        {
            SkipUnlessStubBackend();

            AssertWmiException(
                () => new WMIHelper(scope: "CimV2", host: " "),
                expectedCode: WmiStatus.NoHresult,
                messageContains: "Host"
            );
        }

        [SkippableFact]
        public void Test108_DisposedHelper_ThrowsObjectDisposedException()
        {
            SkipUnlessStubBackend();
            var wmi = CreateStubHelper();
            wmi.Dispose();

            Assert.Throws<ObjectDisposedException>(() => wmi.Query<dynamic>("SELECT * FROM Win32_Process").ToList());
        }
    }
}
