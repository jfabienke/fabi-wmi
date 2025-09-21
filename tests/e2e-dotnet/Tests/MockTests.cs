using Xunit;
using Xunit.Abstractions;
using FluentAssertions;
using LinuxWmi.E2ETests.Infrastructure;
using System.Linq;

namespace LinuxWmi.E2ETests.Tests
{
    /// <summary>
    /// Tests using mock WMI helper to verify test infrastructure without real Windows host
    /// </summary>
    public class MockTests : E2ETestBase
    {
        public MockTests(ITestOutputHelper output) : base(output) { }

        [Fact]
        public void Test_MockWMIHelper_ReturnsExpectedProcesses()
        {
            // Arrange
            var mock = new MockWMIHelper();

            // Act
            var processes = mock.Query<dynamic>("SELECT * FROM Win32_Process").ToList();

            // Assert
            processes.Should().NotBeNull();
            processes.Should().HaveCount(3);

            dynamic? systemProcess = processes.FirstOrDefault(p => (uint)p.ProcessId == 4);
            Assert.NotNull(systemProcess);

            Output.WriteLine($"✅ Mock returned {processes.Count} processes");
        }

        [Fact]
        public void Test_MockWMIHelper_ReturnsComputerSystem()
        {
            // Arrange
            var mock = new MockWMIHelper();

            // Act
            var systems = mock.Query<dynamic>("SELECT * FROM Win32_ComputerSystem").ToList();

            // Assert
            systems.Should().NotBeNull();
            systems.Should().HaveCount(1);

            dynamic system = systems.First();
            Assert.Equal("MOCK-PC", system.Name);
            Assert.Equal(8589934592ul, (ulong)system.TotalPhysicalMemory);

            Output.WriteLine($"✅ Mock returned computer system: {system.Name}");
        }

        [Fact]
        public void Test_MockWMIHelper_ExecutesStaticMethod()
        {
            // Arrange
            var mock = new MockWMIHelper();

            // Act
            var result = mock.ExecuteStaticMethod<dynamic>("Win32_Process", "GetOwner", null);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(0u, (uint)result.ReturnValue);
            Assert.Equal("SYSTEM", result.User);

            Output.WriteLine($"✅ Mock executed static method successfully");
        }
    }
}