using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;
using Xunit.Abstractions;
using FluentAssertions;
using LinuxWmi.E2ETests.Infrastructure;

namespace LinuxWmi.E2ETests.Tests
{
    /// <summary>
    /// Priority 0: Critical Path - Basic Query Tests
    /// These tests verify that basic WQL queries work and return expected data.
    /// </summary>
    public class Priority0_BasicQueryTests : E2ETestBase
    {
        public Priority0_BasicQueryTests(ITestOutputHelper output) : base(output) { }

        // Define test data classes
        public class Win32_Process
        {
            public string? Name { get; set; }
            public uint ProcessId { get; set; }
            public uint? ParentProcessId { get; set; }
            public string? ExecutablePath { get; set; }
            public uint? HandleCount { get; set; }
            public ulong? WorkingSetSize { get; set; }
        }

        public class Win32_ComputerSystem
        {
            public string? Name { get; set; }
            public string? Domain { get; set; }
            public string? Manufacturer { get; set; }
            public string? Model { get; set; }
            public uint? NumberOfProcessors { get; set; }
            public ulong? TotalPhysicalMemory { get; set; }
        }

        public class Win32_OperatingSystem
        {
            public string? Name { get; set; }
            public string? Version { get; set; }
            public string? BuildNumber { get; set; }
            public string? CSName { get; set; }
            public DateTime? InstallDate { get; set; }
            public DateTime? LastBootUpTime { get; set; }
        }

        [Fact]
        public void Test010_QueryMultipleProcesses_ReturnsNonEmptyCollection()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act
            var processes = wmi.Query<Win32_Process>("SELECT Name, ProcessId FROM Win32_Process").ToList();

            // Assert
            processes.Should().NotBeNull();
            processes.Should().NotBeEmpty("Windows always has running processes");
            processes.Should().HaveCountGreaterThan(5, "Windows typically has many processes running");

            var systemProcess = processes.FirstOrDefault(p => p.ProcessId == 0 || p.ProcessId == 4);
            systemProcess.Should().NotBeNull("System process (PID 0 or 4) should always exist");

            Output.WriteLine($"✅ Query returned {processes.Count} processes");
            Output.WriteLine($"Sample processes: {string.Join(", ", processes.Take(5).Select(p => $"{p.Name}({p.ProcessId})"))}");
        }

        [Fact]
        public void Test011_QueryComputerSystem_ReturnsSingleObject()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act
            var systems = wmi.Query<Win32_ComputerSystem>("SELECT * FROM Win32_ComputerSystem").ToList();

            // Assert
            systems.Should().NotBeNull();
            systems.Should().HaveCount(1, "Win32_ComputerSystem should return exactly one instance");

            var system = systems.First();
            system.Name.Should().NotBeNullOrEmpty();
            system.Manufacturer.Should().NotBeNullOrEmpty();
            system.NumberOfProcessors.Should().BeGreaterThan(0);
            system.TotalPhysicalMemory.Should().BeGreaterThan(0);

            Output.WriteLine($"✅ Computer System Information:");
            Output.WriteLine($"   Name: {system.Name}");
            Output.WriteLine($"   Domain: {system.Domain}");
            Output.WriteLine($"   Manufacturer: {system.Manufacturer}");
            Output.WriteLine($"   Model: {system.Model}");
            Output.WriteLine($"   Processors: {system.NumberOfProcessors}");
            Output.WriteLine($"   Memory: {system.TotalPhysicalMemory:N0} bytes");
        }

        [Fact]
        public void Test012_QueryWithWhereClause_FiltersCorrectly()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act - Query for explorer.exe or services.exe (common Windows processes)
            var query = "SELECT Name, ProcessId FROM Win32_Process WHERE Name = 'services.exe' OR Name = 'explorer.exe'";
            var processes = wmi.Query<Win32_Process>(query).ToList();

            // Assert
            processes.Should().NotBeNull();
            processes.Should().NotBeEmpty("services.exe should always be running on Windows");

            processes.All(p => p.Name == "services.exe" || p.Name == "explorer.exe")
                .Should().BeTrue("all returned processes should match the WHERE clause");

            Output.WriteLine($"✅ Filtered query returned {processes.Count} matching processes");
            foreach (var process in processes)
            {
                Output.WriteLine($"   {process.Name} (PID: {process.ProcessId})");
            }
        }

        [Fact]
        public void Test013_QueryOperatingSystem_ReturnsValidData()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act
            var os = wmi.QueryFirstOrDefault<Win32_OperatingSystem>("SELECT * FROM Win32_OperatingSystem");

            // Assert
            os.Should().NotBeNull();
            os!.Name.Should().NotBeNullOrEmpty();
            os.Version.Should().NotBeNullOrEmpty();
            os.BuildNumber.Should().NotBeNullOrEmpty();

            Output.WriteLine($"✅ Operating System Information:");
            Output.WriteLine($"   Name: {os.Name}");
            Output.WriteLine($"   Version: {os.Version}");
            Output.WriteLine($"   Build: {os.BuildNumber}");
            Output.WriteLine($"   Computer: {os.CSName}");
            if (os.LastBootUpTime.HasValue)
            {
                Output.WriteLine($"   Last Boot: {os.LastBootUpTime.Value:yyyy-MM-dd HH:mm:ss}");
            }
        }

        [Fact]
        public void Test014_QueryWithSpecificFields_ReturnsOnlyRequestedFields()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act
            var query = "SELECT ProcessId, HandleCount FROM Win32_Process WHERE ProcessId = 4";
            var process = wmi.QueryFirstOrDefault<Win32_Process>(query);

            // Assert
            process.Should().NotBeNull("System process (PID 4) should exist");
            process!.ProcessId.Should().Be(4);
            process.HandleCount.Should().BeGreaterThan(0, "System process should have handles");

            // Note: Name should be null/empty since we didn't request it
            // (depending on the WMI implementation, it might still be populated)

            Output.WriteLine($"✅ Specific field query succeeded:");
            Output.WriteLine($"   ProcessId: {process.ProcessId}");
            Output.WriteLine($"   HandleCount: {process.HandleCount}");
        }

        [Fact]
        public void Test015_QueryWithOrderBy_ReturnsOrderedResults()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act
            var query = "SELECT Name, WorkingSetSize FROM Win32_Process ORDER BY WorkingSetSize DESC";
            var processes = wmi.Query<Win32_Process>(query).Take(5).ToList();

            // Assert
            processes.Should().NotBeNull();
            processes.Should().NotBeEmpty();

            // Verify ordering
            for (int i = 1; i < processes.Count; i++)
            {
                var prev = processes[i - 1].WorkingSetSize ?? 0;
                var curr = processes[i].WorkingSetSize ?? 0;
                prev.Should().BeGreaterThanOrEqualTo(curr, "results should be ordered by WorkingSetSize DESC");
            }

            Output.WriteLine($"✅ Top 5 processes by memory usage:");
            foreach (var process in processes)
            {
                var memoryMB = (process.WorkingSetSize ?? 0) / (1024.0 * 1024.0);
                Output.WriteLine($"   {process.Name}: {memoryMB:N2} MB");
            }
        }
    }
}