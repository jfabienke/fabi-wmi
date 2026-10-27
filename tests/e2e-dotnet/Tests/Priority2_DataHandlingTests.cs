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
    /// Priority 2: Data Handling and Edge Cases
    /// These tests cover nuances in data handling and less common scenarios.
    /// </summary>
    [Trait("Category", "Priority2")]
    public class Priority2_DataHandlingTests : E2ETestBase
    {
        public Priority2_DataHandlingTests(ITestOutputHelper output) : base(output) { }

        // Test data classes with various data types
        public class Win32_OperatingSystem
        {
            public string? Name { get; set; }
            public string? BootDevice { get; set; }
            public uint BuildNumber { get; set; }
            public DateTime? InstallDate { get; set; }
            public bool Primary { get; set; }
            public ulong TotalVisibleMemorySize { get; set; }
            public string? Status { get; set; }
        }

        public class Win32_NetworkAdapter
        {
            public string? Name { get; set; }
            public string? MACAddress { get; set; }
            public bool PhysicalAdapter { get; set; }
            public ulong? Speed { get; set; } // uint64 in WMI: 10 Gbit/s exceeds a uint
            public uint Index { get; set; }
        }

        public class Win32_LogicalDisk
        {
            public string? DeviceID { get; set; }
            public uint DriveType { get; set; }
            public ulong? Size { get; set; }
            public ulong? FreeSpace { get; set; }
            public string? FileSystem { get; set; }
            public string? VolumeName { get; set; }
        }

        [SkippableFact]
        public void Test040_QueryReturningZeroResults_ReturnsEmptyCollection()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act - Query for a process that definitely doesn't exist
            var query = "SELECT * FROM Win32_Process WHERE Name = 'this_process_definitely_does_not_exist_12345.exe'";
            var processes = wmi.Query<dynamic>(query).ToList();

            // Assert
            processes.Should().NotBeNull("should return empty collection, not null");
            processes.Should().BeEmpty("query with no matches should return empty collection");

            Output.WriteLine("✅ Query with zero results correctly returned empty collection");
        }

        [SkippableFact]
        public void Test041_QueryWithVariedDataTypes_DeserializesCorrectly()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act
            var query = "SELECT Name, BootDevice, BuildNumber, InstallDate, Primary, TotalVisibleMemorySize, Status FROM Win32_OperatingSystem";
            var os = wmi.QueryFirstOrDefault<Win32_OperatingSystem>(query);

            // Assert
            os.Should().NotBeNull();

            // String types
            os!.Name.Should().NotBeNullOrEmpty("Name should be populated");
            os.BootDevice.Should().NotBeNullOrEmpty("BootDevice should be populated");

            // Integer types
            os.BuildNumber.Should().BeGreaterThan(0, "BuildNumber should be valid");

            // Boolean type
            os.Primary.Should().BeTrue("Primary OS should be true");

            // ULong type
            os.TotalVisibleMemorySize.Should().BeGreaterThan(0, "Memory size should be positive");

            Output.WriteLine($"✅ Various data types deserialized correctly:");
            Output.WriteLine($"   String: Name = {os.Name}");
            Output.WriteLine($"   String: BootDevice = {os.BootDevice}");
            Output.WriteLine($"   UInt32: BuildNumber = {os.BuildNumber}");
            Output.WriteLine($"   Boolean: Primary = {os.Primary}");
            Output.WriteLine($"   UInt64: TotalVisibleMemorySize = {os.TotalVisibleMemorySize}");
            Output.WriteLine($"   DateTime: InstallDate = {os.InstallDate}");
        }

        [SkippableFact]
        public void Test042_LargeResultSet_HandlesCorrectly()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act - Every process: a result set that spans several response fragments
            var query = "SELECT Name, ProcessId, HandleCount FROM Win32_Process";
            var processes = wmi.Query<dynamic>(query).ToList();

            // Assert
            processes.Should().NotBeNull();
            processes.Should().HaveCountGreaterThan(20, "Windows typically has many processes");

            // Verify we can iterate through all results
            var totalHandles = 0L;
            foreach (dynamic process in processes)
            {
                if (process.HandleCount != null)
                {
                    totalHandles += (long)process.HandleCount;
                }
            }

            totalHandles.Should().BeGreaterThan(0, "total handle count across all processes should be significant");

            Output.WriteLine($"✅ Large result set handled correctly:");
            Output.WriteLine($"   Total processes: {processes.Count}");
            Output.WriteLine($"   Total handles: {totalHandles:N0}");
        }

        [SkippableFact]
        public void Test043_UnicodeStrings_HandledCorrectly()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act - Query for data that might contain Unicode characters
            var query = "SELECT Name, Description FROM Win32_Service";
            var services = wmi.Query<dynamic>(query).Take(10).ToList();

            // Assert
            services.Should().NotBeNull();
            services.Should().NotBeEmpty();

            // Check that strings are properly decoded (no corruption)
            foreach (dynamic service in services)
            {
                string name = service.Name?.ToString() ?? "";
                string description = service.Description?.ToString() ?? "";

                // Basic validation that strings are readable
                name.Should().NotContain("\0", "should not contain null characters");
                name.Should().NotContain("�", "should not contain replacement characters");

                if (!string.IsNullOrEmpty(description))
                {
                    description.Should().NotContain("\0", "should not contain null characters");
                }
            }

            Output.WriteLine($"✅ Unicode strings handled correctly in {services.Count} services");
        }

        [SkippableFact]
        public void Test044_NullableProperties_HandledCorrectly()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act - Query network adapters which often have nullable properties
            var query = "SELECT Name, MACAddress, Speed, PhysicalAdapter FROM Win32_NetworkAdapter";
            var adapters = wmi.Query<Win32_NetworkAdapter>(query).ToList();

            // Assert
            adapters.Should().NotBeNull();
            adapters.Should().NotBeEmpty();

            // Some adapters won't have MAC addresses or speeds
            var hasNullMac = adapters.Any(a => string.IsNullOrEmpty(a.MACAddress));
            var hasNullSpeed = adapters.Any(a => !a.Speed.HasValue || a.Speed == 0);

            hasNullMac.Should().BeTrue("some network adapters should have null MAC addresses");
            hasNullSpeed.Should().BeTrue("some network adapters should have null speeds");

            // But physical adapters should have MAC addresses
            var physicalAdapters = adapters.Where(a => a.PhysicalAdapter).ToList();
            if (physicalAdapters.Any())
            {
                physicalAdapters.Should().Contain(a => !string.IsNullOrEmpty(a.MACAddress),
                    "at least one physical adapter should have a MAC address");
            }

            Output.WriteLine($"✅ Nullable properties handled correctly:");
            Output.WriteLine($"   Total adapters: {adapters.Count}");
            Output.WriteLine($"   Adapters with null MAC: {adapters.Count(a => string.IsNullOrEmpty(a.MACAddress))}");
            Output.WriteLine($"   Adapters with null Speed: {adapters.Count(a => !a.Speed.HasValue)}");
        }

        [SkippableFact]
        public void Test045_LargeNumericValues_HandledCorrectly()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act - Query disk information which has large numeric values
            var query = "SELECT DeviceID, Size, FreeSpace, DriveType FROM Win32_LogicalDisk WHERE DriveType = 3"; // Fixed disks
            var disks = wmi.Query<Win32_LogicalDisk>(query).ToList();

            // Assert
            if (disks.Any())
            {
                var systemDisk = disks.FirstOrDefault(d => d.DeviceID == "C:");
                if (systemDisk != null)
                {
                    systemDisk.Size.Should().NotBeNull();
                    systemDisk.Size.Should().BeGreaterThan(1_000_000_000, "C: drive should be at least 1GB");
                    systemDisk.FreeSpace.Should().NotBeNull();
                    systemDisk.FreeSpace.Should().BeGreaterThan(0, "should have some free space");
                    systemDisk.FreeSpace.Should().BeLessThanOrEqualTo(systemDisk.Size!.Value, "free space should not exceed total size");

                    var sizeGB = systemDisk.Size!.Value / (1024.0 * 1024.0 * 1024.0);
                    var freeGB = systemDisk.FreeSpace!.Value / (1024.0 * 1024.0 * 1024.0);

                    Output.WriteLine($"✅ Large numeric values handled correctly:");
                    Output.WriteLine($"   Drive: {systemDisk.DeviceID}");
                    Output.WriteLine($"   Size: {sizeGB:N2} GB ({systemDisk.Size:N0} bytes)");
                    Output.WriteLine($"   Free: {freeGB:N2} GB ({systemDisk.FreeSpace:N0} bytes)");
                }
            }
            else
            {
                Output.WriteLine("⚠️ No fixed disks found to test large numeric values");
            }
        }

        [SkippableFact]
        public void Test046_SpecialCharactersInStrings_HandledCorrectly()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act - Query for paths which often contain special characters
            var query = "SELECT Name, PathName FROM Win32_Service WHERE PathName IS NOT NULL";
            var services = wmi.Query<dynamic>(query).Take(20).ToList();

            // Assert
            services.Should().NotBeNull();
            services.Should().NotBeEmpty();

            foreach (dynamic service in services)
            {
                string pathName = service.PathName?.ToString() ?? "";

                if (!string.IsNullOrEmpty(pathName))
                {
                    // Common special characters in Windows paths
                    var hasSpecialChars = pathName.Contains("\\") ||
                                          pathName.Contains(" ") ||
                                          pathName.Contains("-") ||
                                          pathName.Contains(".");

                    hasSpecialChars.Should().BeTrue($"path '{pathName}' should contain typical path characters");
                }
            }

            Output.WriteLine($"✅ Special characters in strings handled correctly for {services.Count} services");
        }

        [SkippableFact]
        public void Test047_QueryFirstOrDefault_WithNoResults_ReturnsNull()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act
            var query = "SELECT * FROM Win32_Process WHERE Name = 'nonexistent_process_xyz.exe'";
            var result = wmi.QueryFirstOrDefault<dynamic>(query);

            // Assert
            // Extension methods don't bind on a dynamic receiver; assert through object
            ((object?)result).Should().BeNull("QueryFirstOrDefault with no matches should return null");

            Output.WriteLine("✅ QueryFirstOrDefault with no results correctly returned null");
        }

        [SkippableFact]
        public void Test048_ArrayProperties_HandledCorrectly()
        {
            // Arrange
            SkipIfNetworkTestsDisabled();
            using var wmi = CreateWmiHelper();

            // Act - Query for data with array properties
            // Win32_ComputerSystem has Roles property which is an array
            var query = "SELECT Name, Roles FROM Win32_ComputerSystem";
            var system = wmi.QueryFirstOrDefault<dynamic>(query);

            // Assert
            ((object?)system).Should().NotBeNull("Win32_ComputerSystem should return an instance");

            // Roles is a string array, which a dynamic row holds as a list
            IEnumerable<object?> roles = system!.Roles;
            roles.Should().NotBeEmpty("every Windows host has roles such as LM_Workstation");
            roles.Should().AllBeOfType<string>();

            Output.WriteLine($"✅ Array property 'Roles': {string.Join(", ", roles)}");
        }
    }
}