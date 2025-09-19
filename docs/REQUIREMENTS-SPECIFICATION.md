# WMI Query Provider Requirements Specification

## Executive Summary

This document provides a comprehensive specification for the WMI Query Provider infrastructure, detailing all WQL queries, WMI namespaces, class schemas, and implementation requirements for future reimplementation while maintaining backwards compatibility.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [WMI Namespaces](#wmi-namespaces)
3. [Authentication & Connection Management](#authentication--connection-management)
4. [WQL Queries by Category](#wql-queries-by-category)
5. [Class Schemas](#class-schemas)
6. [Error Handling & Diagnostics](#error-handling--diagnostics)
7. [Performance Considerations](#performance-considerations)
8. [Backwards Compatibility Requirements](#backwards-compatibility-requirements)

## Architecture Overview

### Core Components

- **WMIQueryProvider**: Main provider class implementing `IWindowsQueryProvider` interface
- **WMIHelper**: Wrapper for WMI connections to different namespaces
- **ORMi Framework**: Object-relational mapping for WMI queries
- **Performance Monitoring**: Built-in timing and diagnostic tracking

### Supported Operating Systems

- Windows Server 2003 (limited support with fallback methods)
- Windows Server 2008 (limited support with fallback methods)
- Windows Server 2012 and later (full support)
- Windows 10/11 workstations

## WMI Namespaces

### Required Namespaces

| Namespace                        | Purpose                               | Authentication Level |
|----------------------------------|---------------------------------------|----------------------|
| `root\CimV2`                     | Core Windows management data          | Default              |
| `root\StandardCimv2`             | Network connections (Windows 8/2012+) | Default              |
| `root\Microsoft\Windows\Storage` | Storage management (Windows 8/2012+)  | Default              |
| `root\WebAdministration`         | IIS configuration                     | PacketPrivacy        |
| `Root\MSCluster`                 | Failover clustering                   | PacketPrivacy        |

### Namespace Availability by OS Version

- Windows Server 2003/2008: Only `root\CimV2` available
- Windows Server 2012+: All namespaces available
- Fallback mechanisms required for missing namespaces

## Authentication & Connection Management

### Connection Requirements

```csharp
ConnectionOptions = {
    Username = username,
    Password = password,
    Authentication = AuthenticationLevel.PacketPrivacy
}
```

### Connection Types

- **Local**: Direct connection without credentials when hostname matches current machine
- **Remote**: Requires username/password authentication

#### Special Cases
- MSCluster and WebAdministration always require PacketPrivacy

## WQL Queries by Category

### System Information Queries

#### Win32_Processor
```sql
SELECT Name, Manufacturer, LoadPercentage, NumberOfCores, NumberOfLogicalProcessors
FROM Win32_Processor
```
- **Namespace**: `root\CimV2`
- **Purpose**: CPU information and utilization monitoring

#### Win32_OperatingSystem
```sql
SELECT Name, FreePhysicalMemory, TotalVisibleMemorySize, OSType
FROM Win32_OperatingSystem
```
- **Namespace**: `root\CimV2`
- **Purpose**: OS information and memory statistics

#### Win32_ComputerSystem
```sql
SELECT Roles, Manufacturer, Model, NumberOfLogicalProcessors,
       NumberOfProcessors, TotalPhysicalMemory
FROM Win32_ComputerSystem
```
- **Namespace**: `root\CimV2`
- **Purpose**: Hardware configuration and system roles

### Storage Management Queries

#### Win32_Volume
```sql
SELECT DeviceId, BlockSize, Capacity, DriveLetter, DriveType,
       FileSystem, FreeSpace, Label, SystemName
FROM Win32_Volume
```
- **Namespace**: `root\CimV2`
- **Purpose**: Volume information (fallback for older systems)

#### MSFT_Volume
```sql
SELECT * FROM MSFT_Volume
```
- **Namespace**: `root\Microsoft\Windows\Storage`
- **Purpose**: Modern storage management (Windows 8/2012+)

### Network Configuration Queries

#### Win32_NetworkAdapterConfiguration
```sql
SELECT * FROM Win32_NetworkAdapterConfiguration
WHERE IPEnabled = true
```
- **Namespace**: `root\CimV2`
- **Purpose**: Network adapter settings and IP configuration

#### MSFT_NetTCPConnection
```sql
SELECT LocalAddress, LocalPort, OwningProcess, RemoteAddress, RemotePort
FROM MSFT_NetTCPConnection
WHERE RemoteAddress IS NOT NULL
  AND RemoteAddress != '::'
  AND RemoteAddress != '::1'
  AND RemoteAddress != '0.0.0.0'
  AND RemoteAddress != '127.0.0.1'
  AND RemoteAddress != LocalAddress
```
- **Namespace**: `root\StandardCimv2`
- **Purpose**: Active TCP connections
- **Fallback**: Netstat command for Windows 2003/2008

### Process Management Queries

#### Win32_Process
```sql
SELECT * FROM Win32_Process
```
- **Namespace**: `root\CimV2`
- **Purpose**: Running process information
- **Additional**: `GetOwner()` method call required for process ownership

### Software Inventory Queries

#### Win32_OptionalFeature
```sql
SELECT * FROM Win32_OptionalFeature
WHERE InstallState = 1
```
- **Namespace**: `root\CimV2`
- **Purpose**: Installed Windows features

#### Win32_QuickFixEngineering
```sql
SELECT * FROM Win32_QuickFixEngineering
```
- **Namespace**: `root\CimV2`
- **Purpose**: Windows updates and security patches

## Class Schemas

### Core System Classes

#### Win32_Processor Schema

| Property                  | Type    | Description                |
|---------------------------|---------|----------------------------|
| Name                      | string  | Processor name/model       |
| Manufacturer              | string  | CPU manufacturer           |
| LoadPercentage            | ushort  | Current CPU load (0-100)   |
| NumberOfCores             | uint    | Physical core count        |
| NumberOfLogicalProcessors | uint    | Logical processor count    |

#### Win32_OperatingSystem Schema

| Property                 | Type     | Description                |
|--------------------------|----------|----------------------------|
| Caption                  | string   | OS display name            |
| Version                  | string   | OS version number          |
| BuildNumber              | string   | OS build number            |
| OSArchitecture           | string   | 32-bit or 64-bit           |
| LastBootUpTime           | DateTime | System boot time           |
| FreePhysicalMemory       | ulong    | Free memory in KB          |
| TotalVisibleMemorySize   | ulong    | Total memory in KB         |
| ServicePackMajorVersion  | ushort   | Service pack major version |
| ServicePackMinorVersion  | ushort   | Service pack minor version |

### Computed Properties

- `MemoryPercentageUsed`: byte (Calculated memory usage percentage)

## Error Handling & Diagnostics

### Exception Types & Handling

#### ManagementException
- **ErrorCode**: `ManagementStatus` enumeration
- **Common Codes**:
  - `AccessDenied`: Insufficient permissions
  - `InvalidClass`: WMI class doesn't exist
  - `InvalidNamespace`: Namespace not found

#### COMException
- **HRESULT Codes**:
  - `0x80070005`: Access denied
  - `0x80041003`: WBEM_E_ACCESS_DENIED
  - `0x800706BA`: RPC server unavailable

#### UnauthorizedAccessException
- Indicates permission issues with specific WMI queries
- May occur even with valid credentials due to WMI security settings

### Diagnostic Tracking

```csharp
public class ScanDiagnostic {
    long ElapsedMilliseconds;
    QueryEnum Query;
    bool Success;
    string ErrorMessage;
}
```

## Performance Considerations

### Query Optimization Strategies

1. **Selective Field Queries**
   - Always specify required fields in SELECT clause
   - Avoid `SELECT *` except where necessary

2. **Filtered Queries**
   - Use WHERE clauses to reduce result sets
   - Filter at WMI level, not in application code

3. **Batch Operations**
   - Group related queries to minimize round trips
   - Reuse WMIHelper connections

4. **Memory Management**
   - String interning for duplicate strings
   - Dispose WMI objects properly
   - Limit result set sizes where possible

### Performance Monitoring

```csharp
using (var timer = new PerfTimerLogger($"WMI {hostname}: {query}", log)) {
    // Execute WMI query
    // Timer automatically logs duration
}
```

### Recommended Timeouts
- Standard queries: 30 seconds
- Event log queries: 60 seconds
- Large result sets: 120 seconds

## Backwards Compatibility Requirements

### Critical Compatibility Points

1. **Property Names**
   - All property names must match exactly (case-sensitive)
   - Computed properties must use `[WMIIgnore]` attribute
   - String interning must be preserved for memory efficiency

2. **Query Results**
   - Null results must be handled as empty lists
   - Missing properties must not cause exceptions
   - Type conversions must match original implementation

3. **Namespace Fallbacks**
   - `MSFT_Volume` → `Win32_Volume`
   - `MSFT_NetTCPConnection` → Netstat command
   - Missing namespaces must not fail entire scan

4. **Authentication Levels**
   - Default: Packet
   - MSCluster: PacketPrivacy required
   - WebAdministration: PacketPrivacy required

5. **OS Version Detection**
   - Windows Server 2003: Limited WMI support
   - Windows Server 2008: Partial StandardCimv2
   - Windows Server 2012+: Full feature set

## Security Considerations

### Authentication Requirements
- Never store credentials in plain text
- Use secure string for password handling
- Implement credential caching carefully
- Log authentication attempts for audit

### Permission Requirements
- Local Administrator or Domain Admin
- WMI/DCOM permissions configured
- Remote Registry access (for some queries)
- Performance Monitor user rights

### Network Security
- Use PacketPrivacy for sensitive namespaces
- Encrypt credentials in transit
- Implement connection throttling
- Monitor for authentication failures

## Implementation Checklist

### Phase 1: Core Infrastructure
- [ ] Implement WMIHelper wrapper class
- [ ] Create connection management with retry logic
- [ ] Implement namespace detection and fallback
- [ ] Set up performance monitoring framework

### Phase 2-8: Systematic Implementation
(Detailed phases include system information, process management, storage, network configuration, advanced features, testing, and validation)

## Appendices

### Appendix A: Query Enum Reference
(Includes comprehensive list of query enumerations)

### Appendix B: Common HRESULT Error Codes
(Detailed list of error codes and their descriptions)

### Appendix C: OS Version Compatibility Matrix
(Comprehensive table of namespace support across different Windows versions)

---

**Document Version**: 1.0
**Last Updated**: 2025-01-16
**Status**: Complete Requirements Specification

**Purpose**: Blueprint for WMI Query Provider Reimplementation
