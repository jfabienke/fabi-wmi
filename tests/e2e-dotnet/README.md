# End-to-End Tests for linux-wmi

This directory contains comprehensive end-to-end tests that validate the entire linux-wmi stack from C# through Rust to Windows WMI.

## Prerequisites

- .NET 10 SDK or later
- A Windows host with:
  - WMI service running
  - RPC Endpoint Mapper accessible (port 135)
  - Dynamic RPC ports open (49152-65535)
  - A test user with appropriate permissions

## Test Organization

Tests are organized by priority:

### Priority 0: Critical Path Tests
- **ConnectionTests**: Verify successful authentication and session creation
- **BasicQueryTests**: Test WQL queries returning multiple objects
- **StaticMethodTests**: Test static method execution with parameters

### Priority 1: Error Handling Tests
- **ErrorHandlingTests**: Ensure graceful failure with actionable errors
  - Invalid credentials
  - Unreachable hosts
  - Invalid queries
  - Timeouts

### Priority 2: Data Handling Tests
- **DataHandlingTests**: Cover edge cases and data type handling
  - Empty result sets
  - Various CIM data types
  - Large result sets
  - Unicode strings
  - Nullable properties

## Configuration

Tests can be configured via:

1. **appsettings.json**: Default configuration file
2. **Environment variables**: Override settings with `WMI_TEST_` prefix
3. **Command line**: Pass parameters to the test runner

### Environment Variables
```bash
export WMI_TEST_DEFAULTHOST=192.168.1.100
export WMI_TEST_DEFAULTUSERNAME=wmi-test
export WMI_TEST_DEFAULTPASSWORD=MyPassword123
export WMI_TEST_DEFAULTDOMAIN=MYDOMAIN
export WMI_TEST_SKIPNETWORKTESTS=false
export WMI_TEST_SKIPAUTHTESTS=false
```

## Running Tests

### Using the Shell Script (Recommended)
```bash
# Run all tests with default configuration
../../examples/run_dotnet_tests.sh

# Run tests against specific host
../../examples/run_dotnet_tests.sh --host 192.168.1.100 --user admin --pass AdminPass

# Run specific test category
../../examples/run_dotnet_tests.sh --filter "Category=Priority0"

# Run with verbose output
../../examples/run_dotnet_tests.sh --verbose
```

### Using dotnet CLI Directly
```bash
# Restore packages
dotnet restore

# Build the test project
dotnet build

# Run all tests
dotnet test

# Run specific tests
dotnet test --filter "FullyQualifiedName~Priority0"

# Run with detailed output
dotnet test --logger "console;verbosity=detailed"
```

## Test Categories

Tests can be filtered by category:
- `Priority0`: Critical path validation
- `Priority1`: Error handling
- `Priority2`: Data handling edge cases

Example:
```bash
dotnet test --filter "Category=Priority0"
```

## Continuous Integration

These tests can be integrated into CI/CD pipelines. Example GitHub Actions workflow:

```yaml
name: E2E Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      windows:
        image: mcr.microsoft.com/windows/servercore:ltsc2022
        options: --platform windows

    steps:
    - uses: actions/checkout@v3
    - uses: actions/setup-dotnet@v3
      with:
        dotnet-version: '10.0.x'

    - name: Build Rust library
      run: cargo build --lib

    - name: Run E2E tests
      run: ./examples/run_dotnet_tests.sh --host windows --user testuser --pass testpass
```

## Troubleshooting

### Common Issues

1. **Library not found**: Ensure the Rust library is built and in the correct location
   ```bash
   cargo build --lib
   ```

2. **Authentication failures**: Verify the test user has:
   - DCOM permissions (Launch and Activation)
   - WMI namespace permissions (root\CIMV2)
   - Membership in "Distributed COM Users" group

3. **Network errors**: Check that:
   - Windows Firewall allows RPC (port 135 and dynamic ports)
   - The host is reachable from the test machine
   - WMI service is running on the Windows host

4. **Test timeouts**: Increase timeout in configuration:
   ```json
   {
     "TestConfiguration": {
       "DefaultTimeout": "00:01:00"
     }
   }
   ```

## Adding New Tests

To add new tests:

1. Create a new test class in the `Tests` directory
2. Inherit from `E2ETestBase`
3. Use the `CreateWmiHelper()` method to get a configured WMI client
4. Follow the naming convention: `TestXXX_Description_ExpectedResult`

Example:
```csharp
public class MyNewTests : E2ETestBase
{
    public MyNewTests(ITestOutputHelper output) : base(output) { }

    [Fact]
    public void Test100_MyNewFeature_WorksCorrectly()
    {
        // Arrange
        SkipIfNetworkTestsDisabled();
        using var wmi = CreateWmiHelper();

        // Act
        var result = wmi.Query<MyClass>("SELECT * FROM Win32_MyClass");

        // Assert
        result.Should().NotBeEmpty();
    }
}
```

## Test Data Classes

Define C# classes that match the WMI class properties you're querying:

```csharp
public class Win32_MyClass
{
    public string? Name { get; set; }
    public uint Id { get; set; }
    public DateTime? CreatedDate { get; set; }
}
```

The JSON deserializer will automatically map WMI properties to these C# properties.