# Integration Testing Guide for fabi-wmi

This guide provides instructions for setting up and running integration tests against real Windows hosts.

## Prerequisites

### Windows Host Setup

1. **Enable DCOM/WMI Access**
   ```powershell
   # Run as Administrator
   Enable-PSRemoting -Force
   winrm quickconfig
   ```

2. **Configure DCOM Settings**
   - Run `dcomcnfg.exe`
   - Navigate to Component Services → Computers → My Computer
   - Right-click → Properties → Default Properties
   - Enable "Enable Distributed COM"
   - Set Default Authentication Level to "Connect" or "None"
   - Set Default Impersonation Level to "Identify" or "Impersonate"

3. **Add Test User to Required Groups**
   ```powershell
   # Add user to necessary groups
   Add-LocalGroupMember -Group "Distributed COM Users" -Member "DOMAIN\testuser"
   Add-LocalGroupMember -Group "Performance Monitor Users" -Member "DOMAIN\testuser"
   ```

4. **Configure WMI Permissions**
   - Run `wmimgmt.msc`
   - Right-click WMI Control → Properties → Security
   - Select "Root\CIMV2" namespace
   - Click Security → Add your test user
   - Grant permissions: Enable Account, Remote Enable, Execute Methods, Read Security

5. **Firewall Configuration**
   ```powershell
   # Allow WMI through firewall
   netsh advfirewall firewall set rule group="Windows Management Instrumentation (WMI)" new enable=yes

   # Or create specific rules
   New-NetFirewallRule -DisplayName "WMI-In" -Direction Inbound -Protocol TCP -LocalPort 135 -Action Allow
   New-NetFirewallRule -DisplayName "WMI-Async-In" -Direction Inbound -Protocol TCP -LocalPort 49152-65535 -Action Allow
   ```

## Running Integration Tests

### Basic Test Execution

```bash
# Set test environment variables
export LINUX_WMI_TEST_HOST="192.168.1.100"
export LINUX_WMI_TEST_USER="testuser"
export LINUX_WMI_TEST_PASS="TestPassword123!"
export LINUX_WMI_TEST_DOMAIN="TESTDOMAIN"

# Run integration tests
cargo test --features integration-tests -- --test-threads=1

# Run specific integration test
cargo test --features integration-tests test_real_connection -- --nocapture
```

### Using the E2E Test Script

```bash
# Basic query test
./examples/test_e2e.sh $LINUX_WMI_TEST_HOST $LINUX_WMI_TEST_USER $LINUX_WMI_TEST_PASS $LINUX_WMI_TEST_DOMAIN "SELECT Name FROM Win32_ComputerSystem"

# Process enumeration
./examples/test_e2e.sh $LINUX_WMI_TEST_HOST $LINUX_WMI_TEST_USER $LINUX_WMI_TEST_PASS $LINUX_WMI_TEST_DOMAIN "SELECT * FROM Win32_Process"

# Method execution test (requires ExecMethod support)
cargo run --example full_wmi_query -- --host $LINUX_WMI_TEST_HOST --user $LINUX_WMI_TEST_USER --pass $LINUX_WMI_TEST_PASS
```

### Kerberos Authentication Tests

```bash
# Ensure Kerberos is configured
kinit $LINUX_WMI_TEST_USER@$LINUX_WMI_TEST_DOMAIN

# Run with Kerberos
cargo test --features kerberos,integration-tests test_kerberos_auth

# Test with delegation (requires proper SPN configuration)
export LINUX_WMI_ENABLE_DELEGATION=1
cargo test --features kerberos,integration-tests test_delegated_auth
```

## Troubleshooting

### Common Issues

1. **Connection Refused (TCP 135)**
   - Verify DCOM is enabled
   - Check Windows Firewall settings
   - Ensure RPC service is running: `sc query rpcss`

2. **Access Denied Errors**
   - Verify user is in "Distributed COM Users" group
   - Check WMI namespace permissions
   - Try with domain administrator account for testing

3. **RPC Server Unavailable**
   - Check if dynamic RPC ports are accessible (49152-65535)
   - Test with `nmap -p 135,445,49152-49200 $LINUX_WMI_TEST_HOST`

4. **Authentication Failures**
   - Verify credentials are correct
   - Check domain trust relationships
   - For Kerberos: verify SPN registration with `setspn -L computername`

### Debug Logging

```bash
# Enable detailed logging
export RUST_LOG=fabi_wmi=debug,fabi_wmi::transport=trace

# Run with debug output
cargo run --example test_connect $LINUX_WMI_TEST_HOST --user $LINUX_WMI_TEST_USER --pass $LINUX_WMI_TEST_PASS --domain $LINUX_WMI_TEST_DOMAIN 2>&1 | tee debug.log
```

### Network Diagnostics

```bash
# Test RPC endpoint mapper
rpcinfo -t $LINUX_WMI_TEST_HOST 135

# Test connectivity to WMI
nc -zv $LINUX_WMI_TEST_HOST 135
nc -zv $LINUX_WMI_TEST_HOST 445

# Capture network traffic for analysis
sudo tcpdump -i any -w wmi-capture.pcap host $LINUX_WMI_TEST_HOST and tcp
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Integration Tests
on: [push, pull_request]

jobs:
  integration:
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'

    steps:
    - uses: actions/checkout@v2

    - name: Setup Windows Test Environment
      run: |
        # This would typically provision a test Windows VM
        # or connect to a persistent test environment

    - name: Run Integration Tests
      env:
        LINUX_WMI_TEST_HOST: ${{ secrets.TEST_HOST }}
        LINUX_WMI_TEST_USER: ${{ secrets.TEST_USER }}
        LINUX_WMI_TEST_PASS: ${{ secrets.TEST_PASS }}
        LINUX_WMI_TEST_DOMAIN: ${{ secrets.TEST_DOMAIN }}
      run: |
        cargo test --features integration-tests
```

## Security Considerations

1. **Never commit credentials** - Use environment variables or secure vaults
2. **Use dedicated test accounts** with minimal required permissions
3. **Isolate test environments** from production networks
4. **Rotate test credentials** regularly
5. **Monitor test accounts** for unauthorized usage

## Performance Testing

```bash
# Benchmark query performance
cargo bench --features integration-tests

# Stress test with concurrent connections
for i in {1..10}; do
  cargo run --example test_connect $LINUX_WMI_TEST_HOST --user $LINUX_WMI_TEST_USER --pass $LINUX_WMI_TEST_PASS &
done
wait
```

## Reporting Issues

When reporting integration test failures, include:
1. Windows version and edition (`winver.exe`)
2. Network topology (domain-joined, workgroup, etc.)
3. Debug logs with `RUST_LOG=fabi_wmi=trace`
4. Wireshark capture if possible
5. Output of diagnostic commands above