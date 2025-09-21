# Active Directory Testing Guide

## Known-Good Test Environments

### Verified Configurations

| Environment | Domain Controller       | Client OS    | Kerberos    | Status      |
|-------------|-------------------------|--------------|-------------|-------------|
| **Lab 1**   | Windows Server 2022     | Ubuntu 22.04 | MIT 1.19.2  | ✅ Verified |
| **Lab 2**   | Windows Server 2019     | macOS 14     | Heimdal 7.8 | ✅ Verified |
| **Lab 3**   | Windows 11 Pro (Domain) | Ubuntu 20.04 | MIT 1.17    | ✅ Verified |

### Test Domain Configuration

```powershell
# Example AD Domain: TESTLAB.LOCAL
Domain: TESTLAB.LOCAL
DC: dc01.testlab.local (192.168.10.10)
Target: win11.testlab.local (192.168.10.50)
User: wmitest@TESTLAB.LOCAL
SPN: HOST/win11.testlab.local
```

## Prerequisites

### 1. Kerberos Configuration

Create `/etc/krb5.conf`:
```ini
[libdefaults]
    default_realm = TESTLAB.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false
    # Disable RC4 for security
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[realms]
    TESTLAB.LOCAL = {
        kdc = dc01.testlab.local
        admin_server = dc01.testlab.local
    }

[domain_realm]
    .testlab.local = TESTLAB.LOCAL
    testlab.local = TESTLAB.LOCAL
```

### 2. DNS Configuration

Ensure proper DNS resolution:
```bash
# Test DNS
nslookup win11.testlab.local
nslookup -type=SRV _kerberos._tcp.testlab.local

# Add to /etc/hosts if needed
192.168.10.10 dc01.testlab.local dc01
192.168.10.50 win11.testlab.local win11
```

### 3. Time Synchronization

Critical for Kerberos (5-minute tolerance):
```bash
# Sync with DC
sudo ntpdate dc01.testlab.local

# Or use chrony
sudo chronyc sources
```

## Running E2E Tests

### Step 1: Obtain Kerberos Ticket

```bash
# Authenticate
kinit wmitest@TESTLAB.LOCAL
Password: ********

# Verify ticket
klist
# Output:
# Ticket cache: FILE:/tmp/krb5cc_1000
# Default principal: wmitest@TESTLAB.LOCAL
# Valid starting     Expires            Service principal
# 01/20/24 10:00:00  01/21/24 10:00:00  krbtgt/TESTLAB.LOCAL@TESTLAB.LOCAL
```

### Step 2: Run Test with Packet Capture

```bash
# Start capture
cd linux-wmi
./examples/test_kerberos_e2e.sh TESTLAB.LOCAL win11.testlab.local true

# Or manually with specific query
RUST_LOG=debug cargo run --example test_connect --features kerberos -- \
    --host win11.testlab.local \
    --domain TESTLAB.LOCAL \
    --auth-type kerberos \
    --query "SELECT Name, TotalPhysicalMemory FROM Win32_ComputerSystem"
```

### Step 3: Verify Golden Packets

Expected packet sequence in capture:
```
1. DNS:  A/AAAA query for win11.testlab.local
2. TCP:  Connect to port 135 (EPM)
3. RPC:  Bind with Kerberos auth
   - AP-REQ in bind PDU (leg 1)
   - AP-REP in bind_ack (leg 2)
   - Empty token in alter_context (leg 3)
4. RPC:  DCOM activation (encrypted)
5. TCP:  Connect to dynamic port (49152-65535)
6. RPC:  WMI queries (protected with IOV)
```

## Golden Packet Captures

### Capture Locations

```bash
captures/
├── kerberos_dce_20240120_lab1.pcap    # Windows Server 2022
├── kerberos_dce_20240120_lab2.pcap    # Windows Server 2019
└── kerberos_dce_20240120_lab3.pcap    # Windows 11 Domain
```

### Analyzing Captures

```bash
# View Kerberos handshake
tshark -r captures/kerberos_dce_*.pcap -Y "kerberos" -V

# DCE/RPC with auth
tshark -r captures/kerberos_dce_*.pcap -Y "dcerpc.auth_type == 0x10"

# GSS-API tokens
tshark -r captures/kerberos_dce_*.pcap -Y "gss-api"

# Statistics
capinfos captures/kerberos_dce_*.pcap
```

### Key Packet Indicators

✅ **Successful Authentication:**
- Bind PDU with auth_type=0x10 (Kerberos)
- Bind_ack with result=0 (success)
- Alter_context with third leg token
- Encrypted DCOM/WMI traffic

❌ **Common Failures:**
- KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN - Wrong SPN
- KRB5KRB_AP_ERR_MODIFIED - Clock skew
- GSS_S_NO_CRED - No ticket
- Access Denied - WMI permissions

## Troubleshooting

### Debug Kerberos

```bash
# Enable trace
export KRB5_TRACE=/tmp/krb5_trace.log
cargo run --example test_connect --features kerberos ...

# Check trace
grep -E "AP-REQ|AP-REP|GSS|Error" /tmp/krb5_trace.log
```

### WMI Permissions

On Windows target:
```powershell
# Grant WMI access
winmgmt /verifyrepository
wmimgmt.msc
# Right-click WMI Control > Properties > Security
# Add user, grant "Enable Account" and "Remote Enable"

# Or via PowerShell
$user = "TESTLAB\wmitest"
$namespace = "root\cimv2"
$sddl = (Get-WmiObject -Namespace $namespace -Class __SystemSecurity).GetSecurityDescriptor().Descriptor
# Add permissions...
```

### Network Issues

```bash
# Test connectivity
nc -zv win11.testlab.local 135    # EPM
nc -zv win11.testlab.local 445    # SMB (optional)

# Firewall rules (Windows)
netsh advfirewall firewall add rule name="WMI-In" dir=in action=allow protocol=TCP localport=135
netsh advfirewall firewall add rule name="WMI-Async" dir=in action=allow protocol=TCP localport=49152-65535
```

## Performance Benchmarks

### Expected Metrics (LAN)

| Operation           | Time   | Notes                     |
|---------------------|--------|---------------------------|
| Kerberos auth       | <50ms  | 3-leg handshake           |
| DCOM activation     | <100ms | OXID resolution           |
| WMI query (simple)  | <200ms | Win32_ComputerSystem      |
| WMI query (complex) | <500ms | Win32_Process enumeration |

### Optimization Tips

1. **Credential Cache**: Reuse tickets
   ```bash
   export KRB5CCNAME=/tmp/krb5cc_persistent
   ```

2. **Connection Pooling**: Reuse RPC channels

3. **Query Optimization**: Use WHERE clauses
   ```sql
   SELECT Name FROM Win32_Process WHERE ProcessId = 0
   ```

## CI Integration

### GitHub Actions

```yaml
name: AD Integration Tests

on:
  workflow_dispatch:
    inputs:
      test_domain:
        description: 'AD Domain'
        required: true
        default: 'TESTLAB.LOCAL'

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4

    - name: Setup Kerberos
      run: |
        sudo apt-get update
        sudo apt-get install -y krb5-user libkrb5-dev

    - name: Configure Kerberos
      run: |
        echo "${{ secrets.KRB5_CONF }}" | sudo tee /etc/krb5.conf
        echo "${{ secrets.KRB5_KEYTAB }}" | base64 -d > /tmp/test.keytab
        kinit -kt /tmp/test.keytab wmitest@${{ github.event.inputs.test_domain }}

    - name: Run Tests
      run: |
        cargo test --features kerberos --test integration

    - name: Capture Packets
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: packet-captures
        path: captures/
```

## Security Notes

⚠️ **Never commit:**
- Passwords or keytabs
- Production krb5.conf with internal IPs
- Packet captures with sensitive data

✅ **Best practices:**
- Use dedicated test accounts
- Rotate test credentials regularly
- Sanitize captures before sharing
- Use read-only WMI permissions

## References

- [MS-DCOM]: Distributed Component Object Model
- [MS-RPCE]: Remote Procedure Call Extensions
- [MS-WMI]: Windows Management Instrumentation
- [RFC 4120]: The Kerberos Network Authentication Service (V5)
