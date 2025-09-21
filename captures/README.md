# Golden Packet Captures

This directory contains reference packet captures of successful Kerberos DCE/RPC authentication against various Windows environments.

## Capture Files

| File | Environment | Date | Status |
|------|------------|------|--------|
| `kerberos_dce_win2022.pcap` | Windows Server 2022 DC | TBD | Pending |
| `kerberos_dce_win2019.pcap` | Windows Server 2019 DC | TBD | Pending |
| `kerberos_dce_win11.pcap` | Windows 11 Pro (Domain) | TBD | Pending |

## Capture Protocol

Each capture includes:
1. DNS resolution for target FQDN
2. Kerberos DCE/RPC 3-leg handshake
3. DCOM activation with OXID resolution
4. WMI ConnectServer and ExecQuery
5. Both Integrity and Privacy mode examples

## Analysis Commands

```bash
# View summary
capinfos *.pcap

# Extract Kerberos messages
tshark -r kerberos_dce_*.pcap -Y "kerberos" -T fields \
    -e frame.number -e kerberos.msg_type -e kerberos.realm

# DCE/RPC auth types
tshark -r kerberos_dce_*.pcap -Y "dcerpc.auth_type" -T fields \
    -e dcerpc.auth_type -e dcerpc.auth_level

# WMI queries
tshark -r kerberos_dce_*.pcap -Y "dcerpc.cn_opnum == 3" -V
```

## Privacy Note

⚠️ **These captures may contain:**
- Internal hostnames and IP addresses
- Kerberos realm names
- Encrypted credentials (safe)

Before sharing publicly:
1. Sanitize with `tcprewrite`
2. Remove sensitive queries
3. Anonymize IP addresses

## Generating New Captures

Use the provided script:
```bash
../examples/test_kerberos_e2e.sh DOMAIN.COM target.domain.com true
```

Or manually:
```bash
# Terminal 1: Start capture
sudo tcpdump -i any -w new_capture.pcap \
    'host TARGET_IP and (port 88 or port 135 or port 445 or portrange 49152-65535)'

# Terminal 2: Run test
cargo run --example test_connect --features kerberos -- \
    --host target.domain.com \
    --auth-type kerberos \
    --query "SELECT Name FROM Win32_ComputerSystem"
```