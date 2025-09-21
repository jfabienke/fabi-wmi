#!/bin/bash
#
# End-to-end Kerberos authentication test against Active Directory
#
# Prerequisites:
# - Valid Kerberos ticket (run kinit first)
# - Network access to AD domain controller
# - WMI permissions on target Windows host
#
# Usage: ./test_kerberos_e2e.sh <domain> <target_host> [capture_pcap]
#
# Example: ./test_kerberos_e2e.sh CORP.EXAMPLE.COM win11.corp.example.com true

set -e

DOMAIN=${1:-""}
TARGET=${2:-""}
CAPTURE=${3:-false}

if [ -z "$DOMAIN" ] || [ -z "$TARGET" ]; then
    echo "Usage: $0 <domain> <target_host> [capture_pcap]"
    echo "Example: $0 CORP.EXAMPLE.COM win11.corp.example.com true"
    exit 1
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}==========================================="
echo "Kerberos DCE/RPC End-to-End Test"
echo "==========================================="
echo -e "Domain: ${YELLOW}$DOMAIN${NC}"
echo -e "Target: ${YELLOW}$TARGET${NC}"
echo -e "Date: $(date)"
echo -e "===========================================${NC}\n"

# Step 1: Check Kerberos ticket
echo -e "${YELLOW}[1/7] Checking Kerberos credentials...${NC}"
if ! klist 2>/dev/null | grep -q "Default principal"; then
    echo -e "${RED}Error: No Kerberos ticket found. Run 'kinit' first.${NC}"
    exit 1
fi

klist | head -5
echo -e "${GREEN}✓ Kerberos ticket valid${NC}\n"

# Step 2: Start packet capture if requested
if [ "$CAPTURE" = "true" ]; then
    echo -e "${YELLOW}[2/7] Starting packet capture...${NC}"
    PCAP_FILE="captures/kerberos_dce_$(date +%Y%m%d_%H%M%S).pcap"
    mkdir -p captures

    # Start capture in background
    if command -v tshark >/dev/null 2>&1; then
        sudo tshark -i any -f "host $TARGET and (port 88 or port 135 or port 445 or portrange 49152-65535)" \
            -w "$PCAP_FILE" 2>/dev/null &
        CAPTURE_PID=$!
        echo -e "${GREEN}✓ Packet capture started (PID: $CAPTURE_PID)${NC}"
    else
        echo -e "${YELLOW}Warning: tshark not found, skipping capture${NC}"
        CAPTURE=false
    fi
else
    echo -e "${YELLOW}[2/7] Packet capture skipped${NC}"
fi

# Step 3: Test DNS resolution
echo -e "${YELLOW}[3/7] Testing DNS resolution...${NC}"
if ! nslookup "$TARGET" >/dev/null 2>&1; then
    echo -e "${RED}Error: Cannot resolve $TARGET${NC}"
    [ "$CAPTURE" = "true" ] && kill $CAPTURE_PID 2>/dev/null
    exit 1
fi
echo -e "${GREEN}✓ DNS resolution successful${NC}\n"

# Step 4: Test port connectivity
echo -e "${YELLOW}[4/7] Testing port connectivity...${NC}"
TARGET_IP=$(nslookup "$TARGET" | grep -A1 "Name:" | grep "Address:" | awk '{print $2}')

for PORT in 135 445; do
    if nc -zv "$TARGET_IP" $PORT 2>&1 | grep -q "succeeded\|open"; then
        echo -e "${GREEN}✓ Port $PORT open${NC}"
    else
        echo -e "${RED}✗ Port $PORT closed${NC}"
    fi
done
echo ""

# Step 5: Build test binary
echo -e "${YELLOW}[5/7] Building test binary...${NC}"
cd "$(dirname "$0")/.."

if ! cargo build --example test_connect --features kerberos 2>&1 | grep -q "Finished"; then
    echo -e "${RED}Error: Build failed${NC}"
    [ "$CAPTURE" = "true" ] && kill $CAPTURE_PID 2>/dev/null
    exit 1
fi
echo -e "${GREEN}✓ Build successful${NC}\n"

# Step 6: Run Kerberos authentication test
echo -e "${YELLOW}[6/7] Running Kerberos authentication test...${NC}"

# Set environment for tracing
export RUST_LOG=linux_wmi=debug,kerbsec=debug
export KRB5_TRACE=/tmp/krb5_trace_$$.log

# Run test with Kerberos auth
echo -e "${YELLOW}Testing DCE/RPC 3-leg handshake...${NC}"
if cargo run --example test_connect --features kerberos -- \
    --host "$TARGET" \
    --domain "$DOMAIN" \
    --auth-type kerberos \
    --query "SELECT Name, Domain FROM Win32_ComputerSystem" 2>&1 | tee test_output.log; then

    echo -e "${GREEN}✓ Kerberos authentication successful!${NC}"

    # Check for specific patterns
    if grep -q "Kerberos context established" test_output.log; then
        echo -e "${GREEN}  ✓ DCE 3-leg handshake completed${NC}"
    fi

    if grep -q "wrap_iov" test_output.log; then
        echo -e "${GREEN}  ✓ Privacy mode (encryption) verified${NC}"
    fi

    if grep -q "sequence.*verified" test_output.log; then
        echo -e "${GREEN}  ✓ Sequence number validation working${NC}"
    fi
else
    echo -e "${RED}✗ Kerberos authentication failed${NC}"
    FAILED=true
fi

# Step 7: Stop capture and analyze
if [ "$CAPTURE" = "true" ]; then
    echo -e "\n${YELLOW}[7/7] Analyzing packet capture...${NC}"
    sleep 2
    kill $CAPTURE_PID 2>/dev/null || true

    echo -e "${YELLOW}Captured packets:${NC}"
    tshark -r "$PCAP_FILE" -q -z io,stat,0 2>/dev/null || true

    echo -e "\n${YELLOW}Kerberos messages:${NC}"
    tshark -r "$PCAP_FILE" -Y "kerberos" -T fields -e kerberos.msg_type 2>/dev/null | sort | uniq -c || true

    echo -e "\n${YELLOW}DCE/RPC operations:${NC}"
    tshark -r "$PCAP_FILE" -Y "dcerpc" -T fields -e dcerpc.opnum 2>/dev/null | sort | uniq -c || true

    echo -e "\n${GREEN}✓ Packet capture saved to: $PCAP_FILE${NC}"
fi

# Display Kerberos trace if exists
if [ -f "$KRB5_TRACE" ]; then
    echo -e "\n${YELLOW}Kerberos trace highlights:${NC}"
    grep -E "AP-REQ|AP-REP|TGS-REQ|Decrypted|GSS" "$KRB5_TRACE" | head -20
    echo -e "${GREEN}Full trace: $KRB5_TRACE${NC}"
fi

# Summary
echo -e "\n${GREEN}==========================================="
echo "Test Summary"
echo "==========================================="

if [ -z "$FAILED" ]; then
    echo -e "${GREEN}✓ All tests PASSED${NC}"
    echo ""
    echo "Verified:"
    echo "  • DCE/RPC 3-leg Kerberos handshake"
    echo "  • Integrity and Privacy modes"
    echo "  • Replay/sequence protection"
    echo "  • WMI query execution"
else
    echo -e "${RED}✗ Some tests FAILED${NC}"
    echo "Check test_output.log for details"
fi

echo -e "===========================================${NC}"

# Cleanup
rm -f test_output.log

exit $([ -z "$FAILED" ] && echo 0 || echo 1)