#!/usr/bin/env bash
# End-to-end connectivity test for linux-wmi against a real Windows host.
# Usage: ./test_e2e.sh [HOST] [USER] [PASS] [DOMAIN] [QUERY]
# Defaults: HOST=localhost, USER=wmi-test, PASS=P@ssw0rd123, DOMAIN="", QUERY="SELECT * FROM Win32_ComputerSystem"

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

HOST="${1:-localhost}"
USER="${2:-wmi-test}"
PASS="${3:-P@ssw0rd123}"
DOMAIN="${4:-}"
QUERY="${5:-SELECT * FROM Win32_ComputerSystem}"

: "${RUST_LOG:=linux_wmi=debug}"
: "${LINUX_WMI_SKIP_EPM:=0}"
TIMEOUT_SECS=60
TIMEOUT_BIN="$(command -v timeout || command -v gtimeout || true)"
LOG_FILE="${SCRIPT_DIR}/test_output.log"

cat <<INFO
🚀 Running linux-wmi e2e test
   Host  : ${HOST}
   User  : ${USER}
   Domain: ${DOMAIN:-<local>}
   Query : ${QUERY}
   Skip EPM/bind: ${LINUX_WMI_SKIP_EPM}
   Logs  : ${LOG_FILE}
   Timeout: $(if [[ -n "${TIMEOUT_BIN}" ]]; then echo "${TIMEOUT_SECS}s via ${TIMEOUT_BIN}"; else echo "disabled"; fi)
INFO

if [[ "${LINUX_WMI_SKIP_EPM}" != "1" ]]; then
  cat <<'TIP'
📌 Ensure the target allows RPC/WMI:
   - User has Distributed COM Users + WMI namespace permissions (root\CIMV2).
   - Windows Firewall allows RPC Endpoint Mapper (TCP 135) and dynamic RPC ports (49152-65535).
   - Consider capturing with Wireshark (filter: dcerpc) for verification.
TIP

  if command -v ping >/dev/null 2>&1; then
    if ! ping -c 1 "${HOST}" >/dev/null 2>&1; then
      echo "❌ Host ${HOST} unreachable (ping failed)." >&2
      exit 1
    fi
  fi

  if command -v nc >/dev/null 2>&1; then
    if ! nc -z -w 5 "${HOST}" 135 >/dev/null 2>&1 && ! nc -z -G 5 "${HOST}" 135 >/dev/null 2>&1; then
      echo "❌ Port 135 closed or unreachable on ${HOST}." >&2
      exit 1
    fi
  fi
fi

trap 'echo "Logs saved to ${LOG_FILE}"' EXIT

export RUST_LOG
export LINUX_WMI_SKIP_EPM
cd "${REPO_ROOT}"

if [[ -n "${TIMEOUT_BIN}" ]]; then
  ${TIMEOUT_BIN} "${TIMEOUT_SECS}"s cargo run --example test_connect -- \
      "${HOST}" \
      --user "${USER}" \
      --pass "${PASS}" \
      --domain "${DOMAIN}" \
      --query "${QUERY}" >"${LOG_FILE}" 2>&1
  RC=$?
  if [[ $RC -eq 124 ]]; then
    echo "❌ Test timed out after ${TIMEOUT_SECS}s (network hang?)." >&2
    tail -n 50 "${LOG_FILE}"
    exit 1
  fi
else
  cargo run --example test_connect -- \
      "${HOST}" \
      --user "${USER}" \
      --pass "${PASS}" \
      --domain "${DOMAIN}" \
      --query "${QUERY}" >"${LOG_FILE}" 2>&1
  RC=$?
fi

if [[ $RC -ne 0 ]]; then
  echo "❌ Test failed (RC=${RC}). See ${LOG_FILE} for details." >&2
  tail -n 50 "${LOG_FILE}"
  exit 1
fi

if ! grep -q 'Query result:' "${LOG_FILE}"; then
  echo "❌ Test did not return query output." >&2
  tail -n 50 "${LOG_FILE}"
  exit 1
fi

echo "✅ Test succeeded." 
if command -v jq >/dev/null 2>&1; then
  echo "🔎 Sample logs:"
  jq '. | select(.target == "linux_wmi::transport")' "${LOG_FILE}" | head -n 10 || true
else
  echo "📄 Last log lines:"
  tail -n 20 "${LOG_FILE}"
fi
