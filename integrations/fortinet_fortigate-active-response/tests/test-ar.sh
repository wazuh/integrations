#!/usr/bin/env bash
# =============================================================================
# test-ar.sh  —  Manual test harness for fortigate-block.sh
#
# Usage:
#   bash tests/test-ar.sh block   <IP>       # test block action
#   bash tests/test-ar.sh unblock <IP>       # test unblock action
#   bash tests/test-ar.sh block   <IP> dry   # print JSON only, no API calls
#
# Must be run as root on the Wazuh Manager with fortigate-ar.conf configured.

# =============================================================================
set -euo pipefail

ACTION="${1:-block}"
TEST_IP="${2:-198.51.100.99}"   
DRY_RUN="${3:-}"

# Locate the AR script (works from repo root or after install)
SCRIPT_PATH="${SCRIPT_PATH:-/var/ossec/active-response/bin/fortigate-block.sh}"
if [[ ! -f "${SCRIPT_PATH}" ]]; then
    SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/active-response/fortigate-block.sh"
fi
[[ -f "${SCRIPT_PATH}" ]] || { echo "ERROR: Script not found at ${SCRIPT_PATH}"; exit 1; }

case "${ACTION}" in
    block|add)       AR_CMD="add"    ;;
    unblock|delete)  AR_CMD="delete" ;;
    *) echo "Usage: $0 [block|unblock] [IP] [dry]"; exit 1 ;;
esac

AR_LOG="/var/ossec/logs/active-responses.log"

echo "========================================================"
echo "  Wazuh FortiGate AR — Manual Test"
echo "  Action  : ${AR_CMD}"
echo "  Test IP : ${TEST_IP}"
echo "  Script  : ${SCRIPT_PATH}"
[[ -n "${DRY_RUN}" ]] && echo "  Mode    : DRY RUN"
echo "========================================================"
echo ""

# Build a compact single-line alert JSON (the script's read call reads one line)
ALERT_JSON=$(jq -cn \
  --arg cmd "${AR_CMD}" \
  --arg ts  "$(date -u '+%Y-%m-%dT%H:%M:%S.000+0000')" \
  --arg ip  "${TEST_IP}" \
  '{
    version: 1,
    origin: {name:"test-node", module:"wazuh-execd"},
    command: $cmd,
    parameters: {
      extra_args: [],
      alert: {
        timestamp: $ts,
        rule: {level:10, description:"SSH brute force", id:"5712"},
        agent: {id:"001", name:"test-agent", ip:"10.0.0.5"},
        manager: {name:"wazuh-manager"},
        data: {srcip:$ip, dstip:"10.0.0.5", dstport:"22"}
      }
    }
  }')

# The "continue" message that wazuh-execd sends after check_keys
CONTINUE_MSG='{"version":1,"origin":{"name":"test-node","module":"wazuh-execd"},"command":"continue","parameters":{}}'

# ---------------------------------------------------------------------------
# Dry-run
# ---------------------------------------------------------------------------
if [[ -n "${DRY_RUN}" ]]; then
    echo "--- Alert JSON (compact, one line as script receives it): ---"
    echo "${ALERT_JSON}" | jq .
    echo ""
    echo "--- Continue message (sent after check_keys): ---"
    echo "${CONTINUE_MSG}" | jq .
    echo ""
    echo "Dry-run complete. No API calls were made."
    exit 0
fi

# ---------------------------------------------------------------------------
# Live run — pre-feed approach (see header comment for explanation)
# ---------------------------------------------------------------------------
echo "--- Feeding input to script ---"
echo "  Line 1 → alert JSON  (command=${AR_CMD}, srcip=${TEST_IP})"
echo "  Line 2 → continue    (sent after script writes check_keys)"
echo ""

# Record current log line count so we only show new output from this run
LOG_START=$(wc -l < "${AR_LOG}" 2>/dev/null || echo 0)

printf '%s\n%s\n' "${ALERT_JSON}" "${CONTINUE_MSG}" \
    | bash "${SCRIPT_PATH}" > /dev/null
EXIT_CODE=$?

echo "--- Script exited with code: ${EXIT_CODE} ---"
echo ""
echo "========================================================"
echo "  Active-responses.log (this run only):"
echo "========================================================"
if [[ -f "${AR_LOG}" ]]; then
    tail -n "+$((LOG_START + 1))" "${AR_LOG}"
else
    echo "(log not found at ${AR_LOG})"
fi
echo ""
