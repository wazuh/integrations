#!/usr/bin/env bash
# =============================================================================
# fortigate-block.sh
# Wazuh Active Response — Fortinet FortiGate IP Block/Unblock via REST API
#
# Version  : 2.1.0
# Tested on: FortiOS 7.4.x, Wazuh Manager 4.14
# Requires : bash 4+, curl, jq
#
# Deploy to: /var/ossec/active-response/bin/fortigate-block.sh
# Owner    : root:wazuh    Permissions: 750
#
# DESCRIPTION
# -----------
# When Wazuh detects a malicious source IP this script is invoked by
# wazuh-execd via STDIN (Wazuh 4.2+ JSON protocol). It:
#   ADD    - creates a host address object on FortiGate and appends
#             it to a pre-existing block group using the member-append API
#             (POST .../addrgrp/{group}/member) so existing members are
#             never overwritten.
#   DELETE - removes the address object from the group and optionally
#             deletes the object.
#
# CONFIGURATION
# -------------
# All site-specific settings are read from:
#   /var/ossec/etc/fortigate-ar.conf  
#
# LOGGING
# -------
# All activity - /var/ossec/logs/active-responses.log
# stderr is also redirected there so it never reaches wazuh-execd.
# =============================================================================

readonly SCRIPT_NAME="fortigate-block"
readonly SCRIPT_VERSION="2.1.0"
readonly AR_LOG="/var/ossec/logs/active-responses.log"
readonly CONFIG_FILE="/var/ossec/etc/fortigate-ar.conf"

# Redirect stderr into the AR log — keeps wazuh-execd's STDIN/STDOUT clean
exec 2>>"${AR_LOG}"

# ---------------------------------------------------------------------------
# Logging helper
# ---------------------------------------------------------------------------
log() {
    local level="$1"; shift
    printf '%s [%s][%s] %s\n' \
        "$(date -u '+%Y/%m/%d %H:%M:%S')" "${SCRIPT_NAME}" "${level}" "$*" \
        >> "${AR_LOG}"
}

log "INFO" "======= Script ${SCRIPT_VERSION} started PID=$$ ======="

# ---------------------------------------------------------------------------
# 1. Dependency check
# ---------------------------------------------------------------------------
for cmd in curl jq; do
    if ! command -v "${cmd}" &>/dev/null; then
        log "ERROR" "Required command '${cmd}' not found. Install it and retry."
        exit 1
    fi
done

# ---------------------------------------------------------------------------
# 2. Load configuration
# ---------------------------------------------------------------------------
if [[ ! -f "${CONFIG_FILE}" ]]; then
    log "ERROR" "Config file not found: ${CONFIG_FILE}"
    exit 1
fi
# shellcheck source=/dev/null
source "${CONFIG_FILE}"

# Validate required keys
for var in FGT_HOST FGT_API_TOKEN FGT_BLOCK_GROUP; do
    if [[ -z "${!var:-}" ]]; then
        log "ERROR" "Required config variable '${var}' is not set in ${CONFIG_FILE}"
        exit 1
    fi
done

# Apply defaults for optional keys
FGT_PORT="${FGT_PORT:-443}"
FGT_VDOM="${FGT_VDOM:-root}"
FGT_VERIFY_SSL="${FGT_VERIFY_SSL:-false}"
FGT_ADDR_PREFIX="${FGT_ADDR_PREFIX:-wazuh-}"
FGT_ADDR_COMMENT="${FGT_ADDR_COMMENT:-Auto-blocked by Wazuh Active Response}"
FGT_CLEANUP_ADDR="${FGT_CLEANUP_ADDR:-true}"
FGT_CURL_TIMEOUT="${FGT_CURL_TIMEOUT:-15}"
LOCAL_WHITELIST_FILE="${LOCAL_WHITELIST_FILE:-/var/ossec/etc/lists/fortigate-ar-whitelist}"

BASE_URL="https://${FGT_HOST}:${FGT_PORT}/api/v2/cmdb"
CURL_SSL_FLAG=""

# ---------------------------------------------------------------------------
# 3a. Validate config values that appear in URL paths
#     FortiGate names allow: letters, digits, hyphens, underscores, dots.
#     Spaces or special characters break the REST API URL — reject early.
# ---------------------------------------------------------------------------
validate_name_field() {
    local field_name="$1" value="$2"
    if [[ ! "${value}" =~ ^[a-zA-Z0-9._-]+$ ]]; then
        log "ERROR" "Config '${field_name}' contains characters not safe for URL paths: '${value}'"
        log "ERROR" "Allowed: letters, digits, hyphen, underscore, dot. No spaces."
        exit 1
    fi
}

validate_name_field "FGT_VDOM"        "${FGT_VDOM}"
validate_name_field "FGT_BLOCK_GROUP" "${FGT_BLOCK_GROUP}"
validate_name_field "FGT_ADDR_PREFIX" "${FGT_ADDR_PREFIX}"

if [[ "${FGT_VERIFY_SSL}" == "false" ]]; then
    CURL_SSL_FLAG="--insecure"
    log "WARN" "SSL verification disabled — enable FGT_VERIFY_SSL=true in production"
fi

# ---------------------------------------------------------------------------
# 3. Read alert JSON from STDIN
# ---------------------------------------------------------------------------
if ! read -r -t 30 INPUT; then
    log "ERROR" "Timed out or empty STDIN — aborting."
    exit 1
fi
log "DEBUG" "Raw STDIN received (${#INPUT} bytes)"

if ! echo "${INPUT}" | jq -e . &>/dev/null; then
    log "ERROR" "STDIN is not valid JSON — aborting."
    exit 1
fi

# ---------------------------------------------------------------------------
# 4. Parse command and extract source IP
# ---------------------------------------------------------------------------
AR_COMMAND=$(echo "${INPUT}" | jq -r '.command // empty')
ALERT_JSON=$(echo "${INPUT}" | jq -c '.parameters.alert // {}')

if [[ -z "${AR_COMMAND}" ]]; then
    log "ERROR" "No 'command' field in JSON input."
    exit 1
fi

# Try all common field paths used by different Wazuh decoders
SRCIP=$(echo "${ALERT_JSON}" | jq -r '
    .data.srcip      //
    .data.src_ip     //
    .data.src        //
    .data.attacker   //
    .data["src-ip"]  //
    .data.source_ip  //
    empty
' 2>/dev/null | head -1 | tr -d '[:space:]')

# Last resort: use agent IP (log a warning so the operator knows)
if [[ -z "${SRCIP}" || "${SRCIP}" == "null" ]]; then
    SRCIP=$(echo "${ALERT_JSON}" | jq -r '.agent.ip // empty' 2>/dev/null | tr -d '[:space:]')
    [[ -n "${SRCIP}" && "${SRCIP}" != "null" ]] && \
        log "WARN" "srcip not in data fields — using agent.ip: ${SRCIP}"
fi

if [[ -z "${SRCIP}" || "${SRCIP}" == "null" ]]; then
    log "ERROR" "Cannot extract source IP from alert. Check your decoder extracts srcip."
    exit 1
fi

RULE_ID=$(echo "${ALERT_JSON}"   | jq -r '.rule.id          // "unknown"')
RULE_DESC=$(echo "${ALERT_JSON}" | jq -r '.rule.description // "unknown"')
AGENT_NAME=$(echo "${ALERT_JSON}"| jq -r '.agent.name       // "unknown"')

log "INFO" "Command=${AR_COMMAND} | IP=${SRCIP} | Rule=${RULE_ID} | Agent=${AGENT_NAME}"

# ---------------------------------------------------------------------------
# 5. Validate IPv4 format
# ---------------------------------------------------------------------------
ip_is_valid() {
    local ip="$1" IFS='.' octets
    read -r -a octets <<< "${ip}"
    [[ ${#octets[@]} -eq 4 ]] || return 1
    local o
    for o in "${octets[@]}"; do
        [[ "${o}" =~ ^[0-9]+$ ]] || return 1
        (( o >= 0 && o <= 255 ))  || return 1
    done
}

if ! ip_is_valid "${SRCIP}"; then
    log "ERROR" "Invalid IPv4 format: '${SRCIP}' — aborting."
    exit 1
fi

# ---------------------------------------------------------------------------
# 6. Whitelist check
# ---------------------------------------------------------------------------
is_whitelisted() {
    local ip="$1"
    local first="${ip%%.*}"
    local second; second="${ip#*.}"; second="${second%%.*}"
    [[ "${ip}" == 127.*       ]] && return 0
    [[ "${ip}" == 169.254.*   ]] && return 0
    (( first == 10 ))            && return 0
    (( first == 172 && second >= 16 && second <= 31 )) && return 0
    [[ "${ip}" == 192.168.*   ]] && return 0
    if [[ -f "${LOCAL_WHITELIST_FILE}" ]]; then
        while IFS= read -r line; do
            [[ "${line}" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line// }" ]]             && continue
            [[ "${ip}" == "${line// }" ]]     && return 0
        done < "${LOCAL_WHITELIST_FILE}"
    fi
    return 1
}

if is_whitelisted "${SRCIP}"; then
    log "WARN" "IP ${SRCIP} is whitelisted — no action taken."
    exit 0
fi

# ---------------------------------------------------------------------------
# 7. Wazuh execd stateful handshake (deduplication)
#    Script writes check_keys - reads "continue" or "abort"
# ---------------------------------------------------------------------------
ADDR_NAME="${FGT_ADDR_PREFIX}$(echo "${SRCIP}" | tr '.' '-')"

CONTROL_MSG=$(jq -cn \
    --arg name "${SCRIPT_NAME}" \
    --arg key  "${SRCIP}" \
    '{version:1,origin:{name:$name,module:"active-response"},
      command:"check_keys",parameters:{keys:[$key]}}')
echo "${CONTROL_MSG}"
log "DEBUG" "Sent check_keys for key=${SRCIP}"

if ! read -r -t 30 EXECD_RESPONSE; then
    log "ERROR" "Timed out waiting for execd response."
    exit 1
fi

EXECD_CMD=$(echo "${EXECD_RESPONSE}" | jq -r '.command // empty')
if [[ "${EXECD_CMD}" != "continue" ]]; then
    log "INFO" "execd responded '${EXECD_CMD}' — skipping (likely duplicate in-flight block)."
    exit 0
fi

# ---------------------------------------------------------------------------
# 8. FortiGate API helper
#    Returns the response body; logs request + HTTP status; returns 1 on error
# ---------------------------------------------------------------------------
VDOM_PARAM="vdom=${FGT_VDOM}"

fgt_api() {
    local method="$1" endpoint="$2" data="${3:-}"
    local url="${BASE_URL}/${endpoint}?${VDOM_PARAM}"

    local cmd=(
        curl --silent --show-error --max-time "${FGT_CURL_TIMEOUT}"
        ${CURL_SSL_FLAG}
        -w "\n__STATUS__%{http_code}"
        -X "${method}"
        -H "Authorization: Bearer ${FGT_API_TOKEN}"
        -H "Content-Type: application/json"
    )
    [[ -n "${data}" ]] && cmd+=(-d "${data}")
    cmd+=("${url}")

    log "DEBUG" "API ${method} ${endpoint}"
    local raw exit_code
    raw=$("${cmd[@]}" 2>&1); exit_code=$?

    if (( exit_code != 0 )); then
        log "ERROR" "curl failed (exit ${exit_code}) ${method} ${endpoint}: ${raw}"
        return 1
    fi

    local body="${raw%__STATUS__*}"
    local http="${raw##*__STATUS__}"
    log "DEBUG" "API response HTTP=${http}: ${body}"

    if (( http >= 500 )); then
        log "ERROR" "FortiGate HTTP ${http} on ${method} ${endpoint} — body: ${body}"
        return 1
    fi

    echo "${body}"
}

# ---------------------------------------------------------------------------
# 9. Address object helpers
# ---------------------------------------------------------------------------
addr_exists() {
    local name="$1"
    local resp; resp=$(fgt_api "GET" "firewall/address/${name}") || return 1
    [[ "$(echo "${resp}" | jq -r '.status // empty')" == "success" ]]
}

create_addr_object() {
    local name="$1" ip="$2"
    # Truncate comment to 255 chars (FortiGate limit)
    local comment="${FGT_ADDR_COMMENT} | Rule:${RULE_ID} | ${RULE_DESC}"
    comment="${comment:0:255}"

    local payload
    payload=$(jq -cn \
        --arg n "${name}" --arg s "${ip}/32" --arg c "${comment}" \
        '{name:$n,type:"ipmask",subnet:$s,comment:$c,color:6}')

    log "INFO" "Creating address object '${name}' for ${ip}/32"
    local resp; resp=$(fgt_api "POST" "firewall/address" "${payload}") || return 1
    local status; status=$(echo "${resp}" | jq -r '.status // empty')

    if [[ "${status}" == "success" ]]; then
        log "INFO" "Address object '${name}' created successfully."
        return 0
    fi
    # 409-equivalent: object already exists — safe to continue
    if addr_exists "${name}"; then
        log "WARN" "Address object '${name}' already exists — proceeding."
        return 0
    fi
    log "ERROR" "Failed to create address object '${name}': ${resp}"
    return 1
}

delete_addr_object() {
    local name="$1"
    log "INFO" "Deleting address object '${name}'"
    local resp; resp=$(fgt_api "DELETE" "firewall/address/${name}") || return 1
    local status; status=$(echo "${resp}" | jq -r '.status // empty')
    if [[ "${status}" == "success" ]]; then
        log "INFO" "Address object '${name}' deleted."
    else
        log "WARN" "Could not delete '${name}' (may still be referenced): ${resp}"
    fi
}

# ---------------------------------------------------------------------------
# 10. Address group helpers — uses the APPEND endpoint to avoid overwriting
#     existing group members (this was the root cause of earlier failures)
#
#     CORRECT: POST .../addrgrp/{group}/member  {"name":"<addr>"}
#     WRONG:   PUT  .../addrgrp/{group}         {"member":[...]}  ← wipes group
# ---------------------------------------------------------------------------
group_add_member() {
    local group="$1" addr_name="$2"
    local payload; payload=$(jq -cn --arg n "${addr_name}" '{"name":$n}')
    log "INFO" "Adding '${addr_name}' to group '${group}'"
    local resp; resp=$(fgt_api "POST" "firewall/addrgrp/${group}/member" "${payload}") || return 1
    local status; status=$(echo "${resp}" | jq -r '.status // empty')
    if [[ "${status}" == "success" ]]; then
        log "INFO" "Successfully added '${addr_name}' to group '${group}'."
        return 0
    fi
    log "ERROR" "Failed to add '${addr_name}' to group '${group}': ${resp}"
    return 1
}

group_remove_member() {
    local group="$1" addr_name="$2"
    log "INFO" "Removing '${addr_name}' from group '${group}'"
    local resp; resp=$(fgt_api "DELETE" "firewall/addrgrp/${group}/member/${addr_name}") || return 1
    local status; status=$(echo "${resp}" | jq -r '.status // empty')
    if [[ "${status}" == "success" ]]; then
        log "INFO" "Removed '${addr_name}' from group '${group}'."
    else
        log "WARN" "Could not remove '${addr_name}' from group (may not be a member): ${resp}"
    fi
    return 0   # non-fatal — group membership may have already been cleaned
}

# ---------------------------------------------------------------------------
# 11. Execute action
# ---------------------------------------------------------------------------
case "${AR_COMMAND}" in
    add)
        log "INFO" "=== BLOCK action for ${SRCIP} ==="
        create_addr_object "${ADDR_NAME}" "${SRCIP}" || exit 1
        group_add_member   "${FGT_BLOCK_GROUP}" "${ADDR_NAME}" || exit 1
        log "INFO" "=== BLOCK complete for ${SRCIP} (object=${ADDR_NAME}, group=${FGT_BLOCK_GROUP}) ==="
        ;;

    delete)
        log "INFO" "=== UNBLOCK action for ${SRCIP} ==="
        group_remove_member "${FGT_BLOCK_GROUP}" "${ADDR_NAME}"
        [[ "${FGT_CLEANUP_ADDR}" == "true" ]] && delete_addr_object "${ADDR_NAME}"
        log "INFO" "=== UNBLOCK complete for ${SRCIP} ==="
        ;;

    *)
        log "WARN" "Unknown command '${AR_COMMAND}' — no action taken."
        exit 0
        ;;
esac

log "INFO" "======= Script completed PID=$$ ======="
exit 0
