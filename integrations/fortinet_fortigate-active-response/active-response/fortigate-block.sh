#!/usr/bin/env bash
# =============================================================================
# fortigate-block.sh
# Wazuh Active Response — Fortinet FortiGate IP Block/Unblock via REST API
#
# Version  : 2.2.0
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
readonly SCRIPT_VERSION="2.2.0"
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
# Validates dotted-quad format and normalises each octet to base 10.
# The 10# prefix is required: bash treats a leading-zero literal as octal, so
# an octet like "08" from a log (e.g. 172.08.1.1) would otherwise abort the
# script with "value too great for base". Normalising also prevents pushing a
# non-canonical address such as 010.0.0.1 to the FortiGate, where it could be
# interpreted differently than intended.
# On success, sets NORMALIZED_IP to the canonical dotted-quad form.
ip_is_valid() {
    local ip="$1" IFS='.' octets
    read -r -a octets <<< "${ip}"
    [[ ${#octets[@]} -eq 4 ]] || return 1

    local o dec normalised=""
    for o in "${octets[@]}"; do
        [[ "${o}" =~ ^[0-9]{1,3}$ ]] || return 1
        dec=$((10#${o}))
        (( dec >= 0 && dec <= 255 )) || return 1
        normalised+="${dec}."
    done

    NORMALIZED_IP="${normalised%.}"
    return 0
}

if ! ip_is_valid "${SRCIP}"; then
    log "ERROR" "Invalid IPv4 format: '${SRCIP}' — aborting."
    exit 1
fi

# Use the canonical form from here on (object names, subnet, whitelist checks)
if [[ "${NORMALIZED_IP}" != "${SRCIP}" ]]; then
    log "INFO" "Normalised source IP '${SRCIP}' to '${NORMALIZED_IP}'"
    SRCIP="${NORMALIZED_IP}"
fi

# ---------------------------------------------------------------------------
# 6. Whitelist check
# ---------------------------------------------------------------------------
is_whitelisted() {
    local ip="$1"
    # 10# forces base-10; without it an octet like "08" is parsed as invalid
    # octal and aborts the script. Input is already normalised by ip_is_valid,
    # but the prefix is kept so the function is safe if reused elsewhere.
    local first=$((10#${ip%%.*}))
    local second_raw="${ip#*.}"; second_raw="${second_raw%%.*}"
    local second=$((10#${second_raw}))

    (( first == 127 ))           && return 0   # loopback
    (( first == 169 && second == 254 )) && return 0   # link-local
    (( first == 10 ))            && return 0   # RFC1918
    (( first == 172 && second >= 16 && second <= 31 )) && return 0   # RFC1918
    (( first == 192 && second == 168 )) && return 0   # RFC1918
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
# 7. Derive the FortiGate address object name (needed by both add and delete)
# ---------------------------------------------------------------------------
ADDR_NAME="${FGT_ADDR_PREFIX}$(echo "${SRCIP}" | tr '.' '-')"

# ---------------------------------------------------------------------------
# 7a. Wazuh execd stateful handshake — PERFORMED ON "add" ONLY
#
#     wazuh-execd runs the check_keys / continue-abort exchange only on the
#     initial "add" invocation, where it binds both stdin and stdout and waits
#     for the script's reply before adding the entry to its timeout list.
#
#     For the deferred "delete" invocation fired when the AR <timeout> expires,
#     execd writes the alert to stdin and closes the pipe — it never reads or
#     replies. Running the handshake there blocks until the 30s read timeout,
#     exits down the error path, and never reaches group_remove_member, so
#     blocked IPs are never cleaned up from the FortiGate.
#
#     This mirrors the upstream Wazuh active-response helpers, which call the
#     handshake only when the command is ADD_COMMAND.
#
#     Returns: 0 = proceed, 1 = abort (duplicate in flight), 2 = protocol error
# ---------------------------------------------------------------------------
execd_handshake() {
    local control_msg execd_response execd_cmd

    control_msg=$(jq -cn \
        --arg name "${SCRIPT_NAME}" \
        --arg key  "${SRCIP}" \
        '{version:1,origin:{name:$name,module:"active-response"},
          command:"check_keys",parameters:{keys:[$key]}}')

    echo "${control_msg}"
    log "DEBUG" "Sent check_keys for key=${SRCIP}"

    if ! read -r -t 30 execd_response; then
        log "ERROR" "Timed out waiting for execd handshake response."
        return 2
    fi

    execd_cmd=$(echo "${execd_response}" | jq -r '.command // empty')
    if [[ "${execd_cmd}" != "continue" ]]; then
        log "INFO" "execd responded '${execd_cmd}' — skipping (duplicate in-flight block)."
        return 1
    fi

    return 0
}

# ---------------------------------------------------------------------------
# 8. FortiGate API helper
#
#    Every HTTP status is surfaced to the caller, not just 5xx: a 4xx with a
#    non-JSON body (an auth proxy's HTML 403 page, for example) is logged with
#    its status code rather than collapsing into a generic failure.
#
#    OUTPUT PROTOCOL: the first line of stdout is the HTTP status code, the
#    remainder is the response body. Callers use api_http / api_body to split.
#    A status code cannot be returned via the exit status (codes above 255
#    wrap) and cannot be passed in a global (callers invoke this via command
#    substitution, which runs in a subshell), so it travels in-band.
#
#    Exit status: 0 = HTTP response received (any code), 1 = curl transport
#    failure (DNS, TLS, connection refused, timeout).
# ---------------------------------------------------------------------------
VDOM_PARAM="vdom=${FGT_VDOM}"

api_http() { printf '%s' "${1%%$'\n'*}"; }

# Command substitution strips trailing newlines, so a response with an empty
# body arrives as just the status code with no separator. Guard against that,
# otherwise the status code would be returned as if it were the body.
api_body() {
    local r="$1"
    [[ "${r}" == *$'\n'* ]] || return 0
    printf '%s' "${r#*$'\n'}"
}

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
        log "ERROR" "curl transport failure (exit ${exit_code}) on ${method} ${endpoint}: ${raw}"
        printf '000\n'
        return 1
    fi

    local body="${raw%__STATUS__*}"
    local http="${raw##*__STATUS__}"
    body="${body%$'\n'}"          # drop the newline injected by -w
    http="${http//[^0-9]/}"
    [[ -z "${http}" ]] && http="000"

    log "DEBUG" "API ${method} ${endpoint} -> HTTP ${http}: ${body}"

    if (( http >= 400 )); then
        local api_err api_msg
        api_err=$(echo "${body}" | jq -r '.error                 // empty' 2>/dev/null)
        api_msg=$(echo "${body}" | jq -r '.cli_error // .message // empty' 2>/dev/null)
        if [[ -n "${api_err}" || -n "${api_msg}" ]]; then
            log "ERROR" "FortiGate HTTP ${http} on ${method} ${endpoint}${api_err:+ (error ${api_err})}${api_msg:+ — ${api_msg}}"
        else
            # Non-JSON body — log it verbatim so the cause is not hidden
            log "ERROR" "FortiGate HTTP ${http} on ${method} ${endpoint} — non-JSON body: ${body}"
        fi
    fi

    printf '%s\n%s' "${http}" "${body}"
    return 0
}

# ---------------------------------------------------------------------------
# 9. Address object helpers
# ---------------------------------------------------------------------------
addr_exists() {
    local name="$1" resp http
    resp=$(fgt_api "GET" "firewall/address/${name}") || return 1
    http=$(api_http "${resp}")
    [[ "${http}" == "200" ]]
}

create_addr_object() {
    local name="$1" ip="$2"
    # FortiGate truncates comments at 255 chars
    local comment="${FGT_ADDR_COMMENT} | Rule:${RULE_ID} | ${RULE_DESC}"
    comment="${comment:0:255}"

    local payload
    payload=$(jq -cn \
        --arg n "${name}" --arg s "${ip}/32" --arg c "${comment}" \
        '{name:$n,type:"ipmask",subnet:$s,comment:$c,color:6}')

    log "INFO" "Creating address object '${name}' for ${ip}/32"

    local resp http body status
    resp=$(fgt_api "POST" "firewall/address" "${payload}") || return 1
    http=$(api_http "${resp}")
    body=$(api_body "${resp}")
    status=$(echo "${body}" | jq -r '.status // empty' 2>/dev/null)

    if [[ "${http}" == "200" && "${status}" == "success" ]]; then
        log "INFO" "Address object '${name}' created."
        return 0
    fi

    # FortiGate answers HTTP 500 with error -5 when the object already exists,
    # so a failed POST is not conclusive — probe before giving up.
    if addr_exists "${name}"; then
        log "WARN" "Address object '${name}' already exists — reusing it."
        return 0
    fi

    log "ERROR" "Could not create address object '${name}' (HTTP ${http}): ${body}"
    return 1
}

delete_addr_object() {
    local name="$1" resp http body status
    log "INFO" "Deleting address object '${name}'"

    resp=$(fgt_api "DELETE" "firewall/address/${name}") || return 1
    http=$(api_http "${resp}")
    body=$(api_body "${resp}")
    status=$(echo "${body}" | jq -r '.status // empty' 2>/dev/null)

    if [[ "${http}" == "200" && "${status}" == "success" ]]; then
        log "INFO" "Address object '${name}' deleted."
        return 0
    fi
    if [[ "${http}" == "404" ]]; then
        log "INFO" "Address object '${name}' already absent — nothing to delete."
        return 0
    fi
    log "WARN" "Could not delete '${name}' (HTTP ${http}, may still be referenced): ${body}"
    return 0   # non-fatal: the IP is already out of the block group
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

    local resp http body status
    resp=$(fgt_api "POST" "firewall/addrgrp/${group}/member" "${payload}") || return 1
    http=$(api_http "${resp}")
    body=$(api_body "${resp}")
    status=$(echo "${body}" | jq -r '.status // empty' 2>/dev/null)

    if [[ "${http}" == "200" && "${status}" == "success" ]]; then
        log "INFO" "Added '${addr_name}' to group '${group}'."
        return 0
    fi
    if [[ "${http}" == "404" ]]; then
        log "ERROR" "Group '${group}' does not exist on the FortiGate — create it first."
        return 1
    fi
    log "ERROR" "Could not add '${addr_name}' to group '${group}' (HTTP ${http}): ${body}"
    return 1
}

group_remove_member() {
    local group="$1" addr_name="$2"
    log "INFO" "Removing '${addr_name}' from group '${group}'"

    local resp http body status
    resp=$(fgt_api "DELETE" "firewall/addrgrp/${group}/member/${addr_name}") || return 1
    http=$(api_http "${resp}")
    body=$(api_body "${resp}")
    status=$(echo "${body}" | jq -r '.status // empty' 2>/dev/null)

    if [[ "${http}" == "200" && "${status}" == "success" ]]; then
        log "INFO" "Removed '${addr_name}' from group '${group}'."
        return 0
    fi
    if [[ "${http}" == "404" ]]; then
        log "INFO" "'${addr_name}' is not a member of '${group}' — nothing to remove."
        return 0
    fi
    log "WARN" "Could not remove '${addr_name}' from group '${group}' (HTTP ${http}): ${body}"
    return 0   # non-fatal — continue to the address object cleanup
}

# ---------------------------------------------------------------------------
# 11. Execute action
# ---------------------------------------------------------------------------
case "${AR_COMMAND}" in
    add)
        # Handshake first — execd only speaks the check_keys protocol on "add"
        execd_handshake
        case $? in
            1) exit 0 ;;   # duplicate in flight — nothing to do
            2) exit 1 ;;   # protocol error
        esac

        log "INFO" "=== BLOCK action for ${SRCIP} ==="
        create_addr_object "${ADDR_NAME}" "${SRCIP}" || exit 1
        group_add_member   "${FGT_BLOCK_GROUP}" "${ADDR_NAME}" || exit 1
        log "INFO" "=== BLOCK complete for ${SRCIP} (object=${ADDR_NAME}, group=${FGT_BLOCK_GROUP}) ==="
        ;;

    delete)
        # No handshake here — execd does not read or reply on the deferred
        # timeout invocation. Attempting it would stall and leave the IP blocked.
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
