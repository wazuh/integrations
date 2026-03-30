#!/var/ossec/framework/python/bin/python3
# AbuseIPDB IP check for Wazuh Integrator
# Keeps original_full_log and data.waf.* at top level (so they appear as data.original_full_log and data.waf.*)

import json
import sys
import os
import re
from socket import socket, AF_UNIX, SOCK_DGRAM

# ============================ Exit error codes =============================

ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_NO_RESPONSE_ABUSEIPDB = 4
ERR_SOCKET_OPERATION = 5
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7
ERR_NO_IP_FOUND = 8

try:
    import requests
    from requests.exceptions import Timeout, RequestException
except Exception:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(ERR_NO_REQUEST_MODULE)

# ============================ Globals / paths ==============================

debug_enabled = False
timeout = 10
retries = 3
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = f"{pwd}/logs/integrations.log"
SOCKET_ADDR = f"{pwd}/queue/sockets/queue"

ALERT_INDEX = 1
APIKEY_INDEX = 2
TIMEOUT_INDEX = 6
RETRIES_INDEX = 7

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# ================================ Main ====================================

def main(args):
    global debug_enabled, timeout, retries
    try:
        bad_arguments = False
        msg = ""
        if len(args) >= 4:
            debug_enabled = len(args) > 4 and args[4] == "debug"
            if len(args) > TIMEOUT_INDEX:
                timeout = int(args[TIMEOUT_INDEX])
            if len(args) > RETRIES_INDEX:
                retries = int(args[RETRIES_INDEX])
        else:
            msg = "# Error: Wrong arguments\n"
            bad_arguments = True

        with open(LOG_FILE, "a") as f:
            f.write(msg)

        if bad_arguments:
            debug(f"# Error: Exiting, bad arguments. Inputted: {args}")
            sys.exit(ERR_BAD_ARGUMENTS)

        process_args(args)

    except Exception as e:
        debug(str(e))
        raise


def process_args(args):
    debug("# Running AbuseIPDB IP script")

    alert_file_location = args[ALERT_INDEX]
    apikey_raw = args[APIKEY_INDEX]
    apikey = parse_api_key(apikey_raw)

    json_alert = get_json_alert(alert_file_location)
    debug(f"# Opening alert file at '{alert_file_location}' with '{json_alert}'")

    msg = request_abuseipdb_info(json_alert, apikey)
    if not msg:
        debug("# Error: Empty message")
        raise Exception

    send_msg(msg, json_alert.get("agent"))

# ================================ Utils ===================================

def debug(msg: str):
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, "a") as f:
            f.write(msg + "\n")


def parse_api_key(arg):
    if isinstance(arg, str) and ":" in arg:
        _, v = arg.split(":", 1)
        return v
    return arg


def get_json_alert(file_location: str):
    try:
        with open(file_location) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        debug(f"# JSON file for alert {file_location} doesn't exist")
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        debug(f"Failed getting JSON alert. Error: {e}")
        sys.exit(ERR_INVALID_JSON)


IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.|$)){4}\b")
IPV6_RE = re.compile(r"\b([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")

def pick_ip(alert):
    prefer = [
        ("data", "srcip"), ("data", "src_ip"), ("data", "source_ip"), ("data", "client_ip"),
        ("srcip",), ("src_ip",), ("source_ip",), ("client_ip",), ("data", "waf", "src"),
    ]
    for path in prefer:
        node = alert
        ok = True
        for k in path:
            if isinstance(node, dict) and k in node:
                node = node[k]
            else:
                ok = False
                break
        if ok and isinstance(node, str) and (IPV4_RE.search(node) or IPV6_RE.search(node)):
            m = IPV4_RE.search(node) or IPV6_RE.search(node)
            return m.group(0)

    def scan(obj):
        if isinstance(obj, dict):
            for v in obj.values():
                ip = scan(v)
                if ip:
                    return ip
        elif isinstance(obj, list):
            for v in obj:
                ip = scan(v)
                if ip:
                    return ip
        elif isinstance(obj, str):
            m = IPV4_RE.search(obj) or IPV6_RE.search(obj)
            if m:
                return m.group(0)
        return None

    return scan(alert)


def collect(data):
    abuse_confidence_score = data.get('abuseConfidenceScore')
    country_code = data.get('countryCode')
    usage_type = data.get('usageType')
    isp = data.get('isp')
    domain = data.get('domain')
    total_reports = data.get('totalReports')
    last_reported_at = data.get('lastReportedAt')
    return abuse_confidence_score, country_code, usage_type, isp, domain, total_reports, last_reported_at


def in_database(data):
    result = data.get('totalReports', 0)
    if result == 0:
        return False
    return True

# ====================== AbuseIPDB request & message build =========================

def request_abuseipdb_info(alert, apikey):
    # Top-level container; Wazuh wraps this as data.*
    out = {"abuseipdb": {}, "integration": "custom-abuseipdb"}

    ip = pick_ip(alert)
    if not ip:
        debug("# No IP found in alert")
        sys.exit(ERR_NO_IP_FOUND)

    # ---- Preserve requested original fields at TOP LEVEL ----
    # These will appear as data.original_full_log and data.waf.*
    if "full_log" in alert:
        out["original_full_log"] = alert["full_log"]

    waf = (((alert.get("data") or {}).get("waf")) or {})
    waf_kept = {}
    for k in ("ref", "request", "src", "sip"):
        if k in waf:
            waf_kept[k] = waf[k]
    if waf_kept:
        out["waf"] = waf_kept

    # ---- Query AbuseIPDB (with retries) ----
    params = {'maxAgeInDays': '90', 'ipAddress': ip}
    headers = {
        "Accept-Encoding": "gzip, deflate",
        'Accept': 'application/json',
        "Key": apikey
    }

    data = None
    for attempt in range(retries + 1):
        try:
            resp = requests.get(ABUSEIPDB_URL, params=params, headers=headers, timeout=timeout)
            if resp.status_code == 429:
                out["abuseipdb"]["error"] = 429
                out["abuseipdb"]["description"] = "Error: AbuseIPDB rate limit"
                send_msg(out, alert.get("agent"))
                sys.exit(ERR_NO_RESPONSE_ABUSEIPDB)
            if resp.status_code == 401:
                out["abuseipdb"]["error"] = 401
                out["abuseipdb"]["description"] = "Error: Unauthorized (check API key)"
                send_msg(out, alert.get("agent"))
                sys.exit(ERR_NO_RESPONSE_ABUSEIPDB)
            if resp.status_code == 422:
                json_response = resp.json()
                out["abuseipdb"]["error"] = 422
                out["abuseipdb"]["description"] = json_response.get("errors", [{}])[0].get("detail", "Validation error")
                send_msg(out, alert.get("agent"))
                sys.exit(ERR_NO_RESPONSE_ABUSEIPDB)
            resp.raise_for_status()
            json_response = resp.json()
            data = json_response.get("data")
            break
        except Timeout:
            debug(f"# Error: Request timed out. Remaining retries: {retries - attempt}")
            continue
        except RequestException as e:
            debug(str(e))
            sys.exit(ERR_NO_RESPONSE_ABUSEIPDB)

    # Base block for IP context
    src = {"alert_id": alert.get("id"), "rule": (alert.get("rule") or {}).get("id"), "ip": ip}
    out["abuseipdb"].update({"found": 0, "source": src})

    if not data:
        return out  # no data returned

    # Check if AbuseIPDB has any info about the srcip
    if in_database(data):
        out["abuseipdb"]["found"] = 1

        # Collect and populate info
        abuse_confidence_score, country_code, usage_type, isp, domain, total_reports, last_reported_at = collect(data)

        out["abuseipdb"]["abuse_confidence_score"] = abuse_confidence_score
        out["abuseipdb"]["country_code"] = country_code
        out["abuseipdb"]["usage_type"] = usage_type
        out["abuseipdb"]["isp"] = isp
        out["abuseipdb"]["domain"] = domain
        out["abuseipdb"]["total_reports"] = total_reports
        out["abuseipdb"]["last_reported_at"] = last_reported_at
        out["abuseipdb"]["permalink"] = f"https://www.abuseipdb.com/check/{ip}"

    debug(f"# Alert output: {out}")

    return out


def send_msg(msg, agent=None):
    if not agent or agent.get("id") == "000":
        string = "1:abuseipdb:{0}".format(json.dumps(msg))
    else:
        location = "[{0}] ({1}) {2}".format(agent["id"], agent["name"], agent.get("ip", "any"))
        location = location.replace("|", "||").replace(":", "|:")
        string = "1:{0}->abuseipdb:{1}".format(location, json.dumps(msg))

    debug(f"# Request result from AbuseIPDB server: {string}")
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
        sock.close()
    except FileNotFoundError:
        debug(f"# Error: Unable to open socket connection at {SOCKET_ADDR}")
        sys.exit(ERR_SOCKET_OPERATION)

# ================================= Entry ==================================

if __name__ == "__main__":
    main(sys.argv)
