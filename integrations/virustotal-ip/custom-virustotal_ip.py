#!/var/ossec/framework/python/bin/python3
# Copyright (C) 2015-2025, Wazuh Inc.
#
# Example ossec.conf:
# <integration>
#   <name>custom-virustotal_ip</name>
#   <api_key>YOUR_VT_KEY</api_key>
#   <group>sshd</group>   #   <alert_format>json</alert_format>
# </integration>

import json
import os
import re
import sys
from datetime import datetime, timezone
from socket import AF_UNIX, SOCK_DGRAM, socket

# ===================== Heuristic constants (tune here) =====================

# Primary threshold: how many "malicious" engines to call it malicious outright
MAL_STRONG_MIN: int = 3

# If at least this many malicious (>=1) AND reputation < REP_BAD_LT -> malicious
REP_BAD_LT: int = 0  # negative reputation considered bad

# Lightweight engine weighting from last_analysis_results
# malicious = 1.0 point, suspicious = 0.5 point
WEIGHT_MAL_STRONG: float = 3.0   # upgrade to malicious if weighted >= this
WEIGHT_MAL_SUS: float    = 1.5   # upgrade unknown -> suspicious if weighted >= this

# If analysis is older than this (days) and hits are weak (<=1 malicious) with non-negative rep -> unknown
STALE_WEAK_DAYS: int = 90

# Risk tags that prevent downgrading below suspicious if there is any engine hit
RISK_TAGS = {"tor", "vpn", "proxy", "anonymizer", "anonymous"}

# ============================ Exit error codes =============================

ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_NO_RESPONSE_VT = 4
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

# Argument positions per Wazuh Integrator call
ALERT_INDEX = 1
APIKEY_INDEX = 2
TIMEOUT_INDEX = 6
RETRIES_INDEX = 7

VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

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
    debug("# Running VirusTotal IP script")

    alert_file_location = args[ALERT_INDEX]
    apikey_raw = args[APIKEY_INDEX]
    apikey = parse_api_key(apikey_raw)

    json_alert = get_json_alert(alert_file_location)
    debug(f"# Opening alert file at '{alert_file_location}' with '{json_alert}'")

    msg = request_virustotal_info(json_alert, apikey)
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
    # Wazuh may pass "api_key:VALUE" or just "VALUE"
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


# Extract a source IP from common alert shapes
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.|$)){4}\b")
IPV6_RE = re.compile(r"\b([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")

def pick_ip(alert):
    # Preferred locations
    prefer = [
        ("data", "srcip"), ("data", "src_ip"), ("data", "source_ip"), ("data", "client_ip"),
        ("srcip",), ("src_ip",), ("source_ip",), ("client_ip",),
    ]
    for path in prefer:
        node = alert
        ok = True
        for k in path:
            if isinstance(node, dict) and k in node:
                node = node[k]
            else:
                ok = False; break
        if ok and isinstance(node, str) and (IPV4_RE.search(node) or IPV6_RE.search(node)):
            m = IPV4_RE.search(node) or IPV6_RE.search(node)
            return m.group(0)

    # Fallback: scan all string fields
    def scan(obj):
        if isinstance(obj, dict):
            for v in obj.values():
                ip = scan(v)
                if ip: return ip
        elif isinstance(obj, list):
            for v in obj:
                ip = scan(v)
                if ip: return ip
        elif isinstance(obj, str):
            m = IPV4_RE.search(obj) or IPV6_RE.search(obj)
            if m: return m.group(0)
        return None

    return scan(alert)


def ts_age_days(ts):
    if not ts:
        return None
    try:
        then = datetime.fromtimestamp(int(ts), tz=timezone.utc)
        now = datetime.now(timezone.utc)
        return (now - then).total_seconds() / 86400.0
    except Exception:
        return None


def vt_get(url, api_key):
    headers = {"x-apikey": api_key, "accept": "application/json"}
    return requests.get(url, headers=headers, timeout=timeout)


def analyze_engine_results(last_analysis_results):
    m = s = 0
    weighted = 0.0
    if isinstance(last_analysis_results, dict):
        for _eng, res in last_analysis_results.items():
            cat = (res or {}).get("category")
            if cat == "malicious":
                m += 1
            elif cat == "suspicious":
                s += 1
            weighted += (1.0 if cat == "malicious" else (0.5 if cat == "suspicious" else 0.0))
    return m, s, weighted


def initial_verdict(mal, sus, rep, days):
    if mal >= MAL_STRONG_MIN or (mal >= 1 and rep < REP_BAD_LT):
        return "malicious"
    if (mal + sus) >= 1:
        if days is not None and days > STALE_WEAK_DAYS and rep >= REP_BAD_LT and mal <= 1:
            return "unknown"  # stale weak hit
        return "suspicious"
    return "unknown"


def apply_modifiers(verdict, weighted_mal, rep, tags, mal, sus):
    # Engine-weight nudges
    if verdict != "malicious":
        if weighted_mal >= WEIGHT_MAL_STRONG:
            verdict = "malicious"
        elif weighted_mal >= WEIGHT_MAL_SUS and verdict == "unknown":
            verdict = "suspicious"

    # Risk tags: if any hit exists, don't let it drop below suspicious
    if (mal + sus) >= 1 and (set(tags or []) & RISK_TAGS):
        if verdict == "unknown":
            verdict = "suspicious"
    return verdict

# ====================== VT request & message build =========================

def request_virustotal_info(alert, api_key):
    out = {"virustotal_ip": {}, "integration": "virustotal_ip"}

    ip = pick_ip(alert)
    if not ip:
        debug("# No IP found in alert")
        sys.exit(ERR_NO_IP_FOUND)
        
    # ---- Preserve requested original fields at TOP LEVEL ----
    # These will appear as data.original_full_log
    if "full_log" in alert:
        out["original_full_log"] = alert["full_log"]

    # ---- Example of preserving WAF data ----
    # waf = (((alert.get("data") or {}).get("waf")) or {})
    # waf_kept = {}
    # for k in ("ref", "request", "src", "sip"):
    #     if k in waf:
    #         waf_kept[k] = waf[k]
    # if waf_kept:
    #     out["waf"] = waf_kept

    # Retry loop
    vt_body = None
    for attempt in range(retries + 1):
        try:
            resp = vt_get(VT_IP_URL.format(ip=ip), api_key)
            if resp.status_code == 429:
                out["virustotal_ip"]["error"] = 429
                out["virustotal_ip"]["description"] = "Error: VT rate limit"
                send_msg(out, alert.get("agent"))
                sys.exit(ERR_NO_RESPONSE_VT)
            if resp.status_code == 401:
                out["virustotal_ip"]["error"] = 401
                out["virustotal_ip"]["description"] = "Error: Unauthorized (check API key)"
                send_msg(out, alert.get("agent"))
                sys.exit(ERR_NO_RESPONSE_VT)
            if resp.status_code == 404:
                vt_body = None
                break
            resp.raise_for_status()
            vt_body = resp.json()
            break
        except Timeout:
            debug(f"# Error: Request timed out. Remaining retries: {retries - attempt}")
            continue
        except RequestException as e:
            debug(str(e))
            sys.exit(ERR_NO_RESPONSE_VT)

    # Prepare output base
    src = {"alert_id": alert.get("id"), "rule": (alert.get("rule") or {}).get("id"), "ip": ip}
    out["virustotal_ip"].update({"found": 0, "verdict": "unknown", "source": src})

    if not vt_body or "data" not in vt_body:
        return out  # not in corpus

    attr = (vt_body.get("data") or {}).get("attributes") or {}
    stats = attr.get("last_analysis_stats") or {}
    mal = int(stats.get("malicious", 0) or 0)
    sus = int(stats.get("suspicious", 0) or 0)
    rep = int(attr.get("reputation", 0) or 0)
    tags = attr.get("tags") or []
    last_ts = attr.get("last_analysis_date")
    days = ts_age_days(last_ts)

    # Lightweight engine weighting
    lar = attr.get("last_analysis_results") or {}
    m_count, s_count, wmal = analyze_engine_results(lar)

    verdict = initial_verdict(mal, sus, rep, days)
    verdict = apply_modifiers(verdict, wmal, rep, tags, mal, sus)

    # Build final block
    out["virustotal_ip"]["found"] = 1
    out["virustotal_ip"]["verdict"] = verdict
    out["virustotal_ip"]["counts"] = {"malicious": mal, "suspicious": sus}
    out["virustotal_ip"]["engine_counts"] = {"malicious": m_count, "suspicious": s_count}
    out["virustotal_ip"]["weighted_malicious"] = round(wmal, 2)
    out["virustotal_ip"]["reputation"] = rep
    out["virustotal_ip"]["tags"] = tags
    out["virustotal_ip"]["age_days"] = None if days is None else round(days, 1)
    out["virustotal_ip"]["last_analysis_date"] = (
        datetime.fromtimestamp(int(last_ts), tz=timezone.utc).isoformat() if last_ts else None
    )
    out["virustotal_ip"]["country"] = attr.get("country")
    out["virustotal_ip"]["as_owner"] = attr.get("as_owner")
    out["virustotal_ip"]["network"] = attr.get("network")
    out["virustotal_ip"]["permalink"] = f"https://www.virustotal.com/gui/ip-address/{ip}"

    # Flat line for rule matching
    out["virustotal_ip"]["verdict_line"] = (
        f"vt_ip verdict={verdict} ip={ip} mal={mal} sus={sus} "
        f"wmal={round(wmal,2)} rep={rep} age_days={out['virustotal_ip']['age_days']} "
        f"tags={','.join(tags[:5]) if tags else '-'} as_owner=\"{attr.get('as_owner')}\""
    )

    return out


def send_msg(msg, agent=None):
    if not agent or agent.get("id") == "000":
        string = "1:virustotal_ip:{0}".format(json.dumps(msg))
    else:
        location = "[{0}] ({1}) {2}".format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any")
        location = location.replace("|", "||").replace(":", "|:")
        string = "1:{0}->virustotal_ip:{1}".format(location, json.dumps(msg))

    debug(f"# Request result from VT server: {string}")
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