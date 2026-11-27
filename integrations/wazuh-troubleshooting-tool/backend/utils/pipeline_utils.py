"""
Reusable helpers for diagnosing the full Wazuh alert pipeline:

    Wazuh Agent -> Wazuh Manager -> alerts.json -> Filebeat -> Wazuh Indexer -> Dashboard

Centralized here so any use case (no_alerts_are_showing, indexing_error,
cluster_issues, etc.) can reuse the same checks instead of each one
re-implementing ossec.conf parsing / alerts.json staleness / shard
analysis by hand.
"""

import re
import time

from executor import run_command
from utils.api_utils import indexer_api_get, indexer_api_get_json

OSSEC_CONF_PATH = "/var/ossec/etc/ossec.conf"
ALERTS_JSON_PATH = "/var/ossec/logs/alerts/alerts.json"
OSSEC_LOG_PATH = "/var/ossec/logs/ossec.log"
FILEBEAT_LOG_PATH = "/var/log/filebeat/filebeat"


# ---------------------------------------------------------------------------
# STEP 1/2 — AGENT STATUS
# ---------------------------------------------------------------------------
def get_agent_status(identifier=None):
    """
    Run `agent_control -l` and, if `identifier` (name or id) is given,
    try to find that specific agent's line and report whether it's Active.

    Returns {"raw": <full output>, "is_active": True/False/None}
    `is_active` is None when we can't determine a clear answer
    (e.g. identifier not found in the output).
    """
    raw = run_command("/var/ossec/bin/agent_control -l") or ""

    is_active = None
    if identifier:
        for line in raw.splitlines():
            if identifier.lower() in line.lower():
                is_active = "active" in line.lower()
                break
    else:
        is_active = bool(re.search(r"\bActive\b", raw))

    return {"raw": raw, "is_active": is_active}


# ---------------------------------------------------------------------------
# STEP 3/4 — MANAGER CONFIG (ossec.conf)
# ---------------------------------------------------------------------------
def check_manager_config():
    """
    Verify the two ossec.conf settings that silently swallow alerts when
    misconfigured: log_alert_level (must be <= 15) and jsonout_output
    (must be "yes", otherwise alerts.json is never written).
    """
    level_raw = run_command(f"grep 'log_alert_level' {OSSEC_CONF_PATH}") or ""
    jsonout_raw = run_command(f"grep 'jsonout_output' {OSSEC_CONF_PATH}") or ""

    level_match = re.search(r"<log_alert_level>\s*(\d+)\s*</log_alert_level>", level_raw)
    level = int(level_match.group(1)) if level_match else None

    jsonout_match = re.search(
        r"<jsonout_output>\s*(yes|no)\s*</jsonout_output>", jsonout_raw, re.IGNORECASE
    )
    jsonout_enabled = bool(jsonout_match and jsonout_match.group(1).lower() == "yes")

    return {
        "log_alert_level": level,
        "log_alert_level_ok": level is not None and level <= 15,
        "jsonout_output_enabled": jsonout_enabled,
        "raw": "\n".join(x for x in [level_raw.strip(), jsonout_raw.strip()] if x),
    }


# ---------------------------------------------------------------------------
# STEP 5 — alerts.json FRESHNESS
# ---------------------------------------------------------------------------
def get_alerts_json_status(max_age_seconds=300, tail_lines=5):
    """
    Check whether the manager is actively writing new alerts to
    alerts.json (the file Filebeat reads from). `age_seconds` is how long
    ago the file was last modified; if it's older than `max_age_seconds`
    (default 5 min) we consider the pipeline stalled at the manager.
    """
    exists = (run_command(f"test -f {ALERTS_JSON_PATH} && echo yes || echo no") or "").strip()
    if exists != "yes":
        return {"exists": False, "age_seconds": None, "is_fresh": False, "tail": ""}

    mtime_raw = (run_command(f"stat -c %Y {ALERTS_JSON_PATH}") or "").strip()
    try:
        age = int(time.time()) - int(mtime_raw)
    except ValueError:
        age = None

    tail = run_command(f"tail -n {tail_lines} {ALERTS_JSON_PATH}") or ""

    return {
        "exists": True,
        "age_seconds": age,
        "is_fresh": age is not None and age <= max_age_seconds,
        "tail": tail,
    }


# ---------------------------------------------------------------------------
# STEP 6 — MANAGER LOGS (ossec.log)
# ---------------------------------------------------------------------------
def get_manager_log_errors(lines=200):
    return run_command(f"tail -n {lines} {OSSEC_LOG_PATH} | grep -i -E 'error|warn'") or ""


# ---------------------------------------------------------------------------
# STEP 7 — FILEBEAT
# ---------------------------------------------------------------------------
def run_filebeat_output_test():
    out = run_command("filebeat test output") or ""
    upper = out.upper()
    ok = "OK" in upper and "ERROR" not in upper
    return {"raw": out, "ok": ok}


def get_filebeat_log_errors(lines=200):
    return run_command(f"tail -n {lines} {FILEBEAT_LOG_PATH} | grep -i -E 'error|warn'") or ""


# ---------------------------------------------------------------------------
# STEP 8/9 — INDEXER: CLUSTER HEALTH + SHARDS
# ---------------------------------------------------------------------------
def check_cluster_shards():
    """
    Pull /_cluster/health and, if the status isn't green and there are
    unassigned shards, also pull the unassigned shard list so the caller
    can show *why* they're unassigned (disk watermark, no replica node, etc).
    """
    health, raw_health = indexer_api_get_json("/_cluster/health")

    if not health:
        return {"reachable": False, "raw": raw_health}

    result = {
        "reachable": True,
        "status": health.get("status", "unknown"),
        "number_of_nodes": health.get("number_of_nodes", 0),
        "active_shards": health.get("active_shards", 0),
        "unassigned_shards": health.get("unassigned_shards", 0),
        "raw": raw_health,
    }

    if result["status"] != "green" and result["unassigned_shards"]:
        shards_raw = indexer_api_get("/_cat/shards?h=index,shard,state,unassigned.reason") or ""
        result["unassigned_detail"] = "\n".join(
            line for line in shards_raw.splitlines() if "UNASSIGNED" in line
        )[:2000]

    return result


# ---------------------------------------------------------------------------
# STEP 10 — INDEXER: wazuh-alerts-* INDICES
# ---------------------------------------------------------------------------
def check_alert_indices():
    """
    Confirm that wazuh-alerts-* indices exist, are healthy, and that one
    matching today's date is present (i.e. new data is actually landing
    in the indexer, not just old indices from before the issue started).
    """
    raw = indexer_api_get("/_cat/indices/wazuh-alerts-*?h=index,health,status,docs.count") or ""
    today = (run_command("date +%Y.%m.%d") or "").strip()

    lines = [l for l in raw.splitlines() if l.strip()]
    todays_index = next((l for l in lines if today and today in l), None)

    return {
        "indices": lines,
        "todays_index_present": bool(todays_index),
        "todays_index": todays_index,
        "raw": raw,
    }
