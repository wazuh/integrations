#!/usr/bin/env python3
"""
SOCRadar Custom Integration for Wazuh
=======================================
This script is called by wazuh-integratord whenever a matching Wazuh
alert fires. It reads the alert JSON and can perform actions on SOCRadar:

  - Auto-close false positives (if AI insight says FP)
  - Post a comment with Wazuh alert context
  - Escalate severity based on rule level

Parameters received from integratord:
  sys.argv[1] = path to temp alert JSON file
  sys.argv[2] = api_key (from <api_key> in ossec.conf)
  sys.argv[3] = hook_url (from <hook_url> in ossec.conf) — unused here
  sys.argv[4] = "debug" or "" (from integratord debug mode)
"""

import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

WAZUH_HOME = os.environ.get("WAZUH_HOME", "/var/ossec")
CONFIG_FILE = os.path.join(WAZUH_HOME, "etc", "socradar.conf")
LOG_FILE = os.path.join(WAZUH_HOME, "logs", "socradar-integration.log")

SOCRADAR_BASE_URL = "https://platform.socradar.com/api"

# Status codes for SOCRadar
STATUS_RESOLVED = 2
STATUS_FALSE_POSITIVE = 9
STATUS_MITIGATED = 12

debug_enabled = False


def log(level, msg):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"{ts} custom-socradar {level}: {msg}"
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass
    if debug_enabled:
        print(line, file=sys.stderr)


def load_config():
    if not os.path.isfile(CONFIG_FILE):
        log("ERROR", f"Config not found: {CONFIG_FILE}")
        return {}
    with open(CONFIG_FILE) as f:
        return json.load(f)


def api_post(url, headers, body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        log("ERROR", f"HTTP {e.code}: {e.read().decode()}")
        return None
    except Exception as e:
        log("ERROR", f"Request error: {e}")
        return None


def update_status(config, alarm_ids, status, comment):
    company_id = config["company_id"]
    url = f"{SOCRADAR_BASE_URL}/company/{company_id}/alarms/status/change"
    headers = {
        "API-Key": config["api_key"],
        "Content-Type": "application/json",
    }
    body = {
        "alarm_ids": [str(a) for a in alarm_ids],
        "status": status,
        "comments": comment,
        "update_related_finding_status": True,
        "email": config.get("user_email", "wazuh@socradar.io"),
    }
    return api_post(url, headers, body)


def add_comment(config, alarm_id, comment):
    company_id = config["company_id"]
    url = f"{SOCRADAR_BASE_URL}/company/{company_id}/alarm/add/comment/v2"
    headers = {
        "API-Key": config["api_key"],
        "Content-Type": "application/json",
    }
    body = {
        "alarm_id": alarm_id,
        "comment": comment,
        "user_email": config.get("user_email", "wazuh@socradar.io"),
    }
    return api_post(url, headers, body)


def change_severity(config, alarm_id, severity):
    company_id = config["company_id"]
    url = f"{SOCRADAR_BASE_URL}/company/{company_id}/alarm/severity"
    headers = {
        "API-Key": config["api_key"],
        "Content-Type": "application/json",
    }
    body = {
        "alarm_id": alarm_id,
        "severity": severity,
    }
    return api_post(url, headers, body)


def add_tag(config, alarm_id, tag):
    company_id = config["company_id"]
    url = f"{SOCRADAR_BASE_URL}/company/{company_id}/alarm/tag"
    headers = {
        "API-Key": config["api_key"],
        "Content-Type": "application/json",
    }
    body = {
        "alarm_id": alarm_id,
        "tag": tag,
    }
    return api_post(url, headers, body)


def ask_analyst(config, alarm_id, comment):
    company_id = config["company_id"]
    url = f"{SOCRADAR_BASE_URL}/company/{company_id}/incidents/ask/analyst/v2"
    headers = {
        "API-Key": config["api_key"],
        "Content-Type": "application/json",
    }
    body = {
        "alarm_id": alarm_id,
        "comment": comment,
    }
    return api_post(url, headers, body)


def process_alert(alert, config):
    """Process a Wazuh alert and take action on SOCRadar."""

    # Extract SOCRadar data from the alert
    socradar = alert.get("data", {}).get("socradar", {})
    if not socradar:
        log("INFO", "Alert has no SOCRadar data, skipping")
        return

    alarm_id = socradar.get("alarm_id")
    if not alarm_id:
        log("INFO", "No alarm_id in alert, skipping")
        return

    risk_level = socradar.get("risk_level", "").upper()
    rule_level = alert.get("rule", {}).get("level", 0)
    rule_id = alert.get("rule", {}).get("id", "")
    agent_name = alert.get("agent", {}).get("name", "unknown")

    integration_config = config.get("integration", {})

    # --- Action 1: Auto-tag with "wazuh-ingested" ---
    if integration_config.get("auto_tag", True):
        add_tag(config, alarm_id, "wazuh-ingested")

    # --- Action 2: Post Wazuh context as comment ---
    if integration_config.get("post_wazuh_context", True):
        comment = (
            f"[Wazuh Alert] Rule {rule_id} (level {rule_level}) triggered on "
            f"agent '{agent_name}' at {datetime.now(timezone.utc).isoformat()}. "
            f"Risk: {risk_level}."
        )
        add_comment(config, alarm_id, comment)
        log("INFO", f"Posted comment for alarm {alarm_id}")

    # --- Action 3: Auto-close if rule says false positive ---
    auto_close_rules = integration_config.get("auto_close_rule_ids", [])
    if rule_id in auto_close_rules:
        update_status(config, [alarm_id], STATUS_FALSE_POSITIVE,
                       f"Auto-closed by Wazuh rule {rule_id}")
        log("INFO", f"Auto-closed alarm {alarm_id} as false positive")
        return

    # --- Action 4: Escalate severity for high Wazuh rule levels ---
    if rule_level >= integration_config.get("escalate_threshold", 12):
        if risk_level not in ("CRITICAL",):
            change_severity(config, alarm_id, "CRITICAL")
            log("INFO", f"Escalated alarm {alarm_id} to CRITICAL")

    # --- Action 5: Ask analyst for critical + high rule level ---
    if (risk_level == "CRITICAL" and rule_level >= integration_config.get("ask_analyst_threshold", 10)):
        if integration_config.get("auto_ask_analyst", False):
            ask_analyst(config, alarm_id,
                        f"[Wazuh Auto] Critical incident detected. "
                        f"Rule {rule_id}, level {rule_level}, agent {agent_name}.")
            log("INFO", f"Requested analyst for alarm {alarm_id}")

    # --- Action 6: Auto-resolve mitigated incidents ---
    auto_resolve_rules = integration_config.get("auto_resolve_rule_ids", [])
    if rule_id in auto_resolve_rules:
        update_status(config, [alarm_id], STATUS_MITIGATED,
                       f"Auto-mitigated by Wazuh rule {rule_id}")
        log("INFO", f"Marked alarm {alarm_id} as mitigated")


def main():
    global debug_enabled

    # Parse arguments from integratord
    if len(sys.argv) < 2:
        log("ERROR", "No alert file provided")
        sys.exit(1)

    alert_file_path = sys.argv[1]
    # api_key_arg = sys.argv[2] if len(sys.argv) > 2 else ""  # unused, we use config file
    # hook_url = sys.argv[3] if len(sys.argv) > 3 else ""     # unused
    debug_enabled = (sys.argv[4] == "debug") if len(sys.argv) > 4 else False

    # Load alert
    try:
        with open(alert_file_path) as f:
            alert = json.load(f)
    except Exception as e:
        log("ERROR", f"Failed to read alert file: {e}")
        sys.exit(1)

    # Load config
    config = load_config()
    if not config:
        sys.exit(1)

    log("INFO", f"Processing alert for rule {alert.get('rule', {}).get('id', '?')}")
    process_alert(alert, config)


if __name__ == "__main__":
    main()
