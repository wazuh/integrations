#!/usr/bin/env python3
"""
SOCRadar Bidirectional Integration for Wazuh
=============================================
Receives Wazuh alerts (via integratord) and sends feedback to SOCRadar:
  - Auto-tag incidents as "wazuh-ingested"
  - Post Wazuh context (rule ID, level, description) as comment
  - Auto-close/resolve incidents based on rule IDs
  - Severity escalation based on Wazuh alert level
  - Ask analyst assignment for high-severity alerts

This script is called by Wazuh integratord when a SOCRadar alert triggers.
It receives two arguments:
  $1 = path to alert JSON file
  $2 = API key (from ossec.conf, optional — we use socradar.conf)

Placement:
  /var/ossec/integrations/custom-socradar.py

Author: SOCRadar Integration Team
Version: 1.0.0
"""

import json
import os
import sys
import ssl
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Paths & Constants
# ---------------------------------------------------------------------------
WAZUH_HOME = os.environ.get("WAZUH_HOME", "/var/ossec")
CONFIG_FILE = os.path.join(WAZUH_HOME, "etc", "socradar.conf")
LOG_FILE = os.path.join(WAZUH_HOME, "logs", "socradar-integration.log")

SOCRADAR_BASE_URL = "https://platform.socradar.com/api"

VERSION = "1.0.1"
USER_AGENT = f"wazuh-socradar-integration/{VERSION}"

# SSL context (initialized in main() after config is loaded)
SSL_CTX = None

# Throttle outbound requests to reduce SOCRadar rate-limit hits.
# This integration can make multiple API calls per alert (tag/comment/status/severity/ask-analyst).
OUTBOUND_REQUEST_DELAY_SECONDS = 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log(level, msg):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"{ts} socradar-integration {level}: {msg}"
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass
    if level == "ERROR":
        print(line, file=sys.stderr)


def load_config():
    if not os.path.isfile(CONFIG_FILE):
        log("ERROR", f"Config not found: {CONFIG_FILE}")
        return None
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except Exception as e:
        log("ERROR", f"Config parse error: {e}")
        return None


def load_alert(alert_file):
    try:
        with open(alert_file) as f:
            return json.load(f)
    except Exception as e:
        log("ERROR", f"Alert file error: {e}")
        return None


def _parse_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in ("1", "true", "yes", "y", "on"):
        return True
    if s in ("0", "false", "no", "n", "off"):
        return False
    return default


def build_ssl_context(config):
    """Build an SSLContext based on config.

    Config options:
      - tls_verify: bool (default true)
      - ca_bundle_path: path to PEM bundle (optional)
    """
    tls_verify = _parse_bool((config or {}).get("tls_verify"), default=True)
    ca_bundle_path = (config or {}).get("ca_bundle_path") or (config or {}).get("ca_bundle")

    if tls_verify:
        if ca_bundle_path:
            if not os.path.isfile(ca_bundle_path):
                log("ERROR", f"ca_bundle_path not found: {ca_bundle_path}")
                return ssl.create_default_context()
            return ssl.create_default_context(cafile=ca_bundle_path)
        return ssl.create_default_context()

    log("WARN", "TLS verification is disabled (tls_verify=false). This is insecure and not recommended.")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _sleep_backoff(attempt, retry_after=None):
    # Small bounded backoff to avoid blocking integratord too long.
    if retry_after is not None:
        try:
            seconds = int(float(retry_after))
            seconds = max(1, min(seconds, 30))
        except Exception:
            seconds = 2
    else:
        seconds = min(2 ** attempt, 8)
    time.sleep(seconds)


def api_post(url, headers, data):
    """Send POST request to SOCRadar API (with basic retry/backoff)."""
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    for attempt in range(1, 4):
        try:
            open_kwargs = {"timeout": 30}
            if SSL_CTX is not None:
                open_kwargs["context"] = SSL_CTX
            with urllib.request.urlopen(req, **open_kwargs) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            retry_after = None
            try:
                retry_after = e.headers.get("Retry-After")
            except Exception:
                retry_after = None
            err_body = ""
            try:
                err_body = e.read().decode(errors="replace") if e.fp else ""
            except Exception:
                err_body = ""

            if e.code in (429, 500, 502, 503, 504) and attempt < 3:
                log("WARN", f"HTTP {e.code} on POST (attempt {attempt}/3). Retrying...")
                _sleep_backoff(attempt, retry_after=retry_after)
                continue

            log("ERROR", f"HTTP {e.code}: {err_body[:500]}")
            return None
        except Exception as e:
            if attempt < 3:
                log("WARN", f"Request failed on POST (attempt {attempt}/3): {e}. Retrying...")
                _sleep_backoff(attempt)
                continue
            log("ERROR", f"Request failed: {e}")
            return None


def api_put(url, headers, data):
    """Send PUT request to SOCRadar API (with basic retry/backoff)."""
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers, method="PUT")
    for attempt in range(1, 4):
        try:
            open_kwargs = {"timeout": 30}
            if SSL_CTX is not None:
                open_kwargs["context"] = SSL_CTX
            with urllib.request.urlopen(req, **open_kwargs) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            retry_after = None
            try:
                retry_after = e.headers.get("Retry-After")
            except Exception:
                retry_after = None
            err_body = ""
            try:
                err_body = e.read().decode(errors="replace") if e.fp else ""
            except Exception:
                err_body = ""

            if e.code in (429, 500, 502, 503, 504) and attempt < 3:
                log("WARN", f"HTTP {e.code} on PUT (attempt {attempt}/3). Retrying...")
                _sleep_backoff(attempt, retry_after=retry_after)
                continue

            log("ERROR", f"HTTP {e.code}: {err_body[:500]}")
            return None
        except Exception as e:
            if attempt < 3:
                log("WARN", f"Request failed on PUT (attempt {attempt}/3): {e}. Retrying...")
                _sleep_backoff(attempt)
                continue
            log("ERROR", f"Request failed: {e}")
            return None


# ---------------------------------------------------------------------------
# SOCRadar API Actions
# ---------------------------------------------------------------------------

def add_tag(config, alarm_id, tag):
    """Add a tag to a SOCRadar alarm."""
    company_id = config["company_id"]
    url = f"{SOCRADAR_BASE_URL}/company/{company_id}/alarm/tag"
    headers = {
        "API-Key": config["api_key"],
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    data = {
        "alarm_id": alarm_id,
        "tag": tag,
        "action": "add"
    }
    result = api_post(url, headers, data)
    if result:
        log("INFO", f"Tag '{tag}' added to alarm {alarm_id}")
    return result


def add_comment(config, alarm_id, comment_text):
    """Add a comment to a SOCRadar alarm."""
    company_id = config["company_id"]
    url = f"{SOCRADAR_BASE_URL}/company/{company_id}/alarm/add/comment/v2"
    headers = {
        "API-Key": config["api_key"],
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    data = {
        "alarm_id": alarm_id,
        "comment": comment_text,
    }
    if config.get("user_email"):
        data["email"] = config["user_email"]

    result = api_post(url, headers, data)
    if result:
        log("INFO", f"Comment added to alarm {alarm_id}")
    return result


def change_status(config, alarm_id, new_status, resolution_type=None):
    """
    Change alarm status on SOCRadar.
    new_status: OPEN, RESOLVED, CLOSED, FALSE_POSITIVE
    resolution_type: Used when closing — e.g. "false_positive", "resolved", "duplicate"
    """
    company_id = config["company_id"]
    url = f"{SOCRADAR_BASE_URL}/company/{company_id}/incidents/v4/status/change"
    headers = {
        "API-Key": config["api_key"],
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    data = {
        "alarm_ids": [alarm_id],
        "status": new_status,
    }
    if resolution_type:
        data["resolution_type"] = resolution_type

    result = api_post(url, headers, data)
    if result:
        log("INFO", f"Alarm {alarm_id} status changed to {new_status}")
    return result


def change_severity(config, alarm_id, new_severity):
    """
    Change alarm severity on SOCRadar.
    new_severity: LOW, MEDIUM, HIGH, CRITICAL
    """
    company_id = config["company_id"]
    url = f"{SOCRADAR_BASE_URL}/company/{company_id}/incidents/v4/severity/change"
    headers = {
        "API-Key": config["api_key"],
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    data = {
        "alarm_ids": [alarm_id],
        "severity": new_severity,
    }
    result = api_post(url, headers, data)
    if result:
        log("INFO", f"Alarm {alarm_id} severity changed to {new_severity}")
    return result


def ask_analyst(config, alarm_id):
    """Request analyst assignment for an alarm."""
    company_id = config["company_id"]
    url = f"{SOCRADAR_BASE_URL}/company/{company_id}/alarm/ask-analyst"
    headers = {
        "API-Key": config["api_key"],
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    data = {
        "alarm_id": alarm_id,
    }
    result = api_post(url, headers, data)
    if result:
        log("INFO", f"Analyst requested for alarm {alarm_id}")
    return result


# ---------------------------------------------------------------------------
# Alert Processing Logic
# ---------------------------------------------------------------------------

def build_wazuh_comment(alert):
    """Build a comment string from Wazuh alert data."""
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    timestamp = alert.get("timestamp", "")

    lines = [
        "=== Wazuh SIEM Alert ===",
        f"Timestamp: {timestamp}",
        f"Rule ID: {rule.get('id', 'N/A')}",
        f"Level: {rule.get('level', 'N/A')}",
        f"Description: {rule.get('description', 'N/A')}",
        f"Groups: {', '.join(rule.get('groups', []))}",
    ]

    if agent.get("name"):
        lines.append(f"Agent: {agent.get('name', '')} (ID: {agent.get('id', '')})")

    manager = alert.get("manager", {})
    if manager.get("name"):
        lines.append(f"Manager: {manager.get('name', '')}")

    lines.append("========================")
    return "\n".join(lines)


def wazuh_level_to_socradar_severity(level):
    """Map Wazuh alert level to SOCRadar severity."""
    if level >= 13:
        return "CRITICAL"
    elif level >= 10:
        return "HIGH"
    elif level >= 7:
        return "MEDIUM"
    else:
        return "LOW"


def _throttle_outbound():
    try:
        time.sleep(OUTBOUND_REQUEST_DELAY_SECONDS)
    except Exception:
        pass


def process_alert(config, alert):
    """Process a single Wazuh alert and perform SOCRadar actions."""
    # Extract SOCRadar alarm ID from alert data.
    # Depending on decoder/version, socradar payload may exist under alert.data or at top-level.
    socradar_data = (
        (alert.get("data") or {}).get("socradar")
        or (alert.get("socradar") or {})
    )
    if not socradar_data:
        log("DEBUG", "No socradar data in alert, skipping")
        return

    alarm_id = socradar_data.get("alarm_id")
    if not alarm_id:
        log("DEBUG", "No alarm_id in socradar data, skipping")
        return

    rule = alert.get("rule", {})
    rule_id = int(rule.get("id", 0))
    rule_level = int(rule.get("level", 0))

    integration_config = config.get("integration", {})

    log("INFO", f"Processing alarm {alarm_id} | Rule: {rule_id}, Level: {rule_level}")

    # --- Action 1: Auto-tag ---
    if integration_config.get("auto_tag", True):
        add_tag(config, alarm_id, "wazuh-ingested")
        _throttle_outbound()

    # --- Action 2: Post Wazuh context as comment ---
    if integration_config.get("post_wazuh_context", True):
        comment = build_wazuh_comment(alert)
        add_comment(config, alarm_id, comment)
        _throttle_outbound()

    # --- Action 3: Auto-close by rule ID ---
    auto_close_rules = integration_config.get("auto_close_rule_ids", [])
    if auto_close_rules and rule_id in auto_close_rules:
        change_status(config, alarm_id, "FALSE_POSITIVE", "false_positive")
        _throttle_outbound()
        log("INFO", f"Alarm {alarm_id} auto-closed (rule {rule_id})")
        return  # Don't process further if closed

    # --- Action 4: Auto-resolve by rule ID ---
    auto_resolve_rules = integration_config.get("auto_resolve_rule_ids", [])
    if auto_resolve_rules and rule_id in auto_resolve_rules:
        change_status(config, alarm_id, "RESOLVED", "resolved")
        _throttle_outbound()
        log("INFO", f"Alarm {alarm_id} auto-resolved (rule {rule_id})")
        return

    # --- Action 5: Severity escalation ---
    escalate_threshold = integration_config.get("escalate_threshold", 12)
    if escalate_threshold and rule_level >= escalate_threshold:
        new_severity = wazuh_level_to_socradar_severity(rule_level)
        current_severity = socradar_data.get("risk_level", "").upper()

        severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        if severity_order.get(new_severity, 0) > severity_order.get(current_severity, 0):
            change_severity(config, alarm_id, new_severity)
            _throttle_outbound()
            log("INFO", f"Alarm {alarm_id} escalated to {new_severity}")

    # --- Action 6: Ask analyst ---
    ask_analyst_enabled = integration_config.get("auto_ask_analyst", False)
    ask_analyst_threshold = integration_config.get("ask_analyst_threshold", 10)
    if ask_analyst_enabled and rule_level >= ask_analyst_threshold:
        ask_analyst(config, alarm_id)
        _throttle_outbound()


# ---------------------------------------------------------------------------
# Main — Called by Wazuh integratord
# ---------------------------------------------------------------------------

def main():
    # integratord passes: $1 = alert file, $2 = api_key (optional)
    if len(sys.argv) < 2:
        log("ERROR", "No alert file provided")
        sys.exit(1)

    alert_file = sys.argv[1]

    # Load config
    config = load_config()
    if not config:
        sys.exit(1)

    # TLS
    global SSL_CTX
    SSL_CTX = build_ssl_context(config)

    # Load alert
    alert = load_alert(alert_file)
    if not alert:
        sys.exit(1)

    # Process
    try:
        process_alert(config, alert)
    except Exception as e:
        log("ERROR", f"Unhandled error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
