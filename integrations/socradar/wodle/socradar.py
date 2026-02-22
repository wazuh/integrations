#!/usr/bin/env python3
"""
SOCRadar Incident Fetcher Wodle for Wazuh
==========================================
Fetches incidents from SOCRadar Incident API v4 and outputs
JSON to stdout for Wazuh ingestion via wodle command framework.

Features:
  - Epoch time based start_date / end_date
  - Full reverse pagination (last page → first page)
  - Chronological output (oldest alarms first)
  - Deduplication via state file
  - Runs every 1 minute via Wazuh wodle command

Pagination Logic:
  SOCRadar returns newest alarms on page 1, oldest on last page.
  We want chronological order, so:
    1. GET page=1 with include_total_records=true → total count
    2. total_pages = ceil(total / 100)
    3. Fetch pages: total_pages, total_pages-1, ..., 2, 1
    4. Emit in that order → oldest first, newest last

Author: SOCRadar Integration Team
Version: 1.0.0
"""

import json
import os
import sys
import time
import math
import ssl
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
WAZUH_HOME = os.environ.get("WAZUH_HOME", "/var/ossec")
CONFIG_FILE = os.path.join(WAZUH_HOME, "etc", "socradar.conf")
STATE_FILE = os.path.join(WAZUH_HOME, "var", "socradar_state.json")
LOG_FILE = os.path.join(WAZUH_HOME, "logs", "socradar-wodle.log")

SOCRADAR_BASE_URL = "https://platform.socradar.com/api"
PAGE_SIZE = 100  # SOCRadar returns max 100 per page

# SSL context — disable verification for environments with proxy/self-signed certs
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log(level, msg):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"{ts} socradar-wodle {level}: {msg}"
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
        sys.exit(1)
    with open(CONFIG_FILE) as f:
        return json.load(f)


def load_state():
    if os.path.isfile(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


def api_request(url, headers):
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=120, context=SSL_CTX) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        err_body = e.read().decode() if e.fp else ""
        log("ERROR", f"HTTP {e.code} from {url}: {err_body}")
        return None
    except Exception as e:
        log("ERROR", f"Request failed: {e}")
        return None


def now_epoch():
    return int(time.time())


# ---------------------------------------------------------------------------
# SOCRadar API v4 — Full Reverse Pagination
# ---------------------------------------------------------------------------

def build_url(config, start_epoch, end_epoch, page, include_total=False):
    """Build API URL with epoch timestamps."""
    company_id = config["company_id"]

    params = {
        "page": page,
        "limit": PAGE_SIZE,
        "start_date": start_epoch,
        "end_date": end_epoch,
        "include_alarm_details": "true",
        "include_ai_insight": "true",
    }

    if include_total:
        params["include_total_records"] = "true"

    # Optional filters from config
    if config.get("fetch_status"):
        params["status"] = config["fetch_status"]
    if config.get("min_severity"):
        params["severities"] = config["min_severity"]

    main_types = config.get("alarm_main_types", [])
    for i, t in enumerate(main_types):
        params[f"alarm_main_types[{i}]"] = t

    query = urllib.parse.urlencode(params, doseq=False)
    return f"{SOCRADAR_BASE_URL}/company/{company_id}/incidents/v4?{query}"


def fetch_page(config, start_epoch, end_epoch, page, include_total=False):
    """Fetch a single page of incidents."""
    url = build_url(config, start_epoch, end_epoch, page, include_total)
    headers = {"API-Key": config["api_key"], "Accept": "application/json"}
    return api_request(url, headers)


def fetch_all_incidents(config, start_epoch, end_epoch):
    """
    Full reverse pagination for chronological order:

    SOCRadar page layout (newest on page 1):
      Page 1: alarms 401-500 (newest)
      Page 2: alarms 301-400
      ...
      Page 5: alarms   1-100 (oldest)

    We fetch: page 5 → 4 → 3 → 2 → 1
    Result:   alarms 1 → 500 (chronological)
    """
    log("INFO", f"Fetching | epoch {start_epoch} -> {end_epoch}")

    # Step 1: Get total count from first request
    result = fetch_page(config, start_epoch, end_epoch, page=1, include_total=True)

    if not result or not result.get("is_success", False):
        log("ERROR", f"Initial call failed: {result}")
        return []

    total_records = result.get("total_records", 0)
    first_page_data = result.get("data", [])

    # Handle both list and dict response formats
    if isinstance(first_page_data, dict):
        total_records = first_page_data.get("total_records", total_records)
        first_page_data = first_page_data.get("data", first_page_data.get("items", []))

    if not isinstance(first_page_data, list):
        log("ERROR", f"Unexpected data type: {type(first_page_data)}")
        return []

    if total_records == 0 and not first_page_data:
        log("INFO", "No incidents in time range")
        return []

    if total_records == 0:
        total_records = len(first_page_data)

    total_pages = math.ceil(total_records / PAGE_SIZE)
    log("INFO", f"Total: {total_records} records, {total_pages} pages")

    # Single page — reverse and return
    if total_pages <= 1:
        return list(reversed(first_page_data))

    # Step 2: Fetch from LAST page to page 2 (we already have page 1)
    all_pages = {1: first_page_data}

    for page_num in range(total_pages, 1, -1):
        log("INFO", f"Fetching page {page_num}/{total_pages}")
        page_result = fetch_page(config, start_epoch, end_epoch, page_num)

        if not page_result or not page_result.get("is_success", False):
            log("ERROR", f"Failed page {page_num}")
            continue

        page_data = page_result.get("data", [])

        # Handle dict response
        if isinstance(page_data, dict):
            page_data = page_data.get("data", page_data.get("items", []))

        if isinstance(page_data, list) and page_data:
            all_pages[page_num] = page_data

        time.sleep(0.2)

    # Step 3: Assemble chronologically (last page first → first page last)
    all_incidents = []
    for page_num in range(total_pages, 0, -1):
        if page_num in all_pages:
            all_incidents.extend(reversed(all_pages[page_num]))

    log("INFO", f"Collected {len(all_incidents)} incidents (chronological)")
    return all_incidents


# ---------------------------------------------------------------------------
# Wazuh Output
# ---------------------------------------------------------------------------

def emit_alert(incident):
    """Print JSON line to stdout for Wazuh ingestion via wodle command."""
    if not isinstance(incident, dict):
        return

    output = {
        "socradar": {
            "source": "incident_api_v4",
            "alarm_id": incident.get("alarm_id"),
            "alarm_asset": incident.get("alarm_asset", ""),
            "risk_level": incident.get("alarm_risk_level", "UNKNOWN"),
            "status": incident.get("status", ""),
            "alarm_text": incident.get("alarm_text", ""),
            "alarm_response": incident.get("alarm_response", ""),
            "date": incident.get("date", ""),
            "notification_id": incident.get("notification_id"),
            "assignees": incident.get("alarm_assignees", []),
            "related_assets": incident.get("alarm_related_assets", []),
            "related_entities": incident.get("alarm_related_entities", []),
            "tags": incident.get("tags", []),
        }
    }

    # Alarm type details
    atd = incident.get("alarm_type_details") or {}
    if atd and isinstance(atd, dict):
        output["socradar"]["main_type"] = atd.get("alarm_main_type", "")
        output["socradar"]["sub_type"] = atd.get("alarm_sub_type", "")
        output["socradar"]["generic_title"] = atd.get("alarm_generic_title", "")
        output["socradar"]["mitigation"] = atd.get("alarm_default_mitigation_plan", "")
        output["socradar"]["detection_analysis"] = atd.get("alarm_detection_and_analysis", "")

        compliance = atd.get("alarm_compliance_list", [])
        if compliance and isinstance(compliance, list):
            output["socradar"]["compliance"] = [
                {
                    "framework": c.get("name", ""),
                    "control": c.get("control_item", ""),
                    "description": c.get("description", ""),
                }
                for c in compliance
                if isinstance(c, dict)
            ]

    # Technical content
    content = incident.get("content") or {}
    if content and isinstance(content, dict):
        tech = {}
        for key in [
            "compromised_domains", "compromised_emails", "compromised_ips",
            "computer_name", "malware_family", "malware_path", "username",
            "antivirus", "app", "log_date",
        ]:
            if content.get(key):
                tech[key] = content[key]

        creds = content.get("credential_details", [])
        if creds and isinstance(creds, list):
            tech["credential_count"] = len(creds)
            tech["credential_urls"] = [
                c.get("URL", "") for c in creds if isinstance(c, dict) and c.get("URL")
            ]
            tech["credential_users"] = [
                c.get("User", "") for c in creds if isinstance(c, dict) and c.get("User")
            ]

        if tech:
            output["socradar"]["content"] = tech

    print(json.dumps(output))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    config = load_config()
    state = load_state()

    # Time window: last_run → now
    end_epoch = now_epoch()

    last_run_epoch = state.get("last_run_epoch")
    if last_run_epoch:
        start_epoch = last_run_epoch
    else:
        # First run: look back N hours (default 24)
        lookback_hours = config.get("initial_lookback_hours", 24)
        start_epoch = end_epoch - (lookback_hours * 3600)

    log("INFO",
        f"Starting | {start_epoch} -> {end_epoch} | "
        f"{datetime.fromtimestamp(start_epoch, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} -> "
        f"{datetime.fromtimestamp(end_epoch, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}")

    # Fetch all incidents (reverse pagination, chronological output)
    incidents = fetch_all_incidents(config, start_epoch, end_epoch)

    # Deduplicate against seen alarm IDs
    seen = set(state.get("seen_alarm_ids", []))
    new_count = 0

    for incident in incidents:
        if not isinstance(incident, dict):
            continue
        alarm_id = incident.get("alarm_id")
        if alarm_id is not None and alarm_id not in seen:
            emit_alert(incident)
            seen.add(alarm_id)
            new_count += 1

    # Bound the seen cache (keep last 10000)
    seen_list = list(seen)
    if len(seen_list) > 10000:
        seen_list = seen_list[-10000:]

    # Save state
    state["seen_alarm_ids"] = seen_list
    state["last_run_epoch"] = end_epoch
    state["last_run_iso"] = datetime.fromtimestamp(end_epoch, tz=timezone.utc).isoformat()
    state["last_fetch_new"] = new_count
    state["last_fetch_total"] = len(incidents)
    save_state(state)

    log("INFO", f"Done | New: {new_count}, Total: {len(incidents)}, Cache: {len(seen_list)}")


if __name__ == "__main__":
    main()
