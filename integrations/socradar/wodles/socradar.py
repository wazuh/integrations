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
  - Retry with exponential backoff on API failures
  - Catch-up mechanism for failed time windows
  - Runs every 1 minute via Wazuh wodle command

Pagination Logic:
  SOCRadar returns newest alarms on page 1, oldest on last page.
  We want chronological order, so:
    1. GET page=1 with include_total_records=true → total count
    2. total_pages = ceil(total / 100)
    3. Fetch pages: total_pages, total_pages-1, ..., 2, 1
    4. Emit in that order → oldest first, newest last

Author: SOCRadar Integration Team
Version: 1.0.2

Changelog:
  1.0.2 - Retry with exponential backoff (3 attempts per request)
        - Catch-up mechanism for failed time windows
        - API timeout increased from 120s to 180s
        - Dedup cache increased from 10,000 to 50,000
        - Failed window queue with max 20 entries
  1.0.1 - TLS config, verbose logging, response shape handling
  1.0.0 - Initial release
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

VERSION = "1.0.2"
USER_AGENT = f"wazuh-socradar-integration/{VERSION}"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_API_TIMEOUT = 180       # seconds per HTTP request (was 120 in v1.0.1)
DEFAULT_RETRY_COUNT = 3         # max retries per request
DEFAULT_RETRY_BACKOFF = 5       # base seconds between retries (5, 10, 15)
DEFAULT_DEDUP_CACHE_SIZE = 50000  # max seen alarm IDs (was 10000 in v1.0.1)
DEFAULT_MAX_FAILED_WINDOWS = 20   # max queued failed windows
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 100

# ---------------------------------------------------------------------------
# Logging (supports INFO/DEBUG verbosity)
# ---------------------------------------------------------------------------

_LEVELS = {"ERROR": 0, "WARN": 1, "INFO": 2, "DEBUG": 3}
_LOG_LEVEL_NUM = _LEVELS["INFO"]


def set_log_level(level):
    global _LOG_LEVEL_NUM
    if not level:
        return
    level = str(level).strip().upper()
    if level in _LEVELS:
        _LOG_LEVEL_NUM = _LEVELS[level]


def _should_log(level):
    return _LEVELS.get(level, 2) <= _LOG_LEVEL_NUM

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
WAZUH_HOME = os.environ.get("WAZUH_HOME", "/var/ossec")
CONFIG_FILE = os.path.join(WAZUH_HOME, "etc", "socradar.conf")
STATE_FILE = os.path.join(WAZUH_HOME, "var", "socradar_state.json")
LOG_FILE = os.path.join(WAZUH_HOME, "logs", "socradar-wodle.log")

SOCRADAR_BASE_URL = "https://platform.socradar.com/api"

# TLS / SSL — initialized in main() after config is loaded.
SSL_CTX = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log(level, msg):
    if not _should_log(level):
        return
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


def _truncate(s, limit=1200):
    if s is None:
        return ""
    if len(s) <= limit:
        return s
    return s[:limit] + f"... (truncated, {len(s)} chars)"


def _safe_headers_for_log(headers_obj):
    """Return selected response headers for debug logging."""
    if not headers_obj:
        return {}
    keys = [
        "Content-Type", "Content-Length", "Retry-After",
        "X-RateLimit-Limit", "X-RateLimit-Remaining",
        "X-RateLimit-Reset", "Date",
    ]
    safe = {}
    try:
        for k in keys:
            v = headers_obj.get(k)
            if v is not None:
                safe[k] = v
    except Exception:
        return {}
    return safe


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


def _parse_int(value, default):
    if value is None:
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def build_ssl_context(config):
    """Build an SSLContext based on config."""
    tls_verify = _parse_bool((config or {}).get("tls_verify"), default=True)
    ca_bundle_path = (config or {}).get("ca_bundle_path") or (config or {}).get("ca_bundle")

    if tls_verify:
        if ca_bundle_path:
            if not os.path.isfile(ca_bundle_path):
                log("WARN", f"ca_bundle_path not found: {ca_bundle_path} (using system trust store)")
                return ssl.create_default_context()
            return ssl.create_default_context(cafile=ca_bundle_path)
        return ssl.create_default_context()

    log("WARN", "TLS verification is disabled (tls_verify=false). This is insecure.")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ---------------------------------------------------------------------------
# API Request with Retry  [NEW in v1.0.2]
# ---------------------------------------------------------------------------

def api_request(url, headers, config=None):
    """
    Send GET request with retry + exponential backoff.
    
    v1.0.2 changes:
      - Timeout: 120s → 180s (configurable via api_timeout)
      - Retries: 0 → 3 attempts with backoff (configurable via api_retries)
    """
    cfg = config or {}
    timeout = _parse_int(cfg.get("api_timeout"), DEFAULT_API_TIMEOUT)
    max_retries = _parse_int(cfg.get("api_retries"), DEFAULT_RETRY_COUNT)
    backoff_base = _parse_int(cfg.get("api_retry_backoff"), DEFAULT_RETRY_BACKOFF)

    last_error = None

    for attempt in range(1, max_retries + 1):
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            start = time.time()
            open_kwargs = {"timeout": timeout}
            if SSL_CTX is not None:
                open_kwargs["context"] = SSL_CTX

            with urllib.request.urlopen(req, **open_kwargs) as resp:
                status = getattr(resp, "status", None) or resp.getcode()
                raw = resp.read()
                elapsed_ms = int((time.time() - start) * 1000)

                if _should_log("DEBUG"):
                    safe_resp_headers = _safe_headers_for_log(getattr(resp, "headers", None))
                    log("DEBUG", f"HTTP {status} {elapsed_ms}ms | {url} | headers={safe_resp_headers} | bytes={len(raw)}")

                try:
                    return json.loads(raw.decode())
                except Exception as e:
                    snippet = ""
                    try:
                        snippet = _truncate(raw.decode(errors="replace"), 2000)
                    except Exception:
                        snippet = "<non-text response>"
                    log("ERROR", f"Failed to parse JSON from {url}: {e} | body={snippet}")
                    return None

        except urllib.error.HTTPError as e:
            err_body = ""
            try:
                err_body = e.read().decode(errors="replace") if e.fp else ""
            except Exception:
                err_body = ""

            # Don't retry on 4xx client errors (except 429 rate limit)
            if 400 <= e.code < 500 and e.code != 429:
                log("ERROR", f"HTTP {e.code} from {url}: {_truncate(err_body, 2000)} (not retrying)")
                return None

            last_error = f"HTTP {e.code}: {_truncate(err_body, 500)}"
            log("WARN", f"Attempt {attempt}/{max_retries} failed: {last_error}")

        except Exception as e:
            last_error = str(e)
            log("WARN", f"Attempt {attempt}/{max_retries} failed: {e} | url={url}")

        # Backoff before retry
        if attempt < max_retries:
            wait = backoff_base * attempt
            log("INFO", f"Retrying in {wait}s...")
            time.sleep(wait)

    log("ERROR", f"All {max_retries} attempts failed for {url}: {last_error}")
    return None


def parse_args(argv):
    args = {"verbose": False, "log_level": None}
    for a in argv[1:]:
        if a in ("-v", "--verbose", "--debug"):
            args["verbose"] = True
        elif a.startswith("--log-level="):
            args["log_level"] = a.split("=", 1)[1]
        elif a == "--log-level":
            pass
    for i, a in enumerate(argv[1:]):
        if a == "--log-level" and i + 2 <= len(argv) - 1:
            args["log_level"] = argv[i + 2]
            break
    return args


def apply_log_settings(config, args):
    env_level = os.environ.get("SOCRADAR_LOG_LEVEL")
    env_verbose = os.environ.get("SOCRADAR_VERBOSE")
    if args.get("log_level"):
        set_log_level(args["log_level"]); return
    if args.get("verbose"):
        set_log_level("DEBUG"); return
    if env_level:
        set_log_level(env_level); return
    if env_verbose and str(env_verbose).strip().lower() in ("1", "true", "yes", "y", "on"):
        set_log_level("DEBUG"); return
    cfg_level = config.get("log_level") if isinstance(config, dict) else None
    cfg_verbose = config.get("verbose") if isinstance(config, dict) else None
    if cfg_level:
        set_log_level(cfg_level)
    elif cfg_verbose is True or str(cfg_verbose or "").strip().lower() in ("1", "true", "yes", "y", "on"):
        set_log_level("DEBUG")


def now_epoch():
    return int(time.time())


def get_page_size(config):
    try:
        page_size = int(config.get("fetch_limit", DEFAULT_PAGE_SIZE))
    except Exception:
        page_size = DEFAULT_PAGE_SIZE
    return max(1, min(page_size, MAX_PAGE_SIZE))


def get_max_pages(config):
    value = config.get("max_pages")
    if value is None or value == "":
        return None
    try:
        max_pages = int(value)
    except Exception:
        return None
    return max_pages if max_pages > 0 else None


def _extract_list_and_total(result):
    """Extract incident list and total_records from varying API response shapes."""
    if not isinstance(result, dict):
        return [], 0

    total_records = result.get("total_records", 0)
    data = result.get("data", [])

    if isinstance(data, dict):
        total_records = data.get("total_records", total_records)
        for key in ("data", "items", "incidents", "alarms", "records", "results"):
            candidate = data.get(key)
            if isinstance(candidate, list):
                return candidate, total_records
        nested = data.get("data")
        if isinstance(nested, dict):
            total_records = nested.get("total_records", total_records)
            for key in ("data", "items", "incidents", "alarms", "records", "results"):
                candidate = nested.get(key)
                if isinstance(candidate, list):
                    return candidate, total_records
        return [], total_records

    if isinstance(data, list):
        return data, total_records

    return [], total_records


# ---------------------------------------------------------------------------
# SOCRadar API v4 — Full Reverse Pagination
# ---------------------------------------------------------------------------

def build_url(config, start_epoch, end_epoch, page, page_size, include_total=False):
    company_id = config["company_id"]
    params = {
        "page": page,
        "limit": page_size,
        "start_date": start_epoch,
        "end_date": end_epoch,

    }
    if include_total:
        params["include_total_records"] = "true"
    if config.get("fetch_status"):
        params["status"] = config["fetch_status"]
    if config.get("min_severity"):
        params["severities"] = config["min_severity"]
    main_types = config.get("alarm_main_types", [])
    for i, t in enumerate(main_types):
        params[f"alarm_main_types[{i}]"] = t
    query = urllib.parse.urlencode(params, doseq=False)
    return f"{SOCRADAR_BASE_URL}/company/{company_id}/incidents/v4?{query}"


def fetch_page(config, start_epoch, end_epoch, page, page_size, include_total=False):
    url = build_url(config, start_epoch, end_epoch, page, page_size, include_total)
    headers = {
        "API-Key": config["api_key"],
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    return api_request(url, headers, config=config)


def fetch_all_incidents(config, start_epoch, end_epoch):
    """Full reverse pagination for chronological order."""
    log("INFO", f"Fetching | epoch {start_epoch} -> {end_epoch}")

    page_size = get_page_size(config)
    max_pages = get_max_pages(config)

    if _should_log("DEBUG"):
        log("DEBUG", f"Fetch settings: page_size={page_size}, max_pages={max_pages}")

    result = fetch_page(config, start_epoch, end_epoch, page=1, page_size=page_size, include_total=True)

    if not result or not result.get("is_success", False):
        # [v1.0.2] Return None instead of [] to distinguish API failure from empty result
        log("ERROR", f"Initial call failed (after retries): {result}")
        return None

    first_page_data, total_records = _extract_list_and_total(result)

    if total_records == 0 and not first_page_data:
        log("INFO", "No incidents in time range")
        return []

    if total_records == 0:
        total_records = len(first_page_data)

    total_pages = math.ceil(total_records / page_size)

    if max_pages and total_pages > max_pages:
        log("INFO", f"Total: {total_records} records, {total_pages} pages (limiting to {max_pages})")
        total_pages = max_pages
    else:
        log("INFO", f"Total: {total_records} records, {total_pages} pages")

    if total_pages <= 1:
        return list(reversed(first_page_data))

    all_pages = {1: first_page_data}
    for page_num in range(total_pages, 1, -1):
        log("INFO", f"Fetching page {page_num}/{total_pages}")
        page_result = fetch_page(config, start_epoch, end_epoch, page_num, page_size)
        if not page_result or not page_result.get("is_success", False):
            log("ERROR", f"Failed page {page_num} (after retries)")
            continue
        page_data, _ = _extract_list_and_total(page_result)
        if page_data:
            all_pages[page_num] = page_data
        time.sleep(0.2)

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
    if not isinstance(incident, dict):
        return

    risk_level = incident.get("alarm_risk_level", "UNKNOWN")
    if risk_level is None:
        risk_level = "UNKNOWN"

    output = {
        "socradar": {
            "source": "incident_api_v4",
            "alarm_id": incident.get("alarm_id"),
            "alarm_asset": incident.get("alarm_asset", ""),
            "risk_level": str(risk_level).upper(),
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
# Failed Window Queue  [NEW in v1.0.2]
# ---------------------------------------------------------------------------

def _get_failed_windows(state):
    """Get list of failed time windows from state."""
    return state.get("failed_windows", [])


def _add_failed_window(state, start_epoch, end_epoch, max_queue=DEFAULT_MAX_FAILED_WINDOWS):
    """Add a failed time window to retry queue."""
    windows = state.get("failed_windows", [])
    # Don't add duplicate
    for w in windows:
        if w.get("start") == start_epoch and w.get("end") == end_epoch:
            w["retries"] = w.get("retries", 0) + 1
            return
    windows.append({
        "start": start_epoch,
        "end": end_epoch,
        "retries": 1,
        "added": datetime.now(timezone.utc).isoformat(),
    })
    # Keep only the most recent N
    if len(windows) > max_queue:
        windows = windows[-max_queue:]
    state["failed_windows"] = windows


def _remove_failed_window(state, start_epoch, end_epoch):
    """Remove a successfully processed window from queue."""
    windows = state.get("failed_windows", [])
    state["failed_windows"] = [
        w for w in windows
        if not (w.get("start") == start_epoch and w.get("end") == end_epoch)
    ]


def _process_window(config, state, start_epoch, end_epoch, seen):
    """
    Fetch and emit incidents for a single time window.
    Returns (new_count, success).
    """
    incidents = fetch_all_incidents(config, start_epoch, end_epoch)

    if incidents is None:
        # API failure — queue for retry
        return 0, False

    new_count = 0
    for incident in incidents:
        if not isinstance(incident, dict):
            continue
        alarm_id = incident.get("alarm_id")
        if alarm_id is not None and alarm_id not in seen:
            if _should_log("DEBUG"):
                log("DEBUG",
                    f"Emitting | alarm_id={alarm_id} "
                    f"risk={incident.get('alarm_risk_level')} "
                    f"date={incident.get('date')}")
            emit_alert(incident)
            seen.add(alarm_id)
            new_count += 1

    return new_count, True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args(sys.argv)
    config = load_config()
    apply_log_settings(config, args)

    global SSL_CTX
    SSL_CTX = build_ssl_context(config)
    state = load_state()

    cache_limit = _parse_int(config.get("dedup_cache_size"), DEFAULT_DEDUP_CACHE_SIZE)

    # Time window: last_run → now
    end_epoch = now_epoch()
    last_run_epoch = state.get("last_run_epoch")

    if last_run_epoch:
        start_epoch = last_run_epoch
    else:
        lookback_hours = config.get("initial_lookback_hours", 24)
        start_epoch = end_epoch - (lookback_hours * 3600)

    log("INFO",
        f"Starting v{VERSION} | {start_epoch} -> {end_epoch} | "
        f"{datetime.fromtimestamp(start_epoch, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} -> "
        f"{datetime.fromtimestamp(end_epoch, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}")

    seen = set(state.get("seen_alarm_ids", []))
    total_new = 0

    # -----------------------------------------------------------------------
    # [v1.0.2] Step 1: Retry any previously failed windows first
    # -----------------------------------------------------------------------
    failed_windows = _get_failed_windows(state)
    if failed_windows:
        log("INFO", f"Retrying {len(failed_windows)} previously failed window(s)")
        remaining_failed = []
        for fw in failed_windows:
            fw_start = fw.get("start")
            fw_end = fw.get("end")
            retries = fw.get("retries", 0)

            # Give up after 5 retries
            if retries >= 5:
                log("WARN", f"Giving up on window {fw_start}->{fw_end} after {retries} retries")
                continue

            log("INFO", f"Retry window {fw_start} -> {fw_end} (attempt {retries + 1})")
            new_count, success = _process_window(config, state, fw_start, fw_end, seen)
            total_new += new_count

            if success:
                log("INFO", f"Retry succeeded | window {fw_start}->{fw_end} | New: {new_count}")
            else:
                fw["retries"] = retries + 1
                remaining_failed.append(fw)
                log("WARN", f"Retry failed again | window {fw_start}->{fw_end}")

        state["failed_windows"] = remaining_failed

    # -----------------------------------------------------------------------
    # Step 2: Process current time window
    # -----------------------------------------------------------------------
    new_count, success = _process_window(config, state, start_epoch, end_epoch, seen)
    total_new += new_count

    if success:
        state["last_run_epoch"] = end_epoch
        state["last_run_iso"] = datetime.fromtimestamp(end_epoch, tz=timezone.utc).isoformat()
    else:
        # [v1.0.2] API failed — save this window for retry, but still advance epoch
        # to prevent infinite retry of the same growing window
        _add_failed_window(state, start_epoch, end_epoch)
        state["last_run_epoch"] = end_epoch
        state["last_run_iso"] = datetime.fromtimestamp(end_epoch, tz=timezone.utc).isoformat()
        log("WARN", f"Current window failed — queued for retry | {start_epoch} -> {end_epoch}")

    # -----------------------------------------------------------------------
    # Save state
    # -----------------------------------------------------------------------
    seen_list = list(seen)
    if len(seen_list) > cache_limit:
        seen_list = seen_list[-cache_limit:]

    state["seen_alarm_ids"] = seen_list
    state["last_fetch_new"] = total_new
    state["last_fetch_total"] = total_new  # approximation since we process multiple windows
    save_state(state)

    failed_count = len(state.get("failed_windows", []))
    log("INFO", f"Done | New: {total_new}, Cache: {len(seen_list)}, Queued: {failed_count}")


if __name__ == "__main__":
    main()
