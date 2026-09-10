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
  - 1-minute incremental window plus periodic catch-up (fetch_overlap_seconds)
  - Uncapped lookback/catch-up bounded per tick (max_catchup_pages + window_resume)
  - Runs every 1 minute via Wazuh wodle command

Pagination Logic:
  SOCRadar returns newest alarms on page 1, oldest on last page.
  We want chronological order, so:
    1. GET page=1 with include_total_records=true → total count
    2. total_pages = ceil(total / 100)
    3. Fetch pages: total_pages, total_pages-1, ..., 2, 1
    4. Emit in that order → oldest first, newest last

Author: SOCRadar Integration Team
Version: 1.0.4
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

VERSION = "1.0.4"
USER_AGENT = f"wazuh-socradar-integration/{VERSION}"


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
DEFAULT_PAGE_SIZE = 100  # SOCRadar returns max 100 per page
MAX_PAGE_SIZE = 100

# TLS / SSL
# Initialized in main() after config is loaded.
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


SEEN_CACHE_MAX = 50000


def persist_seen(state, seen):
    """Write seen_alarm_ids only. Does not set last_run or last_catchup."""
    seen_list = list(seen)
    if len(seen_list) > SEEN_CACHE_MAX:
        seen_list = seen_list[-SEEN_CACHE_MAX:]
        seen.clear()
        seen.update(dict.fromkeys(seen_list))
    state["seen_alarm_ids"] = seen_list
    save_state(state)


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
        "Content-Type",
        "Content-Length",
        "Retry-After",
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-RateLimit-Reset",
        "Date",
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
                log("WARN", f"ca_bundle_path not found: {ca_bundle_path} (using system trust store)")
                return ssl.create_default_context()
            return ssl.create_default_context(cafile=ca_bundle_path)
        return ssl.create_default_context()

    log("WARN", "TLS verification is disabled (tls_verify=false). This is insecure and not recommended.")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _get_int(config, key, default=None, min_value=None, max_value=None):
    if not isinstance(config, dict):
        return default
    value = config.get(key)
    if value is None or value == "":
        return default
    try:
        num = int(value)
    except Exception:
        return default
    if min_value is not None and num < min_value:
        num = min_value
    if max_value is not None and num > max_value:
        num = max_value
    return num


def _get_float(config, key, default=None, min_value=None, max_value=None):
    if not isinstance(config, dict):
        return default
    value = config.get(key)
    if value is None or value == "":
        return default
    try:
        num = float(value)
    except Exception:
        return default
    if min_value is not None and num < min_value:
        num = min_value
    if max_value is not None and num > max_value:
        num = max_value
    return num


def _should_retry_http_status(code):
    # Common transient errors / Cloudflare upstream timeouts.
    return code in (408, 425, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524)


def api_request(url, headers, config=None, timeout_seconds=None):
    """Perform a GET request and parse JSON.

    Retries are intentionally conservative and configurable. The main resiliency
    mechanism is the persistent retry queue in the state file.
    """
    http_retries = _get_int(config, "http_retries", default=0, min_value=0, max_value=5)
    if timeout_seconds is None:
        timeout_seconds = _get_int(config, "http_timeout_seconds", default=120, min_value=5, max_value=600)
    else:
        try:
            timeout_seconds = int(timeout_seconds)
        except Exception:
            timeout_seconds = 15
        if timeout_seconds < 5:
            timeout_seconds = 5
        if timeout_seconds > 600:
            timeout_seconds = 600

    attempts = 0
    max_attempts = 1 + http_retries
    req = urllib.request.Request(url, headers=headers, method="GET")

    while True:
        attempts += 1
        try:
            start = time.time()
            open_kwargs = {"timeout": timeout_seconds}
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
            code = getattr(e, "code", None)
            err_body = ""
            try:
                err_body = e.read().decode(errors="replace") if e.fp else ""
            except Exception:
                err_body = ""
            extra = ""
            if _should_log("DEBUG"):
                extra = f" | headers={_safe_headers_for_log(getattr(e, 'headers', None))}"

            if code and _should_retry_http_status(code) and attempts < max_attempts:
                retry_after = 0
                try:
                    retry_after = int(getattr(e, "headers", {}).get("Retry-After") or 0)
                except Exception:
                    retry_after = 0
                sleep_s = retry_after if retry_after > 0 else min(10, 2 ** (attempts - 1))
                log("WARN", f"HTTP {code} (attempt {attempts}/{max_attempts}) | retrying in {sleep_s}s | url={url}")
                time.sleep(sleep_s)
                continue

            log("ERROR", f"HTTP {code} from {url}: {_truncate(err_body, 2000)}{extra}")
            return None
        except Exception as e:
            # Covers timeouts/URLError/ssl errors.
            if attempts < max_attempts:
                sleep_s = min(10, 2 ** (attempts - 1))
                log("WARN", f"Request failed (attempt {attempts}/{max_attempts}) | retrying in {sleep_s}s | err={e} | url={url}")
                time.sleep(sleep_s)
                continue
            log("ERROR", f"Request failed: {e} | url={url}")
            return None


def parse_args(argv):
    args = {"verbose": False, "log_level": None}
    for a in argv[1:]:
        if a in ("-v", "--verbose", "--debug"):
            args["verbose"] = True
        elif a.startswith("--log-level="):
            args["log_level"] = a.split("=", 1)[1]
        elif a == "--log-level":
            # Next token handled in a second pass below
            pass

    # second pass for "--log-level DEBUG" form
    for i, a in enumerate(argv[1:]):
        if a == "--log-level" and i + 2 <= len(argv) - 1:
            args["log_level"] = argv[i + 2]
            break

    return args


def apply_log_settings(config, args):
    """Set global log level from CLI args/env/config."""
    env_level = os.environ.get("SOCRADAR_LOG_LEVEL")
    env_verbose = os.environ.get("SOCRADAR_VERBOSE")

    if args.get("log_level"):
        set_log_level(args["log_level"])
        return

    if args.get("verbose"):
        set_log_level("DEBUG")
        return

    if env_level:
        set_log_level(env_level)
        return

    if env_verbose and str(env_verbose).strip().lower() in ("1", "true", "yes", "y", "on"):
        set_log_level("DEBUG")
        return

    cfg_level = config.get("log_level") if isinstance(config, dict) else None
    cfg_verbose = config.get("verbose") if isinstance(config, dict) else None

    if cfg_level:
        set_log_level(cfg_level)
    elif cfg_verbose is True or str(cfg_verbose).strip().lower() in ("1", "true", "yes", "y", "on"):
        set_log_level("DEBUG")


def now_epoch():
    return int(time.time())


def get_page_size(config):
    try:
        page_size = int(config.get("fetch_limit", DEFAULT_PAGE_SIZE))
    except Exception:
        page_size = DEFAULT_PAGE_SIZE

    if page_size < 1:
        page_size = 1
    if page_size > MAX_PAGE_SIZE:
        page_size = MAX_PAGE_SIZE
    return page_size


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

    # SOCRadar has returned multiple shapes historically. Support common patterns:
    # - {data: [ ... ], total_records: N}
    # - {data: {items: [ ... ], total_records: N}}
    # - {data: {incidents: [ ... ]}}
    # - {data: {alarms: [ ... ]}}
    if isinstance(data, dict):
        total_records = data.get("total_records", total_records)
        for key in ("data", "items", "incidents", "alarms", "records", "results"):
            candidate = data.get(key)
            if isinstance(candidate, list):
                return candidate, total_records

        # Sometimes the list is nested one more level down.
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


def _params_fingerprint(config):
    """Fingerprint parts of config that affect API query params (excluding api_key)."""
    if not isinstance(config, dict):
        return ""
    try:
        data = {
            "company_id": config.get("company_id"),
            "fetch_status": config.get("fetch_status"),
            "min_severity": config.get("min_severity"),
            "alarm_main_types": config.get("alarm_main_types", []),
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":"))
    except Exception:
        return ""


def _page_key(start_epoch, end_epoch, page, page_size, include_total, fingerprint):
    try:
        return f"{int(start_epoch)}:{int(end_epoch)}:{int(page)}:{int(page_size)}:{'t' if include_total else 'f'}:{fingerprint}"
    except Exception:
        return f"{start_epoch}:{end_epoch}:{page}:{page_size}:{include_total}:{fingerprint}"


def _get_retry_pages(state):
    if not isinstance(state, dict):
        return []
    q = state.get("retry_pages")
    if isinstance(q, list):
        return q
    return []


def _set_retry_pages(state, pages):
    if isinstance(state, dict):
        state["retry_pages"] = pages if isinstance(pages, list) else []


def _prune_retry_pages(state, max_retry_pages):
    if not isinstance(state, dict):
        return
    q = _get_retry_pages(state)
    if max_retry_pages is not None and int(max_retry_pages) <= 0:
        _set_retry_pages(state, [])
        return
    if len(q) <= max_retry_pages:
        _set_retry_pages(state, q)
        return

    def _created(w):
        if isinstance(w, dict):
            return int(w.get("created_epoch") or 0)
        return 0

    q_sorted = sorted([w for w in q if isinstance(w, dict)], key=_created)
    _set_retry_pages(state, q_sorted[-max_retry_pages:])


def enqueue_retry_page(
    state,
    start_epoch,
    end_epoch,
    page,
    page_size,
    include_total=False,
    reason=None,
    fingerprint=None,
    apply_max_pages=True,
):
    if not isinstance(state, dict):
        return
    try:
        start_epoch = int(start_epoch)
        end_epoch = int(end_epoch)
        page = int(page)
        page_size = int(page_size)
    except Exception:
        return

    if start_epoch <= 0 or end_epoch <= 0 or start_epoch >= end_epoch:
        return
    if page < 1 or page_size < 1:
        return

    fingerprint = fingerprint or ""
    key = _page_key(start_epoch, end_epoch, page, page_size, include_total, fingerprint)
    now = now_epoch()

    q = _get_retry_pages(state)
    for t in q:
        if isinstance(t, dict) and t.get("key") == key:
            t["last_error"] = str(reason) if reason else t.get("last_error")
            t["last_enqueued_epoch"] = now
            if not apply_max_pages:
                t["apply_max_pages"] = False
            return

    q.append(
        {
            "key": key,
            "start_epoch": start_epoch,
            "end_epoch": end_epoch,
            "page": page,
            "page_size": page_size,
            "include_total": bool(include_total),
            "apply_max_pages": bool(apply_max_pages),
            "fingerprint": fingerprint,
            "attempts": 0,
            "next_retry_epoch": 0,
            "created_epoch": now,
            "last_error": str(reason) if reason else None,
            "last_attempt_epoch": None,
            "last_success_epoch": None,
            "last_enqueued_epoch": now,
        }
    )
    _set_retry_pages(state, q)


def _due_retry_pages(state, max_per_run):
    q = _get_retry_pages(state)
    if not q:
        return []

    now = now_epoch()

    def _next(w):
        if isinstance(w, dict):
            try:
                return int(w.get("next_retry_epoch") or 0)
            except Exception:
                return 0
        return 0

    due = []
    for t in sorted([w for w in q if isinstance(w, dict)], key=_next):
        if len(due) >= max_per_run:
            break
        if _next(t) <= now:
            due.append(t)
    return due


def _mark_retry_page_attempt(task, config, failure_reason=None):
    if not isinstance(task, dict):
        return
    now = now_epoch()
    task["attempts"] = int(task.get("attempts") or 0) + 1
    task["last_attempt_epoch"] = now
    if failure_reason:
        task["last_error"] = str(failure_reason)

    base = _get_int(config, "retry_backoff_seconds", default=60, min_value=5, max_value=3600)
    max_b = _get_int(config, "retry_backoff_max_seconds", default=3600, min_value=60, max_value=86400)
    exp = min(10, int(task["attempts"]))
    delay = min(max_b, base * (2 ** (exp - 1)))
    task["next_retry_epoch"] = now + delay


def _mark_retry_page_success(task):
    if not isinstance(task, dict):
        return
    now = now_epoch()
    task["last_success_epoch"] = now
    task["next_retry_epoch"] = 0


def _remove_retry_page(state, key):
    if not isinstance(state, dict):
        return
    q = _get_retry_pages(state)
    _set_retry_pages(state, [t for t in q if not (isinstance(t, dict) and t.get("key") == key)])


def _try_migrate_retry_windows_to_pages(state, config):
    """Best-effort migration for older 'retry_windows' entries.

    If a window's last_error contains 'failed_pages=[...]', enqueue those pages.
    Otherwise, keep the old window entry untouched.
    """
    if not isinstance(state, dict):
        return

    old = state.get("retry_windows")
    if not isinstance(old, list) or not old:
        return

    page_size = get_page_size(config) if isinstance(config, dict) else DEFAULT_PAGE_SIZE
    fingerprint = _params_fingerprint(config)
    migrated_any = False
    remaining_windows = []

    for w in old:
        if not isinstance(w, dict):
            continue
        w_start = w.get("start_epoch")
        w_end = w.get("end_epoch")
        last_error = str(w.get("last_error") or "")

        failed_pages = None
        if "failed_pages=" in last_error:
            try:
                # expects something like "failed_pages=[4, 2]"
                part = last_error.split("failed_pages=", 1)[1].strip()
                if part.startswith("[") and "]" in part:
                    inside = part.split("]", 1)[0].lstrip("[")
                    nums = []
                    for token in inside.split(","):
                        token = token.strip()
                        if token:
                            nums.append(int(token))
                    failed_pages = nums
            except Exception:
                failed_pages = None

        if failed_pages:
            for p in failed_pages:
                enqueue_retry_page(state, w_start, w_end, page=p, page_size=page_size, include_total=False, reason=last_error, fingerprint=fingerprint)
            migrated_any = True
            continue

        if "initial_call_failed" in last_error:
            enqueue_retry_page(state, w_start, w_end, page=1, page_size=page_size, include_total=True, reason=last_error, fingerprint=fingerprint)
            migrated_any = True
            continue

        remaining_windows.append(w)

    if migrated_any:
        state["retry_windows"] = remaining_windows


# ---------------------------------------------------------------------------
# SOCRadar API v4 — Full Reverse Pagination
# ---------------------------------------------------------------------------

def build_url(config, start_epoch, end_epoch, page, page_size, include_total=False):
    """Build API URL with epoch timestamps."""
    company_id = config["company_id"]

    params = {
        "page": page,
        "limit": page_size,
        "start_date": start_epoch,
        "end_date": end_epoch
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


def fetch_page(config, start_epoch, end_epoch, page, page_size, include_total=False, timeout_seconds=None):
    """Fetch a single page of incidents."""
    url = build_url(config, start_epoch, end_epoch, page, page_size, include_total)
    headers = {
        "API-Key": config["api_key"],
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    return api_request(url, headers, config=config, timeout_seconds=timeout_seconds)


def _empty_fetch_result(page1_ok=False, err_summary=None, failed_pages=None, total_pages=0):
    return {
        "pages": [],
        "had_failures": bool(failed_pages),
        "err_summary": err_summary,
        "failed_pages": failed_pages or [],
        "page1_ok": page1_ok,
        "resume_next_page": None,
        "total_pages": total_pages,
    }


def fetch_all_incidents(
    config,
    start_epoch,
    end_epoch,
    sleep_seconds=0.2,
    apply_max_pages=True,
    page_budget=None,
    resume_from_page=None,
    timeout_seconds=None,
    skip_page1=False,
    known_total_pages=None,
):
    """
    Full reverse pagination for chronological order.

    Returns a result dict. pages is oldest-first; each entry is one page of
    incidents in chronological order within that page.

    When page_budget is set, older pages are fetched from the true last page
    (or resume_from_page) and unattempted pages are returned as resume_next_page.
    max_pages remapping (newest N pages) is only used when apply_max_pages=True.
    """
    log("INFO", f"Fetching | epoch {start_epoch} -> {end_epoch}")

    page_size = get_page_size(config)
    max_pages = get_max_pages(config) if apply_max_pages else None

    if _should_log("DEBUG"):
        debug_filters = {
            "fetch_status": config.get("fetch_status"),
            "min_severity": config.get("min_severity"),
            "alarm_main_types": config.get("alarm_main_types", []),
            "page_size": page_size,
            "max_pages": max_pages,
            "apply_max_pages": apply_max_pages,
            "page_budget": page_budget,
            "resume_from_page": resume_from_page,
            "skip_page1": skip_page1,
        }
        log("DEBUG", f"Fetch settings: {debug_filters}")

    failed_pages = []
    all_pages = {}
    total_pages = 0
    page1_ok = False

    if skip_page1:
        try:
            total_pages = int(known_total_pages or 0)
            start_older = int(resume_from_page or 0)
        except (TypeError, ValueError):
            return _empty_fetch_result(page1_ok=False, err_summary="invalid_resume")
        if total_pages < 2 or start_older < 2:
            return _empty_fetch_result(page1_ok=True, total_pages=total_pages)
        page1_ok = True
    else:
        result = fetch_page(
            config, start_epoch, end_epoch, page=1, page_size=page_size,
            include_total=True, timeout_seconds=timeout_seconds,
        )

        if not result or not result.get("is_success", False):
            log("ERROR", f"Initial call failed: {result}")
            failed_pages.append({"page": 1, "include_total": True})
            return _empty_fetch_result(
                page1_ok=False, err_summary="initial_call_failed", failed_pages=failed_pages
            )

        first_page_data, total_records = _extract_list_and_total(result)
        page1_ok = True

        if total_records == 0 and not first_page_data:
            log("INFO", "No incidents in time range")
            return _empty_fetch_result(page1_ok=True, total_pages=0)

        if total_records == 0:
            total_records = len(first_page_data)

        total_pages = math.ceil(total_records / page_size)

        if max_pages and total_pages > max_pages:
            log("INFO", f"Total: {total_records} records, {total_pages} pages (limiting to {max_pages})")
            total_pages = max_pages
        else:
            log("INFO", f"Total: {total_records} records, {total_pages} pages")

        all_pages[1] = first_page_data
        if total_pages <= 1:
            pages = [list(reversed(first_page_data))]
            log("INFO", f"Collected {len(first_page_data)} incidents (chronological)")
            return {
                "pages": pages,
                "had_failures": False,
                "err_summary": None,
                "failed_pages": [],
                "page1_ok": True,
                "resume_next_page": None,
                "total_pages": total_pages,
            }
        start_older = total_pages

    older_budget = page_budget
    if page_budget is not None and not skip_page1:
        older_budget = page_budget - 1
        if older_budget < 0:
            older_budget = 0

    older_pages = list(range(start_older, 1, -1))
    attempted = []
    for page_num in older_pages:
        if older_budget is not None and len(attempted) >= older_budget:
            break
        log("INFO", f"Fetching page {page_num}/{total_pages}")
        page_result = fetch_page(
            config, start_epoch, end_epoch, page_num, page_size, timeout_seconds=timeout_seconds
        )
        attempted.append(page_num)

        if not page_result or not page_result.get("is_success", False):
            log("ERROR", f"Failed page {page_num}")
            failed_pages.append({"page": page_num, "include_total": False})
        else:
            page_data, _ = _extract_list_and_total(page_result)
            if page_data:
                all_pages[page_num] = page_data

        if sleep_seconds and sleep_seconds > 0:
            time.sleep(sleep_seconds)

    unattempted = [p for p in older_pages if p not in attempted]
    resume_next_page = unattempted[0] if unattempted else None
    if resume_next_page is not None:
        log("INFO", f"Page budget reached; resume at page {resume_next_page}/{total_pages}")

    assemble_from = start_older if skip_page1 else total_pages
    pages = []
    collected = 0
    for page_num in range(assemble_from, 0, -1):
        if page_num in all_pages:
            page_incidents = list(reversed(all_pages[page_num]))
            pages.append(page_incidents)
            collected += len(page_incidents)

    log("INFO", f"Collected {collected} incidents (chronological)")
    had_failures = len(failed_pages) > 0
    err_summary = None
    if had_failures:
        err_summary = f"failed_pages={[f.get('page') for f in failed_pages if isinstance(f, dict)]}"
    return {
        "pages": pages,
        "had_failures": had_failures,
        "err_summary": err_summary,
        "failed_pages": failed_pages,
        "page1_ok": page1_ok,
        "resume_next_page": resume_next_page,
        "total_pages": total_pages,
    }


# ---------------------------------------------------------------------------
# Wazuh Output
# ---------------------------------------------------------------------------

# Wazuh drops / fails oversized events (often ~64KB). Keep emitted JSON well under that.
WAZUH_EMIT_MAX_BYTES = 28000
WAZUH_FIELD_MAX = {
    "alarm_text": 2000,
    "alarm_response": 1500,
    "mitigation": 1000,
    "detection_analysis": 1000,
}


def _clip_str(value, limit):
    if value is None:
        return ""
    s = value if isinstance(value, str) else str(value)
    if len(s) <= limit:
        return s
    if limit <= 0:
        return ""
    # Reserve room for the suffix so the result never exceeds `limit`.
    suffix_template = "... [truncated {} chars]"
    kept = max(0, limit - len(suffix_template.format(len(s))))
    truncated = len(s) - kept
    suffix = suffix_template.format(truncated)
    kept = max(0, limit - len(suffix))
    return (s[:kept] + suffix_template.format(len(s) - kept))[:limit]


def _dumps_emit(output):
    return json.dumps(output, ensure_ascii=False, separators=(",", ":"))


def _bound_emit_payload(output, alarm_id=None):
    """Ensure stdout JSON stays within Wazuh-safe size by shrinking large fields."""
    payload = _dumps_emit(output)
    if len(payload.encode("utf-8")) <= WAZUH_EMIT_MAX_BYTES:
        return payload

    socradar = output.get("socradar")
    if not isinstance(socradar, dict):
        socradar = {}
        output["socradar"] = socradar
    for key in ("alarm_text", "alarm_response", "mitigation", "detection_analysis"):
        if key in socradar:
            socradar[key] = _clip_str(socradar.get(key), min(WAZUH_FIELD_MAX.get(key, 500), 400))

    # Drop bulky optional blocks if still too large
    for key in ("compliance", "assignees", "related_assets", "related_entities", "content"):
        payload = _dumps_emit(output)
        if len(payload.encode("utf-8")) <= WAZUH_EMIT_MAX_BYTES:
            break
        socradar.pop(key, None)

    # Last resort: keep identity fields only
    payload = _dumps_emit(output)
    if len(payload.encode("utf-8")) > WAZUH_EMIT_MAX_BYTES:
        output["socradar"] = {
            "source": socradar.get("source"),
            "alarm_id": socradar.get("alarm_id"),
            "alarm_asset": socradar.get("alarm_asset", ""),
            "risk_level": socradar.get("risk_level", "UNKNOWN"),
            "status": socradar.get("status", ""),
            "generic_title": socradar.get("generic_title", ""),
            "main_type": socradar.get("main_type", ""),
            "sub_type": socradar.get("sub_type", ""),
            "date": socradar.get("date", ""),
            "alarm_text": _clip_str(socradar.get("alarm_text"), 500),
            "truncated": True,
        }
        payload = _dumps_emit(output)

    log(
        "WARN",
        f"Truncated oversized emit payload | alarm_id={alarm_id} "
        f"bytes={len(payload.encode('utf-8'))}",
    )
    return payload


def emit_alert(incident):
    """Print JSON line to stdout for Wazuh ingestion via wodle command.

    Large API fields (e.g. 300KB alarm_text dumps) are truncated for Wazuh.
    """
    if not isinstance(incident, dict):
        return

    risk_level = incident.get("alarm_risk_level", "UNKNOWN")
    if risk_level is None:
        risk_level = "UNKNOWN"

    raw_text = incident.get("alarm_text", "") or ""
    raw_response = incident.get("alarm_response", "") or ""
    if len(raw_text) > WAZUH_FIELD_MAX["alarm_text"] or len(raw_response) > WAZUH_FIELD_MAX["alarm_response"]:
        log(
            "WARN",
            f"Large fields clipped for Wazuh emit | alarm_id={incident.get('alarm_id')} "
            f"alarm_text_len={len(raw_text)} alarm_response_len={len(raw_response)}",
        )

    output = {
        "socradar": {
            "source": "incident_api_v4",
            "alarm_id": incident.get("alarm_id"),
            "alarm_asset": incident.get("alarm_asset", ""),
            "risk_level": str(risk_level).upper(),
            "status": incident.get("status", ""),
            "alarm_text": _clip_str(raw_text, WAZUH_FIELD_MAX["alarm_text"]),
            "alarm_response": _clip_str(raw_response, WAZUH_FIELD_MAX["alarm_response"]),
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
        output["socradar"]["mitigation"] = _clip_str(
            atd.get("alarm_default_mitigation_plan", ""),
            WAZUH_FIELD_MAX["mitigation"],
        )
        output["socradar"]["detection_analysis"] = _clip_str(
            atd.get("alarm_detection_and_analysis", ""),
            WAZUH_FIELD_MAX["detection_analysis"],
        )

        compliance = atd.get("alarm_compliance_list", [])
        if compliance and isinstance(compliance, list):
            output["socradar"]["compliance"] = [
                {
                    "framework": c.get("name", ""),
                    "control": c.get("control_item", ""),
                    "description": _clip_str(c.get("description", ""), 300),
                }
                for c in compliance[:10]
                if isinstance(c, dict)
            ]

    # Technical content (never include content_preview — can be hundreds of KB)
    content = incident.get("content") or {}
    if content and isinstance(content, dict):
        tech = {}
        for key in [
            "compromised_domains", "compromised_emails", "compromised_ips",
            "computer_name", "malware_family", "malware_path", "username",
            "antivirus", "app", "log_date", "source", "source_link", "file", "date",
        ]:
            if content.get(key):
                val = content[key]
                tech[key] = _clip_str(val, 500) if isinstance(val, str) else val

        creds = content.get("credential_details", [])
        if creds and isinstance(creds, list):
            tech["credential_count"] = len(creds)
            tech["credential_urls"] = [
                c.get("URL", "") for c in creds[:20] if isinstance(c, dict) and c.get("URL")
            ]
            tech["credential_users"] = [
                c.get("User", "") for c in creds[:20] if isinstance(c, dict) and c.get("User")
            ]

        if tech:
            output["socradar"]["content"] = tech

    print(_bound_emit_payload(output, alarm_id=incident.get("alarm_id")))


def _enqueue_failed_pages(
    state, config, start_epoch, end_epoch, failed_pages, err_summary, max_retry_pages, apply_max_pages=True
):
    fingerprint = _params_fingerprint(config)
    page_size = get_page_size(config)
    for fp in failed_pages:
        if not isinstance(fp, dict):
            continue
        enqueue_retry_page(
            state,
            start_epoch,
            end_epoch,
            page=fp.get("page"),
            page_size=page_size,
            include_total=bool(fp.get("include_total")),
            reason=err_summary,
            fingerprint=fingerprint,
            apply_max_pages=apply_max_pages,
        )
    _prune_retry_pages(state, max_retry_pages=max_retry_pages)


def _emit_unseen(incidents, seen):
    """Emit alerts for alarm_ids not already in seen. Returns new emit count."""
    new_count = 0
    for incident in incidents:
        if not isinstance(incident, dict):
            continue
        alarm_id = incident.get("alarm_id")
        if alarm_id is not None and alarm_id not in seen:
            if _should_log("DEBUG"):
                log(
                    "DEBUG",
                    "Emitting new incident | "
                    f"alarm_id={alarm_id} "
                    f"risk={incident.get('alarm_risk_level')} "
                    f"status={incident.get('status')} "
                    f"date={incident.get('date')}"
                )
            emit_alert(incident)
            seen[alarm_id] = True
            new_count += 1
    return new_count


def _ingest_time_window(
    config,
    state,
    start_epoch,
    end_epoch,
    sleep_s,
    seen,
    max_retry_pages,
    apply_max_pages=True,
    page_budget=None,
    resume=None,
    timeout_seconds=None,
    kind=None,
):
    """Fetch one time window, enqueue failed pages, emit unseen IDs.

    Emits and persists seen IDs once per page.
    Returns (new_count, fetched_count, page1_ok, resume_out).
    """
    skip_page1 = False
    resume_from_page = None
    known_total_pages = None
    if resume:
        skip_page1 = True
        resume_from_page = resume.get("next_page")
        known_total_pages = resume.get("total_pages")
        start_epoch = int(resume["start_epoch"])
        end_epoch = int(resume["end_epoch"])
        kind = kind or resume.get("kind")

    result = fetch_all_incidents(
        config,
        start_epoch,
        end_epoch,
        sleep_seconds=sleep_s,
        apply_max_pages=apply_max_pages,
        page_budget=page_budget,
        resume_from_page=resume_from_page,
        timeout_seconds=timeout_seconds,
        skip_page1=skip_page1,
        known_total_pages=known_total_pages,
    )
    if result["had_failures"]:
        _enqueue_failed_pages(
            state,
            config,
            start_epoch,
            end_epoch,
            result["failed_pages"],
            result["err_summary"],
            max_retry_pages,
            apply_max_pages=apply_max_pages,
        )
    new_count = 0
    fetched_count = 0
    for page_incidents in result["pages"]:
        fetched_count += len(page_incidents)
        page_new = _emit_unseen(page_incidents, seen)
        new_count += page_new
        if page_new:
            persist_seen(state, seen)

    if result.get("err_summary") == "invalid_resume":
        page1_ok = False
    elif resume:
        page1_ok = True
    else:
        page1_ok = bool(result["page1_ok"])
    resume_out = None
    next_page = result.get("resume_next_page")
    if page1_ok and next_page is not None and int(next_page) >= 2:
        resume_out = {
            "kind": kind,
            "start_epoch": int(start_epoch),
            "end_epoch": int(end_epoch),
            "next_page": int(next_page),
            "total_pages": int(result.get("total_pages") or 0),
            "page_size": get_page_size(config),
            "fingerprint": _params_fingerprint(config),
        }
    return new_count, fetched_count, page1_ok, resume_out


def _window_resume(state, config):
    if not isinstance(state, dict):
        return None
    raw = state.get("window_resume")
    if not isinstance(raw, dict):
        return None
    try:
        next_page = int(raw.get("next_page"))
        start_epoch = int(raw.get("start_epoch"))
        end_epoch = int(raw.get("end_epoch"))
        total_pages = int(raw.get("total_pages"))
        kind = raw.get("kind")
    except (TypeError, ValueError):
        return None
    if next_page < 2 or start_epoch <= 0 or end_epoch <= start_epoch or total_pages < 2:
        return None
    if kind not in ("lookback", "catchup"):
        return None
    saved_fp = raw.get("fingerprint") or ""
    current_fp = _params_fingerprint(config)
    if saved_fp and saved_fp != current_fp:
        log("WARN", "Dropping window_resume (fingerprint changed)")
        return None
    return raw


def _stamp_last_run(state, end_epoch):
    end_epoch = int(end_epoch)
    state["last_run_epoch"] = end_epoch
    state["last_run_iso"] = datetime.fromtimestamp(end_epoch, tz=timezone.utc).isoformat()


def _stamp_last_catchup(state, end_epoch):
    end_epoch = int(end_epoch)
    state["last_catchup_epoch"] = end_epoch
    state["last_catchup_iso"] = datetime.fromtimestamp(end_epoch, tz=timezone.utc).isoformat()


def _apply_resume_result(state, resume, resume_out, page1_ok):
    """Persist or clear window_resume.

    Lookback does not rewrite last_run (stamped when page 1 first succeeded).
    Catch-up stamps last_catchup to the original window end when drain finishes.
    """
    if resume_out:
        state["window_resume"] = resume_out
        return
    state.pop("window_resume", None)
    if not page1_ok or not resume:
        return
    if resume.get("kind") == "catchup":
        _stamp_last_catchup(state, resume.get("end_epoch"))


def _live_incremental(config, state, end_epoch, sleep_s, seen, max_retry_pages, timeout_seconds=None):
    """Fetch last_run → now. Stamp last_run to end_epoch only if page 1 succeeded."""
    last_run = state.get("last_run_epoch")
    if not last_run:
        return 0, 0
    inc_new, inc_fetched, page1_ok, _unused = _ingest_time_window(
        config,
        state,
        int(last_run),
        end_epoch,
        sleep_s,
        seen,
        max_retry_pages,
        apply_max_pages=True,
        timeout_seconds=timeout_seconds,
    )
    if page1_ok:
        _stamp_last_run(state, end_epoch)
    return inc_new, inc_fetched


def _catchup_due(state, end_epoch, overlap, is_first_run):
    if not overlap or is_first_run:
        return False
    last_catchup = state.get("last_catchup_epoch")
    if not last_catchup:
        return True
    try:
        return (end_epoch - int(last_catchup)) >= overlap
    except (TypeError, ValueError):
        return True


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

    # Incremental window: last_run → now. Catch-up (if due) is a second fetch.
    end_epoch = now_epoch()
    overlap = _get_int(config, "fetch_overlap_seconds", default=180, min_value=0, max_value=86400)

    last_run_epoch = state.get("last_run_epoch")
    is_first_run = not bool(last_run_epoch)
    if last_run_epoch:
        start_epoch = int(last_run_epoch)
    else:
        # First run: look back N hours (default 24)
        lookback_hours = config.get("initial_lookback_hours", 24)
        start_epoch = end_epoch - (lookback_hours * 3600)

    log("INFO",
        f"Starting v{VERSION} | incremental {start_epoch} -> {end_epoch} | "
        f"{datetime.fromtimestamp(start_epoch, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} -> "
        f"{datetime.fromtimestamp(end_epoch, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}")

    # Deduplicate against seen alarm IDs (dict preserves insertion order)
    seen = dict.fromkeys(state.get("seen_alarm_ids", []))
    new_count = 0
    total_fetched = 0

    # Retry queue settings (support older key names as fallback)
    max_retry_pages = _get_int(
        config,
        "max_retry_pages",
        default=_get_int(config, "max_retry_windows", default=25, min_value=0, max_value=200),
        min_value=0,
        max_value=200,
    )
    max_retry_pages_per_run = _get_int(
        config,
        "max_retry_pages_per_run",
        default=_get_int(config, "max_retry_windows_per_run", default=1, min_value=0, max_value=20),
        min_value=0,
        max_value=50,
    )

    page_sleep_seconds = _get_float(config, "page_sleep_seconds", default=2, min_value=0.0, max_value=10.0)
    lookback_page_sleep_seconds = _get_float(
        config,
        "lookback_page_sleep_seconds",
        default=page_sleep_seconds,
        min_value=0.0,
        max_value=10.0,
    )
    page_budget = _get_int(config, "max_catchup_pages", default=15, min_value=1, max_value=200)
    catchup_http_timeout = _get_int(
        config, "catchup_http_timeout_seconds", default=15, min_value=5, max_value=600
    )

    _try_migrate_retry_windows_to_pages(state, config)
    _prune_retry_pages(state, max_retry_pages=max_retry_pages)

    try:
        # 1) Retry queued failed pages first (bounded), to heal gaps cheaply.
        used_120s_retry = False
        for t in _due_retry_pages(state, max_per_run=max_retry_pages_per_run):
            t_key = t.get("key")
            t_start = t.get("start_epoch")
            t_end = t.get("end_epoch")
            t_page = t.get("page")
            t_page_size = t.get("page_size")
            t_include_total = bool(t.get("include_total"))
            apply_cap = t.get("apply_max_pages", True)
            retry_timeout = None if apply_cap else catchup_http_timeout
            if apply_cap:
                used_120s_retry = True
            log("INFO", f"Retry page {t_page} | key={t_key}")

            page_result = fetch_page(
                config,
                t_start,
                t_end,
                page=t_page,
                page_size=t_page_size,
                include_total=t_include_total,
                timeout_seconds=retry_timeout,
            )
            if not page_result or not page_result.get("is_success", False):
                _mark_retry_page_attempt(t, config=config, failure_reason="retry_page_failed")
                log("WARN", f"Retry page still failing | key={t_key} | next_retry_epoch={t.get('next_retry_epoch')}")
                continue

            page_data, total_records = _extract_list_and_total(page_result)
            # Emit oldest-first within this page; persist once if anything new.
            page_new = _emit_unseen(list(reversed(page_data or [])), seen)
            if page_new:
                persist_seen(state, seen)
            new_count += page_new
            total_fetched += len(page_data or [])

            # If this was the initial include_total request (page 1), expand into per-page
            # tasks so we can backfill the whole window incrementally without a single
            # long run.
            if t_include_total:
                if total_records == 0:
                    total_records = len(page_data or [])
                total_pages = 1
                try:
                    total_pages = int(math.ceil(float(total_records) / float(t_page_size or 1)))
                except Exception:
                    total_pages = 1

                max_pages = get_max_pages(config) if apply_cap else None
                if max_pages and total_pages > max_pages:
                    total_pages = max_pages

                fingerprint = t.get("fingerprint") or _params_fingerprint(config)
                # Enqueue older pages first (highest page number is oldest).
                for page_num in range(total_pages, 1, -1):
                    enqueue_retry_page(
                        state,
                        t_start,
                        t_end,
                        page=page_num,
                        page_size=t_page_size,
                        include_total=False,
                        reason="expanded_from_include_total",
                        fingerprint=fingerprint,
                        apply_max_pages=apply_cap,
                    )
                _prune_retry_pages(state, max_retry_pages=max_retry_pages)

            _mark_retry_page_success(t)
            _remove_retry_page(state, key=t_key)

        # 2) Drain an in-progress uncapped window, or start lookback / incremental.
        resume = _window_resume(state, config)
        if state.get("window_resume") and resume is None:
            state.pop("window_resume", None)

        if used_120s_retry:
            log("INFO", "Skipping budgeted uncapped window (120s incremental retry already ran)")
            live_new, live_fetched = _live_incremental(
                config, state, end_epoch, page_sleep_seconds, seen, max_retry_pages
            )
            new_count += live_new
            total_fetched += live_fetched
            persist_seen(state, seen)
        elif resume:
            log(
                "INFO",
                f"Resume {resume.get('kind')} | page {resume.get('next_page')}/"
                f"{resume.get('total_pages')} | {resume.get('start_epoch')} -> {resume.get('end_epoch')}",
            )
            sleep_s = lookback_page_sleep_seconds if resume.get("kind") == "lookback" else page_sleep_seconds
            r_new, r_fetched, page1_ok, resume_out = _ingest_time_window(
                config,
                state,
                resume.get("start_epoch"),
                resume.get("end_epoch"),
                sleep_s,
                seen,
                max_retry_pages,
                apply_max_pages=False,
                page_budget=page_budget,
                resume=resume,
                timeout_seconds=catchup_http_timeout,
                kind=resume.get("kind"),
            )
            new_count += r_new
            total_fetched += r_fetched
            _apply_resume_result(state, resume, resume_out, page1_ok)
            persist_seen(state, seen)
            live_new, live_fetched = _live_incremental(
                config,
                state,
                end_epoch,
                page_sleep_seconds,
                seen,
                max_retry_pages,
                timeout_seconds=catchup_http_timeout,
            )
            new_count += live_new
            total_fetched += live_fetched
            persist_seen(state, seen)
        elif is_first_run:
            sleep_s = lookback_page_sleep_seconds
            inc_new, inc_fetched, page1_ok, resume_out = _ingest_time_window(
                config,
                state,
                start_epoch,
                end_epoch,
                sleep_s,
                seen,
                max_retry_pages,
                apply_max_pages=False,
                page_budget=page_budget,
                timeout_seconds=catchup_http_timeout,
                kind="lookback",
            )
            new_count += inc_new
            total_fetched += inc_fetched
            if page1_ok:
                _stamp_last_run(state, end_epoch)
            if resume_out:
                state["window_resume"] = resume_out
            persist_seen(state, seen)
        else:
            inc_new, inc_fetched, page1_ok, _resume_unused = _ingest_time_window(
                config, state, start_epoch, end_epoch, page_sleep_seconds, seen, max_retry_pages
            )
            new_count += inc_new
            total_fetched += inc_fetched
            if page1_ok:
                _stamp_last_run(state, end_epoch)
            persist_seen(state, seen)

            # 3) Periodic catch-up: now − overlap → now (same process; not every tick)
            if _catchup_due(state, end_epoch, overlap, is_first_run) and not state.get("window_resume"):
                catchup_start = end_epoch - overlap
                last_catchup = state.get("last_catchup_epoch")
                log(
                    "INFO",
                    f"Catch-up fetch | last={last_catchup} overlap_seconds={overlap} "
                    f"{catchup_start} -> {end_epoch}",
                )
                cu_new, cu_fetched, cu_page1_ok, resume_out = _ingest_time_window(
                    config,
                    state,
                    catchup_start,
                    end_epoch,
                    page_sleep_seconds,
                    seen,
                    max_retry_pages,
                    apply_max_pages=False,
                    page_budget=page_budget,
                    timeout_seconds=catchup_http_timeout,
                    kind="catchup",
                )
                new_count += cu_new
                total_fetched += cu_fetched
                if resume_out:
                    state["window_resume"] = resume_out
                elif cu_page1_ok:
                    _stamp_last_catchup(state, end_epoch)
                persist_seen(state, seen)

        state["last_fetch_new"] = new_count
        state["last_fetch_total"] = total_fetched
        persist_seen(state, seen)

        q_len = len(_get_retry_pages(state))
        log(
            "INFO",
            f"Done | New: {new_count}, Total: {total_fetched}, "
            f"Cache: {len(state.get('seen_alarm_ids') or [])}, RetryQueue: {q_len}",
        )
    finally:
        # Exception-path flush only. Does not run on modulesd SIGKILL.
        persist_seen(state, seen)


if __name__ == "__main__":
    main()
