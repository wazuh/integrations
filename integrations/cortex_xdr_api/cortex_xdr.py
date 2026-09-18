#!/var/ossec/framework/python/bin/python3
"""Cortex XDR incident collector for Wazuh.

Polls Cortex XDR for incidents modified since the previous run and appends one
NDJSON event per incident to a log file that Wazuh tails with
<log_format>json</log_format>. There is no custom decoder: the built-in json
decoder flattens each line into cortex.* fields, which is what the ruleset
matches on.

Endpoint (Standard API key auth):
  POST {base}/incidents/get_incidents/

Tested against Cortex XDR 5.0 and Wazuh 4.14.7.
"""

import argparse
import fcntl
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

INTEGRATION_NAME = "cortex_xdr"
COLLECTOR_VERSION = "1.0"

# Everything under /var/ossec, in the directories Wazuh already uses for each
# purpose, matching what the aws wodle does with its state database.
WODLE_DIR = "/var/ossec/wodles/cortex_xdr"
DEFAULT_CONFIG = WODLE_DIR + "/config.json"
DEFAULT_STATE_FILE = WODLE_DIR + "/state.json"
DEFAULT_LOG_FILE = "/var/ossec/logs/cortex_xdr.log"
DEFAULT_LOCK_FILE = "/var/ossec/var/run/cortex_xdr.lock"
STATE_VERSION = 1

# The 5.x docs and the tenant console give /XDR/public/v1; long-standing field
# clients use /public_api/v1. Tenants answer on one or the other, so try both
# and cache the winner in the state file rather than making it a support call.
BASE_PATHS = ["XDR/public/v1", "public_api/v1"]

# Documented per-request cap for get_incidents. Asking for more is rejected.
PAGE_SIZE = 100
# (connect, read). Cortex is fine normally but slow under a large backlog.
TIMEOUT = (10, 60)
DEFAULT_LOOKBACK_HOURS = 24
# A first run with no state would otherwise pull the entire incident history.
MAX_LOOKBACK_HOURS = 24 * 30

VALID_SEVERITIES = ("informational", "low", "medium", "high", "critical")

log = logging.getLogger(INTEGRATION_NAME)


def load_config(path):
    with open(path, encoding="utf-8") as fh:
        cfg = json.load(fh)

    for key in ("fqdn", "api_key_id", "api_key"):
        if not cfg.get(key):
            raise SystemExit("config: '{}' is required".format(key))

    # Accept a full URL and reduce it to the host, since the console shows one.
    cfg["fqdn"] = cfg["fqdn"].replace("https://", "").replace("http://", "")
    cfg["fqdn"] = cfg["fqdn"].split("/")[0].strip().rstrip("/")
    cfg["api_key_id"] = str(cfg["api_key_id"])

    cfg.setdefault("base_path", None)
    cfg.setdefault("log_file", DEFAULT_LOG_FILE)
    cfg.setdefault("state_file", DEFAULT_STATE_FILE)
    cfg.setdefault("lock_file", DEFAULT_LOCK_FILE)
    cfg.setdefault("page_size", PAGE_SIZE)
    cfg.setdefault("severities", [])

    hours = cfg.get("lookback_hours", DEFAULT_LOOKBACK_HOURS)
    try:
        hours = int(hours)
    except (TypeError, ValueError):
        raise SystemExit("config: 'lookback_hours' must be a number")
    cfg["lookback_hours"] = max(1, min(hours, MAX_LOOKBACK_HOURS))

    cfg["page_size"] = max(1, min(int(cfg["page_size"]), PAGE_SIZE))

    bad = [s for s in cfg["severities"] if s not in VALID_SEVERITIES]
    if bad:
        raise SystemExit("config: unknown severities {}; valid values are {}".format(
            bad, list(VALID_SEVERITIES)))
    return cfg


def build_session():
    session = requests.Session()
    # Retry the transient cases only. A 4xx here means the key or the filter is
    # wrong and retrying just burns API quota.
    retry = Retry(total=3, backoff_factor=1.5,
                  status_forcelist=(429, 500, 502, 503, 504),
                  allowed_methods=frozenset(["POST"]),
                  raise_on_status=False)
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


def headers(cfg):
    """Standard (not Advanced) API key auth: the key travels as-is."""
    return {
        "Authorization": cfg["api_key"],
        "x-xdr-auth-id": cfg["api_key_id"],
        "Content-Type": "application/json",
    }


def api_call(session, cfg, endpoint, request_data):
    """POST to the tenant, resolving the base path on first use.

    ponytail: the fallback exists because the docs and the field disagree on
    the prefix. Once state records a working one, later runs try it first and
    this costs nothing.
    """
    bases = [cfg["base_path"]] if cfg["base_path"] else BASE_PATHS
    tried = []
    for base in bases:
        url = "https://{}/{}/{}/".format(cfg["fqdn"], base, endpoint)
        response = session.post(url, headers=headers(cfg),
                                json={"request_data": request_data}, timeout=TIMEOUT)
        if response.status_code == 404:
            # Wrong prefix for this tenant. A real missing incident is not a 404
            # here; get_incidents answers 200 with an empty list.
            tried.append(url)
            log.debug("404 on %s, trying the next base path", url)
            continue
        if response.status_code in (401, 403):
            raise SystemExit(
                "Cortex XDR rejected the credentials ({}). Check the API key, that "
                "x-xdr-auth-id is {}, and that the key's role can read incidents."
                .format(response.status_code, cfg["api_key_id"]))
        response.raise_for_status()
        cfg["base_path"] = base
        return response.json()

    raise SystemExit("No Cortex XDR base path answered; tried: {}".format(", ".join(tried)))


def fetch_incidents(session, cfg, since_ms):
    """Every incident modified at or after since_ms, oldest first.

    Sorted ascending so paging stays stable while the watermark advances: a new
    incident arriving mid-run lands at the end, not in a page already read.
    """
    filters = [{"field": "modification_time", "operator": "gte", "value": since_ms}]
    if cfg["severities"]:
        filters.append({"field": "severity", "operator": "in", "value": cfg["severities"]})

    incidents, offset = [], 0
    while True:
        reply = api_call(session, cfg, "incidents/get_incidents", {
            "filters": filters,
            "search_from": offset,
            "search_to": offset + cfg["page_size"],
            "sort": {"field": "modification_time", "keyword": "asc"},
        }).get("reply", {})

        page = reply.get("incidents") or []
        incidents.extend(page)
        total = reply.get("total_count")
        offset += len(page)
        log.debug("fetched %d incidents (%d/%s)", len(page), offset, total)

        # Stop on a short page. Trusting total_count alone would loop forever if
        # the tenant reports a count it will not actually serve.
        if len(page) < cfg["page_size"]:
            break
        if isinstance(total, int) and offset >= total:
            break
    return incidents


def epoch_ms_to_iso(value):
    if not isinstance(value, (int, float)) or value <= 0:
        return None
    return datetime.fromtimestamp(value / 1000, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.") + "{:03d}Z".format(int(value) % 1000)


def prune(value):
    """Drop None and empty containers.

    analysisd stringifies decoded JSON, and a null the index mapping rejects
    discards the whole alert, so an absent field beats an empty one.
    """
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            item = prune(item)
            if item is not None and item != {} and item != []:
                out[key] = item
        return out
    if isinstance(value, list):
        return [i for i in (prune(v) for v in value) if i is not None]
    if isinstance(value, str) and not value.strip():
        return None
    return value


def build_event(incident, collected_at):
    """One incident becomes one Wazuh event under the cortex.* namespace."""
    body = {
        "event_type": "incident",
        "incident_id": str(incident.get("incident_id") or ""),
        "incident_name": incident.get("incident_name"),
        "description": incident.get("description"),
        "status": incident.get("status"),
        "severity": incident.get("severity"),
        "creation_time": incident.get("creation_time"),
        "creation_time_iso": epoch_ms_to_iso(incident.get("creation_time")),
        "modification_time": incident.get("modification_time"),
        "modification_time_iso": epoch_ms_to_iso(incident.get("modification_time")),
        "assigned_user_mail": incident.get("assigned_user_mail"),
        "assigned_user_pretty_name": incident.get("assigned_user_pretty_name"),
        "alert_count": incident.get("alert_count"),
        "low_severity_alert_count": incident.get("low_severity_alert_count"),
        "med_severity_alert_count": incident.get("med_severity_alert_count"),
        "high_severity_alert_count": incident.get("high_severity_alert_count"),
        "host_count": incident.get("host_count"),
        "user_count": incident.get("user_count"),
        "alert_sources": incident.get("alert_sources"),
        "xdr_url": incident.get("xdr_url"),
        "resolve_comment": incident.get("resolve_comment"),
        # "resolved" is the common rule predicate and is tedious to express as a
        # prefix match across the seven resolved_* status values.
        "is_resolved": str(bool(str(incident.get("status") or "").startswith("resolved"))).lower(),
    }
    return prune({
        "integration": INTEGRATION_NAME,
        "collector_version": COLLECTOR_VERSION,
        "collected_at": collected_at,
        "cortex": body,
    })


def load_state(path):
    try:
        with open(path, encoding="utf-8") as fh:
            state = json.load(fh)
    except FileNotFoundError:
        return {}
    except (ValueError, OSError) as exc:
        log.warning("state file unusable (%s); starting from the lookback window", exc)
        return {}
    if state.get("version") != STATE_VERSION:
        log.warning("state version %s is not %s; starting fresh", state.get("version"), STATE_VERSION)
        return {}
    return state


def save_state(path, watermark, boundary_ids, base_path):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({
            "version": STATE_VERSION,
            "last_modification_time": watermark,
            # Ids sitting exactly on the watermark. The next query is inclusive
            # (gte), so without these every run re-emits the newest incidents.
            "boundary_ids": sorted(boundary_ids),
            "base_path": base_path,
        }, fh)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def advance_watermark(incidents, previous_watermark):
    """Return the new watermark and the incident ids sitting on it."""
    times = [i.get("modification_time") for i in incidents
             if isinstance(i.get("modification_time"), int)]
    watermark = max(times) if times else previous_watermark
    boundary = {str(i.get("incident_id")) for i in incidents
                if i.get("modification_time") == watermark}
    return watermark, boundary


def drop_already_seen(incidents, watermark, boundary_ids):
    """Remove the incidents the previous run already emitted at the watermark."""
    if not boundary_ids:
        return incidents
    return [i for i in incidents
            if not (i.get("modification_time") == watermark
                    and str(i.get("incident_id")) in boundary_ids)]


def write_events(path, events):
    """Append NDJSON and fsync, so a crash cannot leave logcollector a torn line."""
    if not events:
        return
    with open(path, "a", encoding="utf-8") as fh:
        for event in events:
            fh.write(json.dumps(event, separators=(",", ":")) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def acquire_lock(path):
    fh = open(path, "w", encoding="utf-8")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        raise SystemExit("Another collector run holds the lock; exiting.")
    fh.write(str(os.getpid()))
    fh.flush()
    return fh


def selftest():
    """The boundary and shaping logic, which is the only part worth a check."""
    incidents = [
        {"incident_id": 1, "modification_time": 100, "severity": "low", "status": "new"},
        {"incident_id": 2, "modification_time": 300, "severity": "high", "status": "new"},
        {"incident_id": 3, "modification_time": 300, "severity": "high",
         "status": "resolved_false_positive"},
    ]

    watermark, boundary = advance_watermark(incidents, 0)
    assert watermark == 300, watermark
    assert boundary == {"2", "3"}, boundary

    # The next poll is inclusive, so the two ids on the watermark come back and
    # must not be emitted twice; a genuinely newer one still gets through.
    again = drop_already_seen(incidents, watermark, boundary)
    assert [i["incident_id"] for i in again] == [1], again
    fresh = incidents + [{"incident_id": 4, "modification_time": 400}]
    assert 4 in [i["incident_id"] for i in drop_already_seen(fresh, watermark, boundary)]

    # An empty page must not rewind the watermark.
    assert advance_watermark([], 300) == (300, set())

    assert prune({"a": None, "b": "", "c": 0, "d": {"e": None}, "f": [None]}) == {"c": 0}
    assert epoch_ms_to_iso(1745080427000) == "2025-04-19T16:33:47.000Z"
    assert epoch_ms_to_iso(None) is None and epoch_ms_to_iso(0) is None

    event = build_event(incidents[2], "2026-09-18T00:00:00Z")
    assert event["cortex"]["is_resolved"] == "true"
    assert event["integration"] == "cortex_xdr"
    assert build_event(incidents[1], "x")["cortex"]["is_resolved"] == "false"
    # alert_count is absent here and must be dropped, not sent as null.
    assert "alert_count" not in event["cortex"]

    print("selftest ok")


def main():
    os.umask(0o027)

    parser = argparse.ArgumentParser(description="Cortex XDR incident collector for Wazuh")
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG)
    parser.add_argument("--stdout", action="store_true",
                        help="Print events instead of writing the log file")
    parser.add_argument("--no-state", action="store_true",
                        help="Do not read or write state; every run uses the lookback window")
    parser.add_argument("--since-hours", type=int,
                        help="Ignore the watermark and look back this many hours")
    parser.add_argument("--selftest", action="store_true", help="Run internal checks and exit")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(stream=sys.stderr,
                        level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if args.selftest:
        selftest()
        return 0

    cfg = load_config(args.config)
    state = {} if args.no_state else load_state(cfg["state_file"])
    if state.get("base_path"):
        cfg["base_path"] = state["base_path"]

    now = datetime.now(timezone.utc)
    if args.since_hours:
        since_ms = int((now - timedelta(hours=args.since_hours)).timestamp() * 1000)
        boundary_ids = set()
    else:
        since_ms = state.get("last_modification_time")
        boundary_ids = set(state.get("boundary_ids") or [])
        if not since_ms:
            since_ms = int((now - timedelta(hours=cfg["lookback_hours"])).timestamp() * 1000)
            boundary_ids = set()
            log.info("no watermark; looking back %d hours", cfg["lookback_hours"])

    lock = None if args.stdout else acquire_lock(cfg["lock_file"])
    session = build_session()
    try:
        incidents = fetch_incidents(session, cfg, since_ms)
        log.info("%d incidents modified since %s", len(incidents), epoch_ms_to_iso(since_ms))

        new_incidents = drop_already_seen(incidents, since_ms, boundary_ids)
        if len(new_incidents) != len(incidents):
            log.debug("skipped %d already emitted at the watermark",
                      len(incidents) - len(new_incidents))

        collected_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        events = [build_event(i, collected_at) for i in new_incidents]
        if args.stdout:
            for event in events:
                print(json.dumps(event, separators=(",", ":")))
        else:
            write_events(cfg["log_file"], events)
        log.info("emitted %d events", len(events))

        # Written after emitting on purpose: a crash here repeats incidents on
        # the next run rather than losing them.
        if not args.no_state and not args.since_hours:
            watermark, boundary = advance_watermark(incidents, since_ms)
            if not incidents:
                boundary = boundary_ids
            save_state(cfg["state_file"], watermark, boundary, cfg["base_path"])
    finally:
        session.close()
        if lock:
            lock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
