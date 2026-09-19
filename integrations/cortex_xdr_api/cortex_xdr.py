#!/var/ossec/framework/python/bin/python3
"""Cortex XDR collector for Wazuh.

Polls the Cortex XDR API on an interval and appends NDJSON to a log file Wazuh
tails with <log_format>json</log_format>. No custom decoder: the built-in json
decoder flattens each line into the cortex.* fields the ruleset matches.

Five data sets, each with its own watermark, all opt-in through "collect":

  incidents         aggregated analyst-facing cases
  alerts            individual detections, with process and MITRE context
  endpoints         agent inventory, health and isolation state
  audit_management  console administrator actions
  audit_agents      per-agent policy, install and scan reports (high volume)

Endpoints, filter fields and the 100-record page cap were all confirmed against
a live 5.0 tenant; see README.md.

Tested against Cortex XDR 5.0 and Wazuh 4.14.7.
"""

import argparse
import fcntl
import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

INTEGRATION_NAME = "cortex_xdr"
COLLECTOR_VERSION = "2.0"

WODLE_DIR = "/var/ossec/wodles/cortex_xdr"
DEFAULT_CONFIG = WODLE_DIR + "/config.json"
DEFAULT_STATE_FILE = WODLE_DIR + "/state.json"
DEFAULT_LOG_FILE = "/var/ossec/logs/cortex_xdr.log"
DEFAULT_LOCK_FILE = "/var/ossec/var/run/cortex_xdr.lock"
STATE_VERSION = 2

# Docs and the console say /XDR/public, but a 5.0 tenant serves on /public_api
# and answers the documented prefix with a 500.
BASE_PREFIXES = ["public_api", "XDR/public"]

# Hard API limit: "0 < search_size <= 100".
PAGE_SIZE = 100
TIMEOUT = (10, 90)
DEFAULT_LOOKBACK_HOURS = 24
MAX_LOOKBACK_HOURS = 24 * 30

# analysisd drops anything past 65535 bytes. Leave room for the queue framing.
MAX_EVENT_BYTES = 60000

VALID_SEVERITIES = ("informational", "low", "medium", "high", "critical")

# Cortex spells audit severity differently from incident severity.
AUDIT_SEVERITY = {
    "SEV_010_INFO": "informational", "SEV_020_LOW": "low", "SEV_030_MEDIUM": "medium",
    "SEV_040_HIGH": "high", "SEV_050_CRITICAL": "critical",
}

# Per data set: the API path, the filter field used for incremental polling, the
# field in each record holding that time, the key the records arrive under, the
# fields identifying a record, and which fields are epoch milliseconds.
COLLECTORS = {
    "incidents": {
        "version": "v1", "endpoint": "incidents/get_incidents",
        "filter_field": "modification_time", "record_time": "modification_time",
        "reply_key": "incidents", "id_fields": ("incident_id",), "event_type": "incident",
        "time_fields": ("creation_time", "modification_time"),
    },
    "alerts": {
        "version": "v2", "endpoint": "alerts/get_alerts_multi_events",
        "filter_field": "creation_time", "record_time": "detection_timestamp",
        "reply_key": "alerts", "id_fields": ("alert_id",), "event_type": "alert",
        "time_fields": ("detection_timestamp", "local_insert_ts", "event_timestamp",
                        "agent_host_boot_time", "causality_actor_process_execution_time"),
        # The per-alert raw event list is unbounded and would blow the size cap.
        "drop_fields": ("events",),
    },
    "endpoints": {
        "version": "v1", "endpoint": "endpoints/get_endpoint",
        "filter_field": "last_seen", "record_time": "last_seen",
        "reply_key": "endpoints", "id_fields": ("endpoint_id",), "event_type": "endpoint",
        "time_fields": ("first_seen", "last_seen", "install_date",
                        "content_release_timestamp", "last_content_update_time"),
        # last_seen advances on every agent heartbeat, so without a diff every
        # endpoint looks changed on every poll: 374 events per run on a 700-agent
        # tenant. Only a change in one of these fields is worth an alert.
        "track_fields": ("endpoint_status", "operational_status", "content_status",
                         "is_isolated", "scan_status", "endpoint_version",
                         "content_version", "os_version", "ip", "public_ip",
                         "group_name", "assigned_prevention_policy",
                         "assigned_extensions_policy", "endpoint_name"),
    },
    "audit_management": {
        "version": "v1", "endpoint": "audits/management_logs",
        "filter_field": "timestamp", "record_time": "AUDIT_INSERT_TIME",
        "reply_key": "data", "id_fields": ("AUDIT_ID",), "event_type": "audit_management",
        "time_fields": ("AUDIT_INSERT_TIME",),
    },
    "audit_agents": {
        "version": "v1", "endpoint": "audits/agents_reports",
        "filter_field": "timestamp", "record_time": "TIMESTAMP",
        "reply_key": "data",
        # No unique id is returned, so a record is identified by its whole shape.
        "id_fields": (), "event_type": "audit_agent",
        "time_fields": ("TIMESTAMP", "RECEIVEDTIME"),
    },
}

# audit_agents is left out: 175k records on a modest tenant, and it is agent
# telemetry rather than security signal. Enable it deliberately.
DEFAULT_COLLECT = ["incidents", "alerts", "endpoints", "audit_management"]

log = logging.getLogger(INTEGRATION_NAME)


def load_config(path):
    with open(path, encoding="utf-8") as fh:
        cfg = json.load(fh)

    for key in ("fqdn", "api_key_id", "api_key"):
        if not cfg.get(key):
            raise SystemExit("config: '{}' is required".format(key))

    cfg["fqdn"] = cfg["fqdn"].replace("https://", "").replace("http://", "")
    cfg["fqdn"] = cfg["fqdn"].split("/")[0].strip().rstrip("/")
    cfg["api_key_id"] = str(cfg["api_key_id"])

    cfg.setdefault("base_prefix", None)
    cfg.setdefault("log_file", DEFAULT_LOG_FILE)
    cfg.setdefault("state_file", DEFAULT_STATE_FILE)
    cfg.setdefault("lock_file", DEFAULT_LOCK_FILE)
    cfg.setdefault("page_size", PAGE_SIZE)
    cfg.setdefault("severities", [])
    cfg.setdefault("collect", list(DEFAULT_COLLECT))
    cfg.setdefault("lookback_hours_by_collector", {})

    unknown = [c for c in cfg["collect"] if c not in COLLECTORS]
    if unknown:
        raise SystemExit("config: unknown collect entries {}; valid values are {}".format(
            unknown, sorted(COLLECTORS)))
    if not cfg["collect"]:
        raise SystemExit("config: 'collect' is empty, nothing to do")

    cfg["lookback_hours"] = _bounded_hours(cfg.get("lookback_hours", DEFAULT_LOOKBACK_HOURS))
    for name, hours in cfg["lookback_hours_by_collector"].items():
        if name not in COLLECTORS:
            raise SystemExit("config: unknown collector '{}' in lookback_hours_by_collector".format(name))
        cfg["lookback_hours_by_collector"][name] = _bounded_hours(hours)

    cfg["page_size"] = max(1, min(int(cfg["page_size"]), PAGE_SIZE))

    bad = [s for s in cfg["severities"] if s not in VALID_SEVERITIES]
    if bad:
        raise SystemExit("config: unknown severities {}; valid values are {}".format(
            bad, list(VALID_SEVERITIES)))
    return cfg


def _bounded_hours(value):
    try:
        return max(1, min(int(value), MAX_LOOKBACK_HOURS))
    except (TypeError, ValueError):
        raise SystemExit("config: lookback hours must be a number, got {!r}".format(value))


def build_session():
    # Transient statuses only; a 4xx means the key or filter is wrong.
    retry = Retry(total=3, backoff_factor=1.5,
                  status_forcelist=(429, 500, 502, 503, 504),
                  allowed_methods=frozenset(["POST"]),
                  raise_on_status=False)
    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


def headers(cfg):
    """Standard API key auth: the key travels as-is."""
    return {
        "Authorization": cfg["api_key"],
        "x-xdr-auth-id": cfg["api_key_id"],
        "Content-Type": "application/json",
    }


def credentials_error(status, cfg):
    return SystemExit(
        "Cortex XDR rejected the credentials ({}). Check the API key, that "
        "x-xdr-auth-id is {}, and that the key's role can read this data."
        .format(status, cfg["api_key_id"]))


def api_call(session, cfg, version, endpoint, request_data):
    if not cfg["base_prefix"]:
        cfg["base_prefix"] = resolve_base_prefix(cfg)

    url = "https://{}/{}/{}/{}/".format(cfg["fqdn"], cfg["base_prefix"], version, endpoint)
    response = session.post(url, headers=headers(cfg),
                            json={"request_data": request_data}, timeout=TIMEOUT)
    if response.status_code in (401, 403):
        raise credentials_error(response.status_code, cfg)
    response.raise_for_status()
    return response.json()


def resolve_base_prefix(cfg):
    """Find the prefix this tenant answers on, and cache it in state.

    A wrong prefix returns 500, not 404, so any non-200 means try the next one.
    Runs outside the retrying session: retrying a 500 that only means "wrong
    prefix" would burn three backoffs per candidate.
    """
    probe = {"request_data": {"search_from": 0, "search_to": 1}}
    tried = []
    for prefix in BASE_PREFIXES:
        url = "https://{}/{}/v1/incidents/get_incidents/".format(cfg["fqdn"], prefix)
        try:
            response = requests.post(url, headers=headers(cfg), json=probe, timeout=TIMEOUT)
        except requests.RequestException as exc:
            tried.append("{} ({})".format(prefix, exc.__class__.__name__))
            continue
        if response.status_code in (401, 403):
            raise credentials_error(response.status_code, cfg)
        if response.status_code == 200:
            log.info("resolved Cortex XDR base prefix: %s", prefix)
            return prefix
        tried.append("{} (HTTP {})".format(prefix, response.status_code))
    raise SystemExit("No Cortex XDR base prefix answered on {}; tried: {}".format(
        cfg["fqdn"], ", ".join(tried)))


def fetch_records(session, cfg, name, since_ms):
    """Every record at or after since_ms, oldest first so paging stays stable."""
    spec = COLLECTORS[name]
    filters = [{"field": spec["filter_field"], "operator": "gte", "value": since_ms}]
    # Severity filtering only makes sense where the API exposes that field.
    if cfg["severities"] and name in ("incidents", "alerts"):
        filters.append({"field": "severity", "operator": "in", "value": cfg["severities"]})

    records, offset = [], 0
    while True:
        reply = api_call(session, cfg, spec["version"], spec["endpoint"], {
            "filters": filters,
            "search_from": offset,
            "search_to": offset + cfg["page_size"],
            "sort": {"field": spec["filter_field"], "keyword": "asc"},
        }).get("reply", {})

        if isinstance(reply, list):
            page, total = reply, len(reply)
        else:
            page = reply.get(spec["reply_key"]) or []
            total = reply.get("total_count")
        records.extend(page)
        offset += len(page)
        log.debug("%s: fetched %d (%d/%s)", name, len(page), offset, total)

        # Short page ends it; trusting total_count alone can loop forever.
        if len(page) < cfg["page_size"]:
            break
        if isinstance(total, int) and offset >= total:
            break
    return records


def epoch_ms_to_iso(value):
    if isinstance(value, str):
        try:
            value = float(value)
        except ValueError:
            return None
    if not isinstance(value, (int, float)) or value <= 0:
        return None
    value = int(value)
    return datetime.fromtimestamp(value / 1000, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.") + "{:03d}Z".format(value % 1000)


def normalize(value):
    """Drop nulls and empties, and unwrap single-element lists.

    Cortex wraps many scalars in one-element lists (ip, user_name, image paths).
    Unwrapping keeps rules and dashboard aggregations readable. analysisd also
    discards an alert whose value the index mapping rejects, so an absent field
    beats an empty one.
    """
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            item = normalize(item)
            if item is not None and item != {} and item != []:
                out[key] = item
        return out
    if isinstance(value, list):
        items = [i for i in (normalize(v) for v in value) if i is not None]
        if not items:
            return None
        return items[0] if len(items) == 1 else items
    if isinstance(value, str) and not value.strip():
        return None
    return value


def record_id(spec, record):
    if spec["id_fields"]:
        return "|".join(str(record.get(f, "")) for f in spec["id_fields"])
    # No id from the API, so identity is the record itself.
    blob = json.dumps(record, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


def snapshot_fields(spec, record):
    return {f: record.get(f) for f in spec["track_fields"] if record.get(f) is not None}


def apply_snapshot_diff(spec, records, previous):
    """Keep only records whose tracked fields changed since the previous run.

    Returns the records worth emitting, each tagged with what changed, and the
    refreshed snapshot map.

    ponytail: snapshots are never pruned. One entry per endpoint is a few dozen
    bytes, so a decommissioned agent costs nothing until someone cares.
    """
    emitted, snapshots = [], dict(previous)
    for record in records:
        rid = record_id(spec, record)
        current = snapshot_fields(spec, record)
        previous_snapshot = previous.get(rid)
        if previous_snapshot is None:
            record["_change"] = "first_seen"
            emitted.append(record)
        else:
            changed = sorted(k for k in set(current) | set(previous_snapshot)
                             if current.get(k) != previous_snapshot.get(k))
            if changed:
                record["_change"] = ",".join(changed)
                emitted.append(record)
        snapshots[rid] = current
    return emitted, snapshots


def record_time(spec, record):
    value = record.get(spec["record_time"])
    if isinstance(value, str):
        try:
            value = float(value)
        except ValueError:
            return None
    return int(value) if isinstance(value, (int, float)) else None


def normalize_severity(name, record):
    raw = record.get("severity") or record.get("AUDIT_SEVERITY") or record.get("SEVERITY")
    if not isinstance(raw, str):
        return None
    if raw in AUDIT_SEVERITY:
        return AUDIT_SEVERITY[raw]
    lowered = raw.lower()
    return lowered if lowered in VALID_SEVERITIES else lowered


def build_event(name, record, collected_at):
    """One API record becomes one Wazuh event under the cortex.* namespace.

    Every field the API returns is carried through rather than allowlisted, so
    the ruleset can be extended later without touching the collector.
    """
    spec = COLLECTORS[name]
    body = dict(record)
    for field in spec.get("drop_fields", ()):
        body.pop(field, None)

    changed = body.pop("_change", None)
    if changed:
        body["changed_fields"] = changed
        body["state_changed"] = "false" if changed == "first_seen" else "true"

    # Epoch milliseconds become ISO: analysisd stringifies decoded numbers,
    # turning 1789574797000 into "1789574797000.000000", which no date or
    # numeric mapping parses cleanly.
    for field in spec["time_fields"]:
        if field in body:
            iso = epoch_ms_to_iso(body[field])
            if iso:
                body[field] = iso

    body["event_type"] = spec["event_type"]
    severity = normalize_severity(name, record)
    if severity:
        body["severity"] = severity

    if name == "incidents":
        # A 5.0 tenant leaves incident_name empty and puts the summary in description.
        body["incident_name"] = record.get("incident_name") or record.get("description")
        # Tenants return resolved_* values beyond the documented set, so rules
        # match this instead of enumerating statuses.
        status = str(record.get("status") or "")
        body["is_resolved"] = str(status.startswith("resolved")).lower()

    event = normalize({
        "integration": INTEGRATION_NAME,
        "collector_version": COLLECTOR_VERSION,
        "collected_at": collected_at,
        "cortex": body,
    })
    return enforce_size(event, name)


def enforce_size(event, name):
    """Keep the line under what analysisd will accept.

    Over the cap the whole event is discarded silently, so the longest fields
    are dropped until it fits and the event is flagged rather than lost.
    """
    encoded = json.dumps(event, separators=(",", ":"))
    if len(encoded.encode("utf-8")) <= MAX_EVENT_BYTES:
        return event

    body = event["cortex"]
    by_size = sorted(body, key=lambda k: len(str(body[k])), reverse=True)
    dropped = []
    for key in by_size:
        if key in ("event_type", "severity"):
            continue
        dropped.append(key)
        del body[key]
        encoded = json.dumps(event, separators=(",", ":"))
        if len(encoded.encode("utf-8")) <= MAX_EVENT_BYTES:
            break
    body["truncated"] = "true"
    body["truncated_fields"] = ",".join(sorted(dropped))
    log.warning("%s: event over %d bytes, dropped %d field(s)", name, MAX_EVENT_BYTES, len(dropped))
    return event


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
        return {"base_prefix": state.get("base_prefix")} if state.get("base_prefix") else {}
    return state


def save_state(path, state):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def advance_watermark(spec, records, previous):
    """Return the new watermark and the ids of records sitting exactly on it."""
    times = [t for t in (record_time(spec, r) for r in records) if t is not None]
    watermark = max(times) if times else previous
    boundary = {record_id(spec, r) for r in records if record_time(spec, r) == watermark}
    return watermark, boundary


def drop_already_seen(spec, records, watermark, boundary_ids):
    """Remove records the previous run already emitted at the watermark."""
    if not boundary_ids:
        return records
    return [r for r in records
            if not (record_time(spec, r) == watermark and record_id(spec, r) in boundary_ids)]


def write_events(path, events):
    """Append NDJSON and fsync, so a crash cannot leave a torn line."""
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


def collect(session, cfg, name, state, now, emit):
    """Poll one data set and return its updated state slice."""
    spec = COLLECTORS[name]
    slice_ = dict(state.get(name) or {})
    watermark = slice_.get("watermark")
    boundary_ids = set(slice_.get("boundary_ids") or [])
    if not watermark:
        hours = cfg["lookback_hours_by_collector"].get(name, cfg["lookback_hours"])
        watermark = int((now - timedelta(hours=hours)).timestamp() * 1000)
        boundary_ids = set()
        log.info("%s: no watermark, looking back %d hours", name, hours)

    records = fetch_records(session, cfg, name, watermark)
    fresh = drop_already_seen(spec, records, watermark, boundary_ids)

    new_slice = {}
    if spec.get("track_fields"):
        before = len(fresh)
        fresh, snapshots = apply_snapshot_diff(spec, fresh, slice_.get("snapshots") or {})
        new_slice["snapshots"] = snapshots
        log.info("%s: %d returned, %d with a tracked change", name, before, len(fresh))
    else:
        log.info("%s: %d changed since %s, %d new", name, len(records),
                 epoch_ms_to_iso(watermark), len(fresh))

    collected_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    emit([build_event(name, r, collected_at) for r in fresh])

    new_watermark, new_boundary = advance_watermark(spec, records, watermark)
    if not records:
        new_boundary = boundary_ids
    new_slice["watermark"] = new_watermark
    new_slice["boundary_ids"] = sorted(new_boundary)
    return new_slice


def selftest():
    spec = COLLECTORS["incidents"]
    records = [
        {"incident_id": 1, "modification_time": 100, "severity": "low", "status": "new"},
        {"incident_id": 2, "modification_time": 300, "severity": "high", "status": "new"},
        {"incident_id": 3, "modification_time": 300, "severity": "high",
         "status": "resolved_false_positive"},
    ]

    watermark, boundary = advance_watermark(spec, records, 0)
    assert watermark == 300, watermark
    assert boundary == {"2", "3"}, boundary

    # The inclusive re-query must not re-emit the boundary, but must pass newer ones.
    again = drop_already_seen(spec, records, watermark, boundary)
    assert [r["incident_id"] for r in again] == [1], again
    fresh = records + [{"incident_id": 4, "modification_time": 400}]
    assert 4 in [r["incident_id"] for r in drop_already_seen(spec, fresh, watermark, boundary)]

    # An empty page must not rewind the watermark.
    assert advance_watermark(spec, [], 300) == (300, set())

    assert normalize({"a": None, "b": "", "c": 0, "d": {"e": None}, "f": [None]}) == {"c": 0}
    # Cortex wraps scalars in one-element lists; multi-element lists stay lists.
    assert normalize({"ip": ["10.0.0.1"], "tags": ["a", "b"]}) == {"ip": "10.0.0.1", "tags": ["a", "b"]}
    assert epoch_ms_to_iso(1745080427000) == "2025-04-19T16:33:47.000Z"
    assert epoch_ms_to_iso(1789725590720.0) == "2026-09-18T09:59:50.720Z"
    assert epoch_ms_to_iso(None) is None and epoch_ms_to_iso(0) is None

    # Audit severities use a different vocabulary from incident severities.
    assert normalize_severity("audit_management", {"AUDIT_SEVERITY": "SEV_010_INFO"}) == "informational"
    assert normalize_severity("alerts", {"severity": "High"}) == "high"

    inc = build_event("incidents", records[2], "x")
    assert inc["cortex"]["is_resolved"] == "true"
    assert inc["cortex"]["event_type"] == "incident"
    assert build_event("incidents", records[1], "x")["cortex"]["is_resolved"] == "false"
    named = build_event("incidents", {"incident_id": 9, "description": "Evasion on host1"}, "x")
    assert named["cortex"]["incident_name"] == "Evasion on host1"
    # Timestamps must reach the indexer as ISO, never as a stringified epoch.
    timed = build_event("incidents", {"incident_id": 9, "creation_time": 1745080427000}, "x")
    assert timed["cortex"]["creation_time"] == "2025-04-19T16:33:47.000Z"

    # The alert events array is unbounded and must never be emitted.
    al = build_event("alerts", {"alert_id": "1", "severity": "high", "events": [{"x": "y"}]}, "x")
    assert "events" not in al["cortex"] and al["cortex"]["event_type"] == "alert"

    # Oversized events are trimmed and flagged, not silently dropped by analysisd.
    big = build_event("alerts", {"alert_id": "1", "severity": "high",
                                 "blob": "x" * (MAX_EVENT_BYTES + 100)}, "x")
    assert big["cortex"]["truncated"] == "true"
    assert "blob" in big["cortex"]["truncated_fields"]
    assert len(json.dumps(big).encode("utf-8")) <= MAX_EVENT_BYTES + 200

    # Endpoint heartbeats must not alert. last_seen moves constantly, so only a
    # tracked field changing may produce an event.
    ep = COLLECTORS["endpoints"]
    first = [{"endpoint_id": "e1", "last_seen": 1000, "endpoint_status": "CONNECTED",
              "operational_status": "PROTECTED"}]
    out, snaps = apply_snapshot_diff(ep, first, {})
    assert len(out) == 1 and out[0]["_change"] == "first_seen"

    beat = [{"endpoint_id": "e1", "last_seen": 9999, "endpoint_status": "CONNECTED",
             "operational_status": "PROTECTED"}]
    out, snaps2 = apply_snapshot_diff(ep, beat, snaps)
    assert out == [], "a heartbeat with no tracked change must emit nothing"

    moved = [{"endpoint_id": "e1", "last_seen": 10000, "endpoint_status": "DISCONNECTED",
              "operational_status": "PROTECTED"}]
    out, _ = apply_snapshot_diff(ep, moved, snaps2)
    assert len(out) == 1 and out[0]["_change"] == "endpoint_status"
    ev = build_event("endpoints", out[0], "x")
    assert ev["cortex"]["state_changed"] == "true"
    assert ev["cortex"]["changed_fields"] == "endpoint_status"
    assert "_change" not in ev["cortex"]

    # Records without an id field are identified by content, so two differing
    # agent reports must not collide.
    agent = COLLECTORS["audit_agents"]
    a = record_id(agent, {"ENDPOINTID": "a", "TIMESTAMP": 1, "DESCRIPTION": "x"})
    b = record_id(agent, {"ENDPOINTID": "a", "TIMESTAMP": 1, "DESCRIPTION": "y"})
    assert a != b and len(a) == 32

    print("selftest ok")


def main():
    os.umask(0o027)

    parser = argparse.ArgumentParser(description="Cortex XDR collector for Wazuh")
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG)
    parser.add_argument("--collect", help="Comma-separated data sets, overriding the config")
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
    if args.collect:
        cfg["collect"] = [c.strip() for c in args.collect.split(",") if c.strip()]
        unknown = [c for c in cfg["collect"] if c not in COLLECTORS]
        if unknown:
            raise SystemExit("--collect: unknown {}; valid values are {}".format(
                unknown, sorted(COLLECTORS)))

    state = {} if args.no_state else load_state(cfg["state_file"])
    if state.get("base_prefix"):
        cfg["base_prefix"] = state["base_prefix"]
    if args.since_hours:
        # A forced window means every collector starts from it.
        for name in cfg["collect"]:
            state[name] = {"watermark": None, "boundary_ids": []}
            cfg["lookback_hours_by_collector"][name] = _bounded_hours(args.since_hours)

    lock = None if args.stdout else acquire_lock(cfg["lock_file"])
    session = build_session()
    now = datetime.now(timezone.utc)
    failures = []

    def emit(events):
        if not events:
            return
        if args.stdout:
            for event in events:
                print(json.dumps(event, separators=(",", ":")))
        else:
            write_events(cfg["log_file"], events)

    try:
        new_state = {"version": STATE_VERSION}
        new_state.update({k: v for k, v in state.items() if k in COLLECTORS})
        for name in cfg["collect"]:
            try:
                # Per collector, so one failing data set cannot lose the others.
                new_state[name] = collect(session, cfg, name, state, now, emit)
            except SystemExit:
                raise
            except Exception as exc:
                log.error("%s: collection failed: %s", name, exc)
                failures.append(name)
        new_state["base_prefix"] = cfg["base_prefix"]

        # Written after emitting: a crash here repeats records rather than losing them.
        if not args.no_state:
            save_state(cfg["state_file"], new_state)
    finally:
        session.close()
        if lock:
            lock.close()

    if failures:
        log.error("%d of %d collectors failed: %s", len(failures), len(cfg["collect"]),
                  ", ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
