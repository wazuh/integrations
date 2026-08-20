#!/var/ossec/framework/python/bin/python3
#
# silent_agent_monitor.py
# Detects Wazuh agents that are still registered (and often still "active")
# but have stopped shipping logs. For every agent in a target group it reads
# the timestamp of the most recent indexed event and, when that timestamp is
# older than the threshold, appends a SILENT record to a local JSON log that
# Wazuh ingests through a <localfile> block. When events start arriving again
# it appends a matching RESTORED record.
#
# State is kept locally so a condition that stays unchanged is reported once,
# not once per run. Standard library only: it runs on the Wazuh embedded
# interpreter with no pip install.
#
# Run modes:
#   silent_agent_monitor.py             normal check (scheduled by a wodle)
#   silent_agent_monitor.py --selftest  offline assertions on the decision logic

import base64
import json
import logging
import os
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

# === CONFIGURATION ===
# Every value can be overridden with an environment variable, so the same file
# can be pointed at a test environment without being edited.
API_URL = os.environ.get("SAM_API_URL", "https://127.0.0.1:55000")
API_USER = os.environ.get("SAM_API_USER", "wazuh-wui")
API_PASSWORD = os.environ.get("SAM_API_PASSWORD", "CHANGE_ME")

INDEXER_URL = os.environ.get("SAM_INDEXER_URL", "https://127.0.0.1:9200")
INDEXER_USER = os.environ.get("SAM_INDEXER_USER", "admin")
INDEXER_PASSWORD = os.environ.get("SAM_INDEXER_PASSWORD", "CHANGE_ME")

# Index pattern holding the events used as proof of life. See the README:
# wazuh-alerts-* only contains alerts, wazuh-archives-* contains every event
# and is the accurate source when archives are enabled and indexed.
INDEX_PATTERN = os.environ.get("SAM_INDEX_PATTERN", "wazuh-alerts-*")

TARGET_GROUP = os.environ.get("SAM_GROUP", "Server")
SILENCE_THRESHOLD = timedelta(hours=float(os.environ.get("SAM_THRESHOLD_HOURS", "24")))

# How far back the aggregation looks. Must exceed the threshold: an agent with
# no events inside this window is reported as silent for "more than" it.
LOOKBACK = timedelta(days=float(os.environ.get("SAM_LOOKBACK_DAYS", "7")))

STATE_FILE = os.environ.get("SAM_STATE_FILE", "/var/ossec/var/silent_agents_state.json")
OUTPUT_LOG = os.environ.get("SAM_OUTPUT_LOG", "/var/ossec/logs/silent_agents.json")
SCRIPT_LOG = os.environ.get("SAM_SCRIPT_LOG", "/var/ossec/logs/silent_agent_monitor.log")

VERIFY_SSL = os.environ.get("SAM_VERIFY_SSL", "no").lower() in ("yes", "true", "1")
PAGE_SIZE = 500
HTTP_TIMEOUT = 30

# === LOGGING ===
_LOG_ARGS = {"format": "%(asctime)s %(levelname)s %(message)s",
             "datefmt": "%Y-%m-%dT%H:%M:%S", "level": logging.INFO}
try:
    logging.basicConfig(filename=SCRIPT_LOG, filemode="a", **_LOG_ARGS)
except OSError:
    # Running as a user that cannot write the log file is not a reason to skip
    # the check. stderr is picked up by whatever scheduled the run.
    logging.basicConfig(stream=sys.stderr, **_LOG_ARGS)

SSL_CONTEXT = ssl.create_default_context()
if not VERIFY_SSL:
    SSL_CONTEXT.check_hostname = False
    SSL_CONTEXT.verify_mode = ssl.CERT_NONE


def http_json(url, method="GET", body=None, token=None, basic=None):
    """One JSON request. Raises on any transport or HTTP error."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if basic:
        raw = base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {raw}")
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=SSL_CONTEXT) as resp:
        return json.loads(resp.read().decode())


def get_token():
    """Authenticate against the Wazuh API and return a JWT token."""
    url = f"{API_URL}/security/user/authenticate"
    return http_json(url, method="POST", basic=(API_USER, API_PASSWORD))["data"]["token"]


def fetch_group_agents(token):
    """Return every agent of TARGET_GROUP, excluding the manager and agents
    that have never connected (those have no logs by definition)."""
    agents, offset = [], 0
    while True:
        url = (f"{API_URL}/agents?group={TARGET_GROUP}&limit={PAGE_SIZE}&offset={offset}"
               f"&sort=%2Bid&select=id,name,status,lastKeepAlive")
        data = http_json(url, token=token).get("data", {})
        agents.extend(a for a in data.get("affected_items", [])
                      if a.get("id") != "000" and a.get("status") != "never_connected")
        offset += PAGE_SIZE
        if offset >= data.get("total_affected_items", 0):
            break
    return agents


def fetch_last_event_times(agent_ids):
    """One aggregation for every agent: newest event timestamp per agent.id.
    Returns {agent_id: datetime}. Agents with no event in LOOKBACK are absent."""
    query = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"terms": {"agent.id": agent_ids}},
            {"range": {"@timestamp": {"gte": f"now-{int(LOOKBACK.total_seconds())}s"}}},
        ]}},
        "aggs": {"per_agent": {
            "terms": {"field": "agent.id", "size": len(agent_ids)},
            "aggs": {"last_event": {"max": {"field": "@timestamp"}}},
        }},
    }
    url = f"{INDEXER_URL}/{INDEX_PATTERN}/_search"
    result = http_json(url, method="POST", body=query,
                       basic=(INDEXER_USER, INDEXER_PASSWORD))
    # Missing aggregations means the query never matched an index. Return no
    # buckets and let the caller's safety stop report it as a lookup problem.
    buckets = result.get("aggregations", {}).get("per_agent", {}).get("buckets", [])
    return {b["key"]: datetime.fromtimestamp(b["last_event"]["value"] / 1000, timezone.utc)
            for b in buckets if b["last_event"]["value"]}


def format_duration(delta):
    """'25h 40m', or '25h' on a whole hour. Matches the notification template."""
    minutes = int(delta.total_seconds() // 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m" if minutes else f"{hours}h"


def local_time(dt):
    """Render a UTC datetime in the manager's local timezone, tz name included."""
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def decide(agent, last_log, previous, now):
    """Pure decision for one agent. Returns (event or None, new state entry).

    last_log is the newest indexed event time, or None when the agent produced
    nothing inside LOOKBACK, which is the deepest form of silence.
    previous is the state entry from the last run, or {}.
    """
    agent_id, name = agent["id"], agent.get("name", "unknown")
    silent = last_log is None or (now - last_log) >= SILENCE_THRESHOLD
    was_silent = previous.get("status") == "SILENT"

    # The state key is named event_status, not status: "status" is one of the
    # Wazuh static field names, and a rule cannot match it with <field name>.
    common = {
        "integration": "silent-agent-monitor",
        "group": TARGET_GROUP,
        "agent_id": agent_id,
        "agent_name": name,
        "agent_status": agent.get("status", "unknown"),
    }
    state = {"status": "SILENT" if silent else "OK", "name": name,
             "last_log": last_log.isoformat() if last_log else previous.get("last_log")}

    if silent and not was_silent:
        gap = (now - last_log) if last_log else LOOKBACK
        event = dict(common, event_status="SILENT",
                     last_log=local_time(last_log) if last_log else "unknown",
                     no_logs_for=format_duration(gap) if last_log
                     else f"more than {format_duration(LOOKBACK)}",
                     no_logs_seconds=int(gap.total_seconds()),
                     message=f"Agent {name} (ID {agent_id}) has sent no logs "
                             f"for more than {format_duration(SILENCE_THRESHOLD)}.")
        return event, state

    if not silent and was_silent:
        # Measured from the last log before the gap to the first log after it,
        # not from the moment this script noticed, so the duration is real.
        previous_log = previous.get("last_log")
        gap = (last_log - datetime.fromisoformat(previous_log)) if previous_log else None
        event = dict(common, event_status="RESTORED",
                     restored_at=local_time(last_log),
                     silence_duration=format_duration(gap) if gap else "unknown",
                     silence_seconds=int(gap.total_seconds()) if gap else 0,
                     message=f"Agent {name} (ID {agent_id}) has resumed sending logs.")
        return event, state

    return None, state


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as err:
        # A corrupt state file must not stop the check. Worst case one repeat.
        logging.error("Could not read state file '%s': %s. Starting empty.", STATE_FILE, err)
        return {}


def save_state(state):
    """Atomic replace, so a kill mid-write cannot leave a truncated state."""
    tmp = f"{STATE_FILE}.tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, STATE_FILE)


def append_events(events):
    with open(OUTPUT_LOG, "a") as f:
        for event in events:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")


def main():
    now = datetime.now(timezone.utc)
    try:
        agents = fetch_group_agents(get_token())
    except (urllib.error.URLError, OSError, KeyError, ValueError) as err:
        logging.error("Wazuh API query failed: %s", err)
        sys.exit(1)

    if not agents:
        logging.info("No agents in group '%s'. Nothing to do.", TARGET_GROUP)
        return

    agent_ids = [a["id"] for a in agents]
    try:
        last_events = fetch_last_event_times(agent_ids)
    except (urllib.error.URLError, OSError, KeyError, ValueError) as err:
        # Exit without touching the state: a failed query must never be read as
        # "every agent went silent", nor as "every agent recovered".
        logging.error("Indexer query failed: %s", err)
        sys.exit(1)

    if not last_events and len(agents) > 1:
        # Every single agent silent at once is far more likely to be a wrong
        # index pattern or wrong credentials than a real outage. Refuse to
        # generate the storm and make the operator look.
        logging.error("No events found for any of the %d agents in '%s' over the last %s. "
                      "Check SAM_INDEX_PATTERN and the indexer credentials. No alerts sent.",
                      len(agents), TARGET_GROUP, format_duration(LOOKBACK))
        sys.exit(1)

    state = load_state()
    events, new_state = [], {}
    for agent in agents:
        event, entry = decide(agent, last_events.get(agent["id"]),
                              state.get(agent["id"], {}), now)
        new_state[agent["id"]] = entry
        if event:
            events.append(event)

    if events:
        append_events(events)
    save_state(new_state)

    silent = sum(1 for e in new_state.values() if e["status"] == "SILENT")
    logging.info("Checked %d agent(s) in '%s': %d silent, %d new event(s) written.",
                 len(agents), TARGET_GROUP, silent, len(events))
    print(f"Checked {len(agents)} agent(s) in '{TARGET_GROUP}': "
          f"{silent} silent, {len(events)} event(s) written to {OUTPUT_LOG}.")


def selftest():
    """Offline assertions on the decision logic. No API, no indexer."""
    now = datetime(2026, 8, 19, 10, 20, 0, tzinfo=timezone.utc)
    agent = {"id": "152", "name": "File2", "status": "active"}

    # Quiet for 25h40m: reported once, then suppressed while unchanged.
    stopped = now - timedelta(hours=25, minutes=40)
    event, state = decide(agent, stopped, {}, now)
    assert event["event_status"] == "SILENT", event
    assert event["no_logs_for"] == "25h 40m", event
    assert event["agent_id"] == "152" and event["agent_name"] == "File2"
    assert state["status"] == "SILENT"
    assert decide(agent, stopped, state, now)[0] is None, "repeat alert not suppressed"

    # Logs resume: one recovery, measured from the last log before the gap.
    resumed = stopped + timedelta(hours=25, minutes=40)
    event, ok_state = decide(agent, resumed, state, now)
    assert event["event_status"] == "RESTORED", event
    assert event["silence_duration"] == "25h 40m", event
    assert ok_state["status"] == "OK"
    assert decide(agent, resumed, ok_state, now)[0] is None, "repeat recovery not suppressed"

    # A healthy agent inside the threshold never reports.
    assert decide(agent, now - timedelta(hours=23), {}, now)[0] is None

    # No events at all inside the lookback window is silence, not a skip.
    event, _ = decide(agent, None, {}, now)
    assert event["event_status"] == "SILENT" and event["last_log"] == "unknown", event

    print("selftest OK")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        main()
