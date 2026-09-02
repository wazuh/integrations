#!/var/ossec/framework/python/bin/python3
#
# silent_agent_monitor.py
# Detects Wazuh agents that are still registered but have stopped shipping
# logs. For every agent in a target group it reads the timestamp of the most
# recent indexed event and, when that timestamp is older than the threshold,
# appends a SILENT record to a local JSON log that Wazuh ingests through a
# <localfile> block. When events start arriving again it appends a matching
# RESTORED record. State is kept locally so an unchanged condition is reported
# once, not once per run. Standard library only.
#
# Usage: silent_agent_monitor.py --group Server,Windows

import argparse
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
API_URL = os.environ.get("SAM_API_URL", "https://127.0.0.1:55000")
API_USER = os.environ.get("SAM_API_USER", "wazuh-wui")
API_PASSWORD = os.environ.get("SAM_API_PASSWORD", "CHANGE_ME")

INDEXER_URL = os.environ.get("SAM_INDEXER_URL", "https://127.0.0.1:9200")
INDEXER_USER = os.environ.get("SAM_INDEXER_USER", "admin")
INDEXER_PASSWORD = os.environ.get("SAM_INDEXER_PASSWORD", "CHANGE_ME")

INDEX_PATTERN = os.environ.get("SAM_INDEX_PATTERN", "wazuh-alerts-*")

# Comma-separated. Overridden by --group, so the wodle owns the group names.
TARGET_GROUPS = [g.strip() for g in os.environ.get("SAM_GROUP", "Server").split(",")
                 if g.strip()]
SILENCE_THRESHOLD = timedelta(hours=float(os.environ.get("SAM_THRESHOLD_HOURS", "24")))
LOOKBACK = timedelta(days=float(os.environ.get("SAM_LOOKBACK_DAYS", "7")))

STATE_FILE = os.environ.get("SAM_STATE_FILE", "/var/ossec/var/silent_agents_state.json")
OUTPUT_LOG = os.environ.get("SAM_OUTPUT_LOG", "/var/ossec/logs/silent_agents.json")
SCRIPT_LOG = os.environ.get("SAM_SCRIPT_LOG", "/var/ossec/logs/silent_agent_monitor.log")

VERIFY_SSL = os.environ.get("SAM_VERIFY_SSL", "no").lower() in ("yes", "true", "1")
PAGE_SIZE = 500
HTTP_TIMEOUT = 30

_LOG_ARGS = {"format": "%(asctime)s %(levelname)s %(message)s",
             "datefmt": "%Y-%m-%dT%H:%M:%S", "level": logging.INFO}
try:
    logging.basicConfig(filename=SCRIPT_LOG, filemode="a", **_LOG_ARGS)
except OSError:
    logging.basicConfig(stream=sys.stderr, **_LOG_ARGS)

SSL_CONTEXT = ssl.create_default_context()
if not VERIFY_SSL:
    SSL_CONTEXT.check_hostname = False
    SSL_CONTEXT.verify_mode = ssl.CERT_NONE


def http_json(url, method="GET", body=None, token=None, basic=None):
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
    url = f"{API_URL}/security/user/authenticate"
    return http_json(url, method="POST", basic=(API_USER, API_PASSWORD))["data"]["token"]


def fetch_group_agents(token, group):
    agents, offset = [], 0
    while True:
        url = (f"{API_URL}/agents?group={group}&limit={PAGE_SIZE}&offset={offset}"
               f"&sort=%2Bid&select=id,name,status,lastKeepAlive")
        data = http_json(url, token=token).get("data", {})
        agents.extend(a for a in data.get("affected_items", [])
                      if a.get("id") != "000" and a.get("status") != "never_connected")
        offset += PAGE_SIZE
        if offset >= data.get("total_affected_items", 0):
            break
    return agents


def fetch_last_event_times(agent_ids):
    """{agent_id: datetime}. Agents with no event inside LOOKBACK are absent."""
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
    buckets = result.get("aggregations", {}).get("per_agent", {}).get("buckets", [])
    return {b["key"]: datetime.fromtimestamp(b["last_event"]["value"] / 1000, timezone.utc)
            for b in buckets if b["last_event"]["value"]}


def format_duration(delta):
    minutes = int(delta.total_seconds() // 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m" if minutes else f"{hours}h"


def local_time(dt):
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def decide(agent, last_log, previous, now):
    """Pure decision for one agent. Returns (event or None, new state entry)."""
    agent_id, name = agent["id"], agent.get("name", "unknown")
    silent = last_log is None or (now - last_log) >= SILENCE_THRESHOLD
    was_silent = previous.get("status") == "SILENT"

    # event_status, not status: "status" is a static Wazuh field name and a
    # rule cannot match it with <field name>.
    common = {
        "integration": "silent-agent-monitor",
        "group": ",".join(agent.get("groups", [])),
        "agent_id": agent_id,
        "agent_name": name,
        "agent_status": agent.get("status", "unknown"),
    }
    state = {"status": "SILENT" if silent else "OK", "name": name,
             "last_log": last_log.isoformat() if last_log else previous.get("last_log")}

    if silent and not was_silent:
        gap = (now - last_log) if last_log else LOOKBACK
        event = dict(common, event_status="SILENT",
                     status_text="No logs received",
                     last_log=local_time(last_log) if last_log else "unknown",
                     no_logs_for=format_duration(gap) if last_log
                     else f"more than {format_duration(LOOKBACK)}",
                     no_logs_seconds=int(gap.total_seconds()),
                     message=f"Agent {name} (ID {agent_id}) has sent no logs "
                             f"for more than {format_duration(SILENCE_THRESHOLD)}.")
        return event, state

    if not silent and was_silent:
        # Measured from the last log before the gap to the first log after it,
        # not from the moment this script noticed.
        previous_log = previous.get("last_log")
        gap = (last_log - datetime.fromisoformat(previous_log)) if previous_log else None
        event = dict(common, event_status="RESTORED",
                     status_text="Logs received",
                     restored_at=local_time(last_log),
                     silence_duration=format_duration(gap) if gap is not None else "unknown",
                     silence_seconds=int(gap.total_seconds()) if gap is not None else 0,
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
        logging.error("Could not read state file '%s': %s. Starting empty.", STATE_FILE, err)
        return {}


def save_state(state):
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
    groups = ",".join(TARGET_GROUPS)
    # An agent in two target groups is checked once and reports both names.
    found = {}
    try:
        token = get_token()
        for group in TARGET_GROUPS:
            for agent in fetch_group_agents(token, group):
                found.setdefault(agent["id"], dict(agent, groups=[]))["groups"].append(group)
    except (urllib.error.URLError, OSError, KeyError, ValueError) as err:
        logging.error("Wazuh API query failed: %s", err)
        sys.exit(1)

    agents = list(found.values())
    if not agents:
        logging.info("No agents in group(s) '%s'. Nothing to do.", groups)
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
        # Every agent silent at once is far more likely a wrong index pattern
        # or wrong credentials than a real outage. Refuse to send the storm.
        logging.error("No events found for any of the %d agents in '%s' over the last %s. "
                      "Check SAM_INDEX_PATTERN and the indexer credentials. No alerts sent.",
                      len(agents), groups, format_duration(LOOKBACK))
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
                 len(agents), groups, silent, len(events))
    print(f"Checked {len(agents)} agent(s) in '{groups}': "
          f"{silent} silent, {len(events)} event(s) written to {OUTPUT_LOG}.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect Wazuh agents that stopped sending logs.")
    parser.add_argument("--group", default=",".join(TARGET_GROUPS),
                        help="comma-separated agent groups to monitor "
                             f"(default: {','.join(TARGET_GROUPS)})")
    args = parser.parse_args()

    TARGET_GROUPS = [g.strip() for g in args.group.split(",") if g.strip()]
    main()
