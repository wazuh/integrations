# Silent Agent Monitoring - Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [How It Works](#how-it-works)
    * [What Counts as a Log](#what-counts-as-a-log)
    * [Alert and Recovery Logic](#alert-and-recovery-logic)
* [Installation and Configuration](#installation-and-configuration)
    * [Using the Integration Files](#using-the-integration-files)
    * [Script Configuration](#script-configuration)
    * [Scheduling the Check](#scheduling-the-check)
    * [Ingesting the Records](#ingesting-the-records)
    * [Rules](#rules)
    * [Email Notifications](#email-notifications)
    * [Telegram Notifications](#telegram-notifications)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Troubleshooting](#troubleshooting)
* [Verification](#verification)
* [Design Notes](#design-notes)
* [Sources](#sources)

---

### Introduction

Wazuh alerts natively when an agent stops connecting: `wazuh-monitord` marks the
agent disconnected after `<agents_disconnection_time>` and rule 502 fires. That
covers the agent that goes away. It does not cover the agent that stays
connected, keeps answering keepalives, and quietly stops shipping logs, because
a log collector died, a log path rotated away, a service stopped writing, or a
permission changed. From the manager's point of view that agent is healthy.

This integration closes that gap. On a schedule it reads, for every agent of a
chosen group, the timestamp of the most recent event that reached the indexer.
When that timestamp is older than the threshold it writes a `SILENT` record;
when events start arriving again it writes one `RESTORED` record. The records
are plain JSON lines that Wazuh ingests through a `<localfile>` block, so they
become normal alerts and can be routed to email, Telegram, or anything else
with the standard `<email_alerts>` and `<integration>` blocks.

The answer to "can this be done from the group and the last event timestamp, or
is a custom script needed": the group and the timestamp are exactly the right
inputs, and a script is needed to join them, because no built-in module tracks
per-agent event recency. Everything downstream of the script (decoding, rules,
alerting, routing) is stock Wazuh.

---

### Prerequisites

- Wazuh manager 4.4 or later, with the Wazuh API reachable and an API user that
  can read `/agents`.
- Wazuh indexer reachable from the manager, with a user that can search the
  alerts (or archives) indices.
- An agent group to monitor. The examples use `Server`.
- Python 3.6 or later. The scripts use only the standard library, so there is no
  `pip install` step; the Wazuh embedded interpreter at
  `/var/ossec/framework/python/bin/python3` satisfies this.
- Filesystem access to the manager to place the files.

**Wazuh Cloud:** managed environments do not give shell access to the manager,
so the two scripts cannot be copied in by the user. Rules, `ossec.conf` blocks,
and the group can be managed from the dashboard, but the script placement and
its execute permissions have to be done by the Wazuh Cloud team through a
support request. Send them this folder and the target paths listed below. In a
cluster, the script, its state file, and the `<localfile>` block must be placed
on one node only (the master); running it on several nodes duplicates every
notification and splits the state.

---

### How It Works

```
                 Wazuh API /agents?group=Server        Wazuh indexer
                            |                                |
                            | agent id, name, status         | max(@timestamp) per agent.id
                            v                                v
                   +--------------------------------------------------+
   command wodle ->|            silent_agent_monitor.py               |
      (hourly)     |  compares each agent against the threshold and   |
                   |  against the previous run's state                |
                   +--------------------------------------------------+
                            |
                            | one JSON line per state change only
                            v
                   /var/ossec/logs/silent_agents.json
                            |
                            | <localfile> json
                            v
                   rules 100121 / 100122  ->  email + Telegram
```

#### What Counts as a Log

The script measures recency against an index pattern, `SAM_INDEX_PATTERN`:

| Pattern | Meaning | Trade-off |
| --- | --- | --- |
| `wazuh-alerts-*` (default) | The newest **alert** produced by the agent. | Available everywhere. An agent that ships logs normally but produces no alert for a full day is reported as silent. |
| `wazuh-archives-*` | The newest **event** received from the agent, whether or not it alerted. | Exact answer to "no logs received", but needs `<logall_json>` enabled and the archives indexed, which costs storage. |

Use archives when they are enabled. On alerts, confirm first that every agent in
the group normally produces at least some alerts within the threshold; a quiet
Windows file server under a tight ruleset sometimes does not. Widening the
threshold or moving to archives both remove that false positive.

#### Alert and Recovery Logic

State is kept in a small local JSON file, so a condition that has not changed is
reported once rather than once per run:

| Previous state | Current reading | Action |
| --- | --- | --- |
| OK (or unknown) | Last event older than the threshold, or no event at all in the lookback window | Write one `SILENT` record, remember the last log timestamp. |
| SILENT | Still older than the threshold | Nothing. No repeated notification. |
| SILENT | Recent events again | Write one `RESTORED` record, clear the state. |
| OK | Recent events | Nothing. |

Durations are measured against real log timestamps, not against the moment the
script noticed. `No Logs For` is the gap between the last received log and now.
`No Logs Duration` on recovery is the gap between the last log before the
silence and the first log after it, which is what the operator actually wants to
read in the incident.

An agent that has never connected is skipped: it has no logs by definition, and
`never_connected` is already visible in the dashboard. Agent `000` (the manager)
is skipped too.

---

### Installation and Configuration

#### Using the Integration Files

```
silent_agent_monitoring/
  silent_agent_monitor.py         # The check. Runs on a schedule from a wodle.
  silent_agent_monitor-rules.xml  # Rules 100120-100122.
  custom-server-telegram          # Integration wrapper (selects the Wazuh interpreter).
  custom-server-telegram.py       # Formats and posts the Telegram message.
```

Target paths on the manager:

```bash
cp silent_agent_monitor.py /var/ossec/wodles/
chmod 750 /var/ossec/wodles/silent_agent_monitor.py
chown root:wazuh /var/ossec/wodles/silent_agent_monitor.py

cp custom-server-telegram custom-server-telegram.py /var/ossec/integrations/
chmod 750 /var/ossec/integrations/custom-server-telegram*
chown root:wazuh /var/ossec/integrations/custom-server-telegram*

cat silent_agent_monitor-rules.xml >> /var/ossec/etc/rules/local_rules.xml
```

A manager upgrade can replace the contents of `/var/ossec/wodles`, so keep a
copy of the configured script outside `/var/ossec` and re-apply it after an
upgrade.

#### Script Configuration

Edit the `CONFIGURATION` block at the top of `silent_agent_monitor.py`, or set
the matching environment variables and leave the file untouched:

| Setting | Variable | Default |
| --- | --- | --- |
| Wazuh API URL | `SAM_API_URL` | `https://127.0.0.1:55000` |
| Wazuh API user / password | `SAM_API_USER`, `SAM_API_PASSWORD` | `wazuh-wui` / `CHANGE_ME` |
| Indexer URL | `SAM_INDEXER_URL` | `https://127.0.0.1:9200` |
| Indexer user / password | `SAM_INDEXER_USER`, `SAM_INDEXER_PASSWORD` | `admin` / `CHANGE_ME` |
| Index pattern | `SAM_INDEX_PATTERN` | `wazuh-alerts-*` |
| Agent group | `SAM_GROUP` | `Server` |
| Silence threshold, hours | `SAM_THRESHOLD_HOURS` | `24` |
| Lookback window, days | `SAM_LOOKBACK_DAYS` | `7` |
| State file | `SAM_STATE_FILE` | `/var/ossec/var/silent_agents_state.json` |
| Output log | `SAM_OUTPUT_LOG` | `/var/ossec/logs/silent_agents.json` |
| Script log | `SAM_SCRIPT_LOG` | `/var/ossec/logs/silent_agent_monitor.log` |
| Verify TLS certificates | `SAM_VERIFY_SSL` | `no` |

The file holds credentials, so keep it `chmod 750` and root-owned. On Wazuh
Cloud, use the environment endpoints and credentials supplied with the
environment rather than the loopback defaults.

`SAM_LOOKBACK_DAYS` must stay larger than the threshold. It bounds the indexer
query, and an agent with nothing inside it is reported as silent for "more than"
that window.

#### Scheduling the Check

`/var/ossec/etc/ossec.conf`, on the master node only:

```xml
<ossec_config>
  <wodle name="command">
    <disabled>no</disabled>
    <tag>silent-agent-monitor</tag>
    <command>/var/ossec/framework/python/bin/python3 /var/ossec/wodles/silent_agent_monitor.py</command>
    <interval>1h</interval>
    <run_on_start>yes</run_on_start>
    <timeout>300</timeout>
    <ignore_output>yes</ignore_output>
  </wodle>
</ossec_config>
```

With `run_on_start`, the very first run after a manager restart can reach the
Wazuh API before it finishes starting and log `HTTP Error 500`. That run exits
non-zero, `wazuh-modulesd` records a warning, and the next scheduled run
succeeds. Nothing is lost, because a failed run never writes state.

One run per hour is enough for a 24 hour threshold: it bounds detection lag and
recovery lag to an hour each while keeping the indexer load at one aggregation
query per hour, whatever the number of agents. Shorten the interval if the
recovery notification needs to arrive sooner.

#### Ingesting the Records

The script writes plain JSON objects, one per line, so the built-in JSON decoder
parses them and **no custom decoder is required**:

```xml
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/ossec/logs/silent_agents.json</location>
  </localfile>
</ossec_config>
```

#### Rules

`silent_agent_monitor-rules.xml` defines a level 0 parent that matches the
`integration` field and two children that alert:

| Rule | Level | Fires when |
| --- | --- | --- |
| 100120 | 0 | Any record from this integration. Classification only. |
| 100121 | 12 | `event_status` is `SILENT`. |
| 100122 | 5 | `event_status` is `RESTORED`. |

The matched field is `event_status`, not `status`: `status` is one of the Wazuh
static field names, and a rule that tries to match it with `<field name="status">`
fails to load with `Field 'status' is static`.

Both children carry `<options>alert_by_email</options>`, which forces the email
regardless of the global `<email_alert_level>`. Without it the level 5 recovery
alert would be dropped by the default threshold of 12 and only the silence
notification would arrive.

Move the IDs into a free range if 100120-100122 are already used; the repository
`detect_new_agents` integration, for example, also ships a rule 100110.

#### Email Notifications

Global email must already be configured (`<global>` with
`<email_notification>yes</email_notification>`, `<smtp_server>`, `<email_from>`,
`<email_to>`). Then route these two rules:

```xml
<ossec_config>
  <email_alerts>
    <email_to>soc-team@example.com</email_to>
    <rule_id>100121,100122</rule_id>
    <do_not_delay />
    <format>full</format>
  </email_alerts>
</ossec_config>
```

`<do_not_delay />` sends immediately instead of waiting for the next email
grouping interval.

The `full` format prints the record's fields one per line, so the email already
carries the agent name, the agent ID, the last log timestamp and the duration.
Only if the email has to look like the Telegram message, with the same heading
and emoji, is a `custom-email` integration script needed in place of
`<email_alerts>`.

#### Telegram Notifications

Add the integration next to the existing Telegram block, reusing the bot token
and chat ID of the Server channel:

```xml
<ossec_config>
  <!-- Telegram Alerts - Server Alerts -->
  <integration>
    <name>custom-server-telegram</name>
    <rule_id>100121,100122</rule_id>
    <hook_url>https://api.telegram.org/bot&lt;BOT_TOKEN&gt;/sendMessage</hook_url>
    <api_key>&lt;CHAT_ID&gt;</api_key>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
```

`<hook_url>` is the full `sendMessage` endpoint of the bot and `<api_key>` is
the numeric chat ID of the channel, both taken from the Telegram block already
in the configuration. The script produces exactly the requested layout:

```
⚠ Server Logging Alert          ✅ Server Logging Restored
Name: File2                      Name: File2
Agent ID: 152                    Agent ID: 152
Status: No logs received         Status: Logs received
Last Log Received: ...           Logging Restored At: ...
No Logs For: 25h 40m             No Logs Duration: 25h 40m
```

`wazuh-integratord` runs integration scripts as the `wazuh` user, not as root,
so the script logs to `/var/ossec/logs/integrations.log`, which that user can
already write. If `TELEGRAM_LOG` is pointed somewhere else, the new file has to
be writable by `wazuh` or the notification is lost before it is sent.

A separate script is used rather than a change to the existing `custom-telegram`
so that the current Telegram alerting keeps working untouched. To format these
two rules inside the existing script instead, add the branch before its normal
message construction and skip this file:

```python
if str(alert.get("rule", {}).get("id")) in ("100121", "100122"):
    d = alert.get("data", {})
    if d.get("event_status") == "SILENT":
        msg = (f"⚠ <b>Server Logging Alert</b>\n<b>Name:</b> {d.get('agent_name')}\n"
               f"<b>Agent ID:</b> {d.get('agent_id')}\n<b>Status:</b> No logs received\n"
               f"<b>Last Log Received:</b> {d.get('last_log')}\n"
               f"<b>No Logs For:</b> {d.get('no_logs_for')}")
    else:
        msg = (f"✅ <b>Server Logging Restored</b>\n<b>Name:</b> {d.get('agent_name')}\n"
               f"<b>Agent ID:</b> {d.get('agent_id')}\n<b>Status:</b> Logs received\n"
               f"<b>Logging Restored At:</b> {d.get('restored_at')}\n"
               f"<b>No Logs Duration:</b> {d.get('silence_duration')}")
```

---

### Integration Steps

1. Confirm the agents to monitor are in the group: `/var/ossec/bin/agent_groups -s -g Server`.
2. Copy the four files to the paths above and set ownership and permissions.
3. Fill in the API and indexer credentials, the group name, and the threshold.
4. Append the rules to `/var/ossec/etc/rules/local_rules.xml`.
5. Add the `<wodle>`, `<localfile>`, `<email_alerts>`, and `<integration>` blocks
   to `/var/ossec/etc/ossec.conf` on the master node.
6. Validate the configuration and restart: `/var/ossec/bin/wazuh-control restart`.
7. Watch `/var/ossec/logs/silent_agent_monitor.log` after the first run.

---

### Integration Testing

**Decision logic, offline.** No API, indexer, or manager needed:

```bash
/var/ossec/framework/python/bin/python3 /var/ossec/wodles/silent_agent_monitor.py --selftest
# selftest OK
```

It asserts that a 25h40m gap reports once and only once, that recovery reports
once with the duration measured from the last log before the gap, that an agent
inside the threshold stays quiet, and that an agent with no events at all is
treated as silent rather than skipped.

**End to end, against the live environment.** Run the check by hand:

```bash
/var/ossec/framework/python/bin/python3 /var/ossec/wodles/silent_agent_monitor.py
# Checked 12 agent(s) in 'Server': 0 silent, 0 event(s) written to /var/ossec/logs/silent_agents.json.
```

To force a notification without waiting a day, drop the threshold for one run
and watch the whole chain fire:

```bash
SAM_THRESHOLD_HOURS=0.05 /var/ossec/framework/python/bin/python3 \
  /var/ossec/wodles/silent_agent_monitor.py
tail -1 /var/ossec/logs/silent_agents.json
tail -f /var/ossec/logs/alerts/alerts.log | grep -A5 100121
```

Delete `/var/ossec/var/silent_agents_state.json` afterwards so the test does not
leave agents marked silent. Running with the real threshold again produces the
`RESTORED` notification, which is a useful way to confirm the recovery path and
the Telegram formatting in one go.

**Rules only**, without running the script:

```bash
echo '{"integration":"silent-agent-monitor","event_status":"SILENT","agent_id":"152","agent_name":"File2","last_log":"2026-08-18 08:35:12 CEST","no_logs_for":"25h 40m"}' \
  | /var/ossec/bin/wazuh-logtest
```

---

### Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `No events found for any of the N agents` in the script log, and no alerts | Deliberate safety stop. Every agent silent at once is almost always a wrong index pattern or wrong indexer credentials, not a real outage, so the script refuses to send the storm. Check `SAM_INDEX_PATTERN` and the indexer user. |
| `Indexer query failed` or `Wazuh API query failed` | The run exits without touching the state, so nothing is reported as silent or as recovered on the strength of a failed query. Check connectivity and credentials. |
| Records in `silent_agents.json` but no alerts | The `<localfile>` block is missing, points elsewhere, or sits on a node that is not running the script. Confirm with `grep silent_agents /var/ossec/logs/ossec.log`. |
| Alerts fire but no email | Global email is not enabled, or the rules lost `<options>alert_by_email</options>`. Check `/var/ossec/logs/ossec.log` for `wazuh-maild`. |
| Alerts fire but no Telegram message | Check `/var/ossec/logs/integrations.log` for a line from `custom-server-telegram`, then `grep integrator /var/ossec/logs/ossec.log`. A missing chat ID or hook URL, or an HTTP error from the bot API, is logged with the rule ID. |
| `Permission denied` from integratord | The integration runs as the `wazuh` user. Any path the script writes, including a custom `TELEGRAM_LOG`, must be writable by it. |
| `Failure to read rule 100121. Field 'status' is static` | The rule was edited to match `status` instead of `event_status`. `status` is a reserved Wazuh field name. |
| A healthy agent is reported silent | It produced no *alerts* within the threshold. Point `SAM_INDEX_PATTERN` at `wazuh-archives-*`, or raise the threshold. |
| Every agent reported again after a manager rebuild | The state file was lost, so the first run after it re-reports the conditions that are still true. One repeat, then quiet again. |

---

### Verification

Run end to end on a Wazuh 4.14.6 single-node server (manager, indexer and
dashboard on one host) with three agents in a `Server` group:

| Check | Result |
| --- | --- |
| `--selftest` on the embedded interpreter | Passes: single alert, single recovery, correct durations, silence on missing data. |
| Group lookup | The `never_connected` agent and agent `000` are excluded; the two real agents are checked. |
| Silence detection | An agent whose newest indexed event was 30 hours old produced one `SILENT` record reading `30h`. |
| Repeat suppression | Three further runs with the condition unchanged produced no further records. |
| Recovery | A fresh event produced one `RESTORED` record reading `30h`, measured from the last log before the gap. |
| Ingestion and rules | The record reached `alerts.json` through the `<localfile>` block as rule 100121, level 12, `mail: true`, with the description fully interpolated. |
| Telegram | `wazuh-integratord` invoked the integration and delivered both formatted messages, captured against a local HTTP endpoint standing in for the bot API. |
| Email | Both rules produced a real email through a local Postfix relay, accepted by the upstream server (`dsn=2.0.0, status=sent`). The stock `full` format carries every field of the record, decoded one per line, under the subject `Wazuh notification - <manager> - Alert level 12`. |
| Wrong index pattern | The safety stop fired: exit code 1, no state written, no alerts sent, and a log line naming the setting to check. |
| Wodle schedule | `wazuh-modulesd` ran the command on its interval, one run per interval, with the output ignored. |

---

### Design Notes

- **One indexer query per run, not one per agent.** A single `terms`
  aggregation on `agent.id` with a `max` on `@timestamp` returns the last event
  time for every agent at once, so the cost does not grow with the fleet.
- **No custom decoder.** JSON lines plus `<log_format>json</log_format>` gives
  fully decoded fields for free, which also removes the dependency on a working
  local syslog daemon that a `logger`-based approach carries.
- **Standard library only.** `urllib.request` instead of `requests`, so the
  script runs on the embedded interpreter and on the system Python with no
  packaging step.
- **Missing data is silence, not a skip.** An agent with no events at all in the
  lookback window is the worst case, not a case to ignore.
- **The state file is written atomically** with a temporary file and a rename,
  so an interrupted run cannot leave the state truncated.

---

### Sources

- [Wazuh - command wodle](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html)
- [Wazuh - localfile configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)
- [Wazuh - integration configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html)
- [Wazuh - granular email alerts](https://documentation.wazuh.com/current/user-manual/manager/manual-email-report/index.html)
- [Wazuh - rules syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
- [Wazuh API - agents](https://documentation.wazuh.com/current/user-manual/api/reference.html#tag/Agents)
- [Wazuh - archiving alerts and events](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html)
