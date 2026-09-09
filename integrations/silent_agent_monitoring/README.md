# Silent Agent Monitoring

## Table of Contents
* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Integration Steps](#integration-steps)
    * [Add the integration files](#add-the-integration-files)
    * [Script configuration](#script-configuration)
    * [Wazuh manager configuration](#wazuh-manager-configuration)
    * [Add custom rules](#add-custom-rules)
    * [Email notifications](#email-notifications)
    * [Telegram notifications](#telegram-notifications)
* [Testing](#testing)
* [Troubleshooting](#troubleshooting)
* [Sources](#sources)

## Introduction
This script runs on the Wazuh manager and detects agents that are still registered, and often still active, while log ingestion from them has stopped.

For every agent of a target group it reads the timestamp of the most recent indexed event. When that timestamp is older than the threshold it appends a `SILENT` record to a local JSON log, and when events start arriving again it appends a `RESTORED` record. State is kept locally so an unchanged condition is reported once, not once per run.

The records are plain JSON lines ingested through a `<localfile>` block, so the built-in JSON decoder handles them and no custom decoder is needed. They trigger rules 100121 and 100122, which are routed to email and to Telegram.

## Prerequisites
- Wazuh manager 4.4 or later, with an API user that can read `/agents`.
- Wazuh indexer reachable from the manager, with a user that can search the alerts (or archives) indices.
- An agent group to monitor.
- The scripts use only the standard library, so the Wazuh embedded interpreter at `/var/ossec/framework/python/bin/python3` is enough and there is no `pip install` step.

In a cluster, install on the master node only: running the script on several nodes duplicates every notification and splits the state.

## Integration Steps

### Add the integration files
```
cp silent_agent_monitor.py /var/ossec/wodles/
cp custom-server-telegram custom-server-telegram.py /var/ossec/integrations/

chown root:wazuh /var/ossec/wodles/silent_agent_monitor.py /var/ossec/integrations/custom-server-telegram*
chmod 750 /var/ossec/wodles/silent_agent_monitor.py /var/ossec/integrations/custom-server-telegram*
```
A manager upgrade can replace the contents of `/var/ossec/wodles`, so keep a copy of the configured script outside `/var/ossec`.

### Script configuration
Edit the `CONFIGURATION` block at the top of `silent_agent_monitor.py`, or set the matching environment variables and leave the file untouched:

| Setting | Variable | Default |
| --- | --- | --- |
| Wazuh API URL | `SAM_API_URL` | `https://127.0.0.1:55000` |
| Wazuh API user / password | `SAM_API_USER`, `SAM_API_PASSWORD` | `wazuh-wui` / `CHANGE_ME` |
| Indexer URL | `SAM_INDEXER_URL` | `https://127.0.0.1:9200` |
| Indexer user / password | `SAM_INDEXER_USER`, `SAM_INDEXER_PASSWORD` | `admin` / `CHANGE_ME` |
| Index pattern | `SAM_INDEX_PATTERN` | `wazuh-alerts-*` |
| Agent groups | `--group`, `SAM_GROUP` | `Server` |
| Silence threshold, hours | `SAM_THRESHOLD_HOURS` | `24` |
| Lookback window, days | `SAM_LOOKBACK_DAYS` | `7` |
| State file | `SAM_STATE_FILE` | `/var/ossec/var/silent_agents_state.json` |
| Output log | `SAM_OUTPUT_LOG` | `/var/ossec/logs/silent_agents.json` |
| Script log | `SAM_SCRIPT_LOG` | `/var/ossec/logs/silent_agent_monitor.log` |
| Verify TLS certificates | `SAM_VERIFY_SSL` | `no` |

The groups are normally passed with `--group` from the wodle, so `ossec.conf` owns them and the script needs no edit to change them. The file holds credentials, so keep it root-owned and `chmod 750`. `SAM_LOOKBACK_DAYS` must stay larger than the threshold: it bounds the indexer query, and an agent with nothing inside it is reported as silent for "more than" that window.

The index pattern decides what counts as a log. `wazuh-alerts-*` is available everywhere but only sees alerts, so an agent that ships logs normally while producing no alert for a full day is reported as silent. `wazuh-archives-*` is the exact answer to "no logs received" but needs `<logall_json>` enabled and the archives indexed. Use archives when they are available; otherwise confirm that every agent in the group normally produces alerts within the threshold.

### Wazuh manager configuration
Add to `/var/ossec/etc/ossec.conf`:

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>silent-agent-monitor</tag>
  <command>/var/ossec/framework/python/bin/python3 /var/ossec/wodles/silent_agent_monitor.py --group Server,Windows</command>
  <interval>1h</interval>
  <run_on_start>yes</run_on_start>
  <timeout>300</timeout>
  <ignore_output>yes</ignore_output>
</wodle>

<localfile>
  <log_format>json</log_format>
  <location>/var/ossec/logs/silent_agents.json</location>
</localfile>
```
`--group` takes a comma-separated list, so one wodle covers several groups: `--group Server,Windows,DMZ`. Agents are deduplicated across them, so an agent in two of the listed groups is checked once and its record names both. A separate wodle per group also works, but each one then needs its own `SAM_STATE_FILE` and `SAM_OUTPUT_LOG`, because a run rewrites the whole state file.

One run per hour bounds detection lag and recovery lag to an hour each, at one indexer query per hour whatever the number of agents. With `run_on_start`, the first run after a restart can reach the API before it finishes starting and log `HTTP Error 500`; nothing is lost, because a failed run never writes state.

### Add custom rules
In the Wazuh dashboard go to Server Management > Rules > Add new rules file, name it `silent_agent_monitor-rules.xml`, add the content of `silent_agent_monitor-rules.xml` and save. Then restart the manager.

| Rule | Level | Fires when |
| --- | --- | --- |
| 100120 | 0 | Any record from this integration. Classification only. |
| 100121 | 12 | `event_status` is `SILENT`. |
| 100122 | 5 | `event_status` is `RESTORED`. |

The matched field is `event_status`, not `status`: `status` is a static Wazuh field name and a rule matching it fails to load. Both children carry `<options>alert_by_email</options>`, which forces the email regardless of the global `<email_alert_level>`; without it the level 5 recovery alert is dropped by the default threshold of 12. Move the IDs into a free range if 100120-100122 are already used.

### Email notifications
Global email must already be configured. Then route the two rules:

```xml
<email_alerts>
  <email_to>soc-team@example.com</email_to>
  <rule_id>100121,100122</rule_id>
  <do_not_delay />
  <format>full</format>
</email_alerts>
```
The `full` format prints the record's fields one per line, so the email already carries the agent name, the agent ID, the last log timestamp and the duration.

### Telegram notifications
Use the bundled script only when there is no Telegram integration yet:

```xml
<integration>
  <name>custom-server-telegram</name>
  <rule_id>100121,100122</rule_id>
  <api_key>&lt;CHAT_ID&gt;:&lt;BOT_TOKEN&gt;</api_key>
  <alert_format>json</alert_format>
</integration>

<!-- Filled in, as a sample -->
<integration>
  <name>custom-server-telegram</name>
  <rule_id>100121,100122</rule_id>
  <api_key>123123123123:8454124324:niwefn76t5safuef8s76tg</api_key>
  <alert_format>json</alert_format>
</integration>
```
`<api_key>` carries both values: the numeric chat ID, a colon, then the bot token. The script splits on that first colon, so the colon inside the token itself is preserved, and it builds the `sendMessage` URL from the token. No `<hook_url>` is needed. The same value can be given in `TELEGRAM_API_KEY` for a manual test run. The messages it produces:

```
⚠️ Server Logging Alert          ✅ Server Logging Restored
Name: File2                      Name: File2
Agent ID: 152                    Agent ID: 152
Status: No logs received         Status: Logs received
Last Log Received: ...           Restored At: ...
No Logs For: 25h 40m             No Logs Duration: 25h 40m
```

When a Telegram integration already exists, keep it and add `100121,100122` to its `<rule_id>` (or `silent_agent_monitoring` to its `<group>`). A dispatcher that maps dotted paths to labels needs one entry per event type, matching on the `server_silent` and `server_restored` rule groups, with the fields listed above; the `Status` line is `data.status_text`, so no literal is needed in the dispatcher.

`wazuh-integratord` runs integration scripts as the `wazuh` user, so any path the script writes, including a custom `TELEGRAM_LOG`, must be writable by it.

## Testing
Run the check by hand against the live environment:
```bash
/var/ossec/framework/python/bin/python3 /var/ossec/wodles/silent_agent_monitor.py --group Server
# Checked 12 agent(s) in 'Server': 0 silent, 0 event(s) written to /var/ossec/logs/silent_agents.json.
```

To force a notification without waiting, drop the threshold for one run:
```bash
SAM_THRESHOLD_HOURS=0.05 /var/ossec/framework/python/bin/python3 \
  /var/ossec/wodles/silent_agent_monitor.py --group Server
tail -1 /var/ossec/logs/silent_agents.json
tail -f /var/ossec/logs/alerts/alerts.log | grep -A5 100121
```
Running with the real threshold again produces the `RESTORED` notification, which confirms the recovery path and the message formatting in one go. Delete `/var/ossec/var/silent_agents_state.json` afterwards so the test does not leave agents marked silent.

The rules can be checked without running the script:
```bash
echo '{"integration":"silent-agent-monitor","event_status":"SILENT","agent_id":"152","agent_name":"File2","last_log":"2026-08-18 08:35:12 CEST","no_logs_for":"25h 40m"}' \
  | /var/ossec/bin/wazuh-logtest
```

## Troubleshooting
| Symptom | Cause and fix |
| --- | --- |
| `No events found for any of the N agents` and no alerts | Deliberate safety stop: every agent silent at once is almost always a wrong index pattern or wrong indexer credentials. Check `SAM_INDEX_PATTERN` and the indexer user. |
| `Indexer query failed` or `Wazuh API query failed` | The run exits without touching the state, so nothing is reported as silent or recovered on a failed query. Check connectivity and credentials. |
| `No agents in group(s) 'X'` | The group does not exist or is empty. Check with `/var/ossec/bin/agent_groups -l`. |
| Records in `silent_agents.json` but no alerts | The `<localfile>` block is missing, points elsewhere, or sits on a node that is not running the script. |
| Alerts fire but no email | Global email is not enabled, or the rules lost `<options>alert_by_email</options>`. Check `/var/ossec/logs/ossec.log` for `wazuh-maild`. |
| Alerts fire but no Telegram message | Check `/var/ossec/logs/integrations.log`. A missing or malformed `<api_key>`, or an HTTP error from the bot API, is logged with the rule ID. |
| `Field 'status' is static` | The rule was edited to match `status` instead of `event_status`. |
| A healthy agent is reported silent | It produced no alerts within the threshold. Point `SAM_INDEX_PATTERN` at `wazuh-archives-*`, or raise the threshold. |
| Every agent reported again after a manager rebuild | The state file was lost, so the first run re-reports the conditions that are still true. One repeat, then quiet again. |

## Sources
- [Wazuh - command wodle](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html)
- [Wazuh - localfile configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)
- [Wazuh - integration configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html)
- [Wazuh - granular email alerts](https://documentation.wazuh.com/current/user-manual/manager/manual-email-report/index.html)
- [Wazuh - rules syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
- [Wazuh API - agents](https://documentation.wazuh.com/current/user-manual/api/reference.html#tag/Agents)
- [Wazuh - archiving alerts and events](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html)
