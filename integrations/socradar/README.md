# SOCRadar

## About

[SOCRadar](https://socradar.io) is an Extended Threat Intelligence (XTI) platform that provides Digital Risk Protection, Attack Surface Management, and Threat Intelligence capabilities. This integration enables automatic ingestion of SOCRadar incident alerts into Wazuh SIEM.

## Integration Overview

| Component         | Description                                                                               |
|-------------------|-------------------------------------------------------------------------------------------|
| **Type**          | Wodle command + Custom integration                                                        |
| **Data flow**     | Bidirectional (SOCRadar → Wazuh, Wazuh → SOCRadar)                                        |
| **API**           | SOCRadar Incident API v4 (fetch) + Alarm feedback endpoints (tag/comment/status/severity) |
| **Compatibility** | Wazuh 4.x                                                                                 |
| **Dependencies**  | Python 3.6+ (stdlib only, no pip packages)                                                |

### How It Works

After a one-time installation, the integration runs fully automatically:

1. **Inbound (SOCRadar → Wazuh):** A wodle command runs every 1 minute, fetches incidents from SOCRadar API v4 using epoch timestamps (`last_run` → now). Periodically it also re-queries a catch-up window (`now − fetch_overlap_seconds` → now) so late-visible alarms are not skipped. First-run lookback and catch-up are uncapped in meaning but fetch at most `max_catchup_pages` HTTP pages per tick (resume the rest). Lookback stamps `last_run` when page 1 succeeds so later resume ticks also incremental-fetch. Deduplication uses `seen_alarm_ids` in the state file. Wazuh decodes the JSON and generates alerts based on severity-mapped rules.
2. **Outbound (Wazuh → SOCRadar):** When a SOCRadar alert triggers in Wazuh, the custom integration sends feedback to SOCRadar — auto-tagging incidents as `wazuh-ingested`, posting Wazuh context as comments, and optionally updating incident status/severity.

No cron jobs, scheduled tasks, or manual triggers are needed. The integration runs continuously as long as the Wazuh Manager service is active.

## Contents

```
.
├── install.sh                             # One-click installer
├── socradar.conf.template                 # Configuration template
├── integration/
│   ├── custom-socradar                    # Wazuh integratord shell wrapper
│   └── custom-socradar.py                 # Wazuh → SOCRadar feedback integration
├── wodles/
│   ├── socradar                           # Wodle shell wrapper
│   └── socradar.py                        # SOCRadar → Wazuh fetcher (epoch time, reverse pagination)
└── ruleset/
  ├── decoders/
  │   └── 0910-socradar_decoders.xml     # JSON decoder for SOCRadar events
  └── rules/
    └── 0910-socradar_rules.xml        # Wazuh rules (IDs 100800-100822)
```

## Prerequisites

- Wazuh Manager 4.x (tested on 4.14.3)
- Python 3.6+ (no external packages required)
- SOCRadar account with API access
- SOCRadar API Key and Company ID
- Outbound HTTPS access to `platform.socradar.com`

## Installation

### One-Click Install (Recommended)

```bash
sudo ./install.sh
```

The installer prompts for your SOCRadar Company ID and API Key, and also:

- Optional `user_email` (used when posting SOCRadar comments)
- Initial lookback hours (first run only)
- Fetch interval in minutes (wodle interval)

Then it automatically:

- Copies all files to correct Wazuh directories
- Sets permissions (`root:wazuh`, `750`/`640` on scripts and config; `660` on the two state files)
- Creates configuration with your credentials
- Injects wodle + integration blocks into `ossec.conf`
- Restarts Wazuh Manager

If your Wazuh is not installed under `/var/ossec`, set `WAZUH_HOME`:

```bash
sudo WAZUH_HOME=/custom/path ./install.sh
```

### Manual Install

#### 1. Copy files

```bash
# Wodle
mkdir -p /var/ossec/wodles/socradar
cp wodles/socradar /var/ossec/wodles/socradar/
cp wodles/socradar.py /var/ossec/wodles/socradar/

# Integration
cp integration/custom-socradar /var/ossec/integrations/
cp integration/custom-socradar.py /var/ossec/integrations/

# Ruleset
cp ruleset/decoders/0910-socradar_decoders.xml /var/ossec/etc/decoders/
cp ruleset/rules/0910-socradar_rules.xml /var/ossec/etc/rules/
```

#### 2. Set permissions

```bash
chmod 750 /var/ossec/wodles/socradar/socradar*
chmod 750 /var/ossec/integrations/custom-socradar*
chown root:wazuh /var/ossec/wodles/socradar/*
chown root:wazuh /var/ossec/integrations/custom-socradar*
chown root:wazuh /var/ossec/etc/decoders/0910-socradar*
chown root:wazuh /var/ossec/etc/rules/0910-socradar*
```

#### 3. Create configuration

Create `/var/ossec/etc/socradar.conf`:

```json
{
  "company_id": "YOUR_COMPANY_ID",
  "api_key": "YOUR_API_KEY",
  "user_email": "your-email@company.com",

  "tls_verify": true,
  "ca_bundle_path": null,

  "verbose": false,
  "log_level": "INFO",

  "fetch_status": "OPEN",
  "fetch_limit": 100,
  "min_severity": null,
  "alarm_main_types": [],
  "initial_lookback_hours": 24,
  "fetch_overlap_seconds": 180,
  "max_pages": 10,
  "max_catchup_pages": 15,
  "http_timeout_seconds": 120,
  "catchup_http_timeout_seconds": 15,
  "http_retries": 0,
  "page_sleep_seconds": 2,
  "lookback_page_sleep_seconds": 2,
  "max_retry_pages": 25,
  "max_retry_pages_per_run": 1,
  "retry_backoff_seconds": 60,
  "retry_backoff_max_seconds": 3600,

  "integration": {
    "auto_tag": true,
    "post_wazuh_context": true,
    "auto_close_rule_ids": [],
    "auto_resolve_rule_ids": [],
    "escalate_threshold": 12,
    "auto_ask_analyst": false,
    "ask_analyst_threshold": 10
  }
}
```

Also create the state files used for inbound dedup and outbound comment idempotency:

```bash
sudo touch /var/ossec/var/socradar_state.json /var/ossec/var/socradar_outbound_state.json
# Group is typically "wazuh" (or "ossec" on some installs)
sudo chown root:wazuh /var/ossec/var/socradar_state.json /var/ossec/var/socradar_outbound_state.json
sudo chmod 660 /var/ossec/var/socradar_state.json /var/ossec/var/socradar_outbound_state.json
echo '{}' | sudo tee /var/ossec/var/socradar_state.json /var/ossec/var/socradar_outbound_state.json >/dev/null
```

#### 4. Update ossec.conf

Add before `</ossec_config>`:

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>socradar</tag>
  <command>/var/ossec/wodles/socradar/socradar</command>
  <interval>1m</interval>
  <ignore_output>no</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>300</timeout>
</wodle>

<integration>
  <name>custom-socradar</name>
  <group>socradar</group>
  <alert_format>json</alert_format>
</integration>
```

#### 5. Restart

```bash
sudo /var/ossec/bin/wazuh-control restart
```

## Configuration

| Parameter                      | Type    | Default                                       | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
|--------------------------------|---------|-----------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `company_id`                   | string  | *required*                                    | SOCRadar Company ID                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `api_key`                      | string  | *required*                                    | SOCRadar API Key                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `user_email`                   | string  | `null`                                        | Email to attribute comments in SOCRadar (used by the outbound integration)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `tls_verify`                   | boolean | `true`                                        | Verify TLS certificates/hostnames (set `false` only if you must)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `ca_bundle_path`               | string  | `null`                                        | Optional CA bundle path (PEM) for proxy/self-signed environments                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `verbose`                      | boolean | `false`                                       | Enable verbose DEBUG logging (to `/var/ossec/logs/socradar-wodle.log`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `log_level`                    | string  | `INFO`                                        | Log level: `ERROR`, `WARN`, `INFO`, `DEBUG` (overrides `verbose`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `fetch_status`                 | string  | *(omit)*                                      | If set (e.g. `OPEN`), sent as API `status` filter. If omitted, no status filter is applied. Installer sets `OPEN`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `fetch_limit`                  | integer | `100`                                         | Page size per API call (`DEFAULT_PAGE_SIZE`; hard-capped at 100)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `min_severity`                 | string  | `null`                                        | If set, sent as API `severities` query param (not a numeric minimum in code)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `alarm_main_types`             | array   | `[]`                                          | Filter by main type (empty = all)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `initial_lookback_hours`       | integer | `24`                                          | Hours to look back on first run. The window is the full lookback (not “latest 1,000”). First-run is uncapped like catch-up and is bounded per tick by `max_catchup_pages`. `last_run` is stamped to **now** when lookback page 1 succeeds; leftover older pages resume on later ticks while a short incremental (`last_run` → now) keeps live ingest current.                                                                                                                                                                                                                                                                                  |
| `fetch_overlap_seconds`        | integer | `180`                                         | Catch-up interval **and** window width — judged as **visibility wait**, not incremental API cost. Incremental runs stay `last_run` → `now` with no per-tick overlap. When this many seconds have passed since the last catch-up (or none has run yet), the same wodle also fetches `now − this value` → `now`. A late OPEN alarm (even ~10s of API lag) is invisible until the next catch-up — **up to 180s** on the shipped default. This is not free: catch-up re-walks the full window every tick, so cost scales linearly with the value (e.g. 900s costs 5x more API pages than 180s for identical alert output). Raise it if you need a longer recovery window; lower it (or set `0` to disable catch-up) to cut cost further. An alarm delayed longer than this window is still missed permanently. |
| `max_pages`                    | integer | `null` (code) / `10` (template and installer) | Optional page cap applied to **steady-state incremental** only (`last_run` → `now`). First-run lookback and catch-up do **not** remap `total_pages` (that would keep pages 10..1 and drop the oldest). Omitted or `null` means unlimited. Template and `install.sh` ship `10`.                                                                                                                                                                                                                                                                                                                                                                 |
| `max_catchup_pages`            | integer | `15`                                          | Per-run HTTP budget for uncapped windows (catch-up and first-run lookback). Walks the true last page first so oldest alarms are not dropped. On the **first** tick, page 1 consumes one slot (page 1 + 14 older pages). Resume ticks (`skip_page1`) still fetch 15 older pages. Remaining pages are stored in `window_resume` and drained on later ticks.                                                                                                                                                                                                                                                                                      |
| `http_timeout_seconds`         | integer | `120`                                         | HTTP request timeout per API call on incremental and incremental retries. A 120s incremental retry skips lookback / resume / catch-up in the same run.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `catchup_http_timeout_seconds` | integer | `15`                                          | HTTP timeout for first-run lookback, catch-up, `window_resume` drains, companion incremental on resume ticks, and uncapped retries. First uncapped tick: 15 HTTP (page 1 + 14 older) + 14 sleeps ≈ 253s, under modulesd 300s.                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `http_retries`                 | integer | `0`                                           | Extra in-run HTTP retries for transient errors (main retry mechanism is the state retry queue)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `page_sleep_seconds`           | number  | `2`                                           | Sleep between page requests during pagination (steady-state runs)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `lookback_page_sleep_seconds`  | number  | *(same as* `page_sleep_seconds`*)*            | Sleep between pages on the first run; defaults to `page_sleep_seconds`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `max_retry_pages`              | integer | `25`                                          | Max failed pages kept in the persistent retry queue (code default; legacy key `max_retry_windows` also accepted)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `max_retry_pages_per_run`      | integer | `1`                                           | How many queued failed pages to attempt per run                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `retry_backoff_seconds`        | integer | `60`                                          | Base backoff for queued page retries (exponential)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `retry_backoff_max_seconds`    | integer | `3600`                                        | Maximum backoff for queued page retries                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |

Outbound (Wazuh → SOCRadar) settings are under `integration` in the same config file:

| Key                                 | Type       | Default | Description                                                                                                                                                                                             |
|-------------------------------------|------------|---------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `integration.auto_tag`              | boolean    | `true`  | Add the `wazuh-ingested` tag to the alarm (skipped if the tag is already present on the alert payload)                                                                                                  |
| `integration.post_wazuh_context`    | boolean    | `true`  | Post rule/level/context as a SOCRadar comment. Skipped if `alarm_id` is already in `/var/ossec/var/socradar_outbound_state.json` (`commented_alarm_ids`). Independent of `auto_tag` / `wazuh-ingested`. |
| `integration.auto_close_rule_ids`   | array[int] | `[]`    | If Wazuh rule ID matches, close as FALSE_POSITIVE                                                                                                                                                       |
| `integration.auto_resolve_rule_ids` | array[int] | `[]`    | If Wazuh rule ID matches, resolve alarm                                                                                                                                                                 |
| `integration.escalate_threshold`    | integer    | `12`    | If Wazuh alert level >= threshold, severity may be escalated                                                                                                                                            |
| `integration.auto_ask_analyst`      | boolean    | `false` | Ask an analyst assignment for high-severity alerts                                                                                                                                                      |
| `integration.ask_analyst_threshold` | integer    | `10`    | Wazuh level threshold for ask-analyst action                                                                                                                                                            |

## Rule Reference

| Rule ID | Level | Description                |
|---------|-------|----------------------------|
| 100800  | 5     | Base SOCRadar incident     |
| 100801  | 3     | LOW severity               |
| 100802  | 7     | MEDIUM severity            |
| 100803  | 10    | HIGH severity              |
| 100804  | 13    | CRITICAL severity          |
| 100810  | 12    | Deep & Dark Web Monitoring |
| 100811  | 13    | Stolen credentials         |
| 100812  | 8     | Attack Surface Management  |
| 100813  | 9     | Vulnerability Monitoring   |
| 100814  | 10    | Brand Protection           |
| 100815  | 11    | Fraud Protection           |
| 100816  | 10    | Supply Chain Intelligence  |
| 100820  | 12    | Malware detected           |
| 100821  | 10    | Compromised IPs            |
| 100822  | 10    | Compromised emails         |

## Viewing Alerts

In Wazuh Dashboard:

1. Navigate to **Threat Intelligence → Threat Hunting** (On some Wazuh versions this is under **Security Events**)
2. Search: `rule.groups:socradar`
3. Set time range to **Last 24 hours**

## Monitoring

```bash
# Fetcher logs
tail -f /var/ossec/logs/socradar-wodle.log

# Outbound integration logs (when SOCRadar rules trigger)
tail -f /var/ossec/logs/socradar-integration.log

# Check alerts
grep socradar /var/ossec/logs/alerts/alerts.json | tail

# State file
cat /var/ossec/var/socradar_state.json
```

To temporarily enable more detailed HTTP/debug logging for a manual run:

```bash
python3 /var/ossec/wodles/socradar/socradar.py --verbose
# or
SOCRADAR_LOG_LEVEL=DEBUG python3 /var/ossec/wodles/socradar/socradar.py
```

## Troubleshooting

| Issue                  | Solution                                                                                            |
|------------------------|-----------------------------------------------------------------------------------------------------|
| SSL certificate error  | Provide `ca_bundle_path` to your CA bundle (preferred) or set `tls_verify: false` (not recommended) |
| Timeout on fetch       | Increase `<timeout>` in ossec.conf (default: 300s)                                                  |
| No alerts in dashboard | Test with `wazuh-logtest` — see below                                                               |
| Exit code 1            | Verify `/var/ossec/etc/socradar.conf` is valid JSON                                                 |
| Duplicates             | Reset: `echo '{}' > /var/ossec/var/socradar_state.json`                                             |

### Testing decoder/rules

```bash
echo '{"socradar":{"source":"incident_api_v4","alarm_id":99999,"risk_level":"HIGH","alarm_asset":"test","generic_title":"Test","main_type":"Attack Surface Management"}}' | /var/ossec/bin/wazuh-logtest
```

Expected: Rule 100803, Level 10.

## References

- [SOCRadar Platform](https://platform.socradar.com)
- [Wazuh Custom Integration Guide](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)

## Author

SOCRadar Integration Team — integrations@socradar.io