# SOCRadar

## About

[SOCRadar](https://socradar.io) is an Extended Threat Intelligence (XTI) platform that provides Digital Risk Protection, Attack Surface Management, and Threat Intelligence capabilities. This integration enables automatic ingestion of SOCRadar incident alerts into Wazuh SIEM.

## Integration Overview

| Component | Description |
|-----------|-------------|
| **Type** | Wodle command + Custom integration |
| **Data flow** | Bidirectional (SOCRadar → Wazuh, Wazuh → SOCRadar) |
| **API** | SOCRadar Incident API v4 (fetch) + Alarm feedback endpoints (tag/comment/status/severity) |
| **Compatibility** | Wazuh 4.x |
| **Dependencies** | Python 3.6+ (stdlib only, no pip packages) |

### How It Works

After a one-time installation, the integration runs fully automatically:

1. **Inbound (SOCRadar → Wazuh):** A wodle command runs every 1 minute, fetches new incidents from SOCRadar API v4 using epoch timestamps, and outputs JSON to stdout. Wazuh decodes the JSON and generates alerts based on severity-mapped rules.

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
- Sets permissions (`root:wazuh`, `750`/`640`)
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
  "max_pages": 10,

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

Also create the state file used for deduplication:

```bash
sudo touch /var/ossec/var/socradar_state.json
# Group is typically "wazuh" (or "ossec" on some installs)
sudo chown root:wazuh /var/ossec/var/socradar_state.json
sudo chmod 660 /var/ossec/var/socradar_state.json
echo '{}' | sudo tee /var/ossec/var/socradar_state.json >/dev/null
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

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `company_id` | string | *required* | SOCRadar Company ID |
| `api_key` | string | *required* | SOCRadar API Key |
| `user_email` | string | `null` | Email to attribute comments in SOCRadar (used by the outbound integration) |
| `tls_verify` | boolean | `true` | Verify TLS certificates/hostnames (set `false` only if you must) |
| `ca_bundle_path` | string | `null` | Optional CA bundle path (PEM) for proxy/self-signed environments |
| `verbose` | boolean | `false` | Enable verbose DEBUG logging (to `/var/ossec/logs/socradar-wodle.log`) |
| `log_level` | string | `INFO` | Log level: `ERROR`, `WARN`, `INFO`, `DEBUG` (overrides `verbose`) |
| `fetch_status` | string | `OPEN` | Filter: OPEN, RESOLVED, etc. |
| `fetch_limit` | integer | `100` | Page size per API call (capped at 100 by the script) |
| `min_severity` | string | `null` | Minimum severity filter |
| `alarm_main_types` | array | `[]` | Filter by main type (empty = all) |
| `initial_lookback_hours` | integer | `24` | Hours to look back on first run |
| `max_pages` | integer | `null` | Optional safety limit for pagination (useful during first runs) |

Outbound (Wazuh → SOCRadar) settings are under `integration` in the same config file:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `integration.auto_tag` | boolean | `true` | Add the `wazuh-ingested` tag to the alarm |
| `integration.post_wazuh_context` | boolean | `true` | Post rule/level/context as a SOCRadar comment |
| `integration.auto_close_rule_ids` | array[int] | `[]` | If Wazuh rule ID matches, close as FALSE_POSITIVE |
| `integration.auto_resolve_rule_ids` | array[int] | `[]` | If Wazuh rule ID matches, resolve alarm |
| `integration.escalate_threshold` | integer | `12` | If Wazuh alert level >= threshold, severity may be escalated |
| `integration.auto_ask_analyst` | boolean | `false` | Ask an analyst assignment for high-severity alerts |
| `integration.ask_analyst_threshold` | integer | `10` | Wazuh level threshold for ask-analyst action |

## Rule Reference

| Rule ID | Level | Description |
|---------|-------|-------------|
| 100800 | 5 | Base SOCRadar incident |
| 100801 | 3 | LOW severity |
| 100802 | 7 | MEDIUM severity |
| 100803 | 10 | HIGH severity |
| 100804 | 13 | CRITICAL severity |
| 100810 | 12 | Deep & Dark Web Monitoring |
| 100811 | 13 | Stolen credentials |
| 100812 | 8 | Attack Surface Management |
| 100813 | 9 | Vulnerability Monitoring |
| 100814 | 10 | Brand Protection |
| 100815 | 11 | Fraud Protection |
| 100816 | 10 | Supply Chain Intelligence |
| 100820 | 12 | Malware detected |
| 100821 | 10 | Compromised IPs |
| 100822 | 10 | Compromised emails |

## Viewing Alerts

In Wazuh Dashboard:

1. Navigate to **Threat Intelligence → Threat Hunting**
  (On some Wazuh versions this is under **Security Events**)
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

| Issue | Solution |
|-------|----------|
| SSL certificate error | Provide `ca_bundle_path` to your CA bundle (preferred) or set `tls_verify: false` (not recommended) |
| Timeout on fetch | Increase `<timeout>` in ossec.conf (default: 300s) |
| No alerts in dashboard | Test with `wazuh-logtest` — see below |
| Exit code 1 | Verify `/var/ossec/etc/socradar.conf` is valid JSON |
| Duplicates | Reset: `echo '{}' > /var/ossec/var/socradar_state.json` |

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
