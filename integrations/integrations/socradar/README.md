# SOCRadar

## About

[SOCRadar](https://socradar.io) is an Extended Threat Intelligence (XTI) platform that provides Digital Risk Protection, Attack Surface Management, and Threat Intelligence capabilities. This integration enables automatic ingestion of SOCRadar incident alerts into Wazuh SIEM.

## Integration Overview

| Component | Description |
|-----------|-------------|
| **Type** | Wodle command + Custom integration |
| **Data flow** | Bidirectional (SOCRadar → Wazuh, Wazuh → SOCRadar) |
| **API** | SOCRadar Incident API v4 |
| **Compatibility** | Wazuh 4.x |
| **Dependencies** | Python 3.6+ (stdlib only, no pip packages) |

### How It Works

After a one-time installation, the integration runs fully automatically:

1. **Inbound (SOCRadar → Wazuh):** A wodle command runs every 1 minute, fetches new incidents from SOCRadar API v4 using epoch timestamps, and outputs JSON to stdout. Wazuh decodes the JSON and generates alerts based on severity-mapped rules.

2. **Outbound (Wazuh → SOCRadar):** When a SOCRadar alert triggers in Wazuh, the custom integration sends feedback to SOCRadar — auto-tagging incidents as `wazuh-ingested`, posting Wazuh context as comments, and optionally updating incident status/severity.

No cron jobs, scheduled tasks, or manual triggers are needed. The integration runs continuously as long as the Wazuh Manager service is active.

## Contents

```
socradar/
├── ruleset/
│   ├── rules/
│   │   └── 0910-socradar_rules.xml       # 16 Wazuh rules (IDs 100800-100822)
│   └── decoders/
│       └── 0910-socradar_decoders.xml     # JSON decoder for SOCRadar events
├── wodle/
│   ├── socradar                           # Shell launcher wrapper
│   └── socradar.py                        # Incident fetcher (epoch time, reverse pagination)
├── integration/
│   ├── custom-socradar                    # Bidirectional integration launcher
│   └── custom-socradar.py                 # SOCRadar feedback integration
├── install.sh                             # One-click installer
├── socradar.conf.template                 # Configuration template
└── README.md
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

The installer prompts for your SOCRadar Company ID and API Key, then automatically:
- Copies all files to correct Wazuh directories
- Sets permissions (`root:wazuh`, `750`/`640`)
- Creates configuration with your credentials
- Injects wodle + integration blocks into `ossec.conf`
- Restarts Wazuh Manager

### Manual Install

#### 1. Copy files

```bash
# Wodle
mkdir -p /var/ossec/wodles/socradar
cp wodle/socradar /var/ossec/wodles/socradar/
cp wodle/socradar.py /var/ossec/wodles/socradar/

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
  "fetch_status": "OPEN",
  "initial_lookback_hours": 24,
  "interval_seconds": 60
}
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
| `fetch_status` | string | `OPEN` | Filter: OPEN, RESOLVED, etc. |
| `min_severity` | string | `null` | Minimum severity filter |
| `alarm_main_types` | array | `[]` | Filter by main type (empty = all) |
| `initial_lookback_hours` | integer | `24` | Hours to look back on first run |
| `interval_seconds` | integer | `60` | Fetch interval in seconds |

## Rule Reference

| Rule ID | Level | Description |
|---------|-------|-------------|
| 100800 | 5 | Base SOCRadar incident |
| 100801 | 3 | LOW severity |
| 100802 | 7 | MEDIUM severity |
| 100803 | 10 | HIGH severity |
| 100804 | 13 | CRITICAL severity |
| 100810 | 12 | Dark Web detection |
| 100811 | 13 | Stolen credentials |
| 100812 | 8 | Attack Surface Management |
| 100813 | 9 | Vulnerability detected |
| 100814 | 10 | Brand Protection |
| 100815 | 11 | Fraud Protection |
| 100816 | 10 | Supply Chain Intelligence |
| 100820 | 12 | Malware detected |
| 100821 | 10 | Compromised IPs |
| 100822 | 10 | Compromised emails |

## Viewing Alerts

In Wazuh Dashboard:

1. Navigate to **Threat Intelligence → Threat Hunting**
2. Search: `rule.groups:socradar`
3. Set time range to **Last 24 hours**

## Monitoring

```bash
# Fetcher logs
tail -f /var/ossec/logs/socradar-wodle.log

# Check alerts
grep socradar /var/ossec/logs/alerts/alerts.json | tail

# State file
cat /var/ossec/var/socradar_state.json
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| SSL certificate error | SSL verification is disabled by default for proxy environments |
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
- [SOCRadar API Documentation](https://docs.socradar.io)
- [Wazuh Custom Integration Guide](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)

## Author

SOCRadar Integration Team — integrations@socradar.io
