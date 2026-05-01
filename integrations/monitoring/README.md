# Wazuh Monitoring Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
    * [Using the Integration Files](#using-the-integration-files)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Sources](#sources)

---

### Introduction

This integration provides an automated health monitoring solution for Wazuh environments. It runs a comprehensive set of checks against the Wazuh Manager, Indexer, and Dashboard, then sends alerts via Slack and email when issues are detected. The goal is to proactively surface configuration problems, resource constraints, and service failures before they impact security operations.

---

### Prerequisites

* Wazuh Manager, Indexer, and Dashboard installed and running
* Root access on the Wazuh server
* `systemctl` available (required for Filebeat service check)
* `filebeat` in PATH (required for output connectivity check)
* A Slack webhook URL (for Slack notifications)
* SMTP credentials (for email notifications)

---

### Installation and Configuration

#### Using the Integration Files

The project is composed of the following files:

```
monitoring/
├── monitoring.py           # Main health check script (15+ checks)
├── slack_notifier.py       # Sends Slack alerts via webhook
├── email_notifier.py       # Sends HTML email alerts via SMTP
├── wrapper.sh              # Entry point — runs all three scripts in sequence
└── health-checker.secrets  # Credentials file (chmod 600, root-owned)
```

**1. Copy scripts to the server:**

```bash
cp monitoring.py slack_notifier.py email_notifier.py wrapper.sh /opt/scripts/
```

**2. Set execute permissions:**

```bash
chmod +x /opt/scripts/monitoring.py
chmod +x /opt/scripts/slack_notifier.py
chmod +x /opt/scripts/email_notifier.py
chmod +x /opt/scripts/wrapper.sh
```

**3. Install Python dependencies** *(only if needed — all checks use APIs by default):*

```bash
pip3 install requests psutil
```

**4. Create the secrets file:**

```bash
cat > /etc/health-checker.secrets << EOF
MANAGER_USER=wazuh-admin
MANAGER_PASS=your_manager_password
INDEXER_USER=admin
INDEXER_PASS=your_indexer_password
EOF

chmod 600 /etc/health-checker.secrets
chown root:root /etc/health-checker.secrets
```

| Key | Description |
|-----|-------------|
| `MANAGER_USER` | Wazuh Manager API username |
| `MANAGER_PASS` | Wazuh Manager API password |
| `INDEXER_USER` | Wazuh Indexer username |
| `INDEXER_PASS` | Wazuh Indexer password |

> Credentials can also be passed as environment variables with the same names. Environment variables take priority over the file.

**5. Configure notification settings:**

*Slack* — edit `slack_notifier.py` and set your webhook URL:

```python
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

*Email* — edit `email_notifier.py` and set your SMTP credentials:

```python
SMTP_USER = "you@gmail.com"
SMTP_PASS = "your_app_password"   # Gmail App Password (not your account password)
DESTINATARIO = "recipient@example.com"
```

---

### Integration Steps

`wrapper.sh` orchestrates the full workflow in sequence:

1. **`monitoring.py`** connects to the Wazuh stack, runs all checks, and appends a JSON result to `/var/log/health-checker.json`.
2. **`slack_notifier.py`** reads the last log entry and posts a Slack message for any check with `notify: true`.
3. **`email_notifier.py`** reads the same log entry and sends an HTML email report with the flagged issues.

**Run manually:**

```bash
./wrapper.sh
# or
bash /opt/scripts/wrapper.sh
```

**Schedule with cron (recommended — every hour as root):**

```bash
crontab -e
0 * * * * /opt/scripts/wrapper.sh >> /var/log/health-checker-cron.log 2>&1
```

**Run with custom options** — `monitoring.py` accepts CLI flags to override all defaults:

```bash
python3 /opt/scripts/monitoring.py \
  --manager-url https://localhost:55000 \
  --indexer-url https://localhost:9200 \
  --dashboard-url https://localhost:443 \
  --secrets-file /etc/health-checker.secrets \
  --disk-threshold 80 \
  --shard-threshold 85 \
  --manager-nodes "10.0.0.1,10.0.0.2,10.0.0.3" \
  --indexer-nodes "10.0.0.1,10.0.0.2,10.0.0.3"
```

| Flag | Default | Description |
|------|---------|-------------|
| `--manager-url` | `https://localhost:55000` | Wazuh Manager API URL |
| `--indexer-url` | `https://localhost:9200` | Wazuh Indexer URL |
| `--dashboard-url` | `https://localhost:443` | Wazuh Dashboard URL |
| `--secrets-file` | `/etc/health-checker.secrets` | Path to credentials file |
| `--disk-path` | `/` | Filesystem path to check |
| `--disk-threshold` | `75` | Disk usage % that triggers alert |
| `--shard-threshold` | `80` | Active shards % of limit that triggers alert |
| `--log-file` | `/var/log/health-checker.json` | Output log path |
| `--jvm-options` | `/etc/wazuh-indexer/jvm.options` | JVM config file path |
| `--manager-host` | `localhost` | Host for TCP port checks |
| `--ports` | `1514,1515` | Comma-separated ports to check |
| `--manager-nodes` | *(empty)* | Manager cluster node IPs (skips check if empty) |
| `--indexer-nodes` | *(empty)* | Indexer cluster node IPs (skips check if empty) |
| `--retention-ism-days` | `90` | Default ISM retention days (fallback) |
| `--retention-alerts-days` | `365` | Default local log retention target |
| `--deploy-mode` | `bare-metal` | Installation type |
| `--node-role` | `all` | Define node role to run specific checks |

The following checks are performed:

| # | Check | Alert Condition |
|---|-------|----------------|
| 1 | Manager API availability | Connection failure or auth error |
| 2 | Indexer API / cluster health | Unreachable or non-200 response |
| 3 | Dashboard accessibility | Unreachable |
| 4 | Disk space usage | ≥ 75% used (configurable) |
| 5 | Shards per node configuration | Informational |
| 6 | Active shards vs. limit | ≥ 80% of shard limit (configurable) |
| 7 | JVM Xms/Xmx vs. system RAM | Heap below 50% of RAM or exceeds RAM |
| 8 | Unassigned shards | Any unassigned shards found |
| 9 | TCP port reachability (1514, 1515) | Port closed or unreachable |
| 10 | Agent summary | Informational (active/disconnected/pending) |
| 11 | ISM policies configured | No policies found |
| 12 | Cron jobs for log rotation | Missing rotation for alerts or archives |
| 13 | Retention feasibility | Projected disk/shard usage exceeds limits |
| 14 | Filebeat service status | Service not active |
| 15 | Filebeat output connectivity | `filebeat test output` fails |
| 16 | Manager cluster nodes *(optional)* | Node missing or not Connected |
| 17 | Indexer cluster nodes *(optional)* | Node missing from cluster |

Results are appended as newline-delimited JSON to `/var/log/health-checker.json`:

```json
{
  "timestamp": "2025-03-03T12:00:00+00:00",
  "notify": true,
  "checks": {
    "manager_api": { "status": "ok", "notify": false, "api_version": "4.x.x" },
    "disk_space":  { "status": "warning", "notify": true, "used_pct": 78.5 }
  }
}
```

`notify: true` at the top level means at least one check requires attention.

---

### Integration Testing

**1. Run the script manually and check the log output:**

```bash
bash /opt/scripts/wrapper.sh
cat /var/log/health-checker.json | tail -1 | python3 -m json.tool
```

**2. Verify a Slack notification is received** by temporarily lowering a threshold (e.g., set `--disk-threshold 1`) and re-running:

```bash
python3 /opt/scripts/monitoring.py --disk-threshold 1
python3 /opt/scripts/slack_notifier.py
```

**3. Check the Wazuh logs** to confirm the script runs without errors:

```bash
cat /var/log/health-checker-cron.log
```

**4. Expected output** — a JSON entry in `/var/log/health-checker.json` per run, and a Slack/email message when any check returns `"status": "warning"`.

---

### Sources

* [Wazuh Documentation](https://documentation.wazuh.com/)
* [Wazuh API Reference](https://documentation.wazuh.com/current/user-manual/api/reference.html)
* [Slack Incoming Webhooks](https://api.slack.com/messaging/webhooks)
