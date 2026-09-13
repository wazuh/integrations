# Wazuh Monitoring Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
    * [Using the Integration Files](#using-the-integration-files)
* [Cluster topology](#cluster-topology)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Sources](#sources)

---

### Introduction

This integration provides an automated health monitoring solution for Wazuh environments. It runs a comprehensive set of checks against the Wazuh Manager, Indexer, and Dashboard, then sends alerts via Slack and email when issues are detected. The goal is to proactively surface configuration problems, resource constraints, and service failures before they impact security operations.

The script is installed on a **single server — the Wazuh Manager master node** — and reaches every other server of the deployment over the network. It supports all-in-one servers, split deployments, and fully distributed clusters with manager workers and multiple indexer nodes. See [Cluster topology](#cluster-topology).

---

### Prerequisites

* Wazuh Manager, Indexer, and Dashboard installed and running
* Root access on the Wazuh Manager master node (the only server where the script is installed)
* For multi-node deployments: network access from the master node to port `55000` on the manager workers, `9200` on the indexer nodes and `443` on the dashboards
* Credentials that are valid on every node of the deployment
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

> **The recommended path is `--init-config`** — see *Configuration* below. It writes a single file holding the credentials, the topology and the notification settings, so none of the steps above have to be done by hand.

**5. Configure notification settings:**

Add them to the same configuration file — nothing is edited in the Python code:

```sh
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@gmail.com
SMTP_PASS=your_app_password      # Gmail App Password, not your account password
EMAIL_TO=recipient@example.com
```

---

### Configuration

Everything the integration needs lives in **one file**, `/etc/wazuh-health-checker.conf` (root-owned, `chmod 600`), in a plain `KEY=VALUE` format. `wrapper.sh` sources that file and exports every value, so `monitoring.py` and both notifiers are configured from the same place.

#### Generate it automatically

```bash
./monitoring.py --init-config
```

This will:

1. read the credentials `wazuh-install.sh` generated, from `/root/wazuh-install-files.tar`, when that file is still present — otherwise prompt for them;
2. discover the cluster topology through `GET /cluster/nodes` (manager) and `_cat/nodes` (indexer);
3. write `/etc/wazuh-health-checker.conf` with `chmod 600`.

Then review the file and fill in the notification settings. Add `--yes` to run it without prompts.

A standalone manager is detected and reported as such — clustering being disabled is not an error, and the node lists are simply left empty.

An annotated template is shipped as `wazuh-health-checker.conf.example`.

#### Precedence

Highest first:

```
CLI flag  >  environment variable  >  /etc/wazuh-health-checker.conf
          >  /etc/health-checker.secrets (legacy)  >  built-in default
```

Existing installations keep working untouched: when the new file is absent, the legacy secrets file and the `DEFAULT_*_NODES` lists are still read.

#### Keys

| Key | Purpose |
|-----|---------|
| `MANAGER_USER` / `MANAGER_PASS` | Wazuh Manager API credentials |
| `INDEXER_USER` / `INDEXER_PASS` | Wazuh Indexer credentials |
| `MANAGER_NODES` / `INDEXER_NODES` / `DASHBOARD_NODES` | Comma-separated cluster topology. Empty = all-in-one |
| `MANAGER_URL` / `INDEXER_URL` / `DASHBOARD_URL` | Override the localhost defaults |
| `LOG_FILE` | Result log, read by both notifiers |
| `SLACK_WEBHOOK_URL` | Slack webhook |
| `SMTP_SERVER` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` / `EMAIL_TO` | Email notifications |
| `DISK_PATH`, `DISK_THRESHOLD`, `SHARD_THRESHOLD`, `RETENTION_ISM_DAYS`, `RETENTION_ALERTS_DAYS`, `ALERTS_TREND_DAYS`, `ALERTS_DROP_THRESHOLD`, `PORTS`, `DEPLOY_MODE`, `NODE_ROLE`, `K8S_NAMESPACE` | Optional tuning; each has a matching CLI flag |

---

### Cluster topology

`monitoring.py` is installed **only on the Wazuh Manager master node**. Every other server of the deployment (manager workers, indexer nodes, dashboards) is reached over the network, so their addresses have to be declared — normally by `--init-config`, which discovers them for you, or by editing three lines in the configuration file.

```sh
# /etc/wazuh-health-checker.conf
MANAGER_NODES=
INDEXER_NODES=
DASHBOARD_NODES=
```

The topology is discovered once and written to the file on purpose. Checks 16 and 17 answer *"is a node I expect missing from the cluster?"*, so the expected list has to be a declaration you reviewed — rediscovering it on every run would make a node that drops out vanish from both sides of the comparison, and the check could never fail.

The `DEFAULT_*_NODES` lists inside `monitoring.py` are still honoured as a fallback for existing installations.

Each entry accepts any of these forms:

| Entry | Resolves to |
|-------|-------------|
| `10.0.0.11` | `https://10.0.0.11:<service default port>` |
| `10.0.0.11:9200` | `https://10.0.0.11:9200` |
| `https://indexer-1:9200` | used verbatim |
| `http://10.0.0.11:9200` | used verbatim (plain HTTP) |

Default ports are `55000` for the Manager API, `9200` for the Indexer and `443` for the Dashboard.

> The credentials in `/etc/wazuh-health-checker.conf` must be valid on **every** declared node, and the master node needs network access to ports 55000 (manager workers), 9200 (indexer nodes) and 443 (dashboards).

#### Scenario A — all-in-one

Manager, indexer and dashboard on a single server. Leave every node list empty; the localhost defaults are used.

```bash
python3 /opt/scripts/monitoring.py
```

#### Scenario B — split services

For example 1 server with the manager (where the script runs) and 1 server with indexer + dashboard:

```sh
# /etc/wazuh-health-checker.conf
MANAGER_NODES=
INDEXER_NODES=10.0.0.2
DASHBOARD_NODES=10.0.0.2
```

```bash
python3 /opt/scripts/monitoring.py \
  --indexer-nodes   10.0.0.2 \
  --dashboard-nodes 10.0.0.2
```

#### Scenario C — distributed cluster

For example 6 servers: 1 manager master (where the script runs), 1 manager worker, 1 indexer master, 2 indexer data nodes and 1 dashboard:

```sh
# /etc/wazuh-health-checker.conf
MANAGER_NODES=10.0.0.1,10.0.0.2                 # master + worker
INDEXER_NODES=10.0.0.3,10.0.0.4,10.0.0.5        # master + 2 data nodes
DASHBOARD_NODES=10.0.0.6
```

```bash
python3 /opt/scripts/monitoring.py \
  --manager-nodes   10.0.0.1,10.0.0.2 \
  --indexer-nodes   10.0.0.3,10.0.0.4,10.0.0.5 \
  --dashboard-nodes 10.0.0.6
```

Include the local master node in `MANAGER_NODES` too: check 16 validates that every declared node is present in the Wazuh cluster response.

#### What multi-node mode changes

| Behaviour | All-in-one | Multi-node |
|-----------|-----------|------------|
| Manager API (check 1) | localhost | localhost (this node is the master) |
| Manager API per node (check 19) | not run | authenticates against every declared manager node and reports its cluster + role |
| TCP ports 1514/1515 (check 9) | localhost | probed on every manager node, since agents connect to workers too |
| Manager cluster nodes (check 16) | not run | every declared node must appear in `GET /cluster/nodes` |
| Indexer cluster-wide checks (2, 4b, 5–8, 11, 13, 18) | localhost | run through the **first indexer node that answers**, so one dead node does not blank out every indexer check |
| Indexer per node (check 20) | not run | queries each indexer node directly and flags unreachable nodes, mismatched cluster names or versions, and disagreement about the cluster size (split cluster) |
| Indexer cluster nodes (check 17) | not run | every declared node must appear in `_cat/nodes` |
| Dashboard (check 3) | localhost | first declared dashboard |
| Dashboard per node (check 21) | not run | every declared dashboard is requested individually |

The resolved topology is recorded in each log entry under `"topology"`.

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
  --secrets-file /etc/health-checker.secrets \
  --disk-threshold 80 \
  --shard-threshold 85 \
  --manager-nodes   "10.0.0.1,10.0.0.2" \
  --indexer-nodes   "10.0.0.3,10.0.0.4,10.0.0.5" \
  --dashboard-nodes "10.0.0.6"
```

| Flag | Default | Description |
|------|---------|-------------|
| `--manager-url` | `https://localhost:55000` | Wazuh Manager API URL of this (master) node |
| `--indexer-url` | `https://localhost:9200` | Indexer URL. Ignored when `--indexer-nodes` is set, unless given explicitly |
| `--dashboard-url` | `https://localhost:443` | Dashboard URL. Ignored when `--dashboard-nodes` is set, unless given explicitly |
| `--secrets-file` | `/etc/health-checker.secrets` | Path to credentials file |
| `--disk-path` | `/` | Filesystem path to check |
| `--disk-threshold` | `75` | Disk usage % that triggers alert |
| `--shard-threshold` | `80` | Active shards % of limit that triggers alert |
| `--log-file` | `/var/log/health-checker.json` | Output log path |
| `--manager-host` | *(manager nodes, else `localhost`)* | Comma-separated hosts for the TCP port checks |
| `--ports` | `1514,1515` | Comma-separated ports to check |
| `--manager-nodes` | *(empty)* | Manager cluster nodes — IP, `host:port` or URL. Enables checks 16 and 19 |
| `--indexer-nodes` | *(empty)* | Indexer cluster nodes — IP, `host:port` or URL. Enables checks 17 and 20 |
| `--dashboard-nodes` | *(empty)* | Dashboard nodes — IP, `host:port` or URL. Enables check 21 |
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
| 11 | ISM policies configured and applied | No policy defined, no index managed by a policy, an ISM action failing, or no delete phase |
| 12 | Cron jobs for log rotation | Missing rotation for alerts or archives |
| 13 | Retention feasibility | Projected disk/shard usage exceeds limits |
| 14 | Filebeat service status | Service not active |
| 15 | Filebeat output connectivity | `filebeat test output` fails |
| 16 | Manager cluster nodes *(multi-node)* | Declared node missing from `GET /cluster/nodes` |
| 17 | Indexer cluster nodes *(multi-node)* | Declared node missing from `_cat/nodes` |
| 18 | Alert volume trend | Alert count dropped ≥ 20% vs. the previous window |
| 19 | Manager API per node *(multi-node)* | A manager node's API is unreachable, or nodes disagree on the cluster name / master |
| 20 | Indexer reachability per node *(multi-node)* | A node is unreachable, reports a different cluster name or version, or disagrees on the cluster size |
| 21 | Dashboard per node *(multi-node)* | A dashboard node is unreachable |

#### ISM policy detection (check 11)

Check 11 previously reported *"No ISM policies found"* on environments where the policies were loaded and working. It now inspects the policies properly and separates four distinct situations:

| Situation | Status | Notifies |
|-----------|--------|----------|
| ISM API could not be read (auth, permissions, connectivity) | `error` | yes — says it is a permissions/connectivity problem, **not** a missing policy |
| No policy defined at all | `warning` | yes |
| Policies defined but no `wazuh-*` index is managed by them | `warning` | yes — points at the `ism_template` index patterns |
| Policies defined, applied and healthy | `ok` | no |

What was fixed:

* **Delete phases are detected by action, not by state name.** A policy that deletes from a state called `purge`, `cold_delete`, … was previously read as having no retention. Any state running a `delete` action now counts, and the retention age is taken from the transition into it.
* **Both API prefixes are tried** — `_plugins/_ism` (OpenSearch) and `_opendistro/_ism` (older Open Distro builds).
* **All policies are fetched.** The endpoint returns only 20 policies unless a size is requested; the script now asks for up to 1000.
* **`403`/`401` responses are reported as permission errors** instead of being folded into "no policies found".
* **Policies are cross-checked against `_ism/explain`**, so the check knows which indices are actually managed, and flags failed ISM actions or ISM disabled on an index.
* **OpenSearch time units are parsed correctly** — `m` is minutes and `M` is months; `h` is hours, not a day. Policies using those units were silently discarded before.
* **Check 13 (retention feasibility) uses the same parser**, so both checks agree on whether a policy exists, and it says *why* it fell back to the default projection.

The policy inventory is printed on every run, whether or not it alerts:

```
  [✓] ISM Policies                 OK
         └─ 1 ISM policy(ies), 1 with a delete phase, 1 managed index(es)
         └─ wazuh-alerts-retention: states=['hot', 'purge'], delete_after=180d, managed_indices=1
```

Results are appended as newline-delimited JSON to `/var/log/health-checker.json`:

```json
{
  "timestamp": "2025-03-03T12:00:00+00:00",
  "deploy_mode": "bare-metal",
  "node_role": "all",
  "topology": {
    "manager_url": "https://localhost:55000",
    "manager_nodes": ["https://10.0.0.1:55000", "https://10.0.0.2:55000"],
    "indexer_url": "https://10.0.0.3:9200",
    "indexer_nodes": ["https://10.0.0.3:9200", "https://10.0.0.4:9200", "https://10.0.0.5:9200"],
    "dashboard_nodes": ["https://10.0.0.6:443"],
    "port_hosts": ["10.0.0.1", "10.0.0.2"]
  },
  "notify": true,
  "checks": {
    "manager_api": { "status": "ok", "notify": false, "api_version": "4.x.x" },
    "disk_space":  { "status": "warning", "notify": true, "used_pct": 78.5 },
    "indexer_node_endpoints": {
      "status": "error", "notify": true,
      "node_count": 3, "reachable": 2,
      "issues": ["10.0.0.5:9200: indexer unreachable (connection refused)"]
    }
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

**3. Verify the cluster topology is resolved as expected** — the run prints it before the checks, and records it in the log entry:

```bash
python3 /opt/scripts/monitoring.py --indexer-nodes 10.0.0.3,10.0.0.4,10.0.0.5
```

```
[*] Starting Wazuh health checks (deploy-mode=bare-metal, node-role=all)…
    Manager   : https://localhost:55000
    Indexer   : https://10.0.0.3:9200  (of 3 node(s))
    Dashboard : https://localhost:443
...
  [✓] Indexer Reach. per Node      OK
         └─ 3/3 node(s) reachable
```

Point a node at an address that is down to confirm it is reported:

```bash
python3 /opt/scripts/monitoring.py --indexer-nodes 10.0.0.3,10.0.0.99
```

```
  [✗] Indexer Reach. per Node      ERROR ← NOTIFICATION
         └─ 10.0.0.99:9200: indexer unreachable (connection refused)
         └─ 1/2 node(s) reachable
```

**4. Verify the ISM policies are detected** — compare what the script reports against the indexer:

```bash
curl -sk -u admin:<pass> "https://localhost:9200/_plugins/_ism/policies?from=0&size=1000" | python3 -m json.tool
curl -sk -u admin:<pass> "https://localhost:9200/_plugins/_ism/explain/wazuh-*"  | python3 -m json.tool
```

The policy count and the number of managed indices must match the `ISM Policies` line of the summary.

**5. Check the Wazuh logs** to confirm the script runs without errors:

```bash
cat /var/log/health-checker-cron.log
```

**6. Expected output** — a JSON entry in `/var/log/health-checker.json` per run, and a Slack/email message when any check returns `"status": "warning"`.

---

### Sources

* [Wazuh Documentation](https://documentation.wazuh.com/)
* [Wazuh API Reference](https://documentation.wazuh.com/current/user-manual/api/reference.html)
* [Slack Incoming Webhooks](https://api.slack.com/messaging/webhooks)
