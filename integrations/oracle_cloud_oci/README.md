# Oracle Cloud Infrastructure (OCI)-Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
    * [Installing Oracle Cloud Infrastructure](#installing-oracle-cloud-infrastructure)
    * [Initial Oracle Cloud Infrastructure Configuration](#initial-oracle-cloud-infrastructure-configuration)
    * [Installing Wazuh](#installing-wazuh)
    * [Initial Wazuh Configuration](#initial-wazuh-configuration)
    * [Using the Integration Files](#using-the-integration-files)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Service Coverage Reference](#service-coverage-reference)
* [Troubleshooting](#troubleshooting)
* [Provenance and Maintenance](#provenance-and-maintenance)
* [Sources](#sources)

---

### Introduction

Wazuh ships native cloud modules for AWS, Azure and GCP, but **there is no native OCI
module**. This integration fills that gap for Oracle Cloud Infrastructure.

The data path Oracle supports is:

```
 OCI service           Logging / Audit          Connector Hub            this integration
┌───────────────┐     ┌────────────────┐      ┌──────────────┐        ┌──────────────────┐
│ VCN           │     │                │      │              │───────▶│  Streaming       │
│ Object Storage│────▶│  Service Logs  │─────▶│   Connector  │        │  consumer group  │──┐
│ API Gateway   │     │                │      │              │        └──────────────────┘  │
│ Email Delivery│     ├────────────────┤      │  (optional   │                              │
├───────────────┤     │                │      │   log filter │        ┌──────────────────┐  │
│ DRG           │     │  Audit Logs    │      │   task)      │───────▶│  Object Storage  │  │
│ Block Storage │────▶│  (_Audit,      │─────▶│              │        │  bucket poller   │──┤
│ ADB / ATP     │     │  every service)│      │              │        └──────────────────┘  │
│ APEX          │     │                │      └──────────────┘                              │
│ Data Integr.  │     └────────────────┘                                                    │
│ Integration   │                                            oci-logs.py                    │
└───────────────┘                                                                           │
                                                                                            ▼
                                   ┌──────────────────────────────────────────────────────────┐
                                   │  Wazuh manager                                           │
                                   │  analysisd socket  ──or──  JSON file + <localfile>        │
                                   │  rules 112000-112099                                      │
                                   └──────────────────────────────────────────────────────────┘
```

> **Other OCI integrations in this repository.** Two others exist and this replaces
> neither. `Oracle_Cloud_Infrastructure_streaming/` routes OCI Streaming through
> Logstash and Kafka and ships a dashboard — use it if you already run Logstash.
> `Oracle-Integration-(OCI)/` is an earlier Streaming-only collector that ships no
> rules. This one talks to OCI directly through the SDK, covers both delivery
> targets, and brings the ruleset. The rules file is named
> `oracle_cloud_oci_rules.xml` so it cannot overwrite theirs in
> `/var/ossec/etc/rules/`.

The `oci-logs.py` collector is the last hop. It reads the log records Connector Hub
delivered, normalises them into a stable JSON shape, and forwards them to Wazuh —
either straight to the analysisd socket or as JSON lines on disk for a `<localfile>`
block to tail.

**What this buys you**

* One collector covers **every OCI service**, because OCI Audit records the control
  plane for all of them. Services that also emit data-plane service logs (VCN flow
  logs, Object Storage access, API Gateway access, Email Delivery) flow through the
  same connector.
* Consistent field names. OCI's raw records nest differently per service; the
  collector hoists `srcip`, `srcuser`, `action`, `status`, `url`, `srcport`,
  `dstip`, `dstport` and `protocol` to the top level so the Wazuh alert schema and
  the dashboards' standard filters work without per-service rule gymnastics.
* 35 rules in the `112000-112099` range, covering IAM changes, security list and
  route table edits, DRG teardown, volume and bucket deletion, public-bucket
  exposure, ADB/ATP stop and credential rotation, rejected VCN flows, API Gateway
  auth failures and Email Delivery bounce storms. Every rule has been exercised
  against a running manager -- see [Integration Testing](#integration-testing).
* An offline replay mode (`--source local`) so the whole normalise-and-alert chain
  can be validated with `wazuh-logtest` before you have a tenancy wired up.

---

### Prerequisites

**Wazuh**

* Wazuh manager 4.4 or later. Rules use `<field>` on JSON-decoded events,
  `same_field`, and `<mitre>`.
* The collector runs on the **manager** (writing to analysisd) or on any **agent**
  (writing to a file that `<localfile>` tails). It does not need to run inside OCI.

**Oracle Cloud Infrastructure**

* A tenancy with the Logging, Audit and Connector Hub services enabled. Audit is on
  by default in every compartment.
* Either an **OCI Streaming** stream or an **Object Storage** bucket to receive the
  Connector Hub output.
* An IAM user with an API signing key, **or** — preferred — a compute instance in a
  dynamic group so the collector can use instance principals and keep no private key
  on disk.

**Host**

* Python 3.8+. The Wazuh manager embeds a suitable interpreter at
  `/var/ossec/framework/python/bin/python3`, which is what the shebang targets.
* The `oci` SDK (`pip install -r requirements.txt`). Not needed for `--source local`.
* Outbound HTTPS (443) to the OCI service endpoints in your region.

**IAM permissions for the collector user or dynamic group**

For an Object Storage bucket:

```
Allow group WazuhCollectors to read objects in compartment <compartment> where target.bucket.name = '<bucket>'
Allow group WazuhCollectors to read buckets in compartment <compartment>
```

Add this only if you run the collector with `--delete-after-read`:

```
Allow group WazuhCollectors to manage objects in compartment <compartment> where all {target.bucket.name = '<bucket>', request.permission = 'OBJECT_DELETE'}
```

For a stream:

```
Allow group WazuhCollectors to use stream-pull in compartment <compartment> where target.stream.id = '<stream OCID>'
Allow group WazuhCollectors to read streams in compartment <compartment>
```

Separately, the **connector itself** needs permission to write to its target. The
Console offers these as default policies when you create the connector; accept them
or write the equivalent custom policy with a dynamic group.

---

### Installation and Configuration

#### Installing Oracle Cloud Infrastructure

OCI is a hosted service; nothing to install. You need an active tenancy and
Console access with administrator rights in the compartments you want to monitor.

#### Initial Oracle Cloud Infrastructure Configuration

**Step 1 — Turn on the logs you want.**

*Audit* is already on for every service and needs no setup. It lands in the `_Audit`
log group of each compartment and is what covers DRG, Block Storage, ADB/ATP, APEX,
Data Integration and Integration Service. See
[Service Coverage Reference](#service-coverage-reference) for which of your services
also have data-plane service logs.

*Service logs* must be enabled per resource. In the Console go to
**Observability & Management > Logging > Logs > Enable service log**, pick the
resource, and pick a log category:

| Service | Log category to enable |
|---|---|
| VCN | Flow Logs (on the subnet or VNIC) |
| Object Storage | Read Access Events, Write Access Events (on the bucket) |
| API Gateway | Access, Execution (on the deployment) |
| Email Delivery | Outbound accepted / relayed / suppressed |

> If the **Enable service log** dialog offers no categories for a resource, that
> service has no data-plane log in your region and Audit is the whole story for it.
> Check this per service rather than assuming — Oracle adds categories over time.

**Step 2 — Create the delivery target.**

Choose one:

* **Object Storage** (simpler, cheaper, minutes of latency): create a bucket, e.g.
  `wazuh-oci-logs`. Set a lifecycle rule to delete objects after a few days, or run
  the collector with `--delete-after-read`.
* **Streaming** (near real time, server-side offset tracking): create a stream, e.g.
  `wazuh-oci-logs`, with a retention long enough to survive a collector outage —
  24 hours or more is sensible.

**Step 3 — Create the connector.**

**Analytics & AI > Messaging > Connector Hub > Create connector**.

* **Source**: Logging.
* **Compartment**: the one you want to collect from.
* **Log group**: `_Audit` for audit, or the log group holding your service logs. Add
  a second source entry per log group — one connector can read several.
  Tick *Include subcompartments* to cover a compartment tree in one connector.
* **Task** (optional): a Log Filter task drops noise before it reaches Wazuh. Filtering
  out `ACCEPT` flow-log records is the highest-value filter in most tenancies.
* **Target**: the bucket or stream from step 2.
* Accept the default IAM policies the Console offers, or supply your own.

> Connector Hub reads log data from the connector's creation time forward, and the
> Logging source retains 24 hours. Create the connector before you need the data.
> Editing a connector's source or target **resets** it internally, which can replay
> or skip records — create a new connector instead of editing a working one.

**Step 4 — Credentials for the collector.**

If the collector runs on an OCI compute instance, skip this: add the instance to a
dynamic group and use `--auth instance_principal`.

Otherwise create an IAM user, generate an API signing key
(**Identity > Users > <user> > API Keys > Add API Key**), and fill in
[config.example](config.example) with the user OCID, fingerprint, key path, tenancy
OCID and region.

#### Installing Wazuh

A standard installation is assumed. Follow the
[Wazuh installation guide](https://documentation.wazuh.com/current/installation-guide/index.html).
This integration needs no special build options or extra modules.

#### Initial Wazuh Configuration

None beyond a working manager. The collector uses the standard analysisd queue socket
at `/var/ossec/queue/sockets/queue`, or writes a file for the standard log collector.

#### Using the Integration Files

| File | Purpose | Install to |
|---|---|---|
| `oci-logs.py` | The collector | `/var/ossec/wodles/oci/oci-logs.py` |
| `ruleset/rules/oracle_cloud_oci_rules.xml` | Rules 112000-112099 | `/var/ossec/etc/rules/` |
| `config.example` | OCI API-key template | `/var/ossec/wodles/oci/config` |
| `systemd/wazuh-oci-logs.service` | Runs one collection pass | `/etc/systemd/system/` |
| `systemd/wazuh-oci-logs.timer` | Schedules the passes | `/etc/systemd/system/` |
| `sample_logs.txt` | Representative records for testing | anywhere |

**Deploy the collector**

```bash
sudo mkdir -p /var/ossec/wodles/oci
sudo cp oci-logs.py /var/ossec/wodles/oci/
sudo chown root:wazuh /var/ossec/wodles/oci/oci-logs.py
sudo chmod 750 /var/ossec/wodles/oci/oci-logs.py

sudo /var/ossec/framework/python/bin/python3 -m pip install -r requirements.txt
```

**Deploy the credentials** (skip if using instance principals)

```bash
sudo install -m 0600 -o root -g root config.example /var/ossec/wodles/oci/config
sudo install -m 0600 -o root -g root ~/oci_api_key.pem /var/ossec/wodles/oci/
sudo "${EDITOR:-vi}" /var/ossec/wodles/oci/config   # fill in your OCIDs
```

**Deploy the rules**

```bash
sudo cp ruleset/rules/oracle_cloud_oci_rules.xml /var/ossec/etc/rules/
sudo chown root:wazuh /var/ossec/etc/rules/oracle_cloud_oci_rules.xml
sudo chmod 660 /var/ossec/etc/rules/oracle_cloud_oci_rules.xml
sudo systemctl restart wazuh-manager
```

No custom decoder is needed. The collector emits JSON, so Wazuh's built-in JSON
decoder parses it and every field the rules reference is addressable directly.

**Schedule the collector**

```bash
sudo cp systemd/wazuh-oci-logs.{service,timer} /etc/systemd/system/
sudo "${EDITOR:-vi}" /etc/systemd/system/wazuh-oci-logs.service   # set your bucket or stream
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-oci-logs.timer
```

Cron works equally well if you would rather not use systemd:

```
* * * * * /var/ossec/wodles/oci/oci-logs.py --source objectstorage --bucket wazuh-oci-logs --config-file /var/ossec/wodles/oci/config >> /var/ossec/logs/oci-logs.log 2>&1
```

---

### Integration Steps

#### Option A — Object Storage (recommended for most deployments)

Connector Hub writes batches of log records into the bucket. The collector lists the
bucket in name order, reads each new object, and checkpoints the last object name to
`--state-file` so restarts resume cleanly.

```bash
/var/ossec/wodles/oci/oci-logs.py \
  --source objectstorage \
  --bucket wazuh-oci-logs \
  --config-file /var/ossec/wodles/oci/config \
  --output analysisd
```

Useful flags: `--prefix` to read one connector's output from a shared bucket,
`--start-time 2026-07-01` to ignore a backlog on first run, and `--delete-after-read`
to drain the bucket as you go.

#### Option B — Streaming (lowest latency)

The collector consumes with a **consumer group**, so OCI tracks the read offset
server-side and a restart picks up where the last run stopped.

```bash
/var/ossec/wodles/oci/oci-logs.py \
  --source streaming \
  --stream-id ocid1.stream.oc1.iad.EXAMPLE \
  --config-file /var/ossec/wodles/oci/config \
  --output analysisd
```

The messages endpoint is looked up automatically from the stream OCID; pass
`--stream-endpoint` to skip the lookup. Change `--group-name` to re-read a stream
from the beginning. Run exactly one process per `--instance-name`.

#### Option C — write to a file and let `<localfile>` tail it

This is the shape Wazuh support describes, and the right choice when the collector
runs on an **agent** rather than the manager.

```bash
/var/ossec/wodles/oci/oci-logs.py \
  --source objectstorage --bucket wazuh-oci-logs \
  --config-file /var/ossec/wodles/oci/config \
  --output file --path /var/ossec/logs/oci/oci.json
```

Then in `ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/ossec/logs/oci/oci.json</location>
</localfile>
```

Rotate that file — the collector appends and never truncates.

#### The event Wazuh receives

Each OCI record becomes one JSON event with a stable shape:

```json
{
  "integration": "oci",
  "oci": {
    "log_type": "audit",
    "service": "objectstorage",
    "type": "com.oraclecloud.objectstorage.DeleteBucket",
    "time": "2026-07-01T08:01:00.000Z",
    "id": "a1b2c3d4-0000-4000-8000-000000000002",
    "data": { "...the untouched OCI record..." },
    "compartment_id": "ocid1.compartment.oc1..aaaaaaaaprod",
    "log_group_id": "_Audit",
    "tenant_id": "ocid1.tenancy.oc1..aaaaaaaatenancyexample",
    "compartment_name": "prod",
    "resource_name": "finance-archive",
    "resource_id": "ocid1.bucket.oc1..aaaaaaaafinance",
    "srcip": "198.51.100.77",
    "srcuser": "contractor@acme.com",
    "action": "DeleteBucket",
    "status": "204",
    "url": "/n/acmens/b/finance-archive"
  },
  "srcip": "198.51.100.77",
  "srcuser": "contractor@acme.com",
  "action": "DeleteBucket",
  "status": "204",
  "url": "/n/acmens/b/finance-archive"
}
```

**Why some values appear twice.** `srcip`, `srcuser`, `action`, `status`, `url` and
friends are emitted both at the top level and mirrored inside `oci`. That is
deliberate. At the top level they land on Wazuh's *static* decoder fields, which is
what populates `data.srcip` in the alert and what `<same_source_ip />` correlates on.
But analysisd matches static fields with a plain `strcmp` for `<action>` and with
OSMatch for `<status>` — neither supports the regex the rules need, and `<field
name="status">` is rejected outright because the name is reserved. The mirror under
`oci.*` is a dynamic field, and `<field>` on a dynamic name gets full OS_Regex. Write
new rules against `oci.action` / `oci.status`, not the bare names.

`oci.status` is always present, falling back to `unknown` when the source record
carries no status. Rules gate on it with `negate="yes"`, which does not match a
missing field, so a record without one would otherwise drop out of the ruleset.

`oci.log_type` is one of `audit`, `vcn_flow`, `objectstorage`, `apigateway_access`,
`apigateway_execution`, `emaildelivery`, `data_integration`, `integration_service`,
`database`, `loadbalancer`, `waf`, `functions`, `oke`, or `oci` for anything
unrecognised. The original record is always preserved under `oci.data`, so a rule can
reach any field Oracle sends even if the collector does not hoist it.

Sending to analysisd uses the header `1:oci:`, so alerts carry `location: oci`.

---

### Integration Testing

#### 1. Offline — no tenancy required

This validates the collector's parsing and normalisation, and every rule field path,
without touching OCI:

```bash
cd integrations/oracle_cloud_oci
python3 oci-logs.py --source local --input sample_logs.txt --output stdout
```

Expected: 21 JSON events on stdout and `Forwarded 21 event(s) via stdout` on stderr.

Now push them through the ruleset:

```bash
python3 oci-logs.py --source local --input sample_logs.txt --output stdout \
  | sudo /var/ossec/bin/wazuh-logtest -q
```

Every row below was confirmed on Wazuh 4.14.7 — each sample lands on exactly this
rule and level:

| Sample record | Rule | Level |
|---|---|---|
| `CreateUser` succeeding | 112005 | 10 |
| `CreateUser` denied with 403 | 112003 | 8 |
| `DeletePolicy` | 112006 | 12 |
| `UpdateSecurityList` opening SSH to 0.0.0.0/0 | 112007 | 10 |
| `DeleteDrgAttachment` | 112009 | 12 |
| `DeleteVolume` | 112011 | 10 |
| `DeleteBucket` | 112012 | 12 |
| `UpdateBucket` with `publicAccessType: ObjectRead` | 112013 | 12 |
| `StopAutonomousDatabase` | 112015 | 10 |
| `ChangeAutonomousDatabaseAdminPassword` | 112016 | 10 |
| `UpdateIntegrationInstance` | 112017 | 5 |
| `DeleteIntegrationInstance` | 112018 | 10 |
| VCN flow log `REJECT` to port 22 | 112021 | 4 |
| Object Storage `DELETE` of `payroll.csv` | 112031 | 6 |
| Object Storage `GET` returning 403 | 112032 | 8 |
| API Gateway 401 | 112042 | 8 |
| API Gateway 500 | 112044 | 7 |
| Email Delivery `SUPPRESSED` / `HARDBOUNCE` | 112051 | 5 |

The VCN flow log `ACCEPT` sample deliberately stops at 112020, level 0 — accepted
traffic is recorded but does not alert.

The five frequency rules need repeated events inside their timeframe, so a single
pass over the samples will not fire them. Replay one record in a loop instead:

```bash
grep REJECT sample_logs.txt > /tmp/reject.json
for i in $(seq 1 25); do cat /tmp/reject.json; done > /tmp/burst.json
python3 oci-logs.py --source local --input /tmp/burst.json --output analysisd
```

Then look for the aggregate rule in `/var/ossec/logs/alerts/alerts.json`. All five
were confirmed to fire:

| Aggregate rule | Trigger | Correlates on | Level |
|---|---|---|---|
| 112004 | 8x rule 112003 in 300s | `same_source_ip` | 10 |
| 112022 | 20x rule 112021 in 120s | `same_source_ip` | 8 |
| 112033 | 30x rule 112030 in 300s | `same_source_ip` | 10 |
| 112043 | 15x rule 112042 in 120s | `same_source_ip` | 10 |
| 112052 | 25x rule 112051 in 300s | `same_field oci.srcuser` | 10 |

#### 2. Connectivity — against your tenancy

Confirm credentials, policy and the delivery target without writing any alerts:

```bash
/var/ossec/wodles/oci/oci-logs.py \
  --source objectstorage --bucket wazuh-oci-logs \
  --config-file /var/ossec/wodles/oci/config \
  --output stdout --max-records 5 --log-level DEBUG
```

A `NotAuthorizedOrNotFound` here means the IAM policy is missing or the bucket name
or compartment is wrong — not a bug in the collector.

#### 3. End to end — generate a real event

Trigger something the ruleset alerts on, then wait for Connector Hub to batch it
(allow a few minutes; up to 17 for a Functions-task pipeline):

```bash
oci iam user create --name wazuh-oci-test --description "Wazuh integration test"
oci iam user delete --user-id <the OCID returned above> --force
```

Then check for the alert:

```bash
sudo grep -F '"integration":"oci"' /var/ossec/logs/alerts/alerts.json | tail -5
sudo jq 'select(.rule.id | startswith("1120"))' /var/ossec/logs/alerts/alerts.json | tail -40
```

Expected — a rule 112005 alert (level 10, *OCI IAM: identity object modified*) and a
rule 112006 alert (level 12) for the delete.

In the Wazuh dashboard, filter on `data.integration: oci` or `rule.groups: oci`.

---

### Service Coverage Reference

The eleven services asked about, and where their logs actually come from. Confirm the
service-log column in your own tenancy — availability varies by region and Oracle adds
categories over time.

| Service | OCI Audit (control plane) | Service log (data plane) | Rules |
|---|---|---|---|
| **Virtual Cloud Network (VCN)** | Yes — VCN, subnet, security list, NSG, route table changes | **Yes** — VCN Flow Logs, per subnet or VNIC | 112007, 112020-112022 |
| **Dynamic Routing Gateway (DRG)** | Yes — DRG and attachment create/update/delete, route distribution | No dedicated log. Traffic crossing a DRG attachment appears in the flow logs of the attached subnets | 112008, 112009 |
| **Block Storage** | Yes — volume, backup, clone, attach/detach | No | 112010, 112011 |
| **Object Storage** | Yes — bucket create/update/delete, policy changes | **Yes** — Read Access Events and Write Access Events, per bucket | 112012, 112013, 112030-112033 |
| **API Gateway** | Yes — gateway and deployment changes | **Yes** — Access and Execution logs, per deployment | 112040-112044 |
| **Oracle Autonomous Database** | Yes — provision, scale, stop, terminate, wallet and admin password | No OCI Logging category. Database-level auditing lives in the DB itself | 112014-112016 |
| **Autonomous Transaction Processing (ATP)** | Same as Autonomous Database — ATP is an ADB workload type | Same as above | 112014-112016 |
| **Oracle APEX** | Yes, indirectly — APEX runs inside an ADB, so ADB operations are audited | No. APEX activity is in `APEX_ACTIVITY_LOG` / `APEX_WORKSPACE_ACCESS_LOG` inside the database | 112014 |
| **Data Integration** | Yes — workspace, application, task changes | Check your tenancy | 112017, 112018 |
| **Email Delivery** | Yes — approved sender, suppression list, SMTP credential changes | **Yes** — outbound accepted / relayed / suppressed | 112050-112052 |
| **Integration Service (OIC)** | Yes — instance create, update, start, stop, delete | Check your tenancy. OIC also keeps its own activity stream inside the instance | 112017, 112018 |

#### Getting database-level visibility for ADB, ATP and APEX

Audit covers *who resized the database*, not *who queried the salary table*. For
in-database activity you need one of these, and neither is shipped here:

**Oracle Data Safe** — the supported route. Register the ADB with Data Safe, enable
audit collection, then use a Connector Hub connector from the Data Safe audit log
group into the same bucket or stream this collector already reads. No extra Wazuh
configuration; the records arrive with `oci.log_type: audit`.

**Scheduled unified-audit export** — if Data Safe is not an option, export from the
database on a schedule and tail the result. Run as a user with `SELECT` on the audit
view:

```sql
SELECT JSON_OBJECT(
         'event_timestamp' VALUE EVENT_TIMESTAMP,
         'db_user'         VALUE DBUSERNAME,
         'client_ip'       VALUE CLIENT_HOST,
         'action'          VALUE ACTION_NAME,
         'object'          VALUE OBJECT_SCHEMA || '.' || OBJECT_NAME,
         'returncode'      VALUE RETURN_CODE,
         'sql_text'        VALUE SQL_TEXT)
  FROM UNIFIED_AUDIT_TRAIL
 WHERE EVENT_TIMESTAMP > SYSTIMESTAMP - INTERVAL '5' MINUTE;
```

For APEX specifically, `APEX_WORKSPACE_ACCESS_LOG` records workspace sign-ins and
`APEX_ACTIVITY_LOG` records page views. Write either to a file and collect it with a
`<localfile>` block using `<log_format>json</log_format>`.

---

### Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Wazuh queue socket not found` | The manager is not running, or the collector is on an agent. Use `--output file` plus a `<localfile>` block. |
| `NotAuthorizedOrNotFound` | IAM policy missing, or wrong compartment/bucket/stream. Verify with `oci os object list --bucket-name <bucket>` as the same user. |
| Collector runs clean, no events | The connector has not batched yet, or it is failing. Check **Connector Hub > your connector > Metrics**, and enable connector logs to see delivery errors. |
| Events reach Wazuh but no alerts fire | Confirm the JSON decoder matched: `wazuh-logtest` should show `json` as the decoder. Then check `oracle_cloud_oci_rules.xml` is in `/var/ossec/etc/rules/` with `wazuh` group ownership. |
| Duplicate events after editing the connector | Expected. Editing a connector's source or target resets it internally and it may re-read from an earlier offset. Create a new connector rather than editing a working one. |
| `Event of N bytes exceeds the 65535 byte analysisd limit` | A single OCI record was too large. The collector drops `oci.data` and forwards the normalised fields with `oci.truncated: true` rather than losing the event. Add a Connector Hub log-filter task to trim the payload at source. |
| Streaming collector reprocesses everything | `--group-name` changed, or the consumer group aged out. Consumer-group offsets are server-side; keep the group name stable. |
| Object Storage collector reprocesses everything | `--state-file` was deleted or is not writable. Default is `/var/ossec/var/run/oci-logs.state`. |
| Flow logs drown out everything else | Add a Connector Hub log-filter task dropping `data.action = "ACCEPT"`, or collect flow logs through a separate connector so you can tune them independently. |

---

### Provenance and Maintenance

* **Original source**: Design informed by the OCI Streaming collector contributed by
  Felix Bocco in [wazuh/integrations#51](https://github.com/wazuh/integrations/pull/51),
  which established the consumer-group approach. The collector here is new code, not a
  modification of that one. Written against Oracle's
  [Connector Hub](https://docs.oracle.com/en-us/iaas/Content/connector-hub/overview.htm)
  and [Logging](https://docs.oracle.com/en-us/iaas/Content/Logging/home.htm)
  documentation, and shaped by the guidance in the Wazuh community thread on
  forwarding OCI logs.
* **Adapted by**: Tamir Suliman.
* **Relationship to the other OCI integrations**: this adds a third and removes
  nothing. `Oracle_Cloud_Infrastructure_streaming/` (Jose Camargo,
  [#55](https://github.com/wazuh/integrations/pull/55)) routes Streaming through
  Logstash and Kafka and ships a dashboard. `Oracle-Integration-(OCI)/` (Felix Bocco,
  [#51](https://github.com/wazuh/integrations/pull/51)) is Streaming-only and ships no
  rules. This one uses the OCI SDK directly, supports both Connector Hub delivery
  targets, and brings a ruleset. Its rules file is `oracle_cloud_oci_rules.xml` so it
  cannot overwrite the others once installed. Which to consolidate, if any, is a call
  for the repository maintainers.
* **What is new here**: the Object Storage source and the file/`<localfile>` output;
  instance-principal and resource-principal auth; record normalisation and a stable
  field schema; the 35-rule `112000-112099` ruleset; offline replay for testing.
* **Tested versions**: Wazuh manager **4.14.7** (Ubuntu 22.04, aarch64, installed from
  `packages.wazuh.com/4.x/apt`); Python 3.9-3.13; `oci` SDK 2.126+. Rules use only
  4.4+ syntax.
* **Maintainer**: community-maintained. Open an issue or PR against
  [wazuh/integrations](https://github.com/wazuh/integrations).
* **Support boundary**: Provided as is, community-maintained. This is **not** a native
  Wazuh module and is not covered by Wazuh support.

  *Verified on a running manager*: the ruleset loads (`wazuh-analysisd -t`); all 21
  bundled samples land on the expected rule and level under `wazuh-logtest`; both
  ingestion paths produce alerts end to end — the analysisd socket (`location: oci`)
  and a file tailed by `<localfile>`; all five frequency rules fire, including
  `same_source_ip` and `same_field` correlation. All 35 rules are exercised — 25 fire
  directly from the samples, the other 10 are parents traversed on the way.

  *Not verified*: the live OCI Streaming and Object Storage code paths have not run
  against a real tenancy. Record shapes vary by service and region, so validate in a
  non-production compartment first and please report field-shape differences you hit.

---

### Sources

* [Overview of Connector Hub](https://docs.oracle.com/en-us/iaas/Content/connector-hub/overview.htm)
* [Connector Hub scenarios](https://docs.oracle.com/en-us/iaas/Content/connector-hub/scenarios.htm)
* [OCI Logging overview](https://docs.oracle.com/en-us/iaas/Content/Logging/home.htm)
* [OCI Logging service logs and categories](https://docs.oracle.com/en-us/iaas/Content/Logging/Concepts/service_logs.htm)
* [OCI Audit overview](https://docs.oracle.com/en-us/iaas/Content/Audit/home.htm)
* [VCN Flow Logs](https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/vcn_flow_logs.htm)
* [OCI Streaming overview](https://docs.oracle.com/en-us/iaas/Content/Streaming/home.htm)
* [OCI SDK for Python](https://docs.oracle.com/en-us/iaas/tools/python/latest/)
* [Calling services from an instance (instance principals)](https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/callingservicesfrominstances.htm)
* [Oracle Data Safe activity auditing](https://docs.oracle.com/en-us/iaas/data-safe/doc/activity-auditing-overview.html)
* [Wazuh log data collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/index.html)
* [Wazuh custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
