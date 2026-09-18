# Cortex XDR (API) - Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Compatibility](#compatibility)
* [What this collects](#what-this-collects)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
    * [Initial Cortex XDR Configuration](#initial-cortex-xdr-configuration)
    * [Initial Wazuh Configuration](#initial-wazuh-configuration)
    * [Using the Integration Files](#using-the-integration-files)
* [Configuration Reference](#configuration-reference)
* [Integration Testing](#integration-testing)
* [How Incremental Polling Works](#how-incremental-polling-works)
* [API Notes](#api-notes)
* [Troubleshooting](#troubleshooting)
* [Sources](#sources)

---

## Introduction

This integration polls the Cortex XDR REST API on an interval and ingests the results
as Wazuh alerts. It covers five data sets: incidents, alerts, endpoint inventory,
console audit logs and per-agent reports.

It is the API pull integration and is separate from `integrations/cortex/`, which
decodes Cortex XDR syslog output with a custom decoder. The two share no files, no
field names and no rule IDs, so they can be installed together.

Every endpoint, filter field and limit documented here was confirmed against a live
Cortex XDR 5.0 tenant. Where the vendor documentation disagreed with the tenant, the
tenant won; see [API Notes](#api-notes).

---

## Compatibility

Tested end to end against a live Cortex XDR 5.0 EU tenant and Wazuh 4.14.7.

---

## What this collects

| Data set | API endpoint | Emitted as | Enabled by default |
|---|---|---|---|
| `incidents` | `incidents/get_incidents` | `cortex.event_type: incident` | yes |
| `alerts` | `alerts/get_alerts_multi_events` | `cortex.event_type: alert` | yes |
| `endpoints` | `endpoints/get_endpoint` | `cortex.event_type: endpoint` | yes |
| `audit_management` | `audits/management_logs` | `cortex.event_type: audit_management` | yes |
| `audit_agents` | `audits/agents_reports` | `cortex.event_type: audit_agent` | no |

Each data set keeps its own watermark, so one can be added or removed without
disturbing the others.

`audit_agents` is off by default. It returned 175,914 records on a 700-agent tenant and
is agent telemetry rather than security signal, so enable it deliberately and give it a
short `lookback_hours`.

Every field the API returns is carried through rather than allowlisted, so a new rule
can use any field without the collector needing a change. Two exceptions: the per-alert
`events` array is dropped because it is unbounded, and any event still over 60,000
bytes has its longest fields trimmed and is flagged with `cortex.truncated`.

---

## Prerequisites

A Cortex XDR API key whose role can read the data sets you enable. In the Cortex
console under **Settings > Configurations > Integrations > API Keys**, create a key and
note both values:

- The **API key**, shown once at creation and never again.
- The **API key ID**, the small integer in the ID column, sent as `x-xdr-auth-id`.

Use a **Standard** security level key. Advanced keys require a per-request nonce and
SHA-256 signature that this collector does not implement.

Your tenant FQDN is on the same page, in the form
`api-<tenant>.xdr.<region>.paloaltonetworks.com`.

---

## Installation and Configuration

### Initial Cortex XDR Configuration

Nothing needs to be enabled in Cortex XDR beyond the API key above. The collector only
reads, and never writes to or acknowledges anything in the tenant.

### Initial Wazuh Configuration

Merge `cortex_xdr_index_mapping.json` into the Wazuh alerts index template. Without it
every field still arrives, but as `keyword`, so date histograms and numeric
aggregations on Cortex fields do not work.

```bash
# 1. Back up the template first.
curl -sk -u admin:admin "https://127.0.0.1:9200/_template/wazuh" > /tmp/wazuh-template.backup.json

# 2. Merge the cortex block into mappings.properties.data.properties, then
# 3. push the template back to the indexer.
```

The mapping uses `ignore_malformed` on every date, numeric and ip field. That matters:
without it a single unparseable value causes the indexer to reject the whole alert
rather than just that field.

The template applies to indices created after it is pushed, so either wait for the next
daily index or roll over to see the change take effect.

### Using the Integration Files

| File | Goes to |
|---|---|
| `cortex_xdr.py` | `/var/ossec/wodles/cortex_xdr/` on the manager |
| `ruleset/rules/cortex_xdr_rules.xml` | `/var/ossec/etc/rules/`. Required: without it nothing reaches the indexer |
| `cortex_xdr_index_mapping.json` | Merged into the alerts index template. Required for date and numeric panels |
| `dashboards/cortex_xdr_dashboard.ndjson` | Incidents and alerts overview |
| `dashboards/cortex_xdr_endpoints_dashboard.ndjson` | Agent inventory and protection state |
| `dashboards/cortex_xdr_audit_dashboard.ndjson` | Console and agent audit activity |
| `dashboards/cortex_xdr_vega_dashboard.ndjson` | Vega explorer: estate treemap, MITRE and agent-health matrices, activity clock |

No decoder ships with this integration and none is needed. The collector writes NDJSON,
logcollector reads it as `json`, and Wazuh's built-in json decoder flattens each line
into the `cortex.*` fields the rules match on.

**1. Install the collector.**

```bash
sudo mkdir -p /var/ossec/wodles/cortex_xdr
sudo cp cortex_xdr.py /var/ossec/wodles/cortex_xdr/
sudo chown -R root:wazuh /var/ossec/wodles/cortex_xdr
sudo chmod 750 /var/ossec/wodles/cortex_xdr /var/ossec/wodles/cortex_xdr/cortex_xdr.py
```

Everything lives under `/var/ossec`, in the directories Wazuh already uses for each
purpose:

| Path | Holds |
|---|---|
| `/var/ossec/wodles/cortex_xdr/cortex_xdr.py` | the collector |
| `/var/ossec/wodles/cortex_xdr/config.json` | credentials, mode `0600` |
| `/var/ossec/wodles/cortex_xdr/state.json` | watermarks and the endpoint snapshot, created by the script |
| `/var/ossec/logs/cortex_xdr.log` | the NDJSON that logcollector tails |
| `/var/ossec/var/run/cortex_xdr.lock` | prevents overlapping runs |

This mirrors what Wazuh's own wodles do: the `aws` one keeps its state database in
`/var/ossec/wodles/aws/buckets_s3/`. RPM and DEB only manage files they own, so a Wazuh
upgrade does not remove this directory.

**2. Write the config,** then `chmod 600` it since it holds an API key. Only `fqdn`,
`api_key_id` and `api_key` are required:

```json
{
  "fqdn": "api-yourtenant.xdr.eu.paloaltonetworks.com",
  "api_key_id": "24",
  "api_key": "REPLACE_WITH_YOUR_API_KEY",
  "collect": ["incidents", "alerts", "endpoints", "audit_management"],
  "lookback_hours": 24,
  "lookback_hours_by_collector": {
    "audit_agents": 6,
    "endpoints": 720
  }
}
```

Verify credentials before scheduling anything. This prints events to the terminal and
writes neither the log nor the state file:

```bash
sudo /var/ossec/framework/python/bin/python3 \
  /var/ossec/wodles/cortex_xdr/cortex_xdr.py --stdout --no-state -v
```

**3. Schedule and ingest it** in the manager's `ossec.conf`:

```xml
  <wodle name="command">
    <disabled>no</disabled>
    <tag>cortex_xdr</tag>
    <command>/var/ossec/framework/python/bin/python3 /var/ossec/wodles/cortex_xdr/cortex_xdr.py</command>
    <interval>5m</interval>
    <run_on_start>yes</run_on_start>
    <ignore_output>yes</ignore_output>
    <timeout>300</timeout>
  </wodle>

  <localfile>
    <log_format>json</log_format>
    <location>/var/ossec/logs/cortex_xdr.log</location>
  </localfile>
```

The wodle decides when the collector runs, the `localfile` decides how its output
reaches analysisd. Both are needed. `ignore_output` is `yes` because ingestion belongs
to logcollector, and `timeout` is bounded so one hung API call cannot stall the wodle.

Five minutes is a sensible interval. The collector asks only for what changed since
each watermark, so a shorter interval mostly costs API quota. Raise `timeout` if you
enable `audit_agents` on a large tenant.

**4. Create the log file before restarting the manager.**

```bash
sudo touch /var/ossec/logs/cortex_xdr.log
sudo chmod 640 /var/ossec/logs/cortex_xdr.log
```

logcollector attaches to a tailed file at its end. If the file does not exist when the
manager starts, logcollector retries, and by the time the collector's first run creates
it the events already written sit behind the read position, so that first batch is
skipped in silence. Creating it empty first leaves nothing to skip. This is the most
likely reason a correct install looks like it produces no alerts on day one.

**5. Load the rules.**

```bash
sudo cp ruleset/rules/cortex_xdr_rules.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/rules/cortex_xdr_rules.xml
sudo chmod 660 /var/ossec/etc/rules/cortex_xdr_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t     # syntax check before restarting
sudo systemctl restart wazuh-manager
```

A restart is required. Wazuh 4.14 has no runtime ruleset reload: `wazuh-control` offers
only `start|stop|restart|status|enable|disable|info`.

The file uses IDs `101100` to `101199`. Confirm they are free first, because the
`100200` block in particular is contested:

```bash
grep -rhoE 'rule id="1011[0-9]{2}"' /var/ossec/etc/rules/ /var/ossec/ruleset/rules/
```

If you renumber, keep the `if_sid` relationships intact. Every rule carries a comment
explaining what it fires on and why its level is what it is.

**6. Import the dashboards** through **Dashboards Management > Saved objects >
Import**, with "overwrite" enabled, or from the command line:

```bash
for d in cortex_xdr_dashboard cortex_xdr_endpoints_dashboard cortex_xdr_audit_dashboard cortex_xdr_vega_dashboard; do
  curl -sk -u admin:admin -X POST \
    "https://127.0.0.1/api/saved_objects/_import?overwrite=true" \
    -H "osd-xsrf:true" --form file=@dashboards/$d.ndjson
done
```

The first three reference the `wazuh-alerts-*` index pattern and render without the index
mapping, though date histograms are more useful once it is applied.

`cortex_xdr_vega_dashboard.ndjson` is the visual explorer, built the same way as the one
in `m365_inventory`: vega-lite v5 for the matrices and the trend, and full Vega v5 for
the treemap, which vega-lite cannot express. It holds an endpoint estate treemap coloured
by protection risk, a MITRE tactic against severity matrix, an agent version against
content status matrix, a stacked alert trend, the noisiest hosts split by severity, a
console activity clock by hour and weekday, and agent report outcomes. Every panel
declares `%context%` and `%timefield%`, so the filter bar and the time picker apply to
them as they do to the other dashboards. These panels count documents rather than
aggregating numerically, so they work without the index mapping too.

---

## Configuration Reference

| Key | Default | Meaning |
|---|---|---|
| `fqdn` | required | Tenant host. A full URL is accepted and reduced to the host |
| `api_key_id` | required | The `x-xdr-auth-id` value |
| `api_key` | required | The Standard API key |
| `collect` | incidents, alerts, endpoints, audit_management | Which data sets to poll |
| `lookback_hours` | `24` | How far back a data set reaches on its first run. Capped at 30 days |
| `lookback_hours_by_collector` | `{}` | Per data set override of the above |
| `severities` | all | Restrict incidents and alerts, for example `["high","critical"]` |
| `page_size` | `100` | Records per request. 100 is the hard API cap |
| `base_prefix` | auto | API prefix. Leave unset, see [API Notes](#api-notes) |
| `log_file` | `/var/ossec/logs/cortex_xdr.log` | NDJSON output |
| `state_file` | `/var/ossec/wodles/cortex_xdr/state.json` | Watermarks and endpoint snapshot |

Command line flags, all intended for testing rather than the wodle:

| Flag | Effect |
|---|---|
| `--collect a,b` | Override the configured data sets for one run |
| `--stdout` | Print events instead of writing the log file |
| `--no-state` | Do not read or write state |
| `--since-hours N` | Ignore every watermark and look back N hours |
| `--selftest` | Run internal checks and exit. Needs no credentials and no network |
| `-v` | Request-level logging |

---

## Integration Testing

**1. Offline checks.** These cover the watermark, deduplication, endpoint diffing,
timestamp conversion and size trimming, with no credentials and no network:

```bash
python3 cortex_xdr.py --selftest
```

**2. Verify a real collection** with the `--stdout --no-state` command above. Each data
set reports how many records changed and how many were emitted.

**3. Verify the rules** by piping one emitted line into logtest:

```bash
head -1 /var/ossec/logs/cortex_xdr.log | sudo /var/ossec/bin/wazuh-logtest -l cortex_xdr
```

Expect decoder `json` in phase 2 and a `1011xx` rule in phase 3. Note that logtest
writes to stderr, so a `2>/dev/null` anywhere in the pipeline makes a working rule look
like no match at all.

**4. Verify ingestion** once the wodle has run:

```bash
grep -o '"id":"1011[0-9][0-9]"' /var/ossec/logs/alerts/alerts.json | sort | uniq -c
```

---

## How Incremental Polling Works

Each data set asks for records at or after the highest timestamp it has already seen,
and stores that watermark in `state.json`.

Because that comparison is inclusive, records sitting exactly on the watermark come back
on every poll. The state file therefore also records their identifiers and the next run
drops them. Making the query exclusive instead would be simpler and wrong: two records
can share a millisecond, and the second would be lost. Agent reports carry no unique id,
so they are identified by a hash of the record itself.

State is written only after events are emitted, so a crash mid-run repeats records
rather than dropping them.

**Endpoints are different.** `last_seen` advances on every agent heartbeat, so a plain
watermark would report all 700 endpoints as changed on every poll. The collector keeps a
snapshot of the fields that matter (protection status, connectivity, content version,
isolation, policy, address) and emits an endpoint only when one of them actually
changes, tagging the event with `cortex.changed_fields`. The first run is a baseline and
emits everything once.

Delete `state.json` to force a re-read of the lookback window. `--since-hours N` does the
same for one run without touching the file.

---

## API Notes

These were established against a live tenant and contradict, or are absent from, the
vendor documentation.

**Base prefix.** Cortex XDR 5.x documentation and the tenant console give the API prefix
as `https://api-{fqdn}/XDR/public/v1/...`. A 5.0 EU tenant does not serve there. It
answers on `https://api-{fqdn}/public_api/v1/...` and returns **HTTP 500, not 404**, for
the prefix its own console documents. The collector probes `public_api` first, treats any
non-200 as the wrong prefix, and caches the winner in `state.json`. The 500 is why
resolution cannot look for a 404, and why it runs outside the retrying session.

**Page size** is capped at 100 by the API itself: `0 < search_size <= 100`.

**Timestamps** are epoch milliseconds throughout, and the collector converts them to ISO
before emitting. This is not cosmetic: analysisd stringifies decoded JSON numbers,
turning `1789574797000` into `"1789574797000.000000"`, which no date or numeric mapping
parses cleanly.

**Filter fields** differ from the field names in the responses. Both audit endpoints
filter on `timestamp` while returning the time as `AUDIT_INSERT_TIME` and `TIMESTAMP`
respectively. Filtering on the returned name is rejected with a 500.

**Incident status values** include `resolved_other` and `resolved_true_positive`, neither
of which appears in the documented list. The collector emits a `cortex.is_resolved`
boolean derived from the `resolved` prefix so rules do not depend on an enumeration that
turns out to be incomplete.

**incident_name** was empty on every incident tested, while `description` always carried
the summary, so `cortex.incident_name` falls back to `description`.

**Single-element lists.** Cortex wraps many scalars in one-element lists, such as `ip`,
`user_name` and process image paths. The collector unwraps those so rules and dashboard
aggregations see a plain value, and leaves genuine multi-value lists alone.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `Cortex XDR rejected the credentials (401)` | Wrong API key, or the key is Advanced rather than Standard |
| `Cortex XDR rejected the credentials (403)` | Key is valid but its role cannot read that data set |
| `No Cortex XDR base prefix answered` | Wrong tenant FQDN, or no network path to it |
| Collector runs, no alerts | Rules not loaded, or the manager was not restarted after copying them |
| First batch never alerts, later ones do | The log file did not exist when the manager started. See install step 4 |
| Nothing after the first run | Normal. Only records changed since each watermark are emitted |
| Hundreds of endpoint events every poll | Running a build without endpoint diffing, or `state.json` is being deleted between runs |
| One data set missing, others fine | Check `ossec.log`. A failing collector is logged and skipped so it cannot take the others down |
| `Another collector run holds the lock` | A previous run is still going. Raise `timeout` or lengthen the interval |
| Date panels empty, other panels fine | The index mapping was not merged, so date fields are `keyword` |

The collector logs to stderr, which the wodle captures into `/var/ossec/logs/ossec.log`.
Add `-v` to the `<command>` for request-level detail.

Add logrotate for `/var/ossec/logs/cortex_xdr.log` with `copytruncate` and
`delaycompress`.

---

## Sources

- [Cortex XDR 5.x API reference](https://cortex-docs.paloaltonetworks.com/cortex-xdr-5.x/reference-and-developer-docs/cortex-xdr-api-reference)
- [Get started with Cortex XDR 5.x APIs](https://cortex-docs.paloaltonetworks.com/xdr-5-api)
- [Wazuh command wodle](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html)
- [Wazuh JSON log collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/how-it-works.html)
