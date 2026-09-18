# Cortex XDR (API) - Wazuh Integration

Polls the Cortex XDR REST API for incidents and ingests them as Wazuh alerts.

This is the API pull integration. It is separate from `integrations/cortex/`, which
decodes Cortex XDR syslog output with a custom decoder and is unrelated to this one.
Nothing here replaces or conflicts with that folder: different ingestion path,
different rule IDs, no shared files.

## Compatibility

Tested end to end against a live Cortex XDR 5.0 EU tenant and Wazuh 4.14.7: 125 incidents
pulled across two pages, rules verified for every severity branch, and alerts confirmed
in `alerts.json`.

## What this collects

One Wazuh event per Cortex XDR incident, each time the incident is created or
modified. Incidents are the aggregated, analyst-facing object: a handful per day on
a typical tenant rather than the endpoint alert firehose. Raw alerts are deliberately
not collected, see [Scope](#scope).

## Files

| File | Goes to |
|---|---|
| `cortex_xdr.py` | `/var/ossec/wodles/cortex_xdr/` on the manager |
| `ruleset/rules/cortex_xdr_rules.xml` | `/var/ossec/etc/rules/` on the manager. Required: without it nothing reaches the indexer |

No decoder file ships with this integration and none is needed. The collector writes
NDJSON, logcollector reads it as `json`, and Wazuh's built-in json decoder flattens
each line into the `cortex.*` fields the rules match on.

## Prerequisites

A Cortex XDR API key with a role that can read incidents. In the Cortex console under
**Settings > Configurations > Integrations > API Keys**, create a key and note both
values:

- The **API key** itself, shown once at creation and never again.
- The **API key ID**, the small integer in the ID column, which travels in the
  `x-xdr-auth-id` header.

Use a **Standard** security level key. Advanced keys require a per-request nonce and
SHA-256 signature that this collector does not implement.

Your tenant FQDN is on the same page, in the form
`api-<tenant>.xdr.<region>.paloaltonetworks.com`.

## Installation

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
| `/var/ossec/wodles/cortex_xdr/state.json` | the polling watermark, created by the script |
| `/var/ossec/logs/cortex_xdr.log` | the NDJSON that logcollector tails |
| `/var/ossec/var/run/cortex_xdr.lock` | prevents overlapping runs |

The wodle keeping its own files beside the script is what Wazuh's own wodles do: the
`aws` one stores its state database in `/var/ossec/wodles/aws/buckets_s3/`. RPM and
DEB only manage files they own, so a Wazuh upgrade does not remove this directory.

**2. Write the config,** then `chmod 600` it since it holds an API key. Only `fqdn`,
`api_key_id` and `api_key` are required:

```json
{
  "fqdn": "api-yourtenant.xdr.eu.paloaltonetworks.com",
  "api_key_id": "24",
  "api_key": "REPLACE_WITH_YOUR_API_KEY",
  "lookback_hours": 24,
  "severities": []
}
```

| Key | Default | Meaning |
|---|---|---|
| `fqdn` | required | Tenant host. A full URL is accepted and reduced to the host |
| `api_key_id` | required | The `x-xdr-auth-id` value |
| `api_key` | required | The Standard API key |
| `base_path` | auto | API prefix. Leave unset, see [Base path](#base-path) |
| `lookback_hours` | `24` | How far back the very first run reaches. Capped at 30 days |
| `severities` | all | Restrict collection, for example `["high","critical"]` |
| `page_size` | `100` | Incidents per request. 100 is the documented API cap |
| `log_file` | `/var/ossec/logs/cortex_xdr.log` | NDJSON output |

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

Five minutes is a sensible interval. Incidents are low volume and the collector asks
only for what changed since its watermark, so a shorter interval mostly costs API
quota. There is no benefit to going below one minute.

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

A restart is required. Wazuh 4.14 has no runtime ruleset reload: `wazuh-control`
offers only `start|stop|restart|status|enable|disable|info`.

The file uses IDs `101100` to `101121`. Confirm they are free first, because the
`100200` block in particular is contested:

```bash
grep -rhoE 'rule id="1011[0-9]{2}"' /var/ossec/etc/rules/ /var/ossec/ruleset/rules/
```

If you must renumber, keep the `if_sid` relationships intact.

## Rules

| ID | Level | Fires on |
|---|---|---|
| 101100 | 0 | Anchor. Never alerts |
| 101101 | 3 | Any incident. The row dashboards count |
| 101110 | 3 | Open, low severity |
| 101111 | 6 | Open, medium severity |
| 101112 | 10 | Open, high severity |
| 101113 | 12 | Open, critical severity |
| 101120 | 3 | Incident closed, any `resolved_*` status |
| 101121 | 12 | 4 or more high severity incidents in 10 minutes |

The severity rules all carry `cortex.is_resolved` set to `false`. That guard is not
decoration: Wazuh alerts on the highest-level matching rule rather than the first, so
without it a critical incident closed as a false positive would alert at level 12
again every time an analyst touched it and bumped its `modification_time`.

## Event shape

Each line is one incident under the `cortex.*` namespace. Two fields exist because the
live API disagreed with its own documentation:

- `cortex.incident_name` falls back to the API's `description`. A 5.0 tenant returned an
  empty `incident_name` on all 125 incidents tested, which would otherwise leave every
  alert description ending in a bare colon.
- `cortex.is_resolved` is the string `"true"` or `"false"`, derived from whether the
  status begins with `resolved`. The live tenant returned `resolved_other` and
  `resolved_true_positive`, neither of which appears in the documented status list, so
  the rules match this boolean rather than enumerating status strings that turn out to
  be incomplete.

Fields the API omits are dropped rather than emitted as null, because analysisd
stringifies decoded JSON and a null the index mapping rejects discards the whole alert.

## Testing

The collector has an offline self-check covering the watermark, deduplication and
event shaping. It needs no credentials and no network:

```bash
python3 cortex_xdr.py --selftest
```

To test the ruleset against a sample event without waiting for a real incident:

```bash
printf '%s\n' '{"integration":"cortex_xdr","cortex":{"event_type":"incident","incident_id":"7","incident_name":"Suspicious process","severity":"critical","status":"new","is_resolved":"false","host_count":2}}' \
  | sudo /var/ossec/bin/wazuh-logtest -l cortex_xdr
```

Expect decoder `json` in phase 2 and rule `101113` at level 12 in phase 3.

## Incremental polling

The collector asks for incidents with `modification_time` greater than or equal to
the highest one it has already seen, and stores that watermark in `state.json`.

Because that comparison is inclusive, incidents sitting exactly on the watermark come
back on every poll. The state file therefore also records their ids and the next run
drops them, which is why an incident is not re-alerted every five minutes. Making the
query exclusive instead would be simpler and wrong: two incidents can share a
millisecond, and the second one would be lost.

State is written only after events are emitted, so a crash mid-run repeats incidents
rather than dropping them.

Delete `state.json` to force a re-read of the `lookback_hours` window. `--since-hours N`
does the same for one run without touching the file.

## Base path

Cortex XDR 5.x documentation and the tenant console both give the API prefix as
`https://api-{fqdn}/XDR/public/v1/{endpoint}/`. A 5.0 EU tenant does not serve incidents
there. It answers on `https://api-{fqdn}/public_api/v1/{endpoint}/`, and returns
**HTTP 500, not 404**, for the prefix its own console documents.

The collector therefore probes `public_api/v1` first, treats any non-200 as "wrong
prefix, try the next one", and records the winner in `state.json` so later runs go
straight to it. Set `base_path` in the config only to pin it explicitly.

That 500 is the reason resolution cannot just look for a 404, and the reason it runs
outside the retrying session: retrying a 500 that only means "wrong prefix" would burn
three backoffs per candidate before failing.

## Scope

Incidents only. The API also exposes `get_incident_extra_data` for the alerts inside
an incident, and `get_alerts_multi_events` for the raw alert stream. Both were left out
on purpose: extra data costs one request per incident, and the raw alert stream is
endpoint telemetry volume that belongs in a dedicated pipeline rather than in general
Wazuh alerting. Each incident event already carries `alert_count`, the per-severity
alert counts and `xdr_url`, which is enough to triage and pivot into the console.

Add them when someone has a concrete use case that the incident object cannot answer.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `Cortex XDR rejected the credentials (401)` | Wrong API key, or the key is Advanced rather than Standard |
| `Cortex XDR rejected the credentials (403)` | Key is valid but its role cannot read incidents |
| `No Cortex XDR base path answered` | Wrong tenant FQDN, or a network path that cannot reach it |
| Collector runs, no alerts | Rules not loaded, or the manager was not restarted after copying them |
| First batch never alerts, later ones do | The log file did not exist when the manager started. See install step 4 |
| Nothing after the first run | Normal. Only incidents modified since the watermark are emitted |
| `Another collector run holds the lock` | A previous run is still going. Lower the interval or raise the timeout |

The collector logs to stderr, which the wodle captures into `/var/ossec/logs/ossec.log`.
Add `-v` to the `<command>` for request-level detail.

Add logrotate for `/var/ossec/logs/cortex_xdr.log` with `copytruncate` and `delaycompress`.

## Sources

- [Cortex XDR 5.x API reference](https://cortex-docs.paloaltonetworks.com/cortex-xdr-5.x/reference-and-developer-docs/cortex-xdr-api-reference)
- [Get started with Cortex XDR 5.x APIs](https://cortex-docs.paloaltonetworks.com/xdr-5-api)
- [Wazuh command wodle](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html)
- [Wazuh JSON log collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/how-it-works.html)
