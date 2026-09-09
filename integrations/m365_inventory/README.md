# Microsoft 365 License Inventory-Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
    * [Initial Microsoft 365 Configuration](#initial-microsoft-365-configuration)
    * [Initial Wazuh Configuration](#initial-wazuh-configuration)
    * [Using the Integration Files](#using-the-integration-files)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Troubleshooting](#troubleshooting)
* [Sources](#sources)

## Introduction

Polls Microsoft Graph for licence pools, seat assignments, renewal dates and user
counts across one or many Microsoft 365 tenants, and writes them as newline-delimited
JSON for a Wazuh agent to tail. Built for MSP-style multi-tenant use: one collector
host, N tenants, one set of dashboards.

It answers what the M365 admin centre cannot answer across tenants: seats bought
versus assigned, what renews soon and how many seats it carries, over-assignment,
licences on disabled accounts, and self-service sign-ups.

The collector diffs each run against the previous one and reports changes rather than
state, which is what makes a 10-minute cadence viable: without it a subscription 20
days from renewal would fire 144 identical alerts a day.

## Prerequisites

A working Wazuh deployment with an agent enrolled on the host that will run the
collector is assumed. Tested on 4.14.6.

* Outbound HTTPS from that host to `login.microsoftonline.com` and
  `graph.microsoft.com`.
* An Entra ID application registration, one per tenant or one multi-tenant app.
* Nothing to install: the collector runs on Wazuh's embedded interpreter,
  `/var/ossec/framework/python/bin/python3`, which already ships `requests`.

## Installation and Configuration

### Initial Microsoft 365 Configuration

The integration only issues `GET` requests and changes nothing in the tenant.

Create an Entra ID application registration and grant these application permissions with admin consent:

| Permission | Needed for |
|---|---|
| `Organization.Read.All` | `/organization`, `/subscribedSkus`, `/directory/subscriptions` |
| `User.Read.All` | `/users?$count=true` and the `assignedLicenses/$count ne 0` filter |

`Directory.Read.All` also works but is higher-privileged. Do not grant both.

Record the client secret's expiry date for the config below. An expired secret stops
collection silently, and rule 100612 is what warns you first.

### Initial Wazuh Configuration

**Add the field mappings before importing any dashboard.** Wazuh's decoder emits
every value as a string and the default template maps `data.*` to `keyword`, so
`"284"` sorts before `"56"` and nothing aggregates. Numeric panels, heatmaps and date
histograms fail outright with `Field [...] of type [keyword] is not supported for
aggregation [max]`.

`m365_index_mapping.json` holds the 91 field mappings. Merge them into the Filebeat
template and let Filebeat push it:

```bash
# 1. Back up the template first.
cp /etc/filebeat/wazuh-template.json /etc/filebeat/wazuh-template.json.bak

# 2. Merge the m365 block into mappings.properties.data.properties.
vim /etc/filebeat/wazuh-template.json

# 3. Push the template to the indexer.
filebeat setup --index-management -E setup.template.overwrite=true
```

Two things to know afterwards:

* **New indices only.** `wazuh-alerts-4.x-*` rolls daily, so the types apply from the
  next index, not to existing data. Refresh the field list under *Dashboards
  Management -> Index patterns* once it has rolled.
* **Re-merge after anything replaces the template.** A Wazuh upgrade that ships a new
  `wazuh-template.json` drops these mappings, so repeat the steps above and keep the
  fragment somewhere you will find it.

### Using the Integration Files

| File | Goes where |
|---|---|
| `m365_inventory.py` | `/var/ossec/wodles/m365_inventory/` on the collector host |
| `ruleset/rules/m365_inventory_rules.xml` | Manager custom rules. Required: without it nothing reaches the indexer |
| `m365_index_mapping.json` | Merged into the Filebeat template. Required: without it numeric panels fail |
| `dashboards/m365_dashboard.ndjson` | Cross-tenant overview |
| `dashboards/m365_tenant_dashboard.ndjson` | Per-tenant detail |
| `dashboards/m365_vega_dashboard.ndjson` | Vega visual explorer |
| `dashboards/m365_vega_compliance_dashboard.ndjson` | Licence compliance |

**1. Install the collector.**

```bash
mkdir -p /var/ossec/wodles/m365_inventory
cp m365_inventory.py /var/ossec/wodles/m365_inventory/
chown -R root:wazuh /var/ossec/wodles/m365_inventory
chmod 750 /var/ossec/wodles/m365_inventory
chmod 750 /var/ossec/wodles/m365_inventory/m365_inventory.py
```

Everything lives under `/var/ossec`, in the directories Wazuh already uses for each
purpose:

| Path | Holds |
|---|---|
| `/var/ossec/wodles/m365_inventory/m365_inventory.py` | the collector |
| `/var/ossec/wodles/m365_inventory/config.json` | credentials, mode `0600` |
| `/var/ossec/wodles/m365_inventory/state.json` | the previous run's snapshot, created by the script |
| `/var/ossec/logs/m365_inventory.log` | the NDJSON that logcollector tails |
| `/var/ossec/var/run/m365_inventory.lock` | prevents overlapping runs |

The wodle keeps its own files beside the script, which is what Wazuh's own wodles do:
the `aws` one stores its state database in `/var/ossec/wodles/aws/buckets_s3/`. RPM
and DEB only manage files they own, so this directory is not removed by a Wazuh
upgrade, and losing the state file costs one baseline re-flush anyway.

**2. Write `/var/ossec/wodles/m365_inventory/config.json`,** then
`chmod 600` it since it holds credentials. Everything except `tenants` has a working default, here is a complete example with two tenants:

```json
{
  "thresholds": {
    "critical_days": 30,
    "warning_days": 90
  },
  "free_sku_part_numbers": [
    "FLOW_FREE", "POWER_BI_STANDARD", "POWERAPPS_DEV", "POWERAPPS_VIRAL",
    "MICROSOFT_BUSINESS_CENTER", "TEAMS_EXPLORATORY", "STREAM",
    "WINDOWS_STORE", "MCOMEETADV_FREE", "RMSBASIC"
  ],
  "nominal_unit_threshold": 10000,
  "min_pool_size_for_exhaustion": 5,
  "secret_expiry_warning_days": 30,
  "currency": "EUR",
  "sku_display_names": {
    "O365_BUSINESS_PREMIUM": "Microsoft 365 Business Standard",
    "VISIOCLIENT": "Visio Plan 2",
    "POWER_BI_PRO": "Power BI Pro",
    "POWER_BI_STANDARD": "Microsoft Fabric (Free)",
    "FLOW_FREE": "Microsoft Power Automate Free",
    "POWERAPPS_DEV": "Microsoft Power Apps for Developer",
    "MICROSOFT_BUSINESS_CENTER": "Microsoft Business Center",
    "Microsoft_Teams_Rooms_Pro": "Microsoft Teams Rooms Pro",
    "ENTERPRISEPACK": "Office 365 E3",
    "SPE_E3": "Microsoft 365 E3",
    "SPE_E5": "Microsoft 365 E5",
    "AAD_PREMIUM": "Entra ID P1",
    "EMS": "Enterprise Mobility + Security E3"
  },
  "tenants": [
    {
      "name": "Contoso HQ",
      "tenant_id": "00000000-0000-0000-0000-000000000001",
      "client_id": "00000000-0000-0000-0000-000000000002",
      "client_secret": "REPLACE_ME"
    },
    {
      "name": "test tenant",
      "tenant_id": "12312312312312",
      "client_id": "12312313213",
      "client_secret": "12312321321321"
    }
  ]
}
```

`name` is what the dashboards filter on; keep it stable. Optional keys, where
`log_file`, `state_file` and `lock_file` override the paths in the table above and are
best left unset: `log_file`, `state_file`, `lock_file`, `thresholds`
(`{"critical_days": 30, "warning_days": 90}`), `secret_expiry_warning_days`,
`sku_costs` (per-seat monthly price by SKU part number, enables the cost panels),
`currency`, `sku_display_names`, `free_sku_part_numbers`, `nominal_unit_threshold`
and `min_pool_size_for_exhaustion`. Numeric values are coerced on load, so `"30"` is
accepted with a warning rather than failing a tenant later.

Validate without writing anything:

```bash
/var/ossec/wodles/m365_inventory/m365_inventory.py --stdout --no-state -v
```

**3. Schedule and ingest it** in the agent's `ossec.conf`:

```xml
  <wodle name="command">
    <disabled>no</disabled>
    <tag>m365_inventory</tag>
    <command>/var/ossec/framework/python/bin/python3 /var/ossec/wodles/m365_inventory/m365_inventory.py</command>
    <interval>10m</interval>
    <run_on_start>yes</run_on_start>
    <ignore_output>yes</ignore_output>
    <timeout>300</timeout>
  </wodle>

  <localfile>
    <log_format>json</log_format>
    <location>/var/ossec/logs/m365_inventory.log</location>
  </localfile>
```

The wodle decides when the collector runs, the `localfile` decides how its output
reaches the manager. Both are needed. `ignore_output` is `yes` because ingestion
belongs to logcollector, and `timeout` is bounded so one hung Graph call cannot stall
the wodle. 10 minutes is a good default and 5 is the floor; the constraint is Graph,
at roughly nine requests per tenant per run.

If you push this via `agent.conf` from an agent group, the agent refuses
remotely-defined commands until `wazuh_command.remote_commands=1` is set in
`/var/ossec/etc/local_internal_options.conf`. This is the most common reason a correct
wodle never appears to run.

Add logrotate for `/var/ossec/logs/m365_inventory.log` with `copytruncate` and
`delaycompress`, sized for 144 runs a day rather than one.

**4. Load the rules.** Copy `ruleset/rules/m365_inventory_rules.xml` to
`/var/ossec/etc/rules/`, or paste it under **Management -> Rules -> Custom rules** on
Wazuh Cloud, then restart the manager. The file is the reference: every rule carries a
comment explaining what it fires on.

It uses IDs 100600 to 100620. Confirm they are unused first, and if you have to
renumber, keep the `if_sid` parent relationships intact.

Two things in that file are easy to break:

* **The rules under the change gate (100615) must stay there.** Re-parenting one onto
  the snapshot rule makes it fire every run instead of on a transition, which at a
  ten-minute cadence is 144 alerts a day per affected SKU per tenant. Do not reach for
  `<ignore>` to quiet that down either: it mutes a rule globally, so one tenant would
  suppress every other tenant's alerts.
* **Level 0 never reaches the indexer,** so level 3 is the floor for anything the
  dashboards need to read.

**5. Import the dashboards** you want, through *Dashboards Management -> Saved
objects -> Import* with **"Check for existing objects"**, so the stable `m365-*` IDs
are reused. "Create new objects" clones every panel under a fresh UUID, and you end up
editing one copy while the dashboard renders another.

**These four are a menu, not a set.** They were built to cover different ways of
looking at the same data, and they overlap on purpose. Import whichever suit you,
delete the rest, and treat them as a starting point to adapt rather than a finished
product: panel choice, layout and colour are all preference. The one thing worth
keeping from each is the query behind a panel, since that is where the field and
aggregation choices are already correct.

| Dashboard | Panels | Answers |
|---|---|---|
| Licence and user inventory | `m365_dashboard.ndjson` contains 20 visualisations | Cross-tenant totals for the whole estate |
| Tenant detail | `m365_tenant_dashboard.ndjson`, 23 panels | Per tenant, with tenant as a filter and a chart axis |
| Visual explorer | `m365_vega_dashboard.ndjson` contains 8 panels | Treemap, dumbbell, bubble quadrant, labelled heatmap |
| Licence compliance | `m365_vega_compliance_dashboard.ndjson` contains 10 panels | Findings matrix, exposure in seats, headroom, self-service |

They are separate because of how the events are shaped. The overview's KPI tiles read
`collection_summary`, a run-level rollup that carries no tenant fields at all, which
is what makes them correct at any tenant count and also why a `tenant_name` filter
blanks them. **Do not add tenant filters to the overview**; use the tenant dashboard,
where every panel reads an event type carrying `tenant_name` and aggregates by it.

Three conventions before editing a panel: charts use `max` over the range while
tables use a Top Hit for the exact latest value, since a Top Hit returns a string a
chart cannot plot; donuts and histograms count distinct SKUs, not documents, which
would multiply by the number of runs in range; and every Vega spec needs
`"%context%": true` and `"%timefield%": "timestamp"` or it silently ignores the
dashboard filters. Vega binds its index by name, so if yours is not `wazuh-alerts-*`,
edit `index` in each spec's `data.url`.

## Integration Steps

1. `wazuh-modulesd` runs the wodle on its interval, executing the collector as root.
2. Per tenant it takes a client-credentials token, then issues about nine Graph `GET`
   calls: `/organization`, five `/users?$count=true` variants, `/subscribedSkus` and
   `/directory/subscriptions`.
3. It diffs each SKU against `state_file`, appends one NDJSON line per event to
   `log_file` and fsyncs. A failed tenant emits an `error` event without stopping the
   others. After all tenants it writes one `collection_summary` and replaces the state
   file. State is written after the events, so a crash re-reports a change rather than
   losing one.
4. `wazuh-logcollector` tails the file, `wazuh-analysisd` decodes, the rules match.

`license`, `tenant_summary`, `sku_removed` and `error` all carry `tenant_name`;
`collection_summary` is the cross-tenant rollup and does not. The complete field list
with types is `m365_index_mapping.json`.

Change detection adds `state_changed`, `changed_fields`, `changed_summary`,
`assigned_units_delta`, `first_seen` and `baseline`. `days_to_next_lifecycle` is
deliberately not tracked, since it decrements daily and would mark every dated SKU
changed once a day. A baseline run, including a lost state file, reports every
currently-true condition once and then goes quiet.

## Integration Testing

**1. Verify a real collection** with the `--stdout --no-state` command above. On the
first run check that free SKUs were classified correctly, that
`disabled_licensed_users` is present, and that `date_source` is `subscription` rather
than `unavailable`.

**2. Verify the rules** by pasting one emitted line into
`/var/ossec/bin/wazuh-logtest`. An unchanged SKU should match 100601 at level 3.

**3. Verify the mapping,** which every numeric panel depends on:

```bash
curl -k -u USER:PASS \
  "https://localhost:9200/wazuh-alerts-4.x-*/_mapping/field/data.m365.days_to_next_lifecycle?pretty"
```

It must report `long`, not `keyword`. Then open each dashboard and confirm the tenant
filter narrows every panel.

## Troubleshooting

Run with `-v` first: it logs the interpreter and library versions.

| Symptom | Cause and fix |
|---|---|
| The wodle never runs, nothing in `ossec.log` | Pushed via `agent.conf` without `wazuh_command.remote_commands=1`. Restart the agent after adding it |
| The wodle runs but nothing reaches the manager | The wodle only schedules. Check the log file grows, then `grep m365_inventory /var/ossec/logs/ossec.log` |
| Events in the log, nothing on the dashboard | Rules not loaded or at level 0. Feed one line to `wazuh-logtest` and confirm a `rule.id` |
| Rule changes have no effect | Two files defining the same IDs; files load alphabetically. `grep -rl 100615 /var/ossec/etc/rules/` and keep one |
| Edits to a visualisation have no effect | Duplicate saved objects from importing with "Create new objects". Delete every M365 object and import once |
| Numeric fields still `keyword` | Mapping applies to new indices only. Wait for the daily roll, then refresh the index pattern. If it persists, check the nesting |
| A Vega panel ignores the tenant filter | Its spec is missing `"%context%": true`, or sets a `body.query` that conflicts with it |
| Every SKU alerts on every run | Change detection is not working. Check for a state-file warning and that the wodle directory is writable |
| `403` on `/users` but `/subscribedSkus` works | `User.Read.All` missing, or admin consent not granted after adding it |
| A field shows as unavailable in a panel | It has no data yet. `currency` needs `sku_costs`, `secret_expiry_bucket` needs `client_secret_expires`, `last_expiry_bucket` needs a SKU to disappear |

## Sources

* [Wazuh: command wodle reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html)
* [Wazuh: rules XML syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
* [Wazuh: localfile reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)
* [Wazuh: indexer indices and templates](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html)
* [Microsoft Graph API reference](https://learn.microsoft.com/en-us/graph/api/overview)
* [OpenSearch Dashboards: Vega visualizations](https://opensearch.org/docs/latest/dashboards/visualize/vega/)
