# Configuration

## Connection and credentials

The tool reads indexer connection settings from environment variables. Any variable not
already set is loaded from an env file, `~/.config/wazuh_correlation_pack/indexer.env` by
default (override with `--env-file` or `WCP_ENV_FILE`). Keep that file readable only by you.
Never put credentials in `pack.yml` or in the repository.

| Variable | Default | Purpose |
|---|---|---|
| `WCP_INDEXER_URL` | `https://127.0.0.1:9200` | Indexer REST endpoint (https only). |
| `WCP_INDEXER_USER` / `WCP_INDEXER_PASSWORD` | – (required) | Indexer internal user. |
| `WCP_CA_CERT` | system trust store | Root CA of the indexer (`/etc/wazuh-indexer/certs/root-ca.pem` on the server; a public certificate). |
| `WCP_TLS_SERVER_NAME` | URL host | Certificate name to verify when it differs from the URL host. |
| `WCP_INSECURE` | unset | `1` disables certificate verification (lab only). |
| `WCP_TARGET` | `<host>_<port>` | Name of the manifest file for this cluster. |
| `WCP_STATE_DIR` | `~/.config/wazuh_correlation_pack/state` | Where manifests are kept. |

**Precedence** (highest first), for every setting above: a command-line option (`--state-dir`,
`--env-file`), the process environment, the selected env file (`--env-file`, else `WCP_ENV_FILE`,
else the default file; it only fills variables that are not already set), the built-in default.
The state directory is resolved after the env file is read, so `WCP_STATE_DIR` in an env file is
honoured. Indexer commands print the manifest they use and where its directory came from
(`state: <path> (--state-dir | environment | env file <path> | default)`). Use one env file per
cluster with its own `WCP_STATE_DIR` (and `WCP_TARGET`), e.g. one for a 5.0.0-rc1 lab and one for a
5.0.0-rc2 lab.

**Manifest identity.** A manifest records the `cluster_uuid` of the cluster it was written for.
Every indexer command compares it with the connected cluster (`GET /`) before it uses the
manifest and refuses a manifest of another cluster, before anything is changed. A manifest
written before this check existed has no identity: read-only commands (`plan`, `status`,
`execute`, dry runs of `remove`/`rollback`) warn, and `apply`, `remove --yes` and
`rollback --yes` refuse until you confirm that it belongs to the connected cluster by adding
`--bind-manifest` (which records the identity). Manifests are never migrated, moved or deleted
automatically.

On the 5.0.0-rc1 test server (installation assistant, all-in-one) the indexer listened on
`127.0.0.1:9200` only and its certificate included `127.0.0.1`. From a workstation, use an SSH
tunnel and keep certificate verification on:

```bash
ssh -N -L 127.0.0.1:9201:127.0.0.1:9200 <user>@<wazuh-server>
export WCP_INDEXER_URL=https://127.0.0.1:9201 WCP_CA_CERT=~/root-ca.pem
```

### Permissions

**Sufficient on 5.0.0-rc2; minimality not verified.** The list below is the expected minimum from
the Alerting plugin's action names. On 5.0.0-rc2 the RC2 validation test
`tests/validation/p4_least_privilege_scheduled.py` (`docs/VALIDATION_TESTS.md`) created a user with
only this role, which ran `preflight`, `plan`, `apply`, `status` and `execute`, and whose monitors ran
on schedule and raised alerts; reads outside the role were refused (PASS 15/15,
`evidence/2026-11-22-rc2-candidate/p4.json`). Not verified: that no listed permission is
superfluous, and `remove`/`rollback` by such a user (P4 removes as `admin`).
`tests/api/test_least_privilege.py` (deployment steps) has not been executed. The 5.0.0-rc1 tests
ran as `admin` (`all_access`).

The deploying user is expected to need (role definition ready to review:
`tests/validation/security/wcp_deployer.role.json`):

* cluster: `cluster:admin/opendistro/alerting/monitor/get`, `.../monitor/search`,
  `.../monitor/write`, `.../monitor/delete`, `.../monitor/execute`, `.../alerts/get`
  (or the built-in `alerting_full_access` role), and `cluster:monitor/main` for `preflight`;
* for `preflight` only (read-only; without them `preflight` reports warnings instead of the
  plugin list and the alert-history setting): `cluster:monitor/state` (`GET _cluster/settings`)
  and `cluster:monitor/nodes/info` (`GET _cat/plugins`);
* index: `read` and `indices:admin/mappings/fields/get` on `wazuh-events-v5-system-activity`.

Alerting runs a monitor's search with the roles recorded for the user who created or last
updated it (OpenSearch Alerting behaviour; not verified on 5.0.0-rc1), so deploy with a user whose
roles can read the events index for as long as the monitors exist.

## Profile (`pack.yml`)

`defaults` applies to every correlation; `correlations.<name>` overrides per correlation.

| Key | Default | Meaning |
|---|---|---|
| `indices` | `[wazuh-events-v5-system-activity]` | Indices / data streams searched. |
| `timestamp_field` | `event.start` | Event-time field used for the window. |
| `interval` | `1m` | Alerting schedule (minimum 1m). |
| `allowed_lateness` | `2m` | Ingest delay still counted. Increases the lookback, not the window. |
| `composite_size` | `500` | Groups per composite page (Alerting pages through all). |
| `max_events_per_group` | `100000` | Events evaluated per group per run; above it the oldest are ignored. |
| `event_identity_field` | `null` | Field identifying one delivered record; repeated values are skipped. No field of the stock 5.x pipeline qualifies (`wazuh.event.id` differs between copies), so source-event deduplication is not performed in a supported configuration. |
| `enabled` | `true` | Create the monitor enabled or disabled. |
| `actions` | `[]` | Notification actions (see below). |
| `context_fields` | `[wazuh.agent.name]` | Extra fields shown in the alert bucket (top 5 values). |
| `extra_filters` | `[]` | Additional query DSL filters (e.g. exclude scanner addresses). |

Thresholds, windows and grouping are **not** profile settings: they are part of the
detection definition (`correlations/*.yml`). To change them, copy the correlation into your
own content directory (keep `--content` pointing at it) or edit the YAML and redeploy; the
change is picked up as an update.

### Local overrides

Keep site-specific settings in a separate file and pass it with `--override`:

```yaml
# site.yml
defaults:
  allowed_lateness: 5m
correlations:
  wcp_ssh_bruteforce:
    extra_filters:
      - bool: {must_not: [{term: {source.ip: "192.0.2.10"}}]}   # vulnerability scanner
    actions:
      - name: soc-slack
        channel_id: <Notifications channel config id>
        notify_on: [NEW]
```

```bash
python -m wcp --override site.yml plan
python -m wcp --override site.yml apply
```

### Notifications

**Tested on 5.0.0-rc2 with a webhook channel** (test P5, PASS 19/19,
`evidence/2026-11-22-rc2-candidate/p5.json`): exactly one notification for a NEW alert, one for a
COMPLETED alert when configured, none for DEDUPED runs, and a notification for an alert that existed
for a single run. Other channel types were not tested.

By default the Notifications plugin blocks webhooks to loopback, link-local, private (RFC 1918) and
TEST-NET addresses (`opensearch.notifications.core.http.host_deny_list`). An administrator must
change that list before a webhook to an internal receiver can work. The P5 lab change is recorded
in `evidence/2026-11-22-rc2-candidate/lab_change_p5_notifications_deny_list.json`.

Each action is sent per alert. `notify_on` selects the alert transitions that notify:

* `NEW` (default): the first run that finds the group over the threshold.
* `COMPLETED`: the first run after the group stopped qualifying (episode end).
* `DEDUPED`: every run while the group keeps qualifying. This re-notifies for unchanged
  activity and is not recommended.

`channel_id` is the id of an existing Notifications channel (Dashboard > Notifications >
Channels). The pack does not create channels. No automatic response (active response, blocking)
is configured by the pack.

## Choosing interval, lateness and window

* The window (Sigma `timespan`) defines the detection; keep it as the threat model needs.
* Set `allowed_lateness` to the delay you expect between an event happening and being
  searchable. On the RC1 test server the normal delay was 14.5 s (live sshd) to ~28 s (replayed
  file lines); events produced while the indexer was down were delivered after the outage,
  minutes late. `allowed_lateness` is the delay that is guaranteed to be tolerated (assuming
  on-time scheduler runs, see `ARCHITECTURE.md`, "Late events"); somewhat later events can still be counted
  depending on the scheduling phase, and events older than the lookback
  (`window + allowed_lateness + interval`) when they become searchable are never counted.
* Keep the monitor search well inside `plugins.alerting.input_timeout` (30 s on 5.0.0-rc1): a run
  whose search times out produces no alerts for that period.
* **Monitor capacity** (`plugins.alerting.monitor.max_monitors`).
  * *Observed on the 5.0.0-rc1 server*: value **10**, the default (not set explicitly; see
    `settings` vs `settings_explicit` in `evidence/2026-11-22-rc1-105573d/platform_facts.json`).
    On 2026-11-22 the Alerting configuration index held 4 monitor documents (the pack's four) and
    22 Security Analytics composite workflows. Creating the pack's 4 monitors, and the lateness
    test's temporary 5th, succeeded.
  * *Scope*: one cluster-wide limit, shared by everyone who creates monitors on the cluster (all
    users, tools and packs); it is not per user, per pack or per index. It is checked only when a
    monitor is **created** (`wcp apply` creating a missing monitor, a reinstall after `remove`);
    updating existing monitors (`wcp apply` with changes, as for the pending Windows spray
    update on the RC1 server) is not checked. What counts, from the `wazuh-indexer-alerting`
    source (branch `main`, 5.1.0-alpha0; **not verified against the 5.0.0-rc1 build**): every
    document with `monitor.type: monitor` in the Alerting configuration index, except monitors
    owned by Security Analytics; composite workflows are not monitor documents. The error is
    "This request would create more than the allowed monitors [10]".
  * *Consequence*: the pack needs 4 of the cluster's 10 (5 while `test_lateness_scheduler.py`
    runs). `wcp apply` cannot create the pack's monitors if 7 or more other monitors already
    exist. The setting is dynamic (same source; `PUT _cluster/settings`); raising it is a
    cluster administrator's decision, not done by the pack.
* A longer lookback also keeps an alert ACTIVE longer after the activity stops (the alert
  completes when no qualifying window remains inside the lookback).
