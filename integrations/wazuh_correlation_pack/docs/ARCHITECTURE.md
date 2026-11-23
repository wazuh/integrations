# Architecture

## Layers

```
 correlations/*.yml   Sigma correlation rules (event_count, value_count)   ─┐  backend-independent
 rules/*.yml          Sigma base rules (selections on WCS fields)          ─┘  content + tests
          │
          ▼  wcp/sigma.py   load + validate the supported subset (rejects everything else)
          ▼  wcp/query.py   selection -> OpenSearch query DSL
 pack.yml ─► wcp/alerting.py  correlation + settings -> Alerting bucket-level monitor
          ▼  wcp/deploy.py  plan / apply / status / remove / rollback, ownership, manifest
          ▼
 Wazuh indexer: Alerting plugin  ->  Alerting > Alerts
```

The Sigma files carry no Alerting-specific settings. When native Sigma correlation support
lands in the Security Analytics plugin (wazuh/wazuh-indexer-security-analytics#119), the
`rules/` and `correlations/` files and the behavioural test scenarios can be reused with a
different backend; only `wcp/alerting.py` and `pack.yml` are specific to the Alerting workaround.

## Data source: events, not findings

The monitors read normalized **events** (data stream `wazuh-events-v5-system-activity` on
5.0.0-rc1; the per-category streams have no suffix, so `wazuh-events-v5-<category>-*` matches
nothing), not detector findings (`wazuh-findings-v5-*`):

* Findings follow rule matches, not activity. On the test server the stock rule "Failed
  authentication attempt" produced 15 findings for 9 SSH password attempts (one per
  `authentication-failure` event: PAM and sshd lines of the same attempt), and one event can match
  several rules. Its title is templated with the user name, so filtering findings by title is
  fragile (`evidence/2026-11-21-rc1/findings_vs_events.json`).
* The selection of the counted events lives in the pack's own base rule, so the count does not
  depend on which stock Sigma rules are enabled in a detector, or on detector scheduling delay.
* Base rules use the fields produced by the stock decoders (`decoder/system-auth/0`,
  `decoder/windows-security/0`); the pack adds no decoders.

## Event time

`@timestamp` is the time the manager processed the event (seconds after the log was written;
minutes for events buffered during an indexer outage). `event.start` is the time written in the
log record (syslog timestamp for sshd, `TimeCreated` for Windows). The window uses `event.start`.

## Timing model

| Setting | Source | Meaning |
|---|---|---|
| window | Sigma `timespan` | Event-time span (`event.start`) the counted events must fit in: a set qualifies when `last - first < window` (half-open). |
| interval | `pack.yml` `interval` | Alerting schedule. |
| allowed lateness | `pack.yml` `allowed_lateness` | Maximum ingest delay (ingest time − event time) still counted. |
| lookback | derived: window + lateness + interval | Event-time range read on each run. |

The window is never widened. Inside the lookback, a Painless `scripted_metric` sorts each
group's events by event time and computes, with a two-pointer sweep, the maximum number of
events (`event_count`) or of distinct values (`value_count`) in any sliding window of exactly
`window` length. The trigger fires for a group when that maximum reaches the threshold.

Why the lookback is `window + lateness + interval`: a qualifying window starting at event time
`a` is complete in the index by `a + window + lateness`; the first scheduled run after that is
before `a + window + lateness + interval`, and that run still reads back to `a`.

Consequences, observed on 5.0.0-rc1 (see `evidence/2026-11-21-rc1/`):

* The lookback is longer than the window, but it does not change what qualifies: only events
  less than `window` apart are counted together.
* `allowed_lateness` is a guarantee, not a cut-off: an event searchable within it is always
  counted; a later one is counted as long as its qualifying set is still inside some run's
  lookback (a replayed set searchable 143-150 s after its event times was counted with a 120 s
  lateness); a set older than the lookback is never counted.
* An alert stays ACTIVE until the qualifying set ages out of the lookback: for the 2-minute
  brute-force correlation, roughly 5 minutes after the burst (observed 276-321 s), not 2 minutes.
* The guarantee assumes runs on schedule (observed: fixed 60 s grid anchored to `enabled_time`,
  no jitter), "searchable" = visible after refresh, and searches within the Alerting input timeout
  (30 s) and cluster limits. See README "Timing and alert lifecycle" for the measured phase
  dependence beyond the guarantee.

## Grouping and alert identity

`group-by` fields become the sources of a `composite` aggregation; every distinct combination is
a bucket. Alerting identifies a bucket-level alert by the hash of its bucket keys, so:

* different agents / source IPs never share an alert;
* while a group keeps qualifying on consecutive runs, its alert stays the same ACTIVE alert
  (Alerting marks it DEDUPED; no new alert; with the default `notify_on: [NEW]` no action should
  run again - notification delivery itself was not tested);
* on the first run where the group no longer qualifies inside the lookback, Alerting marks the
  alert COMPLETED (on 5.0.0-rc1, `plugins.alerting.alert_history_enabled` defaults to `false`, so
  the completed alert is then deleted instead of being kept in history);
* later activity of the same group creates a NEW alert (a new episode).

Events without a value in a group-by field (or in the `value_count` field) are excluded by an
`exists` filter; they are not merged into an "empty" group.

## Derived values

Sigma `value_count` counts one field. A Windows account needs two (realm and name), and the
decoded realm field depends on the reporting subject. `wcp/identity.py` defines derived values
(prefix `wcp.`) computed per event in the Painless map script, with a Python reference used by the
unit tests; the query/API test checks that both give the same identities. A derived value can only
be a correlation's `condition.field`; the monitor's `exists` filter uses its required WCS fields.
Monitors without a derived value use the shared map script unchanged.

## Counting units and duplicates

* Base rules select one event per counted unit (e.g. one sshd `Failed password` line per SSH
  credential attempt), not every log line of the attempt.
* Source-event deduplication is **not performed**: `event_identity_field` (off by default) would skip
  repeated values of one field, but no field of the stock 5.x pipeline identifies one log record.
  Alert suppression (one ACTIVE alert per group, DEDUPED runs) is the Alerting plugin's, and is
  unrelated to counting.
  Identical content is never collapsed: two genuine identical lines are two attempts. On
  5.0.0-rc1 every collected record gets its own `wazuh.event.id`, so a record collected twice
  (double `<localfile>`, file re-read) is counted twice; retransmission inside the pipeline was
  not tested (README, "Duplicates").

## Distinct counts

`value_count` uses an exact distinct count (a `HashMap` inside the sliding window), not the
`cardinality` aggregation, whose HyperLogLog++ estimate is approximate. Exactness is bounded by
`max_events_per_group` (default 100000 events per group per lookback); above it only the most
recent events are evaluated, which can only under-count.

## Ownership and state

* A monitor belongs to the pack only if its stored query carries the marker
  `aggregations.wcp_groups.meta.wcp.pack == "wazuh_correlation_pack"` (aggregation `meta` is
  kept verbatim by the Alerting plugin; monitor `ui_metadata` is not persisted on 5.0.0-rc1), or
  if its id is recorded in this target's manifest as created by the pack. Other monitors and
  workflows are never modified or deleted.
* The marker also records the correlation id, pack version and a content hash used to decide
  create / update / no-op.
* A local manifest (`~/.config/wazuh_correlation_pack/state/<target>.manifest.json`) records the
  monitor ids and full bodies of each deployment (last 20), for `rollback` and audit.
* The pack creates no indices, detectors, integrations, decoders or cluster settings.
