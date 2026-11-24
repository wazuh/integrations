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

The sshd syslog timestamp has 1-second resolution and no year or time zone. Only endpoints running
in UTC were tested.

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
  (30 s) and cluster limits. See "Late events" below for the measured phase dependence beyond
  the guarantee.

### Settings of the shipped correlations

| Setting | Brute force and burst | Spray |
|---|---|---|
| Window, measured on event time (`event.start`) | 2 minutes | 10 minutes |
| Monitor interval | 1 minute | 1 minute |
| Allowed lateness | 2 minutes | 2 minutes |
| Lookback read on each run | 5 minutes | 13 minutes |

The **window** decides whether activity is enough for an alert. For brute force, 8 events must lie
less than 120 s apart. Eight attempts spread over exactly 120 s do not alert, and neither do
4 + 4 attempts 150 s apart, even though all of them fall within the lookback.

The **lookback** decides which events each run reads. It sets how late an event can become
searchable and still count. It also sets how long an alert stays active: the alert stays active
while a qualifying set of events remains within the lookback.

### Alert lifecycle (observed on 5.0.0-rc1)

* An alert appears at the first run after a qualifying set of events becomes searchable.
* While activity continues, the same alert stays active. Runs do not create new alerts.
* The alert ends at the first run where no qualifying set remains within the lookback. For a short
  burst this is about 5 minutes after the burst. Without alert history, the ended alert is deleted.
* New activity after that raises a new alert.

### Late events

A qualifying set is counted if each event becomes searchable within the allowed lateness
(2 minutes) of its event time. This holds only when:

1. the monitor runs on schedule. Missed runs are not caught up;
2. the agent, manager and indexer deliver the event in time. All delays count towards the
   2 minutes;
3. the search finishes within `plugins.alerting.input_timeout` (30 s on 5.0.0-rc1), and the group
   has no more than `max_events_per_group` events in the lookback.

Two minutes is a guaranteed minimum, not a cut-off. With the 300 s lookback and a burst that lasts
`s` seconds, a delay of up to about `240 - s` seconds is always counted. Up to about `300 - s`
seconds is counted only when the events become searchable just before a run. Tests with the real
scheduler matched this: delays of 110-133 s were always counted, 264 s depended on timing, and
335 s was never counted. Events older than the lookback when they become searchable are never
counted, for example after a long indexer outage.

An alert caused only by late events may stay active for a single run. Without alert history it then
disappears about a minute later, so configure a notification or enable alert history.

On the 5.0.0-rc1 server, a live SSH attempt was searchable 14.5 s after it happened. Alerts
appeared 19.6 s and 35.5 s after the last attempt of two bursts.

## Grouping and alert identity

`group-by` fields become the sources of a `composite` aggregation; every distinct combination is
a bucket. Alerting identifies a bucket-level alert by the hash of its bucket keys, so:

* different agents / source IPs never share an alert;
* while a group keeps qualifying on consecutive runs, its alert stays the same ACTIVE alert
  (Alerting marks it DEDUPED; no new alert; with the default `notify_on: [NEW]` no action runs
  again - notification delivery was verified with a webhook on 5.0.0-rc2, test P5 in
  `VALIDATION_TESTS.md`);
* on the first run where the group no longer qualifies inside the lookback, Alerting marks the
  alert COMPLETED (on 5.0.0-rc1, `plugins.alerting.alert_history_enabled` defaults to `false`, so
  the completed alert is then deleted instead of being kept in history);
* later activity of the same group creates a NEW alert (a new episode).

Events without a value in a group-by field (or in the `value_count` field) are excluded by an
`exists` filter; they are not merged into an "empty" group.

The backend can also group across agents, for example by source IP only. No shipped correlation
does this, and it was not tested.

## Derived values

Sigma `value_count` counts one field. A Windows account needs two (realm and name), and the
decoded realm field depends on the reporting subject. `wcp/identity.py` defines derived values
(prefix `wcp.`) computed per event in the Painless map script, with a Python reference used by the
unit tests; the query/API test checks that both give the same identities. A derived value can only
be a correlation's `condition.field`; the monitor's `exists` filter uses its required WCS fields.
Monitors without a derived value use the shared map script unchanged.

## Windows account identity

The README section "Grouping" specifies the account the Windows spray monitor counts
(`wcp.windows_target_account`). This section explains why only the failed target's fields are used.

How the stock 5.0 decoders (`decoder/windows-event/0`, `decoder/windows-security/0`; observed on
5.0.0-rc1 and 5.0.0-rc2) map a 4625 event:

| Field of the decoded 4625 event | No reporting subject (network logons such as SMB, RDP) | Reporting subject present (for example local logons) |
|---|---|---|
| `user.target.name` | TargetUserName | TargetUserName |
| `user.target.domain` | not set | TargetDomainName |
| `user.domain` | TargetDomainName | SubjectDomainName (the subject's domain) |

`user.target.domain` is the only indexed field whose value demonstrably comes from the failed
target's domain. The pack never uses `user.domain`: when a subject is present it holds the
subject's domain. One case cannot be told apart from a subject-absent event: a subject name with the
null SID and no TargetDomainName gives `user.id` equal to `user.target.id` and `user.domain` equal
to the subject's domain (5.0.0-rc2, test P1). A monitor cannot read the raw event to check, because
`event.original` is not indexed and has no doc values.

As a result, network logons have no known domain and are counted by user name (`?\name`). The
counting script (`PAINLESS_REDUCE_UNKNOWN_REALM` in `wcp/alerting.py`) counts `?\name` only if no
known-domain account with the same user name is in the window. This removed the double count of one
target seen in both decoded shapes, at the cost of possible under-counting. The rules and their
Python reference are in `wcp/identity.py`.

## Counting units and duplicates

* Base rules select one event per counted unit (e.g. one sshd `Failed password` line per SSH
  credential attempt), not every log line of the attempt. One failed SSH password produces several
  sshd and PAM log lines, and the stock decoder marks several of them as
  `event.action: authentication-failure` (observed on 5.0.0-rc1):

  | Activity | sshd lines | `authentication-failure` events | Counted by the pack |
  |---|---|---|---|
  | 1 attempt, unknown user | 5 | 3 | 1 |
  | 1 attempt, existing user | 3 | 2 | 1 |
  | 3 attempts, existing user, one connection | 6 | 5 | 3 |

  Counting `authentication-failure` events would reach a threshold of 8 after only 3 to 5
  attempts. sshd writes exactly one `Failed <method>` line per rejected password, so the pack counts
  those. `Failed publickey` and `Failed none` are not password guessing and are not counted.
* Source-event deduplication is **not performed**: `event_identity_field` (off by default) would skip
  repeated values of one field, but no field of the stock 5.x pipeline identifies one log record.
  Alert suppression (one ACTIVE alert per group, DEDUPED runs) is the Alerting plugin's, and is
  unrelated to counting.
  Identical content is never collapsed: two genuine identical lines are two attempts. On
  5.0.0-rc1 every collected record gets its own `wazuh.event.id`, so a record collected twice
  (double `<localfile>`, file re-read) is counted twice; retransmission inside the pipeline was
  not tested (README, "Known limitations").
* Duplicates affect event counts (`event_count`: SSH brute force, Windows burst). They do not
  increase a distinct count (`value_count`: both spray monitors): a duplicate record carries the
  same user name or account, which is counted once per window.

## Distinct counts

`value_count` uses an exact distinct count (a `HashMap` inside the sliding window), not the
`cardinality` aggregation, whose HyperLogLog++ estimate is approximate. Exactness is bounded by
`max_events_per_group` (default 100000 events per group per lookback); above it only the most
recent events are evaluated, which can only under-count. Tested with up to 5000 events in one
group, and 300 through the full pipeline.

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

## Differences from 4.x frequency rules

This describes documented 4.x behaviour. No 4.x system was tested.

| Wazuh 4.x | This pack |
|---|---|
| Evaluated by analysisd as events arrive, on each manager node. | Evaluated by the indexer every minute over indexed events. On the 5.0.0-rc1 test server, alerts appeared 20-36 s after the last attempt. |
| `timeframe` uses the time the manager received the event. | The window uses the event's own time (`event.start`). Late events are handled explicitly. |
| `frequency` counts matches of a parent rule, often several lines per attempt. | Counts one event per attempt. |
| The result is a rule match with level, groups and MITRE data, and can trigger active response. | The result is an Alerting alert per group. No Wazuh finding, no active response. |
| `same_*` and `different_*` options. | `group-by` on any WCS field. `different_*` becomes a distinct count of one field. |
| `ignore` suppresses new alerts for a number of seconds. | One alert per group while active. Notifications only for new alerts by default. |
