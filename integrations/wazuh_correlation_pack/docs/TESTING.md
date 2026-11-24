# Testing

Three layers (plus an offline reproducibility check) are kept separate because each proves
something different. The validation tests P1-P6 were added for 5.0.0-rc2. Recorded results exist
for 5.0.0-rc2 and 5.0.0-rc1; see [Recorded results](#recorded-results) and
`../evidence/README.md`. Results for any other version must be recorded in their own evidence
directory (see `RC2_VALIDATION_PLAN.md`).

| Layer | Location | Needs | Proves | Does not prove |
|---|---|---|---|---|
| Reproducibility | `tests/repro/check_clean_checkout.py` | git, Python, PyPI or a pip cache | A fresh clone of one commit, in a new virtual environment built from `requirements.txt`, with no credentials, no deployment state and no access to the original checkout, passes the unit tests and renders monitors byte-identical to `expected/monitors/`; nothing needed is untracked; documentation file references resolve. | Anything about OpenSearch or Wazuh. |
| Unit | `tests/unit/` | Python + PyYAML | Sigma subset parsing and rejections, query compilation, the sliding-window algorithm (against a brute-force reference on random inputs), monitor rendering, deployment planning (create / update / no-op / prune / adopt / duplicates / remove / rollback) against a fake Alerting API. | Anything about OpenSearch. |
| Query / API | `tests/api/test_monitor_execute.py` | Indexer credentials | The real query, Painless evaluation and bucket-level trigger on OpenSearch, at millisecond precision, using fixtures in a temporary pack-owned index (`wcp-test-fixtures`, deleted afterwards) and the Alerting `_execute` dry-run API. | Collection, decoding, field names produced by Wazuh, the scheduler. |
| Pipeline | `tests/e2e/` | Indexer credentials + lab (`tests/lab/`) | The whole path to a scheduler-created alert: log source -> agent -> manager -> engine (stock decoders) -> events data stream -> Alerting monitor run by the scheduler -> alert in Alerting > Alerts. | See "replay" vs "live" below. |
| Validation P1-P6 (for RC2) | `tests/validation/` | Lab configuration (`tests/validation/lab.example.yml`), `--live`; per test: endpoints, Windows, resource-creation permission | Windows identity through ingestion (P1), reporting subject vs target (P2), real Windows collection (P3), least-privilege installation and scheduled execution (P4), notification delivery (P5), missed runs and recovery (P6). **Run on 5.0.0-rc2 on 2026-11-22**: revision 38ad481 (P1 FAIL: detection defect, `evidence/2026-11-22-rc2/`); candidate 5c1da90 with the fixes: all PASS, incl. live SSH, replay batches and sample decoding (`evidence/2026-11-22-rc2-candidate/`); current revision (6ee2300, unknown-realm counting): affected Windows paths PASS (`evidence/2026-11-23-rc2-mixed-realm/`); deferred: two scenarios needing two Linux endpoints; disabled by default; see `VALIDATION_TESTS.md`. Offline self-tests: `tests/validation/test_offline.py`. | Other versions and labs; the RC1 suites not re-run on RC2. |

## Pipeline tests: live vs replay

* `tests/e2e/test_ssh_live.py`: real sshd authentication failures on a test endpoint
  (`sshd -> journald -> wazuh-agent`), from a second endpoint, against locked `wcpt-*` test
  accounts with a fixed dummy password. Covers detection, counting, alert de-duplication across
  scheduled runs, resolution and a second episode.
* `tests/e2e/test_replay.py`: lines appended to `/var/log/wcp-replay/replay.log` on a test
  endpoint and collected by the agent (`log_format syslog`). Gives control over event time and
  source address, so it covers thresholds, window edges, grouping, lateness and duplicates.
  It bypasses sshd/journald, and for Windows it bypasses the EventChannel collector: the
  Windows events are real captured 4625 XML (`samples/windows/`) and events derived from it,
  decoded by the stock Wazuh 5.0.0-rc1 Windows decoders, but **not collected from a Windows
  endpoint**. `bf_duplicate_delivery` writes records twice to the collected file (duplication
  at the source); it does not exercise retransmission inside the pipeline.
* `tests/api/test_least_privilege.py` checks the documented permissions with a temporary role
  and user. It was **not executed** for the recorded RC1 results.
* `tests/api/test_lateness_scheduler.py` (since f3af740): the real Alerting scheduler with a
  temporary monitor and index (deleted afterwards); event visibility is controlled directly, so it
  measures scheduling-phase effects on lateness, not ingestion.
* `tests/api/collect_platform_facts.py`: read-only collection of the platform facts the pack
  relies on (versions, data streams, field types, limits, decoded 4625 identity shapes).
* `tests/unit/test_identity.py`: identity derivation and the golden monitor outputs
  (`expected/monitors/`).

Evidence directories are per platform version and detection commit; `../evidence/README.md`
lists them.

Only alerts read back from `GET _plugins/_alerting/monitors/alerts` (created by the Alerting
scheduler) count as detections in the pipeline layer.

## Labs used for the recorded results

5.0.0-rc2 (November 2026): an all-in-one server on Ubuntu 24.04.5, one Linux endpoint (Ubuntu
22.04.5, OpenSSH 8.9p1) and one Windows Server 2019 endpoint, each with wazuh-agent 5.0.0-rc2. The
Linux endpoint served both Linux roles, so scenarios that need two Linux endpoints were deferred.

5.0.0-rc1:

* Wazuh server 5.0.0-rc1 all-in-one (manager, indexer, dashboard) on Ubuntu 22.04, 4 vCPU,
  4 GB RAM.
* Two LXD containers (Ubuntu 22.04, OpenSSH 8.9p1) on a dedicated bridge, each with
  wazuh-agent 5.0.0-rc1: `wcp-ep1` (agent 001) and `wcp-ep2` (agent 002).
* Test identities: locked local accounts `wcpt-alice`, `wcpt-bob`, ... (no usable password).

Recreate it with `tests/lab/README.md`.

## Running

```bash
python tests/repro/check_clean_checkout.py --commit HEAD --out evidence/<run>  # clean checkout
python -m unittest discover -s tests/unit                       # unit
python tests/api/test_monitor_execute.py --evidence evidence/<run>  # query/API
python -m wcp apply                                              # deploy before pipeline tests
python tests/e2e/test_ssh_live.py --evidence evidence/<run>
python tests/e2e/test_replay.py   --evidence evidence/<run> --batch ssh
python tests/e2e/test_replay.py   --evidence evidence/<run> --batch windows
python -m unittest discover -s tests/validation -p "test_*.py"  # validation harness, offline
python tests/validation/p1_windows_identity_replay.py           # plan only; --live needs WCP_LAB_CONFIG
```

Each pipeline scenario uses its own source address (its own alert group), so a batch runs
concurrently; re-running within the longest lookback (13 min) needs `--ip-offset N` to avoid
counting the previous run's events.

Evidence: one JSON file per scenario with inputs (sanitized), expected outcome, observed
counts and alerts, timings and per-check PASS/FAIL.

## Recorded results

Revision ids are commits of the development branch, which is not part of the contribution.
`../evidence/README.md` shows how the contributed files match the tested revisions.

### Current version on 5.0.0-rc2

The README table "Validation on 5.0.0-rc2" summarizes the results. They come from two revisions:

* The Windows password spraying monitor was retested after its last change, at detection revision
  6ee2300 with harness revisions 3868f23 to 8ce737c (`evidence/2026-11-23-rc2-mixed-realm/`).
* All other results come from candidate 5c1da90 (`evidence/2026-11-22-rc2-candidate/`). That
  candidate differs from 6ee2300 only in how the Windows spray monitor counts accounts. The other
  three monitors are byte-identical.

Before the last change, the Windows spray monitor counted one account twice when it appeared in
both decoded forms. Three real accounts scored 6 and raised a false alert. That failing run is kept
as `evidence/2026-11-23-rc2-mixed-realm/api_monitor_execute_df2ae18_before_fix.json`. An earlier
5.0.0-rc2 run of revision 38ad481 found a different defect in the Windows account identity (P1
FAIL). It is kept in `evidence/2026-11-22-rc2/`.

`bf_different_endpoints` and `spray_split_endpoints` need two monitored Linux endpoints and were
deferred on 5.0.0-rc2. Both passed on 5.0.0-rc1 (25e52cc).

### SSH brute-force scenarios

Threshold: 8 attempts within 2 minutes per agent and source. The scenarios ran on 5.0.0-rc1
(25e52cc) and again on 5.0.0-rc2 (5c1da90), with the same outcomes and scores. `different
endpoints` ran on 5.0.0-rc1 only. The input timings in the table, such as 143-150 s, were measured
in the 5.0.0-rc1 run.

| Scenario (replayed unless noted) | Input | Expected | Observed |
|---|---|---|---|
| live burst | 9 real attempts in 28 s | alert, score 9 | alert, score 9 |
| below threshold | 7 attempts in 60 s | no alert | no alert |
| at threshold | 8 attempts in 70 s | alert, score 8 | alert, score 8 |
| above threshold | 12 attempts in 55 s | alert, score 12 | alert, score 12 |
| span equal to the window | 8 attempts, first and last 120 s apart | no alert | no alert |
| span shorter than the window | 8 attempts within 119 s | alert, score 8 | alert, score 8 |
| split beyond the window | 4 + 4 attempts, 150 s apart | no alert | no alert |
| different sources | 5 + 5 attempts from two IPs | no alert | no alert |
| different endpoints | 5 + 5 attempts on two agents | no alert | no alert (5.0.0-rc1 only) |
| log lines versus attempts | 5 attempts with an unknown user: 25 log lines | no alert | no alert |
| the same records collected twice | 4 records, each written twice | alert, score 8 (known limitation) | alert, score 8 |
| late, within the lookback | 8 attempts searchable 143-150 s after their event time | alert | alert |
| late, beyond the lookback | 8 attempts searchable 423-430 s after their event time | no alert | no alert |

The per-scenario files are in `../evidence/2026-11-22-rc2-candidate/replay_ssh.json` and
`../evidence/2026-11-21-rc1/`.

### Earlier versions on 5.0.0-rc1 (historical)

* 2026-11-21, revision 25e52cc: passed the unit, API, deployment, live SSH and replay tests
  (`evidence/2026-11-21-rc1/`). Permissions, notifications and collection from a Windows agent
  were not tested on 5.0.0-rc1.
* Revision 105573d: passed the unit, API and scheduler tests (`evidence/2026-11-22-rc1-105573d/`).

The current Windows identity and counting rules were not tested on 5.0.0-rc1.

### History of the Windows account identity

Revision 25e52cc counted user names only. Revision 105573d added the domain, falling back to
`user.domain` in some cases. On 5.0.0-rc2 that fallback took the reporting subject's domain
(`evidence/2026-11-22-rc2/`), so it was removed. Revision 6ee2300 added the conservative counting
of accounts with an unknown domain. The current rule has been tested on 5.0.0-rc2 only.
