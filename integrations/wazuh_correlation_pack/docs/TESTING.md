# Testing

Three layers (plus an offline reproducibility check), kept separate because each proves
something different. Recorded results exist for **5.0.0-rc1 only** (`evidence/2026-11-21-rc1/`,
`evidence/2026-11-22-rc1-105573d/`); results for any other version must be recorded in their own
evidence directory (see `RC2_VALIDATION_PLAN.md`).

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

Evidence directories are per platform version and detection commit:
`evidence/2026-11-21-rc1/` (25e52cc) and `evidence/2026-11-22-rc1-105573d/` (105573d).

Only alerts read back from `GET _plugins/_alerting/monitors/alerts` (created by the Alerting
scheduler) count as detections in the pipeline layer.

## Lab used for the recorded results

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
