# Test run 2026-11-22 - Wazuh 5.0.0-rc1 - detection code 105573d

> **Sanitized publication copy.** Lab addresses, host names, the lab cluster id and workstation
> paths are replaced consistently; measurements, outcomes and monitor hashes are unchanged. Files
> named here but absent (superseded attempts, harness errors, intermediate records) are kept in
> the unpublished development archive. Revision ids are development-branch commits. See
> [../README.md](../README.md).

**Code version.** Detection code (`wcp/`, `rules/`, `correlations/`, `pack.yml`) and expected
monitor outputs of commit `105573d` (Windows spraying counts `wcp.windows_target_account`; monitor
content hash `0603b54f3c657714`). Test harness of commit `f3af740` (the lateness test of
`105573d` lacked continuous alert polling; the detection code of `f3af740` is identical to
`105573d`). Earlier results (`../2026-11-21-rc1/`) belong to `25e52cc`.

**Environment.** The same RC1 server as `../2026-11-21-rc1/` (Wazuh 5.0.0-rc1, OpenSearch 3.6.0);
the host now reported 6857 MB total memory (4159 MB on 2026-11-21). **The test lab was not
recreated**: no agent, no ingestion pipeline. Only lightweight, indexer-level tests ran. The four
monitors deployed from 25e52cc were not changed (`wcp plan` lists one pending update for
`wcp_windows_password_spray`, deliberately not applied). Indexer user: `admin`.

## Results

| File | Layer | Result |
|---|---|---|
| `unit_tests.txt` | unit (49: Sigma subset, query compilation, sliding window, rendering, deployment planning, identity derivation, golden monitor outputs) | 49/49 PASS |
| `api_monitor_execute.json` | query/API: 22 fixture cases through the Alerting `_execute` API; for identity cases the Painless identities are compared with the Python reference | 22/22 PASS |
| `api_lateness_scheduler.json` | real Alerting scheduler, temporary monitor + index (deleted), controlled visibility: delays ~110/121/132 s at three phases, ~264 s and ~335 s, 2 repetitions | 24/24 PASS |
| `api_lateness_scheduler.run1-harness-gap.json` | first run of the same test (harness of 105573d) | 23/24: the "before, 264 s" case of repetition 0 was counted by one run only; its alert existed ~60 s (alert history disabled) while the harness was not polling. Same case in repetition 1: alert observed. Fixed in f3af740 (poll every 2 s). |
| `platform_facts.json` | read-only facts: indexer version, data streams, field types (incl. `user.target.domain` **not mapped**), limits, decoded 4625 identity shapes | recorded |
| `windows_decoder_identity_steps.json` | stock decoder steps and kvdb list membership that determine the 4625 identity fields (sha256 of the files) | recorded |

## Identity cases (query/API layer)

| Case | Input (decoded-field shape) | Identities (Painless = Python) | Result |
|---|---|---|---|
| `win_id_observed_shape` | shape observed on all 112 RC1 4625 events: `user.domain` `.`, `user.id` = `user.target.id`, host `WCP-WIN-LAB1` | `wcp-win-lab1\user0..4` | alert, 5 |
| `win_id_same_name_five_domains` | subject present, `bob` in 5 target domains | `adatum\bob`, `contoso\bob`, `fabrikam\bob`, `northwind\bob`, `tailspin\bob` | alert, 5 (name-only counting would give 1) |
| `win_id_case_and_local_computer` | `.\admin`, `WIN-LAB1\Admin`, `win-lab1\ADMIN` on host `WIN-LAB1.corp.example`, `CONTOSO\admin`, `contoso\Admin` | `win-lab1\admin`, `contoso\admin` | no alert (2) |
| `win_id_missing_domain` | `bob` (none), `CONTOSO\bob`, `alice` (`-`), `CONTOSO\alice`, `carol` (empty) | `?\bob`, `contoso\bob`, `?\alice`, `contoso\alice`, `?\carol` | alert, 5 |
| `win_id_subject_not_used` | subject present (`WORKGROUP`, `WIN10$`), no TargetDomainName | `?\u0..4` (never `workgroup\...`) | alert, 5 |
| `win_id_sid_mismatch` | `user.domain` set but `user.id` != `user.target.id` | `?\v0..3` | no alert (4) |

The "subject present" shapes are derived from the RC1 decoder and kvdb content
(`windows_decoder_identity_steps.json`); no such event has been decoded on this server.

## Scheduler measurements

* Runs on a fixed 60 s grid anchored to the monitor's `enabled_time`; the 8 run instants observed
  (runs that created an alert) were 9-22 ms after their grid point.
* Lateness with the 300 s lookback (bursts of 8 events spanning 7 s):

| Visibility delay after last event | Phase (event visible ...) | Expected (margin) | Observed (2 repetitions) |
|---|---|---|---|
| ~110 / ~121 / ~132 s | 10 s after a run | alert (+113..+133 s) | alert, alert |
| ~110 / ~121 / ~132 s | 30 s after a run | alert (+133..+153 s) | alert, alert |
| ~110 / ~121 / ~132 s | 10 s before a run | alert (+153..+173 s) | alert, alert |
| ~264 s | 10 s after a run | no alert (-17 s) | no alert, no alert |
| ~264 s | 10 s before a run | alert (+23 s) | alert, alert (one-run alerts) |
| ~335 s | 10 s before a run | no alert (-47 s) | no alert, no alert |

Margin = (first event time + 300 s) - next run after visibility; expected alert iff >= 0.

## Pending (not run for 105573d)

* Pipeline layer (live sshd, replay SSH/Windows, deployment lifecycle) - needs the test lab, which
  is memory-heavy on this host.
* Decoding of 4625 events with a reporting subject (local/interactive logons, explicit target
  domain): RC1 offers no log-test API endpoint; needs an agent.
* Windows endpoint collection; least-privilege user; notification delivery; missed/late
  scheduler runs; 5.0.0-rc2 (`docs/RC2_VALIDATION_PLAN.md`).
