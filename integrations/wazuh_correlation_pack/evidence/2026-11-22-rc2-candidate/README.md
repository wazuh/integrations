# RC2 validation of the candidate with the two fixes (2026-11-22 21:00 - 23:25 UTC)

> **Sanitized publication copy.** Lab addresses, host names, the lab cluster id and workstation
> paths are replaced consistently; measurements, outcomes and monitor hashes are unchanged. Files
> named here but absent (superseded attempts, harness errors, intermediate records) are kept in
> the unpublished development archive. Revision ids are development-branch commits. See
> [../README.md](../README.md).

Full available validation, on the same Wazuh 5.0.0-rc2 lab as `../2026-11-22-rc2/`, of a candidate
that fixes the two defects found there. The earlier run's files are unchanged; it validated 38ad481.
The RC1 reference server was not contacted.

## Candidate

| Item | Revision |
|---|---|
| **Validated candidate (harness + code)** | `5c1da90c968be6630ad4f366f261fe8ecd5423e8` |
| Detection (rules, correlations, rendering) | `d090875ac4b109112ccb2486794472f9c0d78d01` - failed-target realm only from `user.target.domain` |
| Deployment-state fix | `657fe397` (`wcp/cli.py`): `WCP_STATE_DIR` from the env file honoured; manifests bound to their cluster |
| Earlier candidate revisions used by part of the run | `706c689` and `3b9201a` - same detection and code; they differ from `5c1da90` only in `tests/validation/replay_batches.py` and in `vlib.AlertTracker` keeping the first alert snapshot (not used by any other check); see "Which result counts" |

Rendered monitors (`expected/monitors/`, identical to `python -m wcp render` at every candidate
revision; clean-checkout records `step0-clean-checkout-706c689`, `-3b9201a`, `-5c1da90`, all PASS):

| Monitor | Content hash | Change |
|---|---|---|
| `wcp_ssh_bruteforce` | `007c0a436059d016` | unchanged since 25e52cc (byte-identical) |
| `wcp_ssh_password_spray` | `172cc43b9dfcc25c` | unchanged since 25e52cc (byte-identical) |
| `wcp_windows_failed_logon_burst` | `d31fc5d758665c2e` | unchanged since 25e52cc (byte-identical) |
| `wcp_windows_password_spray` | **`4564e84945edcf3a`** | was `0603b54f3c657714` (105573d / 38ad481); LF SHA-256 `a4754728057cb8c6...` |

Deployment on RC2 (`wcp_plan_before_update.txt`, `wcp_update_apply.txt`): `plan` listed one update
(`wcp_windows_password_spray` `0603b54f3c657714` -> `4564e84945edcf3a`), three no-ops. The existing
RC2 manifest had no cluster identity: `apply` without `--bind-manifest` was refused; after checking
that its monitor ids equal the live pack monitors, `apply --bind-manifest` recorded
`cluster_uuid RC2-LAB-CLUSTER-UUID` and applied the update; `plan` then showed 0 changes.

## Environment

As `../2026-11-22-rc2/README.md`: all-in-one Wazuh 5.0.0-rc2 (manager `0a951d0`, OpenSearch 3.6.0)
on Ubuntu 24.04.5 upgraded in place from 22.04; one Ubuntu 22.04.5 agent (both Linux roles, one
machine); one Windows Server 2019 agent. Platform facts: `platform_facts.json`. Resource log
`resources.csv` (21:07-23:21 UTC, 131 samples per host): minimum available memory server 3093 MB,
Linux endpoint 1293 MB; no swap; no OOM kill during the run (the Linux endpoint's 3 OOM lines
predate the run: ClamAV, removed earlier); both hosts reachable at every sample.

## Results (validated candidate)

| Test | Result | Evidence | Run on |
|---|---|---|---|
| Unit tests (incl. state and identity regressions) | PASS | clean-checkout records | 5c1da90 |
| Harness self-tests | PASS | clean-checkout records | 5c1da90 |
| Platform facts (read-only) | recorded | `platform_facts.json` | 706c689 |
| Query/API fixtures (`tests/api/test_monitor_execute.py`) | **PASS 24/24**; Painless identities = Python reference in all Windows cases | `api_monitor_execute.json` | 706c689 |
| Lateness scheduler (`tests/api/test_lateness_scheduler.py`) | **PASS 24/24** | `api_lateness_scheduler.json` | 706c689 |
| Deployment lifecycle (`tests/e2e/test_deploy_lifecycle.py`) | **PASS 45/45**; 22 non-pack documents unchanged at every step | `deploy_lifecycle.json` | 706c689 |
| P4 least privilege, scheduled execution | **PASS 15/15** | `p4.json` | 706c689 |
| P1 Windows identity replay (16 scenarios, 80 records) | **PASS 121/121** - incl. the ambiguous subject-domain cases: one `?\bob`, no spray | `p1.json` | 706c689 |
| Replay batch SSH (port of RC1 test 7) | **PASS 51/51**; 16 scenarios; `bf_different_endpoints`, `spray_split_endpoints` **DEFERRED** | `replay_ssh.json` | 5c1da90 |
| Replay batch Windows (port of RC1 test 8) | **PASS 16/16** | `replay_windows.json` | 5c1da90 |
| Real 4625 sample decoding (port of RC1 test 9) | **PASS 9/9** | `win_sample_decoding.json` | 5c1da90 |
| P2 real reporting-subject capture | **PASS 7/7** | `p2.json` | 5c1da90 |
| Live SSH burst | **PASS 15/15** | `ssh_live.json` | 5c1da90 |
| P5 notifications | **PASS 19/19** | `p5.json`, `lab_change_p5_notifications_deny_list.json` | 5c1da90 |
| P3 real Windows collection (SMB + RDP) | **PASS 14/14** | `p3.json` | 5c1da90 |
| P6 part a (disable / re-enable) | **PASS 8/8** | `p6_part_a.json` | 5c1da90 |
| P6 part b (one controlled indexer restart) | **PASS 5/5** | `p6_part_b.json` | 5c1da90 |

### Which result counts (superseded attempts are kept)

| Attempt | Result | Superseded by | Why |
|---|---|---|---|
| `replay_ssh_run1.json` (706c689) | FAIL 49/51 | `replay_ssh.json` | harness defect: compared the alert's **latest** snapshot; an ACTIVE alert's bucket is refreshed by every DEDUPED run, so its score falls as events leave the lookback (12 -> 8, 300 -> 126) |
| `replay_ssh_run2.json`, `replay_ssh_run3.json` (3b9201a) | FAIL 50/51 | `replay_ssh.json` | same defect (300 -> 183); 3b9201a had only added scheduler alignment and visibility recording; its commit message wrongly says an alert keeps its creation score |
| `diag_bruteforce_execute_vs_search.log` | diagnostics | - | deployed query, `_execute` and the scheduler's alerts at creation give the full score in four reproductions; established the cause above |
| `replay_windows_706c689.json` | PASS | `replay_windows.json` | rerun on 5c1da90 after the score-snapshot change |
| `p5_attempt1_interrupted.json` | INTERRUPTED (not a test result) | `p5.json` | the operator's command wrapper killed P5 during its cleanup; leftover index and channel deleted at once; two leftover monitors were found only later |
| `p5_rerun1.json` (5c1da90) | FAIL 13/19 | `p5.json` | the two leftover monitors of the interrupted attempt (same names, index, channel id) still ran and doubled every notification; deleted (verified), then P5 rerun on a clean cluster |

The tests run on 706c689 (query/API, lateness, lifecycle, P4, P1) used test code identical to
5c1da90 for their checks (`git diff 706c689 5c1da90` touches only `docs/VALIDATION_TESTS.md`, `tests/validation/replay_batches.py`
and the first-snapshot field of `vlib.AlertTracker`, which those tests do not read).

## Platform behaviour recorded on 5.0.0-rc2 (reproduced from the first run)

* Permission loss (P4): no ERROR alert; input error only in a dry-run `_execute`; new activity not
  counted; the earlier alert stays ACTIVE after its events left the lookback.
* Disable / re-enable (P6a): no catch-up; new grid from the enable time; activity visible only
  while disabled never counted; a second NEW alert for an episode that was ACTIVE.
* Indexer restart (P6b): restart requested 23:18:35, cluster back 23:18:56 (~21 s); missed slot
  23:18:42 not caught up; first run 23:19:42 on the old grid (45.6 s after the cluster was back);
  a set visible only for the missed run never counted; the ACTIVE alert of a continuing episode
  kept, no duplicate.
* Webhook destinations (P5): the Notifications default host deny list blocks loopback and private
  ranges; narrowed transiently to 127.0.0.1/32 for the run and reverted (verified).
* Alert content: an ACTIVE alert's bucket (score, sample) is refreshed by every DEDUPED run.
* RDP with NLA logged as LogonType 3, not mapped to an indexed field (P3, sample decoding).

## Identity results under the fix (real events)

P2: LogonUser failures with a reporting subject keep their explicit target domain
(`wcpotherdom\...`; `.` -> the computer); the SMB failure without a subject counts as
`?\wcpt-p2-smb`. P3: subject-absent SMB/RDP accounts count as `?\wcpt-p3-...` (7 distinct, spray
score 7 as before). No account takes a reporting subject's domain.

## Cleanup

Verified after the run: no `[wcp-test]` monitor (config index count 0), no `wcp-test-*` index, no
`wcp_` user or role, no test channel, no transient cluster setting, cluster green, no machine
lock; deny list default; tunnels closed; lab configuration `enabled: false`. The pack stays
deployed at the candidate (4 monitors in sync, `plan` 0 changes, manifest bound to the cluster).
