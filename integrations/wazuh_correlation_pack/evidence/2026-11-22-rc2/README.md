# RC2 validation run 2026-11-22 (Wazuh 5.0.0-rc2)

> **Sanitized publication copy.** Lab addresses, host names, the lab cluster id and workstation
> paths are replaced consistently; measurements, outcomes and monitor hashes are unchanged. Files
> named here but absent (superseded attempts, harness errors, intermediate records) are kept in
> the unpublished development archive. Revision ids are development-branch commits. See
> [../README.md](../README.md).

First run of the pack on **Wazuh 5.0.0-rc2**: the RC2 validation tests P1-P6
(`docs/VALIDATION_TESTS.md`) and the live SSH burst ported from RC1 test 6. Separate from the RC1
evidence (`../2026-11-21-rc1/`, `../2026-11-22-rc1-105573d/`); the RC1 reference server was not
contacted. Detection logic frozen at `38ad481e2c522c5ba0d22423423d20702d8a946f` throughout:
`git diff 38ad481 <HEAD> -- wcp rules correlations pack.yml expected` is empty for every commit of
this run, and the deployed monitors carried the frozen content hashes in every test.

## Environment

| Item | Value |
|---|---|
| Server | all-in-one, `wazuh-install-5.0.0-rc2.sh -a -d pre-release`; manager 5.0.0-1 stage rc2 commit `0a951d0`; indexer 5.0.0-1 stage rc2 (`dbe3dd9d-...`, OpenSearch 3.6.0, Alerting / Notifications 5.0.0.1); dashboard 5.0.0-1 stage rc2 (`0e59eb63-...`); single node, green |
| Server OS | **Ubuntu 24.04.5 LTS upgraded in place from 22.04.5** (`do-release-upgrade`, after a full 22.04 update; Wazuh was installed on 22.04 and carried through the upgrade unchanged); kernel 6.8.0-151; 4 vCPU, 7.9 GB RAM, no swap; VMware VM |
| Linux endpoint | Ubuntu 22.04.5, OpenSSH 8.9p1, wazuh-agent 5.0.0 rc2 (`0a951d0`), agent `001`; journald (sshd) + replay localfile; **one VM serves both Linux roles** (`linux_replay`, `linux_source`; same machine identity, counted once) |
| Windows endpoint | Windows Server 2019 Standard 10.0.17763 (workgroup), wazuh-agent 5.0.0 rc2 (`0a951d0`), agent `002`; Security channel through EventChannel; Audit Logon Success and Failure; no account lockout |
| Workstation | Windows 11, Python 3.12.3 + PyYAML 6.0.4; indexer through an SSH tunnel; OpenSSH 9.5 client (live SSH test); webhook receiver through a reverse SSH tunnel (P5) |
| Credentials | RC2 indexer admin from the server's root-only `credentials.env`, copied over SSH into a user-only env file outside the repository (never printed); separate RC2 deployment state directory |

Platform facts (read-only): `platform_facts.json`. `max_monitors` 10; 22 Security Analytics
workflows (+ 22 delegate monitor documents in the config index, not counted by the limit);
`alert_history_enabled` false (as RC1). Resource log of the run: `resources.csv` (every 60 s:
available memory, swap, root use, OOM-kill count, load; 18:58-20:12 UTC, covering every test).
Minimum available memory: server 3145 MB, Linux endpoint 1324 MB; no swap use; both hosts
reachable at every sample; no OOM kill on either host during the run (the Linux endpoint's 3 OOM
lines date from 17:56, before the run, when ClamAV's clamd was killed; ClamAV was removed).

## Results

| Test | Result | Harness | Evidence |
|---|---|---|---|
| P1 Windows identity through ingestion (synthetic replay, 12 scenarios, 60 records) | **FAIL - detection defect**: 11 scenarios PASS end to end (decoding, Python and Painless identities, scheduler alerts); the ambiguous account-domain scenario FAILS (below) | `97012b4` | `p1.json` (77/81 checks) |
| P2 reporting subject vs failed target (**real capture**) | **PASS**: 10 LogonUser failures (types 2 and 3) with a reporting subject + 1 SMB failure; decoded = model, identity from the target fields, realm never the subject's domain, 9 target accounts for 1 subject | `97012b4` | `p2.json`, `p2_captured_4625.sanitized.xml.log` |
| P3 real Windows collection | **PASS**: 18 real 4625 (5 SMB spray, 10 SMB burst, 3 RDP) collected exactly once (EventRecordIDs = Security log); burst alert score 18, spray alert score 7 | `67db133` | `p3.json`, `p3_captured_4625.sanitized.xml.log` |
| P4 least privilege, scheduled execution | **PASS** (second run); first run FAIL on a harness assumption (below) | `d720779` (run 1: `9557bec`) | `p4.json` (15/15), `p4_run1.json` |
| P5 notification delivery | **PASS**: one NEW notification per alert (normal, continued, single-run), COMPLETED when configured, none for deduplicated runs, all attributable | `67db133` | `p5.json`, `lab_change_p5_notifications_deny_list.json` |
| P6 part a: disable / re-enable | **PASS** | `75e3683` | `p6_part_a.json` |
| P6 part b: indexer restart (one, authorised) | **PASS** | `75e3683` | `p6_part_b.json` |
| Live SSH burst (port of RC1 test 6) | **PASS**: 9 real failed passwords (journal ground truth) -> 9 counted events -> alert score 9; no spray; one alert over 3 runs; resolved after the lookback; new alert for episode 2 | `6c5b1bb` | `ssh_live.json` |
| Prerequisite: sshd replay path | indexed fields as RC1 (F3/F4) | - | `prereq_sshd_replay_probe.json` |

**Deferred** (need two monitored Linux endpoints): RC1 test 7 scenarios `bf_different_endpoints`
and `spray_split_endpoints`. **Not executed on RC2** (not part of this run): Query/API fixture suite
(`tests/api/test_monitor_execute.py`), lateness scheduler suite (`test_lateness_scheduler.py`),
deployment lifecycle (`tests/e2e/test_deploy_lifecycle.py`), replay batches
(`tests/e2e/test_replay.py`, still bound to the RC1 containers), sample decoding test.

### Detection defect (P1, ambiguous account domain)

Scenario `p2_edge_subject_name_with_null_sid` (synthetic): a 4625 with a subject **name** but
SubjectUserSid `S-1-0-0` and TargetDomainName `-`. The RC2 decoders produce what the RC1-derived
model predicted (`user.id` = `user.target.id`, `user.domain` = SubjectDomainName), so the frozen
derivation of `wcp.windows_target_account` takes the **reporting subject's domain** as the realm:
five records for target `bob` from five subject domains are counted as `subj0\bob` ...
`subj4\bob` (score 5, a false spray alert) instead of one account `?\bob`. This is incorrect
failed-target identity. The real captures of P2 did not produce this shape (every LogonUser record
had a real SubjectUserSid; SMB had no subject), so its frequency in practice is unknown. Detection
logic was not changed; a fix needs a new behaviour revision and fresh validation.

### Platform behaviour recorded (5.0.0-rc2)

* **P4, permission loss**: after the role's index permission was removed, the scheduler raised **no
  ERROR alert**; a dry-run `_execute` as the restricted user returned HTTP 200 with input error
  `no permissions for [indices:data/read/search]` and no buckets; a new indexed burst was not
  counted; the first alert **stayed ACTIVE** after its burst left the lookback (+ 2 runs). Losing read
  access stops detection silently and leaves stale alerts. The monitor's `user` is not returned by
  the REST API (GET monitor, `_search`); the stored user (read from the config index with the
  super-admin certificate) was the restricted user with its roles plus `wazuh_ai_assistant` (a
  reserved RC2 role mapped to all users; it grants only AI-assistant session access).
* **P5**: the Notifications plugin's default `host_deny_list` denies loopback and all private and
  TEST-NET ranges; a webhook to a lab receiver needs that list narrowed. For the run it was set
  transiently to deny everything as before except `127.0.0.1/32` (reverse tunnel), then reverted
  and verified (`lab_change_p5_notifications_deny_list.json`). Notifications arrived ~0.1-0.2 s
  before the alert's recorded `start_time`.
* **P6a**: no alert while disabled; no catch-up run; first run E+60.02 s, second E+120.01 s (grid
  anchored to the new `enabled_time`); a set visible only while disabled was never counted; an
  episode ACTIVE before the disable got a **second NEW alert** after re-enabling (the old one stayed
  ACTIVE).
* **P6b**: restart requested 20:08:35, cluster back 20:08:56 (~21 s); the run slot 20:08:41 was
  missed and not caught up; the first run after the restart came at 20:09:41.48 on the **old grid**
  (offset 0.13 s), 45 s after the cluster was back; a set visible only for the missed run was never
  counted (detection gap); the ACTIVE alert of a continuing episode survived without a duplicate.
* **P3**: RDP failures with NLA are logged as LogonType 3, like SMB; LogonType is not mapped to an
  indexed field. RDP records carry no TargetDomainName (`?\` realm), SMB records `WORKGROUP`.

## Harness changes made during the run (each committed separately, clean-checkout check repeated)

| Commit | Change | Clean checkout |
|---|---|---|
| `9557bec` | P4 records the platform's reaction to a removed permission instead of requiring an ERROR alert; P5 records the Notifications deny list | FAIL (uncommitted evidence present), rerun PASS |
| `d720779` | P4 reads the stored monitor user from the config index (REST API omits it); observes the first alert past its lookback; evidence files without workstation paths | FAIL (uncommitted record), rerun PASS |
| `97012b4` | P1 checks the ambiguous account-domain case explicitly (was observation only) | PASS |
| `6c5b1bb` | live SSH burst ported (`tests/validation/ssh_live_burst.py`) | PASS |
| `67db133` | RDP attempts under `xvfb-run` (FreeRDP's X11 client needs a display) | PASS |
| `75e3683` | `parse_iso` kept offset digits as fraction (1 h shift with local time UTC+1) | FAIL (uncommitted capture file), rerun PASS |
| `857e6df` | P6 does not list the first run's own slot as missed | covered by the final records |
| `8776386` | evidence files replace configured access-account names (`<access-account>`); applied to `p2.json` and `ssh_live.json` in `84203ab` (the earlier commits `e486836`, `7b6c275` still hold the names) | covered by the final records |

Records: `step0-clean-checkout-*` (the tested revision `91787fd` before the run, then one per
harness commit; failed records are kept). Final records: `step0-clean-checkout-final-7da7d70` (after the documentation update)
and `step0-clean-checkout-final-*` for the last harness revision, both PASS.

### Corrections to recorded values (harness defects found during the run)

Pass/fail results are unaffected. Values compared against the real clock through `parse_iso`
before `75e3683` are off by exactly -3600 s:

| File | Field | Recorded | Correct |
|---|---|---|---|
| `p3.json` | `timings_s.*_alert_after_last_attempt` | -3547.0 | 53.0 s |
| `p5.json` | channel test delay (check detail) | -3599.5 | 0.5 s |
| `p5.json` | `expected.single_run_counting_runs` | 18:46:46 | 19:46:46 (matches the alert seen at 19:46:47) |
| `ssh_live.json` | `timings_s.alert_left_active_after_last_attempt` | -3293.8 | 306.2 s |
| `p6_part_b.json` | `observed.missed_grid_slots` | 20:08:41.357, 20:09:41.357 | 20:08:41.357 only (the 20:09:41 run happened; fixed in `857e6df`) |

`ssh_live.json` note "indexed events by event.reason" shows `"None": 0` although events without a
reason exist (string comparison); the counted-event check is unaffected.
`harness.uncommitted_changes_in_pack: true` in some files refers to `resources.csv`, which was being
written during the run; detection files never differed from the frozen commit.

## Tooling defect (not detection logic)

`wcp/cli.py` computes the `--state-dir` default before loading the env file, so `WCP_STATE_DIR` set
only in an env file is ignored (documented as an env-file setting in `docs/CONFIGURATION.md`). The
first admin `apply` of the run wrote its manifest to the default state directory; it was moved to
the RC2 state directory and `WCP_STATE_DIR` was exported for the rest of the run. `wcp/` is part of
the frozen file set and was not changed.

## Lab changes and cleanup

* Temporary resources of every test deleted and verified (no `[wcp-test]` monitor, `wcp-test-*`
  index, `wcp_p4_deployer` user/role or test channel left; no transient cluster setting); machine
  locks released; tunnels closed; the lab configuration set back to `enabled: false`.
* The pack stays deployed (admin, frozen hashes, 4 monitors in sync) for follow-up review.
* Endpoint changes for the run: `xvfb` installed on the Linux endpoint (RDP client display).
  Failed logons used only non-existent `wcpt-*` accounts and the dummy password.
