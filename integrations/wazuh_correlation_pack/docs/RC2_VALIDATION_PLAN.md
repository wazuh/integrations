# Validation plan: Wazuh 5.0.0-rc2

**Status: executed on 2026-11-22.** First run of revision 38ad481 (`evidence/2026-11-22-rc2/`):
P1 found a detection defect and the deployment tool a state-directory defect. Both were fixed
(d090875, 657fe39) and candidate 5c1da90 passed every available test on the same lab,
including the RC1 query/API, lateness, deployment-lifecycle, replay and sample-decoding tests
(`evidence/2026-11-22-rc2-candidate/`). A third defect (one failed target counted twice through
both decoded shapes) was fixed in 6ee2300 and its Windows paths validated on the same lab
(`evidence/2026-11-23-rc2-mixed-realm/`). Deferred: the two replay scenarios that need two monitored
Linux endpoints. Compatibility statements name 5.0.0-rc2 only for what passed there.

## Frozen revision

The feature scope is frozen. The revision to validate, its detection-code, expected-output and
harness revisions and the rendered-monitor hashes are recorded, with the result of a clean-checkout
reproducibility check, in `evidence/<date>-reproducibility/README.md` (first record: 2026-11-22;
it is committed after the frozen revision, so it can name that revision). Validate that commit
or a later one whose **detection files** equal it (check with
`git diff --stat <frozen> <candidate> -- wcp rules correlations pack.yml expected`, which must print
nothing). Later commits may add harness code (`tests/`), documentation and evidence; each such
candidate gets its own clean-checkout record naming the harness revision (the first: the P1-P6
validation tests, `docs/VALIDATION_TESTS.md`, recorded in `evidence/<date>-reproducibility-<commit>/`).
Harness additions are separate commits (ground rule 3) and do not change the frozen detection code.

## Ground rules

1. **No in-place upgrade.** The RC1 reference server stays on RC1 as the reference
   environment. RC2 is validated on a **new, separately provisioned** server.
2. **Same implementation.** The implementation under test is `wcp/`, `rules/`, `correlations/`
   and `pack.yml` at one fixed commit, recorded in the RC2 evidence README. These files are not
   changed during the run. If RC2 needs a change, it is a new commit, and the whole plan is run
   again on that commit; the RC1 results then no longer cover the new commit until RC1 is re-run
   too.
3. **Test harness changes** (`tests/`) are allowed (e.g. a new Windows endpoint test). Each one is
   listed in the RC2 evidence README with its commit.
4. **Separate evidence**: `evidence/<date>-rc2/` (never inside `evidence/2026-11-21-rc1/`), with
   the same structure: one JSON per scenario, a README with the environment, results,
   measurements and deviations.
5. **Claims follow evidence.** README, docs and Sigma descriptions say "5.0.0-rc1 and
   5.0.0-rc2" only for behaviour that passed on both; any RC2 difference is documented per version.

## Resources

What the RC1 run showed on a 4 vCPU / 4 GB all-in-one server: the indexer used ~1.8-1.9 GB RSS
(1 GB heap), the manager processes ~1 GB in total, the dashboard ~0.25 GB, leaving 0.3-0.5 GB
available with no swap. Launching two memory-uncapped test containers on that host made the
kernel OOM-kill the indexer (20-minute outage). The RC2 environment is therefore sized on
**physical RAM** with headroom, and the test endpoints run on separate machines.

**Swap is not capacity.** The sizes below must be met with physical RAM. A small swap area may
be configured as an optional contingency (to survive a transient spike instead of an OOM kill),
but the run is planned so that it is never needed: if the server starts swapping during the run,
stop and treat the results as invalid for timing measurements (swapping changes run delays).

| Machine | Role | Minimum | Recommended | Notes |
|---|---|---|---|---|
| Wazuh server | manager + indexer + dashboard 5.0.0-rc2 (all-in-one, installation assistant) | 4 vCPU, 8 GB physical RAM, 50 GB disk | 4 vCPU, 16 GB physical RAM, 100 GB SSD | Swap optional (contingency only, not counted). **No test endpoints on this host.** |
| Linux endpoint 1 | sshd target, agent rc2 (`linux_replay`); also the SMB/RDP source (`linux_source`) when no second Linux VM exists | 1 vCPU, 1 GB RAM, 10 GB | same | Ubuntu 22.04 (OpenSSH 8.9p1, same as RC1) |
| Linux endpoint 2 (deferred in the 2026-11 lab) | second agent and live SSH source | 1 vCPU, 1 GB RAM, 10 GB | same | Ubuntu 22.04; needed only by the tests listed in "Single Linux endpoint" below |
| Linux endpoint 3 (optional) | newer OpenSSH (`sshd-session`/`sshd-auth` process names) | 1 vCPU, 1 GB | same | Ubuntu 24.04 or later; extends coverage, not a pass criterion |
| Windows endpoint | real EventChannel collection, agent rc2 | 2 vCPU, 4 GB RAM, 40 GB | Windows Server 2019 (the 2026-11 lab; 2022 also suitable), 4 GB | Audit Logon failure enabled; reachable over SMB (445) and RDP (3389) from the `linux_source` host |
| Workstation | runs `wcp` and the tests | Python 3 + PyYAML | - | SSH tunnel to the indexer, root CA pinned; runs the P5 webhook receiver (reverse tunnel from the server) |

The endpoints are separate VMs, or containers on **another** host than the Wazuh server; each
endpoint's RAM is physical too. Network: endpoints -> server on the
agent ports used by RC2 (RC1 used 1514/tcp, 1515/tcp and 1517/tcp HTTPS), workstation -> server
SSH. Expected duration: about 3 hours including provisioning of the server, 1.5 hours for the
test run itself.

Credentials needed (kept out of the repository): SSH access to the RC2 hosts; an indexer admin
user for the run; authorisation to create a temporary indexer role and user (permission test);
optionally a Notifications channel (e.g. a webhook to a listener on the workstation) for the
notification test.

Concrete per-host requirements of the P1-P6 tests (`docs/VALIDATION_TESTS.md`; their lab
configuration template is `tests/validation/lab.example.yml`):

* **Wazuh server**: `cluster_uuid` (`GET /`) written into the lab configuration; the indexer admin
  may use the security REST API (P4) and create/delete Notifications channels (P5) - or a channel
  is created beforehand and its id configured; `max_monitors` leaves room for 4 pack monitors plus
  2 temporary ones; for P6 part b an SSH account with `sudo -n systemctl restart wazuh-indexer`.
* **Linux endpoint 1** (`linux_replay`): agent rc2 with the replay `localfile` of
  `tests/lab/README.md`; clock in UTC; SSH account allowed `sudo -n` to append to the replay file.
* **`linux_source`** (Linux endpoint 1 in the 2026-11 lab, same VM as `linux_replay`): `smbclient`
  and `xfreerdp` (FreeRDP 2.x, `+auth-only`; plus `xvfb` on a headless host - the X11 client opens a display even for `+auth-only`); reaches the Windows endpoint on 445 and 3389; its
  address as seen by Windows in the configuration.
* **Windows endpoint**: Windows Server 2019, agent rc2 (Security channel collected), Audit Logon
  "Failure" enabled, OpenSSH server with an administrative account (reads the Security log; is the
  reporting subject in P2, never a target), SMB and RDP reachable from `linux_source`, no domain
  account lockout risk (the tests use non-existent `wcpt-*` names only).
* **Workstation**: the frozen revision (or a candidate per "Frozen revision") checked out, Python 3
  with PyYAML, `git`; the P5 receiver port reachable from the server (reverse tunnel).

### Single Linux endpoint (2026-11 lab)

The lab provisioned for the RC2 run has **one** Linux VM. It serves both Linux roles of the P1-P6
harness: `linux_replay` (agent with the replay file) and `linux_source` (SMB/RDP client against the
Windows endpoint). In the lab configuration both entries carry the same `machine` label; the
harness verifies the machine identity behind each alias, refuses aliases of one VM with different
labels, holds one lock per machine for the duration of a test (so P1-P6 run one after another), and
records `distinct_machines` - never the number of aliases - in every evidence file. Results from
the two roles are never reported as coming from two independent endpoints.

Test 6 (live sshd burst) is ported to this layout as `tests/validation/ssh_live_burst.py`: the
client is the workstation, which is not a monitored endpoint, so one Linux endpoint suffices.

Deferred until a second Linux VM exists (recorded as "deferred", not as failed or passed):

| Test | Why it needs a second Linux endpoint |
|---|---|
| Test 7 `test_replay.py --batch ssh`, scenarios `bf_different_endpoints` and `spray_split_endpoints` (the two that use `EP2`) | they prove that buckets of **two agents** with the same source address are not merged; one agent cannot show this |
| Optional test 12 (newer OpenSSH, endpoint 3) | unchanged: optional |

Tests 7-9 are ported to SSH endpoints: `tests/validation/replay_batches.py` (`--batch ssh|windows`;
the scenario definitions of `tests/e2e/test_replay.py` are used unchanged) and
`tests/validation/windows_sample_decoding.py`. The `tests/e2e/` originals drove the RC1 container
lab (`wcp-ep1`/`wcp-ep2` through `tests/lab/lab.py`) and are kept as the record of the RC1 runs.

## Step 1 - Provision and record the baseline (read-only)

Record in `evidence/<date>-rc2/README.md`:

* package names, versions and SHA-256 of the RC2 installation files; `VERSION.json` of
  manager, indexer and dashboard (all must report stage `rc2`); OpenSearch version; plugin list;
* agent package version on every endpoint;
* the commit under test.

## Step 2 - Re-verify the RC1 platform facts

Each fact below was observed on RC1 and is relied on by the pack or its documentation. Record
the RC2 value next to the RC1 value. Any difference is a finding to resolve before Step 3.

| # | Fact on RC1 | How to check on RC2 |
|---|---|---|
| F1 | Events go to the data stream `wazuh-events-v5-system-activity` (no suffix) | `GET _data_stream/wazuh-events-v5-*` |
| F2 | Field types: `event.start` date, `source.ip` ip, `event.reason`, `event.code`, `user.name`, `user.target.name`, `wazuh.agent.id` keyword; `message` keyword | `GET wazuh-events-v5-system-activity/_mapping/field/...`, `wcp preflight` |
| F3 | `event.start` = log record time; `@timestamp` = manager processing time | compare both on a live event |
| F4 | sshd `Failed password` -> `event.reason: "Failed password"`; Invalid/PAM/Failed lines -> `authentication-failure` | live probe (1 invalid-user + 1 valid-user attempt), as on RC1 |
| F5 | 4625 -> `event.code "4625"`, `event.dataset security`, `user.target.name` = TargetUserName, `source.ip` = IpAddress, `error.code` = SubStatus; LogonType not mapped | `tests/e2e/test_windows_sample_decoding.py` + stock decoder content |
| F5b | Identity of 4625 (`wcp.windows_target_account`): reporting subject `-` -> `user.domain` = TargetDomainName, `user.id` = `user.target.id`, no `user.target.domain` (observed on RC1); reporting subject present -> `user.domain` = SubjectDomainName, `user.target.domain` = TargetDomainName, `user.id` = SubjectUserSid (**derived from the RC1 decoder, never observed**); 4625 only in kvdb lists `target_user_1` and `auth_fields` | `tests/api/collect_platform_facts.py` (identity shapes), decoder/kvdb content, and new decoded events with a reporting subject (test 10b) |
| F6 | `plugins.alerting.alert_history_enabled` defaults to `false` | `GET _cluster/settings?include_defaults=true` (`wcp preflight` warns) |
| F7 | Monitor `ui_metadata` is not persisted; aggregation `meta` is (ownership marker) | `wcp apply` then `wcp plan` must show no changes |
| F8 | `scripted_metric` rejects `null` params; buckets come back under `agg_alert_content` in `_execute` and the alerts API | covered by the query/API test |
| F9 | Linux agent collects `journald` by default; enrollment uses enrollment tokens | agent `ossec.conf`, enrollment |
| F10 | Stock Security Analytics workflows exist and must stay untouched | `deploy_lifecycle` snapshot |
| F11 | Alerting / scheduler limits: `max_monitors` 10 (default value; cluster-wide, checked on monitor creation only; on RC1 4 monitor documents + 22 composite workflows existed), `input_timeout` 30s, job scheduler `jitter_limit` 0.6 (setting), `search.max_buckets` 65535; monitors run on a fixed 60 s grid anchored to `enabled_time` with no observed jitter (RC1) | `tests/api/collect_platform_facts.py`, `tests/api/test_lateness_scheduler.py`; count monitor documents before `wcp apply` (`POST _plugins/_alerting/monitors/_search` with a terms aggregation on `monitor.type`); record which documents count towards the limit on RC2 (the scope above comes from the plugin's `main` source, not from the RC1 build) |

Step 2 is automated by `tests/api/collect_platform_facts.py` (read-only, writes
`platform_facts.json`), plus the live probe for F3/F4 and the decoder/kvdb content for F5/F5b.

## Step 3 - Run the tests (same commands as RC1)

Memory guard on every host during the run: `free -m` before each step; stop if available memory
on the server drops below 1 GB, if swap use grows during the run, or if the kernel log shows an
OOM kill.

| Order | Test | Pass criterion |
|---|---|---|
| 0 | `python tests/repro/check_clean_checkout.py --commit <frozen> --out evidence/<date>-rc2` on the workstation | PASS: unit tests, validate, rendered monitors byte-identical to `expected/monitors/` (hashes as recorded for the frozen revision), imports only from the clean checkout |
| 1 | `python -m unittest discover -s tests/unit` | all pass (49 at 105573d; no RC dependency; confirms the commit, including the expected monitor outputs) |
| 2 | `python -m wcp preflight` | no `error`; history warning expected if F6 unchanged |
| 3 | `tests/api/test_monitor_execute.py` | 24/24 (22 at 105573d; 2 identity cases added with d090875), Painless identities equal the Python reference |
| 3b | `tests/api/test_lateness_scheduler.py` | all 24 cases as expected. RC1 reference: visibility delays ~110 s (within the 120 s allowed lateness), ~121 s and ~132 s (slightly beyond it) counted in every phase; ~264 s counted only when visible just before a run; ~335 s never |
| 4 | `tests/api/test_least_privilege.py` (if authorised); superseded for RC2 by P4 (`tests/validation/p4_least_privilege_scheduled.py`) | PASS and cleanup verified; otherwise record "not executed" |
| 5 | `wcp apply`, then `tests/e2e/test_deploy_lifecycle.py` | PASS; all non-pack documents unchanged |
| 6 | `tests/e2e/test_ssh_live.py` | PASS (counting, alert, de-duplication, resolution, new episode) |
| 7 | `tests/validation/replay_batches.py --batch ssh` (RC1: `tests/e2e/test_replay.py`) | 18/18 (16/16 with one Linux endpoint; 2 deferred) |
| 8 | `tests/validation/replay_batches.py --batch windows` | 4/4 |
| 9 | `tests/validation/windows_sample_decoding.py` (RC1: `tests/e2e/test_windows_sample_decoding.py`) | PASS |
| 10b | P2 (`tests/validation/p2_reporting_subject_capture.py`). Windows identity with a reporting subject: failed *local/interactive* logons (e.g. `runas` or console with a wrong password, LogonType 2) and failed network logons with an explicit domain (`smbclient -U 'OTHERDOM\wcpt-x'`) on the Windows endpoint | decoded fields match F5b; `wcp.windows_target_account` never contains the subject's domain; same user name in two domains counts twice |
| 10 | P3 (`tests/validation/p3_windows_collection.py`). Windows endpoint, live: failed SMB logons from `linux_source` (`smbclient` with a wrong password, test account), then failed RDP logons | 4625 events collected through EventChannel; `event.original` format compared with `samples/windows/`; burst alert at 10 attempts; spray alert at 5 accounts; LogonType of the SMB and RDP failures recorded (to decide whether RDP-specific detection becomes possible) |
| 11 | P5 (`tests/validation/p5_notifications.py`). Notification: actions with `notify_on: [NEW]` and `[NEW, COMPLETED]` to a webhook channel | one notification per NEW alert, none for DEDUPED runs |
| 12 | Optional: endpoint 3 (`sshd-session`) live SSH burst | counted as on endpoint 1 |

Record the same measurements as RC1: event searchable delay, alert delay, resolution time,
query `took`.

## Priorities for the RC2 run

These six items close the gaps that the RC1 evidence leaves open; they are run first after
Steps 1-2 and tests 0-3b. "Harness" says where the test code is. All six are implemented as
separate harness commits after the frozen revision (`tests/validation/`, `docs/VALIDATION_TESTS.md`)
and were executed on 2026-11-22 on 5.0.0-rc2 (`evidence/2026-11-22-rc2/README.md`); their offline self-tests pass. Prerequisites, assertions, evidence
and cleanup of each are in `docs/VALIDATION_TESTS.md`.

| Priority | What | Procedure | Pass criterion | Harness |
|---|---|---|---|---|
| P1 | Updated Windows spray monitor (`wcp.windows_target_account`, 105573d) through the ingestion pipeline | `wcp apply` of the frozen revision; test 8 (`test_replay.py --batch windows`); replayed 4625 records for: same user name in 2+ domains, a missing TargetDomainName, upper/lower case variants, the local computer realm `.` | alert/no-alert and the account set in the alert's bucket match the query/API identity cases; `wcp status` in sync | test 8 (4 scenarios from 25e52cc) plus `tests/validation/p1_windows_identity_replay.py`: 12 identity scenarios, 60 synthetic records derived from `samples/windows/`; **FAIL** 2026-11-22 on 5.0.0-rc2: 11 scenarios PASS; ambiguous account-domain case uses the reporting subject's domain (detection defect) |
| P2 | A real 4625 event with both a reporting subject and a failed target account | test 10b on the Windows endpoint: `runas /user:OTHERDOM\wcpt-x` and a console logon with a wrong password (LogonType 2), plus SMB with an explicit domain | decoded `user.domain`, `user.target.domain`, `user.id`, `user.target.id` match F5b; `wcp.windows_target_account` uses TargetDomainName, never SubjectDomainName; one sanitized event saved under `samples/windows/` | synthetic part in P1 (scenarios `p2_*`); captured part `tests/validation/p2_reporting_subject_capture.py` (LogonUser on the endpoint + SMB with an explicit domain); PASS 2026-11-22 on 5.0.0-rc2 (real capture) |
| P3 | Real Windows collection | test 10: EventChannel on Windows Server 2019, failed SMB then RDP logons from `linux_source` | 4625 collected; `event.original` compared with `samples/windows/`; burst alert at 10, spray alert at 5 accounts; LogonType recorded | `tests/validation/p3_windows_collection.py` (SMB; RDP with `--rdp`); PASS 2026-11-22 on 5.0.0-rc2 |
| P4 | Least-privilege deployment **and execution** | test 4 (`test_least_privilege.py`) covers preflight, plan, update, status and a dry-run `_execute` as the restricted user. Add: a monitor saved by the restricted user is run by the **scheduler** and raises an alert from a test burst; with the index read permission removed from the role, a new burst is not counted; how the platform reports the denied search (ERROR alert, input error, or nothing) is recorded, not assumed | test 4 PASS; scheduled run as the restricted user alerts; no alert for the burst after the permission removal; temporary user/role deleted and the monitor restored by admin | `tests/validation/p4_least_privilege_scheduled.py` (installation, scheduled execution, two negative reads, permission removal; role file `tests/validation/security/wcp_deployer.role.json`); PASS 2026-11-22 on 5.0.0-rc2 (first run FAIL: harness assumption, fixed) |
| P5 | Notification delivery, including short-lived alerts | webhook channel to a listener on the workstation; action `notify_on: [NEW]` (and a second run with `[NEW, COMPLETED]`); cases: a normal burst; continued activity (DEDUPED runs); a late set counted by a single run (as the "before, ~264 s" lateness case, whose alert exists ~60 s with alert history disabled) | exactly one NEW notification per alert, none for DEDUPED runs; the single-run alert is notified; COMPLETED notified when configured; delivery delay recorded | `tests/validation/p5_notifications.py` + `webhook_listener.py` (temporary monitor copies with test actions); needs a Notifications channel or permission to create one; PASS 2026-11-22 on 5.0.0-rc2 |
| P6 | Missed scheduler runs and recovery | (a) disable the monitor for 3 minutes during and after a burst, then re-enable; (b) restart the indexer service while a burst is in the lookback (dedicated RC2 server only, never on the RC1 reference server) | (a) runs resume on a grid anchored to the new `enabled_time`; missed runs are not caught up; a set still inside the lookback at the first run after recovery is counted, an older one is not (record both); (b) first run after restart, state of ACTIVE alerts (kept, deduplicated or completed) and any duplicate NEW alert recorded | `tests/validation/p6_scheduler_recovery.py` (`--part a` disable/re-enable, `--part b` indexer restart); PASS 2026-11-22 on 5.0.0-rc2 (parts a and b) |

What remains before the RC2 run can start is the environment, the accounts and the authorisations
in "Resources", and step 0 (the clean-checkout check of the candidate commit).

## Step 4 - Decide and document

* All pass criteria met and F1-F10 unchanged: update the compatibility statement to "validated on
  5.0.0-rc1 and 5.0.0-rc2", per-version rows in the README results table, link both evidence
  directories.
* Any difference: document it per version; if the pack must change, follow ground rule 2.
* Tests 10-12 extend coverage; if they are not run, the corresponding limitations stay as they
  are (Windows endpoint collection, notification delivery, newer OpenSSH untested).

## Step 5 - Clean up the RC2 environment

`python -m wcp remove --yes`; delete the temporary role/user if test 4 ran; remove or revoke
test agents and enrollment tokens; delete the test endpoints. Record the cleanup in the RC2
evidence README.
