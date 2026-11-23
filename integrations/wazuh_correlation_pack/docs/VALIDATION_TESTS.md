# Validation tests P1-P6 (for the 5.0.0-rc2 run)

**Status: run on 5.0.0-rc2 on 2026-11-22**: revision 38ad481 (`evidence/2026-11-22-rc2/README.md`) and candidate 5c1da90 with the fixes (`evidence/2026-11-22-rc2-candidate/README.md`); the Windows paths again on the current revision (`evidence/2026-11-23-rc2-mixed-realm/README.md`). These tests close the gaps the 5.0.0-rc1 evidence leaves
open (`RC2_VALIDATION_PLAN.md`, "Priorities for the RC2 run"). None has run against a cluster:
there is no RC2 environment yet, and several need a Windows endpoint, credentials or permission to
create resources. Only their offline self-tests have run (see "Checked offline" below). Nothing here
changes the compatibility statement, which stays **5.0.0-rc1 only**.

Detection baseline: frozen revision `38ad481e2c522c5ba0d22423423d20702d8a946f` (detection
behaviour of `105573d`, content hashes in `../evidence/2026-11-22-reproducibility/README.md`). The
tests are harness code in `tests/validation/`; they do not change `wcp/`, `rules/`, `correlations/`,
`pack.yml` or `expected/`. P1, P3 and P4 check that the monitors under test carry the frozen content
hashes.

## Coverage

| Priority | Test | What a PASS shows | Input | Needs | Status |
|---|---|---|---|---|---|
| P1 | `tests/validation/p1_windows_identity_replay.py` | The Windows spray monitor counts accounts as specified (domain, missing domain, case, local realm `.`) after the real ingestion pipeline: decoded fields, Python and Painless identities, scheduler alerts | 12 scenarios, 60 records, **synthetic** (derived from the real capture) | RC2 cluster, Linux replay agent | FAIL on 38ad481 (detection defect); PASS on 5c1da90; **PASS** on the current revision (8ce737c, 6ee2300; 2026-11-23) |
| P2 | P1 (scenarios `p2_*`) and `tests/validation/p2_reporting_subject_capture.py` | With a reporting subject different from the failed target, the target account determines the count; the subject-present decoding matches the decoder model on **real** events | synthetic (P1) and **captured** (P2) | + Windows endpoint, Linux source | PASS 2026-11-22 on 5.0.0-rc2 (38ad481 and candidate 5c1da90; real capture) |
| P3 | `tests/validation/p3_windows_collection.py` | Real EventChannel collection: every Security-log record is indexed once, normalized as expected, and counted by the burst and spray monitors as computed from the log | **captured** (SMB; RDP optional) | + Windows endpoint, Linux source | PASS 2026-11-22 on 5.0.0-rc2 (38ad481 and candidate 5c1da90) |
| P4 | `tests/validation/p4_least_privilege_scheduled.py` | A user with only `wcp_deployer` can install and run the pack; the scheduler runs that user's monitors; out-of-role requests are refused; losing index access stops the monitor from counting (how the platform reports it is recorded) | temporary role/user | + permission to create security resources | PASS 2026-11-22 on 5.0.0-rc2 (38ad481 after a harness fix; candidate 5c1da90) |
| P5 | `tests/validation/p5_notifications.py` + `webhook_listener.py` | One notification per NEW (and COMPLETED when configured), none for DEDUPED runs, including an alert that exists for a single run; payloads, duplicates and delays recorded | temporary monitor copies, controlled visibility | + Notifications channel, reachable receiver | PASS 2026-11-22 on 5.0.0-rc2 (38ad481 and candidate 5c1da90) |
| P6 | `tests/validation/p6_scheduler_recovery.py --part a` / `--part b` | (a) disable/re-enable: no catch-up, new grid, detection gap recorded; (b) an enabled monitor missing runs (indexer restart): first run after recovery, gaps and alert state recorded | temporary monitor copy, controlled visibility | + resource creation; (b) indexer restart on a dedicated server | PASS 2026-11-22 on 5.0.0-rc2 (parts a and b; 38ad481 and candidate 5c1da90) |

## Safety model: disabled by default

A live test runs only when **all** of these hold (`tests/validation/vlib.py`, `gate`):

1. `--live` is given. Without it the test prints its plan (inputs and expected results, computed
   offline) and reports `NOT EXECUTED`; with `--evidence DIR` it writes `<test>_plan.json`. No
   network access.
2. A lab configuration file is given (`--lab-config` or `WCP_LAB_CONFIG`) with `enabled: true`
   and the test in `tests_enabled`. The template `tests/validation/lab.example.yml` is disabled.
3. The indexer the credentials point at reports the `cluster.cluster_uuid` of that file.
4. No pack monitor on that cluster carries a content hash of the RC1 reference deployment
   (`409a902d80326aad`, the Windows spray monitor applied from 25e52cc): the 5.0.0-rc1 reference
   server is refused even if it is configured by mistake.
5. Resource-creating tests (P4, P5, P6) need `allow.create_resources: true`; P6 part b also
   `allow.restart_indexer: true`.

Other rules: target accounts must carry the test prefix (`wcpt-`) and never contain an access
account name; failed logons use non-existent accounts (no lockout) and the dummy password
`wcp-not-a-password`. Temporary resources are named `[wcp-test] ...` (monitors, channel),
`wcp-test-*` (indices) or `wcp_p4_deployer` (role, user), are deleted in a `finally` block, and the
deletion is verified (404) and recorded. Captured Windows events are sanitized before they are
saved; a capture in which a configured name, address or access account remains is not saved.

The lab configuration contains no credentials: indexer credentials come from the `wcp` env file
(`docs/CONFIGURATION.md`), SSH authentication from the SSH agent or keys. Keep the file outside
the repository.

### Endpoint roles and shared machines

`linux_replay`, `linux_source`, `windows` and `server` are **roles**. One VM may serve several
roles (the 2026-11 RC2 lab has a single Linux VM for `linux_replay` and `linux_source`); its
entries then carry the same `machine` label. For every alias a live test uses, the harness reads
the machine identity (`/etc/machine-id`, or the Windows `MachineGuid`; stored only as a 16-hex
hash) and:

* refuses two aliases of one machine with different labels, and one label on two machines;
* takes one lock per machine (`/tmp/wcp-validation.lock`, `C:\ProgramData\wcp-validation.lock`)
  for the whole test and releases it at the end, so tests sharing a machine - and the conflicting
  scenarios they generate - run one after another; a second run is refused with the lock owner;
* records `environment.endpoint_machines` (`distinct_machines`, and per machine its label,
  hash and aliases) in the evidence. Aliases are never reported as independent endpoints.

A lock left by an interrupted run is removed by hand (`rm -rf /tmp/wcp-validation.lock`) after
checking that no test is running. Tests that need a second Linux machine are listed as deferred in
`docs/RC2_VALIDATION_PLAN.md` ("Single Linux endpoint").

## Running

```bash
export WCP_LAB_CONFIG=~/.config/wazuh_correlation_pack/lab-rc2.yml   # copy of tests/validation/lab.example.yml
python tests/validation/p1_windows_identity_replay.py            # plan only
python tests/validation/p1_windows_identity_replay.py --live --evidence evidence/<date>-rc2
```

Suggested order on a fresh RC2 cluster (each test is independent otherwise):

1. P4 (installs the pack as the restricted user and removes it again; needs the pack absent);
2. `python -m wcp apply` as admin, `python -m wcp status` (frozen hashes);
3. P1, P2, P3 (read the deployed monitors; create nothing);
4. P5, P6 part a (temporary monitor copies);
5. P6 part b last (restarts the indexer).

Every test writes `<test>.json` (P6: `p6_part_a.json`, `p6_part_b.json`) with: environment
(OpenSearch version, cluster match), harness revision (`git rev-parse HEAD`, uncommitted changes,
whether detection files differ from the frozen commit), plan, inputs with provenance, expected
values, observations (recorded, not pass criteria), checks, timings, cleanup, and a status: `PASS`
only if every check passed, `FAIL`, or `ERROR` (exception, with the traceback).

## P1 - Windows account identity through the ingestion pipeline

* **Prerequisites**: the pack deployed at the frozen revision; `endpoints.linux_replay` = a Linux
  test agent (RC2 agent) with the replay `localfile` of `tests/lab/README.md`, `sudo -n` allowed
  for appending to the replay file; the scenario source addresses (198.51.100.60-71 plus
  `--ip-offset`) without events in the last 15 minutes.
* **Execution**: builds 60 4625 records from the first event of the real capture with the
  identity fields of each scenario (`tests/validation/identity_scenarios.py`), appends them to the
  replay file, waits until they are searchable, runs a threshold-1 dry-run copy of the spray
  monitor per scenario, then observes the deployed monitors for `--observe` seconds (default 300).
* **Assertions** per scenario: frozen content hashes deployed; every record indexed once (matched
  by EventRecordID); decoded identity fields = `winevents.decoder_model` (the RC1 decoder steps);
  `wcp.identity` on the decoded event = the specified account; Painless identities = the specified
  account set; one spray alert with the specified score and account sample when >= 5 accounts,
  none otherwise; no burst alert. The expected accounts are written from the specification, and
  every scenario is decisive: a wrong identity (user name only, case-sensitive, subject domain or
  subject account) changes its outcome (checked offline).
* **Evidence**: `p1.json`.
* **Cleanup**: none on the cluster (the replayed events stay in the events data stream, as in the
  RC1 replay runs).
* **Not covered**: EventChannel collection (P3); events written by Windows itself (P2/P3).

## P2 - reporting subject vs failed target

* **Synthetic part** (in P1, scenarios `p2_*`): one subject with five targets (5 accounts), five
  subjects with one target (1 account), subject present with TargetDomainName `-` (realm `?`),
  the same account with and without a subject (one account). Provenance `synthetic-derived`.
* **Captured part** (`p2_reporting_subject_capture.py`), provenance `captured`:
  * **Prerequisites**: `endpoints.windows` (agent id, address, PowerShell over SSH with an account
    that may read the Security log; it is the reporting subject of the local calls, never a
    target), `endpoints.linux_source` with `smbclient`.
  * **Execution**: LogonUser() on the endpoint for 5 targets in `WCPOTHERDOM` (interactive),
    3 times one target, 2 targets with realm `.` (network type), and one SMB failure from the
    Linux source with an explicit domain. Ground truth: `Get-WinEvent` of the Security log.
  * **Assertions**: one 4625 per attempt; the LogonUser records have a subject that differs from
    the target; every record indexed once; decoded identity = decoder model (first observation of
    the subject-present shape on real events); `wcp.identity` = the account from the raw target
    fields, never the subject's domain; a threshold-1 dry-run probe grouped by agent (the local
    records have no `source.ip` and are not counted by the pack's correlations - documented in the
    base rule) returns exactly the target accounts for one subject.
  * **Evidence**: `p2.json`, `p2_captured_4625.sanitized.xml.log` (copy one record into
    `samples/windows/` with a README entry after review).
  * **Cleanup**: none needed (non-existent accounts; the Security log keeps its records).
* **Ambiguous account domain** (scenarios `p2_ambiguous_subject_domain`,
  `p2_ambiguous_no_target_domain_element`): a 4625 with a subject *name* but the NULL SID and no
  TargetDomainName decodes with `user.id` = `user.target.id` and `user.domain` = the subject's
  domain. With 105573d the pack took that subject domain as the target's realm (five subject
  domains -> five accounts, false spray alert; RC2 run 2026-11-22, `evidence/2026-11-22-rc2/p1.json`).
  Since d090875 the realm comes only from `user.target.domain`; the specification is one account
  `?\bob`, no alert. Every P1 scenario also checks that no failed-target account takes its realm
  from a reporting subject's domain.

## P3 - real Windows collection

* **Prerequisites**: Windows Server 2019 (or 2022) with the RC2 agent (default EventChannel collection of the
  Security log), Audit Logon "Failure" enabled (checked), OpenSSH server and an administrative
  account for `Get-WinEvent`; `endpoints.linux_source` with `smbclient` (and `xfreerdp` with `xvfb` on a headless host for
  `--rdp`), reaching the endpoint on 445 (and 3389); no 4625 from that source on that agent in the
  last 15 minutes and no ACTIVE alert for the group.
* **Execution**: 5 SMB spray attempts (`wcpt-p3-s01..s05`), 10 SMB burst attempts
  (`wcpt-p3-burst`), optionally 3 RDP attempts (`wcpt-p3-rdp`); then the Security-log records of
  those names are read and traced.
* **Assertions**: one record per attempt; indexed EventRecordIDs = Security-log EventRecordIDs,
  each once; `event.original` = the Windows rendering without CR/LF, single line, no RenderingInfo,
  same EventData names as `samples/windows/`; per record event.code, dataset, action,
  `source.ip` = IpAddress, `user.target.name` = TargetUserName, `error.code` = SubStatus,
  `event.start` = TimeCreated (ms), identity fields = decoder model; one burst alert and one spray
  alert for [Windows agent, source] whose scores and account sample equal the values computed from
  the Security-log records (independent brute-force window count).
* **Recorded**: LogonType of the SMB (and RDP) records and whether any WCS field carries it (to
  decide whether an RDP-specific detection becomes possible); delays event time -> `@timestamp`.
* **Evidence**: `p3.json`, `p3_captured_4625.sanitized.xml.log` (one record per LogonType).
* **Cleanup**: none needed on the cluster; ACTIVE alerts resolve after the 13-minute lookback.

## P4 - least-privilege installation and scheduled execution

* **Prerequisites**: `allow.create_resources`; admin credentials with security REST API access;
  the pack **not** deployed; room for 4 monitors (`max_monitors`); `endpoints.linux_replay` with a
  UTC clock (replayed sshd lines carry no time zone).
* **Execution**: creates role `wcp_p4_deployer` (from
  `tests/validation/security/wcp_deployer.role.json`; `--minimal` drops the two read-only
  preflight permissions), user `wcp_p4_deployer` (random password, in memory only) and index
  `wcp-test-p4-noaccess`; as that user runs `python -m wcp preflight / plan / apply / status /
  execute` with a separate state directory; replays two 9-attempt sshd bursts, the second after
  removing the role's index permission.
* **Assertions**: CLI steps succeed (4 creates, 4 in sync, frozen hashes); each monitor records the
  restricted user; `GET _plugins/_security/api/internalusers` and a search on
  `wcp-test-p4-noaccess` are refused with 403 (harmless: both are reads); the scheduler runs the
  restricted user's brute-force monitor and raises an ACTIVE alert with score 9; after the index
  permission is removed the second burst (indexed, read as admin) raises no ACTIVE alert during
  three scheduler runs.
* **Stored user**: each monitor's stored `user` is the restricted user, read read-only from
  `.opendistro-alerting-config` on the server with the indexer's super-admin certificate
  (`endpoints.server`), because the 5.0.0-rc2 REST API (GET monitor, `_search`) omits `user`.
* **Recorded** (not assumed): `plugins.alerting.filter_by_backend_roles`; the `user` returned by
  GET monitor; whether ERROR alerts appear after the removal and their messages; a dry-run `_execute` of
  the monitor as the restricted user after the removal (input error or empty result); what happens
  to the first alert until its burst has left the lookback (+ 2 runs).
* **Evidence**: `p4.json`.
* **Cleanup** (always): `wcp remove --yes` as admin, then the user, role and index are deleted and
  verified; the state directory is removed. The pack is left **not deployed**.

## P5 - notification delivery

* **Fail-fast on leftovers**: before anything is created, the test refuses to run if any monitor named
  `[wcp-test] ...` exists (enabled or disabled), or its test index or notification channel exists - typically left by an
  interrupted run. It reports them (id, name, enabled) and deletes nothing; review and delete them,
  then re-run. (Added after an interrupted P5 left two enabled monitors that doubled the next run's
  notifications, `evidence/2026-11-22-rc2-candidate/p5_rerun1.json`.)

* **Prerequisites**: `allow.create_resources`; `notifications.listener_bind`, `listener_token` and
  `webhook_url` (the receiver's URL as seen from the indexer; for a workstation receiver use a
  reverse tunnel, e.g. `ssh -R 8765:127.0.0.1:8765 <rc2 server>` and
  `http://127.0.0.1:8765/wcp-p5/<token>`); either `notifications.channel_id` of an existing webhook
  channel or permission to create one; room for 2 monitors.
* **Execution**: starts the receiver, creates (or reuses) the channel and sends the channel's test
  message, creates index `wcp-test-p5` and two monitor copies (`notify_on: [NEW]` and
  `[NEW, COMPLETED]`), then a probe, a normal burst, a continued burst (DEDUPED runs) and a
  single-run burst timed from the measured run instants; observes until every alert has ended.
* **Assertions**: the channel test reaches the receiver; per copy and case exactly one alert,
  exactly one NEW notification, one COMPLETED notification only for the NEW+COMPLETED copy (so
  none for DEDUPED runs); the single-run alert is notified; every received body is attributable.
* **Recorded**: every received payload (selected headers and body), counts, duplicates, delivery
  delays, the single-run alert's state history.
* **Evidence**: `p5.json`.
* **Cleanup**: monitor copies, index and (if created) channel deleted and verified; receiver
  stopped. The deployed pack monitors are never modified.

## P6 - missed scheduler runs and recovery

* **Fail-fast on leftovers**: before anything is created, the test refuses to run if any monitor named
  `[wcp-test] ...` exists (enabled or disabled), or its test index exists - typically left by an
  interrupted run. It reports them (id, name, enabled) and deletes nothing; review and delete them,
  then re-run. (Added after an interrupted P5 left two enabled monitors that doubled the next run's
  notifications, `evidence/2026-11-22-rc2-candidate/p5_rerun1.json`.)

* **Prerequisites**: `allow.create_resources`, room for 1 monitor; part b also
  `allow.restart_indexer`, `endpoints.server` (sudo for `systemctl restart wazuh-indexer`) and at
  least 1 GB available memory on the server (checked); **dedicated lab server only**.
* **Part a, disable/re-enable** (the monitor is switched off; nothing is "missed" from the
  scheduler's point of view): a continuing group, a burst that only a run during the disabled
  period could count (`gap`), a burst still in the lookback at re-enable (`kept`), and a burst
  after re-enable (`after`). Checks: no alert while disabled; first run ~1 interval after the new
  `enabled_time` (no catch-up), second one interval later; `gap` never counted; `kept` counted.
  Recorded: the continuing group's alert across disable/enable (kept, deleted, or a NEW duplicate).
* **Part b, enabled monitor missing runs** (indexer restart): a continuing group, `gap` (only the
  run at M can count it) and `kept`, made searchable just before the run M, then the restart.
  Checks: the cluster comes back; a scheduled run happens after it; `gap` is counted iff the run at
  M happened; `kept` is counted at the first run after it became searchable iff that run is inside
  its lookback. Recorded: stop/up times, missed grid slots, first run after the restart relative to
  the old grid and to the recovery, the continuing alert's state and any duplicate NEW alert.
* Both parts index a new *heartbeat* group every 30 s so that each run creates an alert and the run
  instants are observable (a DEDUPED run leaves no trace in the alerts API: on 5.0.0-rc1
  `last_notification_time` did not change across runs without actions).
* **Evidence**: `p6_part_a.json`, `p6_part_b.json`.
* **Cleanup**: monitor copy and index deleted and verified. Part b restarts the indexer, which
  interrupts ingestion and every other monitor during the restart.

## Replay batches (`replay_batches.py`, port of RC1 tests 7/8)

* **Prerequisites**: the pack deployed; `endpoints.linux_replay` (agent, hostname, replay file, UTC
  clock). `tests_enabled`: `replay_ssh`, `replay_windows`.
* **Execution**: the scenario definitions of `tests/e2e/test_replay.py` (`ssh_batch`,
  `windows_batch`), unchanged, appended over SSH to the replay file; `--observe` seconds of
  scheduled runs (default 240).
* **Assertions** (as RC1): counted events searchable; `authentication-failure` counts where defined;
  per correlation and group an alert with the expected score, or none.
* **Deferred**: scenarios that put lines on a second monitored Linux endpoint (`bf_different_endpoints`,
  `spray_split_endpoints`) are recorded as DEFERRED with one Linux endpoint, never as passed.
* **Score at creation**: the expected score is compared with the alert's score when it was created
  (first snapshot), as in RC1; an ACTIVE alert's bucket is refreshed by every later DEDUPED run
  (5.0.0-rc2), so its latest score decreases as events leave the lookback. The batch is replayed
  just after a run of its monitors and the instant each group became fully searchable is recorded
  (an alert created earlier is labelled as timing, and still fails).
* **Evidence**: `replay_ssh.json`, `replay_windows.json`. **Cleanup**: none.

## Real 4625 sample decoding (`windows_sample_decoding.py`, port of RC1 test 9)

* The 20 sanitized real events of `samples/windows/` replayed through the Linux endpoint (2016 event
  times, no alert possible); the RC1 field checks (integration, event code/dataset, source.ip,
  target name, error code, event time, action/outcome, LogonType not exposed). `tests_enabled`:
  `win_sample_decoding`. Evidence: `win_sample_decoding.json`.

## Live SSH burst (`ssh_live_burst.py`, port of RC1 test 6)

* **Prerequisites**: the pack deployed; `endpoints.linux_replay` with `agent_id` and `address`
  (its sshd); `ssh_live.client_ip` = this workstation's address as seen by the endpoint; an
  OpenSSH client >= 8.4 on the workstation (forced askpass). The workstation is the client because
  it is not a monitored endpoint (RC1 used a second Linux endpoint; Windows Server 2019's built-in
  client 7.7 cannot answer password prompts non-interactively).
* **Execution**: 3 connections x 3 password prompts for non-existent `wcpt-alice/bob/carol`,
  dummy password; after resolution a second identical burst.
* **Assertions**: frozen hashes; target accounts absent on the endpoint; no ACTIVE alert and no
  counted attempt from the client in the last 300 s; 9 `Failed password` lines in the endpoint's
  sshd journal; 9 indexed `event.reason: Failed password` events; ACTIVE brute-force alert with
  score 9; no spray alert; one alert over three further runs; the alert leaves ACTIVE after the
  lookback and a dry run no longer triggers; the second burst creates a new alert.
* **Evidence**: `ssh_live.json`. **Cleanup**: none (failed logins of non-existent accounts).

## Administrative setup (ready for review)

Definitions in `tests/validation/security/`; nothing is created by the pack itself. All three are
**unverified** on any Wazuh version until P4/P5 have run.

**Deployment role** - `wcp_deployer.role.json`: the Alerting monitor and alert actions, read on
`wazuh-events-v5-system-activity*`, `cluster:monitor/main`, and two read-only permissions used only
by `preflight` (`cluster:monitor/state`, `cluster:monitor/nodes/info`). As a cluster administrator:

```bash
curl --cacert root-ca.pem -u admin -X PUT "https://<indexer>:9200/_plugins/_security/api/roles/wcp_deployer" \
     -H 'Content-Type: application/json' --data @tests/validation/security/wcp_deployer.role.json
# either an internal user (set the password in your copy of the file; never commit it):
curl --cacert root-ca.pem -u admin -X PUT "https://<indexer>:9200/_plugins/_security/api/internalusers/<deploy user>" \
     -H 'Content-Type: application/json' --data @wcp_deployer.internaluser.local.json
# or a mapping of an existing user / backend role (template: wcp_deployer.rolesmapping.json):
curl --cacert root-ca.pem -u admin -X PUT "https://<indexer>:9200/_plugins/_security/api/rolesmapping/wcp_deployer" \
     -H 'Content-Type: application/json' --data @wcp_deployer.rolesmapping.local.json
```

(`-u admin` without a password makes curl prompt for it, so it does not reach the shell history.)
Alerting runs a monitor with the roles of the user who created or last updated it: keep the role
mapped for as long as the monitors exist (P4 checks what happens otherwise).

**Notifications channel** - `notifications_webhook_channel.json`: a webhook channel named
`[wcp-test] P5 webhook receiver` (config id `wcp-test-p5-webhook`) posting to the lab receiver;
replace the URL, then `POST _plugins/_notifications/configs` with the file; delete it after the run
(`DELETE _plugins/_notifications/configs/wcp-test-p5-webhook`). P5 creates and deletes it itself
when `notifications.channel_id` is null. The user running P5 needs, besides the Alerting
permissions, the Notifications actions to create, read, delete and test a channel (the built-in
`notifications_full_access` role, or `all_access`).

**Accounts used by the tests**: the indexer admin of the RC2 lab (P4 creates and deletes the
temporary role and user through the security REST API); SSH to the Linux endpoints (`sudo -n`
for the replay file on `linux_replay`) and to the RC2 server (P6 part b, `sudo -n systemctl
restart wazuh-indexer`); an administrative SSH account on the Windows endpoint (reads the
Security log; is the reporting subject in P2, never a target).

## Checked offline (no cluster)

`python -m unittest discover -s tests/validation -p "test_*.py"` (also run by the clean-checkout
check) covers: the gate refuses to run without `--live`, without or with a disabled configuration,
for an unlisted test, without resource permission, and without a cluster UUID; the example
configuration is disabled; every test's plan mode; the frozen hashes equal the committed expected
monitors; target-account and temporary-name rules; endpoint command quoting (POSIX, PowerShell
encoded command); shared-machine handling (aliases of one VM counted once and locked once,
unlabelled or mislabelled aliases refused, a concurrent run refused, plan mode contacts nothing);
the 4625 builder and parser; the decoder model reproduces the identity shape
observed on 5.0.0-rc1 for the 20 real sample records; the sanitizer; the specified P1/P2 accounts
equal the derivation on the modeled decoding (no exception) and every
scenario is decisive; the P5/P6 timing margins (>= 15 s); the P3 window counts against the pack's
reference algorithm; the receiver and the attribution of notification bodies; the role file against
the documented permissions. These checks say nothing about RC2 behaviour.
