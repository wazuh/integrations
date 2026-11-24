# Test run 2026-11-21 - Wazuh 5.0.0-rc1

> **Sanitized publication copy.** Lab addresses, host names, the lab cluster id and workstation
> paths are replaced consistently; measurements, outcomes and monitor hashes are unchanged. Files
> named here but absent (superseded attempts, harness errors, intermediate records) are kept in
> the unpublished development archive. Revision ids are development-branch commits. See
> [../README.md](../README.md).

**Code version.** Detection code (`wcp/`, `rules/`, `correlations/`, `pack.yml`) of commit
`25e52cc`; Windows spraying then counted distinct `user.target.name` (monitor content hash
`409a902d80326aad`). The test harness used is committed in `fce7a87` (it was excluded from
25e52cc by the repository root `.gitignore`). These results do **not** cover later detection
changes: for `105573d` (Windows account identity) see `../2026-11-22-rc1-105573d/`.

## Environment

| Component | Version / detail |
|---|---|
| Wazuh manager, indexer, dashboard | packages `5.0.0-1`, `VERSION.json` stage `rc1` (installed from `*_5.0.0-rc1_amd64.deb`), all-in-one on Ubuntu 22.04.5, 4 vCPU, 4 GB RAM, no swap |
| Indexer | OpenSearch 3.6.0, plugin `wazuh-indexer-alerting`; `plugins.alerting.alert_history_enabled` = `false` (default) |
| Test endpoints | 2 LXD containers, Ubuntu 22.04.5, OpenSSH 8.9p1, wazuh-agent 5.0.0-rc1 (agents 001 `wcp-ep1`, 002 `wcp-ep2`) |
| Content | stock `standard` space (policy "RC1 public"), integrations `system-auth` and `windows` |
| Client | Windows 11, Python 3.12.3, PyYAML 6.0.2; indexer reached through an SSH tunnel with TLS verified against the indexer root CA |
| Indexer user for the tests | `admin` (`all_access`) |

## Results

| Evidence | Layer | Checks | Verdict |
|---|---|---|---|
| `../../tests/unit` (not a file: `python -m unittest discover -s tests/unit`) | unit | 35 tests | PASS |
| `api_monitor_execute.json` | query/API (fixtures + `_execute`) | 16 cases | PASS |
| `ssh_live_burst_and_lifecycle.json` | pipeline, live sshd | 11 | PASS |
| `ssh__*.json` (18 files) | pipeline, replay | 18 scenarios | PASS |
| `windows__*.json` (4 files) | pipeline, replay (real-derived 4625) | 4 scenarios | PASS |
| `windows_real_sample_decoding.json` | pipeline, replay (real 4625, decoding only) | 9 | PASS |
| `deploy_lifecycle.json` | deployment against the real cluster | 45 | PASS |
| `findings_vs_events.json` | observation (no verdict) | - | - |

Not executed: `tests/api/test_least_privilege.py` (creating a temporary security user on the
server was not authorised). No Windows endpoint was available: Windows collection (EventChannel)
is not tested.

## Measurements

| Measurement | Value |
|---|---|
| Live: last SSH attempt -> events searchable | 14.5 s |
| Live: last SSH attempt -> ACTIVE alert (scheduler, 1 min interval) | 19.6 s (episode 1), 35.5 s (episode 2) |
| Live: last SSH attempt -> alert no longer ACTIVE (300 s lookback) | ACTIVE at every 5 s poll from 275.7 s (start of resolution polling); absent at the 320.9 s poll |
| Replay: line written -> event searchable | 26.9-28.3 s (median 27.5, n=25) |
| Replay: line written -> alert seen (10 s polling) | 77.8-78.8 s in the reference run (`ssh__*`, `windows__*`); 38.4-57.7 s in the superseded run (`superseded/`) |
| Monitor query, fixtures (`took`) | 2-7 ms; 85 ms for one group of 5000 events (`api_monitor_execute.json`) |
| Deployed monitor dry run on the live data stream (1079 events, round trip through the tunnel) | 27-75 ms - console output of `wcp execute`, **not stored in an evidence file** |
| Outage observation | events generated at 07:50 UTC while the indexer was down (OOM, 07:35-07:55) carried `@timestamp` = 07:50:29 (manager processing time) - session observation, **not stored in an evidence file** |

## Superseded files

`superseded/` holds the evidence of the first replay batches (same scenario names). They were
replaced because the lab driver sent replay lines with CRLF line endings (Windows text-mode pipe),
so lines whose stock pattern ends in a field (`Invalid user ... port N`, `pam_unix ... rhost=IP`)
did not decode as on a real endpoint. Counted `Failed password` lines and Windows events decoded
correctly in both runs and all alert outcomes were the same; the re-run (LF line endings, fresh
source addresses) is the reference. A run before that failed its positive checks because the
harness read alerts after they had completed and been deleted (alert history disabled); the
harness was fixed to record alerts while active (that run's files were overwritten by the next
run and are not kept).

## Review of 2026-11-21 (claims reconciled with these files)

The evidence JSON files were not changed. The following statements in the README and docs of
commit 25e52cc were corrected or qualified:

| Statement in 25e52cc | Evidence | Correction |
|---|---|---|
| "late within lateness: 8 attempts stamped 113-120 s before delivery" | `ssh__bf_late_within_lateness.json`: event times 09:04:01-09:04:08, replay written 09:06:03.5, searchable 27.7 s later | Event times were 115-123 s before the replay and the events became searchable 143-150 s after their event times, i.e. **beyond** the 120 s `allowed_lateness`. They were counted because the set was still inside the 300 s lookback. The scenario shows that lateness is a guarantee, not a cut-off; it does not test the 120 s boundary itself. (The scenario name in the file is unchanged.) |
| "late beyond lookback: stamped 400 s before delivery" | `ssh__bf_late_beyond_lookback.json`: 08:59:21-08:59:28 vs 09:06:03.5, searchable +27.8 s | 396-403 s before the replay, 423-430 s before searchable. Not counted (correct). |
| "duplicate delivery: 4 records delivered twice" | `ssh__bf_duplicate_delivery.json`: 4 distinct lines (ports 50000-50003) each appended twice to the collected file, all at 09:05:31 | This is duplication **at the source** (a record collected twice). It does not test retransmission inside the pipeline (agent -> manager -> indexer), which remains untested. |
| "alert left ACTIVE 276-321 s after the last attempt" | `ssh_live_burst_and_lifecycle.json`: states `[275.7, ACTIVE]`, `[320.9, ABSENT]`, 5 s polling from 275.7 s | ACTIVE at every poll from 275.7 s, absent at the 320.9 s poll. Consistent with the 300 s lookback: the 9 attempts span 08:57:11-08:57:36, fewer than 8 remain in the lookback after 08:57:15 + 300 s = 09:02:15 (279 s after the last attempt), next scheduled run within 60 s. |
| "no repeated notification with notify_on: [NEW]" | `ssh_live_burst_and_lifecycle.json`: same alert id and `last_notification_time` over 3 runs; no actions configured | Alert de-duplication is evidenced; notification delivery is **not tested**. |
| "96 ms for a 5000-event group" | `api_monitor_execute.json`: `spray_large` query `took` = 85 ms | 85 ms (96 ms came from an earlier, unrecorded execution). |
| "deployed monitors ran in 27-75 ms" | no file | Kept as a console observation, labelled as such. |
| "the stock decoders do not map TargetDomainName" | stock `decoder/windows-security/0` (rc1) | Wrong: it is mapped to `user.domain` (when `SubjectDomainName` is `-`) or `user.target.domain`. Conclusion unchanged: no single field holds the target domain, so the spray correlation counts names only. |
| Windows agent default configuration "collects the Security channel"; agent XML format | not observed | Marked unverified: no Windows agent was run. |
| Permissions list | `tests/api/test_least_privilege.py` not executed | Marked unverified; all tests ran as `admin` (`all_access`). |

Not covered by this evidence: Wazuh 5.0.0-rc2 or later (see `docs/RC2_VALIDATION_PLAN.md`;
results for another version go in a separate `evidence/<date>-<version>/` directory).
