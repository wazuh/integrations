# One failed target in both decoded 4625 shapes - defect, fix, RC2 validation (2026-11-23)

> **Sanitized publication copy.** Lab addresses, host names, the lab cluster id and workstation
> paths are replaced consistently; measurements, outcomes and monitor hashes are unchanged. Files
> named here but absent (superseded attempts, harness errors, intermediate records) are kept in
> the unpublished development archive. Revision ids are development-branch commits. See
> [../README.md](../README.md).

Same 5.0.0-rc2 lab as `../2026-11-22-rc2-candidate/` (RC1 not contacted). Earlier result files are
unchanged.

## The question and the existing coverage

Case: one agent, one source, one window; failed targets CONTOSO\alice, \bob, \carol, each seen
once without a reporting subject (decoded realm unknown, `?\name`) and once with one (explicit
`user.target.domain`, `contoso\name`). Ground truth from the raw failed-target fields (every
record has TargetDomainName CONTOSO): **3 accounts, no spray alert** (threshold 5).

Existing tests did not cover it exactly. The closest, P1 `p2_subject_present_and_absent_counts_twice`
(`../2026-11-22-rc2-candidate/p1.json`), had 4 actual accounts (contoso\bob in both shapes, c1-c3),
counted 5 keys and raised a spray alert - its specification called that "counts twice" and passed.

## Defect reproduced (deployed candidate monitor, Windows spray `4564e84945edcf3a`)

`api_monitor_execute_df2ae18_before_fix.json` (tests `df2ae18`, detection unchanged since d090875):
`win_id_mixed_shapes_three_accounts` **FAIL** - six representation keys counted, spray alert score 6
from three accounts. `win_id_mixed_shapes_five_names` (5 distinct names across both shapes) PASS.

## Fix (detection `6ee2300`)

Conservative counting for `wcp.windows_target_account` (`PAINLESS_REDUCE_UNKNOWN_REALM`, used only
by the Windows spray monitor): in a window, each known-realm account counts once; `?\name` adds an
account only if no known-realm account with the same user name is present. The reporting subject's
domain is never used. Trade-off: an unknown-realm event of a different account that shares a user
name with an explicit one is merged into it (the count can be lower than the number of real
accounts). The fix addresses the over-count demonstrated here (one failed target counted twice through
both decoded shapes); other over-count causes (NetBIOS/DNS forms of one domain, a record collected
twice) are unchanged.

| Monitor | Content hash | Change |
|---|---|---|
| `wcp_windows_password_spray` | **`98f4090ad6dfc58f`** | was `4564e84945edcf3a` |
| `wcp_ssh_bruteforce`, `wcp_ssh_password_spray`, `wcp_windows_failed_logon_burst` | `007c0a436059d016`, `172cc43b9dfcc25c`, `d31fc5d758665c2e` | byte-identical |

Deployment (`wcp_update_apply.txt`): `plan` one update (`4564e84945edcf3a` -> `98f4090ad6dfc58f`),
`apply` with the bound RC2 manifest, `plan` 0 changes.

## Validation of the affected Windows paths (final results)

| Test | Result | Code that ran | Evidence |
|---|---|---|---|
| Query/API, 26 cases (incl. both mixed-shape cases) | **PASS 26/26** | b9dc276 | `api_monitor_execute.json` |
| P1, 18 scenarios / 91 records (incl. `p2_mixed_shapes_three_accounts`: score 3, no spray; `..._five_names`: alert 5) | **PASS 134/134** (one compile-limit retry, recorded) | 8ce737c | `p1.json` |
| Replay batch Windows | **PASS 16/16** | 3868f23 | `replay_windows.json` |
| P2 real reporting-subject capture | **PASS 7/7** | 3868f23 | `p2.json` |
| P3 real Windows collection (SMB, RDP) | **PASS 14/14** | 3868f23 | `p3.json` |
| Unit tests (68) and harness self-tests (48) | PASS | every candidate | `step0-clean-checkout-*` |

Detection (`wcp/`, rules, correlations, `pack.yml`, `expected/`) is identical in 3868f23, b9dc276,
8ce737c, 78600f9 and 10e53cc (detection last changed in 6ee2300; both change documentation only, clean
checkout `step0-clean-checkout-final-78600f9/` PASS; 10e53cc likewise, `step0-clean-checkout-final-10e53cc/`
PASS). Between those revisions only harness code changed: the
representation-aware sample comparison (used by P1 and query/API only) and the dry-run retry on the
compile rate limit (P1/P2 probes; P2 needed no retry). Tests not affected by the change - SSH
monitors (byte-identical), P4-P6, lifecycle, lateness, live SSH, SSH replay, sample decoding - keep
their results from candidate 5c1da90 (`../2026-11-22-rc2-candidate/`).

### Superseded attempts (kept)

| File | Result | Cause |
|---|---|---|
| `api_monitor_execute_df2ae18_before_fix.json` | FAIL | the defect (before the fix) |
| `replay_windows_c3d4fec.json` | PASS | rerun on 3868f23 for one attribution |
| `api_monitor_execute_c3d4fec_parity_check_FAIL.json` | FAIL | harness: identity parity compared the merged Painless sample with an unmerged Python set |
| `p1_c3d4fec_compile_limit_ERROR.json` | ERROR | indexer script compilation rate limit (input error) right after the query/API suite |
| `p2_/p3_c3d4fec_windows_unreachable_ERROR.json` | ERROR | the Windows VM's DHCP address changed (.155 -> .134; same VM: MAC, SSH host key, machine identity and agent 002 unchanged) |
| `p1_3868f23_sample_representation_FAIL.json`, `api_monitor_execute_3868f23_sample_representation_FAIL.json` | FAIL | harness: the account sample (values when the best score was first reached) named carol as `?\carol`; checks compared strings, not accounts. Score 3 and no alert were correct |
| `p1_b9dc276_compile_limit_trigger_ERROR.json` | ERROR (89 checks passed) | compile rate limit surfaced as a trigger error over an empty input |

Platform observation: OpenSearch's script compilation rate limit (`compilation_limit_triggered`
rose 0 -> 4 during the run) is reached by many unsaved `_execute` bodies in a row (each is a new
search template); deployed monitors reuse cached scripts.

## Cleanup

No `[wcp-test]` monitor (config index count 0; guard check empty), no `wcp-test-*` index, no `wcp_`
user or role, no transient setting, cluster green, no machine lock, tunnel closed, lab configuration
`enabled: false`. The pack stays deployed (Windows spray `98f4090ad6dfc58f`, `plan` 0 changes).
