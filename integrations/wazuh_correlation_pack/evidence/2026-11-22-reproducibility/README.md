# Reproducibility check 2026-11-22 - frozen revision for RC2 validation

> **Sanitized publication copy.** Lab addresses, host names, the lab cluster id and workstation
> paths are replaced consistently; measurements, outcomes and monitor hashes are unchanged. Files
> named here but absent (superseded attempts, harness errors, intermediate records) are kept in
> the unpublished development archive. Revision ids are development-branch commits. See
> [../README.md](../README.md).

Offline check that the **committed** pack alone reproduces its unit tests and its expected
monitor outputs. No Wazuh or OpenSearch access, so it says nothing about platform behaviour
(5.0.0-rc1 evidence: `../2026-11-21-rc1/`, `../2026-11-22-rc1-105573d/`; 5.0.0-rc2: not tested).

## Frozen revision

| Item | Commit | Note |
|---|---|---|
| **Tested (frozen) commit** | `38ad481e2c522c5ba0d22423423d20702d8a946f` | feature scope frozen; this record is committed after it and changes nothing outside `evidence/` |
| Detection behaviour (rendered monitors) | `105573d1c1b086e3e05ff1c2d3aa98cc290617f2` | `expected/monitors/` last changed here; rendering at the frozen commit is identical |
| Detection code files last changed (`wcp/`, `rules/`, `correlations/`, `pack.yml`) | `497dccaa70a75ebea9211e86b930df815ff51a3b` | docstring only: one hunk in `wcp/identity.py` (an evidence file name); `git diff 105573d 38ad481 -- wcp rules correlations pack.yml` contains nothing else |
| Test harness last changed (`tests/`) | `38ad481e2c522c5ba0d22423423d20702d8a946f` | `tests/repro/check_clean_checkout.py` (added in 497dcca, LF comparison in 0513c72, temporary-directory removal in 38ad481). Logic of the other tests: `tests/unit` and `tests/api/test_monitor_execute.py` 105573d; `tests/api/test_lateness_scheduler.py` f3af740 (docstring changed in 497dcca); `tests/api/collect_platform_facts.py` f3af740; `tests/api/test_least_privilege.py` and `tests/e2e/` fce7a87; `tests/lab/` e1bd181 |

Earlier evidence keeps its attribution: `../2026-11-21-rc1/` = detection code 25e52cc, harness
committed in fce7a87; `../2026-11-22-rc1-105573d/` = detection code 105573d, harness f3af740.
Neither was re-run against the frozen commit; the frozen commit's detection behaviour is that of
105573d.

## Rendered monitors (frozen commit)

| Monitor | Content hash (pack marker) | SHA-256 of the committed `expected/monitors/<name>.monitor.json` (LF) | Rendered = expected |
|---|---|---|---|
| `wcp_ssh_bruteforce` | `007c0a436059d016` | `8f1cb5c74dba9be4505446ceeba79ba443d4c315f1201ba2d33e3c254599dad5` | yes |
| `wcp_ssh_password_spray` | `172cc43b9dfcc25c` | `5859c19cc5db8220a00de694f0e56177820f24294a39bb197adda3134cce379d` | yes |
| `wcp_windows_failed_logon_burst` | `d31fc5d758665c2e` | `4d4e0e28569639255c2b39777e4338a4e42c970741b3c7e42c6e29c37a9e5a4f` | yes |
| `wcp_windows_password_spray` | `0603b54f3c657714` | `555cff966a46881f28cf33a8a0d7d901b362617ef0d7d4de14f2d811b86b9f5f` | yes |

The content hash is the identifier `wcp plan` and `wcp status` compare. The SHA-256 is of the LF
form, which is what git stores (`git show <commit>:<path> | sha256sum`); a Windows checkout with
`core.autocrlf=true` has CRLF files with other byte hashes (the check records `checkout_eol`).

The RC1 reference server still runs the four monitors applied from 25e52cc (Windows spray
`409a902d80326aad`); it was not changed.

## How it ran

```
python tests/repro/check_clean_checkout.py --commit HEAD --out <dir>     # HEAD = 38ad481
```

* `git clone --no-local` of the repository into a new temporary directory, commit checked out
  detached (only committed files);
* a new virtual environment with only `requirements.txt` installed: pip 24.0, PyYAML 6.0.4
  (requirement `PyYAML>=5.4`); Python 3.12.3 on Windows 11;
* the clone's own copy of the script run with `-E -s -B`, working directory = the clone's pack
  directory, an **empty temporary home directory** (so no `indexer.env`, CA file or deployment
  manifest can be found) and no `WCP_*`/`PYTHON*` variables;
* the temporary directory was removed afterwards (check `temp_dir_removed`; before 38ad481 the
  script left it behind on Windows, see the runs below).

## Results (`clean_checkout.json`): PASS, 16/16 checks

| Check | Result |
|---|---|
| Unit tests in the clean checkout | 49/49 pass |
| Every `wcp` and test module loaded from the clone; none from the source checkout; `sys.path` free of it; `python -m wcp` imports the clone | pass |
| `wcp validate` | 2 base rules, 4 correlations valid |
| `wcp render` identical to `expected/monitors/` (4 files, LF form); pack-marker hash = computed content hash | pass |
| All 25 Python files of the pack compile | pass |
| Documentation references to pack paths resolve to tracked files | pass |
| No tracked file named like a credential or deployment state (`*.env`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*manifest.json`, `state/`) | pass (111 tracked pack files) |
| The source checkout has no untracked or ignored files in the pack (nothing that exists locally but not in git) | pass |
| The run wrote nothing into the clone or the home directory; the temporary directory was removed | pass |

Additional checks in the same session, not part of the script:

* the indexer password configured for the RC1 tests occurs in no tracked pack file and nowhere
  in the branch history since the upstream base (value compared in-process, never printed);
* the result files contain no absolute local path, user name or server address.

## All runs of the check (same day)

| Commit | Result | Note |
|---|---|---|
| `2c560e2` | PASS | ad-hoc version of the same steps (before the check was committed): 49/49, 4/4 monitors identical |
| `497dcca` | FAIL (1 check) | README named a file of the wazuh/wazuh repository by its path there; reworded in `4c22f00` |
| `4c22f00` | PASS | |
| `02e3b82` | PASS | result kept as `clean_checkout.02e3b82.json`; its file hashes were of a CRLF checkout (platform-dependent), fixed in the check in `0513c72` |
| `0513c72` | FAIL (1 check) | the first version of this record contained a foreign repository path; reworded in `3fcee4c` |
| `3fcee4c` | PASS (15/15) | recorded in `43fd9bd` as the frozen revision; result kept as `clean_checkout.3fcee4c.json`. That record said the temporary directory was deleted - it was not: on Windows the clone's read-only git object files were skipped silently by `rmtree(..., ignore_errors=True)`. The six leftover directories of all runs so far (the check's own clones) were deleted by hand; fixed and checked in `38ad481` |
| **`38ad481`** | **PASS (16/16)** | **frozen revision**, `clean_checkout.json` |

## Notes

* A Windows checkout of this repository always shows `integrations/Technitium_DNS/README.md` as
  modified: upstream tracks `integrations/Technitium_DNS/README.md`,
  `integrations/technitium_dns/README.md` and `integrations/technitium_dns/readme.md`, which
  map to one file on a case-insensitive file system. Unrelated to this pack; not changed.
* The repository root `.gitignore` ignores `test*`; the pack's own `.gitignore` re-includes it
  (`tests/repro/` is tracked, verified by the clean checkout).
