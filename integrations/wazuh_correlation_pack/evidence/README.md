# Evidence (sanitized publication selection)

This directory holds the recorded test runs behind the results in the [README](../README.md). It is a
**sanitized selection** made for publication. The complete archive stays on the unpublished
development branch: every superseded attempt, harness failure or error, and intermediate
clean-checkout record. Measurements, outcomes, timings, scores and monitor content hashes are
unchanged.

## Runs

| Directory | Wazuh | Code that ran (development revisions) | Status |
|---|---|---|---|
| [2026-11-23-rc2-mixed-realm/](2026-11-23-rc2-mixed-realm/README.md) | 5.0.0-rc2 | detection 6ee2300; harness 3868f23, b9dc276, 8ce737c | **current**: Windows spray paths; includes the failing run before the fix |
| [2026-11-22-rc2-candidate/](2026-11-22-rc2-candidate/README.md) | 5.0.0-rc2 | 706c689, 5c1da90 (detection d090875) | **current** for every test except the Windows spray paths |
| [2026-11-22-rc2/](2026-11-22-rc2/README.md) | 5.0.0-rc2 | 38ad481 and harness revisions | historical: first RC2 run; detection defect (P1 FAIL), fixed since |
| [2026-11-22-rc1-105573d/](2026-11-22-rc1-105573d/README.md) | 5.0.0-rc1 | 105573d | historical |
| [2026-11-21-rc1/](2026-11-21-rc1/README.md) | 5.0.0-rc1 | 25e52cc (tests fce7a87) | historical |
| [2026-11-22-reproducibility/](2026-11-22-reproducibility/README.md) | none (offline) | 38ad481 | historical: freeze record |

The current Windows identity and counting rules were not tested on 5.0.0-rc1. No run executed the
publication commit itself. That commit's own checks are offline: unit tests, harness self-tests and
the clean-checkout check. Its record is
[2026-11-23-publication/clean-checkout-f0edcc5/clean_checkout.json](2026-11-23-publication/clean-checkout-f0edcc5/clean_checkout.json)
(PASS 18/18 on the snapshot commit f0edcc5). The check covers 68 unit tests and 48 harness self-tests, and checks
that rendered monitors equal `expected/` and that documentation references resolve.

## Provenance of the contributed files

Revision ids above are commits of the development branch, which is not part of this contribution.
The contribution is one snapshot of that branch's final revision (`0d52aaf`), with the publication
edits listed below. Git tree and blob ids were compared per path:

| Path | Identical to development revision(s) |
|---|---|
| `rules/`, `correlations/`, `pack.yml`, `requirements.txt`, `NOTICE` | 6ee2300 (last detection change), 8ce737c, 0d52aaf |
| `wcp/` except `wcp/identity.py` | 6ee2300, 8ce737c, 0d52aaf |
| `wcp/identity.py` | Code identical to 6ee2300, 8ce737c and 0d52aaf. Only the module docstring was corrected for publication, to describe the counting as conservative and to limit the over-counting fix to the demonstrated case. Blob `81ada41f8d28` (tested) became `3aa371d6e9cb` (published). The parsed code with docstrings removed is identical, and the rendered monitors are unchanged. |
| `expected/` (rendered monitors and their content hashes) | 6ee2300, 8ce737c, 0d52aaf |
| `samples/` | 6ee2300, 8ce737c, 0d52aaf |
| `tests/` | 8ce737c (last harness change; ran P1 of the current run), 0d52aaf |
| `docs/` | 0d52aaf (documentation only since 8ce737c) |
| `README.md` | rewritten in plain English for publication from the 0d52aaf version; it adds the contributor names and keeps the same facts, results and limitations |
| `evidence/` | this sanitized selection of 0d52aaf |

Rendered monitors (`python -m wcp render`) equal `expected/monitors/`:

| Monitor | Content hash |
|---|---|
| `wcp_ssh_bruteforce` | `007c0a436059d016` |
| `wcp_ssh_password_spray` | `172cc43b9dfcc25c` |
| `wcp_windows_failed_logon_burst` | `d31fc5d758665c2e` |
| `wcp_windows_password_spray` | `98f4090ad6dfc58f` |

## Sanitization

Each replacement is applied consistently across all published files. Equal values stay equal and
different values stay different, so same/different accounts, domains, sources and endpoints read as
in the original.

| Original | Published as | Relationships kept |
|---|---|---|
| Lab subnet (a private /24) | `10.10.0.0/24`, last octet kept | `.1` workstation (live SSH client, as seen by the endpoint); `.130` RC2 server; `.131` RC1 server; `.132` Linux endpoint (both Linux roles); `.155` then `.134` Windows endpoint (the same VM before and after a DHCP change). Private addresses stay private, which matters for the Notifications deny list |
| Windows lab computer name | `WCP-WIN-RC2`; as a realm label `wcp-win-rc2` | the `.` realm maps to this computer label |
| Linux lab endpoint host name | `lab-linux-1` | host name in replayed and live sshd lines |
| RC2 lab cluster id (`cluster_uuid`) | `RC2-LAB-CLUSTER-UUID` | the manifest binding to that cluster |
| Workstation profile directory in paths | `C:\Users\user` (8.3 form `USER~1`) | none |
| Lab login accounts | `<access-account>` (the harness replaces them when it saves a capture) | never test targets |

Not replaced, because the values are needed to interpret the results or are not lab-specific:
- loopback `127.0.0.1` and the private CIDRs of the Notifications deny list;
- documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`);
- the RC1 container bridge `10.231.40.0/24`, which is defined by the lab recipe in
  [tests/lab/README.md](../tests/lab/README.md);
- test accounts (`wcpt-*`) and synthetic domains (`CONTOSO`, `FABRIKAM`, `wcpotherdom`);
- SIDs, which were already sanitized at capture;
- `Administrator` in the public DeepBlueCLI sample, where it is the attacked account and not a lab
  login;
- monitor ids, timestamps, scores and hashes.

SHA-256 values recorded inside evidence files were computed on the original files. Examples are the
manifest digests in `deployment_state_audit.json` and the file hashes in clean-checkout records.

## Reproducing

- [docs/TESTING.md](../docs/TESTING.md): test layers and how to run them.
- [docs/VALIDATION_TESTS.md](../docs/VALIDATION_TESTS.md): the RC2 validation tests P1-P6.
- [tests/lab/README.md](../tests/lab/README.md): lab setup.
- [tests/repro/check_clean_checkout.py](../tests/repro/check_clean_checkout.py): offline clean-checkout check.

Fixtures and samples are in `tests/` and `samples/`.
