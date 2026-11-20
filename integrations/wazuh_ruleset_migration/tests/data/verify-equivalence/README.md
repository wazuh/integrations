# Recorded indexer verdicts (equivalence contract of the local Sigma reader)

`verify --engine-socket` gives rule verdicts with the tool's own Sigma reader (`rmig/verify/sigma.py`, `verdict`).
These records are the contract it must meet: the normalized event the server saw, and the server's answer.

Source: `rmig verify` (indexer mode) runs against a Wazuh 5.0.0 rc1 test indexer, 2026-11-18 and 2026-11-19.
Per dataset, `verification.json` is the run's file and `rules/<integration>/<4.x id>.json` are the
rules of the same run's `out/` (only the integrations with replayed events).

| Dir | Run | What it shows |
|---|---|---|
| `acmepay` | `examples/acmepay`, own decoders and an on-stock rule (2026-11-18) | 4 of 5 reproduced; 100300 (`cidr` filter) not reproduced; 100202 silenced |
| `acmepay-broken-root` | `examples/acmepay` under a draft whose root took no event (2026-11-19) | negatives: every event reached `wazuh-core` only, no rule matched |
| `acmepay-ioc` | `examples/acmepay` with the IoC feed option (2026-11-19) | 100205 on `wazuh.threat.enrichments.indicator.type`: no match |

What is verbatim: every rule file, and in `verification.json` every value but local paths. The JSON was re-indented
(sorted keys) and the local paths in `alerts`, `samples_dir` and `events[].source` were cut to `<local>/<dir>/<file>`.

Two contracts per dataset (`test_verify_offline.py`):

1. Per event with a `normalized` document: the reader's verdict on the rule's `detection` equals `matched`.
2. Per rule: the other rules of the same integration that match its events locally equal `shadowing` (the server
   listed every rule of the integration that matched).

Silencer events (`fired`, no `normalized`) are not usable: the record has no normalized event.
