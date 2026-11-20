# rmig: guide for agents

`rmig` migrates custom Wazuh 4.14 content (rules, decoders, CDB lists) to Wazuh 5.x content and loads it into a
Wazuh indexer. The manual is [README.md](README.md); details are in [docs/reference.md](docs/reference.md).

## Running it

| Phase | Commands | Changes anything live |
|---|---|---|
| Offline | `scan`, `plan`, `build` (or `migrate`), `stats` | no |
| Load and test | `apply`, `verify` | draft and test spaces only |
| Go live | `activate --yes` | custom space and detectors |
| Undo | `rollback`, `rollback --yes` | yes |

Rules:

- Never run `activate --yes` or `rollback --yes` without the user's explicit go: both change what the manager runs.
- Never answer a `DECISION` yourself: put each question of `decisions.json` to the user.
- Never edit `out/` by hand: change `decisions.json` and rebuild.
- Never pass `--force`, `--include-foreign-changes` or `--insecure` without saying what they do and getting a go.
- Credentials come from the environment or `--credentials-file`. Never put them on the command line or in a file
  you commit.
- Exit codes: 0 done, 1 done with items waiting, 2 usage error or a protective stop (`RM-P-*`).

## Changing the code

- Python 3.9, standard library only. No new dependency.
- Check a change offline with steps 1 and 2 of the README example on `examples/acmepay/`: the counts must not change
  unless the change means them to.
- No 4.x ruleset data in the tree: the stock index is built at run time from `--stock-dir`.
- Do not invent an indexer or engine request or response shape: follow what a real 5.x indexer and engine answer.
- After a change to a reason code: `python3 scripts/gen_reason_codes_doc.py`, then `--check` must pass.
- A value read from the input never becomes a path, a URL part or report text without `translate/meta.slug`,
  `textsafe.md` or `textsafe.plain`. A value of `ossec.conf` goes through `parse/ossec_conf.mask_value`.
