# Expected monitor outputs

`monitors/<correlation>.monitor.json` is the exact Alerting monitor body that `python -m wcp
render` produces for the shipped `rules/`, `correlations/` and `pack.yml`.
`tests/unit/test_identity.py::TestExpectedMonitors` fails when the rendering changes, so every
change to detection output is visible in review.

When detection code or content changes on purpose:

```bash
python -m wcp render --out expected/monitors
python -m unittest discover -s tests/unit
```

and record the change below.

| Correlation | Content hash | Since |
|---|---|---|
| `wcp_ssh_bruteforce` | `007c0a436059d016` | 25e52cc (unchanged) |
| `wcp_ssh_password_spray` | `172cc43b9dfcc25c` | 25e52cc (unchanged) |
| `wcp_windows_failed_logon_burst` | `d31fc5d758665c2e` | 25e52cc (unchanged) |
| `wcp_windows_password_spray` | `98f4090ad6dfc58f` | unknown-realm counting (an account seen with and without an explicit target domain counts once; see the commit that changes this line); was `4564e84945edcf3a` (realm only from `user.target.domain`, d090875), `0603b54f3c657714` (105573d) and `409a902d80326aad` (25e52cc) |

The monitors deployed on the 5.0.0-rc1 test server were applied from 25e52cc (Windows spray
hash `409a902d80326aad`) and were deliberately not updated. The other three monitors are
byte-identical in 25e52cc, 105573d and the identity fix (LF SHA-256 recorded in
`evidence/2026-11-22-reproducibility/` and the candidate records).
