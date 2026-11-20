# Recorded engine answers

Real answers of the Wazuh 5.x engine API on its unix socket, used by `test_verify_offline.py` to replay
`verify --engine-socket`. Recorded on 2026-11-16 against the engine of a 5.0.0 nightly manager (`VERSION.json`: 5.0.0, stage rc3, commit `49f301e`),
socket `/var/wazuh-manager/queue/sockets/engine-api-http.sock`. The standalone engine package serves the same API.

Each file: `{"engine", "request": {"method", "path", "payload"}, "http", "raw"}`. `raw` is the body as the engine
sent it. The space name of the recording is shown as `rmig_contract` in requests and answers alike; nothing else
was changed.
In the requests, `full_policy` is a placeholder text: the recorder did not keep the policy body.

| File | Call | Answer |
|---|---|---|
| `status.json` | `GET /status` | 200, `ready: false`, `ioc.*.available: false` |
| `validate-load-migrated.json` | `POST /content/validate/policy`, `load_in_tester: true` | 200 `{"status":"OK"}` |
| `validate-load-unmigrated.json` | same, content with old helper names | 400, `Operation builder 'kvdb_get' not found` |
| `validate-bad-space.json` | same, space `bad-space` | 400, invalid characters |
| `logtest-notrace.json` | `POST /logtest`, `trace_level: NONE` | 200, `result.output` (an auditd event) |
| `logtest-no-session.json` | `POST /logtest` on a space never loaded | 400, environment does not exist |
| `delete.json` | `DELETE /logtest` | 200 `{"status":"OK"}` |

Composed answers. To run the migrated rules, the fake engine of the tests answers `POST /logtest` with the envelope
of `logtest-notrace.json` (`status`, `result.asset_traces`, `result.validation`) and puts the test's own normalized
event in `result.output`. The envelope is recorded; the event is test data.
