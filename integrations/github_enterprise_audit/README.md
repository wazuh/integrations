# GitHub Enterprise audit log (GHE.com and enterprise endpoint)

The built-in Wazuh GitHub module only queries `https://api.github.com/orgs/{org}/audit-log`. The API host is not configurable and the enterprise endpoint is not supported, so it cannot collect from GitHub Enterprise Cloud with data residency (`api.<subdomain>.ghe.com`) or from `/enterprises/{enterprise}/audit-log`.

`github_audit_wodle.py` fills that gap. It runs on a Wazuh agent as a command wodle, polls the audit log API, and writes each event to the agent's local queue socket in the same format the native module uses:

```
1:github:{"integration":"github","github":{ ...original audit event... }}
```

Rule 91100 matches any JSON event with `integration: github`, so the whole stock ruleset (`0750-github_rules.xml`, rules 91100-91449) applies unchanged. No custom decoders or rules are needed.

## Features

- GitHub.com or GHE.com, enterprise or organization audit log.
- `include` of `web`, `git` or `all`.
- Bookmark in a state file, with an overlap window and `_document_id` de-duplication, so restarts and late-indexed events neither duplicate nor drop events.
- Honours `Retry-After` and `X-RateLimit-*` headers, retries 5xx and network errors.
- Per-run budget (`max_runtime`, `max_events`); unfinished windows resume on the next run.
- Throttled to `max_eps`, like the native module's `wazuh_modules.max_eps`.
- After 3 consecutive failed runs it sends the native module's internal failure event (rule 91448), then repeats every 12 further failures.
- Events over 60000 bytes are reduced to their essential fields and flagged `wazuh_truncated: true`.
- Python 3.6+ standard library only.

## Requirements

- A Wazuh agent (or manager) host with outbound HTTPS to the GitHub API.
- A token from an enterprise owner (classic PAT with `read:audit_log`) or an organization owner for the org endpoint.

## Installation

On the agent, as root:

```bash
mkdir -p /var/ossec/wodles/github-audit
cp github_audit_wodle.py /var/ossec/wodles/github-audit/
chmod 750 /var/ossec/wodles/github-audit/github_audit_wodle.py
( umask 077; printf '%s' '<TOKEN>' > /var/ossec/wodles/github-audit/token )
chown -R root:wazuh /var/ossec/wodles/github-audit
```

Edit the `CONFIG` block at the top of the script (`api_url`, `enterprise` or `org`, `include`), or pass the same settings as command-line options (`--help` lists them).

Validate the connection without sending anything to Wazuh:

```bash
python3 /var/ossec/wodles/github-audit/github_audit_wodle.py --dry-run \
    --initial-lookback 60 --log-stderr --state-file /tmp/github-test.json
```

Add the wodle to the agent's `ossec.conf` and restart the agent:

```xml
<ossec_config>
  <wodle name="command">
    <disabled>no</disabled>
    <tag>github-audit</tag>
    <command>/usr/bin/python3 /var/ossec/wodles/github-audit/github_audit_wodle.py</command>
    <interval>5m</interval>
    <run_on_start>yes</run_on_start>
    <timeout>300</timeout>
    <ignore_output>yes</ignore_output>
  </wodle>
</ossec_config>
```

Keep `max_runtime` (default 240 s) below the wodle `<timeout>`. The script prints nothing to stdout during normal runs, so `ignore_output` can stay `yes`.

To push this from a centralized agent group (`agent.conf`) instead, the agent must allow remote commands: add `wazuh_command.remote_commands=1` to its `/var/ossec/etc/local_internal_options.conf` and restart it.

## Configuration notes

| Setting | Default | Notes |
|---|---|---|
| `initial_lookback` | 0 | Minutes fetched on the first run. 0 starts from now. |
| `delay` | 60 | Seconds behind now each window ends (audit log indexing lag). |
| `overlap` | 600 | Seconds re-read before the bookmark; repeats are de-duplicated. Raise it if events reach the API later than this. |
| `max_eps` | 100 | Keep at or below the agent's `<client_buffer>` `events_per_second`. |
| `max_runtime` / `max_events` | 240 / 20000 | Per-run limits; the rest is collected on the next run. |

The script logs to `/var/ossec/logs/github_audit_wodle.log` (rotated at 5 MB, 3 backups) and keeps its bookmark in `/var/ossec/wodles/github-audit/state.json`. Delete the state file to start over.

The state file holds the IDs of events inside the overlap window. With `include=all` on a very busy enterprise this can reach tens of thousands of entries; shorten `overlap` if it grows too large.

## Testing

`mock_ghe_api.py` is a stdlib mock of the enterprise audit log endpoint (cursor pagination, `created:` range and `include` filters, live events with indexing lag, and injected 429 / 403 rate-limit / 500 / oversized-event faults). Token is `test-token`.

```bash
python3 mock_ghe_api.py --port 8765 --backfill 250 --live-every 2 --faults 429,500,403rl &
GITHUB_TOKEN=test-token python3 github_audit_wodle.py --api-url http://127.0.0.1:8765 \
    --enterprise example --dry-run --initial-lookback 60 --log-stderr --state-file /tmp/gh-state.json
```

Verified against the mock and a Wazuh 4.14.5 manager running the script as a command wodle:

- Rate-limit and 5xx responses are retried and the run completes.
- `include` filters return only web, only git, or both.
- 30 budget-limited runs with live, late-indexed events sent 538 events with no duplicates and no losses.
- Alerts arrive with `location: github` and the stock rules fire (91158, 91160, 91190, 91232, 91277, 91318, 91320), with no duplicate alerts across overlapping runs.
- Three runs with a bad token raise rule 91448; the next good run resets the failure counter.
- A 70 KB event is truncated and still matches its rule.
- A concurrent run is skipped by the lock; a corrupt state file or missing token is reported.

Not yet verified against a real GHE.com tenant.
