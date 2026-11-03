# Claude Code-Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
    * [Installing Claude Code](#installing-claude-code)
    * [Initial Claude Code Configuration](#initial-claude-code-configuration)
    * [Installing Wazuh (if applicable)](#installing-wazuh-if-applicable)
    * [Initial Wazuh Configuration (if applicable)](#initial-wazuh-configuration-if-applicable)
    * [Using the Integration Files](#using-the-integration-files)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Sources](#sources)

### Introduction

Claude Code is Anthropic's agentic coding CLI. It can export structured OpenTelemetry (OTel) logs describing every tool call it makes (reads, writes, shell commands, MCP calls) and the permission decision behind each one. This integration detects an agent acting outside its intended scope on a host: bypassing its own permission system, tampering with its guardrail configuration, running destructive or download-and-execute shell commands, or touching credential files.

There was no Wazuh coverage for Claude Code's own telemetry anywhere before this integration.

### Prerequisites

* Claude Code CLI, version 2.1.304 or later (`permission_mode` on the `tool_decision` event requires 2.1.301+, per the official docs).
* `CLAUDE_CODE_ENABLE_TELEMETRY=1` and `OTEL_LOG_TOOL_DETAILS=1` set in the environment Claude Code runs in. **`OTEL_LOG_TOOL_DETAILS=1` is not optional for this integration** — without it, `tool_decision`/`tool_result` never carry the tool's actual arguments (file paths, shell commands), and every path-based rule in this ruleset (997003-997007) goes blind. This was verified empirically: the same `~/.ssh` read produced an identical event with and without the flag, except for the presence of `tool_input`/`tool_parameters`.
* An OpenTelemetry Collector (`otelcol-contrib`) able to receive OTLP/gRPC or OTLP/HTTP and export to a local file. Wazuh 4.x has no OTLP receiver of its own.
* Python 3 for the shipper script in `scripts/otel_shipper.py`.
* Wazuh manager 4.14.x (empirically validated against both 4.9.2 and 4.14.9 — see Integration Testing below).

### Installation and Configuration

#### Installing Claude Code

```bash
npm install -g @anthropic-ai/claude-code
```

#### Initial Claude Code Configuration

Set the telemetry environment variables wherever Claude Code runs (shell profile, systemd unit, or CI environment):

```bash
export CLAUDE_CODE_ENABLE_TELEMETRY=1
export OTEL_LOGS_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
export OTEL_EXPORTER_OTLP_PROTOCOL=grpc
export OTEL_LOG_TOOL_DETAILS=1
```

Run the OpenTelemetry Collector with the config in `scripts/otel-collector-config.yaml` (an OTLP receiver on 4317/4318, exporting to a local file):

```bash
docker run -d --name otel-collector-claude \
  -p 4317:4317 -p 4318:4318 \
  -v $(pwd)/scripts/otel-collector-config.yaml:/etc/otelcol-contrib/config.yaml \
  -v /var/log/otel:/var/log/otel \
  otel/opentelemetry-collector-contrib:latest
```

**The Collector's own output is not directly usable by Wazuh.** Claude Code's OTel SDK batches many log records (one per event: `tool_decision`, `tool_result`, `api_request`, ...) into a single export call, and the Collector's `file` exporter writes that whole batch as one JSON line per flush, with each event's attributes encoded as an OTLP array of `{"key", "value"}` pairs rather than plain `key: value` JSON. Verified directly against `wazuh-logtest`: feeding a raw Collector output line through `JSON_Decoder` produced exactly one opaque field holding the entire nested structure as Python-repr text, not usable for field-based rule matching, and one manager log line always corresponds to one Wazuh event, so a batched line could never become more than one alert regardless of decoder.

`scripts/otel_shipper.py` sits between the two: it reads the Collector's file output, splits every batched export into one flat JSON object per log record, and appends each as its own line to the file Wazuh actually reads. It also renames every attribute's literal dot to an underscore (`service.name` becomes `service_name`) — the Wazuh 5.0-rc decoder docs don't specify how to address a flat key that itself contains a dot, since their only documented dotted syntax is for real nesting, so this sidesteps that ambiguity for both Wazuh versions rather than relying on unconfirmed behavior. Run it continuously:

```bash
python3 scripts/otel_shipper.py /var/log/otel/claude-code-logs.jsonl /var/log/claude-code/events.jsonl --follow
```

#### Installing Wazuh (if applicable)

See the [official Wazuh installation guide](https://documentation.wazuh.com/current/installation-guide/index.html).

#### Initial Wazuh Configuration (if applicable)

Add a `localfile` block to `ossec.conf` pointing at the shipper's output file:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/claude-code/events.jsonl</location>
</localfile>
```

#### Using the Integration Files

Copy `ruleset/decoders/claude_code_decoders.xml` to `/var/ossec/etc/decoders/` and `ruleset/rules/claude_code_rules.xml` to `/var/ossec/etc/rules/`, then restart the manager.

### Integration Steps

1. Enable telemetry and `OTEL_LOG_TOOL_DETAILS=1` on every host running Claude Code.
2. Deploy the OTel Collector with `scripts/otel-collector-config.yaml`.
3. Run `scripts/otel_shipper.py --follow` as a persistent process (systemd unit or equivalent) between the Collector's output and Wazuh's `localfile` input.
4. Install the decoder and rules, restart the manager.
5. Confirm agent events are reaching the manager (`/var/ossec/logs/alerts/alerts.json`).

### Integration Testing

All 7 detection rules and the base parse rule were tested against **real telemetry captured from an actual Claude Code v2.1.304 session**, not fabricated — every line in `sample_logs.txt` and `claude_code.ini` is a real event emitted by the tool, run inside a sandboxed WSL environment. Each was verified individually with `wazuh-logtest`, and each malicious-shaped scenario was paired with a benign counter-example confirmed **not** to fire the scenario-specific rule (only the level-0 base rule).

This ruleset was validated against two real Wazuh manager versions, not just the directory's target version by assumption:

| File | Cases | Wazuh manager 4.9.2 | Wazuh manager 4.14.9 |
| --- | --- | --- | --- |
| `claude_code.ini` | 9 | All pass | All pass |

The 4.14.9 run was a second, independent `wazuh-logtest` pass against a real `wazuh/wazuh-manager:4.14.9` container (the current latest stable release as of this writing), not an assumption that 4.9.2-tested XML syntax carries forward unchanged. All 9 cases produced the exact expected rule ID and alert level on both manager versions.

Sample `wazuh-logtest` output for the bypass-permissions and download-and-execute cases:

```
**Phase 3: Completed filtering (rules).
	id: '997001'
	level: '12'
	description: 'Claude Code: tool call accepted under bypassPermissions mode (tool_use_id toolu_01FppnPARLv7z3vcqbcbLZFB)'
	groups: '['claude_code', 'ai_agent', 'guardrail_tampering']'
	mitre.id: '['T1562']'
	mitre.tactic: '['Defense Evasion']'
	mitre.technique: '['Impair Defenses']'
**Alert to be generated.
```

```
**Phase 3: Completed filtering (rules).
	id: '997004'
	level: '15'
	description: 'Claude Code: download-and-execute pattern (curl/wget piped to a shell) via Bash tool'
	groups: '['claude_code', 'ai_agent', 'execution', 'download_and_execute']'
	mitre.id: '['T1105']'
	mitre.tactic: '['Command and Control']'
	mitre.technique: '['Ingress Tool Transfer']'
**Alert to be generated.
```

Rule `997003` (destructive Bash command) was additionally verified in isolation with `permission_mode` forced back to `default`, since the only real captured sample of that scenario happened to also use `bypassPermissions` (both are independently true facts about that one event, and both rules correctly fire for it).

Sample `wazuh-logtest` output for the same bypass-permissions case, from the 4.14.9 confirmation run:

```
**Phase 3: Completed filtering (rules).
	id: '997001'
	level: '12'
	description: 'Claude Code: tool call accepted under bypassPermissions mode (tool_use_id toolu_01FppnPARLv7z3vcqbcbLZFB)'
	groups: '['claude_code', 'ai_agent', 'guardrail_tampering']'
	firedtimes: '1'
	mail: 'True'
```

Four blocking paths for disallowed tools were tested and only one produces a detectable event — see `VERIFY.md` for the other three, which are a confirmed gap, not an oversight.

### Sources

* https://code.claude.com/docs/en/monitoring-usage
* https://code.claude.com/docs/en/permission-modes.md
* https://code.claude.com/docs/en/managed-settings
* https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/exporter/fileexporter/README.md
* Real telemetry captured directly from Claude Code v2.1.304 in this project's own test sandbox (see `VERIFY.md`)

## Provenance and Maintenance

* Original source, written from scratch against Claude Code's documented OTel telemetry schema and empirically verified against real captured events; no third party ruleset was adapted or copied.
* Adapted by, Anmol Vats (GitHub: NucleiAv)
* Tested versions, Wazuh manager 4.9.2 and 4.14.9, Claude Code CLI v2.1.304, opentelemetry-collector-contrib v0.163.1
* Maintainer, Anmol Vats (GitHub: NucleiAv)
* Support boundary, community maintained, provided as is
