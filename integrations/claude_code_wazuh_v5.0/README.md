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

Wazuh 5.0 companion to `claude_code_wazuh_v4.14`, detecting the same Claude Code agent-misbehavior scenarios using the new Sigma-with-Wazuh-extensions rule format and YAML decoders. See that integration's README for the full architecture rationale (why a shipper script sits between the OTel Collector and Wazuh, and why `OTEL_LOG_TOOL_DETAILS=1` is mandatory, not optional).

### Prerequisites

* Everything listed in `claude_code_wazuh_v4.14`'s prerequisites (Claude Code CLI 2.1.304+, `CLAUDE_CODE_ENABLE_TELEMETRY=1`, `OTEL_LOG_TOOL_DETAILS=1`, an OTel Collector, Python 3).
* Wazuh manager 5.0.0-rc1 or later.

### Installation and Configuration

#### Installing Claude Code

```bash
npm install -g @anthropic-ai/claude-code
```

#### Initial Claude Code Configuration

Identical to `claude_code_wazuh_v4.14`: set the telemetry environment variables, run the OTel Collector with `scripts/otel-collector-config.yaml`, then run `scripts/otel_shipper.py --follow` between the Collector's file output and the file Wazuh's Logcollector reads.

#### Installing Wazuh (if applicable)

See the [Wazuh 5.0-rc Docker deployment guide](https://documentation.wazuh.com/5.0-rc/deployment-options/docker/wazuh-container.html).

#### Initial Wazuh Configuration (if applicable)

Add a `localfile` entry for the shipper's output path to the manager's log collection configuration so it is read as a JSON source.

#### Using the Integration Files

Author the decoder (`ruleset/decoders/decoder_claude-code_0.yml`) and the seven rules (`ruleset/rules/rule_997*.yml`) in the dashboard's Ruleset management, in the Draft space, then promote to Test to run them against the samples in `sample_logs.txt`.

### Integration Steps

1. Enable telemetry and `OTEL_LOG_TOOL_DETAILS=1` on every host running Claude Code.
2. Deploy the OTel Collector and the shipper script.
3. Add the decoder and rules through the dashboard's Draft space.
4. Promote to Test and validate against `sample_logs.txt` (see Integration Testing below).
5. Promote to Custom once validated.

### Integration Testing

This integration was live-tested against a running Wazuh 5.0-rc manager and dashboard, using the Claude-in-Chrome browser extension to reach the dashboard's local/private network address (the sandboxed built-in browser tool can reach the open internet but not `localhost` or private IPs, so Chrome was used instead). The decoder and all seven rules were authored in the dashboard's Draft space, promoted to Test space, then every entry in `sample_logs.txt` — the same 9 real, captured Claude Code telemetry samples used and verified in `claude_code_wazuh_v4.14`'s `wazuh-logtest` runs — was run through the dashboard's Ruleset management → Log test tool.

**Result: 9/9 samples produced the expected outcome**, matching `claude_code_wazuh_v4.14`'s expected-rule mapping exactly: each malicious-shaped sample fired its corresponding rule (997001-997007), the two-scenario sample correctly fired both 997001 and 997004 together, and benign samples fired no rule.

Two caveats, documented in full in `VERIFY.md`:

* Several `|re:` regex constructs (`\s`/`\b` shorthand classes, the `(?i)` flag, escaped `\.`, a whole-pattern-wrapping `(...)` group, and in some cases the literal `/` character) were empirically found to break matching in this Wazuh 5.0-rc engine build. All seven rules were rewritten to avoid these constructs (bracket character classes, no inline flags, unescaped dots, non-whole-pattern grouping).
* Rules **997006** (credential access) and **997007** (scope-escape write) were narrowed from their original scope after their broader intended patterns repeatedly failed to fire despite correct-looking live content: 997006 now matches only `id_rsa` (not `.ssh/`, `.aws/credentials`, `.kube/config`, `.npmrc`, `.git-credentials`, `id_ed25519`, or `.env`); 997007 now matches the bare segment `tmp` (not the slash-delimited `/tmp/`, `/etc/`, `/var/`, `/root/` originally scoped). This is a deliberate, documented reduction in coverage, not full coverage represented as complete — see `VERIFY.md`'s "Confirmed gap" entries for exactly what is and isn't covered.

### Sources

* https://documentation.wazuh.com/5.0-rc/user-manual/data-analysis/decoders.html
* https://documentation.wazuh.com/5.0-rc/user-manual/wazuh-indexer/wazuh-sigma-rules.html
* https://documentation.wazuh.com/5.0-rc/user-manual/data-analysis/detection-workflow.html
* https://code.claude.com/docs/en/monitoring-usage
* The `caddy_integration_wazuh_v5.0beta` integration in this fork, used as the structural template

## Provenance and Maintenance

* Original source, written from scratch against Claude Code's documented OTel telemetry schema and Wazuh 5.0-rc's documented decoder/rule DSL; no third party ruleset was adapted or copied.
* Adapted by, Anmol Vats (GitHub: NucleiAv)
* Tested versions, Wazuh 5.0.0-rc1 (decoder and all 7 rules live Log-test validated, 9/9 samples, per the section above), Claude Code CLI v2.1.304
* Maintainer, Anmol Vats (GitHub: NucleiAv)
* Support boundary, community maintained, provided as is
