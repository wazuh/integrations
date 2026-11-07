# Agentmetry-Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
    * [Installing Agentmetry](#installing-agentmetry)
    * [Initial Agentmetry Configuration](#initial-agentmetry-configuration)
    * [Installing Wazuh (if applicable)](#installing-wazuh-if-applicable)
    * [Initial Wazuh Configuration (if applicable)](#initial-wazuh-configuration-if-applicable)
    * [Using the Integration Files](#using-the-integration-files)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Limitations](#limitations)
* [Provenance and Maintenance](#provenance-and-maintenance)
* [Sources](#sources)

### Introduction

[Agentmetry](https://github.com/blitzcrieg1/agentmetry) is an Apache-2.0 sensor for AI coding agents. It records the tool calls agents report through their hooks, plus calls to MCP servers wrapped by its proxy, in a hash-chained local trail. It then correlates sequences into detections mapped to MITRE ATT&CK, such as a credential read followed by network egress in the same session.

This integration reads that trail with a Wazuh `localfile` and raises alerts on the detection events. It sits beside `claude_code_wazuh_v4.14`, which uses Claude Code's OpenTelemetry output. The difference is coverage of other agents, no collector, and detections correlated across a session. On file paths, the Claude Code integration sees more when `OTEL_LOG_TOOL_DETAILS=1` is set, because Agentmetry hashes tool arguments by default.

### Prerequisites

* Agentmetry 0.10.6 or later on each machine running coding agents.
* A Wazuh agent on those machines, or a manager that can read the trail file directly.
* Wazuh manager 4.14.x. See [Integration Testing](#integration-testing) for what was tested.

### Installation and Configuration

#### Installing Agentmetry

```bash
pip install agentmetry
agentmetry hooks install
agentmetry start
```

#### Initial Agentmetry Configuration

No special configuration is needed. The trail is `audit-forward.jsonl` in the Agentmetry data directory, unless `AGENTMETRY_AUDIT_EXPORT_PATH` names another file.

#### Installing Wazuh (if applicable)

See the [official Wazuh installation guide](https://documentation.wazuh.com/current/installation-guide/index.html).

#### Initial Wazuh Configuration (if applicable)

Add a `localfile` block to `ossec.conf` on the machine that holds the trail, using its full path:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/path/to/audit-forward.jsonl</location>
</localfile>
```

#### Using the Integration Files

Copy `ruleset/rules/agentmetry_rules.xml` to `/var/ossec/etc/rules/` on the manager, then restart it. No custom decoder is needed, because Wazuh's built-in JSON decoder handles trail lines:

```bash
systemctl restart wazuh-manager
```

### Integration Steps

1. An agent makes tool calls, and its hook reports them to the local recorder.
2. The recorder appends each event to the trail as one line: `{"trail":{...},"event":{...}}`.
3. When a sequence matches, the recorder appends a detection event to the same trail.
4. Wazuh reads the file, and its built-in JSON decoder decodes each line, so fields appear under `trail.` and `event.`.
5. `agentmetry_rules.xml` alerts on detection events. Other trail records match rule 997600 at level 0 and raise no alert.

| Rule IDs | Matches | Level |
| --- | --- | --- |
| 997600 | Any trail record | 0 |
| 997601 | Any detection event | 0 |
| 997602, 997610-997616 | Critical detections | 15 |
| 997603, 997617-997621 | High detections | 12 |
| 997604, 997622 | Medium detections | 7 |
| 997605, 997623 | Low detections | 4 |

997602 to 997605 catch any detection by severity, including rules Agentmetry adds later or an operator writes. The specific rules add a description and a MITRE mapping.

### Integration Testing

Tested on 2026-11-07 against a real `wazuh/wazuh-manager:4.14.9` container (`wazuh-control info` reports v4.14.9), with Agentmetry 0.10.6 from PyPI.

`scripts/capture_and_test.sh` runs the whole test in a throwaway environment. It starts a scratch recorder, replays the 26 scripted attack sessions that ship with Agentmetry through its real ingest route, and verifies the trail's hash chain (140 chained lines, all verified). It then runs each case in `agentmetry.ini` through `wazuh-logtest`, and appends `sample_logs.txt` to a file the manager watches through a `localfile` block.

| Check | Result |
| --- | --- |
| `agentmetry.ini` through `wazuh-logtest` | 15 of 15 pass on rule, level and decoder |
| Live `localfile` path into `alerts.json` | 14 of 14 detection samples alerted, one alert per rule, 997610 to 997623 |
| Tool call activity sample | Matches 997600 at level 0, no alert |

The script turns off the manager's vulnerability scanner, because its content download filled a 32 GB disk. These tests do not use it.

Sample `wazuh-logtest` result for a `credential-exfil` line: decoder `json`, rule `997611`, level `15`.

To check by hand:

```bash
/var/ossec/bin/wazuh-logtest
```

Paste a line from `sample_logs.txt`.

### Limitations

* **What the samples are.** Every line in `sample_logs.txt` was written and hash-chained by a real recorder, but the sessions are Agentmetry's scripted attack cases, not a live agent session.
* **Plaintext in one sample.** The activity sample holds the scripted command `cat ~/.ssh/id_rsa`, because the corpus replays with its command. A default install stores a hash instead.
* **Severity fallback.** 997602 to 997605 sit on the path of every tested detection, but no captured sample stops at one of them, because each has a specific rule.
* **Detections only.** This version raises no alerts on individual tool calls. Arguments are hashed by default, so rules on commands or file paths would not match a default install.
* **Rules not captured.** `host-subagent-swarm-burst` and `off-hours-activity` have no captured sample, so they have no specific rule here. They alert by severity with no MITRE mapping.
* **What Agentmetry cannot see.** It sees what agents report through their hooks. A disabled hook, or activity outside the hooks, is not recorded.
* **Tamper evidence stays in the trail.** Wazuh does not check the hash chain. Use `agentmetry verify --trail <path>` for that.
* **Agents.** The live test had the manager read the file itself. A Wazuh agent reading a trail on a developer machine, on any operating system, has not been tested.
* **Wazuh 5.0.** This package targets 4.14. Wazuh 5.0 needs a separately tested package.

### Provenance and Maintenance

* **Original source:** written for this repository, following the layout of `claude_code_wazuh_v4.14`. The MITRE mappings come from the `technique_ids` on Agentmetry's detection events.
* **Adapted by:** not adapted from another integration.
* **Tested versions:** Wazuh manager 4.14.9, Agentmetry 0.10.6.
* **Maintainer:** [blitzcrieg1](https://github.com/blitzcrieg1), the Agentmetry maintainer.
* **Support boundary:** community-maintained. Report problems at [blitzcrieg1/agentmetry](https://github.com/blitzcrieg1/agentmetry/issues). The fields these rules read are listed in Agentmetry's [event schema](https://github.com/blitzcrieg1/agentmetry/blob/master/docs/agentmetry-event-schema.md).

### Sources

* [Agentmetry](https://github.com/blitzcrieg1/agentmetry)
* [Agentmetry event schema](https://github.com/blitzcrieg1/agentmetry/blob/master/docs/agentmetry-event-schema.md)
* [Wazuh JSON decoder](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html)
* [Discussion that agreed this package](https://github.com/wazuh/wazuh/discussions/41217)
