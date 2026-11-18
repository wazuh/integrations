# Java4Shell Exposure-Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Sources](#sources)

### Introduction

Turn runtime inventory for CVE-2026-114938 into patch-priority alerts and evidence gaps. The integration takes an explicit vendor verdict for the running JVM build, CPU capability as seen by the workload, and effective mitigation state. It makes no network requests and touches no JVM process.

### Prerequisites

- A Wazuh 4.x manager and connected Linux agent.
- Python 3 on the inventory host and on the machine running the replay.
- A trusted workload inventory source and access to the runtime vendor's advisory. Restrict write access to the assessment log to the trusted producer.

### Installation and Configuration

Copy `ruleset/rules/java4shell_rules.xml` to `/var/ossec/etc/rules/` on the manager. Check that rule IDs 112938–112940 are available in the deployed ruleset. Validate the manager configuration with `/var/ossec/bin/wazuh-analysisd -t` and restart `wazuh-manager`.

Create `/var/log/java4shell-assessments.jsonl` with restricted write permissions and read access for the agent's Logcollector. Add this block inside `<ossec_config>` in the agent's `ossec.conf` and restart `wazuh-agent`.

```xml
<localfile>
  <location>/var/log/java4shell-assessments.jsonl</location>
  <log_format>json</log_format>
</localfile>
```

### Integration Steps

1. Identify the Java process serving each workload. Verify the live vendor and build through trusted runtime telemetry or, where supported and permitted, `jcmd PID VM.version`. A host package upgrade still needs a process restart or workload rollout. For containers, check the live workload as well as the replacement image.
2. Assign `vendor_status` according to the vendor advisory for the exact build. Use `affected`, `fixed`, `unaffected`, or `unknown`. Vendor backports and product-specific builds can differ even when their Java feature versions match.
3. Check the architecture and effective CPU flags in the workload's execution environment. On Linux, check for the exact `avx512vbmi` token in the CPU flags and verify x86-64. Use `present` when both prerequisites are verified, `absent` when either is ruled out, and `unknown` when visibility is incomplete.
4. Check whether the running JVM has an effective advisory-listed workaround, for example via `jcmd PID VM.flags -all` on a supported HotSpot JVM with attach permissions. On applicable builds, verify that `UseBASE64Intrinsics` is false or AVX-512 has been disabled as described by the vendor. Supply `present`, `absent`, or `unknown`. An edited service definition awaiting restart counts only after the running process is checked.
5. Emit one event per workload observed. Use a stable workload identifier, the running vendor and build in `--runtime`, and send assessments when the state changes to avoid repeat alerts. All three states default to `unknown`.

Example using synthetic inventory. Append the output to the agent's configured assessment file when replaying it on a test agent.

```sh
python3 assess.py --workload synthetic-api --runtime 'Fixture JVM' \
  --vendor-status affected --cpu-path present --mitigation absent
```

| Rule | Level | Meaning |
| --- | --- | --- |
| 112939 | 8 | Vendor reports an affected build, CPU prerequisites are present, and the workaround is absent |
| 112940 | 5 | Evidence is incomplete and no verified exclusion is recorded |
| 112938 | 0 | Assessment envelope |

Look up `rule.id:112939` and `rule.id:112940` in the Wazuh dashboard or in the manager's `/var/ossec/logs/alerts/alerts.json`. Use the workload identifier to route the finding. Keep the original inventory for remediation tracking because resolved assessments are silent.

Patch priority describes runtime conditions. Actual exposure also depends on whether requests can reach a code path that decodes untrusted input. The rules consume declared observations and cannot independently verify the vendor verdict, runtime flags, inventory coverage, or application reachability. Use fresh observations after patching and restarting. An endpoint that reports nothing has no assessment.

### Integration Testing

On a lab manager with these rules loaded, run `python3 tests/replay.py` with permission to invoke Logtest. It checks the JSON decoder, rule IDs, levels, and whether Wazuh would generate an alert. The fixtures cover an affected build, fixed and unaffected builds, a CPU without the required path, verified mitigation, and missing evidence. All records are synthetic.

### Sources

- [Red Hat product security bulletin](https://access.redhat.com/security/vulnerabilities/RHSB-2026-018)
- [Oracle November 2026 security patch update](https://www.oracle.com/security-alerts/cspunov2026.html#AppendixJAVA)
- [Wazuh Logcollector configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)

**Provenance and maintenance**

- Original source and adaptation — original integration by SAMsploit1 based on the vendor guidance above.
- Tested versions — Wazuh 4.14.10 manager (internal revision rc2), [9/9 synthetic Logtest cases](tests/results-wazuh-4.14.10.txt). Live agent ingestion and runtime collection remain unverified.
- Maintainer and support — SAMsploit1, community-maintained through the Wazuh Integrations repository.
