# Flowtriq-Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
    * [Configuring Flowtriq Syslog/CEF Output](#configuring-flowtriq-syslogcef-output)
    * [Using the Integration Files](#using-the-integration-files)
* [Integration Testing](#integration-testing)
* [Rule Reference](#rule-reference)
* [Sources](#sources)

---

### Introduction

This integration enables Wazuh to parse and generate alerts from [Flowtriq](https://flowtriq.com) DDoS detection events. Flowtriq monitors network traffic via NetFlow/sFlow and detects volumetric DDoS attacks. When an attack is detected or resolved, Flowtriq sends a syslog message in CEF (Common Event Format) to the Wazuh manager.

The decoder extracts all CEF fields (target IP, peak PPS/BPS, source count, attack family, severity, incident ID, timestamps, and message) and the rules generate alerts at appropriate severity levels with MITRE ATT&CK mapping to T1498 (Network Denial of Service) and T1499 (Endpoint Denial of Service).

---

### Prerequisites

* Wazuh Manager 4.x or later.
* Flowtriq dashboard with the Syslog/CEF integration enabled.
* Network connectivity from the Flowtriq instance to the Wazuh manager on the configured syslog port (default 514/UDP).

---

### Installation and Configuration

#### Configuring Flowtriq Syslog/CEF Output

1. In the Flowtriq dashboard, navigate to **Settings > Integrations**.
2. Add a new **Syslog/CEF** integration.
3. Set the **Host** to your Wazuh manager IP address.
4. Set the **Port** to the port Wazuh is listening on for syslog (default: 514).
5. Set the **Protocol** to UDP or TCP as appropriate.
6. Save the integration.

Flowtriq will now send CEF-formatted syslog messages for attack start and attack resolved events.

The CEF messages use the following format:

```
<priority>Mmm DD HH:MM:SS hostname Flowtriq: CEF:0|Flowtriq|FlowtriqDDoS|1.0|SignatureID|EventName|Severity|Extensions
```

Extension fields include:
- `dst` - Target node IP address
- `cn1` / `cn1Label=PeakPPS` - Peak packets per second
- `cn2` / `cn2Label=PeakBPS` - Peak bits per second
- `cnt` - Number of unique source IPs
- `cs1` / `cs1Label=AttackFamily` - Attack classification (e.g., syn_flood, udp_flood, tcp_flood, http_flood, icmp_flood, dns_flood, multi_vector)
- `cs2` / `cs2Label=Severity` - Severity level (low, medium, high, critical)
- `cs3` / `cs3Label=IncidentID` - Flowtriq incident identifier
- `start` - Attack start timestamp (epoch milliseconds)
- `end` - Attack end timestamp (epoch milliseconds, present only on resolved events)
- `msg` - Human-readable event description

#### Using the Integration Files

1. Copy the decoder file to the Wazuh manager:

```bash
cp ruleset/flowtriq_decoders.xml /var/ossec/etc/decoders/flowtriq_decoders.xml
```

2. Copy the rules file to the Wazuh manager:

```bash
cp ruleset/flowtriq_rules.xml /var/ossec/etc/rules/flowtriq_rules.xml
```

3. Configure Wazuh to accept syslog input. Add the following to `/var/ossec/etc/ossec.conf` inside the `<ossec_config>` block:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>YOUR_FLOWTRIQ_IP</allowed-ips>
</remote>
```

Replace `YOUR_FLOWTRIQ_IP` with the IP address of your Flowtriq instance.

4. Restart the Wazuh manager:

```bash
systemctl restart wazuh-manager
```

---

### Integration Testing

Use the sample logs provided in `sample_logs.txt` to verify the decoder and rules are working:

```bash
/var/ossec/bin/wazuh-logtest < sample_logs.txt
```

You can also use `wazuh-logtest` interactively by pasting individual log lines. Expected behavior:

- **DDoS Attack Detected** events should trigger rule 100901 (level 10) or higher depending on severity and attack family.
- **DDoS Attack Resolved** events should trigger rule 100920 (level 5).
- Critical severity attacks trigger rule 100903 (level 14).
- High severity attacks trigger rule 100902 (level 12).
- Multi-vector attacks trigger rule 100916 (level 13).

---

### Rule Reference

| Rule ID | Level | Description |
|---------|-------|-------------|
| 100900  | 0     | Base rule for Flowtriq events |
| 100901  | 10    | DDoS attack detected (any severity) |
| 100902  | 12    | High severity DDoS attack |
| 100903  | 14    | Critical severity DDoS attack |
| 100910  | 12    | SYN flood attack |
| 100911  | 10    | UDP flood attack |
| 100912  | 10    | TCP flood attack |
| 100913  | 12    | HTTP flood attack |
| 100914  | 10    | ICMP flood attack |
| 100915  | 12    | DNS flood attack |
| 100916  | 13    | Multi-vector attack |
| 100920  | 5     | DDoS attack resolved |

All attack detection rules include MITRE ATT&CK mappings to T1498 and/or T1499.

---

### Sources

* [Flowtriq Documentation](https://flowtriq.com/docs)
* [CEF Format Specification](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors/pdfdoc/common-event-format-v25/common-event-format-v25.pdf)
* [Wazuh Custom Decoders](https://documentation.wazuh.com/current/user-manual/ruleset/custom.html)
* [MITRE ATT&CK T1498 - Network Denial of Service](https://attack.mitre.org/techniques/T1498/)
* [MITRE ATT&CK T1499 - Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)
