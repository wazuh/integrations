### Bitdefender GravityZone-Wazuh Integration

#### **Table of Contents**

  * [Introduction](#introduction)
  * [Prerequisites](#prerequisites)
  * [Initial Bitdefender GravityZone Configuration](#initial-bitdefender-gravityzone-configuration)
  * [Installing and Configuring the Integration](#installing-and-configuring-the-integration)
  * [Integration Testing](#integration-testing)

### Introduction

This guide outlines the steps to integrate Bitdefender GravityZone with Wazuh. This integration relies on parsing Common Event Format (CEF) logs forwarded by the GravityZone console or endpoint relays.

### Prerequisites

Before starting, ensure the following:

  * A functioning Bitdefender GravityZone Control Center capable of forwarding logs via Syslog in CEF format.
  * A Wazuh Manager installed and configured to receive Syslog events (or reading from a centralized log file).

### Initial Bitdefender GravityZone Configuration

Access your Bitdefender GravityZone Control Center and navigate to the SIEM integration or Event Push notifications settings. You must set the platform to forward its detection and audit logs to the Wazuh Manager (or a designated Wazuh Agent acting as a Syslog collector) over UDP or TCP on your preferred port (commonly 514). Ensure the output format is strictly set to CEF (Common Event Format), as the Wazuh decoders rely on this format to accurately extract fields like `EventName`, `MalwareName`, and `gravityzone_action`.

### Installing and Configuring the Integration

#### Copy the Custom Decoders

The custom decoders instruct Wazuh on how to parse the GravityZone CEF logs. Copy the decoders file to the Wazuh Manager's custom decoders directory:

```bash
cp integrations/bitdefender_gravityzone/bitdefender_gravityzone_decoders.xml /var/ossec/etc/decoders/
```

Or navigate to **Server Management** --\> **Decoders** --\> **Add new decoders file** --\> paste the content, save the file and reload the cluster.

#### Copy the Custom Rules

The custom rules map the decoded fields to specific security alerts, such as Critical alerts for unblocked malware or disabled security modules. Copy the rules file to the Wazuh Manager's custom rules directory:

```bash
cp integrations/bitdefender_gravityzone/bitdefender_gravityzone_rules.xml /var/ossec/etc/rules/
```

Or navigate to **Server Management** --\> **Rules** --\> **Add new rules file** --\> paste the content, save the file and reload the cluster.

#### Set File Permissions

Ensure that the Wazuh user has the appropriate permissions to read the newly added files:

```bash
chown wazuh:wazuh /var/ossec/etc/decoders/bitdefender_gravityzone_decoders.xml
chown wazuh:wazuh /var/ossec/etc/rules/bitdefender_gravityzone_rules.xml
chmod 660 /var/ossec/etc/decoders/bitdefender_gravityzone_decoders.xml
chmod 660 /var/ossec/etc/rules/bitdefender_gravityzone_rules.xml
```

#### Restart the Wazuh Manager (If using CLI)

If you copied the files directly via the command line, apply the new decoders and rules by restarting the Wazuh Manager service:

```bash
systemctl restart wazuh-manager
```

### Integration Testing

#### Test Using Wazuh-Logtest

You can verify that the decoders and rules are working correctly by using the `wazuh-logtest` tool with a provided `sample_logs.txt`:

1.  Navigate to **Server Management** --\> **Ruleset Test** on the Dashboard.
2.  Paste a raw CEF log from Bitdefender GravityZone into the prompt.
3.  Verify that Phase 2 correctly identifies the `gravityzone_soc` decoder and Phase 3 triggers the appropriate rule (e.g., Rule `110003` for an unmitigated malware detection or `110008` for a disabled module).

#### Verify in Wazuh Dashboard

1.  Open the Wazuh Dashboard.
2.  Navigate to the **Discover** tab.
3.  Add a filter: `Field` `rule.groups`, `Operator` `is`, `Value` `gravityzone`.
4.  Alternatively, filter by `Field` `decoder.name`, `Operator` `is`, `Value` `gravityzone_soc`.
5.  Save the filter or view the dashboard to monitor ingested Bitdefender GravityZone events in real-time.
