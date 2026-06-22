### QNAP NAS - Wazuh Integration

#### **Table of Contents**

  * [Introduction](#introduction)
  * [Prerequisites](#prerequisites)
  * [Initial QNAP Configuration](#initial-qnap-configuration)
  * [Installing and Configuring the Integration](#installing-and-configuring-the-integration)
  * [Integration Testing](#integration-testing)

### Introduction

This guide outlines the steps to integrate QNAP NAS logs with Wazuh. This integration focuses on parsing the `qulogd` daemon's output to strictly audit user activity, including SMB/SAMBA file access (Read, Write, Rename, Delete) and login/logout events.

### Prerequisites

Before starting, ensure the following:

  * A functioning QNAP NAS device running QuLog Center.
  * A Wazuh Manager (or a designated Wazuh Agent) configured to receive Syslog traffic.

### Initial QNAP Configuration

To forward QNAP logs to Wazuh, configure the NAS to push system and connection logs:
1. Open **QuLog Center** on your QNAP NAS.
2. Navigate to **Log Sender** (under Local Device).
3. Add a new Log Destination pointing to your Wazuh Manager/Agent IP address and Syslog port (default 514).
4. Ensure both "System Event Logs" and "System Connection Logs" are selected to be forwarded.

### Installing and Configuring the Integration

#### Copy the Custom Decoders

Copy the QNAP decoder file to the Wazuh Manager's custom decoders directory:

```bash
cp integrations/qnap_nas/decoders/qnap_decoder.xml /var/ossec/etc/decoders/

```

#### Copy the Custom Rules

Copy the QNAP rules file to the Wazuh Manager's custom rules directory to trigger alerts on actions like file deletions or failed logins:

```bash
cp integrations/qnap_nas/rules/qnap_rules.xml /var/ossec/etc/rules/

```

#### Set File Permissions

Ensure that the Wazuh user has the appropriate permissions:

```bash
chown wazuh:wazuh /var/ossec/etc/decoders/qnap_decoder.xml
chown wazuh:wazuh /var/ossec/etc/rules/qnap_rules.xml
chmod 660 /var/ossec/etc/decoders/qnap_decoder.xml
chmod 660 /var/ossec/etc/rules/qnap_rules.xml

```

#### Restart the Wazuh Manager (If using CLI)

```bash
systemctl restart wazuh-manager

```

### Integration Testing

#### Test Using Wazuh-Logtest

Verify the configuration using `wazuh-logtest` and the provided `sample_logs.txt`:

1. Navigate to **Server Management** --> **Ruleset Test**.
2. Paste a raw log from `sample_logs.txt` (e.g., `Jun  9 10:35:12 PROD-SERVER qulogd[29981]: conn log: Users: admin, Source IP: 10.0.0.5, ... Action: Delete`).
3. Verify Phase 2 identifies the `qnap_qulogd` decoder and Phase 3 triggers the relevant file auditing or authentication rule.

#### Verify in Wazuh Dashboard

1. Navigate to the **Discover** tab in the Wazuh Dashboard.
2. Add a filter: `Field` `decoder.name`, `Operator` `is`, `Value` `qnap_qulogd`.
3. Monitor the ingested QNAP file access events in real-time.
