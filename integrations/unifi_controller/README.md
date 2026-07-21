### UniFi Controller–Wazuh Integration

#### **Table of Contents**

  * [Introduction](#introduction)
  * [Prerequisites](#prerequisites)
  * [Initial UniFi Controller Configuration](#initial-unifi-controller-configuration)
  * [Installing and Configuring the Integration](#installing-and-configuring-the-integration)
  * [Integration Testing](#integration-testing)

### Introduction

This guide outlines the steps to integrate UniFi Network Application (controller) CEF syslog events with Wazuh. This integration relies on parsing CEF activity logs (`CEF:0|Ubiquiti|UniFi Network|...`) to track WiFi client connect, disconnect, and roam events, as well as administrator access to the UniFi Network UI/API.

This ruleset is separate from the UniFi AP syslog ruleset (the `unifi_ap` integration).

### Prerequisites

Before starting, ensure the following:

  * A functioning UniFi Network Application generating CEF activity logs over syslog.
  * A Wazuh Manager (or a designated Wazuh Agent) installed and configured to receive those syslog events.

### Initial UniFi Controller Configuration

To forward UniFi controller logs to Wazuh, configure the UniFi Network Application to send activity notifications/logs in CEF format to a syslog destination (the Wazuh manager or an agent that relays them).

Ensure log collection is active so Wazuh can ingest the raw CEF lines and begin parsing fields like `unifi_event_id`, `unifi_client_mac`, `unifi_wifi_name`, `unifi_ap_name`, `srcip`, and `srcuser`.

### Installing and Configuring the Integration

#### Copy the Custom Decoders

The custom decoders instruct Wazuh on how to parse the UniFi Network Application CEF format. Copy the decoders file to the Wazuh Manager's custom decoders directory:

```bash
cp integrations/unifi_controller/unifi_controller_decoder.xml /var/ossec/etc/decoders/
```

Or navigate to **Server Management** --\> **Decoders** --\> **Add new decoders file** --\> paste the content, save the file and reload the cluster.

#### Copy the Custom Rules

The custom rules map the decoded fields to specific connectivity and auditing alerts, such as alerting when a WiFi client connects, disconnects, or roams, or when an administrator accesses UniFi Network. Copy the rules file to the Wazuh Manager's custom rules directory:

```bash
cp integrations/unifi_controller/unifi_controller_rules.xml /var/ossec/etc/rules/
```

Or navigate to **Server Management** --\> **Rules** --\> **Add new rules file** --\> paste the content, save the file and reload the cluster.

#### Set File Permissions

Ensure that the Wazuh user has the appropriate permissions to read the newly added files:

```bash
chown wazuh:wazuh /var/ossec/etc/decoders/unifi_controller_decoder.xml
chown wazuh:wazuh /var/ossec/etc/rules/unifi_controller_rules.xml
chmod 660 /var/ossec/etc/decoders/unifi_controller_decoder.xml
chmod 660 /var/ossec/etc/rules/unifi_controller_rules.xml
```

#### Restart the Wazuh Manager (If using CLI)

If you copied the files directly via the command line, apply the new decoders and rules by restarting the Wazuh Manager service:

```bash
systemctl restart wazuh-manager
```

### Integration Testing

#### Test Using Wazuh-Logtest

You can verify that the decoders and rules are working correctly by using the `wazuh-logtest` tool with a log from your `log_samples.txt`:

1.  Navigate to **Server Management** --\> **Ruleset Test** on the Dashboard.
2.  Paste a raw CEF log from UniFi into the prompt (e.g., `CEF:0|Ubiquiti|UniFi Network|10.4.57|400|WiFi Client Connected|1|UNIFIcategory=Client Devices UNIFIsite=Site A UNIFIhost=CONTROLLER UNIFIconnectedToDeviceName=UNIAP-01 UNIFIclientAlias=PHONE-01 UNIFIclientIp=10.0.1.50 UNIFIclientMac=aa:bb:cc:11:11:11 UNIFIwifiName=CORP-WIFI UNIFIauthMethod=wpapsk UNIFIWiFiRssi=-60 ...`).
3.  Verify that Phase 2 correctly identifies the `unifi-controller` decoder (and child field extractions) and Phase 3 triggers the appropriate rule (e.g., Rule `111551` for a client connected, `111552` for disconnected, `111553` for roamed, or `111554` for Network Accessed).

#### Verify in Wazuh Dashboard

1.  Open the Wazuh Dashboard.
2.  Navigate to the **Discover** tab.
3.  Add a filter: `Field` `rule.groups`, `Operator` `is`, `Value` `unifi_controller`.
4.  Alternatively, filter by `Field` `decoder.name`, `Operator` `is`, `Value` `unifi-controller`.
5.  Save the filter or view the dashboard to monitor ingested UniFi controller events in real-time.
