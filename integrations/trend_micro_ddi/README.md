### Trend Micro DDI-Wazuh Integration


#### **Table of Contents**

  * [Introduction](#introduction)
  * [Prerequisites](#prerequisites)
  * [Initial Trend Micro DDI Configuration](#initial-trend-micro-ddi-configuration)
  * [Installing and Configuring the Integration](#installing-and-configuring-the-integration)
  * [Integration Testing](#integration-testing)


### Introduction

This guide outlines the steps to integrate Trend Micro Deep Discovery Inspector (DDI) with Wazuh. Unlike API-based integrations, this setup relies on parsing Common Event Format (CEF) logs forwarded by the DDI appliance.

### Prerequisites

Before starting, ensure the following:

  * A functioning Trend Micro Deep Discovery Inspector (DDI) appliance capable of forwarding logs via Syslog in CEF format.
  * A Wazuh Manager installed and configured to receive Syslog events (or reading from a centralized log file).

### Initial Trend Micro DDI Configuration

Access your Trend Micro DDI management console and configure the log forwarding settings. You must set the appliance to forward its detection logs to the Wazuh Manager (or a designated Wazuh Agent acting as a Syslog collector) over UDP or TCP on your preferred port (commonly 514). Ensure the output format is strictly set to CEF (Common Event Format), as the Wazuh decoders rely on this specific structure to extract fields properly.

### Installing and Configuring the Integration

#### Copy the Custom Decoders

The custom decoders instruct Wazuh on how to parse the DDI CEF logs. Copy the `trend_micro_ddi_decoders.xml` file to the Wazuh Manager's custom decoders directory:

```bash
cp integrations/trend_micro_ddi/trend_micro_ddi_decoders.xml /var/ossec/etc/decoders/
```

Or navigate to Server Management --> Decoders --> Add new decoders file --> paste the content, save the file and reload the cluster

#### Copy the Custom Rules

The custom rules map the decoded fields to specific security alerts and severities. Copy the `trend_micro_ddi_rules.xml` file to the Wazuh Manager's custom rules directory:

```bash
cp integrations/trend_micro_ddi/trend_micro_ddi_rules.xml /var/ossec/etc/rules/
```

Or navigate to Server Management --> Rules --> Add new rules file --> paste the content, save the file and reload the cluster

#### Set File Permissions

Ensure that the Wazuh user has the appropriate permissions to read the newly added files:

```bash
chown wazuh:wazuh /var/ossec/etc/decoders/trend_micro_ddi_decoders.xml
chown wazuh:wazuh /var/ossec/etc/rules/trend_micro_ddi_rules.xml
chmod 660 /var/ossec/etc/decoders/trend_micro_ddi_decoders.xml
chmod 660 /var/ossec/etc/rules/trend_micro_ddi_rules.xml
```

### Integration Testing

#### Test Using Wazuh-Logtest

You can verify that the decoders and rules are working correctly by using the `wazuh-logtest` tool with the provided `sample_logs.txt`:

1.  Navigate to Server Management --> Ruleset Test on the Dashboard:
2.  Paste a raw CEF log from the `sample_logs.txt` file into the prompt.
3.  Verify that Phase 2 correctly identifies the `Deep_Discovery_Inspector` decoder and Phase 3 triggers the appropriate rule (e.g., Rule `100010` for WebScript Injection).

#### Verify in Wazuh Dashboard

1.  Open the Wazuh Dashboard.
2.  Navigate to the **Discover** tab.
3.  Add a filter: `Field` `rule.groups`, `Operator` `is`, `Value` `TrendMicro`.
4.  Alternatively, filter by `Field` `decoder.name`, `Operator` `is`, `Value` `Deep_Discovery_Inspector`.
5.  Save the filter or view the dashboard to monitor ingested Trend Micro DDI events in real-time.
