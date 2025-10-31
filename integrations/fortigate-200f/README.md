# FG-200F Fortinet - Wazuh Decoders

## Table of Contents

* [Introduction](#introduction)
* [Compatibility](#compatibility)
* [Version](#version)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
    * [Installing FG-200F Fortinet](#installing-fortigate-200f)
    * [Initial FG-200F Fortinet Configuration](#initial-fortigate-200f-configuration)
    * [Installing Wazuh (if applicable)](#installing-wazuh-if-applicable)
    * [Initial Wazuh Configuration (if applicable)](#initial-wazuh-configuration-if-applicable)
    * [Using the Integration Files](#using-the-integration-files)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Sources](#sources)

---

### Introduction

This integration provides support for ingesting and decoding logs from FG-200F Fortinet into Wazuh. It includes an essential ruleset, decoders, and an optional dashboard to visualize events. This integration was developed in a real use case.

---

## Compatibility

Tested and validated with:

- Wazuh v4.12
- FG-200F Fortinet (various event types).


## Version

Tested on: `Wazuh v4.12`

---

### Prerequisites

- An already "working on" environment of Wazuh.
- FG-200F Fortinet log source.
- Access to `/var/ossec/` for integration files.
- Access to Wazuh Dashboard for content visualization.

---

### Installation and Configuration

#### Installing FG-200F Fortinet

It is assumed that FG-200F Fortinet is already installed in your environment. If not, refer to the [official documentation](https://docs.fortinet.com/document/fortigate/hardware/fortigate-200f-series-quickstart-guide) for deployment.


#### Initial FG-200F Fortinet Configuration

Ensure that logs are being exported via Syslog or API to Wazuh.
This may include:
- Enabling log forwarding
- Configuring filters
- Creating service accounts or API keys
- (https://docs.fortinet.com/document/fortigate/hardware/fortigate-200f-series-quickstart-guide) for successfully deploy and the initial configuration.
- (https://community.fortinet.com/t5/FortiGate/Technical-Tip-How-to-configure-syslog-on-FortiGate/ta-p/331959) for set up a syslog.


#### Installing Wazuh (if applicable)

A standard Wazuh installation is assumed.  
Refer to the official guide: https://documentation.wazuh.com/current/installation-guide/index.html

#### Initial Wazuh Configuration (if applicable)

Make sure Wazuh Manager is receiving logs and that the `ossec.conf` references the new decoders.

#### Using the Integration Files

Place the following files:

- **Decoders**:
  - File: `/content/ruleset/fortigate-200f/fortigate-200f-decoder-type1.xml`
  - File: `/content/ruleset/fortigate-200f/fortigate-200f-decoder-type2.xml`
  - File: `/content/ruleset/fortigate-200f/fortigate-200f-decoder-type3.xml`
  - Path: `/var/ossec/etc/decoders`

  - **Rules**: 
  - File: `/content/ruleset/fortigate-200f/fortigate-200f-rules.xml`
  - Path: `/var/ossec/etc/rules/`
  
- **Sample logs**:
  - `/content/ruleset/fortigate-200f/fortigate-200f-logs-type-1/log-type-1` → matches `<decoder name="fortif200_ports">`
  - `/content/ruleset/fortigate-200f/fortigate-200f-logs-type-2/log-type-2` → matches `<decoder name="fortif200_trapmgr_fields">`
  - `/content/ruleset/fortigate-200f/fortigate-200f-logs-type-3/log-type-3` → matches `<decoder name="fortif200_dhcp_cli">`

- **Screenshots**:
  - Located on: `/content/ruleset/fortigate-200f/fortigate-200f-screenshots/`
  - Located on: `/content/ruleset/fortigate-200f/fortigate-200f-screenshots/`
  - Located on: `/content/wazuh_dashboard/fortigate-200f/fortigate-200f-essential-dashboard-screenshots`
  
  - **Essential Custom Dashboard**:
  - Fortigate 200F Essential Dashboard can be imported in Wazuh Dashboard.
  - Located on: `/content/wazuh_dashboard/fortigate-200f/fortigate-200f-essential-dashboard.ndjson`

Restart Wazuh Manager after configuration:
```bash
systemctl restart wazuh-manager
```

---

### Integration Steps

1. Copy the **Decoders** files in your environment.
2. Restart the wazuh-manager.
3. Use the Ruleset Test or live events to rule evaluation. If testing with Ruleset Test:
  3.1 From the Wazuh Dashboard, navigate to --> hamburguer menu --> Server Management --> Ruleset Test.
  3.2 Copy one of the sample logs into the text box and press the blue Test button.
  3.3 Notice the output with the decoded fields.

---

### Integration Steps

1. Copy the **Decoders** and **Rules** files in your environment.
2. Restart the wazuh-manager.
3. Use the Ruleset Test or live events to rule evaluation. If testing with Ruleset Test:
  3.1 From the Wazuh Dashboard, navigate to --> hamburguer menu --> Server Management --> Ruleset Test.
  3.2 Copy one of the sample logs into the text box and press the blue Test button.
  3.3 Notice the output with the decoded fields and the alert that it triggers.
4. Import the Essential Custom Dashboard:
  4.1 Download the file `/content/wazuh_dashboard/fortigate-200f/fortigate-200f-essential-dashboard.ndjson`
  4.2 From the Wazuh Dashboard, navigate to --> hamburguer menu --> Dashboards Management.
  4.3 On the left area, click on --> Saved objects.
  4.4 At the upper right corner press on Import.
  4.5 Select the downloaded from your local system `/content/wazuh_dashboard/fortigate-200f/fortigate-200f-essential-dashboard.ndjson`
5. The Visualizations from the Essential Custom Dashboard content:
  5.1 `Table of Contents - fortigate-200f | Markdown.`

Provides a simple navigation menu for the Fortigate 200F Essentials dashboard. It allows to quickly locate key visualizations and sections.

  5.2 `Events by Rule ID fortigate-200f | Pie`

Displays the distribution of Fortigate 200F events based on the rule.id

  5.3 `Logs by Agent fortigate-200f | Vertical Bar`

Displays the number of Fortigate 200F events generated by each agent. Useful to identify which endpoints are producing the most activity.

  5.4 `Total FG-200F Logs fortigate-200f | Metric`

Shows the total number of Fortigate 200F logs. Useful as a quick indicator of activity volume.

---

### Integration Testing

To verify:

1. Use the Ruleset Test or live events to rule evaluation. If testing with Ruleset Test:
  1.1 From the Wazuh Dashboard, navigate to --> hamburguer menu --> Server Management --> Ruleset Test.
  1.2 Copy one of the sample logs into the text box and press the blue Test button.
  1.3 Notice the output with the decoded fields and the alert that it triggers.

2. Or inject real logs and verify output in:

  - `/var/ossec/logs/archives/archives.log`
  - `/var/ossec/logs/ossec.log`

- Confirm expected alerts are triggered.
- Use Wazuh Dashboard with the *Fortigate 200F Essential Dashboard* for visualization.

---

### Sources

- https://www.fortinet.com/resources/data-sheets/fortigate-200f-series
- https://docs.fortinet.com/
- https://documentation.wazuh.com/current/user-manual/ruleset/testing.html
- https://documentation.wazuh.com/current/user-manual/ruleset/decoders/custom.html
