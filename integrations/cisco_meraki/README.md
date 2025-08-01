# Cisco Meraki-Wazuh Integration

## Table of Contents
* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
    * [Installing Cisco Meraki](#installing-cisco-meraki)
    * [Initial Cisco Meraki Configuration](#initial-cisco-meraki-configuration)
    * [Installing Wazuh (if applicable)](#installing-wazuh-if-applicable)
    * [Initial Wazuh Configuration (if applicable)](#initial-wazuh-configuration-if-applicable)
    * [Using the Integration Files](#using-the-integration-files)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Sources](#sources)

---

## Introduction

Cisco Meraki offers a centralized cloud management platform for all Meraki devices such as MX Security Appliances, MR Access Points, and so on. Its out-of-band cloud architecture creates secure, scalable, and easy-to-deploy networks that can be managed from anywhere. This can be done from almost any device using the web-based Meraki Dashboard and Meraki Mobile App. Each Meraki network generates its own events. This integration supports gathering events via the Cisco Meraki syslog. The integration allows you to search, observe, and visualize these events through Wazuh.

**Compatibility**: A syslog server can be configured to store messages for reporting purposes from MX Security Appliances, MR Access Points, and MS switches. This package collects events from the configured syslog server. The integration supports collection of events from "MX Security Appliances" and "MR Access Points". The "MS Switch" events are not recognized.

**Version**: The latest version supported is Meraki 8.11.0.

---

## Prerequisites

List all necessary prerequisites for setting up this integration. This may include:

* **Wazuh Environment**: A running Wazuh environment (Server, Indexer, Dashboard) with version 4.x or higher. A standard Wazuh installation is assumed.
* **Cisco Meraki Devices**: Cisco Meraki devices (MX Security Appliances, MR Access Points) configured and operational.
* **Syslog Server**: A syslog server (e.g., rsyslog, syslog-ng) configured to receive syslog events from Cisco Meraki devices.
* **Network Connectivity**: Network connectivity allowing syslog traffic from Meraki devices to the syslog server, and from the syslog server to the Wazuh agent/server.
* **Access**: Administrative access to the Cisco Meraki Dashboard to configure syslog forwarding.

---

## Installation and Configuration

### Installing Cisco Meraki

This integration assumes you have existing Cisco Meraki devices and a configured Meraki network. For initial setup of Cisco Meraki devices, please refer to the [official Cisco Meraki documentation](https://documentation.meraki.com/).

### Initial Cisco Meraki Configuration

To prepare your Cisco Meraki devices for integration with Wazuh, you need to configure them to send syslog events to a syslog server.

Refer to the [Cisco Meraki Syslog Server Overview and Configuration](https://documentation.meraki.com/General_Administration/Monitoring_and_Reporting/Syslog_Server_Overview_and_Configuration) page for detailed instructions on how to configure syslog on your Cisco Meraki dashboard.

Ensure that your MX Security Appliances and MR Access Points are configured to send their logs to your designated syslog server.

### Installing Wazuh (if applicable)

This integration assumes a standard Wazuh installation. If you need to install Wazuh, please follow the official documentation: [Wazuh Installation Guide](https://documentation.wazuh.com/current/installation-guide/index.html).

### Initial Wazuh Configuration (if applicable)

To enable your Wazuh agent to receive syslog events from the syslog server, you need to configure it to listen for incoming syslog messages.

Refer to the [Forward syslog events documentation](https://documentation.wazuh.com/current/cloud-service/your-environment/send-syslog-data.html#rsyslog-on-linux) for detailed instructions on how to configure your Wazuh agent to collect syslog events.


### Using the Integration Files

This integration provides custom rules and decoders to properly parse and alert on Cisco Meraki events.

1.  **Rules and Decoders Deployment**:
    * In Wazuh Dashboard, navigate to `Server Management` > `Rules`.
    * Click `Add new rules file`, copy and paste the content of your custom rules file (e.g., `meraki_rules.xml`), and save it in `.xml` format (e.g., `meraki_rules.xml`).
    * In Wazuh Dashboard, navigate to `Server Management` > `Decoders`.
    * Click `Add new decoders file`, copy and paste the content of your custom decoders file (e.g., `meraki_decoders.xml`), and save it in `.xml` format (e.g., `meraki_decoders.xml`).

2.  **Configuration in `ossec.conf`**:
    * Ensure your `ossec.conf` (on the Wazuh Server or Agent receiving logs from the syslog server) is configured to include these new files. 
    ```
    <localfile>
        <log_format>syslog</log_format>
        <location>/var/log/<FILE_NAME.log></location>
    </localfile>
    ```
  
3.  **Restart Wazuh Cluster**: After making these configuration changes, you must restart the Wazuh cluster to apply them.
    ```bash
    systemctl restart wazuh-manager
    ```

---

## Integration Steps

The integration workflow is as follows:

1.  **Cisco Meraki Device Configuration**: Configure your Cisco Meraki MX Security Appliances and MR Access Points to forward syslog events to your designated syslog server.
2.  **Syslog Server Reception**: The syslog server receives events from Cisco Meraki devices.
3.  **Wazuh Agent Collection**: A Wazuh agent (or the Wazuh server directly if it's acting as the syslog receiver) is configured to collect these syslog events from the syslog server (either by listening on a UDP/TCP port or by monitoring a log file).
4.  **Wazuh Server Processing**: The collected events are forwarded to the Wazuh server, where the custom Meraki decoders parse the raw syslog messages, and the custom Meraki rules generate alerts based on the decoded information.
5.  **Wazuh Dashboard Visualization**: Alerts and events are then available for search, observation, and visualization in the Wazuh Dashboard.

---

## Integration Testing

To verify that the Cisco Meraki integration is working correctly:

1.  **Trigger a Meraki Event**: Perform an action on a Cisco Meraki device (e.g., connect a new client to an MR Access Point, or trigger a firewall event on an MX Security Appliance) that is expected to generate a syslog event.
2.  **Check Syslog Server Logs**: Confirm that the syslog server is receiving the events from the Meraki device.
3.  **Check Wazuh Agent/Server Logs**:
    * On the Wazuh agent (if configured to collect syslog), check `/var/ossec/logs/archives/archives.log` for the raw Meraki syslog events.
    * On the Wazuh Server, check `/var/ossec/logs/ossec.log` for processed events and alerts. Look for alerts generated by your custom Meraki rules.
    * Example log snippet you might look for (actual content will vary):
        ```
        ** Alert 1234567890.12345 **: - meraki,
        2023 Jul 22 12:00:00 meraki-device-name Meraki_event_type: client_connected client_mac: 00:11:22:33:44:55
        Rule: 8XXXX (Meraki: Client Connected)
        Level: 5
        ```
4.  **View in Wazuh Dashboard**:
    * Log in to your Wazuh Dashboard.
    * Navigate to `Modules` > `Security events`.
    * Apply filters for `data.integration: meraki` or search for specific Meraki event types to see if alerts are being generated and displayed correctly.

---

## Sources

* [Cisco Meraki Syslog Server Overview and Configuration](https://documentation.meraki.com/General_Administration/Monitoring_and_Reporting/Syslog_Server_Overview_and_Configuration)
* [Wazuh Documentation: Forward syslog events](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html#localfile-syslog)
* [Wazuh Installation Guide](https://documentation.wazuh.com/current/installation-guide/index.html)
* [Official Cisco Meraki documentation](https://documentation.meraki.com/)