## DNS-Level Threat Monitoring with Wazuh and Technitium DNS Server 

## Table of Contents
- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Installation and Configuration](#installation-and-configuration)
  - [Installing Technitium DNS Server](#installing-technitium-dns-server)
  - [Accessing Technitium DNS Web UI](#accessing-technitium-dns-web-ui)
- [Wazuh and Technitium DNS Integration Using JSON Logs](#wazuh-and-technitium-dns-integration-using-json-logs)
  - [Log Exporter Integration](#log-exporter-integration)
  - [Logging Settings](#logging-settings)
  - [Generate DNS Queries for Testing](#generate-dns-queries-for-testing)
  - [Verify JSON Log Output](#verify-json-log-output)
- [Wazuh Agent Configuration](#wazuh-agent-configuration)
- [Custom Ruleset Configuration in Wazuh Server](#custom-ruleset-configuration-in-wazuh-manager-server)
  - [Testing Decoders and Rules](#testing-decoders-and-rules)
- [Dashboard Configuration](#dashboard-configuration)
- [Sources](#sources)

## Introduction
This integration offers a comprehensive guide and the required configurations to integrate Technitium DNS Server with Wazuh. By leveraging this integration, security teams can collect, parse, and analyze DNS query logs from Technitium in real time through Wazuh. This enables effective monitoring of DNS traffic, detection of suspicious or malicious domains, and correlation of DNS-based indicators with other security events across the environment.

## Prerequisites
Before starting the integration, ensure you have the following:

- A dedicated server with supported Linux operating system for installing Technitium DNS and the Wazuh Agent.
- A fully functional Wazuh environment, including the Server, Indexer, and Dashboard components.
- Reliable network connectivity between the Wazuh Agent and the Wazuh Server to ensure uninterrupted log transmission.

## Installation and Configuration

### Installing Technitium DNS Server

Download and Install Technitium DNS Server
```bash
curl -LO https://download.technitium.com/dns/install.sh
chmod +x install.sh
sudo ./install.sh
```
Verify the Service Status
```bash
systemctl status dns
```
Ensure the service is running without errors before proceeding with the integration.

### Accessing Technitium DNS Web UI

You can access the Technitium DNS Server Web UI through port `5380` on the machine hosting the service. Open the following `URL` in your browser:

`http://<server-ip>:5380` 

When prompted, log in using the `default` administrator credentials and it is strongly recommended to change the default password after the initial login to secure the server.


<img width="950" height="492" alt="image" src="https://github.com/user-attachments/assets/a2dda26a-dbcf-418f-acc8-bb65d09a1d29" />

## Wazuh and Technitium DNS integration using JSON logs

### Log Exporter Integration
Technitium’s Log Exporter is configured either via the administrative UI or a JSON file. In this article, logs are written to a local file in JSON Lines format:

Navigate `Apps` → `App store`, and select and insatll `Log Exporter app`.

<img width="1181" height="462" alt="image" src="https://github.com/user-attachments/assets/f95de817-26a8-44e4-bc1c-2868186e2ca0" />

Once the installation is complete, click the Config button, modify the settings as mentioned below, and save the changes.

<img width="1165" height="746" alt="image" src="https://github.com/user-attachments/assets/eddf4b9f-4bb6-4cf4-9f72-32999da3dc02" />



```json

{
  "maxQueueSize": 1000000,
  "file": {
    "path": "/var/log/dns/dns_logs.json",
    "enabled": true
  },
  "http": {
    "endpoint": "http://localhost:5000/logs",
    "headers": {
      "Authorization": "Bearer abc123"
    },
    "enabled": false
  },
  "syslog": {
    "address": "127.0.0.1",
    "port": 514,
    "protocol": "UDP",
    "enabled": false
  }
}

```


### Logging Settings

Although the main objective is to integrate DNS query logs with Wazuh, it is recommended to fine-tune Technitium’s default logging configuration to reduce noise and follow best practices.

- Navigate to `Settings` → `Logging` in the Technitium DNS Web UI.

Apply the following configuration:
- Enable Logging To: Select `File` to store logs in a file for Wazuh agent to collect.
- Logging Options: Enable `Ignore Resolver Error Logs` to avoid unnecessary domain resolution error entries, which can generate excessive noise when there is no response.
- Log Folder Path:
Technitium DNS defaults to storing logs in `/etc/dns/` due to containerized environment support. However, both Linux and Windows best practices discourage keeping logs in the configuration directory. Configure a dedicated log directory instead, for example: `/var/log/dns/`

<img width="920" height="648" alt="image" src="https://github.com/user-attachments/assets/878be082-ee28-44b0-a526-2bf0240a8598" />



Restart Technitium DNS Service

Go to the CLI and Restart Technitium DNS Service (to ensure Log Exporter App is loaded)

```bash
sudo systemctl restart dns
```

### Generate DNS Queries for Testing

From the Technitium DNS server:

```bash
dig @localhost example.com
dig @localhost google.com
```
From another machine:

```bash
dig @<your-server-ip> yahoo.com
```

### Verify JSON Log Output

Check if the DNS log file is created and populated with events:

```bash
ls -l /var/log/dns/dns_logs.json
tail -n 20 /var/log/dns/dns_logs.json
```
### Expected Output:

You should see DNS events formatted as JSON objects.

**Note:** If the file `/var/log/dns/dns_logs.json` is created, JSON logging is working and you are ready to integrate it with Wazuh.

## Wazuh Agent Configuration

The Wazuh agent reads the Technitium DNS JSON log file directly. For this integration, you can use either the centralized configuration (via Wazuh Server) or the local agent configuration. You can refer to this [document](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html) for the centralized configuration.

If the `Wazuh agent` is not already installed on the Technitium DNS server, you must install it first. Follow the official [document](https://documentation.wazuh.com/current/cloud-service/getting-started/enroll-agents.html#deploy-agent)

Local Agent Configuration:

To configure it locally, add the following `<localfile>` block in the agent’s `/var/ossec/etc/ossec.conf` file:

```xml
<localfile>
    <log_format>json</log_format>
    <only-future-events>no</only-future-events>
    <location>/var/log/dns/dns_logs.json</location>
    <out_format>{"dns": $(log) }</out_format> <!-- Wrapping the original log with a "dns" field so that the flattened log becomes `data.dns.fieldName`. -->
    <label key="type">dns</label> <!-- This is just to ensure we are collecting the correct logs. -->
</localfile>
```

The configuration above wraps each log line under a `dns` object, which keeps fields grouped and reduces collision risks. As a side note, I must remind you to set up logrotate for this log file if you have not. It is not related to Wazuh, but for proper maintenance of your log file. DNS logs are noisy, causing the filesystem to run out of space easily.

**Recommendation:** Set up logrotate for `/var/log/dns/dns_logs.json` to prevent the file from consuming excessive disk space, as DNS logs can grow quickly.

Restart Wazuh Agent

After saving the configuration, restart the agent:

```bash
sudo systemctl restart wazuh-agent
```
Verify that the agent is reading the DNS log file by checking `tail -f /var/ossec/logs/ossec.log | grep dns_logs.json`


## Custom Ruleset configuration in wazuh server

The following rule group processes Technitium DNS logs. It includes classification of allowed vs. blocked traffic, pattern detection for encoded or long queries, and frequency-based anomaly detection. This can be extended with list-based IOC matching or response code logic.

Create a Custom Rules File

Create a new custom rule file under `/var/ossec/etc/rules/` for Technitium DNS integration and add the custom rules provided below:

```bash
nano /var/ossec/etc/rules/technitiumdns_rules.xml
```

<details>
<summary>Click to expand custom rules</summary>
  
##### Technitium DNS Custom Rules:

**Note:**

- Use rule ID numbers between `100000` and `120000` for custom rules.
- Ensure there are no duplicate rule IDs configured in any `custom` or `default` rule files.


Set the correct permissions:

```bash
chown wazuh:wazuh /var/ossec/etc/rules/technitiumdns_rules.xml
chmod 660 /var/ossec/etc/rules/technitiumdns_rules.xml
```

Restart the Wazuh server service:

After saving the rules, restart the Wazuh server to apply changes:

```bash
sudo systemctl restart wazuh-manager
```


The /var/ossec/bin/wazuh-logtest tool allows you to test and verify decoders and rules against sample log entries directly on the Wazuh server.

To validate the Technitium DNS rules, execute wazuh-logtest on the Wazuh server and provide a sample DNS JSON log entry for testing.

```bash
/var/ossec/bin/wazuh-logtest
```

<details>
<summary>Click to see logtest result</summary>

Sample output:

<img width="968" height="888" alt="image" src="https://github.com/user-attachments/assets/2988ac23-198d-491d-844b-e5cab20d626c" />

<img width="1515" height="504" alt="image" src="https://github.com/user-attachments/assets/57905865-dd29-4a44-bde0-1d8508c9d11e" />

</details>

## Dashboard Configuration

Using the collected DNS query logs, you can create a custom Wazuh dashboard that replicates the visibility provided by Technitium DNS’s native interface.

Below is a sample dashboard configuration that visualizes DNS queries, blocked vs. allowed traffic, and domain activity trends:

A sample dashboard export file, [technitium_dns_dashboard.ndjson](https://github.com/wazuh/operations/blob/technitium-dns-integration/integrations/integrations/Technitium-DNS/technitium_dns_dashboard.ndjson), is included in this repository for quick setup.

You can download it directly from the GitHub UI by clicking the link above and selecting “Download raw file”. Once downloaded, you can import it into the Wazuh Dashboard by navigating to Wazuh Dashboard → Menu → Stack Management → Saved Objects.

<img width="1236" height="936" alt="image" src="https://github.com/user-attachments/assets/08e22723-492c-402c-b6f5-b3bbe9a002bc" />

## Sources

<details>
<summary>Click to expand source references</summary>

- [
DNS-Level Threat Monitoring with Wazuh and Technitium DNS Server ](https://zaferbalkan.com/technitium/)
- [Running Technitium DNS Server on Ubuntu Linux](https://blog.technitium.com/2017/11/running-dns-server-on-ubuntu-linux.html?)
- [Technitium dns integration using syslog](https://zaferbalkan.com/technitium/#wazuh-and-technitium-dns-integration-using-syslog)
  
- [Wazuh custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
- [Wazuh Centralized configuration](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html)

</details>
