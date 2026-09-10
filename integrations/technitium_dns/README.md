## DNS-Level Threat Monitoring with Wazuh and Technitium DNS Server

## Table of Contents

- [DNS-Level Threat Monitoring with Wazuh and Technitium DNS Server](#dns-level-threat-monitoring-with-wazuh-and-technitium-dns-server)
- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Installation and Configuration](#installation-and-configuration)
  - [Installing Technitium DNS Server](#installing-technitium-dns-server)
  - [Accessing Technitium DNS Web UI](#accessing-technitium-dns-web-ui)
- [Wazuh and Technitium DNS integration using JSON logs](#wazuh-and-technitium-dns-integration-using-json-logs)
  - [Log Exporter Integration](#log-exporter-integration)
  - [Logging Settings](#logging-settings)
  - [Generate DNS Queries for Testing](#generate-dns-queries-for-testing)
  - [Verify JSON Log Output](#verify-json-log-output)
- [Wazuh Agent Configuration](#wazuh-agent-configuration)
- [Custom Ruleset configuration in wazuh server](#custom-ruleset-configuration-in-wazuh-server)
  - [Technitium DNS Custom Rules](#technitium-dns-custom-rules)
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

Two LogExporterApp implementations can be used with this integration. Both export structured Technitium DNS query and response events, but they differ in distribution, configuration, and processing capabilities.

**Choose Option 1** if you want the App Store-managed exporter, a flat configuration, and straightforward file, HTTP, or Syslog export. **Choose Option 2** if you need an independently released ETL-style pipeline with domain metadata, static tagging, or enrichment-oriented workflows such as preserving Extended DNS Error (EDE) context from other Technitium DNS apps for downstream correlation in Wazuh.

#### Option 1: Technitium DNS Server LogExporterApp

The original [LogExporterApp](https://github.com/TechnitiumSoftware/DnsServer/tree/master/Apps/LogExporterApp) was designed and implemented by **Zafer Balkan** and is now maintained by **Shreyas Zare** in the Technitium DNS Server main repository. It is distributed through the Technitium DNS App Store and follows the Technitium DNS Server application and release workflow.

Use this option for direct DNS log export without an additional processing pipeline. It writes to file, HTTP, or Syslog and uses the flat configuration schema shown below.

**File-output prerequisite:** The account running the Technitium DNS Server service must have write access to the configured log directory and file. Ensure the target directory exists and that its permissions allow the service account to create and append to the configured log file.

Navigate to `Apps` → `App store`, select `Log Exporter`, and install it.

<img width="1181" height="462" alt="image" src="https://github.com/user-attachments/assets/f95de817-26a8-44e4-bc1c-2868186e2ca0" />

Once the installation is complete, click the Config button, modify the settings as shown below, and save the changes.

<img width="1165" height="746" alt="image" src="https://github.com/user-attachments/assets/eddf4b9f-4bb6-4cf4-9f72-32999da3dc02" />

Configure the file sink to write JSON Lines to `/var/log/dns/dns_logs.json`. The `maxQueueSize` value limits the number of log entries held in the in-memory queue. The shipped configuration uses `1000000`; when the queue reaches the configured limit, additional records are not enqueued until space becomes available. Adjust the value according to DNS query volume and available memory.

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

#### Option 2: DeltaZulu-OU LogExporterApp

An evolved implementation is maintained separately by **Zafer Balkan** in the [DeltaZulu-OU/LogExporterApp](https://github.com/DeltaZulu-OU/LogExporterApp) repository and is released independently from Technitium DNS Server. This version develops the exporter into an ETL-style log pipeline with optional transformation and enrichment stages.

It is **not installed from the Technitium App Store**. Download the current release package from the [DeltaZulu-OU releases](https://github.com/DeltaZulu-OU/LogExporterApp/releases/latest), then install the ZIP from the Technitium DNS web console using `Apps` → `Install`.

**File-output prerequisite:** The account running the Technitium DNS Server service must have write access to the configured log directory and file. Ensure the target directory exists and that its permissions allow the service account to create and append to the configured log file.

The DeltaZulu exporter can add Public Suffix List-derived domain metadata and static tags before exporting events to console, file, HTTP, or Syslog sinks. It uses bounded asynchronous pipeline stages and reports dropped records when sustained load fills a stage.

Its enrichment capabilities are particularly useful when another Technitium DNS app attaches context to a DNS response. Extended DNS Error (EDE) metadata is one example. For instance, [DeltaZulu-OU/MispConnectorApp](https://github.com/DeltaZulu-OU/MispConnectorApp) can add blocking context such as `source=misp-connector;domain=example.org` when a matching domain is blocked. With `enableEdnsLogging` enabled, the DeltaZulu exporter preserves that context in the exported event, giving Wazuh visibility into *why* the response was blocked rather than only *that* it was blocked.

For this Wazuh integration, the following example enables EDE logging and domain normalization while keeping file output as the active sink. The `maxQueueSize` value is an example capacity for each bounded pipeline stage; adjust it according to DNS query volume, processing latency, and available memory.

```json
{
  "sinks": {
    "maxQueueSize": 50000,
    "enableEdnsLogging": true,
    "console": {
      "enabled": false
    },
    "file": {
      "enabled": true,
      "path": "/var/log/dns/dns_logs.json"
    },
    "http": {
      "enabled": false,
      "endpoint": "https://collector.example.com/dns",
      "headers": {}
    },
    "syslog": {
      "enabled": false,
      "address": "127.0.0.1",
      "port": 6514,
      "protocol": "TLS"
    }
  },
  "pipeline": {
    "normalize": {
      "enabled": true
    },
    "tagging": {
      "enabled": false,
      "tags": []
    }
  }
}
```

- `enableEdnsLogging: true` includes EDNS Extended DNS Error data in exported events.
- `normalize.enabled: true` adds Public Suffix List-derived domain structure under `meta.domainInfo`.
- `tagging.enabled: false` can be changed to `true` to add configured static tags under `meta.tags`.
- `maxQueueSize: 50000` is an example value. Each bounded pipeline stage uses this capacity; when a stage is full, new entries are dropped and the app periodically reports the drop count.

| Feature | Option 1: Technitium App Store | Option 2: DeltaZulu-OU |
| --- | --- | --- |
| Distribution | Technitium DNS App Store | GitHub release ZIP installed through `Apps` → `Install` |
| Maintenance | Technitium DNS Server repository; maintained by Shreyas Zare | Independent DeltaZulu-OU repository; maintained by Zafer Balkan |
| Configuration | Flat schema | Nested sinks and pipeline schema |
| Processing | Direct export | Optional PSL-based domain metadata and static tagging |
| Queue behavior | Capped in-memory queue; excess records are not enqueued while full | Bounded pipeline stages; dropped records are counted and reported |
| Best fit | Simple App Store-managed DNS log export | Enrichment-oriented DNS telemetry and independent feature updates |

Refer to the [DeltaZulu-OU repository](https://github.com/DeltaZulu-OU/LogExporterApp) for current configuration and capabilities. For technical background on the evolution of the two implementations, see [MISP Connector and Log Exporter Apps for Technitium DNS Server Have Moved](https://zaferbalkan.com/technitium-apps/).

The examples above configure either exporter to write newline-delimited JSON query logs to `/var/log/dns/dns_logs.json`, which the remaining Wazuh configuration assumes.

### Logging Settings

Although the main objective is to integrate DNS query logs with Wazuh, it is recommended to fine-tune Technitium's default logging configuration to reduce noise and follow best practices. These settings control Technitium DNS Server's native logging and are separate from the LogExporter file sink configured above.

- Navigate to `Settings` → `Logging` in the Technitium DNS Web UI.

Apply the following configuration:

- Enable Logging To: Select `File` if you also want Technitium DNS Server's native logs written to disk. This setting does not control `/var/log/dns/dns_logs.json`, which is written by LogExporter.
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

Check that the configured LogExporter file exists and contains DNS events:

```bash
ls -l /var/log/dns/dns_logs.json
tail -n 20 /var/log/dns/dns_logs.json
```

You should see DNS events formatted as JSON objects. If `/var/log/dns/dns_logs.json` is created and populated, JSON logging is working and you are ready to integrate it with Wazuh.

If LogExporter fails to write events, check the Technitium DNS Server logs for exporter or I/O errors and verify that the service account has write access to the configured directory and file, as described in the file-output prerequisite for the selected option.

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
  
### Technitium DNS Custom Rules

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

### Tools and repositories

- [Technitium DNS Server LogExporterApp](https://github.com/TechnitiumSoftware/DnsServer/tree/master/Apps/LogExporterApp)
- [DeltaZulu-OU LogExporterApp](https://github.com/DeltaZulu-OU/LogExporterApp)
- [DeltaZulu-OU LogExporterApp releases](https://github.com/DeltaZulu-OU/LogExporterApp/releases/latest)
- [DeltaZulu-OU MispConnectorApp](https://github.com/DeltaZulu-OU/MispConnectorApp)

### Guides and technical background

- [DNS-Level Threat Monitoring with Wazuh and Technitium DNS Server](https://zaferbalkan.com/technitium/)
- [MISP Connector and Log Exporter Apps for Technitium DNS Server Have Moved](https://zaferbalkan.com/technitium-apps/)
- [Creating and running DNS Apps on Technitium DNS Server](https://blog.technitium.com/2021/03/creating-and-running-dns-apps-on.html)
- [Running Technitium DNS Server on Ubuntu Linux](https://blog.technitium.com/2017/11/running-dns-server-on-ubuntu-linux.html)
- [Technitium DNS integration using syslog](https://zaferbalkan.com/technitium/#wazuh-and-technitium-dns-integration-using-syslog)

### Wazuh documentation

- [Wazuh custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
- [Wazuh Centralized configuration](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html)

</details>
