### ESET-Wazuh Integration (Agent-based Deployment)

-----

#### **Table of Contents**

  * [Introduction](https://www.google.com/search?q=%23introduction)
  * [Prerequisites](https://www.google.com/search?q=%23prerequisites)
  * [Initial ESET Configuration](https://www.google.com/search?q=%23initial-eset-configuration)
  * [Installing and Configuring the Integration](https://www.google.com/search?q=%23installing-and-configuring-the-integration)
  * [Integration Steps Summary](https://www.google.com/search?q=%23integration-steps-summary)
  * [Integration Testing](https://www.google.com/search?q=%23integration-testing)

-----

### Introduction

This guide explains how to integrate the ESET PROTECT Platform with Wazuh by deploying the ESET integration application where the Wazuh Agent is installed. Instead of writing ESET detection logs directly to the Wazuh Manager, the integration stores them locally on the endpoint, where the agent collects and forwards them to the Manager. It uses the agent’s built-in queuing, buffering, security, and resilience to network interruptions to prevent event loss. The collected ESET events are indexed and analyzed in the Wazuh Dashboard alongside other security data.

### Prerequisites

Before starting, ensure the following:

  * An active ESET Connect API user account created in the ESET Protect Hub with permissions for integrations.
  * A Wazuh Agent installed on the endpoint where the ESET integration application will run, configured to communicate with your Wazuh Manager.
  * Docker and Docker Compose installed on the endpoint with the agent.
  * Access to the ESET integration application repository.

### Initial ESET Configuration

In the ESET Protect Hub, create an API user with permissions to access ESET detection data. Enable the `Integrations` permission for this user so the application can retrieve detection events via the ESET Public API. Confirm the correct region for your ESET instance, for example: `us`, `eu`, `ca`, `de`, `jpn`.

### Installing and Configuring the Integration

#### Download the Integration Application

Clone the integration repository on the endpoint where the Wazuh Agent is installed:

```bash
git clone --branch 1.2.1 https://github.com/eset/ESET-Integration-Wazuh.git /opt/eset-integration
```

#### Copy the Custom Wazuh Rules

The repository includes `eset_local_rules.xml` with mappings to MITRE ATT\&CK. Copy it to the agent host rules directory so it is synchronized with the Manager:

```bash
cp /opt/eset-integration/eset_local_rules.xml /var/ossec/etc/rules
```

#### Create the Local Log File

Create the file where the integration will write ESET detections:

```bash
touch /var/log/eset_integration.log
```

#### Configure the Wazuh Agent to Monitor the Log File

Edit the agent `ossec.conf` and add the following `localfile` block:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/eset_integration.log</location>
</localfile>
```

#### Configure the .env File

Create `/opt/eset-integration/.env` with your ESET API parameters:

```ini
EP_INSTANCE=yes|no
EI_INSTANCE=yes|no
ECOS_INSTANCE=yes|no
INTERVAL=<polling interval in minutes, min: 3>
INSTANCE_REGION=<region code: us|eu|ca|de|jpn>
USERNAME_INTEGRATION=<ESET API user email>
PASSWORD_INTEGRATION=<ESET API user password>
```

#### Run the Integration Application

Start the integration using Docker Compose:

```bash
docker compose --file /opt/eset-integration/docker-compose.yml up -d
```

### Integration Steps Summary

  * Create the API user in ESET Protect Hub.
  * Clone the integration on the agent endpoint.
  * Copy the custom rules to `/var/ossec/etc/rules`.
  * Create `/var/log/eset_integration.log`.
  * Add the `localfile` block to the agent configuration.
  * Populate `.env` with ESET API credentials and settings.
  * Start the container with Docker Compose.
  * The agent forwards detections to the Wazuh Manager.

### Integration Testing

#### Check Docker Container Logs

```bash
docker logs -f <container_name>
```

#### Check the Local Log File

```bash
tail -n 50 /var/log/eset_integration.log
```

#### Verify in Wazuh Dashboard

1.  Open the Wazuh Dashboard.
2.  Add a filter: `Field` `rule.groups`, `Operator` `is`, `Value` `eset`.
3.  Save the filter to view ingested ESET events.
