# Incident.io integration

## Introduction

This repository provides a small Python integration script that takes **Wazuh JSON alerts** and forwards them to **incident.io** using an inbound webhook.

## How it works

* Wazuh triggers the script on matching alerts.
* The script:

  * Reads the alert JSON file provided by Wazuh.
  * Maps Wazuh fields into an incident.io payload (title, description, metadata).
  * Posts the result to your incident.io **webhook URL**.

## Installation

1. **Copy [this](incidentio) bash script** to your Wazuh manager under the integrations folder:

   ```
   vim /var/ossec/integrations/custom-incidentio
   ```

2. **Copy [this](incidentio.py) python script** to your Wazuh manager under the integrations folder:

   ```
   vim /var/ossec/integrations/custom-incidentio.py
   ```

3. **Set executable permissions**:

   ```bash
   sudo chmod 750 /var/ossec/integrations/custom-incidentio*
   sudo chown root:wazuh /var/ossec/integrations/custom-incidentio*
   ```

## Configuration

1. **Add (or edit) an integration block** for the integration in the Wazuh `ossec.conf` file:

    ```xml
    <integration>
    <name>custom-incidentio</name>
    <hook_url>https://api.incident.io/v1/webhooks/XXXXXXXXXXXX</hook_url>
    <level>3</level>                 <!-- minimum rule level to trigger, adjust to preference -->
    <alert_format>json</alert_format>
    </integration>
    ```

    * **`<name>custom-incidentio</name>`**: Must remain `custom-incidentio` so Wazuh invokes the script file named `custom-incidentio`.
    * **`<hook_url>`**: Your **incident.io** inbound webhook URL.
    * **`<level>`**: Only alerts with `rule.level >= level` trigger the integration.
    * **`<alert_format>json</alert_format>`**: Required as this script expects JSON.

2. **Restart the manager to apply**:

    ```bash
    systemctl restart wazuh-manager
    ```

## Logs
The script logs its activity to `/var/ossec/logs/integrations.log`. Check this file for any errors or information about the script's execution. CrowdStrike Falcon detection events will be processed by Wazuh and can be viewed in the Wazuh dashboard.