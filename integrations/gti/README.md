# Wazuh - Google Threat Intelligence Integration

## Table of Contents

- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Rule Reference](#rule-reference)
- [Monitoring](#monitoring)

## Introduction

This integration enriches Wazuh alerts with threat and vulnerability assessment from Google Threat Intelligence. It’s built on Wazuh’s Integrator framework and the GTI v3 API.

This integration can be broken down into the following steps:

* Wodle script, fetches the IOCs data from the Google Threat Intelligence for the configured Threat Lists IDs and stores them into json structures.
* Integration script
  * Extracts the **IOCs** and/or **Vulnerability** from Wazuh alerts using flexible path detection.
  * Enrich the IOCs, if found within the JSON data structures.
  * If the **realtime** flag is enabled, queries the GTI's respective endpoint to fetch the GTI assessment of that IOC.
  * For File Hashes, if the **mitre_attack** is enabled, it queries the file endpoint(`/api/v3/files/{id}/behaviour_mitre_trees`) for Mitre Attack Info associated with the File Hash.
  * If vulnerability is detected, it queries the **GTI endpoint** (`/api/v3/collections/{id}`) to fetch the related information.
  * Enrichment data includes **GTI Threat Assessment**, **Mitre Attack info** and **Vulnerability information** depending on the alert 
  * Preserves original alert context within(`alert_info`) fields for correlation.
  * Handles API errors gracefully with proper error codes sent back to Wazuh for generating error alerts.
  * Enriched alerts are passed on to the Wazuh indexer.
* Alert rules, will intercept the enriched alerts and generate new alerts which will be displayed on the Wazuh UI

## Prerequisites

* Wazuh Manager (v4.x) running
* Python 3.10+ on Wazuh Manager
* Network connectivity from Wazuh Manager to Google Threat Intel Platform
* Root access on the Wazuh server
* Access to `/var/ossec/` for integration files.


## Installation

**Note:** This integration uses two python scripts: an ingestion script (along with a config .ini file) to fetch IOCs from GTI platform and an integration script (along with a shell wrapper) that performs the enrichment logic.

**Ingestion Script** (`wodles/gti-sync.py`) : To fetch IOCs from GTI platform and create JSON data.

**Config file** (`wodles/gti-config.ini`) : Config file to add configuration for ingestion script. 
  
**Integration Script** (`integration/custom-gti.py`) : Script that performs the enrichment logic.

**Shell Wrapper** (`integration/custom-gti`) : Shell script wrapper called by Wazuh.


1. **Clone the repository**:
    ```sh
    git clone https://github.com/yourusername/integrations-gti.git
    cd integrations-gti
    ```
2. Set `WAZUH_HOME` to (`/var/ossec`)

```bash
sudo WAZUH_HOME=/var/ossec
```

### One-Click Install (Recommended)

3. Set `SCRIPT_DIR` to absolute path where you cloned the repository:

```bash
sudo SCRIPT_DIR=/var/GTI
```

4. Execute the `install.sh`:

```bash
sudo bash install.sh
```

The installer prompts for:
- GTI API Key
- Fetch interval in minutes (wodle interval)

Then it automatically:
- Install the python packages using requirements.txt.
- Copies all files to correct Wazuh directories
- Sets permissions (`root:wazuh`, `750`)
- Creates configuration with your credentials
- Injects wodle + integration blocks into `ossec.conf`
- Restarts Wazuh Manager


### Manual Install

3. **Install dependencies**:
    ```sh
    pip install -r requirements.txt
    ```
4. **Place the [Ingestion files](wodles/) to the Wazuh wodles directory**:
    ```sh
    sudo mkdir -p /var/ossec/wodles/gti
    sudo cp GTI/wodles/ /var/ossec/wodles/gti/

    # Set permissions
    chmod 750 /var/ossec/wodles/gti/
    chown root:wazuh /var/ossec/wodles/gti/
    ```
   
5. **Place the [Integration files](integration/) in `/var/ossec/integrations/`**:

    ```bash
    # Copy the Python script and shell wrapper
    cp GTI/integration/ /var/ossec/integrations/

    # Set permissions
    chmod 750 /var/ossec/integrations/custom-gti*
    chown root:wazuh /var/ossec/integrations/custom-gti*
    ```
6. **Place the [GTI rules](ruleset/rules/1001-gti_rules.xml) in Wazuh custom rules directory**:

    ```bash
    # Copy the rules file
    cp GTI/ruleset/rules/1001-gti_rules.xml /var/ossec/etc/rules/

    # Set permissions
    chmod 750 /var/ossec/etc/rules/1001-gti_rules.xml
    chown root:wazuh /var/ossec/etc/rules/1001-gti_rules.xml


## Configuration

1. **Configure the [Ingestion Script Config file](wodles/gti-config.ini)**:
    - Configurable fields are
      - api_key = Replace the `your_gti_api_key_here` with the `GTI API KEY`.
      - threat_list_ids = comma(,) separated list of Threat List ID(s)
        - Possible values : 
        ```
        ransomware, malicious-network-infrastructure, malware, threat-actor, trending, mobile, osx, linux, iot, cryptominer, phishing, first-stage-delivery-vectors, vulnerability-weaponization, infostealer
        ```
      - severities = comma(,) separated list of IOC Severity level(s)
        - Possible values :
        ```
        SEVERITY_NONE, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_UNKNOWN
        ```
      - verdicts = comma(,) separated list of IOC Verdict level(s)
        - Possible values:
        ```
        VERDICT_BENIGN, VERDICT_UNDETECTED, VERDICT_SUSPICIOUS, VERDICT_MALICIOUS, VERDICT_UNKNOWN
        ```
      - threat_score = Minimum threat score for fetching IOCs.
        - Possible value: number between 0 and 100
    - Example:
        ```ini
        [gti]
        api_key = your_gti_api_key_here
        base_url = https://www.virustotal.com/api/v3
        checkpoint_file = gti-checkpoint.json
        [filters]
        threat_list_ids = comma(,) separated list of Threat List IDs
        severities = comma(,) separated list of IOC Severity levels
        verdicts =comma(,) separated list of IOC Verdict levels
        threat_score = threat score between 0 and 100
        [WAZUH]
        json_dir = /var/ossec/integrations/gti
        [OUTPUT]
        ip_list = malicious_ips
        domain_list = malicious_domains
        url_list = malicious_urls
        hash_list = malicious_hashes
        [LOGGING]
        log_file = gti_ioc_fetcher.log
        ```

2. **Wodle Configuration** :

    **Note**: `<interval>` property is used to set the frequency for the Ingestion script execution. Its recommended to be kept in multiple of hours (Min. interval: 1h).
    ```
    <wodle name="command">  
        <disabled>no</disabled>
        <tag>gti-sync</tag>
        <command>/var/ossec/framework/python/bin/python3.10 /var/ossec/wodles/gti/gti_sync.py</command>
        <interval>1h</interval>
        <run_on_start>yes</run_on_start>
        <timeout>300</timeout>
    </wodle>
    ```
3. **Integration Config** :

Add the following block to `/var/ossec/etc/ossec.conf`. The `<name>` must match the shell script wrapper.

**Configurable options**
   1. `mitre_attack` : Set the flag to true, to enable the integration to fetch **mitre_attack_info** related to the File Hash. (Default `true`)
   2. `realtime` : Set the flag to true, to enable the integration to fetch **gti_assessment** related to the IOC via REST API to the GTI platform instead of CDB List. (Default `false`)
   3. `log_level` : Set the logging level for the integration via this option. Possible values `INFO, DEBUG, ERROR` (Default `INFO`)
   4. `ip_fields` : Optional. Custom set of fields which may contain IP Addresses and referenced for Enrichment
   5. `domain_fields` : Optional. Custom set of fields which may contain Domain and referenced for Enrichment
   6. `url_fields` : Optional. Custom set of fields which may contain URL Addresses and referenced for Enrichment
   7. `filehash_fields` : Optional. Custom set of fields which may contain a File Hash and referenced for Enrichment
   8. `vuln_fields` : Optional. Custom set of fields which may contain Vulnerability ID and referenced for Enrichment
   
**_\<ioc\>\_fields_** : This option enables the integration to check for a specific IOC in the specified set of comma(,) separated custom fields apart from the predefined set of fields for each IOC. 

  
    <integration>
        <name>custom-gti</name>
        <api_key>GTI_API_KEY</api_key> <!-- Replace with your GTI API key -->
        <alert_format>json</alert_format>
        <options>
        {"mitre_attack": true, "realtime": false, "log_level": "INFO", "ip_fields":"src_ip,ip_addresses", "domain_fields":"domain", "url_fields":"", "filehash_fields":"", "vuln_fields":"cveid,cve_id"}
        </options>
    </integration>

## Rule Reference

| Rule ID | Level | Description |
|---------|-------|-------------|
| 111111  |   0   | Base GTI event. |
| 111112  |   0   | GTI event without any enrichment.|
| 111113  |   6   | GTI event with vulnerability enrichment. |
| 111114  |   6   | GTI event with error code during vulnerability enrichment. |
| 111115  |   6   | GTI event with error description message during vulnerability enrichment.|
| 111119  |   6   | GTI event with IOC enrichment.|

## Monitoring

```bash
# Ingestion script logs
tail -f /var/ossec/wodles/gti/gti-sync.log

# Integration logs
tail -f /var/ossec/logs/gti-integration.log

# Check alerts
grep gti_assessment /var/ossec/logs/alerts/alerts.json | tail

# GTI IOCs Ingestion Checkpoint file
cat /var/ossec/wodles/gti/checkpoint.json
```
