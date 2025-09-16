# Rapid7-Wazuh Integration

## Table of Contents
* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Sources](#sources)

## Introduction
Rapid7 is a unified, cloud-based platform that provides visibility, analytics, and automation across an organization's entire IT environment, from the endpoint to the cloud. 
The integration with Wazuh helps organizations to view and analyze Rapid7 alerts from the Wazuh console.

## Prerequisites
- A valid Rapid7 API key with Log Search and SIEM Logs Export permissions.
- The region where the logs are stored.

## Integration Steps
### Add the integration script
- Copy the `custom-rapid7.py` script to `/var/ossec/integrations/` folder of one of your Wazuh manager nodes.
- Edit the script to set the correct API key and region (`API_KEY` and `REGION` variables)
- Set the permissions and ownership:
```
chown root:wazuh /var/ossec/integrations/custom-rapid7.py
chmod 750 /var/ossec/integrations/custom-rapid7.py
```

### Wazuh manager configuration
- Add the following to the configuration of the manager where you copied the integration script:
```
<wodle name="command">
      <tag>Rapid7 integration</tag>
      <command>/var/ossec/framework/python/bin/python3 /var/ossec/integrations/custom-rapid7.py</command>
      <interval>5m</interval>
      <run_on_start>no</run_on_start>
      <ignore_output>yes</ignore_output>
  </wodle>
```
The script will run every 5 minutes and fetch the logs generated during the last 5 minutes.

### Add decoders and rules
- In Wazuh Dashboard go to Server Management > Decoderss > Add new decoders file. Name it `rapid7-decoders.xml`, add the content of rapid7-decoders.xml and save.
- In Wazuh Dashboard go to Server Management > Rules > Add new rules file. Name it `rapid7-rules.xml`, add the content of rapid7-rules.xml and save.
- Restart the Wazuh Cluster to apply the changes.

## Integration testing
Once the configuration on the manager is done, the integration will run after 5 minutes and the alerts will appear on the dashboard.
<img width="1340" height="602" alt="image" src="https://github.com/user-attachments/assets/fc1c354d-b893-42ca-95bd-4bcf37039d85" />

## Sources
- https://docs.rapid7.com/insightidr/log-search-api/#tag/Logs-and-Log-Sets/operation/getLogs
- https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html
