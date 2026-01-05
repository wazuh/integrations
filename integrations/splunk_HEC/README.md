# Wazuh-Splunk_HEC Integration

## Table of Contents
* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Sources](#sources)

## Introduction
Splunk HTTP Event Collector (HEC) is a fast, token-based method for sending application logs and events directly to Splunk over HTTP/HTTPS, ideal for developers needing to get data from apps, mobile devices, or IoT without a full Splunk forwarder. It uses unique tokens for secure authentication, allowing apps to send data in various formats (like JSON or raw) to your Splunk Enterprise or Cloud deployment, simplifying data ingestion for custom applications. 
This integration can be adapted to forward logs to any other HEC.

## Prerequisites
- HEC token
- HEC endpoint

## Integration Steps
### Add the integration script
- Copy the `custom-splunk_hec.py` script to `/var/ossec/integrations/` folder of all your manager nodes.
- Edit the script to set the correct values for `s_protocol`, `s_host`, `s_port`, `s_endpoint` and `TOKEN` variables.
- Set the permissions and ownership:
```
chown root:wazuh /var/ossec/integrations/custom-splunk_hec.py
chmod 750 /var/ossec/integrations/custom-splunk_hec.py
```

### Wazuh manager configuration
- Add the following to the configuration of your managers:
```
<integration>
  <name>custom-splunk_hec.py</name>
  <rule_id>5760</rule_id>>
  <alert_format>json</alert_format>
</integration>
```
The integration will run only for alerts triggered by the rule 5760. You can update the configuration according to your needs.
Restart the Wazuh-manager service after applying the configuration.

## Integration testing
After generating an alert from the configured rule. You will see the alert on Splunk dashboard.
<img width="1095" height="574" alt="image" src="https://github.com/user-attachments/assets/87b5c207-d8a7-4e7b-97cd-f30ea97cd7cc" />


## Sources
- https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html
- [https://wazuh-support.atlassian.net/wiki/spaces/OKB/pages/230195210/How+to+integrate+third-party+solutions+with+Wazuh](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.2/get-data-with-http-event-collector/http-event-collector-rest-api-endpoints)
- https://dev.splunk.com/enterprise/docs/devtools/httpeventcollector/
