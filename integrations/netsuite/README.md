# NetSuite-Wazuh Integration

## Table of Contents
* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Sources](#sources)

## Introduction
NetSuite is an AI-powered, cloud-based Enterprise Resource Planning (ERP) (ERP) software suite by Oracle, offering a single, integrated system for managing core business processes like financials, CRM, e-commerce, inventory, and more, helping businesses streamline operations, gain real-time visibility, and accelerate growth from any device. 

## Prerequisites
Valid Netsuite credentials:
- CLIENT_ID
- CLIENT_SECRET
- TOKEN_ID
- TOKEN_SECRET

## Integration Steps
### Add the integration script
- Copy the `custom-netsuite.py` script to `/var/ossec/integrations/` folder of one of your Wazuh manager/agent nodes.
- Edit the script to set the correct credentials (`CLIENT_ID`, `CLIENT_SECRET`, `TOKEN_ID` and `TOKEN_SECRET` variables)
- Set the permissions and ownership:
```
chown root:wazuh /var/ossec/integrations/custom-netsuite.py
chmod 750 /var/ossec/integrations/custom-netsuite.py
```

### Wazuh manager configuration
- Add the following to the configuration of the manager/agent where you copied the integration script:
```
  <wodle name="command">
      <tag>NetSuite integration</tag>
      <command>/PATH/TO/python3 /PATH/TO/custom-netsuite.py</command>
      <interval>10m</interval>
      <run_on_start>no</run_on_start>
      <ignore_output>yes</ignore_output>
  </wodle>

  <localfile>
    <log_format>json</log_format>
    <location>/var/log/netsuite_logs.json</location>
  </localfile>
```
The script will  fetch the new logs every time it runs and write them to the file: `/var/log/netsuite_logs.json`

### Add rules
- In Wazuh Dashboard go to Server Management > Rules > Add new rules file. Name it `netsuite-rules.xml`, add the content of netsuite-rules.xml and save.
- Restart the Wazuh Cluster to apply the changes.

## Integration testing
Once the configuration is done, the integration will run after 10 minutes and the alerts will appear on the dashboard.
<img width="1352" height="533" alt="image" src="https://github.com/user-attachments/assets/85cd15a8-ff41-48fc-aabd-c4c593102639" />


## Sources
- [https://docs.rapid7.com/insightidr/log-search-api/#tag/Logs-and-Log-Sets/operation/getLogs](https://docs.oracle.com/en/cloud/saas/netsuite/ns-online-help/section_157373386674.html)
- https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html
- https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html
- https://wazuh-support.atlassian.net/wiki/spaces/OKB/pages/230195210/How+to+integrate+third-party+solutions+with+Wazuh
