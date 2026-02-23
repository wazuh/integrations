# Sentinel One integration

## Description
This integration is used to retrieve logs from SentinelOne API. The API provides logs in JSON format, which means the inbuilt Wazuh JSON decoder can easily decode the logs without the need for custom decoders. Another advantage of the API method is that it provides richer logs than that provided by the syslog alerts.

## Requirements
- Access to SentinelOne UI
- SentinelOne API key

## Configurations:

### SentinelOne
1. Navigate to SETTINGS > USERS > Service Users.
2. Click on the Actions dropdown menu and select Create New Service User.
3. Set appropriate values for the Name, Description, and Expiration Date fields and click Next:
4. Select the Scope of Access for the user. The Account Scope of Access is valid for the entire SentinelOne cloud console account while the Site Scope of Access is only valid for a particular site under the SentinelOne cloud console account.
5. Select the Viewer permission then click Create User then input your 2FA code.
6. Copy the generated API token.

### Wazuh manager
1. Copy the *sentinel_one.py* script to `/var/ossec/integrations/` folder in your manager to connect to the SentinelOne API and retrieve alerts.
Replace the <API_KEY> and <MANAGEMENT_CONSOLE_URL> variables with the appropriate values.
The <MANAGEMENT_CONSOLE_URL> refers to your unique URL used to access the SentinelOne cloud console, for example, my-console.sentinelone.net.

2. Set the ownership and permissions of the ``/var/ossec/integrations/sentinel_one.py`` file.
```
chown root:wazuh /var/ossec/integrations/sentinel_one.py
chmod 750 /var/ossec/integrations/sentinel_one.py
```
3. Add the following configuration to the <ossec_config> block of the `/var/ossec/etc/ossec.conf` local configuration file to automate the execution of the script.
```
<wodle name="command">
  <disabled>no</disabled>
  <command>/var/ossec/framework/python/bin/python3 /var/ossec/integrations/sentinel_one.py</command>
  <interval>1m</interval>
  <ignore_output>yes</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
</wodle>

<localfile>
  <log_format>json</log_format>
  <location>/var/log/sentinelone.json</location>
</localfile>
```
4. Create the rules for SentinelOne logs. You can find rules in `/content/ruleset/SentinelOne/` of this repository

6. Restart the wazuh-manager service:
`systemctl restart wazuh-manager`

More information: https://wazuh.com/blog/integrating-sentinelone-xdr-with-wazuh/
 
