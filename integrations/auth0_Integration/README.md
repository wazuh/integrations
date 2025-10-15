# Wazuh - Auth0 Integration

## Table of Contents

- <a href="#overview">Overview</a>
- <a href="#prerequisites">Prerequisites</a>
- <a href="#confauth0">Configure Auth0</a>
- <a href="#approach1">Approach One</a>
- <a href="#readauth0">Configure Wazuh to Read Auth0 Logs</a>
- <a href="#validateint">Validate Integration</a>
- <a href="#approach2" >Approach Two</a>
- <a href="#createrule" >Create rule</a>
- <a href="#visualization">Screenshots on Wazuh Dashboard</a>


## <h2 id="overview" >Overview</h2>

Integrate Auth0 logs into Wazuh by polling the Auth0 Management API. Logs such as successful logins, failed logins, password resets, and suspicious activity will be collected from Auth0 and forwarded to Wazuh for monitoring, alerting, and correlation.

## <h2 id="prerequisites" >Prerequisites</h2>

1. A working Wazuh manager or Wazuh agent configured to collect local log files.
2. jq is installed on the host (JSON processor).
3. Access to an Auth0 tenant with administrator permissions.
4. Ability to run scheduled jobs (cron/systemd timers).

## <h2 id="confauth0" >Configure Auth0</h2>

**Poll the Auth0 Management API Create a Machine-to-Machine (M2M) App in Auth0**: In your Auth0 dashboard, register an application (Type: **Machine-to-Machine**) and authorize it for the Auth0 Management API with the `read:logs` scope. Save the `client_id` and `client_secret`.

<img width="400" height="600" src="https://github.com/wazuh/integrations/blob/Harry4share-auth0-integration/integrations/auth0_Integration/Screenshots/cerateapp.jpg" />
<img width="400" height="600" src="https://github.com/wazuh/integrations/blob/Harry4share-auth0-integration/integrations/auth0_Integration/Screenshots/m2mapp.jpg" />

## <h3>Get an Access Token</h3> 
Use the OAuth client-credentials flow to obtain a JWT. For example:
```
curl -X POST 'https://<YOUR_TENANT>.auth0.com/oauth/token' \
-H 'Content-Type: application/json' \
-d '{
"client_id":"<YOUR_CLIENT_ID>",
"client_secret":"<YOUR_CLIENT_SECRET>",
"audience":"https://<YOUR_TENANT>.auth0.com/api/v2/",
"grant_type":"client_credentials"
}'
```

Add instructions on how to generate the Auth

<img width="1000" height="300" src="https://github.com/wazuh/integrations/blob/Harry4share-auth0-integration/integrations/auth0_Integration/Screenshots/genauth.jpg" />

The response JSON contains `"access_token"`.

Auth0 returns up to 100 log entries per request. Use the Link: next URL header to paginate or repeatedly call with the new from log ID as shown in Auth0’s docs. Note that Auth0 only retains logs for a limited period (based on your subscription), so schedule fetches frequently enough to avoid gaps.

[Retrieve Log Logs Using the Management API](https://auth0.com/docs/deploy-monitor/logs/retrieve-log-events-using-mgmt-api)

## <h2 id="approach1" >Approach One</h2>

## <h3>Prepare Polling Script</h3>

On the Wazuh manager, create a [bash script](auth0-poll-logs.sh) file at `/usr/local/bin/auth0-poll-logs.sh`:

## <h3>Make it executable:</h3>
``chmod 700 /usr/local/bin/auth0-poll-logs.sh``

## <h3>Schedule Script</h3>

Set up a cron job to poll every 5 minutes (adjust as needed):

`*/5 * * * * /usr/local/bin/auth0-poll-logs.sh`

This ensures new logs are continuously fetched and appended to `/var/log/auth0_logs.json`.

## <h2 id="readauth0" >Configure Wazuh to Read Auth0 Logs</h2>

Edit the Wazuh configuration (`/var/ossec/etc/ossec.conf`) and add:
```
<localfile>
  <log_format>json</log_format>
  <location>/var/log/auth0_logs.json</location>
</localfile>
```

<h3>Restart Wazuh manager/agent:</h3>

`systemctl restart wazuh-manager`

## <h2 id="validateint" >Validate Integration</h2>

Generate some events in Auth0 (e.g., failed login attempts).

Check the local log file:

`tail -n5 /var/log/auth0_logs.json | jq .`

Test decoding in Wazuh: `/var/ossec/bin/wazuh-logtest`

<img width="1000" height="800" src="https://github.com/wazuh/integrations/blob/Harry4share-auth0-integration/integrations/auth0_Integration/Screenshots/validateint.jpg" />

## <h2 id="approach2" >Approach Two</h2>

<h3>Prepare a Script to fetch Auth0 Log</h3>

On the Wazuh Manager, Create a [bash script](auth0_wodle_fetch.sh), e.g.,`/var/ossec/bin/auth0_wodle_fetch.sh`.

<h3>Make it Executable:</h3>

`sudo chmod +x /var/ossec/bin/auth0_wodle_fetch.sh`

<h3>Configure the command wodle in `ossec.conf`</h3>

Edit the Wazuh manager’s `ossec.conf` (usually `/var/ossec/etc/ossec.conf`), add a block inside `<wodle>`:
```
<wodle name="command">
  <disabled>no</disabled>
  <tag>auth0-logs</tag>
  <command>/var/ossec/bin/auth0_wodle_fetch.sh</command>
  <interval>1m</interval>     
  <timeout>30</timeout>        
  <ignore_output>no</ignore_output>
  <run_on_start>yes</run_on_start> 
</wodle>
```
<h3>Explanation:</h3>

- `<tag>`: a label; log messages from this wodle will have `auth0-logs` tag.
- `<command>`: path to your script.
- `<interval>`: how often to run. Wodle supports time suffixes like `s, m, h`. 
- `<timeout>`: max time allowed; if the script runs longer, it's killed. 
- `<ignore_output>`: if set to `“no”`, the output is sent to Wazuh. If `“yes”`, output is ignored. 

<h3>Restart the Wazuh Manager</h3>

`sudo systemctl restart wazuh-manager`

Command Validation:

<img width="800" height="400" src="https://github.com/wazuh/integrations/blob/Harry4share-auth0-integration/integrations/auth0_Integration/Screenshots/commandValidation.jpg" />

## <h2 id="createrule" >Create rule:</h2>

`nano /var/ossec/etc/rules/auth0_rules.xml`

```
<group name="auth0">
  <rule id="100765" level="5">
    <decoded_as>json</decoded_as>
    <field name="tenant_name">dev-gesy3u41yseebje3</field>
    <description>$(description) and data type "$(type)"</description>
    <options>no_full_log</options>
  </rule>
</group>
```
<img width="800" height="400" src="https://github.com/wazuh/integrations/blob/Harry4share-auth0-integration/integrations/auth0_Integration/Screenshots/ruleValidation.jpg" />


## <h2 id="visualization" >Screenshots on Wazuh Dashboard</h2>

<img width="800" height="600" src="https://github.com/wazuh/integrations/blob/Harry4share-auth0-integration/integrations/auth0_Integration/Screenshots/DashboardVisualization.jpg" />
<img width="800" height="400" src="https://github.com/wazuh/integrations/blob/Harry4share-auth0-integration/integrations/auth0_Integration/Screenshots/DashboardVisualization2.jpg" />
<img width="800" height="1000" src="https://github.com/wazuh/integrations/blob/Harry4share-auth0-integration/integrations/auth0_Integration/Screenshots/DashboardVisualization3.jpg" />
<img width="800" height="1000" src="https://github.com/wazuh/integrations/blob/Harry4share-auth0-integration/integrations/auth0_Integration/Screenshots/DashboardVisualization4.jpg" />





















