Wazuh - Auth0 Integration

1. Overview
Integrate Auth0 logs into Wazuh by polling the Auth0 Management API. Logs such as successful logins, failed logins, password resets, and suspicious activity will be collected from Auth0 and forwarded to Wazuh for monitoring, alerting, and correlation.
2. Prerequisites
A working Wazuh manager or Wazuh agent configured to collect local log files.


jq is installed on the host (JSON processor).


Access to an Auth0 tenant with administrator permissions.


Ability to run scheduled jobs (cron/systemd timers).

3. Configure Auth0 : Poll the Auth0 Management API Create a Machine-to-Machine (M2M) App in Auth0: In your Auth0 dashboard, register an application (Type: Machine-to-Machine) and authorize it for the Auth0 Management API with the read:logs scope. Save the client_id and client_secret.


Get an Access Token: Use the OAuth client-credentials flow to obtain a JWT. For example:
curl -X POST 'https://<YOUR_TENANT>.auth0.com/oauth/token' \
-H 'Content-Type: application/json' \
-d '{
"client_id":"<YOUR_CLIENT_ID>",
"client_secret":"<YOUR_CLIENT_SECRET>",
"audience":"https://<YOUR_TENANT>.auth0.com/api/v2/",
"grant_type":"client_credentials"
}'


Add instructions on how to generate the Auth
The response JSON contains "access_token".
Auth0 returns up to 100 log entries per request. Use the Link: next URL header to paginate or repeatedly call with the new from log ID as shown in Auth0’s docs. Note that Auth0 only retains logs for a limited period (based on your subscription), so schedule fetches frequently enough to avoid gaps.
Retrieve Log Logs Using the Management API 
Approach One

4. Prepare Polling Script

On the Wazuh manager, create a script file /usr/local/bin/auth0-poll-logs.sh:
#!/bin/bash

# ===== Auth0 Configuration =====
AUTH0_DOMAIN="your-tenant.auth0.com"    # Replace with your Auth0 domain
CLIENT_ID="YOUR_CLIENT_ID"              # Replace with your client ID
CLIENT_SECRET="YOUR_CLIENT_SECRET"      # Replace with your client secret
AUDIENCE="https://${AUTH0_DOMAIN}/api/v2/"
LOG_FILE="/var/log/auth0_logs.json"     # Wazuh will monitor this file
STATE_FILE="/var/log/auth0_last_id.txt" # To remember the last log we fetched

# ===== Get Access Token =====
ACCESS_TOKEN=$(curl -s --request POST \
  --url "https://${AUTH0_DOMAIN}/oauth/token" \
  --header 'content-type: application/json' \
  --data "{
    \"client_id\":\"${CLIENT_ID}\",
    \"client_secret\":\"${CLIENT_SECRET}\",
    \"audience\":\"${AUDIENCE}\",
    \"grant_type\":\"client_credentials\"
  }" | jq -r .access_token)

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" == "null" ]; then
  echo " Failed to get Auth0 token"
  exit 1
fi

# ===== Load last checkpoint =====
if [ -f "$STATE_FILE" ]; then
  LAST_ID=$(cat "$STATE_FILE")
else
  LAST_ID=""
fi

# ===== Fetch Logs from Auth0 =====
RESPONSE=$(curl -s \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  "https://${AUTH0_DOMAIN}/api/v2/logs?from=${LAST_ID}&take=100")

COUNT=$(echo "$RESPONSE" | jq 'length')

if [ "$COUNT" -gt 0 ]; then
  # Append each log entry as one JSON line
  echo "$RESPONSE" | jq -c '.[]' >> "$LOG_FILE"

  # Save last ID for next run
  NEW_LAST_ID=$(echo "$RESPONSE" | jq -r '.[-1]._id')
  echo "$NEW_LAST_ID" > "$STATE_FILE"

  echo "Fetched $COUNT logs. Last ID: $NEW_LAST_ID"
else
  echo "No new logs found."
fi


Make it executable:
chmod 700 /usr/local/bin/auth0-poll-logs.sh


5. Schedule Script
Set up a cron job to poll every 5 minutes (adjust as needed):
*/5 * * * * /usr/local/bin/auth0-poll-logs.sh


This ensures new logs are continuously fetched and appended to /var/log/auth0_logs.json.

6. Configure Wazuh to Read Auth0 Logs
Edit the Wazuh configuration (/var/ossec/etc/ossec.conf) and add:
<localfile>
  <log_format>json</log_format>
  <location>/var/log/auth0_logs.json</location>
</localfile>


Restart Wazuh manager/agent:
systemctl restart wazuh-manager


7. Validate Integration
Generate some events in Auth0 (e.g., failed login attempts).


Check the local log file:
tail -n5 /var/log/auth0_logs.json | jq .

Test decoding in Wazuh: /var/ossec/bin/wazuh-logtest



Approach Two

Write a Script for Auth0 Log Fetching
Create a script, e.g.,/var/ossec/bin/auth0_wodle_fetch.sh.
#!/bin/bash

AUTH0_DOMAIN="your-tenant.auth0.com"
CLIENT_ID="YOUR_CLIENT_ID"
CLIENT_SECRET="YOUR_CLIENT_SECRET"
AUDIENCE="https://${AUTH0_DOMAIN}/api/v2/"
STATE_FILE="/var/ossec/queue/last_auth0_id.txt"

# get token
ACCESS_TOKEN=$(curl -s -H "Content-Type: application/json" \
  -d "{\"client_id\":\"$CLIENT_ID\",\"client_secret\":\"$CLIENT_SECRET\",\"audience\":\"$AUDIENCE\",\"grant_type\":\"client_credentials\"}" \
  "https://${AUTH0_DOMAIN}/oauth/token" | jq -r .access_token)

[ -z "$ACCESS_TOKEN" ] && exit 1

# get last processed id
if [ -f "$STATE_FILE" ]; then
  LAST_ID=$(cat "$STATE_FILE")
else
  LAST_ID=""
fi

# fetch logs
RESPONSE=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://${AUTH0_DOMAIN}/api/v2/logs?from=${LAST_ID}&take=100")

# count logs
COUNT=$(echo "$RESPONSE" | jq 'length' 2>/dev/null)

if [ "$COUNT" -gt 0 ]; then
  # print each log as json line to stdout
  echo "$RESPONSE" | jq -c '.[]'

  # update state
  NEW_LAST_ID=$(echo "$RESPONSE" | jq -r '.[-1]._id')
  echo "$NEW_LAST_ID" > "$STATE_FILE"
fi

Make it Executable:
sudo chmod +x /var/ossec/bin/auth0_wodle_fetch.sh

Configure the command wodle in ossec.conf
Edit the Wazuh manager’s ossec.conf (usually /var/ossec/etc/ossec.conf), add a block inside <wodle>:
<wodle name="command">
  <disabled>no</disabled>
  <tag>auth0-logs</tag>
  <command>/var/ossec/bin/auth0_wodle_fetch.sh</command>
  <interval>1m</interval>     
  <timeout>30</timeout>        
  <ignore_output>no</ignore_output>
  <run_on_start>yes</run_on_start> 
</wodle>

Explanation:
<tag>: a label; log messages from this wodle will have auth0-logs tag.
<command>: path to your script.
<interval>: how often to run. Wodle supports time suffixes like s, m, h. 
<timeout>: max time allowed; if the script runs longer, it's killed. 
<ignore_output>: if set to “no”, the output is sent to Wazuh. If “yes”, output is ignored. 
Restart the Wazuh Manager
sudo systemctl restart wazuh-manager

Command Validation:


Create a rules: nano /var/ossec/etc/rules/auth0_rules.xml
<group name="auth0">
  <rule id="100765" level="5">
    <decoded_as>json</decoded_as>
    <field name="tenant_name">dev-gesy3u41yseebje3</field>
    <description>$(description) and data type "$(type)"</description>
    <options>no_full_log</options>
  </rule>
</group>




8. Screenshots on Wazuh Dashboard:



