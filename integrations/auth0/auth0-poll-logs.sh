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