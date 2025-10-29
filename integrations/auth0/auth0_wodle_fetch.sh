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