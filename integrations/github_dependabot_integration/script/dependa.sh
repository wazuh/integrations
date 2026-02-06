#!/usr/bin/env bash

# ==============================
# GitHub Dependabot Fetch Script
# ==============================

# GitHub repository and token details
ORG="<ORG_NAME>"
REPO="<REPO_NAME>"
TOKEN="github_pat_<TOKEN>"

# Log directory and file naming with hourly timestamp
LOG_DIR="/var/log/dependabot"
CURRENT_HOUR=$(date +'%Y%m%d_%H')
LOG_FILE="$LOG_DIR/dependabot_${CURRENT_HOUR}.json"

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

echo "[INFO] Fetching Dependabot alerts for $ORG/$REPO at $(date)"

# Fetch Dependabot alerts from GitHub API (fixed URL)
curl -s -X GET \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "https://api.github.com/repos/$ORG/$REPO/dependabot/alerts" \
  -o "$LOG_FILE"

# Validate that the response is an array before converting
if [ -s "$LOG_FILE" ]; then

  # Check response type (must be array)
  if jq -e 'type == "array"' "$LOG_FILE" >/dev/null 2>&1; then

    # Convert array → NDJSON (1 alert per line)
    jq -c --arg time "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
      '.[] | {fetched_at: $time} + .' "$LOG_FILE" \
      > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "$LOG_FILE"

    echo "[INFO] NDJSON alerts saved to $LOG_FILE"

  else
    echo "[ERROR] GitHub did not return an array. Raw output:"
    cat "$LOG_FILE"
  fi

else
  echo "[WARNING] Empty response received, check your token or API access."
fi

# Delete logs older than 1 hour to manage storage
find "$LOG_DIR" -type f -name "dependabot_*.json" ! -name "dependabot_${CURRENT_HOUR}.json" -delete

echo "[INFO] Cleanup complete — only current hour log retained."
echo "[DONE] Execution finished at $(date)"

