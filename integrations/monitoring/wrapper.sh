#!/bin/bash
# Prefer the Wazuh-embedded Python (3.10+); fall back to the system one.
WAZUH_PY="/var/ossec/framework/python/bin/python3"
if [ -x "$WAZUH_PY" ]; then
    PY="$WAZUH_PY"
else
    PY="$(command -v python3)"
fi

# 1. Monitoring script execution
"$PY" /opt/scripts/monitoring.py || exit 1

# 2. Notification channels
"$PY" /opt/scripts/slack_notifier.py
"$PY" /opt/scripts/teams_notifier.py
"$PY" /opt/scripts/email_notifier.py