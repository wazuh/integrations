#!/bin/bash
# Wazuh health checker – entry point.
#
# Loads the single configuration file and exports every value, so monitoring.py
# and the notifier scripts are all configured from one place. Nothing in this
# file needs editing: put your settings in $CONF instead.
#
# Generate that file with:   ./monitoring.py --init-config

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="${HEALTH_CHECKER_CONF:-/etc/wazuh-health-checker.conf}"
LEGACY_CONF="/etc/health-checker.secrets"

# Export every KEY=VALUE so the notifier scripts inherit the same settings.
# The legacy credentials file is read first, the new one overrides it.
set -a
# shellcheck source=/dev/null
[ -r "$LEGACY_CONF" ] && . "$LEGACY_CONF"
# shellcheck source=/dev/null
[ -r "$CONF" ] && . "$CONF"
set +a

if [ ! -r "$CONF" ] && [ ! -r "$LEGACY_CONF" ]; then
    echo "ERROR: No configuration found at '$CONF'." >&2
    echo "       Run '$SCRIPT_DIR/monitoring.py --init-config' to create it." >&2
    exit 1
fi

# Prefer the Wazuh-embedded Python (3.10+); fall back to the system one.
WAZUH_PY="/var/ossec/framework/python/bin/python3"
if [ -x "$WAZUH_PY" ]; then
    PY="$WAZUH_PY"
else
    PY="$(command -v python3)"
fi

# 1. Monitoring script execution
"$PY" "$SCRIPT_DIR/monitoring.py" "$@" || exit 1

# 2. Notification channels – each one is optional and skipped when absent.
for notifier in slack_notifier.py teams_notifier.py email_notifier.py; do
    [ -f "$SCRIPT_DIR/$notifier" ] && "$PY" "$SCRIPT_DIR/$notifier"
done

exit 0
