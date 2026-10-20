"""
Generic systemd service helpers.

Reusable by ANY use case that needs to check or restart a service
(wazuh-indexer, wazuh-manager, wazuh-dashboard, filebeat, etc.) instead of
each use case writing its own run_command("systemctl ...") + sleep loop by
hand.

IMPORTANT: restart/start use "--no-block" so the systemctl command returns
immediately instead of blocking until the service is fully up. For
JVM-based services (like wazuh-indexer) that startup can take a long time,
and a plain blocking "systemctl restart" gives zero feedback while it waits
- it just looks stuck. Firing the command with --no-block and then polling
"is-active" ourselves, with a bounded window, avoids that.
"""

import time
from executor import run_command


def get_service_status(service_name):
    """Return the current systemd status string: 'active', 'inactive', 'failed', etc."""
    return (run_command(f"systemctl is-active {service_name}") or "").strip()


def restart_service_and_wait(service_name, max_attempts=20, delay=3):
    """
    Restart a systemd service and wait for it to actually come back up.
    Returns the final status string once active, or after max_attempts.
    """
    run_command(f"systemctl --no-block restart {service_name}")
    return _poll_until_active(service_name, max_attempts, delay)


def start_service_and_wait(service_name, max_attempts=20, delay=3):
    """Same as restart_service_and_wait, but for starting a stopped service."""
    run_command(f"systemctl --no-block start {service_name}")
    return _poll_until_active(service_name, max_attempts, delay)


def _poll_until_active(service_name, max_attempts, delay):
    status = ""
    for _ in range(max_attempts):
        time.sleep(delay)
        status = get_service_status(service_name)
        if status == "active":
            break
    return status
