import time
from executor import run_command

ALERTS_JSON_PATH = "/var/ossec/logs/alerts/alerts.json"
ALERTS_LOG_PATH = "/var/ossec/logs/alerts/alerts.log"


def alerts_json_exists():
    return (run_command(f"test -f {ALERTS_JSON_PATH} && echo yes || echo no") or "").strip() == "yes"


def alerts_json_age_seconds():
    """Seconds since alerts.json was last modified, or None if it doesn't exist."""
    if not alerts_json_exists():
        return None
    mtime_raw = (run_command(f"stat -c %Y {ALERTS_JSON_PATH}") or "").strip()
    try:
        return int(time.time()) - int(mtime_raw)
    except ValueError:
        return None


def is_alerts_json_fresh(max_age_seconds=300):
    age = alerts_json_age_seconds()
    return age is not None and age <= max_age_seconds


def tail_alerts_json(lines=5):
    return run_command(f"tail -n {lines} {ALERTS_JSON_PATH}") or ""


def tail_alerts_log(lines=100):
    return run_command(f"tail -n {lines} {ALERTS_LOG_PATH}") or ""


def alerts_log_mentions(identifier, lines=200):
    """
    Check the last N lines of alerts.log for a mention of this agent's
    ID/name - used right after restarting an agent as a live test: if the
    resulting check-in event shows up here, the manager is receiving and
    logging that agent's events.
    """
    if not identifier:
        return False
    return identifier.lower() in tail_alerts_log(lines).lower()


def alerts_json_mentions(identifier, lines=200):
    """
    Same idea as alerts_log_mentions(), but checks alerts.json instead -
    this is the file the agent-restart pipeline test actually checks
    against (a matching rule 503 'Wazuh agent started' entry confirms the
    manager received and logged that agent's event).
    """
    if not identifier:
        return False
    return identifier.lower() in tail_alerts_json(lines).lower()
