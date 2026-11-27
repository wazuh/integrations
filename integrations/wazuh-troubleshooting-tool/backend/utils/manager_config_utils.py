import re
from executor import run_command

OSSEC_CONF_PATH = "/var/ossec/etc/ossec.conf"


def get_log_alert_level():
    """Configured log_alert_level as an int, or None if not set/found."""
    raw = run_command(f"grep 'log_alert_level' {OSSEC_CONF_PATH}") or ""
    match = re.search(r"<log_alert_level>\s*(\d+)\s*</log_alert_level>", raw)
    return int(match.group(1)) if match else None


def is_log_alert_level_ok(level=None):
    """
    Alerts with a rule level below log_alert_level are never logged by the
    manager. A value above 15 means most/all alerts get silently dropped
    before they ever reach alerts.json.
    """
    level = get_log_alert_level() if level is None else level
    return level is not None and level <= 15


def set_log_alert_level(value=3):
    """Set log_alert_level in ossec.conf. Caller is responsible for restarting wazuh-manager afterward."""
    replacement = "<log_alert_level>{}<\\/log_alert_level>".format(value)
    cmd = "sed -i 's/<log_alert_level>.*<\\/log_alert_level>/{}/' {}".format(replacement, OSSEC_CONF_PATH)
    run_command(cmd)
    return get_log_alert_level()


def get_jsonout_output_enabled():
    """True if jsonout_output is set to 'yes' (required for alerts.json to be written)."""
    raw = run_command(f"grep 'jsonout_output' {OSSEC_CONF_PATH}") or ""
    match = re.search(r"<jsonout_output>\s*(yes|no)\s*</jsonout_output>", raw, re.IGNORECASE)
    return bool(match and match.group(1).lower() == "yes")


def enable_jsonout_output():
    """Set jsonout_output to yes in ossec.conf. Caller is responsible for restarting wazuh-manager afterward."""
    replacement = "<jsonout_output>yes<\\/jsonout_output>"
    cmd = "sed -i 's/<jsonout_output>.*<\\/jsonout_output>/{}/' {}".format(replacement, OSSEC_CONF_PATH)
    run_command(cmd)
    return get_jsonout_output_enabled()
