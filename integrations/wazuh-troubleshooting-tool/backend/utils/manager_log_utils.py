import time
from executor import run_command

OSSEC_LOG_PATH = "/var/ossec/logs/ossec.log"


def tail_manager_log(lines=200):
    """Raw last N lines of ossec.log, no filtering."""
    return run_command(f"tail -n {lines} {OSSEC_LOG_PATH}") or ""


def get_manager_log_errors(lines=200):
    """Last N lines of ossec.log filtered to error/warn only."""
    return run_command(f"tail -n {lines} {OSSEC_LOG_PATH} | grep -i -E 'error|warn'") or ""


def has_manager_log_errors(lines=200):
    """True/False, so callers don't have to test truthiness of the string themselves."""
    return bool(get_manager_log_errors(lines).strip())


def manager_log_age_seconds():
    """Seconds since ossec.log was last written to, or None if the file doesn't exist."""
    exists = (run_command(f"test -f {OSSEC_LOG_PATH} && echo yes || echo no") or "").strip()
    if exists != "yes":
        return None
    mtime_raw = (run_command(f"stat -c %Y {OSSEC_LOG_PATH}") or "").strip()
    try:
        return int(time.time()) - int(mtime_raw)
    except ValueError:
        return None


def get_manager_disk_usage():
    """`df -h` for the manager's data directory - checked when the pipeline test
    (restarting an agent and looking for its event) comes back empty, since a
    full disk on the manager is a common silent cause of that."""
    return run_command("df -h /var/ossec") or ""
