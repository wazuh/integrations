from executor import run_command
import re


class LogHandler:

    # -----------------------------------------
    # GET INDEXER LOGS
    # Reads from /var/log/wazuh-indexer/wazuh-cluster.log
    # Uses awk to filter lines from the last X hours,
    # then grep to keep only error/warn lines.
    # Fixed: ($1" "$2) compares only the timestamp portion
    # of each line — not the entire line — so filtering
    # works correctly regardless of log content.
    # -----------------------------------------
    @staticmethod
    def get_indexer_logs(hours=2):
        cmd = (
            f"awk -v d1=\"$(date --date='{hours} hours ago' '+%Y-%m-%d %H:%M:%S')\" "
            f"'($1\" \"$2) >= d1' /var/log/wazuh-indexer/wazuh-cluster.log "
            "| grep -i -E 'error|warn'"
        )
        return run_command(cmd) or ""

    # -----------------------------------------
    # GET DASHBOARD LOGS
    # Uses journalctl for the wazuh-dashboard service
    # -----------------------------------------
    @staticmethod
    def get_dashboard_logs(hours=2):
        return run_command(
            f"journalctl -u wazuh-dashboard --since '{hours} hours ago' "
            "| grep -i -E 'error|warn'"
        ) or ""

    # -----------------------------------------
    # CLEAN LOGS
    # Deduplicates lines, strips timestamps for
    # comparison only, returns max 50 unique lines
    # -----------------------------------------
    @staticmethod
    def clean_logs(log_text):
        if not log_text:
            return "(no logs found)"

        lines  = log_text.splitlines()
        seen   = set()
        unique = []

        for line in lines:
            # strip HH:MM:SS for dedup comparison only
            cleaned = re.sub(r"\d{2}:\d{2}:\d{2}", "", line).strip()
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                unique.append(line)   # keep original line for display

        return "\n".join(unique[:50])
