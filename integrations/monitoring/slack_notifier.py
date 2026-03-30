#!/var/ossec/framework/python/bin/python3
# Slack notification sender
# Wazuh Inc. 
# Nicolás Curioni <nicolas.curioni@wazuh.com>
import json
import requests
import socket
import sys
# === CONFIGURACIÓN ===
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/....../......"
#N8N_WEBHOOK_URL = "https://tu-instancia-n8n.com/webhook/...."
LOG_PATH = "/var/log/health-checker.json"
HOSTNAME = socket.gethostname()


def _format_agents_msg(details: dict) -> str:
    """Build a bullet-point agent summary from the agents check payload."""
    total       = details.get('total', 0)
    active      = details.get('active', 0)
    active_pct  = details.get('active_pct', 0.0)
    disc        = details.get('disconnected', 0)
    disc_pct    = details.get('disconnected_pct', 0.0)
    pending     = details.get('pending', 0)
    pending_pct = details.get('pending_pct', 0.0)
    never       = details.get('never_connected', 0)
    never_pct   = details.get('never_connected_pct', 0.0)
    return (
        f"• Total: {total}\n"
        f"• Active: {active} ({active_pct}%)\n"
        f"• Disconnected: {disc} ({disc_pct}%)\n"
        f"• Pending: {pending} ({pending_pct}%)\n"
        f"• Never connected: {never} ({never_pct}%)"
    )


def _get_environment_identity(checks: dict) -> tuple[str, str]:
    """Return manager version and UUID from manager_api check payload."""
    manager_api = checks.get('manager_api', {})
    version = manager_api.get('manager_version') or "unknown"
    uuid = manager_api.get('manager_uuid') or "unknown"
    return version, uuid


def send_notifications():
    try:
        # 1. Read last log line
        with open(LOG_PATH, 'r') as f:
            lines = f.readlines()
            if not lines:
                print("Empty log file")
                return
            last_line = lines[-1].strip()
            
        # 2. JSON parsing
        data = json.loads(last_line)
        all_checks = data.get('checks', {})
        manager_version, manager_uuid = _get_environment_identity(all_checks)
        issues = []

        # 3. Checks analysis
        for check_id, details in all_checks.items():
            # Agent check always include information
            if check_id == 'agents' and details.get('total') is not None:
                msg = _format_agents_msg(details)
                issues.append({
                    "name": "Agent Summary",
                    "status": details.get('status', 'OK').upper(),
                    "message": msg
                })
                continue


            if details.get('notify') is not True:
                continue

            msg = details.get('details') or details.get('issues') or "Review configuration"
            if isinstance(msg, list):
                msg = "\n".join([f"• {m}" for m in msg])

            issues.append({
                "name": check_id.replace('_', ' ').title(),
                "status": details.get('status', 'WARNING').upper(),
                "message": msg
            })

        if not issues:
            print("No problems that need attention were found.")
            return

        # 4. Slack payload
        slack_payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"🚨 Wazuh Health Alert: {HOSTNAME}"}
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*Environment version:* `{manager_version}`\n"
                            f"*Environment UUID:* `{manager_uuid}`"
                        )
                    }
                },
                {"type": "divider"}
            ]
        }

        # First warnings/errors, then agent summary
        alerts   = [i for i in issues if i['status'] != 'OK']
        info     = [i for i in issues if i['status'] == 'OK']
        ordered  = sorted(alerts, key=lambda x: x['status']) + info

        for issue in ordered:
            if issue['status'] == 'ERROR':
                emoji = "🔴"
            elif issue['status'] == 'WARNING':
                emoji = "⚠️"
            else:
                emoji = "✅"

            slack_payload["blocks"].append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{emoji} *{issue['name']}* | `{issue['status']}`\n{issue['message']}"
                }
            })

        # 5. Send to Slack
        resp = requests.post(SLACK_WEBHOOK_URL, json=slack_payload, timeout=10)

        # A n8n 
        # requests.post(N8N_WEBHOOK_URL, json={
        #     "hostname": HOSTNAME,
        #     "status": "issues_detected",
        #     "report": data
        # }, timeout=10)

        print(f"✅ Notification sent: {len(alerts)} alert(s) found.")

    except Exception as e:
        print(f"❌ Error in the process: {e}")


if __name__ == "__main__":
    send_notifications()
