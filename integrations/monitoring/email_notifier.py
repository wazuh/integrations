#!/var/ossec/framework/python/bin/python3
# SMTP notification sender
# Wazuh Inc.
# Nicolás Curioni <nicolas.curioni@wazuh.com>
import json
import smtplib
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# === SMTP CONFIGURATION ===
SMTP_SERVER  = "smtp.gmail.com"
SMTP_PORT    = 587
SMTP_USER    = "<SENDER_EMAIL>"
SMTP_PASS    = "<APP_PASSWORD>"
DESTINATARIO = "<RECEIPIENT_EMAIL>"
LOG_PATH     = "/var/log/health-checker.json"
HOSTNAME     = socket.gethostname()


def _format_agents_msg_html(details: dict) -> str:
    """Build an HTML bullet-point agent summary from the agents check payload."""
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
        f"• Total: {total}<br>"
        f"• Active: {active} ({active_pct}%)<br>"
        f"• Disconnected: {disc} ({disc_pct}%)<br>"
        f"• Pending: {pending} ({pending_pct}%)<br>"
        f"• Never connected: {never} ({never_pct}%)"
    )


def _get_environment_identity(checks: dict) -> tuple[str, str]:
    """Return manager version and UUID from manager_api check payload."""
    manager_api = checks.get('manager_api', {})
    version = manager_api.get('manager_version') or "unknown"
    uuid = manager_api.get('manager_uuid') or "unknown"
    return version, uuid


def send_email_notification():
    try:
        # 1. Read last JSON line
        with open(LOG_PATH, 'r') as f:
            lines = f.readlines()
            if not lines:
                return
            data = json.loads(lines[-1].strip())

        # 2. Filter issues (notify: true) + always include agents
        all_checks = data.get('checks', {})
        manager_version, manager_uuid = _get_environment_identity(all_checks)
        issues = []

        for check_id, details in all_checks.items():
            # Agent check always includes information 
            if check_id == 'agents' and details.get('total') is not None:
                msg = _format_agents_msg_html(details)
                issues.append({
                    "name":   "Agent Summary",
                    "status": details.get('status', 'OK').upper(),
                    "message": msg
                })
                continue

            
            if details.get('notify') is not True:
                continue

            msg = details.get('details') or details.get('issues') or "Review logs"
            if isinstance(msg, list):
                msg = "<br>".join([f"• {m}" for m in msg])

            issues.append({
                "name":    check_id.replace('_', ' ').title(),
                "status":  details.get('status', 'WARNING').upper(),
                "message": msg
            })

        if not issues:
            print("Email: No alerts to be sent.")
            return

        # 3. Email body 
        subject = f"⚠️ ALERT: Wazuh Health Check - {HOSTNAME}"

        # First alerts, then info (agents OK at the end)
        alerts  = [i for i in issues if i['status'] != 'OK']
        info    = [i for i in issues if i['status'] == 'OK']
        ordered = sorted(alerts, key=lambda x: x['status']) + info

        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; color: #333;">
            <h2 style="color: #d9534f;">Wazuh Alerts report</h2>
            <p>Some issues were detected at server: <strong>{HOSTNAME}</strong></p>
            <p>
                Environment: <strong>{manager_version}</strong><br>
                UUID: <strong>{manager_uuid}</strong>
            </p>
            <table border="1" cellpadding="10" cellspacing="0"
                   style="border-collapse: collapse; width: 100%;">
                <tr style="background-color: #f8f9fa;">
                    <th>Component</th>
                    <th>State</th>
                    <th>Details</th>
                </tr>
        """

        for issue in ordered:
            if issue['status'] == 'ERROR':
                color = "#d9534f"
            elif issue['status'] == 'WARNING':
                color = "#f0ad4e"
            else:
                color = "#5cb85c"   #  OK green

            html += f"""
                <tr>
                    <td><strong>{issue['name']}</strong></td>
                    <td style="color: white; background-color: {color};
                               text-align: center;">{issue['status']}</td>
                    <td>{issue['message']}</td>
                </tr>
            """

        html += """
            </table>
            <br>
            <p>Please verify the Errors and take actions</p>
        </body>
        </html>
        """

        # 4. Configure message
        msg = MIMEMultipart()
        msg['From']    = SMTP_USER
        msg['To']      = DESTINATARIO
        msg['Subject'] = subject
        msg.attach(MIMEText(html, 'html'))

        # 5. Send
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)

        alerts_count = len([i for i in issues if i['status'] != 'OK'])
        print(f"✅ Email successfully sent. {alerts_count} alert(s) found.")

    except Exception as e:
        print(f"❌ Error sending email: {e}")


if __name__ == "__main__":
    send_email_notification()
