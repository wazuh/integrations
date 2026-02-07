#!/usr/bin/env python3
import requests
import json
import logging
import time
from socket import AF_UNIX, SOCK_DGRAM, socket

# ============================
# CONFIGURATION
# ============================

API_KEY = "API_KEY"
TERAMIND_URL = "TERAMINDS_URL"

SOCKET_ADDR = "/var/ossec/queue/sockets/queue"
LOG_FILE = "/var/ossec/logs/integration.log"
LABEL = "teramind"

# ============================
# LOGGING SETUP
# ============================
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(message)s"
)

# ============================
# CALCULATE LAST 15 MIN WINDOW
# ============================
NOW = int(time.time())
PERIOD_END = NOW
PERIOD_START = NOW - (1000 * 60)    # 15 minutes ago

# ============================
# SEND EVENT TO WAZUH + LOG
# ============================
def send_to_wazuh(entry, endpoint):
    """Send event JSON to Wazuh and log it with top-level 'teramind' object."""
    try:
        payload = json.dumps({
            "teramind": {
                "endpoint": endpoint,
                "data": entry
            }
        })

        # Log clean JSON to integrations.log
        #logging.info(payload)

        # Send same JSON to Wazuh socket
        msg = f"1:{LABEL}:{payload}"
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(msg.encode())
        sock.close()

    except Exception as e:
        logging.info(json.dumps({
            "teramind": {
                "error": str(e)
            }
        }))

# ============================
# GENERIC API PROCESSOR
# ============================
def process_endpoint(url, payload, rename_duration=False):
    try:
        headers = {
            "Content-Type": "application/json",
            "x-access-token": API_KEY
        }

        response = requests.post(url, json=payload, headers=headers, timeout=30)
        data = response.json()

        rows = data.get("rows", [])

        for row in rows:
            # Rename 'duration' -> 'durations' only if requested
            if rename_duration and 'duration' in row:
                row['durations'] = row.pop('duration')

            send_to_wazuh(row, url)

    except Exception as e:
        logging.info(json.dumps({
            "teramind": {
                "endpoint": url,
                "error": str(e)
            }
        }))

# ============================
# ENDPOINT FUNCTIONS
# ============================
def endpoint_emails():
    process_endpoint(
        f"{TERAMIND_URL}/tm-api/report/emails/grid",
        {"periodStart": PERIOD_START, "periodEnd": PERIOD_END}
    )

def endpoint_searches():
    process_endpoint(
        f"{TERAMIND_URL}/tm-api/report/searches/grid",
        {"periodStart": PERIOD_START, "periodEnd": PERIOD_END}
    )

def endpoint_sessions():
    process_endpoint(
        f"{TERAMIND_URL}/tm-api/report/sessions/grid",
        {"periodStart": PERIOD_START, "periodEnd": PERIOD_END}
    )

def endpoint_keystrokes():
    process_endpoint(
        f"{TERAMIND_URL}/tm-api/report/keystrokes/grid",
        {"periodStart": PERIOD_START, "periodEnd": PERIOD_END}
    )

def endpoint_webapps():
    # Pass rename_duration=True to rename 'duration' to 'durations'
    process_endpoint(
        f"{TERAMIND_URL}/tm-api/report/web-pages-applications/grid",
        {"periodStart": PERIOD_START, "periodEnd": PERIOD_END},
        rename_duration=True
    )

def endpoint_employees():
    process_endpoint(
        f"{TERAMIND_URL}/tm-api/report/employees/grid",
        {}
    )

def endpoint_computers():
    process_endpoint(
        f"{TERAMIND_URL}/tm-api/report/computers/grid",
        {"viewMode": 1}
    )

def endpoint_audit():
    process_endpoint(
        f"{TERAMIND_URL}/tm-api/report/audit/grid",
        {
            "agents": [],
            "departments": [],
            "computers": [],
            "tasks": [],
            "filter": "",
            "sortCol": "timestamp",
            "sortDir": "desc",
            "page": 0,
            "periodStart": PERIOD_START,
            "periodEnd": PERIOD_END,
            "customFilter": [],
            "partial": 0,
            "action": 1,
            "accessToken": "",
            "showUrls": 0
        }
    )

# ============================
# MAIN EXECUTION
# ============================
if __name__ == "__main__":
    endpoint_emails()
    endpoint_searches()
    endpoint_sessions()
    endpoint_keystrokes()
    endpoint_webapps()       # 'duration' will be renamed to 'durations'
    endpoint_employees()
    endpoint_computers()
    endpoint_audit()
