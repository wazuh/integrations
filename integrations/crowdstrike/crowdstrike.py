from falconpy import Alerts
import datetime
import json
import os
import logging
from socket import AF_UNIX, SOCK_DGRAM, socket

# =========================
# User Configuration
# =========================
CLIENT_ID = 'xxxxx'
CLIENT_SECRET = 'xxxxx'
SOCKET_ADDR = "/var/ossec/queue/sockets/queue"
LOG_FILE = "/var/ossec/logs/integrations.log"
LABEL = "crowdstrike"

# =========================
# Logging
# =========================
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# =========================
# Send event to Wazuh
# =========================
def send_event_to_wazuh(msg, label):
    try:
        wazuh_event = json.dumps({label: json.loads(msg)})
        payload = f"1:{label}:{wazuh_event}"
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(payload.encode())
        sock.close()
        logging.info("Event sent to Wazuh")
    except Exception as e:
        logging.error(f"Error sending event to Wazuh: {e}")

# =========================
# Get alert IDs
# =========================
def get_alert_ids(client_id, client_secret):
    falcon = Alerts(client_id=client_id, client_secret=client_secret)

    end_time = datetime.datetime.now(datetime.timezone.utc)
    start_time = end_time - datetime.timedelta(hours=60)

    start = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    end = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')

    logging.info(f"Querying alerts from {start} to {end}")

    try:
        response = falcon.query_alerts(
            filter=f"created_timestamp:>='{start}'+created_timestamp:<='{end}'",
            limit=100,
            sort="created_timestamp|asc"
        )

        if response["status_code"] != 200:
            logging.error(f"Alert query failed: {response}")
            return None

        alert_ids = response["body"]["resources"]
        logging.info(f"Found {len(alert_ids)} alerts")
        return alert_ids

    except Exception as e:
        logging.error(f"Exception querying alerts: {e}")
        return None

# =========================
# Get alert details
# =========================
def get_alert_details(client_id, client_secret, alert_ids):
    if not alert_ids:
        return None

    falcon = Alerts(client_id=client_id, client_secret=client_secret)

    try:
        response = falcon.get_alerts(ids=alert_ids)

        if response["status_code"] != 200:
            logging.error(f"Alert details fetch failed: {response}")
            return None

        return response["body"]["resources"]

    except Exception as e:
        logging.error(f"Exception fetching alert details: {e}")
        return None

# =========================
# Process and send alerts
# =========================
def process_and_send(alerts, label):
    for alert in alerts:
        try:
            send_event_to_wazuh(json.dumps(alert), label)
        except Exception as e:
            logging.error(f"Error processing alert: {e}")

# =========================
# Main
# =========================
if __name__ == "__main__":
    client_id = os.environ.get("CROWDSTRIKE_CLIENT_ID", CLIENT_ID)
    client_secret = os.environ.get("CROWDSTRIKE_CLIENT_SECRET", CLIENT_SECRET)
    label = os.environ.get("WAZUH_LABEL", LABEL)

    logging.info("Starting CrowdStrike → Wazuh Alerts integration")

    alert_ids = get_alert_ids(client_id, client_secret)

    if alert_ids:
        alerts = get_alert_details(client_id, client_secret, alert_ids)
        if alerts:
            process_and_send(alerts, label)
        else:
            logging.warning("No alert details returned")
    else:
        logging.warning("No alerts found")

    logging.info("CrowdStrike → Wazuh integration completed")

