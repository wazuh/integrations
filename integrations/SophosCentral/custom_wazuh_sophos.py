#!/usr/bin/env python3
import requests
import json
import sys
import logging
import argparse
from socket import AF_UNIX, SOCK_DGRAM, socket

# === DEFAULT CONFIGURATION ===
API_HOST_DEFAULT = "https://api-us01.central.sophos.com"  # Adjust for your region
TOKEN_URL = "https://id.sophos.com/api/v2/oauth2/token"
SOCKET_ADDR = "/var/ossec/queue/sockets/queue"
LOG_FILE = "/var/ossec/logs/integrations.log"
LABEL = "wazuh_sophos"

# === ARGUMENT PARSER ===
parser = argparse.ArgumentParser(description="Sophos Central to Wazuh Integration Script with In-Memory Scroll")
parser.add_argument("--client-id", required=True, help="Sophos Central Client ID")
parser.add_argument("--client-secret", required=True, help="Sophos Central Client Secret")
parser.add_argument("--tenant-id", required=True, help="Sophos Central Tenant ID")
parser.add_argument("--api-host", default=API_HOST_DEFAULT, help="Sophos API Host (region-specific)")
parser.add_argument("--limit", type=int, default=200, help="Number of events per request (default: 200)")
args = parser.parse_args()

# === LOGGING CONFIGURATION ===
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def get_token():
    """Retrieve a valid Sophos Central OAuth2 token"""
    data = {
        "grant_type": "client_credentials",
        "client_id": args.client_id,
        "client_secret": args.client_secret,
        "scope": "token"
    }
    resp = requests.post(TOKEN_URL, data=data)
    resp.raise_for_status()
    return resp.json()["access_token"]

def fetch_events(token):
    """Fetch all events from Sophos Central using cursor (scroll) until no more results"""
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Tenant-ID": args.tenant_id,
        "Accept": "application/json"
    }

    events = []
    cursor = None

    while True:
        url = f"{args.api_host}/siem/v1/events?limit={args.limit}"
        if cursor:
            url += f"&cursor={cursor}"

        logging.info(f"Fetching events from URL: {url}")
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()

        items = data.get("items", [])
        events.extend(items)
        logging.info(f"Fetched {len(items)} events (total so far: {len(events)})")

        if data.get("has_more") and data.get("next_cursor"):
            cursor = data["next_cursor"]
        else:
            break

    return events

def send_event_to_wazuh(event):
    """Send a single event to Wazuh with a clean location tag"""
    try:
        wazuh_event = json.dumps({LABEL: event}, ensure_ascii=False)
        message = f"1:{LABEL}:{wazuh_event}"
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(message.encode())
        sock.close()
        logging.info(f"Sent event ID: {event.get('id', 'no-id')}")
    except Exception as e:
        logging.error(f"Error sending to Wazuh socket: {e}")

def main():
    try:
        logging.info("=== Starting Sophos Central -> Wazuh integration (scroll in-memory) ===")
        token = get_token()
        events = fetch_events(token)
        logging.info(f"Retrieved {len(events)} events from Sophos API")

        for ev in events:
            send_event_to_wazuh(ev)

        logging.info("=== Integration finished ===")

    except Exception as e:
        logging.error(f"Fatal error: {e}")
        print(f"[!] Error: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
