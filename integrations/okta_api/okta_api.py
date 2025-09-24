#!/usr/bin/env python3
import requests, time, json
from datetime import datetime, timedelta
from socket import socket, AF_UNIX, SOCK_DGRAM

OKTA_DOMAIN = "https://yourcompany.okta.com"
API_TOKEN = "REPLACE_WITH_YOUR_TOKEN"
SOCKET = "/var/ossec/queue/sockets/queue"

headers = {
    "Authorization": f"SSWS {API_TOKEN}",
    "Accept": "application/json"
}

def send_event(event):
    try:
        s = socket(AF_UNIX, SOCK_DGRAM)
        s.connect(SOCKET)
        message = f'1:okta:{json.dumps({"okta": event})}'
        s.send(message.encode())
        s.close()
        time.sleep(0.1)
    except Exception as e:
        print(f"Socket error: {e}")

def fetch_okta_logs():
    since = (datetime.utcnow() - timedelta(minutes=10)).isoformat() + "Z"
    url = f"{OKTA_DOMAIN}/api/v1/logs?since={since}"
    try:
        res = requests.get(url, headers=headers)
        if res.status_code == 200:
            for event in res.json():
                send_event(event)
        else:
            print(f"Error fetching logs: {res.status_code}")
    except Exception as e:
        print(f"Request error: {e}")

if __name__ == "__main__":
    fetch_okta_logs()
