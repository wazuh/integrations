#!/var/ossec/framework/python/bin/python3

import requests
import json
from datetime import datetime, timedelta
import logging
from socket import socket, AF_UNIX, SOCK_DGRAM
import sys, os

# === CONFIGURATION ===
API_KEY = "YOUR API KEY HERE"
REGION = "REGION HERE"
LOOKBACK_MINUTES = 5

pwd             = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
SOCKET_ADDR     = f'{pwd}/queue/sockets/queue'

# === LOGGING ===
logging.basicConfig(filename='/var/ossec/logs/rapid7_integration.log',
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%Y-%m-%dT%H:%M:%S',
                    level=logging.DEBUG)

# === API ENDPOINT ===
BASE_URL = f"https://{REGION}.rest.logs.insight.rapid7.com"
DOWNLOAD_URL = f"{BASE_URL}/download/logs/"
ID_SEARCH_URL = f"{BASE_URL}/log_search/management/logs"
AUTH_URL = f"https://{REGION}.api.insight.rapid7.com/validate"

headers = {
    "X-Api-Key": API_KEY,
    "Content-Type": "application/json"
}

logging.info("\n\nRunning the Rapid7 integration script.")

# === CHECK CREDENTIALS ===
auth_response = requests.get(AUTH_URL, headers=headers)
if auth_response.status_code == 200:
    if auth_response.json().get('message', "null") != "Authorized":
        logging.error("Failed to authenticate to Rapid7 API.")
        sys.exit(1)

# === MAKE REQUEST ===
response = requests.get(ID_SEARCH_URL, headers=headers)

# === HANDLE RESPONSE ===
if response.status_code == 200:
    log_ids = list()
    logsets = response.json()["logs"]
    for logset in logsets:
        log_ids.append(logset["id"])
    logging.info(f"Retrieved {len(log_ids)} log IDs.")
    logging.info(f"Extracting logs from each log ID")
    total_logs = 0


    t = len(log_ids)
    q = t//10
    r = t%10
    all_logs = list()

    for i in range(q):
        current_ids = ':'.join(log_ids[10*i:10*i+10])
        response = requests.get(DOWNLOAD_URL + current_ids + "?time_range=last+" + str(LOOKBACK_MINUTES) + "+minutes" , headers=headers)
        logs = response.text.split('\n')
        total_logs += len(logs)
        for log in logs:
            all_logs.append(log)

    if r > 0:
        ids = ':'.join(log_ids[-r:])
        response = requests.get(DOWNLOAD_URL + ids + "?time_range=last+" + str(LOOKBACK_MINUTES) + "+minutes" , headers=headers)
        logs = response.text.split('\n')
        total_logs += len(logs)
        for log in logs:
            all_logs.append(log)

    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        for log in all_logs:
            if log != "": #Skip empty logs
                sock.send(('""rapid7:' + log).encode())
        sock.close()
        logging.info(f"Fetched {len(all_logs)} logs from the API. Logs sent to the Wazuh analysis queue.\nIntegration completed successfully.")

    except Exception as error:
        logging.error("Failed to send logs to the wazuh-analysis queue: %s", str(error));
        sys.exit(1)

else:
    print("Incorrect Response code received from Rapid7 API: %s. Exiting", str(response.status_code))
    sys.exit(1)
