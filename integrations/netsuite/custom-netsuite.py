#!/usr/bin/env python3
from datetime import datetime
import json
import sys, os
import requests
from requests_oauthlib import OAuth1
import logging

###   Logging function
logging.basicConfig(filename='/var/ossec/logs/integrations.log',
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s NetSuite:%(levelname)s %(message)s',
                    datefmt='%Y-%m-%dT%H:%M:%S',
                    level=logging.INFO)

# === NetSuite API Endpoint ===
API_URL = "https://5541365-sb2.restlets.api.netsuite.com/app/site/hosting/restlet.nl?script=6948&deploy=1"

# === OAuth 1.0 Credentials ===
CLIENT_ID = "your client_id"
CLIENT_SECRET = "your client_secret"
TOKEN_ID = "your token_id"
TOKEN_SECRET = "your token_secret"
REALM = "your Realm"

# === File Paths ===
LOCAL_LOG_FILE = "/var/log/netsuite_logs.json"
WAZUH_LOG_FILE = "/var/ossec/logs/active-responses.log"
CURSOR_FILE = "/tmp/netsuite_last_timestamp.txt"

# === Auth Setup ===
auth = OAuth1(
    CLIENT_ID,
    CLIENT_SECRET,
    TOKEN_ID,
    TOKEN_SECRET,
    realm=REALM,
    signature_method="HMAC-SHA256"
)

logging.info("[+] Fetching NetSuite Logs...")

# === Read Last Timestamp (Avoid Duplicates) ===
def load_last_timestamp():
    if os.path.exists(CURSOR_FILE):
        with open(CURSOR_FILE, "r") as f:
            t = f.read().strip()
            logging.info(f"last time stamp: {t}")
        return t
    else:
        logging.info(f"last time stamp not found. Proceeding...")
        return None

def save_last_timestamp(ts_value):
    with open(CURSOR_FILE, "w") as f:
        f.write(ts_value)


last_timestamp = load_last_timestamp()

try:
    res = requests.get(API_URL, auth=auth, timeout=30)
    if res.status_code != 200:
        logging.error(f"[❌] API Error {res.status_code}: {res.text[:200]}")
        sys.exit(1)
    
    logs = json.loads(res.text)["data"]
    new_logs = list()
    for log in logs:
        new = False
        log["time-stamp"] = log.pop("timestamp", "")
        log_ts = log.get("time-stamp", "")
        if not last_timestamp:
            new = True
        else:
            t0 = datetime.strptime(last_timestamp, "%m/%d/%Y %I:%M %p")
            t1 = datetime.strptime(log_ts, "%m/%d/%Y %I:%M %p")
            if  t1 > t0:
                new = True
        if new:
            new_logs.append(log)
            with open(LOCAL_LOG_FILE, "a") as f:
                f.write(json.dumps(log) + '\n')
    if len(new_logs) > 0:
        logging.info(f"Fetched {len(new_logs)} new logs on {len(logs)} logs. Writing them to the local file 🚀")
        last_timestamp = str(new_logs[-1].get("time-stamp", last_timestamp))
        save_last_timestamp(last_timestamp)
    else:
        logging.info(f"No new logs found. Exiting.")

except Exception as e:
    logging.error(f"[❌] Script Error: {str(e)}")
    sys.exit(1)
