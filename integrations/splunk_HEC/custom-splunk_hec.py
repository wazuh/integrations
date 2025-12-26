#!/usr/bin/python3

import json
import requests
from requests.auth import HTTPBasicAuth
import urllib3
import sys
import logging

###     Disable insecure https warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

### Spunk configuration
s_protocol = "PROTOCOL"
s_host = 'SPLUNK IP'
s_port = 'HEC PORT'
s_endpoint = 'ENDPOINT'
TOKEN = 'TOKEN'

s_url = f'{s_protocol}://{s_host}:{s_port}{s_endpoint}'
s_headers = {'Authorization': f'Splunk {TOKEN}'}

###   Logging function
logging.basicConfig(filename='/var/ossec/logs/integrations.log',
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s:%(levelname)s %(message)s',
                    datefmt='%Y-%m-%dT%H:%M:%S',
                    level=logging.INFO)
try:
    # Reading config parameter
    logging.info("Reading config parameters")
    alert_file = open(sys.argv[1])

except Exception as e:
    logging.error("Failed to read config parameters: %s", str(e))
    sys.exit(1)

try:
    # Read the alert file
    logging.info("Reading the alert.")
    alert_json = json.loads(alert_file.read())
    alert_file.close()
except Exception as e:
    logging.error("Failed to read the alert: %s", str(e)) 
    sys.exit(1)

try:
    splunk_event = {
        "event": json.dumps(alert_json),  # Convert to JSON string
        "sourcetype": "wazuh:alerts",
        "source": "wazuh-manager"
    }

    logging.debug("Sending alert to Splunk HEC.")

    # Send to Splunk HEC
    s_response = requests.post(
        s_url,
        headers=s_headers,
        data=json.dumps(splunk_event),
        verify=False
    )

    logging.debug(f"Splunk response: {s_response.text}")
    logging.info("Alert successfully forwarded to Splunk.")

    # Check for errors
    if s_response.status_code != 200:
        logging.error(f"ERROR: Failed to send alert. Status: {s_response.status_code}")
        sys.exit(1)

except Exception as e:
    logging.error(f"Failed forwarding the alert to Splunk: {str(e)}")

sys.exit(0)
