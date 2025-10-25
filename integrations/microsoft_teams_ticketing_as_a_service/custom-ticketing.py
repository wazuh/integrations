import json
import os
import sys
import requests
from datetime import datetime, timezone

# Exit error codes
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7
ERR_API_ERROR = 8

# Global vars
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = f'{pwd}/logs/integrations.log'

# Constants
ALERT_INDEX = 1
API_KEY_INDEX = 2
API_URL_INDEX = 3

def main(args):
    global debug_enabled
    try:
        if len(args) < 4:
            log_error("# ERROR: Incorrect number of arguments provided.")
            sys.exit(ERR_BAD_ARGUMENTS)
        
        debug_enabled = len(args) > 4 and args[4] == 'debug'
        log_debug(f"# Arguments received: {args}")

        process_args(args)
    except Exception as e:
        log_error(f"# ERROR: Exception in main - {str(e)}")
        sys.exit(ERR_API_ERROR)


def process_args(args):
    log_debug('# Running Ticketing Tool script')

    alert_file_location = args[ALERT_INDEX]
    api_key = args[API_KEY_INDEX]
    api_url = args[API_URL_INDEX]

    log_debug(f"# Alert file location: {alert_file_location}")
    log_debug(f"# API URL: {api_url}")
    log_debug(f"# API Key (masked): {api_key[:4]}...{api_key[-4:]}")

    json_alerts = load_json(alert_file_location)
    
    if isinstance(json_alerts, list):
        log_debug(f"# Found {len(json_alerts)} alert(s). Processing each separately.")
        for json_alert in json_alerts:
            log_debug(f"# Parsed alert JSON: {json.dumps(json_alert, indent=2)}")
            msg = generate_msg(json_alert)
            log_debug(f"# Generated message: {json.dumps(msg, indent=2)}")
            
            response = send_msg(msg, api_url, api_key)
            log_debug(f"# API Response: {response.status_code} - {response.text}")
            
            if response.status_code != 201:
                log_error(f"# ERROR: Ticket creation failed with status {response.status_code}: {response.text}")
                sys.exit(ERR_API_ERROR)
            else:
                log_debug("# Ticket successfully created.")
    else:
        log_error("# ERROR: JSON format is not a list of alerts.")
        sys.exit(ERR_INVALID_JSON)


def generate_msg(alert):
    timestamp = alert.get('timestamp', datetime.now(timezone.utc).isoformat())
    description = alert.get('rule', {}).get('description', 'No description available')

    return {
        "ticket": {
            "title": f"Wazuh Alert: {description}",
            "description": f"Alert received at {timestamp}. Details: {description}",
            "customFields": {"timestamp": timestamp},
             "requestor": {
                 "id": "s178s5f-8dd1-4dds6-a20a-c507a8dfa",
	        "name": "Hasitha Upekshitha",
        	"email": "Hasitha@yourdomain.com"
            }
        },
        "user": {
             "id": "71785f5f-83a1-4616-a20a-c507a817742a",
             "name": "Hasitha Upekshitha",
             "email": "Hasitha@yourdomain.com"
        }
    }


def send_msg(msg, api_url, api_key):
    headers = {
        'Content-Type': 'application/json',
        'Accept-Charset': 'UTF-8',
        'Authorization': f'Bearer {api_key}',
        'x-subscription-key': api_key  # Add the subscription key here if required
    }
     
    try:
        response = requests.post(api_url, json=msg, headers=headers, timeout=10)
        return response
    except requests.exceptions.RequestException as e:
        log_error(f"# ERROR: Request failed - {e}")
        sys.exit(ERR_API_ERROR)


def load_json(file_location):
    try:
        with open(file_location) as json_file:
            data = json_file.read()
            json_objects = []
            while data:
                obj, index = json.JSONDecoder().raw_decode(data)
                json_objects.append(obj)
                data = data[index:].lstrip()  # Move to the next JSON object
            return json_objects  # Return a list of parsed JSON objects
    except FileNotFoundError:
        log_error(f"# ERROR: JSON file not found - {file_location}")
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.JSONDecodeError as e:
        log_error(f"# ERROR: Invalid JSON format - {e}")
        sys.exit(ERR_INVALID_JSON)



def log_debug(msg):
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, 'a') as f:
            f.write(f"{datetime.now(timezone.utc).isoformat()} DEBUG {msg}\n")


def log_error(msg):
    print(msg, file=sys.stderr)
    with open(LOG_FILE, 'a') as f:
        f.write(f"{datetime.now(timezone.utc).isoformat()} ERROR {msg}\n")


if __name__ == '__main__':
    main(sys.argv)
