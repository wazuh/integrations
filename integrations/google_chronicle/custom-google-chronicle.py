#!/var/ossec/framework/python/bin/python3
## Google Chronicle (Google SecOps) API Integration
#
import json
import os
import sys

# Exit error codes
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7
ERR_REQUEST_FAILED = 8

try:
    import requests
except Exception:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(ERR_NO_REQUEST_MODULE)

# ossec.conf configuration structure
#  <integration>
#      <name>google-chronicle</name>
#      <hook_url>https://<CHRONICLE_REGION>-chronicle.googleapis.com/v1alpha/projects/<GOOGLE_PROJECT_NUMBER>/locations/<LOCATION>/instances/<CUSTOMER_ID>/feeds/<FEED_ID>:importPushLogs?key=<API_KEY>&secret=<SECRET></hook_url>
#      <alert_format>json</alert_format>
#      <level>0</level>  <!-- Adjust the level as needed -->
#  </integration>

# Global vars
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

# Log path
LOG_FILE = f'{pwd}/logs/integrations.log'

# Constants
ALERT_INDEX = 1
WEBHOOK_INDEX = 3


def main(args):
    global debug_enabled
    try:
        # Read arguments
        bad_arguments = False
        if len(args) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(
                args[1], args[2], args[3], args[4] if len(args) > 4 else '', args[5] if len(args) > 5 else ''
            )
            debug_enabled = len(args) > 4 and args[4] == 'debug'
        else:
            msg = '# ERROR: Wrong arguments'
            bad_arguments = True

        # Logging the call
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')

        if bad_arguments:
            debug('# ERROR: Exiting, bad arguments. Inputted: %s' % args)
            sys.exit(ERR_BAD_ARGUMENTS)

        # Core function
        process_args(args)

    except Exception as e:
        debug(f'# ERROR: {str(e)}')
        raise


def process_args(args):
    """Core function that processes the alert and sends it to Google SecOps
    
    Parameters
    ----------
    args : list[str]
        The argument list from main call
    """
    debug('# Running Google SecOps integration script')

    # Read args
    alert_file_location = args[ALERT_INDEX]
    webhook_url = args[WEBHOOK_INDEX]

    # Load alert. Parse JSON object.
    json_alert = get_json_alert(alert_file_location)
    debug(f"# Opening alert file at '{alert_file_location}'")

    # Send to SecOps
    debug(f'# Sending alert to Google SecOps via webhook: {webhook_url}')
    send_to_secops(json_alert, webhook_url)


def debug(msg):
    """Log the message in the log file with the timestamp, if debug flag is enabled
    
    Parameters
    ----------
    msg : str
        The message to be logged.
    """
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')



def send_to_secops(payload, webhook_url):
    """Send the alert payload to Google SecOps
    
    Parameters
    ----------
    payload : dict
        The alert data to send
    webhook_url : str
        The SecOps webhook URL
    """
    try:
        # Prepare headers for SecOps
        headers = {
            'Content-Type': 'application/json'
        }
        
        # Extract API key and secret from URL if present
        if 'key=' in webhook_url:
            api_key = webhook_url.split('key=')[1].split('&')[0]
            headers['X-goog-api-key'] = api_key
        
        if 'secret=' in webhook_url:
            secret = webhook_url.split('secret=')[1].split('&')[0]
            headers['X-Webhook-Access-Key'] = secret
        
        # Convert payload to JSON string
        json_payload = json.dumps(payload)
        
        # Send the request
        response = requests.post(
            webhook_url,
            data=json_payload,
            headers=headers,
            timeout=30
        )
        
        # Check response
        if response.status_code == 200:
            debug(f'# Successfully sent alert to SecOps. Response: {response.status_code}')
        else:
            debug(f'# WARNING: SecOps returned status {response.status_code}: {response.text}')
            
    except requests.exceptions.RequestException as e:
        debug(f'# ERROR: Failed to send alert to SecOps: {str(e)}')
        sys.exit(ERR_REQUEST_FAILED)
    except Exception as e:
        debug(f'# ERROR: Unexpected error sending to SecOps: {str(e)}')
        sys.exit(ERR_REQUEST_FAILED)


def get_json_alert(file_location):
    """Load and parse the JSON alert file
    
    Parameters
    ----------
    file_location : str
        Path to the alert file
        
    Returns
    -------
    dict
        Parsed JSON alert object
    """
    debug(f'# Getting alert file from: {file_location}')
    
    try:
        with open(file_location) as alert_file:
            json_alert = json.load(alert_file)
        return json_alert
    except FileNotFoundError:
        debug(f'# ERROR: Alert file not found: {file_location}')
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.JSONDecodeError as e:
        debug(f'# ERROR: Invalid JSON in alert file: {str(e)}')
        sys.exit(ERR_INVALID_JSON)
    except Exception as e:
        debug(f'# ERROR: Failed to read alert file: {str(e)}')
        sys.exit(ERR_FILE_NOT_FOUND)


if __name__ == '__main__':
    main(sys.argv)                                                            