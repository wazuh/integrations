#!/var/ossec/framework/python/bin/python3
import json
import sys
import time
import os

try:
    import requests
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)
    
# Exit error codes
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

#  <integration>
#      <name>custom-incidentio</name>
#      <hook_url>https://api.incident.io/v1/webhooks/XXXXXXXXXXXX</hook_url>
#      <level>3</level> <!-- feel free to modify this -->
#      <alert_format>json</alert_format>
#  </integration>


# Global vars
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
json_options = {}

# Log path
LOG_FILE = f'{pwd}/logs/integrations.log'

# Constants
ALERT_INDEX = 1
WEBHOOK_INDEX = 3
    
def main(args):
    global debug_enabled
    try:
        # Read arguments
        bad_arguments: bool = False
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
        debug(str(e))
        raise

def process_args(args) -> None:
    """This is the core function, creates a message with all valid fields
    and overwrite or add with the optional fields

    Parameters
    ----------
    args : list[str]
        The argument list from main call
    """
    debug('# Running Slack script')

    # Read args
    alert_file_location: str = args[ALERT_INDEX]
    webhook: str = args[WEBHOOK_INDEX]
    options_file_location: str = ''

    # Look for options file location
    for idx in range(4, len(args)):
        if args[idx][-7:] == 'options':
            options_file_location = args[idx]
            break

    # Load options. Parse JSON object.
    json_options = get_json_options(options_file_location)
    debug(f"# Opening options file at '{options_file_location}' with '{json_options}'")

    # Load alert. Parse JSON object.
    json_alert = get_json_alert(alert_file_location)
    debug(f"# Opening alert file at '{alert_file_location}' with '{json_alert}'")

    debug('# Generating message')
    msg: any = generate_msg(json_alert, json_options)

    if not len(msg):
        debug('# ERROR: Empty message')
        raise Exception

    debug(f'# Sending message {msg} to Slack server')
    send_msg(msg, webhook)
    
def debug(msg: str) -> None:
    """Log the message in the log file with the timestamp, if debug flag
    is enabled

    Parameters
    ----------
    msg : str
        The message to be logged.
    """
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')

def generate_msg(alert: any, options: any) -> any:
    """Generate the JSON object with the message to be send
    Maps a Wazuh alert into incident.io's expected payload format.

    Parameters
    ----------
    alert : any
        JSON alert object.

    Returns
    -------
    json: str
        The JSON message to send
    """


    # Severity mapping -> metadata
    level = alert['rule']['level']
    if level <= 4:
        severity = "low"
    elif level <= 7:
        severity = "medium"
    else:
        severity = "high"

    title = alert['rule'].get('description', 'Wazuh Alert')
    description = alert.get('full_log', 'No full_log provided')

    # A deduplication key so repeated alerts collapse in incident.io
    deduplication_key = f"wazuh-rule-{alert['rule']['id']}"

    # Metadata mapping (extend as needed)
    metadata = {
        "agent": alert.get('agent', {}).get('name', 'N/A'),
        "location": alert.get('location', 'N/A'),
        "rule_id": str(alert['rule']['id']),
        "severity": severity,
        "timestamp": alert.get('timestamp', time.strftime("%Y-%m-%dT%H:%M:%SZ"))
    }

    payload = {
        "title": title,
        "description": description,
        "deduplication_key": deduplication_key,
        "status": "firing",   # always firing on alert; clearing requires Wazuh custom handling
        "metadata": metadata
    }
    
#    if options:
        # Update message, not used in this case.

    return json.dumps(payload)
    
def send_msg(msg: str, url: str) -> None:
    """Send the message to the API

    Parameters
    ----------
    msg : str
        JSON message.
    url: str
        URL of the API.
    """
    headers = {'content-type': 'application/json'}
    res = requests.post(url, data=msg, headers=headers, timeout=10)
    debug('# Response received: %s' % res.json)

def get_json_alert(file_location: str) -> any:
    """Read JSON alert object from file

    Parameters
    ----------
    file_location : str
        Path to the JSON file location.

    Returns
    -------
    dict: any
        The JSON object read it.

    Raises
    ------
    FileNotFoundError
        If no JSON file is found.
    JSONDecodeError
        If no valid JSON file are used
    """
    try:
        with open(file_location) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        debug("# JSON file for alert %s doesn't exist" % file_location)
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        debug('Failed getting JSON alert. Error: %s' % e)
        sys.exit(ERR_INVALID_JSON)

def get_json_options(file_location: str) -> any:
    """Read JSON options object from file

    Parameters
    ----------
    file_location : str
        Path to the JSON file location.

    Returns
    -------
    dict: any
        The JSON object read it.

    Raises
    ------
    JSONDecodeError
        If no valid JSON file are used
    """
    try:
        with open(file_location) as options_file:
            return json.load(options_file)
    except FileNotFoundError:
        debug("# JSON file for options %s doesn't exist" % file_location)
    except BaseException as e:
        debug('Failed getting JSON options. Error: %s' % e)
        sys.exit(ERR_INVALID_JSON)


if __name__ == '__main__':
    main(sys.argv)
