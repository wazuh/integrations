#!/usr/bin/env python3
from google.oauth2 import service_account
from googleapiclient.discovery import build
import os, sys, json, argparse, tempfile, traceback, random, time
import logging
import glob
import re
import shutil
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta

# --- CONFIGURATION ---
SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))
LOG_FILE_PATH = '/var/log/gworkspace.log'
STR_LAST_ACTIVITY_TIME = 'lastActivityTime'
STR_GWORKSPACE = 'gworkspace'
RESULTS_PER_REQUEST = 800
MAX_API_RETRIES = 5
MAX_ALERT_LENGTH = 5000
GOOGLE_APPLICATIONS = 'access_transparency,admin,calendar,chat,drive,gcp,gplus,groups,groups_enterprise,jamboard,login,meet,mobile,rules,saml,token,user_accounts,context_aware_access,chrome,data_studio,keep,alert'
SCOPES = [
    'https://www.googleapis.com/auth/admin.reports.audit.readonly',
    'https://www.googleapis.com/auth/apps.alerts'
]

# --- LOGGING SETUP ---
def setup_logging(debug_mode=False):
    level = logging.DEBUG if debug_mode else logging.INFO
    logger = logging.getLogger("gworkspace")
    logger.setLevel(level)
    # Create log directory if it doesn't exist (if running as root)
    try:
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        # Rotating file handler: 10MB per file, keep 5 backups
        handler = RotatingFileHandler(LOG_FILE_PATH, maxBytes=10*1024*1024, backupCount=5)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    except Exception as e:
        # Fallback to stderr if log file cannot be created
        pass
    return logger

# --- ARGUMENT PARSING ---
parser = argparse.ArgumentParser(description="Export Google Workspace logs for multiple accounts.")
parser.add_argument('--applications', '-a', dest='applications', required=True, help='comma-separated app names or "all"')
parser.add_argument('--offset', '-o', dest='offset', required=False, default=24, type=int, help='hours to go back')
parser.add_argument('--unread', '-u', dest='unread', action='store_true', help='keep marked as unread')
parser.add_argument('--debug', '-d', dest='debug', action='store_true', help='enable debug logging to file')
args = parser.parse_args()

# Initialize Logger
logger = setup_logging(args.debug)

# Global output file for Wazuh to consume
GLOBAL_RESULTS = tempfile.TemporaryFile(mode='w+')

def main():
    logger.info("Starting GWorkspace extraction script (Multi-Account)")

    if args.applications == "all":
        args.applications = GOOGLE_APPLICATIONS

    # Find all config files
    config_files = glob.glob(os.path.join(SCRIPT_PATH, 'config*.json'))
    if not config_files:
        fatal_error(f"No configuration files (config*.json) found in {SCRIPT_PATH}")

    processed_count = 0

    for config_path in config_files:
        filename = os.path.basename(config_path)
        # Determine the tag based on filename: config_mytag.json -> tag: mytag
        # config.json -> tag: default
        match = re.match(r'^config(?:_(.+))?\.json$', filename)
        if not match:
            continue
        
        account_tag = match.group(1) or 'default'

        # Define corresponding key and state files
        if account_tag == 'default':
            key_path = os.path.join(SCRIPT_PATH, 'service_account_key.json')
            state_path = os.path.join(SCRIPT_PATH, 'state.json')
        else:
            key_path = os.path.join(SCRIPT_PATH, f'service_account_key_{account_tag}.json')
            state_path = os.path.join(SCRIPT_PATH, f'state_{account_tag}.json')

        if not os.path.exists(key_path):
            logger.warning(f"Skipping account '{account_tag}': Key file not found at {key_path}")
            continue

        try:
            process_account(account_tag, config_path, key_path, state_path)
            processed_count += 1
        except Exception as e:
            logger.error(f"Error processing account '{account_tag}': {traceback.format_exc()}")
            continue

    if processed_count == 0:
        logger.warning("No accounts were processed successfully.")
    else:
        logger.info(f"Successfully processed {processed_count} accounts.")

    print_results()
    json_msg('extraction', 'finished', 'message', "extraction finished")

def process_account(tag, config_path, key_path, state_path):
    logger.info(f"[{tag}] Processing account using {os.path.basename(config_path)}")
    
    # Load Config
    try:
        with open(config_path, 'r') as cf:
            config = json.load(cf)
    except Exception as e:
        logger.error(f"[{tag}] Failed to load config: {e}")
        return

    # Load State
    state = load_state(state_path)

    # Calculate Time Offset
    offset_time = datetime.now() - timedelta(hours=args.offset)
    offset_time_iso = as_iso8601(offset_time)

    # Temporary file for this specific account's results
    # We use this to calculate state updates before merging to global results
    account_results = tempfile.TemporaryFile(mode='w+')

    scoped_applications = args.applications.split(',')
    
    for application in scoped_applications:
        if application not in GOOGLE_APPLICATIONS.split(','):
            logger.error(f"[{tag}] Unknown application type: {application}")
            continue

        # Determine start time for this app
        earliest_time = dict_path(state, capitalize(application), STR_LAST_ACTIVITY_TIME) or offset_time_iso
        logger.info(f"[{tag}] Fetching {application} logs since {earliest_time}")

        try:
            if application == 'alert':
                service = get_service('alertcenter', 'v1beta1', key_path, config.get('service_account'))
                get_alerts(service, earliest_time, account_results, tag)
            else:
                service = get_service('admin', 'reports_v1', key_path, config.get('service_account'))
                get_logs(service, application, earliest_time, account_results, tag)
        except Exception as e:
            logger.error(f"[{tag}] Error fetching logs for {application}: {str(e)}")
            continue

    # Update state for this account based on fetched results
    if not args.unread:
        updated_state = calculate_new_state(state, account_results)
        save_state(updated_state, state_path)

    # Append account results to global results
    account_results.seek(0)
    shutil.copyfileobj(account_results, GLOBAL_RESULTS)
    account_results.close()

def get_service(service_name, service_version, key_file_path, subject_email):
    credentials = service_account.Credentials.from_service_account_file(key_file_path, scopes=SCOPES)
    if subject_email:
        credentials = credentials.with_subject(subject_email)
    return build(service_name, service_version, credentials=credentials, num_retries=MAX_API_RETRIES)

def dict_path(dictionary, *path):
    curr_element = dictionary
    for idx, key in enumerate(path):
        if not isinstance(curr_element, dict): return None
        curr_element = curr_element.get(key)
        if (idx == len(path) - 1): break
        if (curr_element == None): return None
    return curr_element

def get_retry(service, method_name, params, retries):
    try:
        method = getattr(service, method_name)
        return method().list(**params).execute(num_retries=0)
    except Exception as e:
        if (retries > 0):
            backoff = 2 ** (MAX_API_RETRIES - retries)
            time.sleep(backoff)
            return get_retry(service, method_name, params, retries - 1)
        else:
            raise

def get_logs(service, application, earliest_time, output_file, account_tag):
    nextToken = get_log_page(service, application, earliest_time, None, output_file, account_tag)
    while (nextToken):
        nextToken = get_log_page(service, application, earliest_time, nextToken, output_file, account_tag)

def get_log_page(service, application, earliest_time, nextToken, output_file, account_tag):
    params = {
        'userKey': 'all',
        'startTime': earliest_time,
        'applicationName': application,
        'maxResults': RESULTS_PER_REQUEST
    }
    if (nextToken): params['pageToken'] = nextToken
    results = get_retry(service, 'activities', params, MAX_API_RETRIES)
    items = results.get('items', [])

    for activity in items:
        # Check event times
        # Note: We filter manually because the API startTime is inclusive
        # and sometimes not perfectly precise on boundaries
        valid_events = []
        for event in activity.get('events', []):
            timestamp = dict_path(activity, 'id', 'time')
            if timestamp <= earliest_time:
                continue
            valid_events.append(event)
        
        if not valid_events:
            continue

        # Build base event object
        converted_event = { }
        converted_event['srcip'] = dict_path(activity, 'ipAddress')
        converted_event['user'] = dict_path(activity, 'actor', 'email')
        converted_event['id'] = dict_path(activity, 'id', 'uniqueQualifier')
        converted_event['timestamp'] = dict_path(activity, 'id', 'time') # timestamp is at activity level

        data = { }
        converted_event[STR_GWORKSPACE] = data
        data['source_account'] = account_tag  # <-- TAG ADDED HERE
        data['profileId'] = dict_path(activity, 'actor', 'profileId')
        data['customerId'] = dict_path(activity, 'id', 'customerId')
        data['application'] = capitalize(dict_path(activity, 'id', 'applicationName'))

        # We process the first valid event found or split? 
        # The original script flattened events. If an activity has multiple events, 
        # it loops them.
        for event in valid_events:
            # Clone for each sub-event if necessary, or just overwrite specific fields
            # Since Wazuh ingests JSON lines, we emit one line per event in the activity
            
            # Shallow copy data dict for specific event fields
            event_data = data.copy()
            event_data['eventtype'] = capitalize(dict_path(event, 'type'))
            event_data['eventname'] = capitalize(dict_path(event, 'name'))
            
            converted_parameters = {}
            for parameter in event.get('parameters') or []:
                name = parameter.get('name')
                for key, value in parameter.items():
                    if key == 'name': continue
                    converted_parameters[name] = value
            event_data['parameters'] = converted_parameters

            # Final object to dump
            final_obj = converted_event.copy()
            final_obj[STR_GWORKSPACE] = event_data
            
            json.dump(final_obj, output_file, indent=None)
            output_file.write("\n")

    return results.get('nextPageToken')

def get_alerts(service, earliest_time, output_file, account_tag):
    nextToken = get_alerts_page(service, earliest_time, None, output_file, account_tag)
    while (nextToken):
        nextToken = get_alerts_page(service, earliest_time, nextToken, output_file, account_tag)

def get_alerts_page(service, earliest_time, nextToken, output_file, account_tag):
    params = { 'filter': f'startTime > "{earliest_time}"' }
    if (nextToken): params['pageToken'] = nextToken
    results = get_retry(service, 'alerts', params, MAX_API_RETRIES)
    alerts = results.get('alerts', [])

    for alert in alerts:
        timestamp = dict_path(alert, 'startTime')
        converted_event = { }
        converted_event['id'] = dict_path(alert, 'alertId')
        converted_event['timestamp'] = timestamp
        email = dict_path(alert, 'data', 'email') or dict_path(alert, 'data', 'actorEmail')
        if email: converted_event['user'] = email

        data = { }
        converted_event[STR_GWORKSPACE] = data
        data['source_account'] = account_tag # <-- TAG ADDED HERE
        data['application'] = 'alert'
        data['customerId'] = dict_path(alert,'customerId')
        data['eventtype'] = capitalize(dict_path(alert, 'source'))
        data['eventname'] = capitalize(dict_path(alert, 'type'))

        json_alert = json.dumps(dict_path(alert, 'data'))
        if len(json_alert) > MAX_ALERT_LENGTH:
            json_alert = json_alert[:MAX_ALERT_LENGTH] + "..."
        data['parameters'] = { 'alert' : json_alert}

        json.dump(converted_event, output_file, indent=None)
        output_file.write("\n")
        
    return results.get('nextPageToken')

def as_iso8601(dt):
    return dt.isoformat() + "Z"

def log_entry(obj):
    return json.dumps(obj)

def capitalize(s):
    return s.replace('_', ' ').lower() if s else s

def print_results():
    GLOBAL_RESULTS.seek(0)
    try:
        for line in GLOBAL_RESULTS:
            print(line.strip())
            # Optional: flush slightly reduces performance but ensures data isn't held in buffer
            # sys.stdout.flush() 
    except BrokenPipeError:
        # Wazuh stopped listening. We just exit silently.
        # Closing stderr ensures no further error noise.
        try:
            sys.stderr.close()
        except:
            pass
        sys.exit(0)

def load_state(path):
    if not os.path.exists(path): return {}
    try:
        with open(path, 'r') as f: return json.load(f)
    except:
        return {}

def save_state(state, path):
    try:
        with open(path + '.tmp', 'w+') as newfile:
            json.dump(state, newfile, indent=3)
            newfile.write("\n")
        os.replace(newfile.name, path)
    except Exception as e:
        logger.error(f"Failed to save state to {path}: {e}")

def calculate_new_state(current_state, account_results_file):
    # Don't modify the passed object directly immediately, create a copy logic if needed
    # But here we update the current_state dict
    account_results_file.seek(0)
    for line in account_results_file:
        try:
            activity = json.loads(line)
            application = dict_path(activity, STR_GWORKSPACE, 'application')
            activityTime = dict_path(activity, 'timestamp')
            if not application or not activityTime: continue

            app_state = current_state.setdefault(application, { STR_LAST_ACTIVITY_TIME: '0000-00-00T00:00:00.000Z' })
            if (app_state[STR_LAST_ACTIVITY_TIME] < activityTime):
                app_state[STR_LAST_ACTIVITY_TIME] = activityTime
        except:
            continue
    return current_state

def json_msg(event_type, event_name, parameter_name, parameter_value):
    msg = {
        'id' : random.randint(0, 99999999999999),
        STR_GWORKSPACE : {
            'application' : 'wazuh extraction',
            'eventtype' : event_type,
            'eventname' : event_name,
            'parameters' : { 'name' : parameter_name, 'value' : parameter_value }
        }
    }
    # We also protect this print against BrokenPipeError
    try:
        print(log_entry(msg))
    except BrokenPipeError:
        pass

def fatal_error(message):
    logger.critical(message)
    json_msg('extraction', 'extraction error', 'message', message)
    sys.exit(0)

if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Filter out BrokenPipeError from the global exception handler
        # if it somehow bubbles up here
        if sys.exc_info()[0] == BrokenPipeError:
            sys.exit(0)
        err = traceback.format_exc()
        logger.error(f"FATAL EXCEPTION:\n{err}")
        fatal_error("fatal exception :\n" + err)
