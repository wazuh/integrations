import os
import re
import requests
import json
from datetime import datetime

# User-defined variables
api_url = "https://<MANAGEMENT_CONSOLE_URL>/web/api/v2.1/threats?limit=10"
api_key = "<API_KEY>"
log_file_path = "/var/log/sentinelone.json"
custom_timestamp = "" #Enter your preferred timestamp within the quotes using the format 2023-01-01T00:00:00


def get_last_timestamp(log_file_path):
    try:
        with open(log_file_path, 'r') as file:
            lines = file.readlines()
            if lines:
                last_line = lines[-1].strip()
                match = re.search(r'"createdAt":\s*"([^"]+)"', last_line)
                if match:
                    last_created_at = match.group(1)
                    last_timestamp = datetime.strptime(last_created_at, "%Y-%m-%dT%H:%M:%S.%fZ").isoformat()
                    return last_timestamp
                else:
                    return None
            else:
                return None
    except FileNotFoundError:
        return None

def get_logs(start_timestamp):
    headers = {
        'Authorization': f'ApiToken {api_key}',
        'Content-Type': 'application/json'
    }

    # Construct query parameters
    params = {}
    if start_timestamp:
        params['createdAt__gt'] = start_timestamp

    response = requests.get(api_url, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch logs: {response.status_code}")
        return None

def main():
    # Get the last timestamp from the log file
    last_timestamp = get_last_timestamp(log_file_path)
    if last_timestamp:
        print(f"Last timestamp in log file: {last_timestamp}")
    else:
        print("Log file is empty or doesn't exist.")

    if custom_timestamp:
        # If custom timestamp is specified, check the log file first
        last_timestamp_from_file = get_last_timestamp(log_file_path)
        if last_timestamp_from_file:
            start_timestamp = last_timestamp_from_file
            print(f"Using last timestamp from log file: {start_timestamp}")
        else:
            start_timestamp = custom_timestamp
            print(f"Using custom timestamp: {start_timestamp}")
    else:
        start_timestamp = last_timestamp
        if last_timestamp:
            print(f"Using last timestamp from log file: {start_timestamp}")
        else:
            print("No last timestamp found in log file.")
            start_timestamp = None  # Reset start timestamp to None if neither custom nor file timestamp available

    # Query the SentinelOne API for logs since the start timestamp
    logs = get_logs(start_timestamp)

    if logs:
        # Write the logs to the local log file
        with open(log_file_path, 'a') as file:
            for log in logs['data']:
                file.write(json.dumps(log))
                file.write('\n')
        print(f"Logs written to {log_file_path}")
    else:
        print("No logs fetched.")

if __name__ == "__main__":
    main()
