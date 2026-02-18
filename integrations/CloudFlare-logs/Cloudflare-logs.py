#!/var/ossec/framework/python/bin/python3

import requests
import time
import os
from datetime import datetime, timedelta, timezone

# === CONFIGURATION ===
ZONE_ID = "XXXXXXXXXXXXXXXXXXXXXXXXXX"
API_TOKEN = "XXXXXXXXXXXXXXXXXXXXXXXXX"
OUTPUT_FILE = "/var/ossec/logs/cloudflare.log"
STATE_FILE = "/var/ossec/logs/cloudflare.last"

FIELDS = ",".join([
    "EdgeStartTimestamp", "CacheCacheStatus", "ClientDeviceType", "ClientIP",
    "ClientRequestBytes", "ClientRequestHost", "ClientRequestMethod",
    "ClientRequestProtocol", "ClientRequestReferer", "ClientRequestURI",
    "ClientRequestUserAgent", "EdgeResponseBytes", "RayID", "WAFRuleID",
    "EdgeResponseStatus", "ZoneID"
])

# === LOG FETCH FUNCTION ===
def fetch_logs(start: str, end: str):
    """Fetch logs from Cloudflare API"""
    url = (
        f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/logs/received"
        f"?fields={FIELDS}&timestamps=rfc3339&start={start}&end={end}"
    )
    headers = {"Authorization": f"Bearer {API_TOKEN}"}

    try:
        response = requests.get(url, headers=headers)
        if response.ok:
            with open(OUTPUT_FILE, "a") as f:
                f.write(response.text + "\n")
            print(f"[{datetime.now().isoformat()}] Logs fetched: {start} to {end}")
            return True
        else:
            print(f"[{datetime.now().isoformat()}] API Error {response.status_code}: {response.text}")
            return False
    except Exception as e:
        print(f"[{datetime.now().isoformat()}] Exception: {e}")
        return False

def load_last_fetched_time():
    """Load the last fetched timestamp from the state file"""
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            timestamp = f.read().strip()
            return datetime.fromisoformat(timestamp)
    else:
        # Default: start from 65 minutes ago on the first run
        return datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(minutes=65)

def save_last_fetched_time(dt):
    """Save the last fetched timestamp to the state file"""
    with open(STATE_FILE, "w") as f:
        f.write(dt.isoformat())

# === MAIN LOGIC ===
def main():
    # Get the current UTC time, rounded down to the nearest minute
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    latest_time = now - timedelta(minutes=5)  # Cloudflare log delay buffer

    # Load the last fetched time from the .last file
    last_fetched = load_last_fetched_time()

    # Calculate the next fetch time, ensuring it's at least one minute ahead
    current = last_fetched + timedelta(minutes=1)

    if current <= latest_time:
        # Define start and end times for the next log fetch
        start = current
        end = current + timedelta(minutes=60)  # Fetch logs for the past hour

        # Fetch logs and check if the operation was successful
        success = fetch_logs(start.isoformat().replace("+00:00", "Z"), end.isoformat().replace("+00:00", "Z"))

        if success:
            # Update the last fetched time in the .last file
            save_last_fetched_time(start)
        else:
            print(f"[{datetime.now().isoformat()}] Fetching logs failed. Exiting.")
            return

    print(f"[{datetime.now().isoformat()}] Script execution complete. Exiting.")

if __name__ == "__main__":
    main()
