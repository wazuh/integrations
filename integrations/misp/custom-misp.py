#!/var/ossec/framework/python/bin/python3
## MISP API Integration
#
# ossec.conf configuration structure
#  <integration>
#      <name>custom-misp</name> <!-- This file should be named custom-misp
#      <group>sysmon_event1,sysmon_event3,sysmon_event6,sysmon_event7,sysmon_event_15,sysmon_event_22,syscheck</group
#      <hook_url>https://misp.com/attributes/restSearch/</hook_url>
#      <api_key>XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX</api_key
#      <alert_format>json</alert_format>
#  </integration>
import sys
import os
import json
import logging
from socket import socket, AF_UNIX, SOCK_DGRAM
from datetime import datetime
import ipaddress
import re

# === Error codes ===
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS     = 2
ERR_FILE_NOT_FOUND    = 6
ERR_INVALID_JSON      = 7

# === Ensure requests is available ===
try:
    import requests
    from requests.exceptions import ConnectionError, RequestException
except ImportError as e:
    print("ERROR: requests module not found, please install it.")  # in case logging isn't set up yet
    sys.exit(ERR_NO_REQUEST_MODULE)

# === Logging setup ===
LOG_DIR = "/var/log/wazuh-misp"
LOG_FILE = os.path.join(LOG_DIR, "custom-misp.log")
try:
    os.makedirs(LOG_DIR, exist_ok=True)
    logging.basicConfig(
        filename=LOG_FILE,
        format="%(asctime)s [%(levelname)s] %(message)s",
        level=logging.INFO,
    )
except Exception as e:
    print(f"Logging setup failed: {e}")
    sys.exit(1)
    
# === Queue configuration ===
QUEUE_FILE = os.path.join(LOG_DIR, "misp_queue.json")
QUEUE_TMP = QUEUE_FILE + ".inprocess"
# === Wazuh socket path ===
SOCKET_PATH = "/var/ossec/queue/sockets/queue"

pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
socket_addr = "{0}/queue/sockets/queue".format(pwd)

# === Read script arguments ===
if len(sys.argv) < 4:
    logging.error("Usage: custom-misp.py <alert_file> <misp_api_key> <misp_base_url>")
    sys.exit(ERR_BAD_ARGUMENTS)

alert_file_path = sys.argv[1]
MISP_API_KEY     = sys.argv[2]
MISP_BASE_URL    = sys.argv[3].rstrip("/")  # ensure no trailing slash

MISP_HEADERS = {
    "Content-Type": "application/json",
    "Authorization": MISP_API_KEY,
    "Accept": "application/json",
}
VERIFY_SSL = False

# Pre-compile the SHA256 regex
regex_file_hash = re.compile(r"\w{64}")

def send_event(msg, agent=None):
    """Send JSON alert back into Wazuh via UNIX socket."""
    if not agent or agent.get("id") == "000":
        payload = f"1:misp:{json.dumps(msg)}"
    else:
        payload = (
            f"1:[{agent['id']}] ({agent['name']}) "
            f"{agent.get('ip','any')}->misp:{json.dumps(msg)}"
        )
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_PATH)
        sock.send(payload.encode())
        sock.close()
    except Exception as e:
        logging.error(f"Failed to send event to Wazuh: {e}")

def queue_event(alert):
    """Append this alert JSON to the local queue for later retry."""
    try:
        os.makedirs(os.path.dirname(QUEUE_FILE), exist_ok=True)
        with open(QUEUE_FILE, "a") as f:
            f.write(json.dumps(alert) + "\n")
        logging.warning("Alert queued due to MISP API error.")
    except Exception as e:
        logging.error(f"Failed to queue alert: {e}")

def process_queue():
    """On startup, re-process any alerts left in the queue."""
    if not os.path.exists(QUEUE_FILE):
        return

    try:
        os.rename(QUEUE_FILE, QUEUE_TMP)
    except Exception as e:
        logging.error(f"Failed to rotate queue file: {e}")
        return

    failed = []
    with open(QUEUE_TMP, "r") as f:
        for line in f:
            try:
                queued_alert = json.loads(line)
                send_to_misp(queued_alert)
            except Exception as e:
                logging.error(f"Queue reprocess error: {e}")
                failed.append(line)

    if failed:
        try:
            with open(QUEUE_FILE, "w") as f:
                f.writelines(failed)
        except Exception as e:
            logging.error(f"Failed to restore failed queue: {e}")

    try:
        os.remove(QUEUE_TMP)
    except Exception as e:
        logging.error(f"Failed to remove temp queue file: {e}")

def send_to_misp(alert):
    """
    Core logic: extract indicator, query MISP, handle failures,
    and send enriched events back to Wazuh.
    """
    agent = alert.get("agent", {})
    alert_output = {}

    # 1) Determine source & type
    try:
        groups       = alert["rule"]["groups"]
        event_source = groups[0]
        event_type   = groups[2]
    except Exception as e:
        logging.error(f"Missing or malformed rule groups: {e}")
        return

    # 2) Extract the relevant indicator
    try:
        if event_source == "windows":
            data = alert["data"]["win"]["eventdata"]
            if event_type == "sysmon_event1":
                param = regex_file_hash.search(data["hashes"]).group(0)
            elif event_type == "sysmon_event3" and data["destinationIsIpv6"] == "false":
                ip = data["destinationIp"]
                if ipaddress.ip_address(ip).is_global:
                    param = ip
                else:
                    return
            elif event_type in (
                "sysmon_event6", "sysmon_event7",
                "sysmon_event_15", "sysmon_event_23",
                "sysmon_event_24", "sysmon_event_25"
            ):
                param = regex_file_hash.search(data["hashes"]).group(0)
            elif event_type == "sysmon_event_22":
                param = data["queryName"]
            else:
                return

        elif event_source == "linux":
            data = alert["data"]["eventdata"]
            if event_type == "sysmon_event3" and data["destinationIsIpv6"] == "false":
                ip = data["DestinationIp"]
                if ipaddress.ip_address(ip).is_global:
                    param = ip
                else:
                    return
            else:
                return

        elif event_source == "ossec" and event_type == "syscheck_entry_added":
            param = alert["syscheck"]["sha256_after"]
        else:
            return

    except Exception as e:
        logging.error(f"Error extracting parameter: {e}")
        return

    # 3) Query MISP
    misp_search_url = f"{MISP_BASE_URL}/value:{param}"
    try:
        resp = requests.get(
            misp_search_url,
            headers=MISP_HEADERS,
            verify=VERIFY_SSL,
            timeout=10
        )
        resp.raise_for_status()
    except (ConnectionError, RequestException) as e:
        logging.error(f"MISP connection error: {e}")
        queue_event(alert)
        send_event({
            "misp": {"error": f"Connection to MISP API failed: {e}"},
            "integration": "misp"
        }, agent)
        return

    # 4) Parse response
    try:
        result = resp.json()
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON from MISP: {e}")
        sys.exit(ERR_INVALID_JSON)

    attrs = result.get("response", {}).get("Attribute", [])
    if attrs:
        entry = attrs[0]
        alert_output["misp"] = {
            "event_id": entry.get("event_id"),
            "category": entry.get("category"),
            "value":    entry.get("value"),
            "type":     entry.get("type"),
            "source":   {"description": alert["rule"].get("description", "")}
        }
        alert_output["integration"] = "misp"
        send_event(alert_output, agent)
        logging.info(f"MISP match sent for indicator: {param}")
    else:
        logging.info(f"No MISP match for indicator: {param}")

if __name__ == "__main__":
    # Retry any queued alerts first
    process_queue()

    # Then load and process this one
    try:
        with open(alert_file_path, "r") as f:
            alert = json.load(f)
    except FileNotFoundError as e:
        logging.error(f"Alert file not found: {e}")
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON in alert file: {e}")
        sys.exit(ERR_INVALID_JSON)

    try:
        send_to_misp(alert)
    except Exception as e:
        logging.error(f"Unexpected error during processing: {e}")
        # Final fallback notification
        try:
            send_event({
                "misp": {"error": f"MISP processing error: {e}"},
                "integration": "misp"
            }, alert.get("agent", {}))
        except Exception:
            logging.error("Fallback send_event also failed.")

