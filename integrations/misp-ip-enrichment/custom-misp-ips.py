#!/var/ossec/framework/python/bin/python3
# Copyright (C) 2025, CIRCL and Luciano Righetti
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the AGPL-3.0 license

import json
import os
import re
import sys
from socket import AF_UNIX, SOCK_DGRAM, socket

# Exit error codes
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_BAD_IPS = 3
ERR_NO_RESPONSE_MISP = 4
ERR_SOCKET_OPERATION = 5
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

try:
    import requests
    from requests.exceptions import Timeout
except Exception:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(ERR_NO_REQUEST_MODULE)

# ossec.conf configuration example:
# <integration>
#   <name>custom-misp-fortigate-ips.py</name>
#   <hook_url>https://misp.example.org</hook_url> <!-- Replace with your MISP host -->
#   <api_key>API_KEY</api_key> <!-- Replace with your MISP API key -->
#   <group>fortigate</group>
#   <alert_format>json</alert_format>
#   <options>{
#       "timeout": 10,
#       "retries": 3,
#       "debug": false,
#       "tags": ["tlp:white", "tlp:clear", "malware"],
#       "push_sightings": true,
#       "sightings_source": "wazuh"
#   }</options>
# </integration>

# Global vars
debug_enabled = False
timeout = 10
retries = 3
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_options = {}
# IPs to ignore (benign / infrastructure)
EXCLUDED_IPS = {
    "8.8.8.8",
    "8.8.4.4",
}

# Log and socket path
LOG_FILE = f"{pwd}/logs/integrations.log"
SOCKET_ADDR = f"{pwd}/queue/sockets/queue"

# Constants (Wazuh passes: script alertfile apikey hook_url [debug] [optionsfile])
ALERT_INDEX = 1
APIKEY_INDEX = 2
MISP_URL_INDEX = 3


def main(args):
    global debug_enabled
    global timeout
    global retries
    global json_options

    try:
        bad_arguments = False

        # Wazuh may pass "debug" as 4th argument
        if len(args) >= 4:
            debug_enabled = len(args) > 4 and args[4] == "debug"

        if len(args) < 4:
            bad_arguments = True

        if bad_arguments:
            debug("# Error: Exiting, bad arguments. Inputted: %s" % args)
            sys.exit(ERR_BAD_ARGUMENTS)

        process_args(args)

    except Exception as e:
        debug(f"# Unhandled exception: {e}")
        sys.exit(1)


def process_args(args) -> None:
    global debug_enabled
    global timeout
    global retries
    global json_options

    debug("# Running MISP IPs script")

    alert_file_location: str = args[ALERT_INDEX]
    misp_url: str = args[MISP_URL_INDEX]
    apikey: str = args[APIKEY_INDEX]
    options_file_location: str = ""

    # Look for options file location (Wazuh passes it and it ends with "options")
    for idx in range(4, len(args)):
        if args[idx][-7:] == "options":
            options_file_location = args[idx]
            break

    # Load options JSON (always end up with a dict)
    if not options_file_location:
        json_options = {}
    else:
        json_options = get_json_options(options_file_location) or {}
    debug(f"# Opening options file at '{options_file_location}' with '{json_options}'")

    if "timeout" in json_options:
        if isinstance(json_options["timeout"], int) and json_options["timeout"] > 0:
            timeout = json_options["timeout"]
        else:
            debug("# Warning: Invalid timeout value. Using default")

    if "retries" in json_options:
        if isinstance(json_options["retries"], int) and json_options["retries"] >= 0:
            retries = json_options["retries"]
        else:
            debug("# Warning: Invalid retries value. Using default")

    if "debug" in json_options:
        if isinstance(json_options["debug"], bool):
            debug_enabled = json_options["debug"]
        else:
            debug("# Warning: Invalid debug value. Using default")

    # Load alert JSON
    json_alert = get_json_alert(alert_file_location)
    debug(f"# Opening alert file at '{alert_file_location}' with '{json_alert}'")

    # Request MISP info
    debug("# Requesting MISP information")
    msg = request_misp_info(json_alert, misp_url, apikey)

    if not msg:
        debug("# Error: Empty message")
        sys.exit(0)

    send_msg(msg, json_alert.get("agent"))


def debug(msg: str) -> None:
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, "a") as f:
            f.write(msg + "\n")


def is_valid_ipv4(ip: str) -> bool:
    # Basic IPv4 validation
    if not isinstance(ip, str):
        return False
    m = re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", ip.strip())
    if not m:
        return False
    parts = ip.split(".")
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False


def is_valid_ipv6(ip: str) -> bool:
    # Reasonable IPv6 validation (not perfect, but safe enough for filtering)
    if not isinstance(ip, str):
        return False
    ip = ip.strip()
    if ":" not in ip:
        return False
    # Allow compressed form, hex groups 0-4 chars
    return re.fullmatch(r"([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}", ip) is not None or "::" in ip

def is_public_ip(ip: str) -> bool:
    """
    Check if IP is public (not private/reserved).
    Returns True only for globally routable IPs.
    Filters out RFC 1918, loopback, link-local, multicast, etc.
    """
    if not isinstance(ip, str):
        return False
    
    ip = ip.strip()
    
    # Check if IPv4
    if is_valid_ipv4(ip):
        parts = [int(p) for p in ip.split(".")]
        first_octet = parts[0]
        second_octet = parts[1]
        
        # Private networks (RFC 1918)
        if first_octet == 10:  # 10.0.0.0/8
            debug(f"# Skipping private IP (10.0.0.0/8): {ip}")
            return False
        if first_octet == 172 and 16 <= second_octet <= 31:  # 172.16.0.0/12
            debug(f"# Skipping private IP (172.16.0.0/12): {ip}")
            return False
        if first_octet == 192 and second_octet == 168:  # 192.168.0.0/16
            debug(f"# Skipping private IP (192.168.0.0/16): {ip}")
            return False
        
        # Loopback (127.0.0.0/8)
        if first_octet == 127:
            debug(f"# Skipping loopback IP: {ip}")
            return False
        
        # Link-local (169.254.0.0/16)
        if first_octet == 169 and second_octet == 254:
            debug(f"# Skipping link-local IP: {ip}")
            return False
        
        # Multicast (224.0.0.0/4)
        if first_octet >= 224 and first_octet <= 239:
            debug(f"# Skipping multicast IP: {ip}")
            return False
        
        # Reserved (240.0.0.0/4)
        if first_octet >= 240:
            debug(f"# Skipping reserved IP: {ip}")
            return False
        
        # Broadcast
        if ip == "255.255.255.255":
            debug(f"# Skipping broadcast IP: {ip}")
            return False
        
        # 0.0.0.0/8
        if first_octet == 0:
            debug(f"# Skipping 0.0.0.0/8 IP: {ip}")
            return False
        
        debug(f"# Public IPv4 detected: {ip}")
        return True
    
    # Check if IPv6
    elif is_valid_ipv6(ip):
        ip_lower = ip.lower()
        
        # Loopback (::1)
        if ip_lower in ["::1", "0:0:0:0:0:0:0:1"]:
            debug(f"# Skipping IPv6 loopback: {ip}")
            return False
        
        # Link-local (fe80::/10)
        if ip_lower.startswith("fe80:"):
            debug(f"# Skipping IPv6 link-local: {ip}")
            return False
        
        # Unique local (fc00::/7)
        if ip_lower.startswith("fc") or ip_lower.startswith("fd"):
            debug(f"# Skipping IPv6 unique local: {ip}")
            return False
        
        # Multicast (ff00::/8)
        if ip_lower.startswith("ff"):
            debug(f"# Skipping IPv6 multicast: {ip}")
            return False
        
        # Unspecified (::)
        if ip_lower in ["::", "0:0:0:0:0:0:0:0"]:
            debug(f"# Skipping IPv6 unspecified: {ip}")
            return False
        
        debug(f"# Public IPv6 detected: {ip}")
        return True
    
    return False

def extract_ips(alert: dict) -> dict:
    """
    Extract data.srcip and data.dstip from FortiGate alerts.
    Returns dict like {"srcip": "x.x.x.x", "dstip": "y.y.y.y"} with ONLY PUBLIC IPs.
    """
    data = alert.get("data", {})
    src = data.get("srcip")
    dst = data.get("dstip")

    ips = {}

    # --- Source IP ---
    if src and (is_valid_ipv4(src) or is_valid_ipv6(src)):
        src = src.strip()

        if src in EXCLUDED_IPS:
            debug(f"# Skipping excluded srcip: {src}")
        elif is_public_ip(src):
            ips["srcip"] = src
        else:
            debug(f"# Filtered out private srcip: {src}")

    # --- Destination IP ---
    if dst and (is_valid_ipv4(dst) or is_valid_ipv6(dst)):
        dst = dst.strip()

        if dst in EXCLUDED_IPS:
            debug(f"# Skipping excluded dstip: {dst}")
        elif is_public_ip(dst):
            ips["dstip"] = dst
        else:
            debug(f"# Filtered out private dstip: {dst}")

    return ips



def request_ip_from_api(ips: dict, alert_output: dict, misp_url: str, api_key: str):
    for attempt in range(retries + 1):
        try:
            misp_response_data = query_api(ips, misp_url, api_key)
            return misp_response_data
        except Timeout:
            debug(
                "# Error: Request timed out. Remaining retries: %s"
                % (retries - attempt)
            )
            continue
        except Exception as e:
            debug(str(e))
            sys.exit(ERR_NO_RESPONSE_MISP)

    debug("# Error: Request timed out and maximum number of retries was exceeded")
    alert_output["misp_fortigate_ips"]["error"] = 408
    alert_output["misp_fortigate_ips"]["description"] = "Error: API request timed out"
    send_msg(alert_output)
    sys.exit(ERR_NO_RESPONSE_MISP)


def push_misp_sighting(misp_url: str, api_key: str, values: list):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "Python library-client-Wazuh-MISP",
        "Authorization": api_key,
    }

    add_sighting_payload = {"values": values, "source": "wazuh"}

    if "sightings_source" in json_options:
        if isinstance(json_options["sightings_source"], str):
            add_sighting_payload["source"] = json_options["sightings_source"]
        else:
            debug("# Warning: Invalid sightings_source value. Ignoring")

    debug("# MISP API request payload: %s" % (json.dumps(add_sighting_payload)))

    response = requests.post(
        f"{misp_url}/sightings/add",
        json=add_sighting_payload,
        headers=headers,
        timeout=timeout,
        verify=False
    )

    if response.status_code == 200:
        debug("# MISP Sighting pushed successfully")
    else:
        debug("# An error occurred pushing MISP sighting: %s" % (response.text))


def request_misp_info(alert: dict, misp_url: str, api_key: str):
    """
    Build output JSON for Wazuh, similar to the official hash integration.
    """
    alert_output = {"misp_fortigate_ips": {}, "integration": "misp_fortigate_ips"}

    ips = extract_ips(alert)

    if not ips:
        debug("# No valid data.srcip or data.dstip found in alert")
        return None

    # Request info using MISP API
    misp_response_data = request_ip_from_api(ips, alert_output, misp_url, api_key)

    alert_output["misp_fortigate_ips"]["found"] = 0
    alert_output["misp_fortigate_ips"]["source"] = {
        "alert_id": alert.get("id"),
        "srcip": alert.get("data", {}).get("srcip"),
        "dstip": alert.get("data", {}).get("dstip"),
    }

    # Check if MISP has any info
    if misp_response_data.get("response", {}).get("Attribute", []) != []:
        alert_output["misp_fortigate_ips"]["found"] = 1
    else:
        debug("# No information found in MISP for the provided IP(s)")
        return alert_output

    misp_attribute = misp_response_data.get("response").get("Attribute")[0]
    event_uuid = misp_attribute.get("Event", {}).get("uuid")
    attribute_uuid = misp_attribute.get("uuid")

    if alert_output["misp_fortigate_ips"]["found"] == 1:
        alert_output["misp_fortigate_ips"].update(
            {
                "type": misp_attribute.get("type"),
                "value": misp_attribute.get("value"),
                "uuid": attribute_uuid,
                "timestamp": misp_attribute.get("timestamp"),
                "event_uuid": event_uuid,
                "permalink": f"{misp_url}/events/view/{event_uuid}/searchFor:{attribute_uuid}",
            }
        )

    if "push_sightings" in json_options and json_options["push_sightings"]:
        push_misp_sighting(misp_url, api_key, list(ips.values()))

    return alert_output


def query_api(ips: dict, misp_url: str, api_key: str) -> dict:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "Python library-client-Wazuh-MISP",
        "Authorization": api_key,
    }

    debug("# Querying MISP API")

    # Search by values; let MISP match attribute type.
    # Types that make sense for IPs: ip-src, ip-dst, ip
    rest_search_payload = {
        "value": list(ips.values()),
        "type": ["ip-src", "ip-dst", "ip"],
        "includeEventTags": 0,
        "includeProposals": 0,
        "includeContext": 0,
        "withAttachments": 0,
        "returnFormat": "json",
        "page": 1,
        "limit": 1,
    }

    if "tags" in json_options:
        if isinstance(json_options["tags"], list) and all(
            isinstance(tag, str) for tag in json_options["tags"]
        ):
            rest_search_payload["tags"] = json_options["tags"]
        else:
            debug("# Warning: Invalid tags value. Ignoring")

    debug("# MISP API request payload: %s" % (json.dumps(rest_search_payload)))

    response = requests.post(
        f"{misp_url}/attributes/restSearch",
        json=rest_search_payload,
        headers=headers,
        timeout=timeout,
        verify=False
    )

    if response.status_code == 200:
        return response.json()

    # Error path (mirror the hash script style)
    alert_output = {"misp_fortigate_ips": {}, "integration": "misp_fortigate_ips"}

    if response.status_code == 429:
        alert_output["misp_fortigate_ips"]["error"] = response.status_code
        alert_output["misp_fortigate_ips"]["description"] = (
            "Error: API request rate limit reached"
        )
        send_msg(alert_output)
        sys.exit(0)

    if response.status_code == 403:
        alert_output["misp_fortigate_ips"]["error"] = response.status_code
        alert_output["misp_fortigate_ips"]["description"] = "Error: Check credentials"
        send_msg(alert_output)
        sys.exit(0)

    alert_output["misp_fortigate_ips"]["error"] = response.status_code
    alert_output["misp_fortigate_ips"]["description"] = "Error: API request fail"
    send_msg(alert_output)
    sys.exit(0)


def send_msg(msg: dict, agent: dict = None) -> None:
    # Keep the â€œchannel nameâ€ in the header similar to the official script,
    # but with our integration name.
    integration_name = "misp_fortigate_ips"

    if not agent or agent.get("id") == "000":
        string = "1:{0}:{1}".format(integration_name, json.dumps(msg))
    else:
        location = "[{0}] ({1}) {2}".format(
            agent.get("id"),
            agent.get("name"),
            agent.get("ip") if "ip" in agent else "any",
        )
        location = location.replace("|", "||").replace(":", "|:")
        string = "1:{0}->{1}:{2}".format(location, integration_name, json.dumps(msg))

    debug("# Request result from MISP server: %s" % string)

    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
        sock.close()
    except FileNotFoundError:
        debug("# Error: Unable to open socket connection at %s" % SOCKET_ADDR)
        sys.exit(ERR_SOCKET_OPERATION)


def get_json_alert(file_location: str) -> dict:
    try:
        # Read raw bytes (prevents UTF-8 crashes)
        with open(file_location, "rb") as f:
            raw = f.read()

        # Decode safely
        text = raw.decode("utf-8", errors="replace").strip()

        # If file is NDJSON (alerts.json), grab the last valid JSON line
        # Wazuh /var/ossec/logs/alerts/alerts.json is JSON-per-line
        if "\n" in text:
            for line in reversed(text.splitlines()):
                line = line.strip()
                if not line:
                    continue
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
            # if nothing parsed:
            debug("Failed getting JSON alert. Error: No valid JSON lines found")
            sys.exit(ERR_INVALID_JSON)

        # Single JSON object
        return json.loads(text)

    except FileNotFoundError:
        debug("# JSON file for alert %s doesn't exist" % file_location)
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        debug("Failed getting JSON alert. Error: %s" % e)
        sys.exit(ERR_INVALID_JSON)
    except Exception as e:
        debug("Failed reading JSON alert. Error: %s" % e)
        sys.exit(ERR_INVALID_JSON)


def get_json_options(file_location: str) -> dict:
    try:
        if not file_location:
            return {}
        with open(file_location) as options_file:
            return json.load(options_file)
    except FileNotFoundError:
        debug("# JSON file for options %s doesn't exist" % file_location)
        return {}
    except BaseException as e:
        debug("Failed getting JSON options. Error: %s" % e)
        sys.exit(ERR_INVALID_JSON)


if __name__ == "__main__":
    main(sys.argv)
