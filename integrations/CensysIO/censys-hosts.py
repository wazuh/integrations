import requests
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
from socket import AF_UNIX, SOCK_DGRAM, socket
import logging

# --- Configuration ---
CENSYS_API_KEY = os.getenv("CENSYS_API_KEY")
CENSYS_BASE_URL = "https://app.censys.io/api"

CENSYS_INVENTORY_SEARCH_URL = f"{CENSYS_BASE_URL}/inventory/v1"

WAZUH_SOCKET_ADDR = "/var/ossec/queue/sockets/queue"
WAZUH_LABEL = "censys_hosts" # Label for host events sent to Wazuh

TIME_WINDOW_HOURS = 24 # Fetch hosts discovered in the past 24 hours
REQUEST_TIMEOUT_SECONDS = 30 # Timeout for HTTP requests to Censys API

CENSYS_WORKSPACES = os.getenv("CENSYS_WORKSPACE")

LOG_FILE = "/var/ossec/logs/integrations.log"

# --- Logging Configuration ---
import logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - custom-censys: %(message)s')

def is_valid_json(data):
    """
    Checks if a given string is a valid JSON format.

    Args:
        data (str): The string to validate.

    Returns:
        bool: True if the string is valid JSON, False otherwise.
    """
    try:
        json.loads(data)
        return True
    except ValueError:
        return False

def recursively_transform(data):
    """
    Recursively traverses a data structure (dictionary or list) and transforms
    lists of dictionaries into dictionaries with string indices as keys.
    This is necessary to ensure compatibility with Wazuh's JSON parsing,
    which can sometimes struggle with nested lists of dictionaries.

    Args:
        data (dict or list): The data structure to transform.

    Returns:
        dict or list: The transformed data structure.
    """
    if isinstance(data, dict):
        # If it's a dictionary, recursively transform its values
        transformed_dict = {}
        for k, v in data.items():
            if isinstance(v, list):
                # If a value is a list, check if it's a list of dictionaries
                if v and all(isinstance(item, dict) for item in v):
                    # If it's a list of dictionaries, convert it to a dictionary
                    # where keys are string indices and values are the transformed dictionaries.
                    transformed_dict[k] = {str(i): recursively_transform(item) for i, item in enumerate(v)}
                else:
                    # If it's a list of non-dictionaries, just recursively transform its elements
                    transformed_dict[k] = [recursively_transform(item) for item in v]
            elif isinstance(v, dict):
                # If a value is a dictionary, recursively transform it
                transformed_dict[k] = recursively_transform(v)
            else:
                # If it's a primitive type, keep it as is
                transformed_dict[k] = v
        return transformed_dict
    elif isinstance(data, list):
        # If the top-level data is a list, recursively transform each item in the list
        return [recursively_transform(item) for item in data]
    else:
        # For primitive types (int, str, bool, None), return as is
        return data

def send_event_to_wazuh(event_data, label):
    """
    Sends a Python dictionary event to the Wazuh Unix domain socket.
    The event_data will be wrapped under the specified label for Wazuh processing.

    Args:
        event_data (dict): The dictionary containing the event data to send.
        label (str): The label to associate with the event in Wazuh (e.g., "censys_hosts").

    Returns:
        bool: True if the event was sent successfully, False otherwise.
    """
    try:
        # Wazuh expects the event data to be wrapped under a key, which is the label.
        wazuh_event_payload = {label: event_data}
        wazuh_event_json_string = json.dumps(wazuh_event_payload)

        # Validate the final JSON string before sending to prevent issues at the Wazuh end.
        if not is_valid_json(wazuh_event_json_string):
            logging.error(f"Invalid JSON format generated for Wazuh event. Skipping send. Data: {wazuh_event_json_string}")
            return False

        # The string format expected by the Wazuh socket is "1:LABEL:JSON_EVENT".
        # '1' is a standard prefix for event messages.
        string_to_send = f'1:{label}:{wazuh_event_json_string}'

        # Create a Unix domain socket and connect to the Wazuh queue socket.
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(WAZUH_SOCKET_ADDR)

        # Send the encoded string over the socket.
        sock.send(string_to_send.encode())

        # Close the socket connection.
        sock.close()

        logging.info(f"Event successfully sent to Wazuh socket for label '{label}'.")
        logging.debug(f"Sent to Wazuh: {string_to_send}")
        return True
    except FileNotFoundError:
        logging.error(f'Error: Unable to open Wazuh socket connection at {WAZUH_SOCKET_ADDR}. '
                      f'Ensure Wazuh is running and the socket path is correct.')
        return False
    except json.JSONDecodeError as e:
        logging.error(f'Error encoding JSON message for Wazuh: {e}. Raw event_data: {event_data}')
        return False
    except Exception as e:
        logging.error(f'An unexpected error occurred while sending event to Wazuh socket: {e}')
        return False

def fetch_and_send_censys_hosts():
    """
    Fetches new host instances from the Censys API discovered in the past 24 hours
    and sends each as a JSON-formatted event to the Wazuh socket.
    """
    if not CENSYS_API_KEY:
        logging.error("CENSYS_API_KEY environment variable is not set. Please set it before running the script.")
        print("Error: CENSYS_API_KEY environment variable not set.")
        return False

    if not CENSYS_WORKSPACES:
        logging.error("CENSYS_WORKSPACES is not set. Please specify at least one workspace ID.")
        print("Error: CENSYS_WORKSPACES not set.")
        return False

    logging.info(f"Starting Censys host collection for the past {TIME_WINDOW_HOURS} hour(s).")

    # Set up headers for Censys API authentication.
    headers = {"Censys-Api-Key": CENSYS_API_KEY}

    # Construct the Censys DSL query string for hosts discovered in the time window.
    # Using 'association_date' and relative time 'now-{X}h TO now' for compatibility with Censys GUI.
    censys_query_string = f"association_date: [now-{TIME_WINDOW_HOURS}h TO now]"

    next_cursor = None
    total_hosts_sent = 0
    page_number = 1

    logging.info(f"Querying Censys Inventory Search API for hosts using query: '{censys_query_string}'")

    # Loop through all pages of results from the Censys API.
    while True:
        logging.debug(f"Fetching page {page_number} from Censys Inventory Search API.")

        # Parameters for the GET request
        params = {
            "query": censys_query_string,
            "pageSize": 1000, # Max limit per page as per documentation
            "workspaces": CENSYS_WORKSPACES, # The requests library will handle this list correctly
            # ADDED: Include all specified fields to get comprehensive information
            "fields": [
                "host.ip",
                "host.dns.names",
                "host.dns.reverse_dns.names",
                "host.services.port",
                "host.services.extended_service_name",
                "host.services.service_name",
                "host.services.software.vendor",
                "host.services.software.product",
                "host.services.software.version",
                "host.services.software.other.key",
                "host.services.software.other.value",
                "host.labels",
                "host.location.country",
                "host.cloud",
                "host.autonomous_system.asn",
                "host.autonomous_system.name"
            ]
        }

        # Add cursor for pagination if available
        if next_cursor:
            params["cursor"] = next_cursor
            logging.debug(f"Setting cursor for next request: {params['cursor']}")

        logging.debug(f"Request URL (base): {CENSYS_INVENTORY_SEARCH_URL}")
        logging.debug(f"Request Parameters: {params}") # Log the dictionary before requests encodes it
        logging.debug(f"Request Headers: {headers}")

        try:
            # Make the HTTP GET request to the Censys API.
            # requests.get will automatically URL-encode the parameters from the 'params' dictionary.
            response = requests.get(CENSYS_INVENTORY_SEARCH_URL, headers=headers, params=params, timeout=REQUEST_TIMEOUT_SECONDS)
            response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx).

            data = response.json() # Parse the JSON response.
            logging.debug(f"Response JSON (Page {page_number}): {json.dumps(data, indent=2)}")

            # Filter for only 'HOST' type assets after receiving the response.
            # The API returns 'hits' which can be of various types (HOST, WEB_ENTITY, etc.)
            all_hits = data.get("hits", [])
            hosts = [hit for hit in all_hits if hit.get('type') == 'HOST']

            logging.debug(f"Found {len(all_hits)} total hits. Filtered down to {len(hosts)} HOST type assets.")

            if not hosts:
                logging.info(f"No new HOSTs found on page {page_number} for the specified time window or no more pages.")
                # Continue fetching next page even if no HOSTs found on this page, as other types might be present.
                # Only break if nextCursor is explicitly None.
                if not data.get("nextCursor"):
                    break

            # Process and send each host to Wazuh.
            for raw_host in hosts:
                # Transform the raw host data to a Wazuh-compatible format.
                processed_host = recursively_transform(raw_host)
                if send_event_to_wazuh(processed_host, WAZUH_LABEL):
                    total_hosts_sent += 1
                else:
                    logging.warning(f"Failed to send a host event to Wazuh. Host data: {raw_host}. "
                                    f"This event will not be processed by Wazuh.")

            # Update cursor for the next page.
            next_cursor = data.get("nextCursor")
            if not next_cursor:
                logging.info("No more pages of hits found.")
                break # No more pages to fetch.

            page_number += 1

        except requests.exceptions.HTTPError as e:
            logging.error(f"HTTP Error during Censys API request (Page {page_number}): {e}. "
                          f"Response status code: {e.response.status_code if e.response else 'N/A'}. "
                          f"Response text: {e.response.text if e.response else 'N/A'}")
            # Add more detailed logging for HTTP errors
            if e.response is not None:
                logging.error(f"Detailed HTTP Error Response: Status Code: {e.response.status_code}, Content: {e.response.text}")
            return False
        except requests.exceptions.ConnectionError as e:
            logging.error(f"Connection Error during Censys API request (Page {page_number}): {e}. "
                          f"Please check network connectivity or Censys API availability.")
            return False
        except requests.exceptions.Timeout as e:
            logging.error(f"Timeout Error during Censys API request (Page {page_number}): {e}. "
                          f"The request took longer than {REQUEST_TIMEOUT_SECONDS} seconds to respond.")
            return False
        except json.JSONDecodeError as e:
            logging.error(f"JSON Decode Error processing Censys API response (Page {page_number}): {e}. "
                          f"The response text from Censys API might be malformed. "
                          f"Raw response: {response.text if 'response' in locals() else 'N/A'}")
            return False
        except Exception as e:
            logging.error(f"An unexpected error occurred during Censys API fetching (Page {page_number}): {e}", exc_info=True)
            return False

    logging.info(f"Censys host collection complete. Successfully sent a total of {total_hosts_sent} new host detections to Wazuh.")
    return True

def main():
    """
    Main function to execute the Censys Hosts to Wazuh integration script.
    """
    logging.info("Censys Hosts Wazuh Integration script started.")
    if fetch_and_send_censys_hosts():
        logging.info("Censys Hosts Wazuh Integration script finished successfully.")
    else:
        logging.error("Censys Hosts Wazuh Integration script finished with errors. Check logs for details.")

if __name__ == "__main__":
    main()
