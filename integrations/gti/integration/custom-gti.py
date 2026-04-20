# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.


import json
import os
import re
import sys
import time
import base64
from datetime import datetime, timezone
from socket import AF_UNIX, SOCK_DGRAM, socket

WAZUH_HOME = os.environ.get("WAZUH_HOME", "/var/ossec")

# Exit error codes
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_BAD_MD5_SUM = 3
ERR_NO_RESPONSE_VT = 4
ERR_SOCKET_OPERATION = 5
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

try:
    import requests
except Exception:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(ERR_NO_REQUEST_MODULE)

# Global vars
timeout = 10
retries = 3
json_alert = {}

# Log and socket path
LOG_FILE = os.path.join(WAZUH_HOME, "logs", "gti-integration.log")
SOCKET_ADDR = os.path.join(WAZUH_HOME, "queue", "sockets", "queue")
GTI_MALICIOUS_IP = os.path.join(WAZUH_HOME, "integrations", "gti_iocs", "malicious_ips.json")
GTI_MALICIOUS_URL = os.path.join(WAZUH_HOME, "integrations", "gti_iocs", "malicious_urls.json")
GTI_MALICIOUS_DOMAIN = os.path.join(WAZUH_HOME, "integrations", "gti_iocs", "malicious_domains.json")
GTI_MALICIOUS_FILE_HASHES = os.path.join(WAZUH_HOME, "integrations", "gti_iocs", "malicious_filehashes.json")

# Constants
ALERT_INDEX = 1
APIKEY_INDEX = 2
CONF_OPTIONS_INDEX = 5
TIMEOUT_INDEX = 6
RETRIES_INDEX = 7

BASE_URL = "https://www.virustotal.com/api/v3/"
VULN_INFO_API = "collections/{id}"
FILE_MITRE_INFO_API = "files/{id}/behaviour_mitre_trees"
FILE_HASH_INFO_API = "files/{id}"
IP_INFO_API = "ip_addresses/{id}"
DOMAIN_INFO_API = "domains/{id}"
URL_INFO_API = "urls/{id}"

VULNERABILITY_FIELDS = [
    "analysis", "available_mitigation", "cve_id", "cvss", "collection_type",
    "description", "epss", "executive_summary", "exploit_availability",
    "exploitation_consequence", "exploitation_state", "exploitation_vectors",
    "name", "origin", "predicted_risk_rating", "priority", "risk_rating",
    "status", "workarounds"
]

IOC_FIELDS = {
    "verdict": "gti_assessment.verdict.value",
    "severity": "gti_assessment.severity.value",
    "threat_score": "gti_assessment.threat_score.value",
    "country": "country",
    "asn": "asn",
    "as_owner": "as_owner",
    "creation_date": "creation_date",
    "last_modification_date": "last_modification_date",
    "last_submission_date": "last_submission_date",
    "last_analysis_date": "last_analysis_date",
    "md5": "md5",
    "sha256": "sha256",
    "meaningful_name": "meaningful_name"
}

ASSESSMENT_MAPPING = {
    "v": "verdict",
    "s": "severity",
    "ts": "threat_score",
    "c": "country",
    "asn": "asn",
    "ao": "as_owner",
    "cd": "creation_date",
    "lmd": "last_modified_date",
    "lsd": "last_submission_date",
    "lad": "last_analysis_date",
    "md5": "md5",
    "sha256": "sha256",
    "mn": "meaningful_name",
}

IP_EXTRACT = [
    "srcip", "src_ip", "source_ip", "client_ip", "dst_ip", "destination_ip", "dstip", "DestinationIP", "remote_ip",
    "external_ip", "SourceIP", "source_ip_address", "clientIP_s", "IPAddress", "originalHost_s", "CallerIPAddress"
]
URL_EXTRACT = [
    "url", "source_url", "TargetURL", "download_url", "http_url"
]
FIELD_HASH_EXTRACT = [
    "sha256", "file_digest", "hash", "file_sha1", "sha1sum", "sha1", "sha256sum", "file_sha256",
    "md5", "md5sum", "file_md5", "hashes"
]
DOMAIN_EXTRACT = ["domain"]
VULN_EXTRACT = ["cve"]

# Extract a source IP from common alert shapes
IPV6_RE = re.compile(r"\b([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")

# More strict IPv4 regex (avoid matching partial tokens)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")


class APIError(Exception):
    def __init__(self, status_code, message):
        self.status_code = status_code
        self.message = message
        super().__init__(f"{status_code}: {message}")


class GTILogger:

    def __init__(self, level="INFO"):
        level = level.strip().upper()
        if level == "DEBUG":
            self.log_level = 1
        elif level == "INFO":
            self.log_level = 2
        elif level == "WARN":
            self.log_level = 3
        elif level == "ERROR":
            self.log_level = 4
        else:
            self.log_level = 2

    def info(self, msg: str):
        if self.log_level <= 2:
            self.write_log("INFO", msg)

    def debug(self, msg: str):
        if self.log_level <= 1:
            self.write_log("DEBUG", msg)

    def warn(self, msg: str):
        if self.log_level <= 3:
            self.write_log("WARN", msg)

    def error(self, msg: str):
        if self.log_level <= 4:
            self.write_log("ERROR", msg)

    def write_log(self, level: str, msg: str):
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        line = f"{ts} {level}: {msg}"
        try:
            with open(LOG_FILE, "a") as f:
                f.write(line + "\n")
        except Exception:
            pass
        if level == "ERROR":
            print(line, file=sys.stderr)


def construct_info_dict(source_dict: dict, field_mapping: dict) -> dict:
    """
    Extract fields from a nested dictionary using dot notation paths.
    
    Args:
        source_dict: The source dictionary with potentially nested data
        field_mapping: A dictionary mapping output keys to dot-notation paths
        
    Returns:
        A new dictionary with extracted values
    """
    result = {}
    for output_key, path in field_mapping.items():
        # Split the path by dots to traverse nested structure
        keys = path.split('.')
        value = source_dict

        # Traverse the nested dictionary
        try:
            for key in keys:
                value = value[key]
            result[output_key] = value
        except (KeyError, TypeError):
            # If path doesn't exist, skip or set to None
            result[output_key] = None

    return result


def extract_vulnerability_fields(source_dict: dict, vulnerability_fields: list) -> dict:
    """
    Extract specified fields from a vulnerability dictionary.
    Supports nested fields with dot notation (e.g., "cvss.cvssv2_0.base_score").
    
    Args:
        source_dict (dict): The source vulnerability dictionary
        vulnerability_fields (list): List of field names to extract
        
    Returns:
        dict: A new dictionary containing only the specified fields
    """
    result = {}
    for field in vulnerability_fields:
        # Handle nested fields with dot notation
        if '.' in field:
            parts = field.split('.')

            # Navigate through the source dictionary
            current_source = source_dict
            valid_path = True
            for part in parts[:-1]:
                if isinstance(current_source, dict) and part in current_source:
                    current_source = current_source[part]
                else:
                    valid_path = False
                    break

            # If path is valid and final key exists, add to result
            if valid_path and isinstance(current_source, dict) and parts[-1] in current_source:
                # Build the nested structure in result
                current_result = result
                for i, part in enumerate(parts[:-1]):
                    if part not in current_result:
                        current_result[part] = {}
                    current_result = current_result[part]

                # Set the final value
                current_result[parts[-1]] = current_source[parts[-1]]
        else:
            # Handle top-level fields
            if field in source_dict:
                result[field] = source_dict[field]

    return result


def convert_mitre_structure(data):
    """
    Converts a MITRE ATT&CK JSON structure from lists to keyed dictionaries.
    - Tactics are keyed by their 'id'.
    - Techniques are keyed by their 'id'.
    - Signatures are keyed by their index string.
    """
    output = {}

    for tool_name, tool_data in data.items():
        new_tool_data = {}
        
        # Process Tactics
        if "tactics" in tool_data:
            tactics_dict = {}
            for tactic in tool_data["tactics"]:
                tactic_id = tactic.get("id")
                
                # Clone tactic and remove id from internal fields if desired, 
                # or just copy the dictionary.
                tactic_entry = {k: v for k, v in tactic.items() if k != "id"}
                
                # Process Techniques within Tactic
                if "techniques" in tactic:
                    techniques_dict = {}
                    for tech in tactic["techniques"]:
                        tech_id = tech.get("id")
                        tech_entry = {k: v for k, v in tech.items() if k != "id"}
                        
                        # Process Signatures within Technique
                        if "signatures" in tech:
                            signatures_dict = {}
                            for idx, sig in enumerate(tech["signatures"]):
                                signatures_dict[str(idx)] = sig
                            tech_entry["signatures"] = signatures_dict
                            
                        techniques_dict[tech_id] = tech_entry
                    tactic_entry["techniques"] = techniques_dict
                
                tactics_dict[tactic_id] = tactic_entry
            new_tool_data["tactics"] = tactics_dict
            
        output[tool_name] = new_tool_data
        
    return output

def main(args):
    global logger
    global timeout
    global retries
    global APIKEY
    global alert_file_location
    global fetch_mi_att_info
    global realtime_enrichment
    global log_level
    global IP_C_FIELDS
    global URL_C_FIELDS
    global DOM_C_FIELDS
    global FL_C_FIELDS
    global VUL_C_FIELDS
    global IP_EXTRACT
    global FIELD_HASH_EXTRACT
    global DOMAIN_EXTRACT
    global VULN_EXTRACT
    global URL_EXTRACT
    try:
        # Read arguments
        options_json = {}

        if len(args) > CONF_OPTIONS_INDEX:
            options_json = get_json_alert(args[5])

        fetch_mi_att_info = str(options_json.get("mitre_attack", "true")).strip().lower() in ("true")
        realtime_enrichment = str(options_json.get("realtime", "false")).strip().lower() in ("true")
        log_level = str(options_json.get("log_level", "INFO"))
        custom_ip_fields = str(options_json.get("ip_fields", "")).split(',')
        custom_domain_fields = str(options_json.get("domain_fields", "")).split(',')
        custom_url_fields = str(options_json.get("url_fields", "")).split(',')
        custom_filehash_fields = str(options_json.get("filehash_fields", "")).split(',')
        custom_vuln_fields = str(options_json.get("vuln_fields", "")).split(',')
        IP_C_FIELDS = [item.strip() for item in custom_ip_fields if item and item.strip()]
        DOM_C_FIELDS = [item.strip() for item in custom_domain_fields if item and item.strip()]
        URL_C_FIELDS = [item.strip() for item in custom_url_fields if item and item.strip()]
        FL_C_FIELDS = [item.strip() for item in custom_filehash_fields if item and item.strip()]
        VUL_C_FIELDS = [item.strip() for item in custom_vuln_fields if item and item.strip()]

        IP_EXTRACT = [x for x in IP_EXTRACT if x not in IP_C_FIELDS]
        DOMAIN_EXTRACT = [x for x in DOMAIN_EXTRACT if x not in DOM_C_FIELDS]
        URL_EXTRACT = [x for x in URL_EXTRACT if x not in URL_C_FIELDS]
        FIELD_HASH_EXTRACT = [x for x in FIELD_HASH_EXTRACT if x not in FL_C_FIELDS]
        VULN_EXTRACT = [x for x in VULN_EXTRACT if x not in VUL_C_FIELDS]

        if log_level not in ("DEBUG", "INFO", "WARN", "ERROR"):
            log_level = "INFO"

        logger = GTILogger(log_level)

        alert_file_location = str(args[ALERT_INDEX])
        APIKEY = args[APIKEY_INDEX]

        if len(args) >= 4:
            if len(args) > TIMEOUT_INDEX:
                timeout = int(args[TIMEOUT_INDEX])
            if len(args) > RETRIES_INDEX:
                retries = int(args[RETRIES_INDEX])
        else:
            logger.debug('# Error: Exiting, bad arguments. Inputted: %s' % args)
            sys.exit(ERR_BAD_ARGUMENTS)

        logger.debug(
            f"Arguments passed in integration: Alert File Path = {alert_file_location},"
            f" API KEY = {APIKEY}, File Mitre Attack = {fetch_mi_att_info}, Log Level = {log_level},"
            f" Realtime Enrichment = {realtime_enrichment}, timeout = {timeout}, retries = {retries}."
        )

        # Core function
        process_args()

    except Exception as e:
        raise Exception(f"Error Occurred: {str(e)}")


def process_args() -> None:
    """This is the core function, creates a message with all valid fields
    and overwrite or add with the optional fields

    """
    logger.info('# Running GTI script')

    # Load alert. Parse JSON object.
    json_alert = get_json_alert(alert_file_location)

    logger.info(f"# Opening alert file at '{alert_file_location}' with '{json_alert}'")

    if 'integration' in json_alert.get('data', {}):
        logger.debug(f"# Alert generated from integration {json_alert.get('data', {}).get('integration', '')}")
        sys.exit(0)

    #  Requesting GTI enriched info
    msg: any = request_gti_info(json_alert)

    if not msg:
        logger.debug('# Error: Empty message')
        raise Exception

    send_msg(msg, json_alert['agent'])


def fetch_ioc_detail(json_file, key):
    """
    Query a Json file
    """
    try:
        for attempt in range(4):
            try:
                with open(json_file, 'r') as file:
                    data = json.load(file)
                return data.get(key, {})
            except (json.JSONDecodeError, OSError) as e:
                if attempt == 3:
                    raise e
                time.sleep(0.05 * (attempt + 1))
    except Exception as e:
        logger.error(f"# Error occurred while reading JSON file {str(e)}")
        return {'error': {'description': str(e)}}

def pick_iocs(alert):
    logger.debug('# Extracting IOCs')

    ioc_extracts = dict()
    ioc_extracts['ip_info'] = extract_ioc_values(alert, IP_EXTRACT, "ip")
    if IP_C_FIELDS:
        cust_ext_ip = extract_ioc_values(alert, IP_C_FIELDS, "ip")
        if cust_ext_ip:
            ioc_extracts['ip_info'].update(cust_ext_ip)
        else:
            logger.warn(f"No IP custom fields {IP_C_FIELDS} found in alert.")

    ioc_extracts['url_info'] = extract_ioc_values(alert, URL_EXTRACT, "url")
    if URL_C_FIELDS:
        cust_ext_url = extract_ioc_values(alert, URL_C_FIELDS, "url")
        if cust_ext_url:
            ioc_extracts['url_info'].update(cust_ext_url)
        else:
            logger.warn(f"No URL custom fields {URL_C_FIELDS} found in alert.")

    ioc_extracts['domain_info'] = extract_ioc_values(alert, DOMAIN_EXTRACT, "domain")
    if DOM_C_FIELDS:
        cust_ext_domain = extract_ioc_values(alert, DOM_C_FIELDS, "domain")
        if cust_ext_domain:
            ioc_extracts['domain_info'].update(cust_ext_domain)
        else:
            logger.warn(f"No Domain custom fields {DOM_C_FIELDS} found in alert.")

    ioc_extracts['file_hashes_info'] = extract_ioc_values(alert, FIELD_HASH_EXTRACT, "file_hashes")
    if FL_C_FIELDS:
        cust_ext_file = extract_ioc_values(alert, FL_C_FIELDS, "file_hashes")
        if cust_ext_file:
            ioc_extracts['file_hashes_info'].update(cust_ext_file)
        else:
            logger.warn(f"No File Hash custom fields {FL_C_FIELDS} found in alert.")

    ioc_extracts['vulnerability_info'] = extract_ioc_values(alert, VULN_EXTRACT, "vulnerability")
    if VUL_C_FIELDS:
        cust_ext_vul = extract_ioc_values(alert, VUL_C_FIELDS, "vulnerability")
        if cust_ext_vul:
            ioc_extracts['vulnerability_info'].update(cust_ext_vul)
        else:
            logger.warn(f"No Vulnerability custom fields {VUL_C_FIELDS} found in alert.")

    return ioc_extracts

def extract_ioc_values(data, fields_to_check, ioc_type):
    """
    Find multiple keys in nested JSON and return only primitive values.
    
    Args:
        data: Dictionary or list to search
        fields_to_check: List of keys to find
        
    Returns:
        Dictionary with each key and list of primitive values found.
        Only includes keys that were actually found.
    """
    # Initialize results dictionary with empty lists for each key
    temp_results = {key: [] for key in fields_to_check}
    def _search(obj):
        if isinstance(obj, dict):
            for target_key in fields_to_check:
                if target_key in obj:
                    value = obj[target_key]
                    # Check if value is a primitive type
                    if isinstance(value, (str, int, float, bool)):
                        if ioc_type == "vulnerability":
                            temp_results[target_key].append("vulnerability--" + value.lower())
                        elif ioc_type == "ip":
                                m = IPV4_RE.search(value) or IPV6_RE.search(value)
                                if m:
                                    temp_results[target_key].append(m.group(0))
                        else:
                            temp_results[target_key].append(value)
            
            for value in obj.values():
                _search(value)
        
        elif isinstance(obj, list):
            for item in obj:
                _search(item)
    
    _search(data)
    
    # Return only keys that have values
    return {key: values for key, values in temp_results.items() if values}


def request_info_from_api(api, alert_key):
    """Request information from an API using the provided alert and API key.

    Parameters
    ----------
    api : str
        The API required for making the API request.
    alert_key : string
        The alert dictionary containing information for the API request.

    Returns
    -------
    dict
        The response data received from the API.

    Raises
    ------
    Timeout
        If the API request times out.
    Exception
        If an unexpected exception occurs during the API request.
    """
    try:
        api = f"{BASE_URL}{api}"
        request_obj = {"HEADER": {"accept": "application/json", "x-tool": "wazuh", "x-apikey": APIKEY},
                       "API": api.format(id=alert_key)}
        gti_response = query_api(request_obj)
        data = gti_response.get("data", {})
        return data.get("attributes", data)  # mitre attack info result does not containing attributes property
    except APIError as e:
        alert_output = {"error": {"code": getattr(e, 'status_code', ""), "description": getattr(e, 'message', "")}}
        return alert_output
    except Exception as e:
        alert_output = {"error": {"description": "Error occurred during API call " + str(e)}}
        logger.error(f"Error occurred while fetching information from GTI API: {str(e)}")
        return alert_output


def request_gti_info(alert: any):
    """Generate the JSON object with the message to be send

    Parameters
    ----------
    alert : any
        JSON alert object.

    Returns
    -------
    msg: str
        The JSON message to send
    """
    # GTI enriched object structure
    gti_alert_output = {
        'alert_info': {'rule_id': '', 'rule_description': '', 'alert_id': '', 'full_logs': '', 'alert_decoder': '',
                       'alert_data': ''},
        'gti_assessment': {'ip_info': {}, 'url_info': {}, 'domain_info': {}, 'file_hashes_info': {},
                           'vulnerability_info': {}},
        'integration': 'GTI'
    }

    # Populating alert details in GTI enriched object
    gti_alert_output['alert_info']['rule_id'] = alert.get('rule', {}).get('id', None)
    gti_alert_output['alert_info']['rule_description'] = alert.get('rule', {}).get('description', None)
    gti_alert_output['alert_info']['alert_id'] = alert.get('id', None)
    gti_alert_output['alert_info']['full_logs'] = alert.get('full_log', None)
    gti_alert_output['alert_info']['alert_decoder'] = json.dumps(alert.get('decoder', {}))
    gti_alert_output['alert_info']['alert_data'] = json.dumps(alert.get('data', {}))

    # Extract IOCs and vulnerability id from alert
    extracted_iocs = pick_iocs(alert)
    logger.info(f"# Extracted IOCs for enrichment: {extracted_iocs}")
    for ioc in extracted_iocs:
        for field_key in extracted_iocs[ioc]:
            ioc_info = []
            for ioc_value in extracted_iocs[ioc][field_key]:
                if ioc == "vulnerability_info":
                    # Requesting vulnerability detail from GTI API
                    enriched_data = request_info_from_api(VULN_INFO_API, ioc_value)
                    if enriched_data:
                        enriched_data["ioc_value"] = ioc_value
                        if "error" not in enriched_data:
                            enriched_data = extract_vulnerability_fields(enriched_data, VULNERABILITY_FIELDS)
                    gti_alert_output['gti_assessment'][ioc] = enriched_data
                else:
                    # Requesting IOC detail
                    enriched_data = enrich_ioc(ioc, ioc_value)
                    ioc_info.append(enriched_data)
            if ioc != "vulnerability_info":
                gti_alert_output['gti_assessment'][ioc].update({field_key: ioc_info})

    logger.info(f"# GTI Assessment for extracted IOCs: {gti_alert_output.get('gti_assessment')}")
    return gti_alert_output


def enrich_ioc(info_key: str, ioc_value: str) -> any:
    """Enrich ioc with information

    Parameters
    ----------
    key : str
        IOC Type
    value : str
        IOC value

    Returns
    -------
    any
        Enriched IOC information
    """

    logger.debug(f"# Requesting {info_key} in GTI")

    enrich_info = {}

    if info_key == "file_hashes_info":
        api = FILE_HASH_INFO_API
        ioc_file = GTI_MALICIOUS_FILE_HASHES
    elif info_key == "domain_info":
        api = DOMAIN_INFO_API
        ioc_file = GTI_MALICIOUS_DOMAIN
    elif info_key == "url_info":
        api = URL_INFO_API
        ioc_file = GTI_MALICIOUS_URL
    elif info_key == "ip_info":
        api = IP_INFO_API
        ioc_file = GTI_MALICIOUS_IP
    else:
        return {"error": {'description': f"Invalid operation type {info_key}"}}

    # Fetching the IOC detail on the basis of user configured option in gti_config.ini (GTI API or JSON file)
    if realtime_enrichment:
        logger.debug(f"# Requesting {info_key} for '{ioc_value}' from GTI API {api}")
        fields_dict = IOC_FIELDS
        if info_key == "url_info":
            url_value = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip("=")
            enrich_info = request_info_from_api(api, url_value)
        else:
            enrich_info = request_info_from_api(api, ioc_value)
        if enrich_info and "error" not in enrich_info:
            enrich_info = construct_info_dict(enrich_info, fields_dict)
    else:
        logger.debug(f"# Requesting {info_key} for '{ioc_value}' from JSON file {ioc_file}")
        enriched_info_dict = fetch_ioc_detail(ioc_file, ioc_value)
        enriched_info_dict.pop('exp', None)
        for key, value in enriched_info_dict.items():
            if key in ASSESSMENT_MAPPING:
                enrich_info[ASSESSMENT_MAPPING[key]] = value
            else:
                logger.warn(f"Key '{key}' not found in ASSESSMENT_MAPPING. {ioc_file} might be changed/modified.")

    # Requesting FILE MITRE ATTACK INFO from GTI API (if configured in gti_config.ini)
    if info_key == "file_hashes_info" and fetch_mi_att_info:
        logger.debug(f"# Requesting File Mitre Attack Info for '{ioc_value}' from GTI API")
        file_mi_att_info = request_info_from_api(FILE_MITRE_INFO_API, ioc_value)
        if file_mi_att_info:
            enrich_info["mitre_attack_info"] = convert_mitre_structure(file_mi_att_info)

    if enrich_info:
        enrich_info['ioc_value'] = str(ioc_value)

    return enrich_info


def query_api(obj: dict) -> any:
    """Send a request to GTI API and fetch information to build message

    Parameters
    ----------
    obj : dict
       API and Header parameters

    Returns
    -------
    data: any
        JSON with the response

    Raises
    ------
    Exception
        If the status code is different than 200.
    """
    max_retries = retries
    delay = 10.0
    for attempt in range(max_retries + 1):
        logger.debug(f"# Querying GTI API {obj}")
        response = requests.get(
            obj.get("API"), headers=obj.get("HEADER"), timeout=timeout
        )
        if response.status_code == 200:
            json_response = response.json()
            return json_response
        elif response.status_code in [424, 429, 503, 504]:
            if attempt == max_retries:
                try:
                    err = response.json().get("error", {})
                    raise APIError(err.get("code", ""), err.get("message", ""))
                except Exception:
                    raise APIError(response.status_code, response.text)
            time.sleep(delay)
            delay = min(delay * 2, 60)
        else:
            try:
                err = response.json().get("error", {})
                raise APIError(err.get("code", ""), err.get("message", ""))
            except Exception:
                raise APIError(response.status_code, response.text)


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
        logger.error("# JSON file for alert %s doesn't exist" % file_location)
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        logger.error('Failed getting JSON alert. Error: %s' % e)
        sys.exit(ERR_INVALID_JSON)


def send_msg(msg: any, agent: any = None) -> None:
    if not agent or agent['id'] == '000':
        string = '1:GTI:{0}'.format(json.dumps(msg))
    else:
        location = '[{0}] ({1}) {2}'.format(agent['id'], agent['name'], agent['ip'] if 'ip' in agent else 'any')
        location = location.replace('|', '||').replace(':', '|:')
        string = '1:{0}->GTI:{1}'.format(location, json.dumps(msg))

    logger.info('# Request result from GTI server: %s' % string)
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
        sock.close()
    except FileNotFoundError:
        logger.error('# Error: Unable to open socket connection at %s' % SOCKET_ADDR)
        sys.exit(ERR_SOCKET_OPERATION)


if __name__ == '__main__':
    main(sys.argv)
