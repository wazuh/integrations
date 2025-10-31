#!/var/ossec/framework/python/bin/python3

import os
import sys
import json
import logging
import asyncio
import httpx
from typing import Any, Dict, List, Optional, Tuple
from socket import AF_UNIX, SOCK_DGRAM, socket
from pathlib import Path
from logging.handlers import RotatingFileHandler

# Global error codes for exit statuses
ERR_NO_RESPONSE_MISP = 10
ERR_SOCKET_OPERATION = 11
ERR_INVALID_JSON = 12
ERR_BAD_ARGUMENTS = 13

# Service configuration constants
SERVICE_NAME = "wazuh-misp-integration"
LOG_DIR = Path("/var/log/wazuh-misp")
LOG_FILE = LOG_DIR / "integrations.log"
SOCKET_ADDR = "/var/ossec/queue/sockets/queue"
QUEUE_FILE_PATH = LOG_DIR / "wazuh-retry-queue"
QUEUE_FILE = QUEUE_FILE_PATH / "misp_queue.json"
QUEUE_TMP = QUEUE_FILE.with_suffix(".inprocess")
FAILED_MISP_ALERTS_DIR = LOG_DIR / "misp-failed-enrichment"

# These will be populated from CLI args or options file
MISP_BASE_URL = ""
MISP_API_KEY = ""
VERIFY_SSL = False

# Supported IOC keys and their possible field names in Wazuh alerts
SUPPORTED_KEYS = [
    ("ip_src", ["src_ip", "source_ip", "srcip", "SourceIP", "aws.source_ip_address", "client_ip", "clientIP_s", "IPAddress", "originalHost_s", "CallerIPAddress"]),
    ("ip_dst", ["dst_ip", "destination_ip", "dstip", "DestinationIP", "remote_ip", "external_ip"]),
    ("sha1",   ["sha1", "sha1sum", "file_sha1", "ciscoendpoint.file.identity.sha1"]),
    ("sha256", ["sha256", "sha256sum", "file_sha256", "ciscoendpoint.file.identity.sha256"]),
    ("md5",    ["md5", "md5sum", "file_md5", "ciscoendpoint.file.identity.md5"]),
    ("url",    ["url", "source_url", "TargetURL", "download_url", "http_url"]),
    ("domain", ["domain", "hostname", "base_domain", "fqdn", "TargetDestination", "Fqdn_s", "win.eventdata.queryName"]),
]

# -------------------- Logging Setup ---------------------

def create_app_logger() -> logging.Logger:
    """
    Create and configure a JSON or plain-text logger for the service.
    Honors LOG_FORMAT environment variable ("json" or "plain").
    """
    logger = logging.getLogger(SERVICE_NAME)
    logger.setLevel(logging.INFO)

    # Remove existing handlers
    for h in list(logger.handlers):
        logger.removeHandler(h)

    # Plain formatter for console and file
    plain_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    # Console handler
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(plain_formatter)
    logger.addHandler(stream_handler)

    # Ensure log directory exists
    log_dir = os.path.dirname(LOG_FILE)
    os.makedirs(log_dir, exist_ok=True)

    # 10MB per file, 5 backups (total: ~500MB)
    file_handler = RotatingFileHandler(LOG_FILE, maxBytes=10_000_000, backupCount=5, encoding="utf-8")
    file_handler.setFormatter(plain_formatter)
    logger.addHandler(file_handler)

    logger.propagate = False
    return logger


logger = create_app_logger()

# -------------------- IOC Extraction ---------------------

def extract_all_iocs(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Given a Wazuh alert, extract all supported IOCs (IP, hash, URL, domain).
    Returns a mapping of normalized IOC keys to their values.
    """
    def get_nested_value(data: dict, key_path: str) -> Optional[Any]:
        # Traverse nested dict by dot-delimited path
        keys = key_path.split(".")
        val = data
        for key in keys:
            if isinstance(val, dict) and key in val:
                val = val[key]
            else:
                return None
        return val

    data = alert.get("data", {})
    syscheck = alert.get("syscheck", {})
    iocs: Dict[str, Any] = {}

    # Iterate supported key sets; pick first matching candidate
    for out_key, candidates in SUPPORTED_KEYS:
        for candidate in candidates:
            val = get_nested_value(data, candidate)
            # If not found in data, check syscheck for "<candidate>_after"
            if val is None and "." not in candidate:
                val = syscheck.get(f"{candidate}_after")
            if val:
                iocs[out_key] = val
                break
    return iocs

# -------------------- MISP Async Query ---------------------

async def misp_fetch(client: httpx.AsyncClient, value: str, sem: asyncio.Semaphore, misp_base_url: str, misp_api_key: str, verify_ssl: bool) -> Tuple[str, Optional[Dict[str, Any]]]:
    """
    Perform a REST search in MISP for a single IOC value.
    Retries up to 3 times on error or timeout. Returns tuple (value, response_data).
    """
    url = f"{misp_base_url.rstrip('/')}/attributes/restSearch/"
    headers = {
        "Content-Type": "application/json",
        "Authorization": misp_api_key,
        "Accept": "application/json",
    }
    payload = {
        "value": value,
        "returnFormat": "json",
        "includeContext": True,
        "includeEventTags": True,
        "includeAttributeTags": True,
        "includeSightings": True,
    }

    async with sem:
            for attempt in range(1, 4):
                try:
                    resp = await client.post(url, headers=headers, json=payload, timeout=10.0)
                    if resp.status_code == 200:
                        data = resp.json()
                        logger.info(f"MISP query successful for '{value}', status {resp.status_code}")
                        return value, data
                    else:
                        logger.error(f"MISP responded with error status {resp.status_code} for IOC value {value}")
                        try:
                            error_data = resp.json()
                        except json.JSONDecodeError:
                            error_data = {"message": resp.text}
                        return value, {"error": {"status": resp.status_code, "data": error_data}}
                except httpx.TimeoutException:
                    logger.warning(f"Timeout on attempt {attempt} for IOC '{value}', retrying...")
                except Exception as e:
                    logger.warning(f"Request exception on attempt {attempt} for IOC '{value}': {e}")
                await asyncio.sleep(2**attempt)

    # All retries failed
            logger.error(f"Failed to fetch MISP data for IOC '{value}' after retries")
            return value, None

def save_failed_misp_alert(alert: dict) -> None:
    """
    Save an alert for retry if MISP is unreachable.
    """
    try:
        if not FAILED_MISP_ALERTS_DIR.exists():
            FAILED_MISP_ALERTS_DIR.mkdir(parents=True, exist_ok=True)
            os.chmod(FAILED_MISP_ALERTS_DIR, 0o750)
        alert_id = alert.get("id", "unknown")
        sanitized_alert_id = alert_id.replace(".", "_")
        fname = FAILED_MISP_ALERTS_DIR / f"alert_{sanitized_alert_id}.json"
        with open(fname, "w", encoding="utf-8") as f:
            json.dump(alert, f, separators=(",", ":"))
        logger.warning(f"Alert {alert_id} saved for retry due to MISP unresponsiveness")
    except Exception as e:
        logger.error(f"Failed to store failed alert to retry folder: {e}")


def process_failed_misp_alerts(misp_base_url, misp_api_key, verify_ssl):
    """
    Retry enriching all alerts in the failed alerts directory.
    Successfully reprocessed alerts are deleted.
    """
    def misp_is_reachable(misp_base_url, misp_api_key, verify_ssl):
        """Quickly check if MISP API responds to a simple authenticated request using httpx."""
        try:
            url = f"{misp_base_url.rstrip('/')}/servers/getVersion.json"
            headers = {"Authorization": misp_api_key}
            resp = httpx.get(url, headers=headers, timeout=5.0, verify=verify_ssl)
            return resp.status_code == 200
        except Exception as e:
            logger.warning(f"MISP healthcheck failed: {e}")
            return False

    failed_dir = FAILED_MISP_ALERTS_DIR
    if not failed_dir.exists():
        return

    # Check if MISP is up before retrying
    if not misp_is_reachable(misp_base_url, misp_api_key, verify_ssl):
        logger.warning("Skipping MISP failed alert retries because MISP is still unreachable.")
        return

    for alert_file in list(failed_dir.glob("alert_*.json")):
        try:
            with open(alert_file, "r", encoding="utf-8") as f:
                alert = json.load(f)
            asyncio.run(process_alerts([alert], misp_base_url, misp_api_key, verify_ssl))
            alert_file.unlink()  # Remove file on success
            logger.info(f"Successfully reprocessed failed alert {alert_file.name}, removed from retry queue.")
        except Exception as e:
            logger.error(f"Failed to reprocess {alert_file.name}: {e}")
            # Keep the file for a future retry

# -------------------- Sending enriched event ---------------------

def send_event(msg: Dict[str, Any], agent: Optional[Dict[str, Any]] = None) -> None:
    """
    Send the enriched alert JSON to Wazuh via UNIX datagram socket.
    On failure, queue the event for retry.
    """
    try:
        line = json.dumps(msg, separators=(",", ":"))
        # Format socket message with optional agent context
        if not agent or agent.get("id") == "000":
            string = f"1:misp:{line}"
        else:
            string = f"1:[{agent['id']}] ({agent['name']}) {agent.get('ip','any')}->misp:{line}"

        with socket(AF_UNIX, SOCK_DGRAM) as sock:
            sock.connect(SOCKET_ADDR)
            sock.send(string.encode())
        logger.info("Sent enriched event to Wazuh socket")
    except FileNotFoundError:
        logger.error(f"Socket file not found at {SOCKET_ADDR}, queuing event for retry")
        save_to_queue(msg)
    except Exception as e:
        logger.error(f"Failed to send event: {e}. Event queued for retry.")
        save_to_queue(msg)

def save_to_queue(event: Dict[str, Any]) -> None:
    """
    Append failed events to a local file for later retry.
    """
    try:
        if not QUEUE_FILE_PATH.exists():
            QUEUE_FILE_PATH.mkdir(parents=True, exist_ok=True)
            os.chmod(QUEUE_FILE_PATH, 0o750)
        with open(QUEUE_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, separators=(",", ":")) + "\n")
        logger.warning("Event saved to retry queue")
    except Exception as e:
        logger.error(f"Failed to write event to retry queue: {e}")

# -------------------- Main Async Alert Processing ---------------------

async def process_alerts(alerts: List[Dict[str, Any]], misp_base_url: str, misp_api_key: str, verify_ssl: bool) -> None:
    """
    Extract IOCs from each alert, de-duplicate values, query MISP concurrently,
    then enrich and send each alert with aggregated IOC results.
    """

    def filtered_alert(alert: dict) -> dict:
        return {
            "id": alert.get("id"),
            "manager.name": alert.get("manager", {}).get("name"),
            "rule.groups": alert.get("rule", {}).get("groups"),
            "rule.id": alert.get("rule", {}).get("id"),
            "rule.level": alert.get("rule", {}).get("level"),
            "timestamp": alert.get("timestamp"),
            "rule.description": alert.get("rule", {}).get("description"),
        }

    if not alerts:
        logger.info("No alerts to process")
        return

    sem = asyncio.Semaphore(10)
    async with httpx.AsyncClient(verify=verify_ssl, timeout=10.0) as session:
        alerts_iocs_list: List[Dict[str, Any]] = []
        all_iocs_values: set = set()

        # Extract IOCs and build unique set
        for alert in alerts:
            iocs = extract_all_iocs(alert)
            alerts_iocs_list.append(iocs)
            all_iocs_values.update(iocs.values())

        # Query MISP for each unique IOC
        tasks = [
            misp_fetch(session, val, sem, misp_base_url, misp_api_key, verify_ssl)
            for val in all_iocs_values
        ]
        results = await asyncio.gather(*tasks)

        # Map IOC value to its MISP response
        global_misp_results = {val: data for val, data in results}

    # Enrich each alert with MISP data
    for alert, iocs in zip(alerts, alerts_iocs_list):
        alert_id = alert.get("id", "unknown")  # Use 'unknown' if 'id' is missing
        if not iocs:
            logger.warning(f"No IOCs extracted from alert (alert_id={alert_id}), skipping enrichment")
            continue

        all_failed = all(global_misp_results.get(val) is None for val in iocs.values())
        if iocs and all_failed:
            save_failed_misp_alert(alert)
            logger.warning(f"MISP unreachable for all IOCs in alert_id={alert_id}. Alert queued for later enrichment.")
            continue

        # Reverse index: value → keys it came from
        value_to_keys: Dict[str, List[str]] = {}
        for key, val in iocs.items():
            value_to_keys.setdefault(val, []).append(key)

        enrichment_iocs: Dict[str, Any] = {}
        result_flags: Dict[str, bool] = {}
        #misp_response: Dict[str, Optional[Dict[str, Any]]] = {}
        misp_response: Dict[str, Dict[str, Any]] = {}
        misp_error_response: Dict[str, Dict[str, Any]] = {}

        # Populate enrichment fields per key
        for value, keys in value_to_keys.items():
            data = global_misp_results.get(value)
            matched = False
            attr_info = None

            if data is None:
                logger.info(f"No response from MISP for IOC value '{value}'")
            elif "error" in data:
                logger.error(f"MISP error for IOC value '{value}': {data['error']}")
                error_info = {
                    "status": data["error"]["status"],
                    "message": data["error"]["data"].get("message", ""),
                    "url": data["error"]["data"].get("url", "")
                }
                for key in keys:
                    misp_error_response[key] = error_info
            else:
                misp_attrs = data.get("response", {}).get("Attribute")
                if misp_attrs and len(misp_attrs) > 0:
                    attr = misp_attrs[0]
                    event = attr.get("Event", {})
                    if value == attr.get("value"):
                        matched = True
                        attr_info = {
                            "value": attr.get("value"),
                            "comment": attr.get("comment"),
                            "uuid": attr.get("uuid"),
                            "timestamp": attr.get("timestamp"),
                            "event_id": attr.get("event_id"),
                            "event_org_id": event.get("org_id"),
                            "event_info": event.get("info"),
                            "threat_level_id": event.get("threat_level_id"),
                        }

            for key in keys:
                enrichment_iocs[key] = value
                result_flags[f"{key}_misp"] = matched
                misp_response[key] = attr_info if matched else {}

            if matched:
                logger.info(f"MISP match found for IOC value '{value}'")
            elif data and "error" not in data:
                logger.info(f"No MISP match for IOC value '{value}'")

        # Build final enriched event payload
        enrichment: Dict[str, Any] = {}
        if misp_error_response:
            enrichment["misp_error_response"] = misp_error_response
        else:
            enrichment = {
                "ioc": enrichment_iocs,
                "result_flags": result_flags,
                "misp_response": misp_response,
                "original_alert": filtered_alert(alert),
            }

        if any(result_flags.values()) or misp_error_response:
            enriched_event = {
                **enrichment,
                "integration": "misp",
                "threat": "MISP match" if any(result_flags.values()) else "MISP error",
            }
            send_event(enriched_event, alert.get("agent"))

def process_queue() -> None:
    """
    Read queued events from disk, attempt to resend them, and handle failures.
    """
    if not QUEUE_FILE.exists():
        return

    try:
        QUEUE_FILE.rename(QUEUE_TMP)
    except Exception as e:
        logger.error(f"Failed to rename queue file: {e}")
        return

    failed: List[str] = []
    with open(QUEUE_TMP, "r", encoding="utf-8") as f:
        for line in f:
            try:
                alert = json.loads(line)
                asyncio.run(process_alerts([alert], MISP_BASE_URL, MISP_API_KEY, VERIFY_SSL))
            except Exception as e:
                logger.error(f"Error processing queued event: {e}")
                failed.append(line)

    # Restore any still-failed events or clean up
    if failed:
        try:
            with open(QUEUE_FILE, "w", encoding="utf-8") as f:
                f.writelines(failed)
        except Exception as e:
            logger.error(f"Failed to restore failed events to queue: {e}")
    else:
        try:
            QUEUE_TMP.unlink()
        except Exception as e:
            logger.error(f"Failed to delete temporary queue file: {e}")

def main():
    """
    Entry point: parse CLI arguments, load options, process any queued events,
    then read and process incoming alerts.
    """
    global MISP_BASE_URL, MISP_API_KEY, VERIFY_SSL

    try:
        alert_file = sys.argv[1]
        MISP_API_KEY = sys.argv[2]
        MISP_BASE_URL = sys.argv[3]
        options_path = sys.argv[5] if len(sys.argv) > 5 else ""
        VERIFY_SSL = False
        if options_path and os.path.isfile(options_path):
            with open(options_path, "r", encoding="utf-8") as f:
                options = json.load(f)
                VERIFY_SSL = (str(options.get("misp_verify_ssl", "false")).strip().lower() == "true")
    except Exception as e:
        logger.error(f"Failed to parse Wazuh integration arguments: {e}")
        sys.exit(ERR_INVALID_JSON)

    # First, retry any queued events
    process_queue()

    # Then, retry failed MISP enrichment for alerts (if any)
    process_failed_misp_alerts(MISP_BASE_URL, MISP_API_KEY, VERIFY_SSL)

    # Load alerts from file or stdin
    alerts: List[Dict[str, Any]] = []
    try:
        if alert_file == "-":
            content = sys.stdin.read()
            parsed = json.loads(content)
            alerts = [parsed] if isinstance(parsed, dict) else parsed
        else:
            with open(alert_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        alerts.append(json.loads(line))
    except Exception as e:
        logger.error(f"Failed to parse alert input: {e}")
        sys.exit(ERR_INVALID_JSON)

    # Process the loaded alerts
    asyncio.run(process_alerts(alerts, MISP_BASE_URL, MISP_API_KEY, VERIFY_SSL))

if __name__ == "__main__":
    main()
