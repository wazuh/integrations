#!/var/ossec/framework/python/bin/python3

import sys
import os
import json
import logging
import time
from argparse import ArgumentParser
from pathlib import Path
from urllib.parse import urlparse
import urllib3
from urllib3.exceptions import InsecureRequestWarning

# === Constants ===
CONTENT_TYPE    = "application/json"
TIMEOUT_CONNECT = 5.0
TIMEOUT_READ    = 30.0
TOKEN_PREFIX    = "Splunk:"

DEBUG = False  # Set to True for debug

# === Exit Codes ===
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS     = 2
ERR_FILE_NOT_FOUND    = 6
ERR_INVALID_JSON      = 7

# === Paths ===
LOG_DIR    = Path("/var/log/custom_splunk")
LOG_FILE   = LOG_DIR / "custom_splunk.log"
QUEUE_FILE = LOG_DIR / "splunk_queue.json"
QUEUE_TMP  = LOG_DIR / "splunk_queue.json.inprocess"

# === Initialize HTTP client ===
urllib3.disable_warnings(InsecureRequestWarning)
http = urllib3.PoolManager(cert_reqs="CERT_NONE")

# === Logging Setup ===
def setup_logging() -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("splunk_soar")
    logger.setLevel(logging.DEBUG if DEBUG else logging.INFO)
    handler = logging.FileHandler(str(LOG_FILE), encoding="utf-8")
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    return logger

# === Helpers ===
def validate_token(raw: str, logger: logging.Logger) -> str:
    if not raw.startswith(TOKEN_PREFIX):
        logger.error("API token must start with '%s'", TOKEN_PREFIX)
        sys.exit(ERR_BAD_ARGUMENTS)
    token = raw.split(':', 1)[1]
    if not token:
        logger.error("API token missing value after prefix")
        sys.exit(ERR_BAD_ARGUMENTS)
    return token

def validate_url(url: str, logger: logging.Logger):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        logger.error("Invalid hook URL: %s", url)
        sys.exit(ERR_BAD_ARGUMENTS)

def load_event(path: Path, logger: logging.Logger) -> dict:
    if not path.is_file():
        logger.error("Event file not found: %s", path)
        sys.exit(ERR_FILE_NOT_FOUND)
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except json.JSONDecodeError as e:
        logger.error("Malformed JSON in '%s': %s", path, e)
        sys.exit(ERR_INVALID_JSON)

# === Payload Builders ===
def build_container_payload(event: dict) -> dict:
    level = event.get('rule', {}).get('level', 0)
    severity = 'high' if level >= 15 else 'medium'
    return {
        'name': f"Custom Wazuh alert - {event.get('rule', {}).get('description', 'wazuh_event')}",
        'description': json.dumps(event),
        'severity': severity,
        'artifacts': [
            {
                'label': 'event',
                'name': 'wazuh',
                'cef': event,
                'type': 'custom_wazuh'
            }
        ]
    }

# === HTTP Sender ===
def send_payload(hook_url: str, token: str, container: dict, logger: logging.Logger) -> bool:
    headers = {
        'Content-Type': CONTENT_TYPE,
        'ph-auth-token': token
    }
    timeout = urllib3.Timeout(connect=TIMEOUT_CONNECT, read=TIMEOUT_READ)
    try:
        resp = http.request('POST', hook_url, headers=headers,
                            body=json.dumps(container), timeout=timeout)
    except Exception as e:
        logger.error('HTTP request failed: %s', e)
        return False

    body = resp.data.decode('utf-8', errors='ignore')
    if resp.status >= 400:
        logger.error('Webhook POST error %s: %s', resp.status, body)
        return False

    logger.info('Webhook POST succeeded: %s', body)
    return True

# === Queue Management ===
def queue_event(container: dict, logger: logging.Logger):
    try:
        LOG_DIR.mkdir(exist_ok=True)
        with open(QUEUE_FILE, 'a') as f:
            f.write(json.dumps(container) + '\n')
        logger.warning('Event queued due to failure')
    except Exception as e:
        logger.error('Failed to queue event: %s', e)

def process_queue(hook_url: str, token: str, logger: logging.Logger):
    if not QUEUE_FILE.exists():
        return
    try:
        os.rename(QUEUE_FILE, QUEUE_TMP)
    except Exception as e:
        logger.error('Could not rotate queue file: %s', e)
        return
    failed = []
    for line in open(QUEUE_TMP):
        try:
            container = json.loads(line)
            if not send_payload(hook_url, token, container, logger):
                failed.append(line)
            else:
                logger.info('Successfully sent queued event %s', container.get('name', 'unknown'))
        except Exception as e:
            logger.error('Queue replay error: %s', e)
            failed.append(line)
    # Write back only failures, or clear queue
    if failed:
        with open(QUEUE_FILE, 'w') as f:
            f.writelines(failed)
    else:
        # No failures -> ensure queue file is removed
        try:
            if QUEUE_FILE.exists():
                QUEUE_FILE.unlink()
        except Exception as e:
            logger.error('Failed to clear queue file: %s', e)
    # Clean up temp
    try:
        os.remove(QUEUE_TMP)
    except Exception:
        pass

# === Main ===
def main():
    # 1) Set up logging first
    logger = setup_logging()

    # 2) Declare our ArgumentParser and grab only the first three positional args + debug flag
    p = ArgumentParser(
        description="Send a Wazuh alert to Splunk SOAR via HTTP webhook."
    )
    p.add_argument("event_file", type=Path,
                   help="Path to the Wazuh event JSON file.")
    p.add_argument("api_token",
                   help=f"API token prefixed with '{TOKEN_PREFIX}'.")
    p.add_argument("hook_url",
                   help="Full URL to the Splunk SOAR webhook endpoint.")
    p.add_argument("-d", "--debug", action="store_true",
                   help="Enable debug-level logging.")

    args, extras = p.parse_known_args()


    # 3) Bump to DEBUG if requested
    if args.debug or DEBUG:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    # 4) Log everything we got
    if DEBUG:
        logger.info("RAW ARGV: %r", sys.argv)
        if extras:
            logger.info("Ignoring extra args: %r", extras)

    try:
        token = validate_token(args.api_token, logger)
        validate_url(args.hook_url, logger)
        event = load_event(args.event_file, logger)

        # Retry queued events
        process_queue(args.hook_url, token, logger)

        # Send current event
        payload = build_container_payload(event)
        if not send_payload(args.hook_url, token, payload, logger):
            queue_event(payload, logger)
        return 0
    except Exception as e:
        logger.error("An error occurred: %s", e)
        return 1

if __name__ == '__main__':
    sys.exit(main())

