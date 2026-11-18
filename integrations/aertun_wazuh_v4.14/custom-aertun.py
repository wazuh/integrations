#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Rashik Adhikari
# SPDX-License-Identifier: Apache-2.0
"""Wazuh to Aertun: send one alert to an Aertun webhook feed.

Wazuh's integrator runs this once for each alert its <integration> block
matches, as

    custom-aertun.py ALERT_FILE API_KEY HOOK_URL [debug] [OPTIONS_FILE]

API_KEY is the feed's signing secret (whsec_...) and HOOK_URL the feed's
address (https://aertun.example.com/feeds/wazuh). The alert is posted exactly
as Wazuh wrote it, signed as a Standard Webhooks delivery
(https://www.standardwebhooks.com), so Aertun can tell it came from this
manager and was not changed on the way; on a feed added with --seal, Aertun
also commits the alert's digest to its audit log as it arrives.

The optional JSON options file may say:

    {"ca_file": "/var/ossec/etc/aertun-ca.pem", "timeout": 10, "retries": 3}

ca_file is a CA to trust beside the system's, for an Aertun behind a private
certificate. Only https is spoken: the signature proves the alert was not
changed, and only TLS keeps it from being read.

The Python standard library only, so it runs on the interpreter Wazuh ships.
The secret and the alert's contents are never written to the log.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "aertun-wazuh/1"
MAX_ALERT = 1 << 20

# integrations.log beside the integrations directory, where Wazuh's own
# integrations write; standard error when it cannot be written.
LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))),
                        "logs", "integrations.log")

debug_enabled = False


def log(message, debug=False):
    if debug and not debug_enabled:
        return
    line = "%s aertun: %s\n" % (time.strftime("%Y/%m/%d %H:%M:%S"), message)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line)
    except OSError:
        sys.stderr.write(line)


def sign(secret, msg_id, timestamp, body):
    """The Standard Webhooks signature: HMAC-SHA256 over id.timestamp.body,
    keyed with the secret's bytes (base64 after whsec_)."""
    if secret.startswith("whsec_"):
        key = base64.b64decode(secret[len("whsec_"):])
    else:
        key = secret.encode()
    mac = hmac.new(key, ("%s.%d." % (msg_id, timestamp)).encode() + body, hashlib.sha256)
    return "v1," + base64.b64encode(mac.digest()).decode()


def delivery_id(alert):
    """One id per alert, the same on every retry so Aertun takes it once:
    the manager's name and Wazuh's own alert id."""
    manager = ""
    if isinstance(alert.get("manager"), dict):
        manager = str(alert["manager"].get("name", ""))
    raw = "wazuh:%s:%s" % (manager, alert.get("id", ""))
    if not alert.get("id"):
        raw = "wazuh:" + hashlib.sha256(json.dumps(alert, sort_keys=True).encode()).hexdigest()
    return re.sub(r"[^A-Za-z0-9._:-]", "-", raw)[:200]


def read_options(args):
    for arg in args[4:]:
        if arg.endswith("options"):
            try:
                with open(arg) as f:
                    options = json.load(f)
                return options if isinstance(options, dict) else {}
            except (OSError, ValueError) as e:
                log("the options file %s does not read: %s" % (arg, e))
                return None
    return {}


def send(url, secret, body, msg_id, options):
    context = ssl.create_default_context()
    ca_file = options.get("ca_file")
    try:
        if ca_file:
            context.load_verify_locations(cafile=ca_file)
        timeout = float(options.get("timeout", 10))
        retries = max(1, min(int(options.get("retries", 3)), 5))
    except (OSError, ssl.SSLError, TypeError, ValueError) as e:
        log("the options do not hold together (ca_file, timeout, retries): %s; the alert is not sent" % e)
        return False
    for attempt in range(1, retries + 1):
        timestamp = int(time.time())
        request = urllib.request.Request(url, data=body, method="POST", headers={
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
            "webhook-id": msg_id,
            "webhook-timestamp": str(timestamp),
            "webhook-signature": sign(secret, msg_id, timestamp, body),
        })
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                log("alert %s delivered (%d)" % (msg_id, response.status), debug=True)
                return True
        except urllib.error.HTTPError as e:
            if e.code < 500 and e.code != 429:
                # Refused for what it is: a wrong secret (401), a body the
                # feed cannot read (400). Sending it again changes nothing.
                log("alert %s refused by Aertun (%d)" % (msg_id, e.code))
                return False
            log("alert %s: Aertun answered %d, attempt %d of %d" % (msg_id, e.code, attempt, retries))
        except (urllib.error.URLError, OSError) as e:
            log("alert %s: %s, attempt %d of %d" % (msg_id, getattr(e, "reason", e), attempt, retries))
        if attempt < retries:
            time.sleep(min(2 ** (attempt - 1), 4))
    return False


def main(args):
    global debug_enabled
    if len(args) < 4:
        log("wrong arguments: custom-aertun.py ALERT_FILE API_KEY HOOK_URL [debug] [OPTIONS_FILE]")
        return 2
    alert_file, secret, url = args[1], args[2], args[3]
    debug_enabled = "debug" in args[4:]
    if urllib.parse.urlsplit(url).scheme != "https":
        log("the hook_url is not https; the alert is not sent")
        return 2
    if len(secret) < 24:
        log("the api_key is not the feed's signing secret")
        return 2
    options = read_options(args)
    if options is None:
        return 2
    try:
        with open(alert_file, "rb") as f:
            body = f.read(MAX_ALERT + 1)
    except OSError as e:
        log("the alert file %s does not read: %s" % (alert_file, e))
        return 1
    if len(body) > MAX_ALERT:
        log("the alert in %s is larger than %d bytes" % (alert_file, MAX_ALERT))
        return 1
    body = body.strip()
    try:
        alert = json.loads(body)
    except ValueError:
        log("the alert in %s is not JSON" % alert_file)
        return 1
    if not isinstance(alert, dict):
        log("the alert in %s is not one JSON object" % alert_file)
        return 1
    return 0 if send(url, secret, body, delivery_id(alert), options) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
