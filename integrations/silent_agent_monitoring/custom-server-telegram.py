#!/var/ossec/framework/python/bin/python3
# Copyright (C) 2015, Wazuh Inc.
# This program is free software; you can redistribute it and/or modify it
# under the terms of GPLv2.
#
# custom-server-telegram.py
# Wazuh Telegram integration for the silent agent monitoring rules. Formats
# rules 100121 (no logs received) and 100122 (logging restored) and posts them
# to a Telegram chat. Any other rule routed here falls back to a generic
# message. wazuh-integratord calls this as:
#   custom-server-telegram <alert_file> <api_key> <hook_url>
# so only <api_key> is needed, given as "<chat_id>:<bot_token>". The
# sendMessage URL is built from the token, and <hook_url> is ignored.

import json
import logging
import os
import sys
import ssl
import urllib.request

# === CONFIGURATION ===
# Used only when ossec.conf passes nothing, or for a manual test run.
# Same "<chat_id>:<bot_token>" form that ossec.conf puts in <api_key>.
API_KEY = os.environ.get("TELEGRAM_API_KEY", "")
LOG_PATH = os.environ.get("TELEGRAM_LOG", "/var/ossec/logs/integrations.log")
VERIFY_SSL = os.environ.get("TELEGRAM_VERIFY_SSL", "yes").lower() in ("yes", "true", "1")
TIMEOUT = 15
API_URL = "https://api.telegram.org/bot{}/sendMessage"

SILENT_RULE = "100121"
RESTORED_RULE = "100122"

_LOG_ARGS = {"format": "%(asctime)s custom-server-telegram %(levelname)s %(message)s",
             "datefmt": "%Y-%m-%dT%H:%M:%S", "level": logging.INFO}
try:
    logging.basicConfig(filename=LOG_PATH, filemode="a", **_LOG_ARGS)
except OSError:
    logging.basicConfig(stream=sys.stderr, **_LOG_ARGS)


def build_message(alert):
    data = alert.get("data", {})
    rule = alert.get("rule", {})
    rule_id = str(rule.get("id", ""))

    if rule_id == SILENT_RULE:
        return (f"⚠ <b>Server Logging Alert</b>\n"
                f"<b>Name:</b> {data.get('agent_name', 'unknown')}\n"
                f"<b>Agent ID:</b> {data.get('agent_id', 'unknown')}\n"
                f"<b>Status:</b> {data.get('status_text', 'No logs received')}\n"
                f"<b>Last Log Received:</b> {data.get('last_log', 'unknown')}\n"
                f"<b>No Logs For:</b> {data.get('no_logs_for', 'unknown')}")

    if rule_id == RESTORED_RULE:
        return (f"✅ <b>Server Logging Restored</b>\n"
                f"<b>Name:</b> {data.get('agent_name', 'unknown')}\n"
                f"<b>Agent ID:</b> {data.get('agent_id', 'unknown')}\n"
                f"<b>Status:</b> {data.get('status_text', 'Logs received')}\n"
                f"<b>Restored At:</b> {data.get('restored_at', 'unknown')}\n"
                f"<b>No Logs Duration:</b> {data.get('silence_duration', 'unknown')}")

    agent = alert.get("agent", {})
    return (f"<b>Wazuh alert</b>\n"
            f"<b>Rule:</b> {rule_id} (level {rule.get('level', '')})\n"
            f"<b>Description:</b> {rule.get('description', '')}\n"
            f"<b>Agent:</b> {agent.get('name', 'manager')} ({agent.get('id', '000')})")


def ssl_context():
    if not VERIFY_SSL:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    # The Wazuh embedded interpreter's OpenSSL looks for roots in a path that
    # does not exist, so a default context trusts nothing. certifi ships with
    # it; a system interpreter without certifi already has a working store.
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def send(bot_token, chat_id, message):
    payload = json.dumps({"chat_id": chat_id, "text": message,
                          "parse_mode": "HTML"}).encode()
    req = urllib.request.Request(API_URL.format(bot_token), data=payload,
                                 method="POST")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ssl_context()) as resp:
        return resp.status


def main():
    if len(sys.argv) < 2:
        logging.error("Usage: %s <alert-file> [chat_id:bot_token]", sys.argv[0])
        sys.exit(1)

    try:
        with open(sys.argv[1]) as f:
            alert = json.load(f)
    except (OSError, ValueError) as err:
        logging.error("Failed to read alert file '%s': %s", sys.argv[1], err)
        sys.exit(1)

    api_key = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else API_KEY
    # The bot token contains a colon of its own, so split on the first one only.
    chat_id, _, bot_token = api_key.partition(":")
    if not chat_id or not bot_token:
        logging.error("Missing or malformed API key. Set <api_key> to "
                      "\"<chat_id>:<bot_token>\" in the <integration> block.")
        sys.exit(1)

    message = build_message(alert)
    try:
        status = send(bot_token, chat_id, message)
    except Exception as err:
        logging.error("Telegram delivery failed for rule %s: %s",
                      alert.get("rule", {}).get("id", ""), err)
        sys.exit(1)

    logging.info("Sent rule %s to chat %s (HTTP %s).",
                 alert.get("rule", {}).get("id", ""), chat_id, status)


if __name__ == "__main__":
    main()
