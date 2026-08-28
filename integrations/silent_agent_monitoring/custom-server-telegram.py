#!/var/ossec/framework/python/bin/python3
# Wazuh Telegram integration for the silent agent monitoring rules.
# Adapted from the Wazuh custom integration examples.
# This program is free software; you can redistribute it and/or modify it
# under the terms of GPLv2.
"""
Formats rules 100121 (no logs received) and 100122 (logging restored) into the
message layout the notification template asks for, and posts them to the
existing Telegram channel. Any other rule routed here falls back to a generic
message, so a wrong <rule_id> in ossec.conf produces a readable alert rather
than a crash.

wazuh-integratord calls this as:
    custom-server-telegram <alert_file> <api_key> <hook_url>
so <api_key> carries the chat ID and <hook_url> the bot sendMessage URL.
"""

import json
import logging
import os
import sys
import ssl
import urllib.request

# === CONFIGURATION ===
# Defaults used only when ossec.conf passes nothing, or for a manual test run.
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
HOOK_URL = os.environ.get("TELEGRAM_HOOK_URL", "")
# integratord runs this as the wazuh user, so the log has to be somewhere that
# user can already write. integrations.log is the standard place for it.
LOG_PATH = os.environ.get("TELEGRAM_LOG", "/var/ossec/logs/integrations.log")
VERIFY_SSL = os.environ.get("TELEGRAM_VERIFY_SSL", "yes").lower() in ("yes", "true", "1")
TIMEOUT = 15

SILENT_RULE = "100121"
RESTORED_RULE = "100122"

_LOG_ARGS = {"format": "%(asctime)s custom-server-telegram %(levelname)s %(message)s",
             "datefmt": "%Y-%m-%dT%H:%M:%S", "level": logging.INFO}
try:
    logging.basicConfig(filename=LOG_PATH, filemode="a", **_LOG_ARGS)
except OSError:
    # An unwritable log must not cost us the notification. stderr is captured
    # by integratord and ends up in ossec.log.
    logging.basicConfig(stream=sys.stderr, **_LOG_ARGS)


def build_message(alert):
    """Return the HTML message body for one alert."""
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


def send(hook_url, chat_id, message):
    payload = json.dumps({"chat_id": chat_id, "text": message,
                          "parse_mode": "HTML"}).encode()
    req = urllib.request.Request(hook_url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    context = ssl.create_default_context()
    if not VERIFY_SSL:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=context) as resp:
        return resp.status


def main():
    if len(sys.argv) < 2:
        logging.error("Usage: %s <alert-file> [chat_id] [hook_url]", sys.argv[0])
        sys.exit(1)

    try:
        with open(sys.argv[1]) as f:
            alert = json.load(f)
    except (OSError, ValueError) as err:
        logging.error("Failed to read alert file '%s': %s", sys.argv[1], err)
        sys.exit(1)

    chat_id = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else CHAT_ID
    hook_url = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else HOOK_URL
    if not chat_id or not hook_url:
        logging.error("Missing chat ID or hook URL. Set <api_key> and <hook_url> "
                      "in the <integration> block.")
        sys.exit(1)

    message = build_message(alert)
    try:
        status = send(hook_url, chat_id, message)
    except Exception as err:
        logging.error("Telegram delivery failed for rule %s: %s",
                      alert.get("rule", {}).get("id", ""), err)
        sys.exit(1)

    logging.info("Sent rule %s to chat %s (HTTP %s).",
                 alert.get("rule", {}).get("id", ""), chat_id, status)


if __name__ == "__main__":
    main()
