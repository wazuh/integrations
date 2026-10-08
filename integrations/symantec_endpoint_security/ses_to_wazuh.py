#!/usr/bin/env python3
"""
Symantec Endpoint Security (cloud)  ->  log file  ->  Wazuh

Pulls events from the SES Event Stream API and appends them, one JSON event per
line, to LOG_FILE. A Wazuh agent reads that file with <log_format>json</log_format>.

Usage:
    python3 ses_to_wazuh.py           # run continuously (use the systemd service)
    python3 ses_to_wazuh.py --check   # test credentials and stream, write nothing
"""

# =========================== EDIT THESE SETTINGS ============================

# Integration > Client Applications > your app > "OAuth Credentials"
OAUTH_CREDENTIAL = "PASTE_OAUTH_CREDENTIALS_HERE"

# Integration > Event Stream > GUID column of your API stream
STREAM_ID = "PASTE_STREAM_GUID_HERE"

# One channel in the console = [0]. Two channels = [0, 1]
CHANNELS = [0]

# US/global tenants. EU tenants: https://api.sep.eu.securitycloud.symantec.com
API_HOST = "https://api.sep.securitycloud.symantec.com"

# File that Wazuh reads
LOG_FILE = "/var/log/symantec-ses/events.json"

# Where the script remembers its position in the stream
STATE_DIR = "/var/lib/ses-to-wazuh"

# ============================================================================

import json
import logging
import os
import signal
import sys
import threading
import time
from collections import deque

import requests

IDLE_SLEEP = 30          # seconds to wait when there are no new events
READ_TIMEOUT = 300       # seconds without data before reconnecting
DEDUP_SIZE = 50000       # recent event IDs remembered to skip duplicates

log = logging.getLogger("ses-to-wazuh")
stop = threading.Event()
file_lock = threading.Lock()


# ---------------------------------------------------------------- auth

class Token:
    def __init__(self):
        self._lock = threading.Lock()
        self._value = None
        self._expires = 0

    def get(self):
        with self._lock:
            if not self._value or time.time() > self._expires - 60:
                r = requests.post(
                    f"{API_HOST}/v1/oauth2/tokens",
                    headers={"Authorization": f"Basic {OAUTH_CREDENTIAL}",
                             "Accept": "application/json",
                             "Content-Type": "application/x-www-form-urlencoded"},
                    data={}, timeout=60)
                if r.status_code != 200:
                    raise RuntimeError(f"Authentication failed (HTTP {r.status_code}): {r.text[:200]}")
                body = r.json()
                self._value = body["access_token"]
                self._expires = time.time() + int(body.get("expires_in", 3000))
                log.info("Got new access token")
            return self._value

    def reset(self):
        with self._lock:
            self._value = None


token = Token()


def open_stream(channel, next_pointer, connection_timeout=30):
    return requests.post(
        f"{API_HOST}/v1/event-export/stream/{STREAM_ID}/{channel}",
        params={"connectionTimeout": connection_timeout},
        json={"next": next_pointer} if next_pointer else {},
        headers={"Authorization": f"Bearer {token.get()}",
                 "Accept": "application/x-ndjson",
                 "Content-Type": "application/json",
                 "Accept-Encoding": "gzip"},
        stream=True, timeout=(15, READ_TIMEOUT))


# ---------------------------------------------------------------- state

class State:
    """Saves the stream position and recent event IDs so restarts don't lose or repeat events."""

    def __init__(self, channel):
        os.makedirs(STATE_DIR, exist_ok=True)
        self.path = os.path.join(STATE_DIR, f"channel_{channel}.json")
        self.next = None
        self.ids = deque(maxlen=DEDUP_SIZE)
        self.id_set = set()
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    data = json.load(f)
                self.next = data.get("next")
                for i in data.get("ids", []):
                    self.add(i)
                log.info("Channel %s: resuming from saved position", channel)
            except Exception as e:
                log.warning("Channel %s: could not read state (%s), starting fresh", channel, e)

    def add(self, event_id):
        if event_id in self.id_set:
            return
        if len(self.ids) == self.ids.maxlen:
            self.id_set.discard(self.ids[0])
        self.ids.append(event_id)
        self.id_set.add(event_id)

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"next": self.next, "ids": list(self.ids)}, f)
        os.replace(tmp, self.path)


# ---------------------------------------------------------------- output

def write_events(lines):
    if not lines:
        return
    with file_lock, open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------- main loop

def read_channel(channel):
    state = State(channel)
    wait = 5

    while not stop.is_set():
        try:
            with open_stream(channel, state.next) as r:
                if r.status_code == 204:                  # nothing new
                    stop.wait(IDLE_SLEEP)
                    continue
                if r.status_code == 401:                  # token expired
                    token.reset()
                    continue
                if r.status_code == 410:                  # saved position too old
                    log.warning("Channel %s: saved position expired, continuing from current", channel)
                    state.next = None
                    state.save()
                    continue
                if r.status_code == 404:
                    log.error("Channel %s: stream not found. Check STREAM_ID, CHANNELS and that "
                              "API State is enabled.", channel)
                    stop.wait(300)
                    continue
                r.raise_for_status()

                for raw in r.iter_lines(chunk_size=1024 * 1024, delimiter=b"\n"):
                    if stop.is_set():
                        break
                    if not raw:
                        continue
                    batch = json.loads(raw)
                    lines, new_ids = [], []
                    for event in batch.get("events") or []:
                        event_id = event.get("uuid")
                        if event_id and event_id in state.id_set:
                            continue
                        event["integration"] = "symantec_ses"
                        lines.append(json.dumps(event, separators=(",", ":"), ensure_ascii=False))
                        if event_id:
                            new_ids.append(event_id)

                    write_events(lines)                   # write first...
                    for i in new_ids:
                        state.add(i)
                    if batch.get("next"):
                        state.next = batch["next"]
                    state.save()                          # ...then save position
                    if lines:
                        log.info("Channel %s: wrote %d events", channel, len(lines))
            wait = 5

        except (requests.exceptions.ReadTimeout,
                requests.exceptions.ChunkedEncodingError,
                requests.exceptions.ConnectionError):
            stop.wait(2)                                  # stream closed normally, reconnect
        except Exception as e:
            log.error("Channel %s: %s (retrying in %ss)", channel, e, wait)
            stop.wait(wait)
            wait = min(wait * 2, 300)


def check():
    try:
        token.get()
        print("Authentication: OK")
    except Exception as e:
        print(f"Authentication: FAILED - {e}")
        return 1
    for ch in CHANNELS:
        try:
            with open_stream(ch, None, connection_timeout=1) as r:
                if r.status_code in (200, 204):
                    print(f"Channel {ch}: OK")
                else:
                    print(f"Channel {ch}: HTTP {r.status_code} - {r.text[:200]}")
        except requests.exceptions.ReadTimeout:
            print(f"Channel {ch}: OK")
        except Exception as e:
            print(f"Channel {ch}: FAILED - {e}")
    return 0


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if "--check" in sys.argv:
        return check()

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    for ch in CHANNELS:
        threading.Thread(target=read_channel, args=(ch,), daemon=True).start()
    log.info("Collecting stream %s -> %s", STREAM_ID, LOG_FILE)

    while not stop.is_set():
        stop.wait(1)
    log.info("Stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
