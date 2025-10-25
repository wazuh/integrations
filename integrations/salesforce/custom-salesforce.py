#!/usr/bin/env python3
"""
Salesforce SetupAuditTrail fetcher -- prints one JSON object per record (no array, no brackets)
Each line is a standalone JSON event, ideal for Wazuh ingestion via wodle.
"""

from __future__ import annotations
import os
import sys
import time
import json
import jwt
import requests
from pathlib import Path
from datetime import datetime, timedelta
from urllib.parse import quote_plus

# ---------------- CONFIGURATION ----------------
CONSUMER_KEY = os.getenv("SF_CONSUMER_KEY", "xxxxxxxxxxxxxxxxxxxxxxxxx_YaRnqsz7Bhu9OXt_9HbicyrJWvfpn2euonYaVQGVGFRuNP9.wCZ")
USERNAME = os.getenv("SF_USERNAME", "xxxxxxxxxxxxx@agentforce.com")
PRIVATE_KEY_PATH = Path(os.getenv("SF_PRIVATE_KEY", "/var/ossec/integrations/private.key"))
IS_SANDBOX = os.getenv("SF_IS_SANDBOX", "false").lower() in ("1", "true", "yes")
API_VERSION = os.getenv("SF_API_VERSION", "v58.0")

OUT_DIR = Path(os.getenv("SF_OUT_DIR", "/var/log/salesforce"))
OUT_DIR.mkdir(parents=True, exist_ok=True)
JSON_FILE = OUT_DIR / "salesforce_audit.json"
TIMESTAMPED_FILE = OUT_DIR / f"salesforce_audit_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json"
STATE_FILE = OUT_DIR / "salesforce_state.json"

INITIAL_LOOKBACK_SECONDS = int(os.getenv("SF_INITIAL_LOOKBACK_SECONDS", "600"))  # 10 minutes
SOQL_LIMIT = int(os.getenv("SF_SOQL_LIMIT", "200"))
# ------------------------------------------------

def fatal(msg: str, code: int = 1):
    print("FATAL:", msg, file=sys.stderr)
    raise SystemExit(code)

def load_private_key() -> str:
    if not PRIVATE_KEY_PATH.exists():
        fatal(f"Private key not found: {PRIVATE_KEY_PATH}", 2)
    return PRIVATE_KEY_PATH.read_text()

def build_jwt() -> str:
    now = int(time.time())
    aud = "https://test.salesforce.com" if IS_SANDBOX else "https://login.salesforce.com"
    payload = {"iss": CONSUMER_KEY, "sub": USERNAME, "aud": aud, "exp": now + 180}
    token = jwt.encode(payload, load_private_key(), algorithm="RS256")
    if isinstance(token, bytes):
        token = token.decode()
    return token

def get_access_token(jwt_assertion: str) -> dict:
    url = ("https://test.salesforce.com" if IS_SANDBOX else "https://login.salesforce.com") + "/services/oauth2/token"
    data = {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": jwt_assertion}
    r = requests.post(url, data=data, timeout=30)
    if not r.ok:
        fatal(f"Token request failed: {r.status_code} {r.text}")
    return r.json()

def read_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            return {}
    return {}

def write_state(state: dict):
    STATE_FILE.write_text(json.dumps(state))

def make_soql(last_seen: str | None, last_id: str | None, limit: int) -> str:
    base = "SELECT Id, Action, CreatedById, CreatedDate, Section, Display FROM SetupAuditTrail"
    order = " ORDER BY CreatedDate ASC, Id ASC"
    if last_seen and last_id:
        where = f" WHERE (CreatedDate > {last_seen}) OR (CreatedDate = {last_seen} AND Id > '{last_id}')"
    elif last_seen:
        where = f" WHERE CreatedDate > {last_seen}"
    else:
        where = ""
    return f"{base}{where}{order} LIMIT {limit}"

def fetch_all_records(instance_url: str, access_token: str, soql: str) -> list:
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    records = []
    url = f"{instance_url}/services/data/{API_VERSION}/query?q={quote_plus(soql)}"
    while url:
        r = requests.get(url, headers=headers, timeout=60)
        if not r.ok:
            fatal(f"SOQL query failed: {r.status_code} {r.text}")
        data = r.json()
        records.extend(data.get("records", []))
        url = f"{instance_url}{data.get('nextRecordsUrl')}" if data.get("nextRecordsUrl") else None
    return records

def simplify_record(rec: dict) -> dict:
    created = rec.get("CreatedDate", "").replace("+0000", "Z").split(".")[0] + "Z"
    return {
        "id": rec.get("Id"),
        "action": rec.get("Action"),
        "user_id": rec.get("CreatedById"),
        "created": created,
        "section": rec.get("Section"),
        "description": rec.get("Display"),
        "_wazuh_source": "salesforce_setup_audit"
    }

def main():
    state = read_state()
    last_seen = state.get("last_seen")
    last_id = state.get("last_id")

    if not last_seen:
        last_seen = (datetime.utcnow() - timedelta(seconds=INITIAL_LOOKBACK_SECONDS)).strftime("%Y-%m-%dT%H:%M:%SZ")

    jwt_token = build_jwt()
    token_resp = get_access_token(jwt_token)
    access_token = token_resp.get("access_token")
    instance_url = token_resp.get("instance_url")
    if not (access_token and instance_url):
        fatal("Missing access token or instance URL")

    soql = make_soql(last_seen, last_id, SOQL_LIMIT)
    records = fetch_all_records(instance_url, access_token, soql)

    if not records:
        return

    records_sorted = sorted(records, key=lambda r: (r.get("CreatedDate", ""), r.get("Id", "")))
    simplified = [simplify_record(r) for r in records_sorted]

    # Print each record as a single one-liner JSON object (no array)
    for rec in simplified:
        print(json.dumps(rec, ensure_ascii=False, separators=(',', ':')))

    # Optional: save last_seen state
    newest = records_sorted[-1]
    new_created = newest.get("CreatedDate", "").replace("+0000", "Z").split(".")[0] + "Z"
    write_state({"last_seen": new_created, "last_id": newest.get("Id")})

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("Fatal error:", e, file=sys.stderr)
        sys.exit(1)
