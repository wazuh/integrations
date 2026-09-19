"""
One-time migration: reads the existing lgtm_issues.json (fetched via
sync_lgtm_issues.py before the SQLite+embeddings switch) and loads it into
the new SQLite DB with embeddings computed via Ollama. Safe to re-run -
upsert_issue() overwrites by issue number.

Usage:
    python3 migrate_json_to_sqlite.py
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import lgtm_db

JSON_PATH = os.path.join(os.path.dirname(__file__), "lgtm_issues.json")


def main():
    if not os.path.exists(JSON_PATH):
        sys.exit(f"No existing data to migrate at {JSON_PATH}")

    with open(JSON_PATH) as f:
        issues = json.load(f)

    print(f"Migrating {len(issues)} issues into SQLite with embeddings...", flush=True)
    ok = 0
    for i, issue in enumerate(issues, 1):
        success = lgtm_db.upsert_issue(issue)
        ok += success
        print(f"  [{i}/{len(issues)}] issue #{issue['number']}: {'OK' if success else 'FAILED (embedding call failed)'}", flush=True)
        time.sleep(0.05)  # let the embedding model breathe between calls

    print(f"Done: {ok}/{len(issues)} migrated. Total in DB now: {lgtm_db.count()}", flush=True)


if __name__ == "__main__":
    main()
