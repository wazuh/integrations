"""
Public sync script — pulls closed issues from the public wazuh/wazuh repo
into the same unified knowledge base as the private LGTM/review-quality
issues and community discussions (backend/knowledge/lgtm.db), so Ollama's
RAG path can search all three sources together without any live network
calls at chat time.

No token required (public repo), but supplying GITHUB_TOKEN raises GitHub's
rate limit from 60 requests/hour to 5,000/hour - worth reusing the same
token from sync_lgtm_issues.py if you have one. Requires Ollama running
locally with the nomic-embed-text model pulled.

wazuh/wazuh has 20,000+ closed issues total - fetching and embedding all of
them would take many hours and mostly add old, low-relevance noise (ancient
versions, since-changed behavior). We sort by most-recently-updated and cap
at WAZUH_MAX_ISSUES (default 500) so this stays a reasonable background job
and stays biased toward currently-relevant content. Raise the cap (or set it
to 0 for no limit) if you want deeper historical coverage.

Usage:
    export GITHUB_TOKEN="..."       # optional but recommended
    export WAZUH_MAX_ISSUES="500"   # optional, this is the default; 0 = no limit
    python3 sync_public_wazuh_issues.py
"""
import os
import sys
import time
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import lgtm_db

REPO = os.environ.get("WAZUH_REPO", "wazuh/wazuh")
STATE = os.environ.get("WAZUH_ISSUE_STATE", "closed")  # closed = likely resolved
MAX_ISSUES = int(os.environ.get("WAZUH_MAX_ISSUES", "500"))

TOKEN = os.environ.get("GITHUB_TOKEN")
HEADERS = {"Accept": "application/vnd.github+json"}
if TOKEN:
    HEADERS["Authorization"] = f"Bearer {TOKEN}"


def fetch_issues():
    issues = []
    page = 1
    while True:
        print(f"Fetching {REPO} issues (state={STATE}, sorted by most-recently-updated, page {page})...", flush=True)
        resp = requests.get(
            f"https://api.github.com/repos/{REPO}/issues",
            headers=HEADERS,
            params={"state": STATE, "sort": "updated", "direction": "desc", "per_page": 100, "page": page},
            timeout=30,
        )
        if resp.status_code != 200:
            print(f"WARNING: issues API returned {resp.status_code}: {resp.text[:200]}", file=sys.stderr)
            break
        items = resp.json()
        if not items:
            break
        # the /issues endpoint also returns pull requests - skip those
        page_issues = [i for i in items if "pull_request" not in i]
        issues.extend(page_issues)
        print(f"  {len(page_issues)} issues on this page ({len(issues)} total so far)", flush=True)
        if MAX_ISSUES and len(issues) >= MAX_ISSUES:
            issues = issues[:MAX_ISSUES]
            print(f"  reached WAZUH_MAX_ISSUES cap ({MAX_ISSUES}) - stopping here", flush=True)
            break
        if len(items) < 100:
            break
        page += 1
        time.sleep(0.5)
    return issues


def fetch_comments(issue_number):
    resp = requests.get(
        f"https://api.github.com/repos/{REPO}/issues/{issue_number}/comments",
        headers=HEADERS,
        params={"per_page": 100},
        timeout=30,
    )
    if resp.status_code != 200:
        return []
    return [c.get("body") or "" for c in resp.json()]


def main():
    issues = fetch_issues()
    print(f"Embedding {len(issues)} public {REPO} issues...", flush=True)
    ok = 0
    for i, issue in enumerate(issues, 1):
        print(f"  [{i}/{len(issues)}] issue #{issue['number']}: {issue['title'][:60]}", flush=True)
        cleaned = {
            "number": issue["number"],
            "title": issue["title"],
            "body": issue.get("body") or "",
            "comments": fetch_comments(issue["number"]),
            "external_community": [],
            "url": issue["html_url"],
            "labels": [l["name"] for l in issue.get("labels", [])],
        }
        if lgtm_db.upsert_issue(cleaned, source="public_wazuh_issue"):
            ok += 1
        else:
            print(f"    WARNING: embedding failed for #{issue['number']} - skipped (check Ollama is running)", flush=True)
        time.sleep(0.3)

    print(f"Saved {ok}/{len(issues)} public issues. Total public_wazuh_issue in DB: {lgtm_db.count('public_wazuh_issue')}")
    print(f"Grand total in knowledge base: {lgtm_db.count()}")


if __name__ == "__main__":
    main()
