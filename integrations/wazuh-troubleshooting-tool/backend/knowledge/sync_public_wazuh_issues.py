"""
Public sync script — pulls closed issues AND answered Discussions
(https://github.com/wazuh/wazuh/discussions) from the public wazuh/wazuh
repo into the same unified knowledge base as the private LGTM/resolved
issues and community discussions (backend/knowledge/lgtm.db), so Ollama's
RAG path can search all sources together without any live network calls at
chat time.

No token required for the issues fetch (public repo), but supplying
GITHUB_TOKEN raises GitHub's rate limit from 60 requests/hour to 5,000/hour,
and is *required* for the Discussions fetch (GraphQL has no anonymous mode
at all, even for public repos) - worth reusing the same token from
sync_lgtm_issues.py if you have one. Requires Ollama running locally with
the nomic-embed-text model pulled.

wazuh/wazuh has 20,000+ closed issues total - fetching and embedding all of
them would take many hours and mostly add old, low-relevance noise (ancient
versions, since-changed behavior). We sort by most-recently-updated and stop
once we reach WAZUH_ISSUES_MAX_AGE_YEARS (default 2) - since results are
sorted newest-first, the moment one falls outside the window everything
after it is guaranteed to be even older, so this also saves the extra
requests, not just narrows the data. WAZUH_MAX_ISSUES is a secondary safety
cap in case an age window is somehow still huge. Same idea applies to
discussions via DISCUSSIONS_MAX_AGE_YEARS.

Usage:
    export GITHUB_TOKEN="..."               # optional for issues, required for discussions
    export WAZUH_ISSUES_MAX_AGE_YEARS="2"   # optional, this is the default
    export WAZUH_MAX_ISSUES="500"           # optional, this is the default; 0 = no limit
    export WAZUH_MAX_DISCUSSIONS="300"      # optional, this is the default; 0 = no limit
    export DISCUSSIONS_MAX_AGE_YEARS="2"    # optional, this is the default
    export SKIP_ISSUES="1"                  # optional - skip re-fetching issues, discussions only
    python3 sync_public_wazuh_issues.py
"""
import os
import sys
import time
from datetime import date, timedelta
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import lgtm_db
from utils.github_discussions import fetch_answered_discussions, discussion_to_issue_dict

REPO = os.environ.get("WAZUH_REPO", "wazuh/wazuh")
STATE = os.environ.get("WAZUH_ISSUE_STATE", "closed")  # closed = likely resolved
MAX_ISSUES = int(os.environ.get("WAZUH_MAX_ISSUES", "500"))
ISSUES_MAX_AGE_YEARS = int(os.environ.get("WAZUH_ISSUES_MAX_AGE_YEARS", "2"))
MAX_DISCUSSIONS = int(os.environ.get("WAZUH_MAX_DISCUSSIONS", "300"))
DISCUSSIONS_MAX_AGE_YEARS = int(os.environ.get("DISCUSSIONS_MAX_AGE_YEARS", "2"))

TOKEN = os.environ.get("GITHUB_TOKEN")
HEADERS = {"Accept": "application/vnd.github+json"}
if TOKEN:
    HEADERS["Authorization"] = f"Bearer {TOKEN}"


def fetch_issues():
    cutoff = (date.today() - timedelta(days=365 * ISSUES_MAX_AGE_YEARS)).isoformat()
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

        # sorted newest-updated-first, so the moment one falls before the
        # cutoff, everything after it is guaranteed to be even older - drop
        # it and stop paginating entirely, saving the remaining requests
        hit_cutoff = False
        in_window = []
        for i in page_issues:
            if i.get("updated_at", "") < cutoff:
                hit_cutoff = True
                break
            in_window.append(i)
        page_issues = in_window

        issues.extend(page_issues)
        print(f"  {len(page_issues)} issues on this page ({len(issues)} total so far)", flush=True)
        if MAX_ISSUES and len(issues) >= MAX_ISSUES:
            issues = issues[:MAX_ISSUES]
            print(f"  reached WAZUH_MAX_ISSUES cap ({MAX_ISSUES}) - stopping here", flush=True)
            break
        if hit_cutoff:
            print(f"  reached the {cutoff} cutoff - stopping here", flush=True)
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


SKIP_ISSUES = os.environ.get("SKIP_ISSUES", "").lower() in ("1", "true", "yes")


def main():
    if SKIP_ISSUES:
        print("SKIP_ISSUES set - skipping the issues fetch entirely (e.g. re-running just to pick up discussions with a token this time).", flush=True)
    else:
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

    cutoff = (date.today() - timedelta(days=365 * DISCUSSIONS_MAX_AGE_YEARS)).isoformat()
    discussions = fetch_answered_discussions(REPO, TOKEN, max_items=MAX_DISCUSSIONS or None, min_updated_at=cutoff)
    print(f"Embedding {len(discussions)} answered {REPO} discussions...", flush=True)
    d_ok = 0
    for i, d in enumerate(discussions, 1):
        print(f"  [{i}/{len(discussions)}] discussion #{d['number']}: {d['title'][:60]}", flush=True)
        try:
            cleaned = discussion_to_issue_dict(d)
            if lgtm_db.upsert_issue(cleaned, source="public_wazuh_discussion"):
                d_ok += 1
            else:
                print(f"    WARNING: embedding failed for discussion #{d['number']} - skipped", flush=True)
        except Exception as e:
            print(f"    WARNING: unexpected error on discussion #{d['number']} ({e}) - skipped", flush=True)
        time.sleep(0.3)

    print(f"Saved {d_ok}/{len(discussions)} discussions. Total public_wazuh_discussion in DB: {lgtm_db.count('public_wazuh_discussion')}")
    print(f"Grand total in knowledge base: {lgtm_db.count()}")


if __name__ == "__main__":
    main()
