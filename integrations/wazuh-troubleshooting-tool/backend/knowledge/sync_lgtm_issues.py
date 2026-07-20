"""
Private sync script — run manually by a team member, NOT called by the
public backend and NOT part of the running app.

It fetches LGTM/resolved/resolved-without-feedback issues from a private/
internal GitHub repo, embeds each one, and stores them in
backend/knowledge/lgtm.db (SQLite, gitignored) for the copilot's semantic
search to read locally.

The GitHub token is never written to disk by this script and never
hardcoded here — it must be set as an environment variable before running.
Requires Ollama running locally with the nomic-embed-text model pulled.

Usage:
    export GITHUB_TOKEN="<your fine-grained PAT, Issues: Read-only>"
    export LGTM_REPO="wazuh/community"        # optional, this is the default
    export LGTM_LABEL="LGTM"                                       # optional, this is the default
    export RESOLVED_LABEL="resolved"                               # optional, this is the default
    export RESOLVED_NO_FEEDBACK_LABEL="resolved without feedback"  # optional, this is the default
    export LGTM_AUTHOR="some-github-username"                      # optional, filters by issue author
    python3 sync_lgtm_issues.py
"""
import os
import re
import sys
import time
from datetime import date, timedelta
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils import lgtm_db

# Matches links to the original community conversation that GitHub issues here
# always reference. Reddit and Google Groups are publicly readable with no
# login, so we fetch them directly. Slack/Discord are NOT handled here — see
# the note in fetch_external_community_content() below for why.
REDDIT_RE = re.compile(r'https?://(?:www\.)?reddit\.com/r/\S+/comments/\S+')
GOOGLE_GROUPS_RE = re.compile(r'https?://groups\.google\.com/\S+')
SLACK_RE = re.compile(r'https?://[\w.-]*\.slack\.com/\S+')
DISCORD_RE = re.compile(r'https?://(?:www\.)?discord\.com/channels/\S+')

REPO = os.environ.get("LGTM_REPO", "wazuh/community")
LABEL = os.environ.get("LGTM_LABEL", "LGTM")
# Issues closed out as resolved outside the LGTM review flow - same idea as
# LGTM, just a different label for "this thread reached a real answer."
RESOLVED_LABEL = os.environ.get("RESOLVED_LABEL", "resolved")
# Resolved without the requester ever confirming the fix worked - still a
# real answer from the responder's side, just missing that final feedback loop.
RESOLVED_NO_FEEDBACK_LABEL = os.environ.get("RESOLVED_NO_FEEDBACK_LABEL", "resolved without feedback")
AUTHOR = os.environ.get("LGTM_AUTHOR")

TOKEN = os.environ.get("GITHUB_TOKEN")
if not TOKEN:
    sys.exit("ERROR: set GITHUB_TOKEN in your shell environment before running this script.")

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
}


def _base_query(label, date_range=None):
    query = f'repo:{REPO} is:issue label:"{label}"'
    if date_range:
        query += f" created:{date_range}"
    if AUTHOR:
        query += f" author:{AUTHOR}"
    return query


def check_connection():
    """Fail fast (a few seconds) with a clear reason instead of silently
    sitting on a slow/broken request for 30s+ with no output at all."""
    print("Checking GitHub connection and token...", flush=True)
    try:
        resp = requests.get("https://api.github.com/rate_limit", headers=HEADERS, timeout=10)
    except requests.exceptions.RequestException as e:
        sys.exit(f"ERROR: could not reach GitHub at all — check your network/proxy/VPN. Details: {e}")
    if resp.status_code == 401:
        sys.exit("ERROR: GitHub rejected the token (401 Bad credentials) — check GITHUB_TOKEN is correct and not expired.")
    if resp.status_code != 200:
        sys.exit(f"ERROR: unexpected response from GitHub ({resp.status_code}): {resp.text[:300]}")
    remaining = resp.json().get("resources", {}).get("search", {}).get("remaining", "?")
    print(f"OK - token works, {remaining} search requests remaining this minute.", flush=True)


def _run_query(query):
    """Fetch every page for a single query. Returns (issues, hit_1000_cap)."""
    issues = []
    page = 1
    while True:
        resp = requests.get(
            "https://api.github.com/search/issues",
            headers=HEADERS,
            params={"q": query, "per_page": 100, "page": page},
            timeout=30,
        )
        if resp.status_code == 422:
            return issues, True  # GitHub's hard 1000-result cap for this query
        if resp.status_code == 403 and resp.headers.get("X-RateLimit-Remaining") == "0":
            reset_at = int(resp.headers.get("X-RateLimit-Reset", 0))
            wait_s = max(reset_at - time.time(), 0) + 5
            print(f"  primary rate limit hit - waiting {int(wait_s)}s for it to reset...", flush=True)
            time.sleep(wait_s)
            continue  # retry this same page
        if resp.status_code == 403 and "rate limit" in resp.text.lower():
            print("  secondary rate limit hit - waiting 60s...", flush=True)
            time.sleep(60)
            continue  # retry this same page
        if resp.status_code != 200:
            sys.exit(f"GitHub API error {resp.status_code}: {resp.text[:300]}")
        items = resp.json().get("items", [])
        if not items:
            break
        issues.extend(items)
        print(f"  found {len(items)} on this page ({len(issues)} so far for this query)", flush=True)
        if len(items) < 100:
            break
        page += 1
        time.sleep(1)
    return issues, False


def fetch_all_issues():
    """
    GitHub's search API caps any single query at 1000 total results, no matter
    how you paginate. We run one query per label (not a combined OR) to keep
    each well under that ceiling, and if a label's own results still exceed
    1000, we fall back to splitting that label's query into ~quarterly date
    ranges going back in time until two consecutive ranges come back empty
    (a reasonable signal we've covered the repo's full history).
    """
    seen = {}
    for label in (LABEL, RESOLVED_LABEL, RESOLVED_NO_FEEDBACK_LABEL):
        print(f"Searching GitHub for label '{label}' in {REPO}...", flush=True)
        issues, hit_cap = _run_query(_base_query(label))
        for it in issues:
            seen[it["number"]] = it
        print(f"  '{label}': {len(issues)} found ({len(seen)} unique total so far)", flush=True)

        if not hit_cap:
            continue

        print(f"  hit GitHub's 1000-result cap for '{label}' - splitting by ~quarter...", flush=True)
        quarter_end = date.today()
        empty_streak = 0
        max_quarters = 80  # ~20 years back - a sane backstop, not expected to ever hit this
        for _ in range(max_quarters):
            if empty_streak >= 2:
                break
            quarter_start = quarter_end - timedelta(days=92)
            print(f"    {label}: {quarter_start.isoformat()}..{quarter_end.isoformat()}...", flush=True)
            q_issues = _fetch_date_range(label, quarter_start, quarter_end)
            for it in q_issues:
                seen[it["number"]] = it
            empty_streak = empty_streak + 1 if not q_issues else 0
            quarter_end = quarter_start
            time.sleep(1)

    return list(seen.values())


def _fetch_date_range(label, start, end):
    """
    Fetch every issue for `label` within [start, end]. If this window alone
    still exceeds the 1000-result cap (as happens for very high-volume/
    bot-applied labels, where even a ~3-month slice isn't narrow enough),
    recursively bisect it and retry each half - down to a 1-day floor, at
    which point we log a warning and accept that single day may be
    incomplete rather than looping forever.
    """
    date_range = f"{start.isoformat()}..{end.isoformat()}"
    issues, hit_cap = _run_query(_base_query(label, date_range))
    if not hit_cap:
        return issues
    if start >= end:
        print(
            f"      WARNING: '{label}' on {start.isoformat()} alone exceeds "
            f"1000 results - some issues from this single day may be missing.",
            flush=True,
        )
        return issues
    mid = start + (end - start) // 2
    print(f"      {date_range} still exceeds 1000 - bisecting at {mid.isoformat()}...", flush=True)
    left = _fetch_date_range(label, start, mid)
    right = _fetch_date_range(label, mid + timedelta(days=1), end)
    return left + right


def fetch_comments(issue_number):
    """
    The actual resolution is usually in the comment thread, not the body.
    Transient network errors (dropped connections, timeouts) are retried a
    few times - across thousands of issues in one run, an occasional blip
    is expected and shouldn't be treated any differently than a bad
    response from GitHub.
    """
    for attempt in range(3):
        try:
            resp = requests.get(
                f"https://api.github.com/repos/{REPO}/issues/{issue_number}/comments",
                headers=HEADERS,
                params={"per_page": 100},
                timeout=30,
            )
            break
        except requests.exceptions.RequestException as e:
            if attempt == 2:
                print(f"    WARNING: comments fetch failed for #{issue_number} after 3 attempts ({e}) - skipping comments for this issue", flush=True)
                return []
            time.sleep(2 * (attempt + 1))
    if resp.status_code != 200:
        return []
    return [c.get("body") or "" for c in resp.json()]


def fetch_reddit_content(url):
    """Reddit's public JSON API needs no login — just a real User-Agent."""
    json_url = url.split('?')[0].rstrip('/') + '.json'
    try:
        resp = requests.get(
            json_url,
            headers={"User-Agent": "wazuh-troubleshooting-tool-sync/1.0"},
            timeout=15,
        )
        if resp.status_code != 200:
            return ""
        data = resp.json()
        post = data[0]["data"]["children"][0]["data"]
        parts = [f"REDDIT POST: {post.get('title', '')}\n{post.get('selftext', '')}"]
        for c in data[1]["data"]["children"]:
            body = c.get("data", {}).get("body")
            if body:
                parts.append(f"REDDIT COMMENT: {body}")
        return "\n\n".join(parts)[:4000]
    except Exception:
        return ""


def fetch_google_groups_content(url):
    """Public Google Groups threads are readable as plain HTML, no login."""
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code != 200:
            return ""
        clean_text = re.sub(r'<[^>]+>', ' ', resp.text)
        clean_text = re.sub(r'\s+', ' ', clean_text).strip()
        return clean_text[:4000]
    except Exception:
        return ""


def fetch_external_community_content(body):
    """
    Best-effort fetch of the original community thread linked from the issue.
    Reddit and Google Groups: fetched directly below, no auth needed.
    Slack/Discord: NOT fetched here. Both require a bot token with membership
    inside that specific workspace/server to read message history at all — an
    unauthenticated script cannot reach them, and Slack's free-tier history
    also expires (~90 days), so even an authenticated fetch could find nothing
    by the time this script runs. The durable fix is extending whatever bot
    already mirrors Reddit into these GitHub issues to also mirror Slack/
    Discord at post time — capturing it before it's ever behind auth for us.
    We just flag that a Slack/Discord link exists so it's visible in the data.
    """
    texts = []
    for url in REDDIT_RE.findall(body):
        text = fetch_reddit_content(url)
        if text:
            texts.append(text)
        time.sleep(1)  # stay well under Reddit's unauthenticated rate limit

    for url in GOOGLE_GROUPS_RE.findall(body):
        text = fetch_google_groups_content(url)
        if text:
            texts.append(text)

    if SLACK_RE.search(body):
        texts.append("[Linked Slack conversation — not fetchable without a bot token in that workspace.]")
    if DISCORD_RE.search(body):
        texts.append("[Linked Discord conversation — not fetchable without a bot token in that server.]")

    return texts


DISCUSSIONS_QUERY = """
query($owner: String!, $name: String!, $after: String) {
  repository(owner: $owner, name: $name) {
    discussions(first: 50, after: $after, orderBy: {field: UPDATED_AT, direction: DESC}) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number
        title
        bodyText
        url
        isAnswered
        answer { bodyText }
        comments(first: 50) { nodes { bodyText } }
      }
    }
  }
}
"""


def fetch_discussions():
    """
    Discussions have no labels the way issues do, and no REST search endpoint
    at all - only GraphQL, via the repository's own discussions connection
    (not the Search API, so no 1000-result cap here, just normal cursor
    pagination). isAnswered is used as the proxy for "resolved" since that's
    the closest equivalent to LGTM/review-quality that Discussions has.
    """
    owner, name = REPO.split("/")
    answered = []
    after = None
    page = 1
    while True:
        print(f"Fetching wazuh/community discussions (page {page})...", flush=True)
        resp = None
        for attempt in range(3):
            try:
                resp = requests.post(
                    "https://api.github.com/graphql",
                    headers={"Authorization": f"Bearer {TOKEN}"},
                    json={"query": DISCUSSIONS_QUERY, "variables": {"owner": owner, "name": name, "after": after}},
                    timeout=30,
                )
                break
            except requests.exceptions.RequestException as e:
                if attempt == 2:
                    print(f"  WARNING: discussions fetch failed after 3 attempts ({e}) - stopping discussions fetch here", flush=True)
                    return answered
                time.sleep(2 * (attempt + 1))
        if resp.status_code != 200:
            print(f"  WARNING: GraphQL error {resp.status_code}: {resp.text[:200]} - stopping discussions fetch here", flush=True)
            break
        data = resp.json().get("data", {}).get("repository", {}).get("discussions", {})
        nodes = data.get("nodes", [])
        new_answered = [d for d in nodes if d.get("isAnswered")]
        answered.extend(new_answered)
        print(f"  {len(nodes)} discussions on this page, {len(new_answered)} answered ({len(answered)} answered so far)", flush=True)
        page_info = data.get("pageInfo", {})
        if not page_info.get("hasNextPage"):
            break
        after = page_info.get("endCursor")
        page += 1
        time.sleep(1)
    return answered


def main():
    check_connection()
    raw_issues = fetch_all_issues()
    print(f"Fetching comments/linked discussions and embedding {len(raw_issues)} issues...", flush=True)
    ok = 0
    for i, issue in enumerate(raw_issues, 1):
        body = issue.get("body") or ""
        print(f"  [{i}/{len(raw_issues)}] issue #{issue['number']}: {issue['title'][:60]}", flush=True)
        try:
            cleaned = {
                "number": issue["number"],
                "title": issue["title"],
                "body": body,
                "comments": fetch_comments(issue["number"]),
                "external_community": fetch_external_community_content(body),
                "url": issue["html_url"],
                "labels": [l["name"] for l in issue.get("labels", [])],
            }
            if lgtm_db.upsert_issue(cleaned, source="community_issue"):
                ok += 1
            else:
                print(f"    WARNING: embedding failed for #{issue['number']} - skipped (check Ollama is running)", flush=True)
        except Exception as e:
            # One bad issue (network blip, unexpected API shape, etc.) should
            # never take down a run that's otherwise processing thousands of
            # issues fine - log it and move on.
            print(f"    WARNING: unexpected error on #{issue['number']} ({e}) - skipped", flush=True)
        time.sleep(0.5)  # one extra request per issue, stay well under rate limits

    print(f"Saved {ok}/{len(raw_issues)} issues. Total community issues in DB: {lgtm_db.count('community_issue')}")

    discussions = fetch_discussions()
    print(f"Embedding {len(discussions)} answered discussions...", flush=True)
    d_ok = 0
    for i, d in enumerate(discussions, 1):
        comments = [c.get("bodyText", "") for c in d.get("comments", {}).get("nodes", [])]
        answer = d.get("answer")
        if answer and answer.get("bodyText"):
            comments.insert(0, f"ACCEPTED ANSWER: {answer['bodyText']}")
        print(f"  [{i}/{len(discussions)}] discussion #{d['number']}: {d['title'][:60]}", flush=True)
        try:
            cleaned = {
                "number": d["number"],
                "title": d["title"],
                "body": d.get("bodyText") or "",
                "comments": comments,
                "external_community": [],
                "url": d["url"],
                "labels": [],
            }
            if lgtm_db.upsert_issue(cleaned, source="community_discussion"):
                d_ok += 1
            else:
                print(f"    WARNING: embedding failed for discussion #{d['number']} - skipped", flush=True)
        except Exception as e:
            print(f"    WARNING: unexpected error on discussion #{d['number']} ({e}) - skipped", flush=True)
        time.sleep(0.3)

    print(f"Saved {d_ok}/{len(discussions)} discussions. Total community discussions in DB: {lgtm_db.count('community_discussion')}")
    print(f"Grand total in knowledge base: {lgtm_db.count()}")


if __name__ == "__main__":
    main()
