"""
Live GitHub search against the public wazuh/wazuh repo — no local file, no
private token required, called at chat time by the copilot.

Optionally set GITHUB_TOKEN in the backend's own environment (not in any
project file) to raise the rate limit from 60 requests/hour to 5,000/hour,
and to enable discussion search — GitHub's GraphQL API has no anonymous
mode, so discussions are skipped silently if no token is set. Issue search
works fine with no token at all, just at the lower rate limit.
"""
import os
import re
import requests

REPO = os.environ.get("WAZUH_REPO", "wazuh/wazuh")
TOKEN = os.environ.get("GITHUB_TOKEN")

_ISSUE_HEADERS = {"Accept": "application/vnd.github+json"}
if TOKEN:
    _ISSUE_HEADERS["Authorization"] = f"Bearer {TOKEN}"

_TIMEOUT = 6  # keep the copilot responsive even if GitHub is slow or down


def _sanitize_query(query: str) -> str:
    """Strip characters that carry special meaning in GitHub search syntax
    (e.g. a stray ':' or '"' from a user's question turning into a qualifier)."""
    return re.sub(r'["\':]', ' ', query).strip()


def _fetch_issue_comments(issue_number, limit=5):
    try:
        resp = requests.get(
            f"https://api.github.com/repos/{REPO}/issues/{issue_number}/comments",
            headers=_ISSUE_HEADERS,
            params={"per_page": limit},
            timeout=_TIMEOUT,
        )
        if resp.status_code != 200:
            return []
        return [c.get("body") or "" for c in resp.json()]
    except Exception:
        return []


def search_public_issues(query: str, top_n: int = 2) -> list:
    """Live keyword search against GitHub issues in wazuh/wazuh."""
    q = _sanitize_query(query)
    if not q:
        return []
    try:
        resp = requests.get(
            "https://api.github.com/search/issues",
            headers=_ISSUE_HEADERS,
            params={"q": f"repo:{REPO} is:issue {q}", "per_page": top_n},
            timeout=_TIMEOUT,
        )
        if resp.status_code != 200:
            return []
    except Exception:
        return []

    results = []
    for item in resp.json().get("items", [])[:top_n]:
        results.append({
            "number": item["number"],
            "title": item["title"],
            "body": (item.get("body") or "")[:500],
            "comments": _fetch_issue_comments(item["number"]),
            "url": item["html_url"],
        })
    return results


_DISCUSSION_SEARCH_QUERY = """
query($searchQuery: String!) {
  search(query: $searchQuery, type: DISCUSSION, first: 3) {
    nodes {
      ... on Discussion {
        number
        title
        bodyText
        url
        isAnswered
        answer { bodyText }
      }
    }
  }
}
"""


def search_public_discussions(query: str, top_n: int = 2) -> list:
    """Live search against GitHub Discussions in wazuh/wazuh. Requires a
    token (GraphQL has no anonymous mode) - any basic token works fine for
    a public repo. Returns [] silently if no token is configured."""
    if not TOKEN:
        return []
    q = _sanitize_query(query)
    if not q:
        return []
    try:
        resp = requests.post(
            "https://api.github.com/graphql",
            headers={"Authorization": f"Bearer {TOKEN}"},
            json={
                "query": _DISCUSSION_SEARCH_QUERY,
                "variables": {"searchQuery": f"repo:{REPO} {q}"},
            },
            timeout=_TIMEOUT,
        )
        if resp.status_code != 200:
            return []
    except Exception:
        return []

    nodes = resp.json().get("data", {}).get("search", {}).get("nodes", [])
    results = []
    for d in nodes[:top_n]:
        answer = d.get("answer")
        results.append({
            "number": d.get("number"),
            "title": d.get("title"),
            "body": (d.get("bodyText") or "")[:500],
            "answer": answer.get("bodyText") if answer else "",
            "url": d.get("url"),
        })
    return results


def format_public_context(issues: list, discussions: list) -> str:
    if not issues and not discussions:
        return ""
    parts = ["=== Public wazuh/wazuh issues & discussions (live GitHub search) ==="]
    for issue in issues:
        resolution = "\n".join(issue.get("comments", []))[:800]
        parts.append(f"- Issue #{issue['number']}: {issue['title']}\n  {issue['body']}\n  Discussion: {resolution}")
    for d in discussions:
        parts.append(f"- Discussion #{d['number']}: {d['title']}\n  {d['body']}\n  Answer: {d.get('answer', '')}")
    parts.append("=================================================")
    return "\n".join(parts)
