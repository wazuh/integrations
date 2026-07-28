"""
Shared GitHub Discussions fetcher - used by both sync_lgtm_issues.py
(wazuh/community discussions) and sync_public_wazuh_issues.py (wazuh/wazuh
discussions, e.g. https://github.com/wazuh/wazuh/discussions).

Discussions have no labels the way issues do, and no REST search endpoint at
all - only GraphQL, via the repository's own discussions connection (not the
Search API, so no 1000-result cap here, just normal cursor pagination).
isAnswered is used as the proxy for "resolved" since that's the closest
equivalent to LGTM/review-quality/resolved that Discussions has.

GraphQL always requires a token (no anonymous calls at all), but for a
PUBLIC repo any basic token works fine, even one scoped to a different repo,
since fine-grained PATs get implicit read access to all public repos.
"""
import time
import requests

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
        updatedAt
        answer { bodyText }
        comments(first: 50) { nodes { bodyText } }
      }
    }
  }
}
"""


def fetch_answered_discussions(repo: str, token: str, label: str = None, max_items: int = None, min_updated_at: str = None) -> list:
    """
    repo: "owner/name", e.g. "wazuh/wazuh" or "wazuh/community"
    token: any GitHub token - required (GraphQL has no anonymous mode)
    label: just used for print statements, defaults to `repo`
    max_items: stop once this many *answered* discussions are collected (None = no cap).
               Results are already ordered most-recently-updated first, so a
               cap stays biased toward current relevance, same idea as
               sync_public_wazuh_issues.py's WAZUH_MAX_ISSUES.
    min_updated_at: ISO 8601 date string, e.g. "2023-07-18". Since results are
               ordered newest-updated-first, the moment a discussion older
               than this cutoff shows up, everything after it is guaranteed
               to be even older - we drop it and stop paginating entirely
               rather than just filtering it out, saving the extra requests.
    """
    if not token:
        print(f"  Skipping {repo} discussions: no token available (GraphQL requires one, even for public repos).", flush=True)
        return []

    label = label or repo
    owner, name = repo.split("/")
    answered = []
    after = None
    page = 1
    while True:
        print(f"Fetching {label} discussions (page {page})...", flush=True)
        resp = None
        for attempt in range(3):
            try:
                resp = requests.post(
                    "https://api.github.com/graphql",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"query": DISCUSSIONS_QUERY, "variables": {"owner": owner, "name": name, "after": after}},
                    timeout=30,
                )
                break
            except requests.exceptions.RequestException as e:
                if attempt == 2:
                    print(f"  WARNING: {label} discussions fetch failed after 3 attempts ({e}) - stopping here", flush=True)
                    return answered
                time.sleep(2 * (attempt + 1))
        if resp.status_code != 200:
            print(f"  WARNING: GraphQL error {resp.status_code}: {resp.text[:200]} - stopping {label} discussions fetch here", flush=True)
            break
        data = resp.json().get("data", {}).get("repository", {}).get("discussions", {})
        nodes = data.get("nodes", [])

        hit_cutoff = False
        if min_updated_at:
            in_range = []
            for d in nodes:
                if d.get("updatedAt", "") < min_updated_at:
                    hit_cutoff = True
                    break
                in_range.append(d)
            nodes = in_range

        new_answered = [d for d in nodes if d.get("isAnswered")]
        answered.extend(new_answered)
        print(f"  {len(nodes)} discussions on this page, {len(new_answered)} answered ({len(answered)} answered so far)", flush=True)

        if max_items and len(answered) >= max_items:
            answered = answered[:max_items]
            print(f"  reached max_items cap ({max_items}) - stopping here", flush=True)
            break
        if hit_cutoff:
            print(f"  reached the {min_updated_at} cutoff - stopping here", flush=True)
            break
        page_info = data.get("pageInfo", {})
        if not page_info.get("hasNextPage"):
            break
        after = page_info.get("endCursor")
        page += 1
        time.sleep(1)
    return answered


def discussion_to_issue_dict(d: dict) -> dict:
    """Reshape a GraphQL discussion node into the same dict shape upsert_issue() expects."""
    comments = [c.get("bodyText", "") for c in d.get("comments", {}).get("nodes", [])]
    answer = d.get("answer")
    if answer and answer.get("bodyText"):
        comments.insert(0, f"ACCEPTED ANSWER: {answer['bodyText']}")
    return {
        "number": d["number"],
        "title": d["title"],
        "body": d.get("bodyText") or "",
        "comments": comments,
        "external_community": [],
        "url": d["url"],
        "labels": [],
    }
