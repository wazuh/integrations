"""
Curated, human-verified Wazuh documentation URLs, fetched live and fed into
the copilot's context - this exists because letting a small local LLM recall
exact doc URLs from memory produces confident-looking but wrong/404 links.
Every URL in KNOWN_DOCS must be a real page a human actually checked; the
model is never asked to invent one.

To add a new one: verify the URL actually loads (not a 404), add an entry
below with a few keywords that should trigger it, done.
"""
import re
import requests

KNOWN_DOCS = {
    "agent_install_linux": {
        "keywords": ["install agent", "add agent", "add an agent", "deploy agent", "agent installation", "install wazuh-agent"],
        "url": "https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html",
        "title": "Wazuh Agent installation on Linux",
    },
    "cloud_trial": {
        "keywords": ["cloud trial", "cloud sign up", "cloud signup", "trial credentials", "wazuh cloud login"],
        "url": "https://documentation.wazuh.com/current/cloud-service/getting-started/sign-up-trial.html",
        "title": "Wazuh Cloud trial sign-up",
    },
}

_cache = {}


def find_matching_doc(query: str):
    """Return the first KNOWN_DOCS entry whose keywords appear in the query, or None."""
    q = query.lower()
    for key, doc in KNOWN_DOCS.items():
        if any(kw in q for kw in doc["keywords"]):
            return key, doc
    return None, None


def fetch_doc_content(url: str) -> str:
    """Fetch and clean a doc page's text. Cached in-memory so repeat questions
    on the same topic don't re-fetch every time."""
    if url in _cache:
        return _cache[url]
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return ""
        html = resp.text
        # Wazuh's doc site wraps real content in <main ...>...</main>; without
        # this, stripping tags on the full page grabs the sidebar table-of-
        # contents (hundreds of unrelated menu links) instead of the article.
        main_match = re.search(r"<main[^>]*>(.*?)</main>", html, flags=re.DOTALL)
        html = main_match.group(1) if main_match else html
        clean_text = re.sub(r"<script[^>]*>.*?</script>", " ", html, flags=re.DOTALL)
        clean_text = re.sub(r"<style[^>]*>.*?</style>", " ", clean_text, flags=re.DOTALL)
        clean_text = re.sub(r"<[^>]+>", " ", clean_text)
        clean_text = re.sub(r"\s+", " ", clean_text).strip()
        content = clean_text[:6000]
        _cache[url] = content
        return content
    except requests.exceptions.RequestException:
        return ""


def format_doc_context(query: str) -> str:
    """If the query matches a known topic, return grounded context with the
    verified URL and an explicit instruction to cite only that exact URL."""
    key, doc = find_matching_doc(query)
    if not doc:
        return ""
    content = fetch_doc_content(doc["url"])
    if not content:
        return ""
    return (
        f"=== Official Wazuh documentation: {doc['title']} ===\n"
        f"{content}\n\n"
        f"Instructions: if you reference documentation for this topic, cite exactly this URL "
        f"and no other: {doc['url']} - do not modify it or invent a different path.\n"
        f"================================================="
    )
