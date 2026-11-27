"""
Wraps Ollama's embedding endpoint for the LGTM knowledge base's semantic
search. nomic-embed-text is asymmetric - it expects a task prefix for best
retrieval quality: "search_document: " when embedding a stored issue,
"search_query: " when embedding a user's question.
"""
import requests

from config import OLLAMA_URL

EMBED_MODEL = "nomic-embed-text"
# 15s was too tight on a loaded, low-core-count host - a correctly-working
# embedding call can simply take longer than that under CPU contention from
# other services (wazuh-indexer, editor tooling, etc.), not because Ollama
# is actually broken. 60s gives real headroom without masking a truly dead
# Ollama for an unreasonable amount of time.
_TIMEOUT = 60


def _embed(text: str):
    try:
        resp = requests.post(
            f"{OLLAMA_URL}/api/embeddings",
            json={"model": EMBED_MODEL, "prompt": text[:8000]},
            timeout=_TIMEOUT,
        )
        if resp.status_code != 200:
            return None
        return resp.json().get("embedding")
    except requests.exceptions.RequestException:
        return None


def embed_document(text: str):
    return _embed(f"search_document: {text}")


def embed_query(text: str):
    return _embed(f"search_query: {text}")
