"""
Reads the locally-synced LGTM/review-quality knowledge base (backend/knowledge/lgtm.db,
a SQLite DB with per-issue embeddings) and semantically matches it against a
user's question via cosine similarity. Needs Ollama running locally with
nomic-embed-text pulled. No GitHub credentials — the DB must already exist,
produced by backend/knowledge/sync_lgtm_issues.py.
"""
from utils import lgtm_db


def find_relevant_issues(query: str, top_n: int = 3, min_similarity: float = 0.5) -> list:
    """Return up to top_n issues whose content is semantically closest to the query."""
    return lgtm_db.search(query, top_n=top_n, min_similarity=min_similarity)


def format_lgtm_context(issues: list) -> str:
    if not issues:
        return ""
    parts = ["=== Internal knowledge base: previously resolved, verified Wazuh issues ==="]
    for issue in issues:
        resolution_bits = issue.get("comments", []) + issue.get("external_community", [])
        # 2000 chars, not 1200 - some threads have a first-draft answer followed
        # by a reviewer's correction, and the correction matters more than the
        # original; truncating too early risks cutting off exactly that part.
        resolution = "\n---\n".join(resolution_bits)[:2000]
        parts.append(
            f"- Issue #{issue['number']}: {issue['title']}\n"
            f"  Question: {issue['body'][:500]}\n"
            f"  Discussion (in order - later comments may correct or refine earlier ones,\n"
            f"  e.g. a reviewer pointing out what the first answer got wrong or missed):\n"
            f"  {resolution}"
        )
    parts.append(
        "Instructions: use the above to ground your answer. When a discussion thread contains "
        "a correction or refinement to an earlier answer, follow the corrected version, not the "
        "original. Do not quote this verbatim or mention it is from an internal issue tracker — "
        "this content is confidential and for grounding only."
    )
    parts.append("=================================================")
    return "\n".join(parts)
