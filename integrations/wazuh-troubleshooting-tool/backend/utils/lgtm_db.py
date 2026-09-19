"""
SQLite-backed store for the unified Wazuh knowledge base, with embeddings for
semantic search. Covers three sources, all searched together as one pool:
  - wazuh/community issues labeled LGTM or review/quality
  - wazuh/community Discussions (isAnswered)
  - wazuh/wazuh (public repo) closed issues

Replaces the old lgtm_issues.json + fuzzy-string-matching approach - fuzzy
matching only catches questions textually similar to a stored issue; cosine
similarity over embeddings also catches semantically similar questions worded
completely differently.

Embeddings are computed once per item at sync time (not per query), so the
per-query cost is just one embedding call for the user's question plus an
in-memory cosine-similarity scan - fast even on CPU (a few thousand items'
worth of 768-dim float32 vectors is a few MB, trivial to hold in memory).

Primary key is "source:number" (not just number) since community issues,
community discussions, and public wazuh/wazuh issues each have their own
independent numbering and would otherwise collide.
"""
import json
import os
import sqlite3
import struct

import numpy as np

from utils.embeddings import embed_document, embed_query

_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "knowledge", "lgtm.db")


def _connect():
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(_DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS issues (
            id TEXT PRIMARY KEY,
            source TEXT,
            number INTEGER,
            title TEXT,
            body TEXT,
            comments TEXT,
            external_community TEXT,
            url TEXT,
            labels TEXT,
            embedding BLOB
        )
    """)
    return conn


def _to_blob(vector):
    return struct.pack(f"{len(vector)}f", *vector)


def _from_blob(blob):
    n = len(blob) // 4
    return np.array(struct.unpack(f"{n}f", blob), dtype=np.float32)


def _embedding_text(issue):
    return (
        issue["title"] + "\n"
        + issue["body"][:1000] + "\n"
        + "\n".join(issue.get("comments", []))[:2000]
    )


def upsert_issue(issue: dict, source: str = "community_issue") -> bool:
    """issue: {number, title, body, comments, external_community, url, labels}.
    source: "community_issue" | "community_discussion" | "public_wazuh_issue".
    Returns False (and doesn't write) if the embedding call fails, so a
    flaky Ollama request during sync doesn't corrupt the DB with a null vector."""
    embedding = embed_document(_embedding_text(issue))
    if embedding is None:
        return False

    item_id = f"{source}:{issue['number']}"
    conn = _connect()
    conn.execute(
        """INSERT INTO issues (id, source, number, title, body, comments, external_community, url, labels, embedding)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET
               title=excluded.title, body=excluded.body, comments=excluded.comments,
               external_community=excluded.external_community, url=excluded.url,
               labels=excluded.labels, embedding=excluded.embedding""",
        (
            item_id, source, issue["number"], issue["title"], issue["body"],
            json.dumps(issue.get("comments", [])),
            json.dumps(issue.get("external_community", [])),
            issue.get("url", ""), json.dumps(issue.get("labels", [])),
            _to_blob(embedding),
        ),
    )
    conn.commit()
    conn.close()
    return True


def _row_to_issue(row):
    return {
        "source": row[0], "number": row[1], "title": row[2], "body": row[3],
        "comments": json.loads(row[4]), "external_community": json.loads(row[5]),
        "url": row[6], "labels": json.loads(row[7]),
    }


def count(source: str = None) -> int:
    if not os.path.exists(_DB_PATH):
        return 0
    conn = _connect()
    if source:
        n = conn.execute("SELECT COUNT(*) FROM issues WHERE source=?", (source,)).fetchone()[0]
    else:
        n = conn.execute("SELECT COUNT(*) FROM issues").fetchone()[0]
    conn.close()
    return n


def search(query: str, top_n: int = 3, min_similarity: float = 0.5) -> list:
    if not query or not os.path.exists(_DB_PATH):
        return []

    query_embedding = embed_query(query)
    if query_embedding is None:
        return []

    q = np.array(query_embedding, dtype=np.float32)
    q = q / (np.linalg.norm(q) or 1)

    conn = _connect()
    rows = conn.execute(
        "SELECT source, number, title, body, comments, external_community, url, labels, embedding FROM issues"
    ).fetchall()
    conn.close()

    scored = []
    for row in rows:
        emb = _from_blob(row[8])
        emb = emb / (np.linalg.norm(emb) or 1)
        similarity = float(np.dot(q, emb))
        if similarity >= min_similarity:
            scored.append((similarity, _row_to_issue(row[:8])))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [issue for _, issue in scored[:top_n]]
