"""
Persists Wazuh Copilot chat sessions to local, gzip-compressed files so
conversation history survives a backend restart. Keeps only the 6 most
recent chats — see utils/compressed_history.py for the underlying mechanism.

Layout:
    backend/sessions/manifest.json      - {chat_id: {title, started_at, updated_at}}
    backend/sessions/<chat_id>.json.gz  - gzip-compressed JSON turn list
"""
import os

from utils.compressed_history import CompressedHistoryStore

MAX_SESSIONS = 6

_SESSIONS_DIR = os.path.join(os.path.dirname(__file__), "..", "sessions")
_store = CompressedHistoryStore(_SESSIONS_DIR, max_items=MAX_SESSIONS)


def _derive_title(turns):
    for t in turns:
        if t.get("role") == "user" and t.get("text"):
            text = t["text"].strip().replace("\n", " ")
            return text[:60] + ("..." if len(text) > 60 else "")
    return "New conversation"


def save_session(chat_id, turns, brain=None):
    _store.save(chat_id, turns, title=_derive_title(turns), extra_meta={"brain": brain} if brain else None)


def load_session(chat_id):
    return _store.load(chat_id)


def list_sessions():
    return [{"chat_id": e["id"], **{k: v for k, v in e.items() if k != "id"}} for e in _store.list()]


def delete_session(chat_id):
    _store.delete(chat_id)


def rename_session(chat_id, new_title):
    return _store.rename(chat_id, new_title)
