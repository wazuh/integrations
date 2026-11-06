"""
Download-only history for the Troubleshooting Library's guided wizard flows.
Unlike session_store.py (Wazuh Copilot chat), these are never resumed/continued
- only saved once a flow reaches a resolution (done: true) and made available
to download/review. Same compressed-storage mechanism, capped at 6, oldest
evicted automatically. See utils/compressed_history.py.

Layout:
    backend/wizard_history/manifest.json    - {run_id: {title, started_at, updated_at}}
    backend/wizard_history/<run_id>.json.gz - gzip-compressed JSON transcript
"""
import os

from utils.compressed_history import CompressedHistoryStore

MAX_RUNS = 6

_WIZARD_DIR = os.path.join(os.path.dirname(__file__), "..", "wizard_history")
_store = CompressedHistoryStore(_WIZARD_DIR, max_items=MAX_RUNS)


def _derive_title(transcript):
    if transcript and transcript[0].get("user"):
        text = transcript[0]["user"].strip().replace("\n", " ")
        return text[:60] + ("..." if len(text) > 60 else "")
    return "Troubleshooting session"


def save_run(run_id, transcript):
    _store.save(run_id, transcript, title=_derive_title(transcript))


def load_run(run_id):
    return _store.load(run_id)


def list_runs():
    return [{"run_id": e["id"], **{k: v for k, v in e.items() if k != "id"}} for e in _store.list()]


def format_transcript_text(transcript, title):
    """Plain-text rendering for download - readable outside the app."""
    lines = [f"Wazuh Troubleshooting Library — {title}", "=" * 60, ""]
    for step in transcript:
        if step.get("user"):
            lines.append(f"> {step['user']}")
        if step.get("assistant"):
            lines.append(step["assistant"])
        lines.append("")
    return "\n".join(lines)
