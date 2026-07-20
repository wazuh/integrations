"""
Generic gzip-compressed rolling history store. Backs both the Wazuh Copilot
chat history (session_store.py) and the Troubleshooting Library's completed-run
downloads (wizard_history.py) — same mechanism, different directory.

Keeps only the N most recently *created* entries: the moment a new one is
saved past the cap, the oldest-created entry is deleted (file + manifest).
"""
import gzip
import json
import os
from datetime import datetime, timezone


class CompressedHistoryStore:
    def __init__(self, directory, max_items=6):
        self.dir = directory
        self.manifest_path = os.path.join(directory, "manifest.json")
        self.max_items = max_items

    def _ensure_dir(self):
        os.makedirs(self.dir, exist_ok=True)

    def _file_path(self, item_id):
        return os.path.join(self.dir, f"{item_id}.json.gz")

    def _load_manifest(self):
        self._ensure_dir()
        if not os.path.exists(self.manifest_path):
            return {}
        try:
            with open(self.manifest_path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    def _save_manifest(self, manifest):
        self._ensure_dir()
        with open(self.manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)

    def save(self, item_id, data, title=None, extra_meta=None):
        """Overwrite the compressed payload for item_id and update the
        manifest. If item_id is brand new and pushes the total past
        max_items, the oldest-created entry is deleted."""
        self._ensure_dir()
        manifest = self._load_manifest()
        is_new = item_id not in manifest

        payload = json.dumps(data).encode("utf-8")
        with gzip.open(self._file_path(item_id), "wb") as f:
            f.write(payload)

        now = datetime.now(timezone.utc).isoformat()
        if is_new:
            manifest[item_id] = {
                "title": title or "Untitled",
                "started_at": now,
                "updated_at": now,
                **(extra_meta or {}),
            }
        else:
            manifest[item_id]["updated_at"] = now
            if title:
                manifest[item_id]["title"] = title
            if extra_meta:
                manifest[item_id].update(extra_meta)

        if is_new and len(manifest) > self.max_items:
            oldest_id = min(manifest, key=lambda k: manifest[k]["started_at"])
            if oldest_id != item_id:
                self.delete(oldest_id, manifest=manifest, persist=False)

        self._save_manifest(manifest)

    def load(self, item_id):
        path = self._file_path(item_id)
        if not os.path.exists(path):
            return None
        try:
            with gzip.open(path, "rb") as f:
                return json.loads(f.read().decode("utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def list(self):
        """Manifest entries, newest-updated first."""
        manifest = self._load_manifest()
        return sorted(
            [{"id": iid, **meta} for iid, meta in manifest.items()],
            key=lambda e: e["updated_at"],
            reverse=True,
        )

    def delete(self, item_id, manifest=None, persist=True):
        own_manifest = manifest is None
        if own_manifest:
            manifest = self._load_manifest()
        manifest.pop(item_id, None)
        path = self._file_path(item_id)
        if os.path.exists(path):
            os.remove(path)
        if own_manifest and persist:
            self._save_manifest(manifest)

    def rename(self, item_id, new_title):
        manifest = self._load_manifest()
        if item_id not in manifest:
            return False
        manifest[item_id]["title"] = new_title[:100]
        self._save_manifest(manifest)
        return True
