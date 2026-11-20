"""``work/state.json``: what the tool created on the server.

Per resource: local id, server id, sha256 of the resource sent, the furthest
space reached and, for an integration set aside, the engine's message. Per
sensitive operation (``--include-foreign-changes``,
``--accept-unclassified-indexing``, ``activate --force``): who and when.
Never credentials.
"""

import datetime
import getpass
import os

from ..jsonio import canonical_sha256, read_json, write_json

SPACES = ("draft", "test", "custom")


def now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def who():
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - no login name in some containers
        return "unknown"


def paths(workdir):
    return {
        "state": os.path.join(workdir, "work", "state.json"),
        "mapping_applied": os.path.join(workdir, "work", "mapping-applied.csv"),
        "out": os.path.join(workdir, "out"),
        "report_json": os.path.join(workdir, "report.json"),
        "report_md": os.path.join(workdir, "report.md"),
        "verification_json": os.path.join(workdir, "verification.json"),
        "verification_md": os.path.join(workdir, "verification.md"),
        "verification_offline_json": os.path.join(workdir, "verification-offline.json"),
        "verification_offline_md": os.path.join(workdir, "verification-offline.md"),
        "plan": os.path.join(workdir, "work", "plan.json"),
        "decisions": os.path.join(workdir, "decisions.json"),
    }


class State:
    def __init__(self, path, data=None):
        self.path = path
        self.data = data or {"version": 1, "resources": {}, "root_decoder": None, "operations": [],
                             "set_aside": {}, "detectors": {}, "last_apply": None, "last_activate": None}

    @classmethod
    def load(cls, workdir):
        p = paths(workdir)["state"]
        if os.path.isfile(p):
            data = read_json(p)
            for k, v in (("resources", {}), ("operations", []), ("set_aside", {}), ("detectors", {})):
                data.setdefault(k, v)
            data.setdefault("root_decoder", None)
            return cls(p, data)
        return cls(p)

    def save(self):
        write_json(self.path, self.data)

    @property
    def resources(self):
        return self.data["resources"]

    def get(self, local_id):
        return self.resources.get(local_id)

    def by_server_id(self):
        return {e["server_id"]: lid for lid, e in self.resources.items() if e.get("server_id")}

    def record(self, res, server_id, space=None):
        e = self.resources.setdefault(res.local_id, {})
        e.update({"type": res.rtype, "integration": res.integration, "title": res.title,
                  "server_id": server_id, "sha256": res.sha256})
        if space:
            e["space"] = space
        e.setdefault("space", "draft")
        return e

    def forget(self, local_id):
        """Drop a resource the tool removed. Its local id is kept in ``retired``: the copy of an activated
        resource stays in custom, with the tool's mark, until activate or rollback --yes promotes the removal, and the
        tool must still recognise it as its own then."""
        if self.resources.pop(local_id, None) is not None:
            retired = self.data.setdefault("retired", [])
            if local_id not in retired:
                retired.append(local_id)
                retired.sort()

    @property
    def retired(self):
        return self.data.get("retired") or []

    def set_space(self, local_id, space):
        e = self.resources.get(local_id)
        if e and SPACES.index(space) > SPACES.index(e.get("space", "draft")):
            e["space"] = space

    def operation(self, op, command, detail=None):
        entry = {"op": op, "command": command, "who": who(), "when": now()}
        if detail:
            entry["detail"] = detail
        self.data["operations"].append(entry)
        return entry

    def fingerprint(self):
        """Hash of what is applied (local id, server id, sha256): a
        verification is valid for activate only while this does not change."""
        return canonical_sha256(sorted([lid, e.get("server_id"), e.get("sha256")]
                                       for lid, e in self.resources.items()
                                       if lid not in self._set_aside_ids()))

    def _set_aside_ids(self):
        out = set()
        for key in self.data.get("set_aside", {}):
            out.update(lid for lid, e in self.resources.items() if e.get("integration") == key)
        return out

    def integration_ids(self, key):
        return {lid: e for lid, e in self.resources.items() if e.get("integration") == key}
