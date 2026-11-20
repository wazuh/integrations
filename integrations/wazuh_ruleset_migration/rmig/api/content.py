"""Content manager reads, ownership and the policy check.

The plugin has no GET per resource and no listing: documents are read from the
``wazuh-threatintel-*`` indices with ``_search`` by ``space.name``
(``wazuh-indexer-plugins@5.0.0:plugins/content-manager/.../utils/Constants.java:602-609``).
"""

from .outdir import marker_uuid

BASE = "/_plugins/_content_manager"
RTYPES = ("integration", "kvdb", "decoder", "rule")
INDEX = {
    "integration": "wazuh-threatintel-integrations",
    "kvdb": "wazuh-threatintel-kvdbs",
    "decoder": "wazuh-threatintel-decoders",
    "rule": "wazuh-threatintel-rules",
    "policy": "wazuh-threatintel-policies",
}
PATH = {
    "integration": BASE + "/integrations",
    "kvdb": BASE + "/kvdbs",
    "decoder": BASE + "/decoders",
    "rule": BASE + "/rules",
}
CHANGE_KEY = {"integration": "integrations", "kvdb": "kvdbs", "decoder": "decoders", "rule": "rules"}
CHANGE_LISTS = ("policy", "integrations", "kvdbs", "decoders", "filters", "rules")
KEY_TYPE = {v: k for k, v in CHANGE_KEY.items()}
NEXT_SPACE = {"draft": "test", "test": "custom"}
SEARCH_SIZE = 10000
# Server-set timestamps: a PUT of the policy refreshes them, so they are not a
# foreign change.
POLICY_VOLATILE_META = ("date", "modified")


def search_space(client, rtype, space):
    """``[(server id, document)]`` of a type in a space."""
    body = {"size": SEARCH_SIZE, "query": {"term": {"space.name": {"value": space}}}}
    res = client.request("POST", "/%s/_search" % INDEX[rtype], body)
    out = []
    for hit in (res.get("hits") or {}).get("hits") or []:
        src = hit.get("_source") or {}
        doc = src.get("document") or {}
        out.append((doc.get("id") or hit.get("_id"), doc))
    out.sort(key=lambda p: str(p[0]))
    return out


def refresh(client):
    for rtype in RTYPES + ("policy",):
        client.request("POST", "/%s/_refresh" % INDEX[rtype])


def read_policy(client, space):
    found = search_space(client, "policy", space)
    return found[0][1] if found else None


def empty_changes():
    return {k: [] for k in CHANGE_LISTS}


class Snapshot:
    """Documents of draft/test/custom and the four policies, read once."""

    def __init__(self, client, spaces=("draft", "test", "custom")):
        refresh(client)
        self.docs = {}
        for space in spaces:
            self.docs[space] = {rtype: dict(search_space(client, rtype, space)) for rtype in RTYPES}
        self.policy = {space: read_policy(client, space) for space in spaces}

    def get(self, space, rtype, server_id):
        return self.docs.get(space, {}).get(rtype, {}).get(server_id)

    def find_type(self, server_id):
        for space in self.docs:
            for rtype in RTYPES:
                if server_id in self.docs[space][rtype]:
                    return rtype
        return None


class Ownership:
    """Which server ids are the tool's: in ``state.json``, or carrying the mark
    with a local id the tool knows (``out/`` or the state). A marked document
    whose local id is unknown is reported and never touched."""

    def __init__(self, snapshot, state, known_local_ids):
        self.snap = snapshot
        self.state = state
        self.known = set(known_local_ids)
        # local ids the tool removed: only their copies in custom, which activate still has to retire
        self.retired = set(getattr(state, "retired", [])) - self.known
        self.owned = {}          # server id -> local id
        self.unknown_marked = []  # (space, rtype, server id, title)
        self.other_tool = {}      # server id -> local id of its mark, for marked documents this workdir does not know
        for lid, e in state.resources.items():
            if e.get("server_id"):
                self.owned[e["server_id"]] = lid
        for space, types in snapshot.docs.items():
            for rtype, docs in types.items():
                for sid, doc in docs.items():
                    mark = marker_uuid(doc)
                    if mark is None:
                        continue
                    if mark in self.known or (space == "custom" and mark in self.retired):
                        self.owned.setdefault(sid, mark)
                    elif sid not in self.owned:
                        self.unknown_marked.append((space, rtype, sid))
                        self.other_tool[sid] = mark
        for sid in self.owned:
            self.other_tool.pop(sid, None)

    def is_own(self, server_id):
        return server_id in self.owned

    def is_other_tool(self, server_id):
        """Carries the tool's mark with a local id this workdir does not know: content of another rmig workdir
        (or of an older build). Never removed, never adopted."""
        return server_id in self.other_tool

    def in_space(self, space, local_id):
        """Server id of a local id in a space (state first, then the mark)."""
        e = self.state.get(local_id)
        for rtype, docs in self.snap.docs.get(space, {}).items():
            if e and e.get("server_id") in docs:
                return e["server_id"]
        for rtype, docs in self.snap.docs.get(space, {}).items():
            for sid, doc in docs.items():
                if marker_uuid(doc) == local_id:
                    return sid
        return None


def foreign_changes(changes, own, other_tool_ok=False):
    """Entries of a ``GET /promote`` answer whose id is not the tool's
    (the policy is checked apart). ``other_tool_ok``: content of another
    rmig workdir is not foreign (see ``other_tool_changes``)."""
    out = []
    for key in CHANGE_LISTS:
        if key == "policy":
            continue
        for op in changes.get(key) or []:
            sid = op.get("id")
            if not own.is_own(sid) and not (other_tool_ok and own.is_other_tool(sid)):
                out.append({"type": key, "operation": op.get("operation"), "id": sid})
    return out


def other_tool_changes(changes, own):
    """Entries of a ``GET /promote`` answer that are content of another rmig workdir."""
    out = []
    for key in CHANGE_LISTS:
        if key == "policy":
            continue
        for op in changes.get(key) or []:
            if own.is_other_tool(op.get("id")):
                out.append({"type": key, "operation": op.get("operation"), "id": op.get("id")})
    return out


def policy_differences(source, target, own, own_root=None, other_tool_ok=False):
    """Field-by-field differences between the policy that would be promoted
    (``source``) and the one in the destination (``target``) that the tool did
    not make: integration ids other than its own, a ``root_decoder`` it did
    not set, and any other field. Returns a list of strings (empty = only the
    tool's changes). ``other_tool_ok``: integrations and a root decoder of
    another rmig workdir are not someone else's either."""
    if source is None or target is None:
        return []
    other = (lambda x: own.is_other_tool(x)) if other_tool_ok else (lambda x: False)
    diffs = []
    keys = sorted(set(source) | set(target))
    for k in keys:
        if k in ("id",):
            continue
        a, b = source.get(k), target.get(k)
        if k == "integrations":
            a, b = list(a or []), list(b or [])
            extra = [i for i in set(a) ^ set(b) if not own.is_own(i) and not other(i)]
            if extra:
                diffs.append("integrations: %s added or removed by someone else" % ", ".join(sorted(extra)))
            fa = [i for i in a if not own.is_own(i) and not other(i)]
            fb = [i for i in b if not own.is_own(i) and not other(i)]
            if not extra and fa != fb:
                diffs.append("integrations: the order of integrations not owned by the tool changed")
        elif k == "root_decoder":
            if (a or None) != (b or None):
                if all(not x or x == own_root or other(x) for x in (a, b)) and (other(a) or other(b)):
                    continue  # between the tool's roots (this workdir's or another's) or none
                ours = own_root is not None and a == own_root
                if not ours or (b and b != own_root):
                    diffs.append("root_decoder: %r -> %r" % (b, a))
        elif k == "metadata":
            ma = {x: y for x, y in (a or {}).items() if x not in POLICY_VOLATILE_META}
            mb = {x: y for x, y in (b or {}).items() if x not in POLICY_VOLATILE_META}
            for mk in sorted(set(ma) | set(mb)):
                if ma.get(mk) != mb.get(mk):
                    diffs.append("metadata.%s: %r -> %r" % (mk, mb.get(mk), ma.get(mk)))
        elif a != b:
            diffs.append("%s: %r -> %r" % (k, b, a))
    return diffs


def policy_put_body(current, root_decoder):
    """``PUT /policy/draft`` body: read-modify-write, only ``root_decoder``
    changes. Every other field of the stored
    document is sent back as read, without ``id`` (checked against a live indexer)."""
    resource = {k: v for k, v in current.items() if k != "id"}
    resource["root_decoder"] = root_decoder
    return {"resource": resource}
