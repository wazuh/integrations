"""Read ``out/`` as fixed by the contract between ``build`` and ``apply``."""

import csv
import os

from ..fsutil import listdir_sorted
from ..jsonio import canonical_sha256, read_json

MARKER_AUTHOR = "wazuh-ruleset-migration"
REF_PREFIX = "wazuh4-migration:"
BASE_KEY = "wazuh4-base"


class OutError(Exception):
    pass


class Resource:
    """One kvdb, decoder or rule of ``out/`` (or the integration itself)."""

    __slots__ = ("rtype", "integration", "local_id", "resource", "source", "fidelity", "reasons", "file", "sha256")

    def __init__(self, rtype, integration, data, path):
        self.rtype = rtype
        self.integration = integration
        self.local_id = data.get("local_id")
        self.resource = data.get("resource")
        self.source = data.get("source") or {}
        self.fidelity = data.get("fidelity")
        self.reasons = data.get("reasons") or []
        self.file = path
        if not self.local_id or not isinstance(self.resource, dict):
            raise OutError("%s: local_id and resource are required" % path)
        self.sha256 = canonical_sha256(self.resource)

    @property
    def title(self):
        """The name the space keeps unique: ``name`` for decoders,
        ``metadata.title`` for the rest."""
        if self.rtype == "decoder":
            return self.resource.get("name")
        return (self.resource.get("metadata") or {}).get("title")


class Integration:
    def __init__(self, key, path):
        self.key = key
        self.path = path
        data = read_json(os.path.join(path, "integration.json"))
        self.kind = data.get("kind")
        self.stock_integration = data.get("stock_integration")
        self.me = Resource("integration", key, data, os.path.join(path, "integration.json"))
        self.kvdbs = self._load("kvdbs", "kvdb")
        self.decoders = self._load("decoders", "decoder")
        self.rules = self._load("rules", "rule")

    def _load(self, sub, rtype):
        d = os.path.join(self.path, sub)
        return [Resource(rtype, self.key, read_json(os.path.join(d, n)), os.path.join(d, n))
                for n in listdir_sorted(d) if n.endswith(".json")]

    @property
    def title(self):
        return self.me.title

    @property
    def category(self):
        return self.me.resource.get("category")

    def children(self):
        return self.kvdbs + self.decoders + self.rules

    def all(self):
        return [self.me] + self.children()


class Out:
    def __init__(self, path):
        self.path = path
        mpath = os.path.join(path, "manifest.json")
        if not os.path.isfile(mpath):
            raise OutError("no manifest.json in %s: run build first" % path)
        self.manifest = read_json(mpath)
        if self.manifest.get("format") != 1:
            raise OutError("%s: unsupported format %r" % (mpath, self.manifest.get("format")))
        self.root = self.manifest.get("root_decoder")
        self.shared_root = None  # set by shared_root.share: out/ read under a root decoder the tool did not set
        self.integrations = []
        for key in self.manifest.get("integrations") or []:
            ipath = os.path.join(path, "integrations", key)
            if not os.path.isfile(os.path.join(ipath, "integration.json")):
                raise OutError("manifest lists %s but %s/integration.json is missing" % (key, ipath))
            self.integrations.append(Integration(key, ipath))
        self.by_local = {}
        for integ in self.integrations:
            for r in integ.all():
                if r.local_id in self.by_local:
                    raise OutError("local_id %s appears twice (%s, %s)" % (r.local_id, self.by_local[r.local_id].file, r.file))
                self.by_local[r.local_id] = r
        if self.root and self.root.get("local_id") not in self.by_local:
            raise OutError("manifest root_decoder %s is not a decoder of out/" % self.root.get("local_id"))
        self.detectors = [read_json(os.path.join(path, "detectors", n))
                          for n in listdir_sorted(os.path.join(path, "detectors")) if n.endswith(".json")]

    def integration(self, key):
        for i in self.integrations:
            if i.key == key:
                return i
        return None

    def mapping_rows(self):
        """Rows of ``mapping.csv`` (field order kept), or of ``mapping.json``."""
        cpath = os.path.join(self.path, "mapping.csv")
        if os.path.isfile(cpath):
            with open(cpath, "r", encoding="utf-8", newline="") as fh:
                reader = csv.DictReader(fh)
                return list(reader.fieldnames or []), [dict(r) for r in reader]
        jpath = os.path.join(self.path, "mapping.json")
        if os.path.isfile(jpath):
            data = read_json(jpath)
            rows = data.get("rows", data.get("rules", [])) if isinstance(data, dict) else data
            fields = ["rule_id_4x", "state", "reasons", "integration", "resource_title", "local_id", "server_id"]
            return fields, [dict(r) for r in rows]
        return [], []


def marker_uuid(document):
    """The local id a server document carries as its ownership mark,
    or None. Both parts are required: the author and the reference."""
    meta = (document or {}).get("metadata") or {}
    if meta.get("author") != MARKER_AUTHOR:
        return None
    for ref in meta.get("references") or []:
        if isinstance(ref, str) and ref.startswith(REF_PREFIX):
            return ref[len(REF_PREFIX):]
    return None


def doc_title(rtype, document):
    if rtype == "decoder":
        return (document or {}).get("name")
    return ((document or {}).get("metadata") or {}).get("title")
