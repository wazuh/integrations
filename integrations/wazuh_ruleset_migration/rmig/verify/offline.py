"""``verify --engine-socket``: the policies loaded into a running 5.x engine, with no indexer.

Two tester sessions, as the indexer's two logtest paths:

* ``rmig_verify`` (the indexer's ``test`` space): ``out/`` as one policy. Its integrations (``wazuh4-base`` and the
  custom ones; ``on-stock`` integrations hold rules only), their decoders and KVDBs, under the tool's root decoder.
  When ``work/state.json`` records a shared root (``apply`` hung the decoders from the standard root), the root is
  the standard one, taken from ``--catalog`` with the integrations its decoders need;
* ``rmig_verify_std`` (the indexer's ``standard`` space): the whole policy of the 5.x catalog snapshot given with
  ``--catalog``, for the rules over stock events. Disabled stock integrations stay disabled, as on the indexer.

Document shapes. Catalog documents are sent as the snapshot holds them (``payload.document``). ``out/`` resources
get the keys the indexer adds when it stores them, and nothing else: ``id`` (the tool's local id), and on an
integration ``decoders``, ``kvdbs``, ``rules`` (empty: rules are not engine content) and ``mode: user-managed``
(as in the integration documents the indexer returns). The tool's policy document has the fields of the indexer's
own draft policy document.
"""

import os
import re

from ..fsutil import listdir_sorted
from ..jsonio import read_json
from ..api.shared_root import STOCK_ROOT
from ..translate import helpers as H

TOOL_SPACE = "rmig_verify"
STOCK_SPACE = "rmig_verify_std"
TOOL_POLICY_ID = "6d4b7a52-7f0e-5c4e-9b51-726d69677631"  # fixed: the tool's policy is rebuilt on every run
IOC_FIELD = "wazuh.threat.enrichments.indicator.type"
# "Error building decoder decoder/syslog/0 from integration 'wazuh-core': ..." (recorded: validate-load-unmigrated)
_BUILD_ERR = re.compile(r"from integration '([^']*)'")
ENRICHMENTS = "wazuh.threat.enrichments."


_MISSING_BUILDER = re.compile(r"Operation builder '([A-Za-z0-9_]+)' not found")


def helper_hint(error):
    """A clear line when the engine refused a policy for a helper name of the other dialect, or None.

    The engine API has no version call (``GET /status`` carries no version), so the release is read from the
    refusal: a 5.0.0 name unknown to the engine (``Operation builder 'in_cidr' not found``, seen on 5.0.0 rc2) means
    an engine older than the renames of wazuh/wazuh#41150; an rc1 name unknown to it (``kvdb_get``, recorded on a
    5.0.0 nightly) means an engine that has them."""
    m = _MISSING_BUILDER.search(error or "")
    if not m:
        return None
    name = m.group(1)
    table = dict(H.renames())
    table[H.CIDR_OLD] = H.CIDR_NEW
    if name in table.values():
        return ("the engine does not know the 5.0.0 helper %s: it is older than 5.0.0 (rc1 or rc2 helper names). "
                "Rebuild with `build --engine-helpers %s`, and use a catalog of the same release as the engine"
                % (name, H.RC1))
    if name in table:
        return ("the engine does not know the rc1 helper %s: it uses the 5.0.0 helper names. Rebuild with "
                "`build --engine-helpers %s`, and use a catalog of the same release as the engine" % (name, H.CURRENT))
    return None


class CatalogError(Exception):
    pass


def _document(env):
    if isinstance(env, dict) and isinstance(env.get("payload"), dict) and "document" in env["payload"]:
        return env["payload"]["document"]
    return env


class Catalog:
    """A 5.x catalog snapshot directory: ``policies/``, ``integrations/``, ``decoders/``, ``kvdbs/``, one JSON per
    asset (``payload.document``), ``manifest.json`` (the layout of a CTI catalog snapshot)."""

    def __init__(self, path):
        self.path = path
        if not os.path.isdir(os.path.join(path, "decoders")):
            raise CatalogError("%s is not a 5.x catalog snapshot (no decoders/)" % path)
        try:
            self.policies = self._read("policies")
            self.integrations = self._read("integrations")
            self.decoders = self._read("decoders")
            self.kvdbs = self._read("kvdbs")
            mpath = os.path.join(path, "manifest.json")
            self.manifest = read_json(mpath) if os.path.isfile(mpath) else {}
        except (OSError, ValueError) as exc:
            raise CatalogError("%s: %s" % (path, exc))
        if len(self.policies) != 1:
            raise CatalogError("%s: expected one policy in policies/, found %d" % (path, len(self.policies)))
        self.policy = next(iter(self.policies.values()))
        self.by_name = {d.get("name"): u for u, d in self.decoders.items()}

    def _read(self, sub):
        d = os.path.join(self.path, sub)
        out = {}
        for n in listdir_sorted(d):
            if n.endswith(".json"):
                doc = _document(read_json(os.path.join(d, n)))
                out[doc.get("id") or n[:-5]] = doc
        return out

    def label(self):
        m = self.manifest
        if m.get("context") and m.get("offset") is not None:
            return "%s offset %s" % (m["context"], m["offset"])
        return os.path.basename(os.path.normpath(self.path))

    def integration_of(self, decoder_id):
        for iid in self.policy.get("integrations") or []:
            if decoder_id in (self.integrations.get(iid) or {}).get("decoders") or []:
                return iid
        return None

    def closure(self, integration_ids):
        """The integrations plus those holding a parent of one of their decoders, in policy order."""
        chosen = set(integration_ids)
        changed = True
        while changed:
            changed = False
            for iid in sorted(chosen):
                for did in (self.integrations.get(iid) or {}).get("decoders") or []:
                    for parent in (self.decoders.get(did) or {}).get("parents") or []:
                        pid = self.integration_of(self.by_name.get(parent))
                        if pid and pid not in chosen:
                            chosen.add(pid)
                            changed = True
        return [i for i in self.policy.get("integrations") or [] if i in chosen]

    def resources(self, integration_ids):
        """``(integrations, decoders, kvdbs)`` documents of the given integrations."""
        ints, decs, kvs, missing = [], [], [], []
        for iid in integration_ids:
            doc = self.integrations.get(iid)
            if doc is None:
                missing.append(iid)
                continue
            ints.append(doc)
            for did in doc.get("decoders") or []:
                if did not in self.decoders:
                    missing.append(did)
                elif self.decoders[did] not in decs:
                    decs.append(self.decoders[did])
            for kid in doc.get("kvdbs") or []:
                if kid not in self.kvdbs:
                    missing.append(kid)
                elif self.kvdbs[kid] not in kvs:
                    kvs.append(self.kvdbs[kid])
        if missing:
            raise CatalogError("the catalog lacks %d referenced asset(s): %s" % (len(missing), ", ".join(missing[:5])))
        return ints, decs, kvs

    def full_policy(self):
        pol = dict(self.policy)
        if pol.get("filters"):
            raise CatalogError("the catalog policy lists filters %s but the snapshot has no filter documents"
                               % pol["filters"])
        pol.pop("outputs", None)  # outputs would write every logtest event
        ints, decs, kvs = self.resources(pol.get("integrations") or [])
        return {"policy": pol, "resources": {"decoders": decs, "integrations": ints, "kvdbs": kvs,
                                             "filters": [], "outputs": []}}


def _with_id(resource, local_id, **extra):
    doc = dict(resource)
    doc["id"] = local_id
    for k, v in extra.items():
        doc.setdefault(k, v)
    return doc


def tool_policy(out, catalog=None):
    """``(full_policy, {integration key: why it is left out})`` for ``out/`` (an ``outdir.Out``, already shared when
    the state records a shared root). Raises :class:`CatalogError` when the shared root needs ``--catalog``."""
    integs = [i for i in out.integrations if i.kind != "on-stock" and (i.decoders or i.kvdbs)]
    extra_ints, extra_decs, extra_kvs = [], [], []
    if out.root:
        root_id = out.root["local_id"]
    else:
        if out.shared_root is None:
            raise CatalogError("out/ has no root decoder")
        if catalog is None:
            raise CatalogError("out/ hangs from the standard root decoder %s (work/state.json, shared root): pass "
                               "--catalog with the 5.x catalog snapshot that holds it" % out.shared_root["name"])
        root_id = catalog.by_name.get(STOCK_ROOT)
        if root_id is None or catalog.integration_of(root_id) is None:
            raise CatalogError("the catalog has no %s in an integration of its policy" % STOCK_ROOT)
        extra_ints, extra_decs, extra_kvs = catalog.resources(catalog.closure([catalog.integration_of(root_id)]))
    names = {d.get("name") for d in extra_decs}
    for i in integs:
        names.update(d.resource.get("name") for d in i.decoders)
    left_out = {}
    for i in integs:
        dangling = sorted({p for d in i.decoders for p in d.resource.get("parents") or [] if p not in names})
        if dangling:
            left_out[i.key] = "parent decoder(s) %s are in neither out/ nor the loaded catalog" % ", ".join(dangling)
    kept = [i for i in integs if i.key not in left_out]
    ints = list(extra_ints) + [
        _with_id(i.me.resource, i.me.local_id, decoders=[d.local_id for d in i.decoders],
                 kvdbs=[k.local_id for k in i.kvdbs], rules=[], mode="user-managed") for i in kept]
    decs = list(extra_decs) + [_with_id(d.resource, d.local_id) for i in kept for d in i.decoders]
    kvs = list(extra_kvs) + [_with_id(k.resource, k.local_id) for i in kept for k in i.kvdbs]
    policy = {"enabled": True, "enrichments": [], "filters": [], "id": TOOL_POLICY_ID,
              "index_discarded_events": False, "index_unclassified_events": False,
              "integrations": [d["id"] for d in ints],
              "metadata": {"author": "wazuh-ruleset-migration", "compatibility": [], "date": "", "description":
                           "rmig verify --engine-socket: the migrated content", "documentation": "", "modified": "",
                           "references": [], "title": "rmig verify"},
              "root_decoder": root_id}
    return {"policy": policy, "resources": {"decoders": decs, "integrations": ints, "kvdbs": kvs,
                                            "filters": [], "outputs": []}}, left_out


def enrichment_gap(detection, ioc=None):
    """Why a rule on IoC enrichment fields is not checked on this engine, or None. Always a reason for such a rule:
    the indexer syncs the IoC feeds and turns enrichment on per policy; the tool's policy sends no enrichments, and
    no recorded answer shows what a standalone engine does with them. ``ioc`` (``GET /status``) is named in the
    reason only."""
    keys = []

    def walk(sel):
        if isinstance(sel, dict):
            keys.extend(k.split("|", 1)[0] for k in sel)
        elif isinstance(sel, list):
            for x in sel:
                walk(x)

    for name, sel in (detection or {}).items():
        if name != "condition":
            walk(sel)
    for field in keys:
        if field.startswith(ENRICHMENTS):
            avail = sorted(t for t, v in (ioc or {}).items() if isinstance(v, dict) and v.get("available"))
            return ("the rule reads %s, set by the IoC enrichment the indexer runs with its feeds; not checked "
                    "offline (engine IoC feeds available: %s)" % (field, ", ".join(avail) or "none"))
    return None

class OfflineEngine:
    """The two tester sessions of one ``verify --engine-socket`` run."""

    def __init__(self, client, catalog_dir=None, say=print):
        self.client = client
        self.catalog_dir = catalog_dir
        self.say = say
        self.catalog = None
        self.catalog_error = None
        self.ioc = {}
        self.tool = None        # (ok, why) of the tool's policy
        self.tool_failure = "NOT_REPRODUCED"  # the result a refusal of the tool's policy gives its rules
        self.stock = None       # (ok, why) of the catalog policy; None when no rule needs it
        self.left_out = {}
        self.loaded = []

    def _load(self, space, full_policy, what):
        ans = self.client.load_policy(space, full_policy)
        if ans.ok:
            self.loaded.append(space)
            r = full_policy["resources"]
            self.say("verify: %s loaded in engine space %s (%d integrations, %d decoders, %d kvdbs)" % (
                what, space, len(r["integrations"]), len(r["decoders"]), len(r["kvdbs"])))
            return True, None
        self.say("verify: the engine refused %s: %s" % (what, ans.error))
        hint = helper_hint(ans.error)
        if hint:
            self.say("verify: %s" % hint)
            return False, "the engine refused %s: %s (%s)" % (what, ans.error, hint)
        return False, "the engine refused %s: %s" % (what, ans.error)

    def prepare(self, out, need_tool, need_stock):
        """Raise :class:`engine.EngineError` when the socket does not answer."""
        from .engine import EngineError

        st = self.client.status()
        if st.status != 200 or not isinstance(st.body, dict):
            raise EngineError("GET /status: %s" % st.error)
        self.ioc = st.body.get("ioc") or {}
        if self.catalog_dir:
            try:
                self.catalog = Catalog(self.catalog_dir)
            except CatalogError as exc:
                self.catalog_error = str(exc)
        if need_tool and getattr(out, "share_error", None):
            self.tool = (False, out.share_error)
            self.tool_failure = "NOT_CHECKED"
            need_tool = False
        if need_tool:
            try:
                full, self.left_out = tool_policy(out, self.catalog)
                self.tool = self._load(TOOL_SPACE, full, "the migrated content (out/)")
                if not self.tool[0] and full["resources"]["integrations"] and out.shared_root:
                    # the policy carries stock integrations of the catalog too: a refusal that does not name one
                    # of the tool's integrations is about the catalog, not about the migration
                    own = {i.title for i in out.integrations}
                    m = _BUILD_ERR.search(self.tool[1])
                    if not (m and m.group(1) in own):
                        self.tool_failure = "NOT_CHECKED"
            except CatalogError as exc:
                self.tool = (False, str(exc))
                self.tool_failure = "NOT_CHECKED"
        if need_stock:
            if self.catalog is not None:
                try:
                    self.stock = self._load(STOCK_SPACE, self.catalog.full_policy(),
                                            "the 5.x catalog (%s)" % self.catalog.label())
                except CatalogError as exc:
                    self.stock = (False, str(exc))
            elif self.catalog_error:
                self.stock = (False, self.catalog_error)
            else:
                self.stock = (False, "the rule runs on stock 5.x events, which need the stock decoders: pass "
                                     "--catalog with a 5.x catalog snapshot")

    def oracle(self, integ):
        if integ.kind == "on-stock":
            return "offline engine (normalization: %s from --catalog)" % STOCK_SPACE
        return "offline engine (%s)" % TOOL_SPACE

    def blocked(self, integ):
        """``(result, why)`` when the integration's events cannot be run, else None. The tool's own content refused
        by the engine is a failure (apply would meet the same refusal); stock content that is missing or refused
        leaves the rule unchecked."""
        if integ.kind == "on-stock":
            ok, why = self.stock or (False, "the catalog policy was not loaded")
            return None if ok else ("NOT_CHECKED", why)
        if integ.key in self.left_out:
            return "NOT_CHECKED", self.left_out[integ.key]
        ok, why = self.tool or (False, "the migrated content was not loaded")
        return None if ok else (self.tool_failure, why)

    def logtest(self, integ, ev):
        """``(normalized event, None)`` or ``(None, the engine's error)``."""
        from .engine import Refused, output_of

        space = STOCK_SPACE if integ.kind == "on-stock" else TOOL_SPACE
        try:
            return output_of(self.client.logtest(space, ev["event"], ev["location"])), None
        except Refused as exc:
            return None, "engine logtest: %s" % exc

    def close(self):
        for space in self.loaded:
            try:
                self.client.delete_session(space)
            except Exception:  # noqa: BLE001  (cleanup of the engine's tester session; the run's result stands)
                pass
        self.loaded = []
