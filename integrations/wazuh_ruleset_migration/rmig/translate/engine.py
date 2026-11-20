"""The translator: from the classified inventory to the 5.x package.

It runs inside :class:`rmig.classify.Classifier` (``translate=True``) after the
classification, so that the state of every item comes out of the translation:

1. decoders (:mod:`.decoders`);
2. rules (conditions, flattening, silencer exclusions, labels,
   lists, metadata) for every rule that classification left
   ``AUTO`` or ``RECIPE`` (a ``RECIPE`` rule is translated as far as it goes, as
   the starting point of its recipe);
3. propagation to a fixed point: parent rule -> child, decoder -> child
   decoder, decoder that sets a field -> rule that reads it, silencer ->
   the rules that carry its exclusion;
4. the package: integrations, decoders (with the label blocks of the emitted
   rules), KVDBs, rules (unique titles), monitors, recipes, detectors and the
   mapping. :mod:`rmig.emit` writes it.
"""

import ipaddress
import json
import os
import re

from .. import model4 as m
from .. import reasons as R
from ..decisions import stock_resolved
from ..fields import STATIC_TO_WCS, static_destination, wcs_fields
from ..parse.lists import split_entry
from .. import stock as stock_mod
from ..stock import DATA_DIR
from . import helpers as H
from . import meta
from .. import feeds as F
from .decoders import FLOATING, NUMERIC, DecoderTranslator, convert_expr
from ..winpack import load_pack
from .patterns import (PatternError, collapse_doubled_backslash, helper_quote, literal_values, parse, to_re2,
                       to_sigma)
from .re_dialect import problems as dialect_problems
from .sigma import AND, NOT, OR, render, sel

BASE_PATH = os.path.join(DATA_DIR, "wazuh4-base.json")
BASE_KEY = "wazuh4-base"
NON_FIELD_ELEMS = ("match", "regex")
_BASE = {}


_BASE_STOCK = {}


def stock_parents(index, parent_name):
    """Stock decoders of the user's 4.x ruleset recreated as 5.x parents:
    root decoders selected by program name (and prematch) only."""
    by_name = {}
    for d in index.decoders:
        by_name.setdefault(d["name"], []).append(d)
    out = {}
    for name in sorted(by_name):
        entries = by_name[name]
        if len(entries) != 1:
            continue
        d = entries[0]
        if d["parent"] or d["regex"] or d["order"] or d["plugin_decoder"] or not d["program_name"]:
            continue
        if not d["program_name"]["value"].strip():
            continue
        try:
            checks = ["regex_match($process.name, %s)" % helper_quote(
                to_re2(d["program_name"]["engine"], d["program_name"]["value"]).pattern())]
            if d["prematch"]:
                checks.append("regex_match($message, %s)" % helper_quote(
                    to_re2(d["prematch"]["engine"], d["prematch"]["value"]).pattern()))
        except PatternError:
            continue
        dname = "decoder/wazuh4-%s/0" % name
        out[name] = {
            "origin": "ruleset/decoders/%s:%d" % (d["file"], d["line"]),
            "text_field": "message",
            "resource": {
                "name": dname,
                "enabled": True,
                "metadata": {"title": dname.split("/")[1],
                             "description": "Wazuh 4.x stock decoder %s recreated as the parent of migrated decoders." % name,
                             "documentation": "", "references": [], "supports": []},
                "parents": [parent_name],
                "check": " AND ".join(checks),
            },
        }
    return out


def load_base(path=None):
    """The base package, plus ``stock_parents`` from the active stock index."""
    path = path or BASE_PATH
    if path not in _BASE:
        with open(path, "r", encoding="utf-8") as fh:
            _BASE[path] = json.load(fh)
    base = _BASE[path]
    index = stock_mod.active()
    if index is None:
        return base
    cached = _BASE_STOCK.get(path)
    if cached is None or cached[0] is not index:
        full = dict(base)
        full["stock_parents"] = stock_parents(index, base["predecoder"])
        full["stock_parents_source"] = index.source
        cached = _BASE_STOCK[path] = (index, full)
    return cached[1]


class Build:
    """What translating one rule collects: codes for the item, label requests,
    KVDBs, notes and whether a part could not be translated."""

    def __init__(self):
        self.codes = []
        self.labels = {}   # tag -> (decoder 4.x name, [blocks])
        self.field_labels = {}  # tag -> {decoder 4.x name: [blocks]}: checks of fields without a WCS field
        self.kvdbs = {}    # list path -> kvdb title
        self.notes = []
        self.failed = False

    def code(self, code, detail=""):
        if (code, detail) not in self.codes:
            self.codes.append((code, detail))
        if R.CATALOG[code].state in (R.RECIPE, R.DECISION):
            self.failed = True

    def merge(self, other):
        for c in other.codes:
            if c not in self.codes:
                self.codes.append(c)
        self.labels.update(other.labels)
        self.field_labels.update(other.field_labels)
        self.kvdbs.update(other.kvdbs)
        for n in other.notes:
            if n not in self.notes:
                self.notes.append(n)


class Source:
    __slots__ = ("kind", "key", "title", "stock_integration", "label_dec", "text_field", "fields",
                 "integration_sel", "decoder_sel", "dec_problem", "feed", "windows")

    def __init__(self, kind):
        self.kind = kind
        self.key = None
        self.title = None
        self.stock_integration = None
        self.label_dec = None
        self.text_field = "message"
        self.fields = {}
        self.integration_sel = None
        self.decoder_sel = None
        self.dec_problem = None  # why a field check cannot run under label_dec (Classifier.decoder_line_problem)
        self.feed = None
        self.windows = False


class Feed:
    """One generated feed decoder: the roots that share an integration."""

    def __init__(self, name):
        self.name = name                     # integration name without the prefix
        self.label = "feed:%s" % name        # label_dec of its rules; never a 4.x decoder name
        self.key = "%s%s" % (meta.PREFIX, meta.slug(name))
        self.dname = "decoder/%s%s/0" % (meta.PREFIX, meta.slug(name))
        self.roots = []                      # feed dicts of the classifier, in load order
        self.json = False
        self.catchall = False
        self.field_exprs = {}                # field name lower-cased -> [value expression]
        self.field_names = {}                # field name lower-cased -> 4.x spelling (first seen)

    @property
    def check(self):
        """OR of the root selectors; a root with no selector of the feed that
        takes the JSON events gives its probe (rmig.feeds.root_probe). None
        when a root has neither: the feed takes every JSON event."""
        sels = []
        for f in self.roots:
            if f["catchall"]:
                s = f.get("probe")
                if not s:
                    return None
            elif f["selector"]:
                s = f["selector"]
            else:
                continue  # RM-R-FEED-NO-SELECTOR: the root is not AUTO
            if s not in sels:
                sels.append(s)
        if not sels:
            return None
        return sels[0] if len(sels) == 1 else " OR ".join("(%s)" % x for x in sels)

    @property
    def takes_every_json(self):
        return self.catchall and self.check is None


class RuleOut:
    def __init__(self, uid, key):
        self.uid = uid
        self.key = key
        self.resource = None
        self.build = None
        self.title_base = None
        self.local_id = None
        self.src = None


class Translator:
    def __init__(self, clf, list_loader=None, date=None, base=None):
        self.clf = clf
        self.items = clf.items
        self.tree = clf.tree
        self.load = clf.load
        self.decisions = clf.decisions
        self.eq = clf.eq
        self.wcs = wcs_fields()
        self.base = base or load_base()
        self.list_loader = list_loader
        self.date = date
        self.dec = DecoderTranslator(self)
        self.rules = {}          # uid -> RuleOut
        self.rule_deps = {}      # uid -> {"decoders": [uids], "fields": [(name, [uids])]}
        self.list_tags = {}      # (path, lookup, field, check_value) -> tag
        self.list_integ = {}     # path -> set of integration keys
        self.winpack = getattr(clf, "winpack", None) or load_pack()
        self._wctx = None        # Windows contexts [(scope, event ids)] of the chain being translated
        self._wctx_all = []
        self.engine_helpers = getattr(clf, "engine_helpers", None) or H.DEFAULT
        H.known(self.engine_helpers)  # an unknown dialect fails here
        self.package = None

    # -- state helpers ---------------------------------------------------------
    def state(self, uid):
        acc = self.clf.acc[uid]
        return R.state_of(list(acc.codes)) if acc.codes else R.AUTO

    def add(self, uid, code, detail=""):
        self.clf.acc[uid].add(code, detail)

    # -- run ---------------------------------------------------------------------
    def run(self):
        self._prescan_lists()
        self._deps()
        self._build_feeds()
        self._translate_decoders()
        self._translate_rules()
        self._check_helpers()
        self._propagate()
        self._finish_rules()
        for acc in self.clf.acc.values():
            if not acc.codes:
                acc.add("RM-X-TRANSLATED")
        self.package = self._assemble()
        return self

    # -- pre-scans -------------------------------------------------------------
    def _custom_rule_uids(self):
        for uid in self.load.node_order:
            node = self.tree.node(uid)
            if node.get("item") is None or node["origin"] != "custom":
                continue
            yield uid

    def _integration_keys(self, uid):
        integ = self.clf.extra.get(uid, {}).get("integration") or []
        if isinstance(integ, str):
            integ = [integ]
        return ["%s%s" % (meta.PREFIX, meta.slug(i)) for i in integ]

    def _prescan_lists(self):
        for uid in self._custom_rule_uids():
            eff = self.tree.item_of(uid)
            if not eff:
                continue
            keys = self._integration_keys(uid)
            for chain_uid in self._chain_rule_uids(uid):
                it = self.tree.item_of(chain_uid)
                for li in (it or {}).get("lists", []):
                    for k in keys:
                        self.list_integ.setdefault(li["path"], set()).add(k)

    def _chain_rule_uids(self, uid):
        out = []
        for ch in self.tree.effective_rule(uid)["chains"]:
            for u in ch["rules"]:
                if u not in out:
                    out.append(u)
        if uid not in out:
            out.append(uid)
        return out

    def _rule_field_names(self, uid):
        names = []
        for u in self._chain_rule_uids(uid):
            it = self.tree.item_of(u)
            if not it:
                continue
            for c in it["conditions"]:
                if c["elem"] in STATIC_TO_WCS and c["elem"] not in ("program_name", "hostname", "location"):
                    names.append(c["elem"])
            names.extend(f["name"] for f in it["fields"])
            names.extend(li["field"] for li in it["lists"] if li["field"])
        out = []
        for n in names:
            if n and n not in out:
                out.append(n)
        return out

    def _deps(self):
        """Decoders a custom-source rule depends on."""
        for uid in self._custom_rule_uids():
            src = self.clf.extra.get(uid, {}).get("source") or {}
            if src.get("kind") != "custom":
                continue
            decs = [d for d in self.tree.chain_decoded_as(uid) if d in self.clf.custom_decoders]
            if not decs:
                continue
            dname = decs[0]
            dec_uids = list(self.clf.custom_decoders[dname])
            scope = [dname] + self.dec.descendants(dname) + self.dec.ancestors(dname)
            fields = []
            for name in self._rule_field_names(uid):
                producers = []
                for g in scope:
                    for du in self.clf.custom_decoders.get(g, []):
                        if name.lower() in [w.lower() for w in self.items[du]["order"]]:
                            producers.append(du)
                if producers:
                    fields.append((name, producers))
            self.rule_deps[uid] = {"decoders": dec_uids, "fields": fields, "decoder": dname}

    # -- feeds -------------------------------------------------------------------
    def _build_feeds(self):
        """Feeds (rmig.feeds): one generated decoder per feed integration, with
        the JSON keys its rules read as fields (``field_exprs``)."""
        self.feeds = {}
        for root_uid, f in sorted(self.clf.feed_roots.items(), key=lambda kv: self.tree.node(kv[0])["seq"]):
            label = "feed:%s" % f["integration"]
            feed = self.feeds.get(label)
            if feed is None:
                feed = self.feeds[label] = Feed(f["integration"])
            feed.roots.append(f)
            feed.json = feed.json or f["json"]
            if f["catchall"]:
                feed.catchall = True
        for uid in self._custom_rule_uids():
            src = self.clf.extra.get(uid, {}).get("source") or {}
            if src.get("kind") != "feed":
                continue
            for integ in self.clf.extra[uid].get("integration") or []:
                feed = self.feeds.get("feed:%s" % integ)
                if feed is None or not feed.json:
                    continue
                for name in self._rule_field_names(uid):
                    low = name.lower()
                    if low in feed.field_exprs:
                        continue
                    key = F.json_key_of(name)
                    path = F.json_path(key) if key else None
                    if path is None:
                        continue
                    feed.field_exprs[low] = [path]
                    feed.field_names[low] = name

    def feed_normalize(self, feed):
        """Normalize blocks of a feed decoder: one temporary per JSON key and
        a map to the WCS field when it is decided, as for a 4.x decoder."""
        extract, maps = [], []
        for n, low in enumerate(sorted(feed.field_exprs), start=1):
            temp = "_c%d" % n
            extract.append({temp: feed.field_exprs[low][0]})
            wcs = self.dec._wcs(feed.field_names[low])
            if wcs is None:
                continue
            expr, ok = convert_expr(self.wcs.type_of(wcs), temp)
            if ok:
                maps.append({wcs: expr})
        return [{"map": extract + maps}] if extract else []

    # -- decoders ----------------------------------------------------------------
    def _translate_decoders(self):
        for name, group in self.dec.groups.items():
            if self.state(group.uids[0]) != R.AUTO:
                continue
            parent, checks, normalize = self.dec.translate_group(group)
            for uid, codes in group.codes.items():
                for code, detail in codes:
                    self.add(uid, code, detail)
            group.resource = {"parent": parent, "checks": checks, "normalize": normalize}

    # -- rules: sources ---------------------------------------------------------
    def stock_entry(self, key, b):
        """Equivalence or decisions entry of a stock reference, validated.
        Returns a dict (integration, selection node, text_field, fields) or
        None (the item already has RM-S-NO-EQUIVALENT or gets an invalid-entry
        code)."""
        kind, _, name = key.partition(":")
        section = {"rule": "rules", "group": "groups", "decoder": "decoders"}[kind]
        if self.winpack.knows(key) and not stock_resolved(self.decisions, key) and name not in self.eq.get(section, {}):
            return {"key": key, "integration": self.winpack.integration, "selection": None, "fields": {},
                    "fidelity": "exact", "windows": self.winpack.alternatives(key)}
        entry = self.eq.get(section, {}).get(name)
        origin = "the equivalence table"
        if not entry:
            entry = self.decisions.get("stock", {}).get(key)
            origin = "decisions.json"
            if not entry or not entry.get("integration"):
                return None
            if kind != "decoder" and not entry.get("selection"):
                return None
        integ = entry.get("integration")
        if not isinstance(integ, str):
            b.code("RM-S-INVALID-ENTRY", "%s (%s): integration must be a name" % (key, origin))
            return None
        if self.std_info(integ).get("unknown"):
            b.code("RM-S-UNKNOWN-INTEGRATION", "%s (%s): %s" % (key, origin, integ))
        selection = entry.get("selection")
        sel_map = None
        if selection:
            sel_map = self._parse_selection(selection)
            if sel_map is None:
                b.code("RM-S-INVALID-ENTRY", "%s (%s): selection must be an object or 'field: value' lines" % (key, origin))
                return None
            bad = [k for k in sel_map if not self.wcs.exists(k.split("|", 1)[0])]
            if bad:
                b.code("RM-S-INVALID-ENTRY", "%s (%s): selection field(s) not in WCS: %s" % (key, origin, ", ".join(bad)))
                return None
        res = {"key": key, "integration": integ, "selection": sel(sel_map) if sel_map else None,
               "fields": dict(entry.get("fields") or {}), "fidelity": entry.get("fidelity", "exact")}
        if "text_field" in entry:
            res["text_field"] = entry.get("text_field")
        if kind == "decoder" and not sel_map:
            b.code("RM-S-BROAD-SELECTION", "%s selected by wazuh.integration.name only" % key)
        if entry.get("fidelity") == "approximate":
            b.notes.append("%s: the equivalence entry is approximate" % key)
        return res

    def std_info(self, integ):
        """Category and ``enabled`` of a standard integration (``unknown``
        when the snapshot does not list it)."""
        std = self.base.get("standard_integrations", {})
        if integ in std:
            return std[integ]
        return {"category": "other", "enabled": True, "unknown": True}

    @staticmethod
    def _parse_selection(selection):
        if isinstance(selection, dict):
            return dict(selection) if selection else None
        if not isinstance(selection, str):
            return None
        text = selection.strip()
        if text.startswith("{"):
            try:
                obj = json.loads(text)
            except ValueError:
                return None
            return obj if isinstance(obj, dict) and obj else None
        out = {}
        for part in [p for line in text.split("\n") for p in line.split(" and ")]:
            part = part.strip()
            if not part:
                continue
            if ":" not in part:
                return None
            k, v = part.split(":", 1)
            k, v = k.strip(), v.strip().strip("\"'")
            if not k:
                return None
            out[k] = v
        return out or None

    def source_of(self, uid, b):
        extra = self.clf.extra.get(uid, {})
        s = extra.get("source") or {}
        kind = s.get("kind")
        if kind == "custom":
            keys = self._integration_keys(uid)
            if len(keys) > 1:
                b.code("RM-R-MULTI-SOURCE", ", ".join(keys))
                return None
            src = Source("custom")
            src.key = keys[0]
            src.title = keys[0]
            decs = [d for d in self.tree.chain_decoded_as(uid) if d in self.clf.custom_decoders]
            src.label_dec = decs[0] if decs else None
            src.dec_problem = self.clf.decoder_line_problem(decs)
            src.integration_sel = sel({"wazuh.integration.name": src.title})
            if src.label_dec and self.dec.top_name(src.label_dec) != src.label_dec:
                tag = "wazuh4.decoder.%s" % meta.tag_part(src.label_dec)
                b.labels[tag] = (src.label_dec, [{"map": [{"tags": "array_append_unique(%s)" % helper_quote(tag)}]}])
                src.decoder_sel = sel({"tags": tag})
            return src
        if kind == "feed":
            keys = self._integration_keys(uid)
            if len(keys) > 1:
                b.code("RM-R-MULTI-SOURCE", ", ".join(keys))
                return None
            feed = self.feeds["feed:%s" % self.clf.extra[uid]["integration"][0]]
            src = Source("custom")
            src.key = feed.key
            src.title = feed.key
            src.feed = feed.label
            src.label_dec = feed.label
            src.integration_sel = sel({"wazuh.integration.name": src.title})
            return src
        if kind == "stock":
            entries = []
            for ref in s.get("stock_refs", []):
                e = self.stock_entry(ref, b)
                if e is None:
                    if not b.failed:
                        b.failed = True  # RM-S-NO-EQUIVALENT from classification
                    continue
                entries.append(e)
            if b.failed:
                return None
            integs = sorted({e["integration"] for e in entries})
            if len(integs) != 1:
                b.code("RM-R-MULTI-SOURCE", ", ".join(integs) or "none")
                return None
            src = Source("stock")
            src.stock_integration = integs[0]
            src.key = "%son-%s" % (meta.PREFIX, meta.slug(integs[0]))
            src.title = src.key
            src.integration_sel = sel({"wazuh.integration.name": integs[0]})
            for e in entries:
                src.fields.update(e["fields"])
            src.windows = any("windows" in e for e in entries) or integs[0] == self.winpack.integration
            if src.windows:
                src.text_field = "event.original"
            text_fields = [e["text_field"] for e in entries if "text_field" in e]
            if text_fields:
                src.text_field = text_fields[0]
            dec_sels = [e["selection"] for e in entries if e["key"].startswith("decoder:") and e["selection"]]
            src.decoder_sel = AND(*dec_sels)
            if not self.std_info(integs[0])["enabled"]:
                b.code("RM-S-INTEGRATION-DISABLED", integs[0])
            return src
        return None

    # -- rules: conditions -----------------------------------------------------
    def wcs_for(self, name, src, b, item, line):
        """The WCS field of a 4.x field (a string), or, for a field without
        one whose events come from generated decoders, ``{decoder 4.x name:
        value expression}`` where the decoders can check it
        (``RM-F-DECODER-CHECK``), or None with a code."""
        if src.kind == "stock" and name in src.fields:
            return src.fields[name]
        is_static, dest = static_destination(name)
        if is_static and dest:
            return dest
        action, wcs = self.clf.field_action(name)
        if action == "map":
            return wcs
        key = self.clf.fkey(name)
        seen = "%s:%d" % (item["file"], line)
        required = True
        if src.label_dec:
            use, detail = self.clf.field_use(name, src.label_dec, src.dec_problem)
            if use == "decoder":
                exts = self.field_extractions(src.label_dec, name)
                if exts:
                    self.clf._want_field(key, m.ref(item), seen)
                    b.code("RM-F-DECODER-CHECK", detail)
                    return exts
                use = "RM-F-DROPPED" if action == "drop" else "RM-F-UNMAPPED"
                leaves, _why = self.clf.decoder_field_sources(src.label_dec, name)
                if all(self.dec.groups.get(n) is None or self.dec.groups[n].resource is None for n in leaves):
                    # the decoders are not translated: their own codes reach the rule, not this field
                    required = False
                    detail = "%s (its decoder is not translated)" % key
                else:
                    detail = "%s (no translated decoder extracts it once)" % key
        else:
            use = "RM-F-DROPPED" if action == "drop" else "RM-F-UNMAPPED"
            detail = key
        self.clf._want_field(key, m.ref(item), seen, required=required)
        b.code(use, detail)
        return None

    def field_extractions(self, label_dec, name):
        """``{decoder 4.x name: value expression}``: the leaf decoders under
        ``label_dec`` that extract ``name`` (:meth:`Classifier.decoder_field_sources`)
        and were translated, each with the expression of its extraction. Empty
        when none can give the value."""
        feed = self.feeds.get(label_dec)
        if feed is not None:
            exprs = feed.field_exprs.get(name.lower())
            return {label_dec: exprs[0]} if exprs else {}
        leaves, _why = self.clf.decoder_field_sources(label_dec, name)
        out = {}
        for n in leaves or []:
            g = self.dec.groups.get(n)
            if g is None or g.resource is None:
                continue  # not translated: 5.x has no events of it
            exprs = g.field_exprs.get(name.lower(), [])
            if len(exprs) == 1:
                out[n] = exprs[0]
        return out

    def decoder_field_node(self, exts, engine, value, negate, b, tag, what):
        """A condition on a field without a WCS field, run where the value is:
        in each leaf decoder that extracts it, the value goes to a temporary
        of the tag and the 4.x match (with its case rules) sets the tag. In
        4.x a missing field never matches, with or without negate."""
        try:
            re2 = to_re2(engine, value).pattern()
        except PatternError as exc:
            b.code("RM-R-RE-UNSUPPORTED", "%s %s %r: %s" % (what, engine, value, exc))
            return None
        temp = label_temp(tag)
        match = "regex_match($%s, %s)" % (temp, helper_quote(re2))
        check = "exists($%s) AND NOT %s" % (temp, match) if negate else match
        add_tag = [{"tags": "array_append_unique(%s)" % helper_quote(tag)}]
        b.field_labels[tag] = {d: [{"map": [{temp: expr}]}, {"check": check, "map": add_tag}]
                               for d, expr in sorted(exts.items())}
        return sel({"tags": tag})

    def _terms_node(self, wcs, terms):
        sels = []
        for mod, vals in terms:
            key = wcs if mod == "" else "%s|%s" % (wcs, mod)
            if mod == "re":
                for v in vals:
                    bad = dialect_problems(v)
                    if bad:
                        raise PatternError("the dialect validator refused %r (%s)" % (v, "; ".join(bad)))
            sels.append(sel({key: vals[0] if len(vals) == 1 else list(vals)}))
        return OR(*sels)

    def _label(self, b, src, tag, wcs, re2):
        block = {"check": "regex_match($%s, %s)" % (wcs, helper_quote(re2)),
                 "map": [{"tags": "array_append_unique(%s)" % helper_quote(tag)}]}
        b.labels[tag] = (src.label_dec, [block])
        return sel({"tags": tag})

    def field_node(self, wcs, engine, value, negate, b, src, tag, what):
        wtype = "keyword" if wcs == "message" else (self.wcs.type_of(wcs) or "keyword")
        node = None
        if wtype in NUMERIC or wtype in FLOATING or wtype in ("ip", "boolean"):
            vals = literal_values(engine, value)
            approx = False
            if vals is None and engine == "osmatch":
                try:
                    parsed = parse(engine, value)
                    if all(a.is_literal() for a in parsed.alts):
                        vals = [a.text() for a in parsed.alts]
                        approx = True
                except PatternError:
                    vals = None
            conv = []
            for v in vals or []:
                try:
                    if wtype in NUMERIC:
                        conv.append(int(v))
                    elif wtype in FLOATING:
                        conv.append(float(v))
                    elif wtype == "ip":
                        ipaddress.ip_address(v)
                        conv.append(v)
                    else:
                        if v.lower() not in ("true", "false"):
                            raise ValueError(v)
                        conv.append(v.lower() == "true")
                except ValueError:
                    conv = None
                    break
            if not conv:
                b.code("RM-R-RE-UNSUPPORTED", "%s: %s pattern %r on the %s field %s has no exact value" % (what, engine, value, wtype, wcs))
                return None
            node = sel({wcs: conv[0] if len(conv) == 1 else conv})
            if approx:
                b.code("RM-R-RE-DIALECT", "%s: the substring match %r on the %s field %s became equality" % (what, value, wtype, wcs))
        else:
            form, err = None, None
            try:
                form = to_sigma(engine, value)
            except PatternError as exc:
                err = str(exc)
            if form is not None and form.exact:
                try:
                    node = self._terms_node(wcs, form.terms)
                except PatternError as exc:
                    form, err = None, str(exc)
            if node is None:
                re2 = None
                if src.kind == "custom" and src.label_dec:
                    try:
                        re2 = to_re2(engine, value).pattern()
                    except PatternError as exc:
                        err = err or str(exc)
                if re2 is not None:
                    node = self._label(b, src, tag, wcs, re2)
                elif form is not None:
                    try:
                        node = self._terms_node(wcs, form.terms)
                        b.code("RM-R-RE-DIALECT", "%s on %s: %s" % (what, wcs, "; ".join(form.why)))
                    except PatternError as exc:
                        err = str(exc)
                if node is None:
                    b.code("RM-R-RE-UNSUPPORTED", "%s %s %r: %s" % (what, engine, value, err or "no form"))
                    b.code("RM-R-RE-DIALECT", "%s: refused (%s)" % (what, err or "no form"))
                    return None
        if negate:
            node = AND(sel({"%s|exists" % wcs: True}), NOT(node))
        return node

    def ip_node(self, wcs, cond, b, what):
        pos, neg = [], []
        for v in cond["values"]:
            v = v.strip()
            target = neg if v.startswith("!") else pos
            v = v.lstrip("!").strip()
            try:
                net = ipaddress.ip_network(v, strict=False)
            except ValueError:
                b.code("RM-R-RE-UNSUPPORTED", "%s: %r is not an address or a network" % (what, v))
                return None
            target.append(str(net))
        if pos and neg:
            b.code("RM-R-RE-UNSUPPORTED", "%s: mixes negated and plain addresses" % what)
            return None
        vals = pos or neg
        node = sel({"%s|cidr" % wcs: vals[0] if len(vals) == 1 else vals})
        negated = bool(neg) != bool(cond.get("negate"))
        if negated:
            node = AND(sel({"%s|exists" % wcs: True}), NOT(node))
        return node

    def list_node(self, li, item, k, b, src):
        what = "<list> %s" % li["path"]
        if li["path"] in self.clf.ioc_feed_lists:
            return self.ioc_feed_node(li, b, what)
        if src.kind != "custom" or not src.label_dec:
            b.code("RM-R-LABEL-UNAVAILABLE", what)
            return None
        if li["lookup"] == "address_match_key_value":
            b.code("RM-L-KEY-VALUE-INVERTED", li["path"])
            return None
        if not li["field"]:
            b.code("RM-X-INVALID", "%s without field" % what)
            return None
        wcs = self.wcs_for(li["field"], src, b, item, li["line"])
        if wcs is None:
            return None
        exts = None
        if isinstance(wcs, dict):  # no WCS field: the lookup reads the value the decoder extracted
            exts = wcs
            wcs = "field:%s" % self.clf.fkey(li["field"])
        kv = self.kvdb_title(li["path"], src.key)
        exact, prefixes = self.list_keys(li["path"])
        combo = (li["path"], li["lookup"], wcs, li.get("check_value"))
        tag = self.list_tag(combo)
        f = "$%s" % (label_temp(tag) if exts else wcs)
        cidrs = []
        for p in prefixes:
            c = prefix_to_cidr(p)
            if c:
                cidrs.append(c)
        lookup = li["lookup"]
        blocks = []
        add_tag = [{"tags": "array_append_unique(%s)" % helper_quote(tag)}]
        if lookup == "match_key":
            blocks.append({"check": "in_kvdb(%s, %s)" % (f, helper_quote(kv)), "map": add_tag})
        elif lookup == "not_match_key":
            blocks.append({"check": "not_in_kvdb(%s, %s)" % (f, helper_quote(kv)), "map": add_tag})
        elif lookup in ("address_match_key", "not_address_match_key"):
            cidr_args = ", ".join(helper_quote(c) for c in cidrs)
            if lookup == "address_match_key":
                parts = ["in_kvdb(%s, %s)" % (f, helper_quote(kv))]
                if cidrs:
                    parts.append("in_cidr(%s, %s)" % (f, cidr_args))
                check = " OR ".join(parts)
            else:
                check = "not_in_kvdb(%s, %s)" % (f, helper_quote(kv))
                if cidrs:
                    check += " AND NOT in_cidr(%s, %s)" % (f, cidr_args)
            blocks.append({"check": check, "map": add_tag})
            if cidrs:
                b.code("RM-L-PREFIX-KEYS", "%s: %d prefix key(s) as %s (IPv4 only)" % (
                    li["path"], len(cidrs), "in_cidr" if self.engine_helpers == H.CURRENT else "ip_cidr_match"))
        elif lookup == "match_key_value":
            temp = "_wazuh4_lv_%s_%d" % (item["id"], k)
            blocks.append({"map": [{temp: "kvdb_lookup(%s, %s)" % (helper_quote(kv), f)}]})
            cv = li.get("check_value")
            if cv:
                try:
                    re2 = to_re2("osmatch", cv).pattern()
                except PatternError as exc:
                    b.code("RM-R-RE-UNSUPPORTED", "%s check_value %r: %s" % (what, cv, exc))
                    return None
                check = "regex_match($%s, %s)" % (temp, helper_quote(re2))
            else:
                check = "exists($%s)" % temp
            blocks.append({"check": check, "map": add_tag})
        else:
            b.code("RM-X-INVALID", "%s: lookup %s" % (what, lookup))
            return None
        if exts:
            if lookup.startswith("not_"):
                # 4.x: a missing field never matches a list (rules.c, RULE_DYNAMIC), negated lookups included;
                # the temporary is unset when the leaf's regex did not match
                for blk in blocks:
                    if "check" in blk:
                        blk["check"] = "exists(%s) AND %s" % (f, blk["check"])
            b.field_labels[tag] = {d: [{"map": [{label_temp(tag): expr}]}] + blocks for d, expr in sorted(exts.items())}
        else:
            b.labels[tag] = (src.label_dec, blocks)
        b.kvdbs[li["path"]] = kv
        return sel({"tags": tag})

    def ioc_feed_node(self, li, b, what):
        """The lookup of an IoC list moved to the 5.x feeds (decisions.json, lists): a match on the IoC
        enrichment of the event. A negated lookup cannot be written that way: RECIPE."""
        from ..quality.lists import IOC_FIELD

        res = self.clf.list_classes.get(li["path"]) or {}
        types = res.get("feed_types") or []
        if li["lookup"].startswith("not_") or li["lookup"] == "match_key_value" and li.get("check_value") \
                or li["lookup"] == "address_match_key_value" or not types:
            b.code("RM-L-IOC-FEED-UNSUPPORTED", "%s: lookup %s%s" % (
                what, li["lookup"], "" if types else " (no feed type known for the list)"))
            return None
        b.code("RM-L-IOC-FEED", "%s: %s in %s" % (what, IOC_FIELD, ", ".join(types)))
        return sel({IOC_FIELD: types[0] if len(types) == 1 else list(types)})

    def own_node(self, uid, b, src):
        """Condition of one 4.x rule (without its parents)."""
        item = self.tree.item_of(uid)
        if item is None:
            return None
        parts = []
        k = 0
        for c in item["conditions"]:
            k += 1
            tag = "wazuh4.rule.%s.c%d" % (item["id"], k)
            what = "<%s> of rule %s" % (c["elem"], item["id"])
            if c["elem"] in NON_FIELD_ELEMS:
                if src.text_field is None:
                    b.code("RM-S-INVALID-ENTRY", "no text field for <%s> on stock content" % c["elem"])
                    continue
                if src.windows:
                    b.code("RM-S-WIN-FULL-LOG", what)
                parts.append(self.field_node(src.text_field, c["engine"], c["value"], c["negate"], b, src, tag, what))
            elif c["elem"] in m.RULE_IP_ELEMENTS:
                wcs = STATIC_TO_WCS[c["elem"]]
                parts.append(self.ip_node(wcs, c, b, what))
            else:
                wcs = self.wcs_for(c["elem"], src, b, item, c["line"])
                if wcs is None:
                    continue
                if isinstance(wcs, dict):
                    parts.append(self.decoder_field_node(wcs, c["engine"], c["value"], c["negate"], b, tag, what))
                    continue
                parts.append(self.field_node(wcs, c["engine"], c["value"], c["negate"], b, src, tag, what))
        for f in item["fields"]:
            k += 1
            tag = "wazuh4.rule.%s.c%d" % (item["id"], k)
            what = "<field name=\"%s\"> of rule %s" % (f["name"], item["id"])
            value = win_value(f["name"], f["engine"], f["value"]) if src.windows else f["value"]
            if src.windows and self._wctx is not None and self.winpack.is_windows_field(f["name"]) \
                    and self.clf.field_action(f["name"])[0] is None:
                handled, node = self.win_field_node(f["name"], f["engine"], value, f["negate"], self._wctx, b, src, tag, what)
                if handled:
                    if node is not WIN_SKIP:
                        parts.append(node)
                    continue
            wcs = self.wcs_for(f["name"], src, b, item, f["line"])
            if wcs is None:
                continue
            if isinstance(wcs, dict):
                parts.append(self.decoder_field_node(wcs, f["engine"], value, f["negate"], b, tag, what))
                continue
            parts.append(self.field_node(wcs, f["engine"], value, f["negate"], b, src, tag, what))
        for li in item["lists"]:
            k += 1
            parts.append(self.list_node(li, item, k, b, src))
        return AND(*parts)

    def _chain_key(self, chain):
        """Stock reference that gives the condition of a chain's stock anchor."""
        anchor = chain["stock_anchor"]
        if not anchor:
            return None
        first = chain["rules"][0] if chain["rules"] else None
        if first is not None:
            node = self.tree.node(first)
            if node.get("link") == "if_group":
                it = self.tree.item_of(first)
                g = it["parents"].get("if_group") or it["parents"].get("if_matched_group")
                return "group:%s" % g
        return "rule:%s" % anchor

    def rule_node(self, uid, b, src):
        eff = self.tree.effective_rule(uid)
        chains = []
        seen = set()
        for ch in eff["chains"]:
            key = self._chain_key(ch)
            sig = (key, tuple(ch["rules"]))
            if sig in seen:
                continue
            seen.add(sig)
            anchor = None
            if key:
                e = self.stock_entry(key, b)
                if e is None:
                    b.failed = True
                    continue
                if src.kind == "stock" and e["integration"] != src.stock_integration:
                    b.code("RM-R-MULTI-SOURCE", "%s is in %s, not %s" % (key, e["integration"], src.stock_integration))
                    continue
                anchor = e["selection"]
                if src.windows and "windows" not in e:
                    # a user's entry for Windows content: the field map of the base decoder
                    self._wctx = self._win_ctx([{"scope": None, "event_ids": None}], ch["rules"])
                if "windows" in e:
                    self._wctx = self._win_ctx(e["windows"], ch["rules"])
                    eids = [x for c in self._wctx for x in (c[1] or [])]
                    if eids and all(x in self.winpack.discarded for x in eids):
                        b.code("RM-S-WIN-DISCARDED", "event id(s) %s" % ", ".join(sorted(set(eids))))
                    for c in self._wctx:
                        if c not in self._wctx_all:
                            self._wctx_all.append(c)
                    anchor = self.win_anchor(key, e["windows"], b, src)
                    if anchor is None:
                        it = self.tree.item_of(uid)
                        if it:
                            self.clf._want_stock(key, m.ref(it), m.origin(it))
                        b.failed = True
                        self._wctx = None
                        continue
            parts = [anchor] + [self.own_node(u, b, src) for u in ch["rules"]]
            self._wctx = None
            chains.append(AND(*parts))
        return OR(*chains)

    # -- rules: the Windows pack -------------------------------------------------
    def _win_ctx(self, alts, chain_rules):
        """[(scope, event ids)] of a Windows anchor; a path without event id
        takes the literal win.system.eventID of the custom rules of the chain."""
        own = None
        for u in chain_rules:
            it = self.tree.item_of(u) or {}
            for f in it.get("fields", []):
                if f["name"].lower() == "win.system.eventid" and not f["negate"]:
                    vals = literal_values(f["engine"], f["value"])
                    if vals:
                        own = vals if own is None else [v for v in own if v in vals]
        out = []
        for a in alts:
            eids = a.get("event_ids") or own
            c = (a.get("scope"), list(eids) if eids else None)
            if c not in out:
                out.append(c)
        return out

    def win_anchor(self, key, alts, b, src):
        """OR of the paths of a stock Windows rule or group (None when a stock
        condition has no 5.x field: the reference becomes a question)."""
        nodes = []
        if self.winpack.partial(key):
            b.code("RM-S-WIN-APPROXIMATE", "%s: %s" % (key, self.winpack.partial(key)))
        for a in alts:
            ctx = [(a.get("scope"), a.get("event_ids"))]
            parts = []
            for n, c in enumerate(a["conditions"]):
                what = "<field name=\"%s\"> of stock rule %s" % (c["name"], c["rule"])
                if c.get("override"):
                    ov = self.winpack.overrides.get(c["override"], {})
                    for r in ov.get("replace", []):
                        vals = r["values"]
                        parts.append(sel({r["wcs"]: vals[0] if len(vals) == 1 else list(vals)}))
                    b.code("RM-S-WIN-APPROXIMATE", "%s: %s" % (what, ov.get("why", "")))
                    continue
                tag = "wazuh4.stock.%s.c%d" % (c["rule"], n + 1)
                handled, node = self.win_field_node(c["name"], c["engine"], win_value(c["name"], c["engine"], c["value"]),
                                                    c["negate"], ctx, b, src, tag, what)
                if node is WIN_SKIP:
                    continue
                if not handled or node is None:
                    b.code("RM-S-WIN-CONDITION", "%s %r (%s)" % (what, c["value"], key))
                    return None
                parts.append(node)
            eids = a.get("event_ids") or []
            if eids and all(e in self.winpack.discarded for e in eids):
                b.code("RM-S-WIN-DISCARDED", "event id(s) %s (%s)" % (", ".join(eids), key))
            nodes.append(AND(*parts) if parts else None)
        if any(nd is None for nd in nodes):
            return sel({"wazuh.integration.name": self.winpack.integration})
        return OR(*nodes)

    def win_field_node(self, name, engine, value, negate, ctx, b, src, tag, what):
        """(handled, node) of a win.* condition through the Windows pack.
        ``handled`` is False when the pack has no 5.x field for it in every
        context: the caller asks for a decision."""
        pack = self.winpack
        low = name.lower()
        table = pack.value_table(low)
        if table is not None:
            vals = literal_values(engine, value)
            if not vals:
                return False, None
            scopes = {s for s, _e in ctx}
            targets, approx = {}, []
            for v in vals:
                ent = table.get(v.lower())
                if ent is None:
                    return False, None
                if ent.get("only_in") and not scopes <= set(ent["only_in"]):
                    return False, None
                if ent.get("fidelity") == "approximate" and not (scopes and scopes <= set(ent.get("exact_in") or {})):
                    approx.append(ent.get("why") or "approximate value")
                out = targets.setdefault(ent["wcs"], [])
                if ent["value"] not in out:
                    out.append(ent["value"])
            if len(targets) != 1:
                return False, None
            wcs, out = list(targets.items())[0]
            if wcs == "log.level" and out == ["information"] and not negate and scopes == {"sysmon"}:
                # Sysmon INFORMATION: no selection on log.level. Its presence on 5.x findings is not
                # proven, and Sysmon writes Level 4 (INFORMATION) on every event but error 255.
                # WARNING and ERROR (rules 61601, 61602) keep log.level: there it selects.
                b.code("RM-S-WIN-APPROXIMATE", "%s: not selected in the Sysmon scope (log.level information)" % what)
                return True, WIN_SKIP
            if wcs == "log.level" and "sysmon" in scopes:
                approx.append("log.level on Sysmon findings is not proven")
            node = sel({wcs: out[0] if len(out) == 1 else out})
            if approx:
                b.code("RM-S-WIN-APPROXIMATE", "%s: %s" % (what, approx[0]))
            if negate:
                node = AND(sel({"%s|exists" % wcs: True}), NOT(node))
            return True, node
        wcs = pack.system_direct(low, ctx)
        fid, why = "exact", []
        if wcs is None:
            res = pack.eventdata(low, ctx)
            if res is None:
                return False, None
            wcs, fid, why = res
        if fid == "approximate":
            b.code("RM-S-WIN-APPROXIMATE", "%s on %s: %s" % (what, wcs, "; ".join(why) or "approximate mapping"))
        vals = literal_values(engine, value)
        if vals and not any(ch.isalpha() for v in vals for ch in v) and (self.wcs.type_of(wcs) or "keyword") == "keyword":
            # a fixed value without letters: equality, case does not matter
            node = sel({wcs: vals[0] if len(vals) == 1 else list(vals)})
            if negate:
                node = AND(sel({"%s|exists" % wcs: True}), NOT(node))
            return True, node
        return True, self.field_node(wcs, engine, value, negate, b, src, tag, what)

    # -- rules: translation ----------------------------------------------------
    def _translate_rules(self):
        for uid in self._custom_rule_uids():
            state = self.state(uid)
            if state not in (R.AUTO, R.RECIPE):
                continue
            if self.tree.is_grouping_only(uid):
                continue
            self.rules[uid] = self.translate_rule(uid)

    def translate_rule(self, uid):
        item = self.tree.item_of(uid)
        b = Build()
        out = RuleOut(uid, None)
        out.build = b
        src = self.source_of(uid, b)
        if src is None:
            for code, detail in b.codes:
                self.add(uid, code, detail)
            return out
        out.key = src.key
        self._wctx_all = []
        node = self.rule_node(uid, b, src)
        for sid in self.clf.extra.get(uid, {}).get("excluded_by", []):
            if self.state(sid) != R.AUTO:
                continue  # the propagation takes its state to this rule
            sb = Build()
            snode = self.rule_node(sid, sb, src)
            if sb.failed or snode is None:
                b.code("RM-R-SHADOWING", "the exclusion of silencer rule %s could not be written" % self.items[sid]["id"])
                continue
            b.merge(sb)
            node = AND(node, NOT(snode))
        if src.decoder_sel is not None:
            node = AND(src.decoder_sel, node)
        node = AND(src.integration_sel, node)
        for code, detail in b.codes:
            self.add(uid, code, detail)
        if b.failed and self.state(uid) == R.AUTO:
            # a part fell without a code of its own (stock entry missing): DECISION
            self.add(uid, "RM-S-NO-EQUIVALENT", "stock content of the rule's chains")
        try:
            detection = render(node)
        except ValueError:
            return out
        tags, compliance = meta.groups_to_tags(item["groups"])
        tags = ["wazuh4.rule.%s" % item["id"]] + [t for t in tags if t != "wazuh4.rule.%s" % item["id"]]
        mitre, mnotes = meta.mitre_block(item["mitre"])
        b.notes.extend(mnotes)
        lid = meta.local_id("rule", m.uid(item))
        refs = ["Migrated from Wazuh 4.x rule %s (%s)" % (item["id"], item["file"])]
        refs += [i["value"] for i in item["info"] if i["type"] == "link" and i["value"]]
        title, missing = meta.title_from_description(item["description"] or "", lambda f: self._title_field(f, src))
        if missing:
            b.notes.append("title placeholder(s) without a WCS field are kept as the 4.x field name: %s"
                          % ", ".join("<%s>" % f for f in missing))
        if not title:
            title = "Wazuh 4.x rule %s" % item["id"]
        desc = "Migrated from Wazuh 4.x rule %s (%s:%d)." % (item["id"], item["file"], item["line"])
        texts = [i["value"] for i in item["info"] if i["type"] != "link" and i["value"]]
        if texts:
            desc += " " + " ".join(texts)
        res = {
            "metadata": meta.metadata(title, lid, desc, refs, self.date),
            "status": "experimental",
            "level": meta.level_keyword(item["level"]),
            "enabled": not self.tree.node(uid)["noalert"],
            "logsource": {"product": src.title},
            "detection": detection,
            "tags": tags,
        }
        if mitre:
            res["mitre"] = mitre
        if compliance:
            res["compliance"] = compliance
        out.resource = res
        out.title_base = title
        out.local_id = lid
        out.src = src
        return out

    def _title_field(self, name, src):
        if src.kind == "stock" and name in src.fields:
            return src.fields[name]
        if src.windows and self.winpack.is_windows_field(name) and self.clf.field_action(name)[0] is None:
            res = self.winpack.eventdata(name, self._wctx_all) if name.lower().startswith("win.eventdata.") else None
            wcs = res[0] if res and res[1] == "exact" else self.winpack.system_direct(name, self._wctx_all)
            if wcs:
                return wcs
        is_static, dest = static_destination(name)
        if is_static and dest:
            return dest
        action, wcs = self.clf.field_action(name)
        return wcs if action == "map" else None

    # -- helper names of the target engine -------------------------------------------
    def _check_helpers(self):
        """Every helper a decoder or a label block would call, rewritten to the
        target dialect, must be registered by that engine; otherwise the item
        is ``RECIPE`` (``RM-D-HELPER-UNAVAILABLE``) and nothing of it is
        emitted. Runs before the propagation, so that children follow."""
        d = self.engine_helpers
        for name, group in self.dec.groups.items():
            if group.resource is None or self.state(group.uids[0]) != R.AUTO:
                continue
            res = {"normalize": group.resource["normalize"]}
            if group.resource["checks"]:
                res["check"] = " AND ".join(group.resource["checks"])
            bad = H.unavailable(H.to_dialect(res, d), d)
            if bad:
                self.add(group.uids[0], "RM-D-HELPER-UNAVAILABLE", "engine %s: %s" % (d, ", ".join(bad)))
        for uid, r in self.rules.items():
            if r.build is None or not (r.build.labels or r.build.field_labels):
                continue
            bad = set()
            for _tag, (_dname, blocks) in sorted(r.build.labels.items()):
                bad.update(H.unavailable(H.to_dialect({"normalize": blocks}, d), d))
            for _tag, per in sorted(r.build.field_labels.items()):
                for _dname, blocks in sorted(per.items()):
                    bad.update(H.unavailable(H.to_dialect({"normalize": blocks}, d), d))
            if bad:
                self.add(uid, "RM-D-HELPER-UNAVAILABLE", "engine %s: %s" % (d, ", ".join(sorted(bad))))

    # -- propagation ---------------------------------------------------------------
    def _snapshot(self):
        return {u: tuple(sorted((c, tuple(d)) for c, d in a.codes.items())) for u, a in self.clf.acc.items()}

    def _propagate(self):
        for _ in range(20):
            before = self._snapshot()
            for uid, node in self.load.dec_nodes.items():
                if node["origin"] != "custom":
                    continue
                for p in node.get("parents", []):
                    if self.load.dec_nodes[p]["origin"] == "custom":
                        self.clf._inherit(self.clf.acc[uid], p, "parent decoder %s" % self.load.dec_nodes[p]["name"])
            for uid in self._custom_rule_uids():
                acc = self.clf.acc[uid]
                if self.state(uid) == R.NOT_APPLICABLE:
                    continue
                for p in self.tree.custom_chain_parents(uid):
                    self.clf._inherit(acc, p, "parent rule %s" % self.tree.node(p)["id"])
                deps = self.rule_deps.get(uid)
                if deps:
                    for du in deps["decoders"][:1]:
                        if self.state(du) != R.AUTO:
                            self.clf._inherit(acc, du, "decoder %s" % self.items[du]["name"])
                    for name, producers in deps["fields"]:
                        if all(self.state(p) != R.AUTO for p in producers):
                            self.clf._inherit(acc, producers[0], "decoder %s, which sets %s" % (self.items[producers[0]]["name"], name))
                for sid in self.clf.extra.get(uid, {}).get("excluded_by", []):
                    if self.state(sid) == R.DECISION:
                        self.clf._inherit(acc, sid, "silencer rule %s" % self.items[sid]["id"])
            if self._snapshot() == before:
                break

    def _finish_rules(self):
        emitted = [r for u, r in self.rules.items() if self.emitted(u)]
        by_title = {}
        for r in emitted:
            by_title.setdefault(r.title_base, []).append(r)
        for title, rs in by_title.items():
            if len(rs) < 2:
                continue
            for r in rs:
                rid = self.items[r.uid]["id"]
                r.resource["metadata"]["title"] = "%s (4.x rule %s)" % (title, rid)
                self.add(r.uid, "RM-R-TITLE-SUFFIXED", "shares the title with %s" % ", ".join(
                    "rule %s" % self.items[o.uid]["id"] for o in rs if o is not r))

    def emitted(self, uid):
        r = self.rules.get(uid)
        if r is None or r.resource is None or r.key is None:
            return False
        if self.state(uid) != R.AUTO:
            return False
        if self.tree.is_silencer(uid) or self.tree.is_grouping_only(uid):
            return False
        return True

    # -- lists -----------------------------------------------------------------
    def kvdb_title(self, path, integ_key):
        name = meta.slug(meta.safe_name(path[len("etc/lists/"):] if path.startswith("etc/lists/") else path.rsplit("/", 1)[-1]))
        if len(self.list_integ.get(path, ())) > 1:
            return "%s-%s" % (integ_key, name)
        return "%s%s" % (meta.PREFIX, name)

    def list_item(self, path):
        for li in self.clf.inv["lists"]:
            if li["name"] == path:
                return li
        return None

    def list_content(self, path):
        """{key: value} of the list, or None when the source is not at hand."""
        li = self.list_item(path)
        if li is None or self.list_loader is None:
            return None
        data = self.list_loader(li)
        if data is None:
            return None
        text = data.replace(b"\r\n", b"\n").decode("utf-8", "replace")
        out = {}
        for line in text.split("\n"):
            kv = split_entry(line)
            if kv is None:
                continue
            out[kv[0]] = kv[1]
        return out

    def list_keys(self, path):
        content = self.list_content(path)
        if content is not None:
            keys = sorted(content)
            return [k for k in keys if not k.endswith(".")], [k for k in keys if k.endswith(".")]
        li = self.list_item(path) or {}
        return list(li.get("sample_keys", [])), list(li.get("prefix_keys", []))

    def list_tag(self, combo):
        if combo not in self.list_tags:
            base = "wazuh4.list.%s" % meta.safe_name(combo[0][len("etc/lists/"):] if combo[0].startswith("etc/lists/") else combo[0])
            used = sum(1 for c in self.list_tags if c[0] == combo[0])
            self.list_tags[combo] = base if used == 0 else "%s.%d" % (base, used + 1)
        return self.list_tags[combo]

    # -- package -----------------------------------------------------------------
    def _assemble(self):
        from .package import assemble
        return assemble(self)


WIN_SKIP = object()  # win_field_node: the condition is left out on purpose (RM-S-WIN-APPROXIMATE)


def label_temp(tag):
    """Temporary field of a decoder-side check: ``wazuh4.rule.1.c2`` ->
    ``_wazuh4_rule_1_c2`` (one per tag, never written by another block)."""
    return "_" + re.sub(r"[^A-Za-z0-9_]", "_", tag)


def prefix_to_cidr(key):
    """``10.`` -> ``10.0.0.0/8``; ``192.168.1.`` -> ``192.168.1.0/24``."""
    parts = key.rstrip(".").split(".")
    if not 1 <= len(parts) <= 3 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return None
    octets = parts + ["0"] * (4 - len(parts))
    return "%s/%d" % (".".join(str(int(o)) for o in octets), 8 * len(parts))


__all__ = ["Translator", "load_base", "label_temp", "prefix_to_cidr", "BASE_KEY"]


def win_value(name, engine, value):
    """A 4.x ``win.*`` pattern for 5.x: 4.x values keep the JSON escaping of the eventchannel decoder (two
    backslashes per separator), 5.x stores one (``collapse_doubled_backslash``). Other fields unchanged."""
    if (name or "").lower().startswith("win."):
        return collapse_doubled_backslash(engine, value)
    return value
