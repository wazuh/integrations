"""Offline "5.x stock for your sources".

For every log source of the custom rules (a custom root decoder, a feed, or a
family of stock 4.x content the rules hang from) this module finds the 5.x
stock integration that decodes it, from the bundled stock 5.x index
(``rmig/data/stock5-index.json``, built by ``scripts/build_stock5_index.py``
from a catalog snapshot), and estimates whether a stock 5.x rule already
detects what each custom rule detects.

Everything here is an offline estimate: no event is decoded and no rule is
run. A ``covered candidate`` is to be confirmed by the live ``coverage``
command (planned). The tool recommends; it never drops a rule.

Matching (evidence, method, confidence):

* ``program-name`` (high): a 4.x ``<program_name>`` equals a
  ``process.name`` value of a 5.x decoder check.
* ``check-literal`` (high): a 4.x literal (prematch, location) contains a
  literal that a 5.x check requires (``contains``/``starts_with``); medium
  when the 5.x literal is short (under 6 characters).
* ``json-tag`` (high): the 4.x feed location or ``integration`` field value
  equals the ``_tmp_json.integration`` value a 5.x check requires; medium when
  they are equal only without separators (``office_365``, ``office365``).
* Literals count only when distinctive: 10+ characters, or 4+ with a
  character that is not a letter or digit. Plain words and shared format
  markers (``CEF:0``, ``LEEF:``) do not count. Negated 5.x literals
  (``NOT contains``) are not probes.
* ``partial-literal`` (medium): a 4.x literal (6+ characters) is part of a 5.x
  check literal, or a 5.x regular expression fragment is part of a 4.x
  literal.
* ``json-keys`` (medium): every ``_tmp_json`` key a 5.x check requires (two
  or more) is a key the 4.x feed root reads.
* ``program-name`` is medium when the 5.x decoder does not hang from the
  syslog decoder (the 4.x program name is the syslog one).
* ``windows-pack`` (high): the stock Windows chain of the Windows pack; the
  pack scope is the 5.x ``event.dataset``.
* ``name`` (low): only the name of the source (for a feed also the top JSON
  keys and the location of its root) names a 5.x integration that has
  decoders: every word of the title, or its first word when no other
  integration starts with it (``eset`` -> ``eset-protect``). Shown as such; no
  evidence from the event.

Stock 4.x anchors resolve to their 4.x decoder (``decoded_as`` up the
``if_sid`` / ``if_group`` chain in the stock 4.14 index) and that decoder is
matched as a custom one.

Rule verdicts, in order: ``tuning`` (level 0-1, silencers, overwrites of stock
rules), ``no 5.x integration``, ``decoded by 5.0, rules still needed`` (the
integration has no stock rule anywhere in the catalog), ``not comparable`` (no
MITRE technique in ``<mitre>`` nor in the description, or no source), ``no stock candidate`` (MITRE present, no
stock rule of the source with the same technique), ``covered candidate`` (an
enabled stock rule of the source with the same technique, and for Windows the
same event code), ``covered if enabled`` (the same, but the stock rule or the
decoding integration ships disabled: enable it). Techniques compare by the
base technique: ``T1059.001`` and ``T1059`` match (shown as ``base``).
"""

import json
import os
import re
from collections import Counter, OrderedDict

from .stock import DATA_DIR, load_stock_index
from .winpack import load_pack
from .textsafe import md

INDEX_PATH = os.path.join(DATA_DIR, "stock5-index.json")
_CACHE = {}

HIGH, MEDIUM, LOW = "high", "medium", "low"
_RANK = {HIGH: 3, MEDIUM: 2, LOW: 1}

V_TUNING = "tuning"
V_NONE = "no 5.x integration"
V_DECODE_ONLY = "decoded by 5.0, rules still needed"
V_NOT_COMPARABLE = "not comparable"
V_NO_CANDIDATE = "no stock candidate"
V_CANDIDATE = "covered candidate"
V_IF_ENABLED = "covered if enabled"
RULE_VERDICTS = (V_CANDIDATE, V_IF_ENABLED, V_NO_CANDIDATE, V_DECODE_ONLY, V_NONE, V_NOT_COMPARABLE, V_TUNING)

S_RULES = "stock rules"
S_RULES_IF_ENABLED = "stock rules if enabled"
S_NO_SOURCE = "no source"
SOURCE_VERDICTS = (S_RULES, S_RULES_IF_ENABLED, V_DECODE_ONLY, V_NONE, S_NO_SOURCE)

MIN_LITERAL = 4      # a 5.x literal shorter than this is never evidence
STRONG_LITERAL = 6   # from this length a contained 5.x literal is high confidence
# 5.x integrations too generic for a match by name only.
_NO_NAME_MATCH = ("linux", "windows", "macos", "system-auth", "wazuh-core")
# Name tokens that say nothing about the product.
_NAME_STOP = {"custom", "parent", "log", "logs", "events", "event", "decoder", "json", "syslog", "child", "feed",
              "wazuh", "rules", "rule", "new", "old", "auth", "system", "integration"}
_TECH = re.compile(r"T\d{4}(?:\.\d{3})?")
_DESC_TECH = re.compile(r"(?<![A-Za-z0-9])T\d{4}(?:\.\d{3})?(?![0-9])")
_TOKEN = re.compile(r"^[A-Za-z0-9_.\-]+$")


# Format markers many products share: never evidence of one product.
GENERIC_LITERALS = ("CEF:0", "CEF:0|", "CEF:", "LEEF:", "LEEF:1.0|", "LEEF:2.0|", "<Event", "<Event xmlns=")
SYSLOG_PARENT = "decoder/syslog/0"


class Stock5Index:
    def __init__(self, data):
        self.data = data
        self.source = data.get("source") or {}
        self.integrations = data.get("integrations", {})
        self.decoders = data.get("decoders", {})
        self.rules = data.get("rules", {})
        self._by_integ = {}
        self._by_dataset = {}
        for rid, r in sorted(self.rules.items()):
            for t in r.get("integrations", []):
                self._by_integ.setdefault(t, []).append(rid)
            for t in r.get("integration_names", []):
                if rid not in self._by_integ.setdefault(t, []):
                    self._by_integ[t].append(rid)
            for ds in r.get("datasets", []):
                self._by_dataset.setdefault(ds, []).append(rid)

    @property
    def offset(self):
        return self.source.get("offset")

    def rules_of(self, integration):
        """Stock rules of an integration: its own and those that select its
        events by ``wazuh.integration.name`` (e.g. ``cloud-detection``)."""
        return list(self._by_integ.get(integration, []))

    def rules_of_dataset(self, dataset):
        return list(self._by_dataset.get(dataset, []))

    def rule_enabled(self, rid):
        r = self.rules[rid]
        return r.get("enabled", True) and any(self.integrations.get(t, {}).get("enabled") for t in r["integrations"])


def load_index(path=None):
    path = path or INDEX_PATH
    if path not in _CACHE:
        if not os.path.exists(path):
            _CACHE[path] = Stock5Index({})
        else:
            with open(path, "r", encoding="utf-8") as fh:
                _CACHE[path] = Stock5Index(json.load(fh))
    return _CACHE[path]


# -- 4.x literals -------------------------------------------------------------
def literals_4x(pattern, engine):
    """Literal text runs a 4.x pattern requires (OS_Match alternatives, or the
    literal runs of an OS_Regex / PCRE2 expression)."""
    if not pattern:
        return []
    out = []
    for alt in _split_alternatives(pattern):
        if engine == "osmatch":
            out.append(alt.strip("^$"))
            continue
        cur, i = [], 0
        while i < len(alt):
            c = alt[i]
            if c == "\\" and i + 1 < len(alt):
                n = alt[i + 1]
                if n.isalnum() or (engine == "osregex" and n == "."):
                    out.append("".join(cur))
                    cur = []
                else:
                    cur.append(n)
                i += 2
                continue
            special = "^$()*+?" if engine == "osregex" else "^$.()[]{}*+?"
            if c in special:
                if engine != "osregex" and c in "*+?{" and cur:
                    cur.pop()
                if engine != "osregex" and c in "[{":
                    j = alt.find("]" if c == "[" else "}", i + 1)
                    i = j if j > 0 else i
                out.append("".join(cur))
                cur = []
                i += 1
                continue
            cur.append(c)
            i += 1
        out.append("".join(cur))
    return [x for x in out if len(x.strip()) >= 3]


def _split_alternatives(pattern):
    """Top-level ``|`` alternatives (an escaped ``\\|`` is a literal bar)."""
    out, cur, depth, i = [], [], 0, 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            cur.append(pattern[i:i + 2])
            i += 2
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth = max(0, depth - 1)
        if c == "|" and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    out.append("".join(cur))
    return out


def program_names_4x(field):
    if not field or not field.get("value"):
        return []
    out = []
    for alt in _split_alternatives(field["value"]):
        alt = alt.strip().strip("^$")
        if _TOKEN.match(alt):
            out.append(alt)
    return out


class Evidence:
    """4.x side of a source: what its events must contain."""

    def __init__(self, name):
        self.name = name
        self.programs = []   # (value, where)
        self.literals = []   # (value, where)
        self.tags = []       # (value, where)
        self.keys = []       # (value, where)

    def add_decoder(self, dec, where):
        for p in program_names_4x(dec.get("program_name")):
            self.programs.append((p, "%s <program_name>" % where))
        pm = dec.get("prematch")
        if pm and pm.get("value"):
            for lit in literals_4x(pm["value"], pm.get("engine") or "osregex"):
                self.literals.append((lit, "%s <prematch>" % where))

    def empty(self):
        return not (self.programs or self.literals or self.tags or self.keys)


def distinctive(text):
    """A literal that can be evidence: 10+ characters, or 4+ with a
    character that is not a letter or digit (``type=``, ``%ASA``). Plain
    short words (``user``, ``auth``) are not."""
    t = text.strip()
    if t in GENERIC_LITERALS:
        return False
    if len(t) >= 10:
        return True
    return len(t) >= MIN_LITERAL and any(not c.isalnum() for c in t)


def _norm_tag(text):
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def _match_decoder(ev, dname, dec):
    """[(confidence, method, text)] for one 5.x decoder."""
    pr = dec.get("probes") or {}
    out = []
    procs = set(pr.get("process_names", []))
    # 4.x program_name is the syslog program name: a 5.x decoder under the syslog decoder reads the same one
    syslog = SYSLOG_PARENT in dec.get("parents", [])
    for p, where in ev.programs:
        if p in procs:
            out.append((HIGH if syslog else MEDIUM, "program-name", "%s %r = %s process.name%s" % (
                where, p, dname, "" if syslog else " (not under the syslog decoder)")))
    req = pr.get("contains", []) + pr.get("starts_with", [])
    for l5 in req:
        s5 = l5.strip()
        if not distinctive(s5):
            continue
        for l4, where in ev.literals:
            if s5 in l4:
                conf = HIGH if len(s5) >= STRONG_LITERAL else MEDIUM
                out.append((conf, "check-literal", "%s %r contains %r of %s" % (where, l4, s5, dname)))
            elif len(l4.strip()) >= STRONG_LITERAL and distinctive(l4) and l4.strip() in l5:
                out.append((MEDIUM, "partial-literal", "%s %r is part of %r of %s" % (where, l4, l5, dname)))
    for frag in pr.get("regex_fragments", []):
        f = frag.strip()
        if len(f) < STRONG_LITERAL or not distinctive(f):
            continue
        for l4, where in ev.literals:
            if f in l4:
                out.append((MEDIUM, "partial-literal", "%s %r contains regex fragment %r of %s" % (where, l4, f, dname)))
    tags = set(pr.get("json_tags", []))
    norm = {_norm_tag(t): t for t in tags}
    for t, where in ev.tags:
        if t in tags:
            out.append((HIGH, "json-tag", "%s %r = _tmp_json.integration of %s" % (where, t, dname)))
        elif len(_norm_tag(t)) >= MIN_LITERAL and _norm_tag(t) in norm:
            out.append((MEDIUM, "json-tag", "%s %r is %r of %s without separators (the 4.x collector may differ)"
                        % (where, t, norm[_norm_tag(t)], dname)))
    keys = set(pr.get("json_keys", []))
    have = {k for k, _w in ev.keys}
    if len(keys) >= 2 and keys <= have:
        where = sorted({w for k, w in ev.keys if k in keys})[0]
        out.append((MEDIUM, "json-keys", "%s: JSON keys %s are all required by %s" % (
            where.split(" <")[0], ", ".join(sorted(keys)), dname)))
    return out


def match_source(ev, index):
    """Best 5.x integration for the evidence: dict with ``integration``,
    ``method``, ``confidence``, ``evidence`` (list) and ``others``; None."""
    by_integ = {}
    for dname, dec in sorted(index.decoders.items()):
        found = _match_decoder(ev, dname, dec)
        if found:
            by_integ.setdefault(dec["integration"], []).extend(found)
    if by_integ:
        def score(item):
            t, found = item
            best = max(_RANK[c] for c, _m, _t in found)
            return (-best, -sum(1 for c, _m, _t in found if _RANK[c] == best), t)
        ranked = sorted(by_integ.items(), key=score)
        t, found = ranked[0]
        best = max(found, key=lambda f: _RANK[f[0]])
        texts = []
        for f in sorted(found, key=lambda f: (-_RANK[f[0]], f[2])):
            if f[2] not in texts:
                texts.append(f[2])
        return {"integration": t, "method": best[1], "confidence": best[0], "evidence": texts[:3],
                "others": [x[0] for x in ranked[1:3]]}
    return _match_name(ev.name, index)


def _tokens(name):
    return {t for t in re.split(r"[-_. ,:/]+", (name or "").lower()) if t and t not in _NAME_STOP}


def _match_name(name, index):
    toks = _tokens(name)
    if not toks:
        return None
    hits = []
    for t, integ in sorted(index.integrations.items()):
        if not integ.get("decoders") or t in _NO_NAME_MATCH:
            continue
        tt = _tokens(t)
        if tt and tt <= toks:
            hits.append(t)
    if not hits:
        # the first word of an integration title (eset-protect), when no other integration starts with it
        heads = {}
        for t, integ in sorted(index.integrations.items()):
            if integ.get("decoders") and t not in _NO_NAME_MATCH:
                heads.setdefault(re.split(r"[-_. ]+", t)[0], []).append(t)
        for tok in sorted(toks):
            if len(tok) >= MIN_LITERAL and len(heads.get(tok, [])) == 1:
                hits.append(heads[tok][0])
    if not hits:
        return None
    order = [x for x in re.split(r"[-_. ,:/]+", (name or "").lower()) if x]

    def first(t):
        return min([order.index(x) for x in _tokens(t) if x in order] or [len(order)])
    hits.sort(key=lambda t: (-len(_tokens(t)), first(t), t))
    return {"integration": hits[0], "method": "name", "confidence": LOW,
            "evidence": ["source name %r names integration %s (no evidence from the event)" % (name, hits[0])],
            "others": hits[1:3]}


# -- stock 4.x anchors ----------------------------------------------------------
class _StockResolver:
    def __init__(self, stock):
        self.stock = stock
        self._rule = {}
        self._group = {}
        self._members = {}
        for r in stock.rules:
            for g in r.get("groups", []):
                self._members.setdefault(g, []).append(r)

    def decoders_of_ref(self, ref):
        kind, _, name = ref.partition(":")
        if kind == "decoder":
            return Counter({name: 1})
        if kind == "rule":
            return self._rule_decoders(name, 0)
        if kind == "group":
            return self._group_decoders(name, 0)
        return Counter()

    def _rule_decoders(self, rid, depth):
        if rid in self._rule:
            return self._rule[rid]
        self._rule[rid] = Counter()  # cycle guard
        out = Counter()
        if depth < 40:
            for r in self.stock.rules_by_id.get(rid, [])[:1]:
                if r.get("decoded_as"):
                    out[r["decoded_as"]] += 1
                    continue
                parents = r.get("parents") or {}
                for key in ("if_sid", "if_matched_sid"):
                    for p in _ids(parents.get(key)):
                        out.update(self._rule_decoders(p, depth + 1))
                for key in ("if_group", "if_matched_group"):
                    g = parents.get(key)
                    if g and not out:
                        out.update(self._group_decoders(g if isinstance(g, str) else g[0], depth + 1))
        self._rule[rid] = out
        return out

    def _group_decoders(self, group, depth):
        if group in self._group:
            return self._group[group]
        self._group[group] = Counter()
        out = Counter()
        if depth < 40:
            for r in self._members.get(group, [])[:200]:
                out.update(self._rule_decoders(r["id"], depth + 1))
        self._group[group] = out
        return out


def _ids(value):
    if not value:
        return []
    if isinstance(value, list):
        vals = value
    else:
        vals = [value]
    out = []
    for v in vals:
        out.extend(x for x in re.split(r"[\s,]+", str(v)) if x)
    return out


# -- custom rule facts ------------------------------------------------------------
def rule_techniques(rule):
    """(technique ids, where): from ``<mitre>``, else from the description
    (``Mitre ATT&CK T1077, ...``), else ([], None)."""
    out = set()
    for e in rule.get("mitre") or []:
        vals = e.values() if isinstance(e, dict) else [e]
        for v in vals:
            for x in (v if isinstance(v, list) else [v]):
                out.update(t.upper() for t in _TECH.findall(str(x).upper()))
    if out:
        return sorted(out), "mitre"
    desc = _DESC_TECH.findall(rule.get("description") or "")
    if desc:
        return sorted(set(desc)), "description"
    return [], None


def rule_event_ids(rule):
    out = set()
    for f in rule.get("fields") or []:
        if f.get("name", "").lower() == "win.system.eventid" and not f.get("negate"):
            out.update(re.findall(r"\d+", f.get("value") or ""))
    return out


def _num(x):
    return (len(x), x)


def _base(t):
    return t.split(".")[0]


def _tech_match(custom, stock):
    exact = sorted(set(custom) & set(stock))
    if exact:
        return exact, "exact"
    base = sorted({_base(t) for t in custom} & {_base(t) for t in stock})
    return base, ("base" if base else None)


def is_tuning(item, rule):
    codes = {c["code"] for c in item.get("codes", [])}
    if codes & {"RM-R-SILENCER", "RM-R-SILENCER-STOCK", "RM-R-OVERWRITE-STOCK"}:
        return True
    lvl = item.get("level")
    if lvl is None and rule is not None:
        lvl = rule.get("level")
    try:
        return int(lvl) <= 1
    except (TypeError, ValueError):
        return False


# -- the section ---------------------------------------------------------------
def build_section(inv, plan_items, decisions=None, index=None, stock=None, pack=None):
    """The ``stock5`` block of ``report.json``."""
    index = index or load_index()
    if not index.integrations:
        return None
    stock = stock or load_stock_index()
    pack = pack or load_pack()
    resolver = _StockResolver(stock)
    rules_by_uid = {"rule:%s:%d" % (r["file"], r["line"]): r for r in inv.get("rules", [])}
    decs = list(inv.get("decoders", []))
    dec_by_pos = {(d["file"], d["line"]): d for d in decs}
    custom_names = {d["name"] for d in decs}
    integ_decs = {}  # custom integration (root decoder name) -> 4.x decoders
    for it in plan_items:
        if it["kind"] == "decoder" and it.get("integration"):
            d = dec_by_pos.get((it["file"], it["line"]))
            if d is not None:
                integ_decs.setdefault(it["integration"], []).append(d)
    feeds = (decisions or {}).get("feeds", {})

    sources = OrderedDict()   # key -> source dict
    rule_rows = []
    excluded = 0
    for it in plan_items:
        if it["kind"] != "rule":
            continue
        if it["state"] == "NOT_APPLICABLE":
            excluded += 1
            continue
        rule = rules_by_uid.get(it["uid"])
        key, mk = _source_key(it, pack, resolver)
        if key not in sources:
            sources[key] = mk(index, stock, pack, integ_decs, custom_names, feeds, inv)
        src = sources[key]
        verdict, why = _rule_verdict(it, rule, src, index, pack)
        src["rules"] += 1
        src["by_verdict"][verdict] += 1
        rule_rows.append({"ref": it["ref"], "uid": it["uid"], "source": src["key"], "verdict": verdict, "why": why})

    by_verdict = Counter(r["verdict"] for r in rule_rows)
    by_source_verdict = Counter(s["verdict"] for s in sources.values())
    out_sources = []
    merged = OrderedDict()  # feed name -> roots of that feed with no 5.x integration (one row per feed)
    for s in sorted(sources.values(), key=lambda s: (SOURCE_VERDICTS.index(s["verdict"]), -s["rules"], s["key"])):
        e = {k: v for k, v in s.items() if k not in ("by_verdict", "rule_ids", "event_ids")}
        e["by_verdict"] = {v: s["by_verdict"].get(v, 0) for v in RULE_VERDICTS if s["by_verdict"].get(v)}
        if s["kind"] == "feed" and s["verdict"] == V_NONE:
            feed = s["key"][len("feed:"):].split("#")[0]
            if feed not in merged:
                merged[feed] = dict(e, key="feed:%s#*" % feed, roots=[], by_verdict=Counter(), rules=0)
                out_sources.append(merged[feed])
            m = merged[feed]
            m["roots"].append(s["key"].split("#", 1)[1] if "#" in s["key"] else "")
            m["rules"] += s["rules"]
            m["by_verdict"].update(s["by_verdict"])
            continue
        out_sources.append(e)
    for feed, m in merged.items():
        m["by_verdict"] = {v: m["by_verdict"].get(v, 0) for v in RULE_VERDICTS if m["by_verdict"].get(v)}
        shown = ", ".join(m["roots"][:5]) + (" and %d more" % (len(m["roots"]) - 5) if len(m["roots"]) > 5 else "")
        m["label"] = "feed %s, %d root rule(s) with no match (%s)" % (feed, len(m["roots"]), shown)
    out_sources.sort(key=lambda s: (SOURCE_VERDICTS.index(s["verdict"]), -s["rules"], s["key"]))
    gaps = [{"source": s["key"], "label": s["label"], "integration": s["integration"], "rules": s["rules"],
             "verdict": s["verdict"]}
            for s in out_sources if s["verdict"] in (V_NONE, V_DECODE_ONLY) and s["kind"] != "none"]
    return {
        "catalog": {k: index.source.get(k) for k in ("consumer", "context", "offset", "snapshot_at")},
        "note": "Offline estimate from the stock 5.x index: no event was decoded and no rule was run. "
                "A candidate shares the MITRE technique (and for Windows the event code) with a stock rule, not "
                "its condition: confirm it with the live coverage command (planned). The generic stock rules "
                "(wazuh-generic-1, wazuh-generic-2, wazuh-ioc) are not counted for any source. The tool never "
                "drops a rule.",
        "rules": len(rule_rows),
        "not_applicable": excluded,
        "by_verdict": {v: by_verdict.get(v, 0) for v in RULE_VERDICTS},
        "sources_by_verdict": {v: by_source_verdict.get(v, 0) for v in SOURCE_VERDICTS},
        "feeds_by_verdict": _feeds_by_verdict(sources),
        "sources": out_sources,
        "gaps": gaps,
        "items": rule_rows,
    }


def _feeds_by_verdict(sources):
    """One verdict per feed (its best root), comparable with a count by feed name."""
    best = {}
    for s in sources.values():
        if s["kind"] != "feed":
            continue
        feed = s["key"][len("feed:"):].split("#")[0]
        rank = SOURCE_VERDICTS.index(s["verdict"])
        best[feed] = min(best.get(feed, rank), rank)
    c = Counter(SOURCE_VERDICTS[r] for r in best.values())
    return {v: c.get(v, 0) for v in SOURCE_VERDICTS if v != S_NO_SOURCE}


def _source_key(it, pack, resolver):
    src = it.get("source") or {}
    kind = src.get("kind")
    integ = it.get("integration")
    integ = integ if isinstance(integ, list) else ([integ] if integ else [])
    if kind == "custom" and integ:
        name = integ[0]
        return "decoder:%s" % name, lambda *a: _custom_source(name, *a)
    if kind == "feed" and integ:
        name = integ[0]
        roots = list(src.get("feeds") or [])[:1]
        key = "feed:%s#%s" % (name, roots[0]) if roots else "feed:%s" % name
        return key, lambda *a: _feed_source(name, roots, *a)
    if kind == "stock":
        refs = src.get("stock_refs") or []
        win = [r for r in refs if pack.knows(r)]
        if win:
            scopes = Counter()
            for r in win:
                for alt in pack.alternatives(r):
                    scopes[alt.get("scope") or "*"] += 1
            scope = sorted(scopes.items(), key=lambda kv: (-kv[1], kv[0]))[0][0] if scopes else "*"
            return "windows:%s" % scope, lambda *a: _windows_source(scope, *a)
        decs = Counter()
        for r in refs:
            decs.update(resolver.decoders_of_ref(r))
        if decs:
            name = sorted(decs.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
            return "stock:%s" % name, lambda *a: _stock_source(name, *a)
        return "stock:?", lambda *a: _none_source("stock:?", "stock content with no 4.x decoder", "stock")
    return "none", lambda *a: _none_source("none", "no source (RM-R-NO-SOURCE)", "none")


def _new_source(key, label, kind):
    return {"key": key, "label": label, "kind": kind, "integration": None, "decoded_by": None, "enabled": None,
            "stock_rules": 0, "method": None, "confidence": None, "evidence": [], "others": [],
            "verdict": V_NONE, "rules": 0, "by_verdict": Counter(), "rule_ids": [], "dataset": None}


def _finish(src, match, index, rule_ids=None, enabled=None):
    if match:
        src.update({k: match[k] for k in ("integration", "method", "confidence", "evidence", "others")})
        integ = index.integrations.get(match["integration"], {})
        src["decoded_by"] = match["integration"]
        src["rule_ids"] = rule_ids if rule_ids is not None else index.rules_of(match["integration"])
        src["stock_rules"] = len(src["rule_ids"])
        on = integ.get("enabled", False) if enabled is None else enabled
        rules_on = any(index.rule_enabled(r) for r in src["rule_ids"])
        src["enabled"] = bool(on)
        if not src["rule_ids"]:
            src["verdict"] = V_DECODE_ONLY
        elif on and rules_on:
            src["verdict"] = S_RULES
        else:
            src["verdict"] = S_RULES_IF_ENABLED
    return src


def _custom_source(name, index, stock, pack, integ_decs, custom_names, feeds, inv):
    src = _new_source("decoder:%s" % name, "custom decoder %s" % name, "custom")
    ev = Evidence(name)
    for d in integ_decs.get(name, []):
        ev.add_decoder(d, "decoder %s" % d["name"])
        parent = d.get("parent")
        if parent and parent not in custom_names:
            for sd in stock.decoder_names.get(parent, [])[:1]:
                ev.add_decoder(sd, "stock parent decoder %s" % parent)
    return _finish(src, match_source(ev, index), index)


def _feed_source(name, roots, index, stock, pack, integ_decs, custom_names, feeds, inv):
    key = "feed:%s#%s" % (name, roots[0]) if roots else "feed:%s" % name
    src = _new_source(key, "feed %s, root rule %s" % (name, roots[0]) if roots else "feed %s" % name, "feed")
    ev = Evidence(name)
    by_id = {}
    for r in inv.get("rules", []):
        by_id.setdefault(str(r["id"]), []).append(r)
    for rid in roots:
        seen = (feeds.get(str(rid)) or {}).get("seen_in")
        cands = by_id.get(str(rid), [])
        root = next((r for r in cands if "%s:%d" % (r["file"], r["line"]) == seen), cands[0] if cands else None)
        if root is None:
            continue
        where = "feed root rule %s" % rid
        for c in root.get("conditions", []):
            if c.get("elem") == "location" and not c.get("negate"):
                for lit in literals_4x(c.get("value"), c.get("engine") or "osmatch"):
                    ev.literals.append((lit, "%s <location>" % where))
                    ev.tags.append((lit.strip(), "%s <location>" % where))
        for f in root.get("fields", []):
            if f.get("negate"):
                continue
            fname = f.get("name", "")
            if fname.split(".")[-1] == "integration":
                for lit in literals_4x(f.get("value"), f.get("engine") or "osregex"):
                    ev.tags.append((lit.strip(), "%s <field name=%s>" % (where, fname)))
            parts = fname.split(".")
            for i in range(1, len(parts) + 1):
                ev.keys.append((".".join(parts[:i]), "%s <field name=%s>" % (where, fname)))
        if root.get("decoded_as") and root["decoded_as"] != "json":
            for sd in stock.decoder_names.get(root["decoded_as"], [])[:1]:
                ev.add_decoder(sd, "stock decoder %s" % root["decoded_as"])
    ev.name = " ".join([name] + sorted({k.split(".")[0] for k, _w in ev.keys}) + [t for t, _w in ev.tags])
    return _finish(src, match_source(ev, index), index)


def _stock_source(name, index, stock, pack, integ_decs, custom_names, feeds, inv):
    src = _new_source("stock:%s" % name, "stock 4.x decoder %s" % name, "stock")
    ev = Evidence(name)
    for sd in stock.decoder_names.get(name, [])[:1]:
        ev.add_decoder(sd, "stock decoder %s" % name)
    # children with the same name add their prematch (e.g. sshd variants)
    for sd in stock.decoder_names.get(name, [])[1:6]:
        ev.add_decoder(sd, "stock decoder %s" % name)
    match = match_source(ev, index) if not ev.empty() else _match_name(name, index)
    return _finish(src, match, index)


def _windows_source(scope, index, stock, pack, integ_decs, custom_names, feeds, inv):
    label = "Windows %s channel" % scope if scope != "*" else "Windows (any channel)"
    src = _new_source("windows:%s" % scope, label, "windows")
    integ = pack.integration or "windows"
    if scope != "*":
        rule_ids = index.rules_of_dataset(scope)
    else:
        rule_ids = sorted({r for t in index.integrations if t == integ or t.startswith(integ + "-")
                           for r in index.rules_of(t)})
    match = {"integration": integ, "method": "windows-pack", "confidence": HIGH,
             "evidence": ["Windows pack: stock chain from rule %s (decoded_as %s) -> 5.x integration %s; scope %s = "
                          "event.dataset of %d stock rule(s)" % (pack.data.get("root", {}).get("rule", "60000"),
                                                                pack.root_decoder, integ, scope, len(rule_ids))],
             "others": []}
    src["dataset"] = None if scope == "*" else scope
    return _finish(src, match, index, rule_ids=rule_ids)


def _none_source(key, label, kind):
    src = _new_source(key, label, kind)
    if kind == "none":
        src["verdict"] = S_NO_SOURCE
    return src


def _rule_verdict(it, rule, src, index, pack):
    if is_tuning(it, rule):
        return V_TUNING, "level 0-1, silencer or overwrite of stock content"
    if src["kind"] == "none":
        return V_NOT_COMPARABLE, "no source"
    if not src["integration"]:
        return V_NONE, "no 5.x integration decodes %s" % src["label"]
    if not src["rule_ids"]:
        return V_DECODE_ONLY, "%s has no stock rule in the catalog" % src["integration"]
    techs, tech_src = rule_techniques(rule or {})
    if not techs:
        return V_NOT_COMPARABLE, "no MITRE technique in the 4.x rule"
    from_desc = " (technique read from the description)" if tech_src == "description" else ""
    windows = src["kind"] == "windows"
    ids = set()
    if windows:
        ids = rule_event_ids(rule or {})
        if not ids:
            for ref in (it.get("source") or {}).get("stock_refs") or []:
                for alt in pack.alternatives(ref):
                    ids.update(alt.get("event_ids") or [])
    if windows and not ids:
        return V_NOT_COMPARABLE, "Windows rule with no known event id (technique %s): no event code to compare" % (
            ", ".join(techs))
    best = None
    for rid in src["rule_ids"]:
        r = index.rules[rid]
        common, how = _tech_match(techs, r.get("techniques", []))
        if not common:
            continue
        codes = set(r.get("event_codes", []))
        if windows and not (codes & ids):
            continue
        on = index.rule_enabled(rid) and src["enabled"]
        cand = (on, how == "exact", rid)
        if best is None or cand[:2] > best[0][:2]:
            best = (cand, r, common, how, sorted(codes & ids) if windows else [])
    if best is None:
        return V_NO_CANDIDATE, "no stock rule of %s%s with technique %s%s%s" % (
            src["integration"], (" (event.dataset %s)" % src["dataset"]) if src.get("dataset") else "",
            ", ".join(techs), (" and event id %s" % ", ".join(sorted(ids, key=_num))) if ids else "", from_desc)
    (on, _exact, rid), r, common, how, codes = best
    why = "stock rule %r (%s): technique %s (%s)%s%s" % (r.get("title"), rid, ", ".join(common), how,
                                                        (", event code %s" % ", ".join(codes)) if codes else "",
                                                        from_desc)
    if on:
        return V_CANDIDATE, why
    off = [t for t in r["integrations"] if not index.integrations.get(t, {}).get("enabled")]
    if not src["enabled"]:
        off.append(src["integration"])
    return V_IF_ENABLED, why + "; enable %s" % ", ".join(sorted(set(off)))


# -- report.md -------------------------------------------------------------------
TOP_CANDIDATES = 50


def _md(text):
    return md(text)


def render_markdown(sec):
    """Lines of the "5.x stock for your sources" section of ``report.md``."""
    out = []
    w = out.append
    cat = sec["catalog"]
    w("## 5.x stock for your sources")
    w("")
    w("Stock 5.x catalog: `%s` / `%s`, offset %s (snapshot %s)." % (
        cat.get("consumer"), cat.get("context"), cat.get("offset"), cat.get("snapshot_at")))
    w("")
    w("%s" % sec["note"])
    w("")
    w("Custom rules: %d (%d `NOT_APPLICABLE` left out)." % (sec["rules"], sec["not_applicable"]))
    w("")
    w("| Verdict | Custom rules | Share |")
    w("|---|---:|---:|")
    total = sec["rules"]
    for v, n in sec["by_verdict"].items():
        w("| %s | %d | %s |" % (v, n, ("%.1f %%" % (100.0 * n / total)) if total else "0.0 %"))
    w("")
    w("| Source | 5.x integration | Enabled | Stock rules | Source verdict | Custom rules | Candidates | Match |")
    w("|---|---|---|---:|---|---:|---:|---|")
    for s in sec["sources"]:
        cands = s["by_verdict"].get(V_CANDIDATE, 0) + s["by_verdict"].get(V_IF_ENABLED, 0)
        w("| %s | %s | %s | %d | %s | %d | %d | %s |" % (
            _md(s["label"]), ("`%s`" % s["integration"]) if s["integration"] else "none",
            "" if s["enabled"] is None else ("yes" if s["enabled"] else "no"), s["stock_rules"], s["verdict"],
            s["rules"], cands, ("%s, %s" % (s["method"], s["confidence"])) if s["method"] else ""))
    w("")
    w("Source verdicts: %s." % ", ".join("%s %d" % (v, n) for v, n in sec["sources_by_verdict"].items()))
    if any(sec.get("feeds_by_verdict", {}).values()):
        w("Feeds (best root per feed): %s. Feed roots with no match are one row per feed." % ", ".join(
            "%s %d" % (v, n) for v, n in sec["feeds_by_verdict"].items()))
    w("")
    ev = [s for s in sec["sources"] if s["evidence"]]
    if ev:
        w("Evidence of each match:")
        w("")
        for s in ev:
            note = " Enable `%s`." % s["integration"] if s["verdict"] == S_RULES_IF_ENABLED else ""
            w("- %s -> `%s`: %s.%s" % (_md(s["label"]), s["integration"], _md(s["evidence"][0]), note))
        w("")
    cands = [r for r in sec["items"] if r["verdict"] in (V_CANDIDATE, V_IF_ENABLED)]
    if cands:
        w("Covered candidates (offline, %d; first %d):" % (len(cands), min(len(cands), TOP_CANDIDATES)))
        w("")
        w("| Custom rule | Verdict | Stock 5.x rule |")
        w("|---|---|---|")
        for r in cands[:TOP_CANDIDATES]:
            w("| `%s` | %s | %s |" % (r["ref"], r["verdict"], _md(r["why"])))
        w("")
    w("### Gap list")
    w("")
    if sec["gaps"]:
        w("Sources with no 5.x integration, or with an integration that has no stock rule (content roadmap):")
        w("")
        w("| Source | 5.x integration | Custom rules | Gap |")
        w("|---|---|---:|---|")
        for g in sec["gaps"]:
            w("| %s | %s | %d | %s |" % (_md(g["label"]), ("`%s`" % g["integration"]) if g["integration"] else "none",
                                         g["rules"], g["verdict"]))
    else:
        w("None.")
    w("")
    return out
