"""The Windows pack: the 5.x field map (``rmig/data/windows-map-5.0.json``)
plus the stock Windows chains, derived at run time from the user's 4.x ruleset.

It resolves the stock Windows references of custom rules (``rule:61603``,
``group:sysmon_event1``, ...) without a decision:

* every stock rule whose chain starts at rule 60000 (decoder
  ``windows_eventchannel``) is the OR of its paths, each path the AND of its
  ``<field>`` conditions (``alternatives``);
* ``win.system.*`` conditions become WCS conditions (``event.code``; value
  tables for ``channel`` and ``severityValue``);
* ``win.eventdata.*`` fields map to WCS per scope (the 5.x child decoder of the
  channel) and event id, only where the 5.x decoders copy the value.

A ``decisions.json`` entry from the user wins over the pack. 4.x compares field
names without case, so lookups here are case-insensitive.
"""

import json
import os

from . import stock as stock_mod
from .stock import DATA_DIR

PACK_PATH = os.path.join(DATA_DIR, "windows-map-5.0.json")
_CACHE = {}
MAX_PATHS = 64
MAX_DEPTH = 40


class WindowsPack:
    def __init__(self, data):
        self.data = data
        root = data.get("root") or {}
        self.integration = root.get("integration")
        self.root_decoder = root.get("decoder")
        self.rules = data.get("rules", {})
        self.groups = data.get("groups", {})
        self.fields = data.get("fields", {})
        self.system = data.get("system", {})
        self.overrides = data.get("overrides", {})
        self.discarded = set((data.get("discarded_event_ids") or {}).get("ids", []))

    # -- references --------------------------------------------------------
    def knows(self, key):
        kind, _, name = key.partition(":")
        if kind == "rule":
            return name in self.rules
        if kind == "group":
            return name in self.groups
        return False

    def partial(self, key):
        """Why a group entry leaves out members (None when it does not)."""
        kind, _, name = key.partition(":")
        if kind == "group":
            return self.groups.get(name, {}).get("why")
        if kind == "rule":
            return self.rules.get(name, {}).get("why")
        return None

    def alternatives(self, key):
        """The paths of a stock rule or of the members of a group."""
        kind, _, name = key.partition(":")
        if kind == "rule":
            return list(self.rules.get(name, {}).get("alternatives", []))
        if kind == "group":
            out = []
            for rid in self.groups.get(name, {}).get("members", []):
                for alt in self.rules.get(rid, {}).get("alternatives", []):
                    if alt not in out:
                        out.append(alt)
            return out
        return []

    # -- fields ----------------------------------------------------------------
    def is_windows_field(self, name):
        low = name.lower()
        return low.startswith("win.system.") or low.startswith("win.eventdata.")

    def eventdata(self, name, ctx):
        """(wcs, fidelity, why) of a ``win.eventdata`` field for every context
        (``[(scope, [event ids] or None)]``), or None when one context has no
        mapping or two contexts disagree."""
        by_scope = self.fields.get(name.lower())
        if not by_scope or not ctx:
            return None
        found = set()
        fidelity, why = "exact", []
        for scope, eids in ctx:
            table = by_scope.get(scope or "*")
            if not table:
                return None
            for eid in (eids or ["*"]):
                ent = table.get(eid) or (table.get("*") if eid != "*" else None)
                if ent is None:
                    return None
                found.add(ent["wcs"])
                if ent.get("fidelity") == "approximate":
                    fidelity = "approximate"
                    if ent.get("why") and ent["why"] not in why:
                        why.append(ent["why"])
        if len(found) != 1:
            return None
        return found.pop(), fidelity, why

    def system_direct(self, name, ctx):
        ent = self.system.get(name.lower())
        if not ent or "scopes" not in ent or not ctx:
            return None
        found = set()
        for scope, _eids in ctx:
            m = ent["scopes"].get(scope or "*")
            if not m:
                return None
            found.add(m["wcs"])
        return found.pop() if len(found) == 1 else None

    def value_table(self, name):
        ent = self.system.get(name.lower())
        if ent and "values" in ent:
            return ent["values"]
        return None


# -- stock chains -------------------------------------------------------------

def _stock_paths(rules_by_id, groups, rid, cache, depth=0):
    """Every path [top .. rid] through if_sid / if_group parents (None when too many)."""
    if rid in cache:
        return cache[rid]
    r = rules_by_id[rid]
    parents = []
    p = r["parents"]
    for sid in p.get("if_sid") or []:
        if sid in rules_by_id:
            parents.append(sid)
    for g in [p.get("if_group")] if p.get("if_group") else []:
        parents.extend(x for x in groups.get(g, []) if x != rid)
    if depth > MAX_DEPTH:
        cache[rid] = None
        return None
    if not parents:
        res = [[rid]]
    else:
        res = []
        for par in parents:
            sub = _stock_paths(rules_by_id, groups, par, cache, depth + 1)
            if sub is None:
                cache[rid] = None
                return None
            res.extend(path + [rid] for path in sub)
            if len(res) > MAX_PATHS:
                cache[rid] = None
                return None
    cache[rid] = res
    return res


def _rule_problem(r):
    if r["conditions"]:
        return "<%s> on the 4.x full log" % r["conditions"][0]["elem"]
    if r["lists"]:
        return "<list>"
    if r["correlation"] or "frequency" in r["attrs"] or r["parents"].get("if_matched_sid") \
            or r["parents"].get("if_matched_group"):
        return "correlation"
    if r["flags"]:
        return "<%s>" % sorted(r["flags"])[0]
    return None


def _literal(cond):
    from .translate.patterns import PatternError, literal_values

    try:
        return literal_values(cond["engine"], cond["value"])
    except PatternError:
        return None


def _flatten(path, rules_by_id, root_rule, implied, overrides):
    """(conditions, problem) of one path."""
    conds = []
    for pid in path:
        pr = _rule_problem(rules_by_id[pid])
        if pr:
            return None, "rule %s: %s" % (pid, pr)
        for f in rules_by_id[pid]["fields"]:
            c = {"name": f["name"], "engine": f["engine"], "value": f["value"], "negate": bool(f["negate"]), "rule": pid}
            if pid == root_rule and {"name": f["name"], "value": f["value"]} in implied:
                continue
            if (pid, f["name"].lower()) in overrides:
                c = {"override": "%s:%s" % (pid, f["name"].lower()), "rule": pid, "name": f["name"]}
            if c not in conds:
                conds.append(c)
    return conds, None


def _channel_and_ids(conds, overrides):
    channel, eids = None, None
    for c in conds:
        if c.get("override"):
            for rep in overrides[(c["rule"], c["name"].lower())]["replace"]:
                if rep["wcs"] == "event.code":
                    eids = list(rep["values"])
            continue
        if c["negate"]:
            continue
        low = c["name"].lower()
        if low == "win.system.channel":
            vals = _literal(c)
            if vals and len(vals) == 1:
                channel = vals[0]
        elif low == "win.system.eventid":
            vals = _literal(c)
            if vals:
                eids = sorted(set(vals) & set(eids) if eids else set(vals), key=lambda x: (len(x), x))
    return channel, eids


def _absorb(alts):
    """Drop an alternative whose conditions include another's."""
    keep = []
    for a in alts:
        ca = [json.dumps(c, sort_keys=True) for c in a["conditions"]]
        if any(set(json.dumps(c, sort_keys=True) for c in b["conditions"]) <= set(ca) and b is not a
               and (len(b["conditions"]) < len(ca) or alts.index(b) < alts.index(a)) for b in alts):
            continue
        keep.append(a)
    return keep


def derive_chains(stock_rules, wmap):
    """``rules``, ``groups`` and ``skipped`` of the pack from the stock rules:
    every stock rule whose chain starts at the root rule, flattened to the
    conditions of its paths, and the 4.x groups whose members are all such rules."""
    root = wmap.get("root") or {}
    root_rule, root_decoder = root.get("rule"), root.get("decoder")
    implied = root.get("implied") or []
    overrides = {}
    for key, o in (wmap.get("overrides") or {}).items():
        rid, _, fname = key.partition(":")
        overrides[(rid, fname)] = o
    channel_scope = {sc["channel"].lower(): k for k, sc in sorted((wmap.get("scopes") or {}).items())}
    rules_by_id, groups = {}, {}
    for r in stock_rules:
        rules_by_id.setdefault(r["id"], r)
    for r in stock_rules:
        for g in r["groups"]:
            groups.setdefault(g, []).append(r["id"])
    cache = {}
    rules_out, skipped_rules = {}, {}
    win_rooted = set()
    for rid in sorted(rules_by_id, key=int):
        paths = _stock_paths(rules_by_id, groups, rid, cache)
        if not paths:
            if paths is None:
                skipped_rules[rid] = "too many paths"
            continue
        win = [p for p in paths if p[0] == root_rule]
        if not win:
            continue
        win_rooted.add(rid)
        legacy = [p for p in paths if p[0] != root_rule]
        alts, problem = [], None
        for path in win:
            conds, problem = _flatten(path, rules_by_id, root_rule, implied, overrides)
            if problem:
                break
            channel, eids = _channel_and_ids(conds, overrides)
            alts.append({"path": path, "conditions": conds, "channel": channel, "event_ids": eids})
        if problem:
            skipped_rules[rid] = problem
            continue
        keep = _absorb(alts)
        for a in keep:
            a["scope"] = channel_scope.get((a["channel"] or "").lower())
            del a["channel"]
        rules_out[rid] = {"alternatives": keep}
        if legacy:
            rules_out[rid]["dropped_paths"] = len(legacy)
            rules_out[rid]["why"] = ("%d path(s) start at rule %s (%s), not at rule %s: 5.x has no source for them"
                                     % (len(legacy), legacy[0][0], rules_by_id[legacy[0][0]]["file"], root_rule))

    groups_out, skipped_groups = {}, {}
    for g in sorted(groups):
        ids = groups[g]
        if not any(i in rules_out for i in ids):
            continue
        missing = [i for i in ids if i not in rules_out]
        blocking = [i for i in missing if i in win_rooted]
        if blocking:
            skipped_groups[g] = "%d member rule(s) are not derived (first: %s)" % (len(blocking), blocking[0])
            continue
        if len(missing) * 2 > len(ids):
            skipped_groups[g] = "most member rules are not Windows eventchannel rules (%d of %d)" % (len(missing), len(ids))
            continue
        ids = [i for i in ids if i in rules_out]
        # a member whose every path goes through another member adds nothing
        mem = []
        for i in ids:
            paths = [a["path"] for a in rules_out[i]["alternatives"]]
            if all(any(o in p[:-1] for o in ids) for p in paths):
                continue
            mem.append(i)
        groups_out[g] = {"members": sorted(set(mem), key=int)}
        if missing:
            groups_out[g]["dropped"] = sorted(missing, key=int)
            groups_out[g]["why"] = ("%d member rule(s) hang from other 4.x decoders (first: %s, %s), not from %s: "
                                    "5.x has no source for them"
                                    % (len(missing), missing[0], rules_by_id[missing[0]]["file"], root_decoder))
    return {"rules": rules_out, "groups": groups_out, "skipped": {"rules": skipped_rules, "groups": skipped_groups}}


def _read_map(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_pack(path=None):
    """The pack for the active stock index (the field map alone without one)."""
    path = path or PACK_PATH
    index = stock_mod.active()
    cached = _CACHE.get(path)
    if cached is None or cached[0] is not index:
        data = _read_map(path)
        if index is not None and data:
            data = dict(data)
            data.update(derive_chains(index.rules, data))
        cached = _CACHE[path] = (index, WindowsPack(data))
    return cached[1]
