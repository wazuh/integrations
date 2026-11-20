"""Tuning of stock rules to redo by hand.

A 4.x level 0 rule that silences a stock rule, and a rule that overwrites a stock rule (``overwrite="yes"`` or a
modified copy), tuned the stock ruleset. 5.x stock rules are read only: there is no supported way to disable one
stock rule, add an exclusion to it or change its level. The tool writes one row per silencer or
overwrite with the stock rule, the 4.x condition and the options that exist; the customer decides. Not
live-verified.
"""

from .. import model4 as m

OPTIONS = {
    "disable": "disable the whole stock integration or standard detector (kept in wazuh-user-overrides): every rule "
               "of it stops, not only this one",
    "filter": "an engine filter in the standard policy that drops the matching events: they reach no rule at all",
    "copy": "a custom copy of the stock rule with the 4.x condition as a `not` selection, and the stock integration "
            "or detector disabled: the copy gets no upstream fixes (custom limits: 100 rules, 50 per detector, "
            "10 detectors)",
    "copy-level": "a custom copy of the stock rule with the new level, and the stock integration or detector "
                  "disabled: the copy gets no upstream fixes",
}


def _condition(item):
    """The 4.x condition of a rule, as short XML."""
    parts = []
    if item.get("decoded_as"):
        parts.append("<decoded_as>%s</decoded_as>" % item["decoded_as"])
    for key in ("if_sid", "if_group"):
        val = item.get("parents", {}).get(key)
        if val:
            parts.append("<%s>%s</%s>" % (key, ",".join(val) if isinstance(val, list) else val, key))
    for c in item.get("conditions", []):
        val = c.get("value")
        if val is None:
            val = ",".join(c.get("values", []))
        neg = ' negate="yes"' if c.get("negate") else ""
        parts.append("<%s%s>%s</%s>" % (c.get("elem"), neg, val, c.get("elem")))
    for f in item.get("fields", []):
        neg = ' negate="yes"' if f.get("negate") else ""
        parts.append('<field name="%s"%s>%s</field>' % (f["name"], neg, f["value"]))
    for li in item.get("lists", []):
        parts.append('<list field="%s" lookup="%s">%s</list>' % (li["field"], li["lookup"], li["path"]))
    return " ".join(parts)


def _stock_5x(key, clf):
    """What the tool knows of the 5.x side of a stock reference (``rule:<id>`` or ``group:<name>``)."""
    entry = clf.decisions.get("stock", {}).get(key) or {}
    if entry.get("integration"):
        return {"source": "decisions.json", "integration": entry["integration"], "selection": entry.get("selection")}
    if clf.winpack.knows(key):
        conds = []
        for alt in clf.winpack.alternatives(key)[:3]:
            conds.append(" AND ".join("%s %s" % (c.get("name"), c.get("value", c.get("values")))
                                      for c in alt.get("conditions", [])))
        return {"source": "Windows pack", "integration": clf.winpack.integration or "windows",
                "selection": None, "paths": conds}
    return None


def _stock_info(key, clf):
    kind, _, name = key.partition(":")
    entries = clf.stock.rules_by_id.get(name) or [] if kind == "rule" else []
    if not entries:
        return {"ref": key, "location": None, "level": None}
    e = entries[0]
    return {"ref": key, "location": "ruleset/rules/%s:%d" % (e["file"], e["line"]), "level": e["level"]}


def _direct_refs(item):
    """Stock references a rule hangs from, as written: ``rule:<id>`` per if_sid, ``group:<name>`` per if_group."""
    p = item.get("parents", {})
    sids = p.get("if_sid") or []
    if isinstance(sids, str):
        sids = [x.strip() for x in sids.replace(" ", ",").split(",") if x.strip()]
    refs = ["rule:%s" % x for x in sids]
    groups = p.get("if_group") or []
    if isinstance(groups, str):
        groups = [g.strip() for g in groups.replace("|", ",").split(",") if g.strip()]
    refs += ["group:%s" % g for g in groups]
    return refs


def analyze(clf):
    rows = []
    for uid in sorted(clf.items, key=lambda u: (clf.items[u]["file"], clf.items[u]["line"], u)):
        item = clf.items[uid]
        if item["kind"] != m.RULE:
            continue
        codes = clf.acc[uid].codes
        if "RM-R-SILENCER-STOCK" in codes:
            targets = [t.split(":", 1)[1] for t in clf.extra.get(uid, {}).get("exclusion_stock_targets", [])]
            # the stock rule or group it hangs from; 4.x also silenced its alerting ancestors and later siblings
            direct = [r for r in _direct_refs(item) if r.split(":", 1)[1] in targets or r.startswith("group:")]
            main = direct[0] if direct else ("rule:%s" % targets[0] if targets else None)
            if main is None:
                continue
            rows.append({"rule": item["id"], "origin": "%s:%d" % (item["file"], item["line"]),
                         "kind": "silencer", "stock": _stock_info(main, clf), "stock_5x": _stock_5x(main, clf),
                         "silenced_in_4x": len(targets),
                         "condition_4x": _condition(item),
                         "options": ["copy", "filter", "disable"],
                         "decision": "needs customer decision", "verified": "not live-verified"})
        if "RM-R-OVERWRITE-STOCK" in codes:
            info = _stock_info("rule:%s" % item["id"], clf)
            new_level = item.get("level")
            silences = new_level == 0
            change = []
            if info["level"] is not None and new_level is not None and info["level"] != new_level:
                change.append("level %s -> %s" % (info["level"], new_level))
            change.append("other changes: compare with %s" % (info["location"] or "the stock rule"))
            rows.append({"rule": item["id"], "origin": "%s:%d" % (item["file"], item["line"]),
                         "kind": "overwrite", "stock": info, "stock_5x": _stock_5x("rule:%s" % item["id"], clf),
                         "condition_4x": _condition(item), "change": "; ".join(change),
                         "options": ["copy", "filter", "disable"] if silences else ["copy-level", "disable"],
                         "decision": "needs customer decision", "verified": "not live-verified"})
    return rows


def render(rows, w, esc):
    w("## Tuning to redo")
    w("")
    if not rows:
        w("No level 0 rule silences a stock rule and no rule overwrites one.")
        w("")
        return
    w("These rules tuned the 4.x stock ruleset. 5.x stock rules are read only: no supported way disables one stock "
      "rule, adds an exclusion to it or changes its level, so this tuning is lost unless you redo it. Each row needs "
      "your decision; none is live-verified. Options:")
    w("")
    for key in ("copy", "copy-level", "filter", "disable"):
        w("- `%s`: %s." % (key, OPTIONS[key]))
    w("")
    w("| 4.x rule | Kind | Stock | 5.x side | 4.x condition | Options |")
    w("|---|---|---|---|---|---|")
    for r in rows:
        s = r["stock"]
        stock = "`%s`%s" % (s["ref"], " (`%s`, level %s)" % (s["location"], s["level"]) if s["location"] else "")
        if r.get("silenced_in_4x", 0) > 1:
            stock += "; %d stock rules silenced in 4.x" % r["silenced_in_4x"]
        five = r["stock_5x"]
        if five is None:
            ftxt = "unknown: no equivalence; find the 5.x rule by its title"
        else:
            ftxt = "integration `%s` (%s)" % (five["integration"], five["source"])
            if five.get("paths"):
                ftxt += ": %s" % "; ".join(five["paths"])
        cond = r["condition_4x"] + ((" (%s)" % r["change"]) if r.get("change") else "")
        w("| %s | %s | %s | %s | `%s` | %s |" % (r["rule"], r["kind"], esc(stock), esc(ftxt), esc(cond),
                                                ", ".join("`%s`" % o for o in r["options"])))
    w("")
