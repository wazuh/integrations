"""Findings per event, 4.x against 5.x.

4.x raises one alert per event: the deepest matching rule. 5.x raises one finding per (event, rule), has no
non-alerting or building-block rule and no chaining. So, for the event that fired 4.x rule X:

* every emitted ancestor of X fires too (X's flattened detection holds its conditions): ``always``. With
  alternative parents (several ``if_sid`` ids, ``if_group``) only the ancestors of the matching chain fire: the
  count is per chain (``always`` the shortest, ``up_to`` the longest);
* a sibling of X, or of an ancestor, under the same parent fires when its own condition also holds: ``maybe``;
* a stock 5.x rule over the same events can fire too when X hangs from stock content: ``stock``.

Grouping parents (level 0 or ``noalert`` with no condition of their own) are not emitted (``RM-R-GROUPING-ONLY``)
and ``noalert`` rules with a condition are emitted disabled, so they add nothing.

Siblings that share a parent, the integration, the level, the tags (but the ``wazuh4.rule`` tag), compliance,
MITRE and the title could be one Sigma rule with ``1 of selection_*``. They are reported, not merged: ``verify``,
the mapping and the frequency monitors read one 5.x rule per 4.x id, and a wrong merge loses detections.
"""



def _emitted(tr, uid):
    try:
        return tr.emitted(uid)
    except KeyError:
        return False


def analyze(clf):
    tr = clf.translation
    if tr is None:
        return {"rows": [], "merge_candidates": [], "histogram": {}}
    tree = clf.tree
    emitted = {u for u in tr.rules if _emitted(tr, u)}
    rows = []
    for uid in sorted(emitted, key=lambda u: (clf.items[u]["file"], clf.items[u]["line"])):
        if not tree.alerting(uid):
            continue
        # parents are alternatives (if_sid with several ids, if_group): count per chain, not over their union
        per_path = [{a for a in path[:-1] if a in emitted and tree.alerting(a)} for path in tree.paths(uid)] or [set()]
        certain = set.intersection(*per_path)
        anc = sorted(certain, key=lambda u: tree.node(u)["seq"])
        up_to = 1 + max(len(s) for s in per_path)
        maybe = set().union(*per_path) - certain
        chain = [uid] + list(tree.ancestors(uid))
        for node in chain:
            for p in [x for x in tree.parents(node) if not tree.is_template(x)]:
                for sib in tree.children.get(p, []):
                    if sib in chain or sib == node:
                        continue
                    for s in [sib] + list(tree.descendants(sib)):
                        if s in emitted and tree.alerting(s) and s not in anc:
                            maybe.add(s)
        stock = bool(tree.stock_anchors(uid))
        always = 1 + min(len(s) for s in per_path)
        if always == 1 and not maybe and not stock:
            continue
        rows.append({"rule": clf.items[uid]["id"],
                     "always": always, "up_to": up_to, "ancestors": [tree.node(a)["id"] for a in anc],
                     "maybe": sorted({tree.node(s)["id"] for s in maybe}, key=lambda x: (len(x), x)),
                     "stock": stock})
    hist = {}
    for r in rows:
        hist[r["always"]] = hist.get(r["always"], 0) + 1
    return {"rows": rows, "merge_candidates": merge_candidates(clf, emitted),
            "histogram": {str(k): v for k, v in sorted(hist.items())}}  # keys in numeric order


def _signature(tr, uid):
    r = tr.rules[uid]
    res = r.resource
    tags = sorted(t for t in res.get("tags", []) if not t.startswith("wazuh4.rule."))
    return (r.key, res.get("level"), bool(res.get("enabled")), tuple(tags),
            repr(sorted((res.get("compliance") or {}).items())), repr(res.get("mitre")), r.title_base)


def merge_candidates(clf, emitted):
    tr = clf.translation
    tree = clf.tree
    groups = {}
    for uid in emitted:
        if not tree.alerting(uid):
            continue
        parents = tuple(sorted(tree.parents(uid)))
        if not parents:
            continue
        item = clf.items[uid]
        groups.setdefault((parents, _signature(tr, uid), item.get("level")), []).append(uid)
    out = []
    for key, uids in groups.items():
        if len(uids) < 2:
            continue
        uids.sort(key=lambda u: tree.node(u)["seq"])
        out.append({"rules": [clf.items[u]["id"] for u in uids],
                    "parent": ",".join(tree.node(p)["id"] for p in key[0]),
                    "title": tr.rules[uids[0]].title_base, "level": tr.rules[uids[0]].resource.get("level")})
    out.sort(key=lambda c: [int(x) if x.isdigit() else 0 for x in c["rules"]])
    return out


def render(f, w, esc):
    w("## Findings per event")
    w("")
    rows = f["rows"]
    if not rows and not f["merge_candidates"]:
        w("Every migrated rule raises one finding for the event that raised its 4.x alert.")
        w("")
        return
    w("4.x raised one alert per event, the deepest matching rule. 5.x raises one finding per matching rule. For the "
      "event that fired the 4.x rule, the table counts the 5.x findings from the chain structure: `always` is the "
      "rule plus the migrated alerting ancestors of every chain (up to: of its longest chain, when its parents are "
      "alternatives); `maybe` are siblings that fire when their own condition also "
      "holds; `stock` means a stock 5.x rule over the same events can fire too. Grouping rules are not emitted. "
      "Not live-verified.")
    w("")
    if f["histogram"]:
        w("Rules by findings per event (always): %s." % ", ".join(
            "%s: %d" % (k, v) for k, v in f["histogram"].items()))
        w("")
    if rows:
        w("| 4.x rule | 4.x alerts | 5.x findings (always) | Ancestors | Maybe | Stock |")
        w("|---|---:|---:|---|---|---|")
        for r in rows[:200]:
            n = "%d" % r["always"] if r["up_to"] == r["always"] else "%d (up to %d)" % (r["always"], r["up_to"])
            w("| %s | 1 | %s | %s | %s | %s |" % (r["rule"], n, ", ".join(r["ancestors"]) or "-",
                                                 esc(", ".join(r["maybe"][:10]) + (" and %d more" % (len(r["maybe"]) - 10)
                                                                                    if len(r["maybe"]) > 10 else "")) or "-",
                                                 "yes" if r["stock"] else "-"))
        if len(rows) > 200:
            w("")
            w("%d more rows in report.json (quality.findings)." % (len(rows) - 200))
        w("")
    if f["merge_candidates"]:
        w("Siblings that are exactly equivalent (same parent, integration, level, tags, MITRE, title) and could be "
          "one Sigma rule with `1 of selection_*`, one finding instead of several. Not merged: `verify`, "
          "`mapping.csv` and the frequency monitors need one 5.x rule per 4.x id. Merge them by hand if you want:")
        w("")
        for c in f["merge_candidates"]:
            w("- %s (parent %s, `%s`): %s" % (", ".join(c["rules"]), c["parent"], c["level"], esc(c["title"])))
        w("")

