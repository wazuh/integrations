"""Migration quality: what the customer would lose without noticing.

Each part reads the classification and the 5.x package and adds a section to the report; none of them changes the
state of an item. ``analyze`` returns ``report["quality"]``; ``markdown`` its sections of ``report.md``; ``files``
the files under ``out/`` (only when there is something to write).

:mod:`.references`
    item 1: alerting blocks of ``ossec.conf`` and their 5.x monitors.
:mod:`.lists`
    item 2: list classes (stock, IoC, business) against the 5.x IoC feeds.
:mod:`.tuning`
    item 4: level 0 silencers and overwrites of stock rules: the tuning to redo.
:mod:`.findings`
    item 3: findings per event, 4.x against 5.x, and siblings that could be one rule.
:mod:`.completeness`
    item 5: what is not migrated and why (dashboards, agent groups, ossec.conf settings, monitors by hand).
"""

import json

from . import completeness as CP
from . import findings as FI
from . import lists as LC
from . import references as REF
from . import tuning as TU
from ..textsafe import md

SECTION_MARKER = "\n## Items\n"


def _kvdb_fallback_title(name):
    from ..translate.meta import PREFIX, safe_name, slug
    return PREFIX + slug(safe_name(name.rsplit("/", 1)[-1]))


def _list_rows(clf, package):
    kvdbs = {}
    if package is not None:
        for key, integ in package.integrations.items():
            for title, doc in integ["kvdbs"].items():
                if doc["source"].get("kind") == "list":
                    kvdbs.setdefault(doc["source"]["id"], (title, key))
    rows = []
    action = clf.decisions.get("lists", {})
    for name, res in getattr(clf, "list_classes", {}).items():
        row = dict(res)
        row["name"] = name
        row["action"] = (action.get(name) or {}).get("action") or "kvdb"
        if res["refresh"]:
            title, key = kvdbs.get(name, (_kvdb_fallback_title(name), "its integration"))
            row["update_step"] = LC.kvdb_update_step(name, title, key)
        rows.append(row)
    return rows


def analyze(clf, package):
    mapping = package.mapping if package is not None else []
    monitors = list(package.monitors) if package is not None else []
    refs = REF.analyze(clf.inv, mapping, monitors, clf.stock, clf.winpack)
    return {"references": refs, "lists": _list_rows(clf, package),
            "tuning": TU.analyze(clf),
            "findings": FI.analyze(clf),
            "completeness": CP.analyze(clf.inv, package, refs, mapping)}


def counts(q):
    by_class = {}
    for r in q["lists"]:
        by_class[r["class"]] = by_class.get(r["class"], 0) + 1
    return {"references": len(q["references"]),
            "reference_flags": sum(len(r["flags"]) for r in q["references"]),
            "lists": by_class,
            "lists_unsure": sum(1 for r in q["lists"] if r["unsure"]),
            "lists_refreshed": sum(1 for r in q["lists"] if r["refresh"]),
            "tuning": len(q["tuning"]),
            "tuning_known_5x": sum(1 for r in q["tuning"] if r["stock_5x"]),
            "findings_rows": len(q["findings"]["rows"]),
            "findings_max": max([r["always"] for r in q["findings"]["rows"]] or [1]),
            "findings_histogram": q["findings"]["histogram"],
            "merge_candidates": len(q["findings"]["merge_candidates"])}


def files(q):
    out = {}
    for ref in q["references"]:
        name = REF.file_name(ref)
        out["references/%s.json" % name] = json.dumps(ref, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
        out["references/%s.md" % name] = REF.render_md(ref)
    return out


def _esc(text):
    return md(text)


def _references_md(refs, w):
    w("## ossec.conf references")
    w("")
    if not refs:
        w("No alerting block (`<active-response>`, `<integration>`, `<email_alerts>`, `<alerts>`, `<reports>`, "
          "`<global>`, `<localfile>`) was found in `ossec.conf`.")
        w("")
        return
    w("5.x does not read these blocks. Each one is a channel or a setting plus an Alerting monitor that you "
      "create by hand: `out/references/` has, per block, the 4.x block, the monitor query and a checklist. "
      "Not live-verified.")
    w("")
    w("| Block | Origin | 5.x | Rule refs | Not mapped |")
    w("|---|---|---|---:|---:|")
    for r in refs:
        w("| `%s` %s | `%s:%d` | %s | %d | %d |" % (r["kind"], _esc(r["label"]), r["file"], r["line"],
                                                     _esc(r["mechanism"]), len(r["rules"]), len(r["flags"])))
    w("")


def _lists_md(rows, w):
    w("## Lists and the 5.x IoC feeds")
    w("")
    if not rows:
        w("No CDB list.")
        w("")
        return
    w("5.x ships IoC feeds (`wazuh-ioc` integration: IP and port, domain, URL, MD5, SHA1, SHA256) that customers "
      "cannot extend. An IoC list is still migrated to a KVDB unless `decisions.json` (`lists`) says "
      "`\"action\": \"ioc-feed\"`: then its rules match `%s` and the KVDB is not emitted. The entries no feed has "
      "cannot be checked offline. Business lists stay KVDBs. Not live-verified." % LC.IOC_FIELD)
    w("")
    w("| List | Class | Why | Rules | 5.x | Feed types |")
    w("|---|---|---|---:|---|---|")
    for r in rows:
        if r["class"] == "stock":
            five = "not migrated (stock)" + (", covered by `wazuh-ioc`" if r["feed_types"] else "")
        elif r["class"] == "ioc":
            five = "IoC feeds (`ioc-feed`)" if r["action"] == "ioc-feed" else "KVDB (default; question in decisions.json)"
        else:
            five = "KVDB"
        why = "; ".join(r["why"][:3])
        if r["unsure"]:
            why = "unsure: %s%s" % (r["unsure"], ("; " + why) if why else "")
        w("| `%s` | %s | %s | %d | %s | %s |" % (r["name"], r["class"], _esc(why), len(r["uses"]), five,
                                                 ", ".join(r["feed_types"])))
    w("")
    for r in rows:
        for warn in r["warnings"]:
            w("- `%s`: %s." % (r["name"], warn))
        if r.get("update_step"):
            ev = r["refresh"][0]
            w("- `%s`: refreshed by `%s` (`%s:%d`). %s" % (r["name"], _esc(ev["command"]), ev["file"], ev["line"],
                                                          r["update_step"]))
    w("")


def markdown(q):
    out = []
    _references_md(q["references"], out.append)
    _lists_md(q["lists"], out.append)
    TU.render(q["tuning"], out.append, _esc)
    FI.render(q["findings"], out.append, _esc)
    CP.render(q["completeness"], out.append, _esc)
    return "\n".join(out).rstrip("\n") + "\n"


def attach(report, md, q):
    """Put ``q`` in the report and its sections in ``report.md`` before the item list."""
    report["quality"] = q
    text = markdown(q)
    i = md.find(SECTION_MARKER)
    if i < 0:
        return md.rstrip("\n") + "\n\n" + text
    return md[:i + 1] + text + md[i:]
