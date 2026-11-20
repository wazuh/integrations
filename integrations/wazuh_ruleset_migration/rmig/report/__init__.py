"""Report: ``report.json`` is the source, ``report.md`` is
rendered from it."""

from collections import Counter

from .. import reasons as R
from .. import limits
from .. import stock5
from ..translate.meta import PREFIX

TOP_STOCK = 25


def _pending_decisions(decisions, wanted):
    """Open questions. A field is pending when an item waits for it
    (``required``); a field the decoders can check without a WCS field is
    optional, and its value is not stored (``not_stored``, with the dropped
    ones)."""
    wf = wanted.get("fields", {})
    dec_fields = decisions.get("fields", {})
    fields = [k for k in wf if dec_fields.get(k, {}).get("action") is None and wf[k].get("required", True)]
    not_stored = [k for k in wf if dec_fields.get(k, {}).get("action") in (None, "drop") and k not in fields]
    stock = []
    for k in wanted.get("stock", {}):
        e = decisions.get("stock", {}).get(k, {})
        if not e.get("integration") or (not k.startswith("decoder:") and not e.get("selection")):
            stock.append(k)
    json_checks = [k for k, e in decisions.get("integrations", {}).items() if "json_check" in e and not e.get("json_check")]
    feeds = [k for k, e in wanted.get("feeds", {}).items()
             if e.get("selector_needed") and not decisions.get("feeds", {}).get(k, {}).get("selector")]
    return {"fields": sorted(fields), "stock": sorted(stock), "json_check": sorted(json_checks),
            "feeds": sorted(feeds, key=lambda k: (len(k), k)), "not_stored": sorted(not_stored)}


def _stock_integrations(package):
    out = []
    if package is None:
        return out
    for key in package.ordered_keys():
        doc = package.integrations[key]["doc"]
        if doc["kind"] == "on-stock":
            out.append(doc["stock_integration"])
    return out


def build_report(inv, plan_items, decisions, wanted, stock_refs, tool, translated=False, package=None, build=None,
                 engine_limits=None):
    """``translated``: the states come from the translator (``plan``/``build``
    from the command line). ``package``: the 5.x package; ``build``: what
    ``build`` wrote (``{"out": path, "files": n}``) or None."""
    by_state = Counter(it["state"] for it in plan_items)
    by_kind = {}
    for it in plan_items:
        by_kind.setdefault(it["kind"], Counter())[it["state"]] += 1
    by_fid = Counter(it["fidelity"] for it in plan_items if it["state"] == R.AUTO)
    by_code = Counter(c["code"] for it in plan_items for c in it["codes"])
    pending = _pending_decisions(decisions, wanted)

    decision_items = [it["uid"] for it in plan_items if it["state"] == R.DECISION]
    recipe_items = [it for it in plan_items if it["state"] == R.RECIPE]
    recipe_codes = Counter(c["code"] for it in recipe_items for c in it["codes"]
                           if R.CATALOG[c["code"]].state == R.RECIPE)
    freq = [it["uid"] for it in plan_items if any(c["code"] == "RM-R-FREQUENCY" and not any(
        d.startswith("from ") for d in c["details"]) for c in it["codes"])]
    auto = [it for it in plan_items if it["state"] == R.AUTO]
    stock_integ = _stock_integrations(package)
    disabled = sorted({d for it in plan_items for c in it["codes"] if c["code"] == "RM-S-INTEGRATION-DISABLED"
                       for d in c["details"]})
    if not translated:
        stock_action = {"order": 3, "id": "stock-integrations",
                        "title": "Enable the stock integrations the migrated content depends on", "count": 0,
                        "text": "None identified: the stock equivalence table has no entries yet, so no 5.x integration is known."}
        verify_action = {"order": 4, "id": "verify", "title": "Build, apply to the test space and verify",
                         "count": len(auto),
                         "text": "%d item(s) are AUTO (provisional). Run build to translate them." % len(auto)}
        monitors_text = "%d frequency rule(s) need a bucket-level monitor (definitions come with the build command)." % len(freq)
    else:
        stock_action = {"order": 3, "id": "stock-integrations",
                        "title": "Enable the stock integrations the migrated content depends on",
                        "count": len(disabled),
                        "text": ("Rules over stock content go to %s. Disabled in the catalog: %s." % (
                            ", ".join(stock_integ) or "no stock integration", ", ".join(disabled) or "none")),
                        "integrations": stock_integ, "disabled": disabled}
        if build:
            vtext = ("%d item(s) are AUTO; build wrote %d file(s) to %s. Run apply (test space), then verify --alerts "
                     "with 4.x alerts." % (len(auto), build.get("files", 0), build.get("out", "out/")))
        else:
            vtext = "%d item(s) are AUTO. Run build to write them to out/, then apply and verify." % len(auto)
        verify_action = {"order": 4, "id": "verify", "title": "Build, apply to the test space and verify",
                         "count": len(auto), "text": vtext}
        nmon = len(package.monitors) if package is not None else 0
        monitors_text = ("%d frequency rule(s); %d monitor definition(s) in out/monitors/ (build does not create them)."
                         % (len(freq), nmon))

    actions = [
        {"order": 1, "id": "decisions", "title": "Complete decisions.json",
         "count": len(pending["fields"]) + len(pending["stock"]) + len(pending["json_check"]) + len(pending["feeds"]),
         "text": "%d field(s), %d stock reference(s)%s and %d JSON check(s) are undecided; %d item(s) wait for them. "
                 "Edit decisions.json and run plan again.%s" % (
                     len(pending["fields"]), len(pending["stock"]),
                     ", %d feed selector(s)" % len(pending["feeds"]) if pending["feeds"] else "",
                     len(pending["json_check"]), len(decision_items),
                     (" %d field(s) have no WCS field: the decoders check them, but their values are not stored "
                      "(optional: map them to keep the values)." % len(pending["not_stored"]))
                     if pending["not_stored"] else ""),
         "pending": pending},
        {"order": 2, "id": "recipes", "title": "Apply the recipes by hand",
         "count": len(recipe_items),
         "text": "%d item(s) have no direct translation. Each card below names the reason." % len(recipe_items),
         "by_code": dict(sorted(recipe_codes.items()))},
        stock_action,
        verify_action,
        {"order": 5, "id": "activate", "title": "Activate",
         "count": 0,
         "text": "After a verification without failures, promote to the custom space (activate --yes)."},
        {"order": 6, "id": "monitors", "title": "Create the Alerting monitors",
         "count": len(freq),
         "text": monitors_text},
    ]
    policy = Counter()
    for it in plan_items:
        for c in it["codes"]:
            if c["code"].startswith("RM-P-") or c["code"] == "RM-D-DUAL-DOCUMENT":
                policy[c["code"]] += 1
    files = [f for f in inv["files"] if f["errors"] or f["unknown"]]
    items = []
    for it in plan_items:
        e = dict(it)
        e["origin"] = "%s:%d" % (it["file"], it["line"])
        e["codes"] = [{"code": c["code"], "details": c["details"], "text": R.CATALOG[c["code"]].text,
                       "doc": R.CATALOG[c["code"]].anchor, "state": R.CATALOG[c["code"]].state}
                      for c in it["codes"]]
        items.append(e)
    return {
        "version": 1,
        "tool": tool,
        "translated": bool(translated),
        "source": inv["source"],
        "stock_index": inv["stock_index"],
        "summary": {
            "items": len(plan_items),
            "by_state": {s: by_state.get(s, 0) for s in R.STATES},
            "by_kind": {k: {s: v.get(s, 0) for s in R.STATES} for k, v in sorted(by_kind.items())},
            "by_fidelity": {f: by_fid.get(f, 0) for f in (R.EXACT, R.APPROXIMATE)},
            "by_code": dict(sorted(by_code.items())),
        },
        "actions": actions,
        "policy_warnings": dict(sorted(policy.items())),
        "stock_without_equivalence": [r for r in stock_refs if not r["equivalence"]][:TOP_STOCK],
        "stock_references": stock_refs,
        "files_with_problems": [{"path": f["path"], "errors": f["errors"], "unknown": f["unknown"]} for f in files],
        "build": _build_summary(package, build, decisions, engine_limits, plan_items) if translated else None,
        "stock5": stock5.build_section(inv, plan_items, decisions),
        "items": items,
    }


def _no_full_log(plan_items):
    """Rules that reach out/ with ``no_full_log``: verify needs sample lines for them."""
    out = []
    for it in plan_items:
        if it["kind"] != "rule" or it["state"] == R.NOT_APPLICABLE:
            continue
        for c in it["codes"]:
            if c["code"] == "RM-R-OPTIONS" and any("no_full_log" in d.split(", ") for d in c["details"]):
                out.append(it["ref"])
                break
    return out


def _build_summary(package, build, decisions=None, engine_limits=None, plan_items=()):
    if package is None:
        return None
    integ = []
    defaulted = []  # generated integrations whose category is the default of the 4.x decoder type
    dec_integ = (decisions or {}).get("integrations", {})
    for key in package.ordered_keys():
        i = package.integrations[key]
        integ.append({"key": key, "kind": i["doc"]["kind"], "category": i["doc"]["resource"]["category"],
                      "decoders": len(i["decoders"]), "kvdbs": len(i["kvdbs"]), "rules": len(i["rules"])})
        name = i.get("source_name") or (key[len(PREFIX):] if key.startswith(PREFIX) else None)
        if i["doc"]["kind"] == "custom" and name in dec_integ                 and dec_integ[name].get("category_source", "default") == "default":
            defaulted.append({"key": key, "decoder": name, "category": i["doc"]["resource"]["category"]})
    return {
        "written": bool(build),
        "out": (build or {}).get("out"),
        "files": (build or {}).get("files"),
        "integrations": integ,
        "default_category": defaulted,
        "monitors": sorted(package.monitors, key=lambda x: int(x) if x.isdigit() else 0),
        "recipes": len(package.recipes),
        "detectors": len(package.detectors),
        "limits": limits.from_package(package, engine_limits),
        "no_full_log": _no_full_log(plan_items),
    }
