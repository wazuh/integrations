"""Render ``report.md`` from ``report.json``."""

from .. import limits
from ..textsafe import md
from .. import reasons as R
from ..stock5 import render_markdown as render_stock5


def _esc(text):
    if text is None:
        return ""
    return md(text)


def _pct(n, total):
    return "%.1f %%" % (100.0 * n / total) if total else "0.0 %"


def render(report):
    s = report["summary"]
    total = s["items"]
    out = []
    w = out.append
    w("# Ruleset migration report")
    w("")
    w("Source: `%s` (%s layout). Stock index: %s. Tool: %s." % (
        report["source"]["name"], report["source"]["mode"], report["stock_index"]["source"], report["tool"]))
    w("")
    w("## Summary")
    w("")
    w("| State | Items | Share |")
    w("|---|---:|---:|")
    for state in R.STATES:
        n = s["by_state"][state]
        w("| `%s` | %d | %s |" % (state, n, _pct(n, total)))
    w("| **Total** | **%d** | |" % total)
    w("")
    w("| Kind | AUTO | DECISION | RECIPE | NOT_APPLICABLE |")
    w("|---|---:|---:|---:|---:|")
    for kind, row in s["by_kind"].items():
        w("| %s | %d | %d | %d | %d |" % (kind, row["AUTO"], row["DECISION"], row["RECIPE"], row["NOT_APPLICABLE"]))
    w("")
    if report.get("translated"):
        w("Fidelity of the `AUTO` items (from the translation): %d exact, %d approximate." % (
            s["by_fidelity"]["exact"], s["by_fidelity"]["approximate"]))
    else:
        w("Fidelity of the `AUTO` items (provisional until the translator runs): %d exact, %d approximate." % (
            s["by_fidelity"]["exact"], s["by_fidelity"]["approximate"]))
    w("")
    w("## What you need to do")
    w("")
    for a in report["actions"]:
        w("%d. **%s** (%d). %s" % (a["order"], a["title"], a["count"], a["text"]))
        if a["id"] == "decisions":
            p = a["pending"]
            if p["fields"]:
                w("   - Fields: %s" % ", ".join("`%s`" % f for f in p["fields"][:30]) + (" and %d more" % (len(p["fields"]) - 30) if len(p["fields"]) > 30 else ""))
            if p["stock"]:
                w("   - Stock references: %s" % ", ".join("`%s`" % f for f in p["stock"][:30]) + (" and %d more" % (len(p["stock"]) - 30) if len(p["stock"]) > 30 else ""))
            if p.get("feeds"):
                w("   - Feed selectors (root rule ids): %s" % ", ".join("`%s`" % f for f in p["feeds"]))
            if p["json_check"]:
                w("   - JSON checks: %s" % ", ".join("`%s`" % f for f in p["json_check"]))
            if p.get("not_stored"):
                ns = p["not_stored"]
                w("   - Values not stored (optional): %s" % ", ".join("`%s`" % f for f in ns[:30])
                  + (" and %d more" % (len(ns) - 30) if len(ns) > 30 else ""))
        if a["id"] == "recipes" and a["by_code"]:
            w("   - " + ", ".join("[`%s`](%s): %d" % (c, R.CATALOG[c].anchor, n) for c, n in a["by_code"].items()))
    w("")
    b = report.get("build")
    if b:
        w("## Build")
        w("")
        if b["written"]:
            w("`build` wrote %d file(s) to `%s`." % (b["files"] or 0, b["out"]))
        else:
            w("Not built yet: run `build` to write `out/`.")
        w("")
        if b["integrations"]:
            w("| Integration | Kind | Category | Decoders | KVDBs | Rules |")
            w("|---|---|---|---:|---:|---:|")
            for i in b["integrations"]:
                w("| `%s` | %s | `%s` | %d | %d | %d |" % (i["key"], i["kind"], i["category"], i["decoders"], i["kvdbs"], i["rules"]))
        else:
            w("No item is `AUTO`: nothing to emit.")
        w("")
        if b.get("default_category"):
            w("Category by default, from the `<type>` of the 4.x decoder: %s. Check it and set `category` and "
              "`\"category_source\": \"user\"` in `decisions.json` (`integrations`)." % ", ".join(
                  "`%s` (`%s`)" % (d["key"], d["category"]) for d in b["default_category"]))
            w("")
        w("Monitors: %s. Recipes: %d. Detector templates: %d." % (
            ", ".join("`%s`" % x for x in b["monitors"]) or "none", b["recipes"], b["detectors"]))
        w("")
        if b.get("no_full_log"):
            nf = b["no_full_log"]
            w("Rules with `no_full_log`: their 4.x alerts have no original log line, so `verify` cannot replay "
              "them. Provide sample logs with `verify --samples DIR` (`DIR/<rule id>.log`, one line per event): "
              "%s." % (", ".join("`%s`" % r for r in nf[:30]) + (" and %d more" % (len(nf) - 30) if len(nf) > 30 else "")))
            w("")
        out.extend(limits.markdown(b.get("limits")))
    if report.get("stock5"):
        out.extend(render_stock5(report["stock5"]))
    if report["policy_warnings"]:
        w("## Policy warnings")
        w("")
        for code, n in report["policy_warnings"].items():
            w("- [`%s`](%s): %d item(s). %s" % (code, R.CATALOG[code].anchor, n, R.CATALOG[code].text))
        w("")
    w("## Stock content referenced without equivalence")
    w("")
    if report["stock_without_equivalence"]:
        w("Most referenced first. Each one needs an entry in the equivalence table or in `decisions.json` (`stock`).")
        w("")
        w("| Reference | Custom items | Stock location |")
        w("|---|---:|---|")
        for r in report["stock_without_equivalence"]:
            w("| `%s` | %d | %s |" % (r["ref"], r["count"], ("`%s`" % r["stock_location"]) if r["stock_location"] else ""))
    else:
        w("None.")
    w("")
    w("## Reason codes")
    w("")
    w("| Code | State | Items |")
    w("|---|---|---:|")
    for code, n in s["by_code"].items():
        w("| [`%s`](%s) | `%s` | %d |" % (code, R.CATALOG[code].anchor, R.CATALOG[code].state, n))
    w("")
    if report["files_with_problems"]:
        w("## Files with problems")
        w("")
        for f in report["files_with_problems"]:
            for e in f["errors"]:
                w("- `%s:%d`: %s" % (f["path"], e["line"], _esc(e["message"])))
            for u in f["unknown"]:
                w("- `%s:%d`: unknown element `<%s>`" % (f["path"], u["line"], _esc(u["element"])))
        w("")
    w("## Items")
    w("")
    for it in report["items"]:
        title = it["ref"]
        if it["kind"] == "rule" and it.get("description"):
            title += ": " + _esc(it["description"].strip())[:120]
        w("### %s" % title)
        w("")
        fid = " (%s)" % it["fidelity"] if it.get("fidelity") else ""
        w("- Origin: `%s`" % it["origin"])
        w("- State: `%s`%s" % (it["state"], fid))
        if it.get("integration"):
            w("- Integration: %s" % ", ".join("`%s`" % i for i in ([it["integration"]] if isinstance(it["integration"], str) else it["integration"])))
        for c in it["codes"]:
            detail = "; ".join(c["details"])
            w("- [`%s`](%s): %s%s" % (c["code"], c["doc"], c["text"], (" Detail: " + _esc(detail) + ".") if detail else ""))
        for n in it.get("notes", []):
            w("- Note: %s" % _esc(n))
        w("")
    return "\n".join(out).rstrip("\n") + "\n"
