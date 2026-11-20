"""Sections ``Apply``, ``Rollback`` and ``Activate`` of ``report.json`` and
``report.md``, and ``work/mapping-applied.csv``."""

import csv
import io
import os

from .. import reasons as R
from ..jsonio import read_json, write_json, write_text
from ..textsafe import md

TITLES = {"apply": "Apply", "rollback": "Rollback", "activate": "Activate"}
ORDER = ("apply", "rollback", "activate")


def _code_ref(code):
    if code and code in R.CATALOG:
        return "[`%s`](%s)" % (code, R.CATALOG[code].anchor)
    return ""


def stop_entry(code, text, items=None):
    e = {"code": code, "text": text, "items": list(items or [])}
    if code and code in R.CATALOG:
        e["doc"] = R.CATALOG[code].anchor
        e["reason"] = R.CATALOG[code].text
    return e


def stop_line(command, entry):
    """The terminal line of a stop: the command, the reason code when there is one, the text."""
    code = entry.get("code")
    return "%s: stopped%s: %s" % (command, " (%s)" % code if code else "", entry["text"])


def render_section(key, sec):
    out = ["## %s" % TITLES[key], ""]
    w = out.append
    w("Run %s%s. Result: **%s**." % (sec.get("when", ""), " (dry run: nothing was written)" if sec.get("dry_run") else "",
                                    sec.get("result", "")))
    w("")
    for s in sec.get("stops", []):
        ref = _code_ref(s.get("code"))
        w("- Stopped%s: %s" % ((" " + ref) if ref else "", s["text"]))
        for it in s.get("items", [])[:50]:
            w("  - %s" % it)
        if len(s.get("items", [])) > 50:
            w("  - and %d more" % (len(s["items"]) - 50))
    if sec.get("integrations"):
        w("")
        w("| Integration | Status | Created | Updated | Unchanged | Deleted | Message |")
        w("|---|---|---:|---:|---:|---:|---|")
        for i in sec["integrations"]:
            w("| `%s` | %s | %d | %d | %d | %d | %s |" % (
                i["key"], i["status"], i.get("created", 0), i.get("updated", 0), i.get("unchanged", 0),
                i.get("deleted", 0), md(i.get("message") or "")[:300]))
    if sec.get("detectors"):
        w("")
        w("| Detector | Status | Rules | Index |")
        w("|---|---|---:|---|")
        for d in sec["detectors"]:
            w("| `%s` | %s | %d | `%s` |" % (d["name"], d["status"], d.get("rules", 0), d.get("index", "")))
    if sec.get("operations"):
        w("")
        for op in sec["operations"]:
            w("- Recorded operation `%s` by %s at %s%s" % (op["op"], op["who"], op["when"],
                                                          (": " + op["detail"]) if op.get("detail") else ""))
    if sec.get("notes"):
        w("")
        for n in sec["notes"]:
            w("- %s" % n)
    w("")
    return out


def update_report(paths, key, section):
    """Store ``section`` under ``report.json[key]`` and re-render the
    networked sections at the end of ``report.md`` (the rest is kept)."""
    rpath = paths["report_json"]
    report = read_json(rpath) if os.path.isfile(rpath) else {}
    report[key] = section
    write_json(rpath, report)
    mpath = paths["report_md"]
    text = ""
    if os.path.isfile(mpath):
        with open(mpath, "r", encoding="utf-8") as fh:
            text = fh.read()
    lines = text.split("\n") if text else ["# Ruleset migration report", ""]
    heads = {"## %s" % t for t in TITLES.values()}
    cut = len(lines)
    for i, line in enumerate(lines):
        if line in heads:
            cut = i
            break
    kept = lines[:cut]
    while kept and kept[-1] == "":
        kept.pop()
    kept.append("")
    for k in ORDER:
        if k in report and isinstance(report[k], dict):
            kept.extend(render_section(k, report[k]))
    write_text(mpath, "\n".join(kept).rstrip("\n") + "\n")


def write_mapping_applied(out, state, path):
    fields, rows = out.mapping_rows()
    if not fields:
        return 0
    if "server_id" not in fields:
        fields = fields + ["server_id"]
    n = 0
    for row in rows:
        e = state.get(row.get("local_id") or "")
        sid = e.get("server_id") if e and e.get("integration") not in state.data.get("set_aside", {}) else ""
        row["server_id"] = sid or ""
        n += 1 if sid else 0
    buf = io.StringIO()
    wr = csv.DictWriter(buf, fieldnames=fields, lineterminator="\n", extrasaction="ignore")
    wr.writeheader()
    for row in rows:
        wr.writerow({k: ("" if row.get(k) is None else row.get(k)) for k in fields})
    write_text(path, buf.getvalue())
    return n
