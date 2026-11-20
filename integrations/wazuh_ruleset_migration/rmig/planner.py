"""``plan``: inventory + decisions -> plan.json, decisions.json, report.{json,md}."""

import os

from . import __version__
from . import decisions as D
from . import reasons as R
from .classify import classify
from .jsonio import read_json, write_json, write_text
from .report import build_report
from .report.markdown import render


class PlanError(Exception):
    pass


def paths(workdir):
    return {
        "inventory": os.path.join(workdir, "work", "inventory.json"),
        "plan": os.path.join(workdir, "work", "plan.json"),
        "decisions": os.path.join(workdir, "decisions.json"),
        "report_json": os.path.join(workdir, "report.json"),
        "report_md": os.path.join(workdir, "report.md"),
    }


def compute(inv, decisions, stock=None, equivalence=None):
    """Everything ``plan`` produces, in memory. Returns a dict with ``plan``,
    ``decisions`` (merged), ``report`` and ``markdown``."""
    tool = "rmig %s" % __version__
    clf = classify(inv, decisions, stock, equivalence)
    items = clf.items_out()
    wanted = clf.wanted_decisions()
    merged = D.merge(decisions, wanted)
    stock_refs = clf.stock_references()
    load = clf.load
    plan = {
        "version": 1,
        "tool": tool,
        "source": inv["source"],
        "stock_index": inv["stock_index"],
        "ruleset": inv["ruleset"],
        "load": {
            "rule_files": [f for f in load.rule_files if f["origin"] == "custom"],
            "decoder_files": [f for f in load.decoder_files if f["origin"] == "custom"],
            "excluded_rule_files": sorted(getattr(load, "excluded_rule_files", [])),
            "declared_lists": load.declared_lists,
            "available_lists": sorted(load.available_lists),
        },
        "summary": {s: sum(1 for it in items if it["state"] == s) for s in R.STATES},
        "stock_references": stock_refs,
        "items": items,
    }
    report = build_report(inv, items, merged, wanted, stock_refs, tool)
    return {"plan": plan, "decisions": merged, "report": report, "markdown": render(report)}


def run(workdir, stock=None, equivalence=None):
    p = paths(workdir)
    if not os.path.exists(p["inventory"]):
        raise PlanError("no inventory at %s: run scan first" % p["inventory"])
    inv = read_json(p["inventory"])
    decisions = D.load(p["decisions"])
    res = compute(inv, decisions, stock, equivalence)
    write_json(p["plan"], res["plan"])
    D.save(p["decisions"], res["decisions"])
    write_json(p["report_json"], res["report"])
    write_text(p["report_md"], res["markdown"])
    return res
