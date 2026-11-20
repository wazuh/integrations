"""``plan`` and ``build`` with the translator: the same products as
:func:`rmig.planner.compute`, with the final state of every item and the 5.x
package."""

import os

from .. import __version__
from .. import decisions as D
from .. import fsutil
from .. import reasons as R
from ..classify import Classifier
from . import helpers as H
from ..report import build_report
from ..report.markdown import render
from .. import quality as Q


def list_loader_for(source):
    """A function that reads the bytes of a list item from the 4.x tree
    ``source`` (the three layouts of ``scan``), or None without a source."""
    if not source:
        return None

    def load(li):
        rel = li["file"]
        candidates = [os.path.join(source, rel)]
        if rel.startswith("etc/"):
            candidates.insert(0, os.path.join(source, rel[4:]))
        for path in candidates:
            if os.path.isfile(path) and fsutil.inside(source, path):
                with open(path, "rb") as fh:
                    return fh.read()
        return None

    return load


def compute(inv, decisions, stock=None, equivalence=None, source=None, date=None, build=None,
            engine_helpers=H.DEFAULT, engine_limits=None):
    """``engine_helpers``: the helper names of the target engine
    (:mod:`.helpers`); an input of the build like the others."""
    tool = "rmig %s" % __version__
    H.known(engine_helpers)
    clf = Classifier(inv, decisions, stock, equivalence, translate=True,
                     list_loader=list_loader_for(source), date=date)
    clf.engine_helpers = engine_helpers
    clf.run()
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
    package = clf.translation.package
    report = build_report(inv, items, merged, wanted, stock_refs, tool, translated=True,
                          package=package, build=build, engine_limits=engine_limits)
    quality = Q.analyze(clf, package)
    return {"plan": plan, "decisions": merged, "report": report, "markdown": Q.attach(report, render(report), quality),
            "package": package, "classifier": clf, "quality": quality}
