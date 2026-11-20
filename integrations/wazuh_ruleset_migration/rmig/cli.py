"""Command line: ``python3 -m rmig {scan,plan,build,migrate,stats}`` plus the
networked commands of :mod:`rmig.api.commands` when that module is present.

Exit codes: 0 correct; 1 ``DECISION`` items pending; 2 usage or
environment error (including an invalid ``decisions.json``).
"""

import argparse
import copy
import importlib
import os
import sys

from . import __version__
from . import decisions as D
from . import emit
from . import limits as L
from . import planner
from . import quality
from . import reasons as R
from . import stock as S
from .jsonio import read_json, write_json, write_text
from .report import build_report
from .report.markdown import render
from .scan import ScanError, scan
from .textsafe import plain
from .translate import helpers as H
from .translate import pipeline

DEFAULT_WORKDIR = "wazuh-ruleset-migration"
WHAT_IF_N = (1, 5, 10)
# what-if only: a keyword WCS field that stands for "the user mapped this field"
WHAT_IF_FIELD = "event.reason"


def _err(msg):
    print("error: %s" % plain(msg), file=sys.stderr)
    return 2


def _out_dir(workdir):
    return os.path.join(workdir, "out")


def _source_ruleset(source):
    """The ``ruleset/`` directory inside a ``--source`` that is a copy of the whole 4.x installation, or None."""
    cand = os.path.join(source, "ruleset") if source else None
    if cand and os.path.isfile(os.path.join(source, "etc", "ossec.conf")) and S.ruleset_dir(cand):
        return cand
    return None


def _use_stock(args):
    """Activate the stock index: ``--stock-dir``; else an index a caller of the
    package already set; else, for the commands that read the source, the
    ``ruleset/`` of a source that is a whole installation, then the manager
    default; else the workdir cache; else the manager default. Returns an
    error message or None."""
    # stats --source works in memory: no cache unless a workdir is named
    workdir = None if args.command == "stats" and args.source and not args.workdir_given else args.workdir
    fresh = args.command in ("scan", "migrate") or (args.command == "stats" and args.source)
    try:
        if args.stock_dir:
            S.use_stock_dir(args.stock_dir, workdir)
        elif S.active() is not None:
            pass
        elif fresh and _source_ruleset(args.source):
            S.use_stock_dir(_source_ruleset(args.source), workdir)
        elif fresh and S.ruleset_dir(S.DEFAULT_STOCK_DIR):
            S.use_stock_dir(S.DEFAULT_STOCK_DIR, workdir)
        elif workdir and S.use_cached(workdir):
            pass
        elif S.ruleset_dir(S.DEFAULT_STOCK_DIR):
            S.use_stock_dir(S.DEFAULT_STOCK_DIR, workdir)
        else:
            return ("no 4.x stock ruleset: pass --stock-dir with the ruleset/ directory of the 4.x manager "
                    "(%s on the manager, a copy of it, or the ruleset/ directory of a wazuh/wazuh checkout at the "
                    "tag of your 4.x version)" % S.DEFAULT_STOCK_DIR)
    except S.StockMissing as exc:
        return str(exc)
    return None


def _stock_cmd(func):
    def run(args):
        msg = _use_stock(args)
        if msg:
            return _err(msg)
        return func(args)
    return run


def cmd_scan(args):
    try:
        inv = scan(args.source)
    except ScanError as exc:
        return _err(str(exc))
    path = planner.paths(args.workdir)["inventory"]
    write_json(path, inv)
    nfiles = len(inv["files"])
    print("scan: %d rule(s), %d decoder(s), %d list(s) from %d file(s) (%s layout) -> %s" % (
        len(inv["rules"]), len(inv["decoders"]), len(inv["lists"]), nfiles, inv["source"]["mode"], path))
    for e in inv.get("conf_problems", {}).get("errors", []):
        if "leaves the source tree" in e.get("message", ""):
            print("scan: skipped %s" % plain(e["message"]))
    bad = [f for f in inv["files"] if f["errors"] or f["unknown"]]
    if bad:
        print("scan: %d file(s) with problems; see the report after plan" % len(bad))
    return 0


def _load_inputs(workdir):
    p = planner.paths(workdir)
    if not os.path.exists(p["inventory"]):
        raise planner.PlanError("no inventory at %s: run scan first" % p["inventory"])
    return read_json(p["inventory"]), D.load(p["decisions"])


def _write_plan(workdir, res):
    p = planner.paths(workdir)
    write_json(p["plan"], res["plan"])
    D.save(p["decisions"], res["decisions"])
    write_json(p["report_json"], res["report"])
    write_text(p["report_md"], res["markdown"])


def _limits(args):
    return L.parse(getattr(args, "engine_limit", None))


def _print_limits(cmd, res):
    for line in L.warnings((res["report"].get("build") or {}).get("limits")):
        print("%s: %s" % (cmd, line))


def cmd_plan(args):
    try:
        inv, decisions = _load_inputs(args.workdir)
        res = pipeline.compute(inv, decisions, engine_limits=_limits(args))
    except (planner.PlanError, D.DecisionsError, L.LimitError) as exc:
        return _err(str(exc))
    _write_plan(args.workdir, res)
    summary = res["plan"]["summary"]
    print("plan: " + ", ".join("%s %d" % (s, summary[s]) for s in R.STATES))
    _print_limits("plan", res)
    p = planner.paths(args.workdir)
    print("plan: wrote %s, %s, %s, %s" % (p["plan"], p["decisions"], p["report_json"], p["report_md"]))
    return 1 if summary[R.DECISION] else 0


def _build(workdir, source, date, engine_helpers=H.DEFAULT, engine_limits=None):
    inv, decisions = _load_inputs(workdir)
    res = pipeline.compute(inv, decisions, source=source, date=date, engine_helpers=engine_helpers,
                           engine_limits=engine_limits)
    pkg = res["package"]
    if pkg.missing_lists:
        raise planner.PlanError("the content of %d list(s) is needed (%s): pass --source with the 4.x tree" % (
            len(pkg.missing_lists), ", ".join(sorted(set(pkg.missing_lists)))))
    if pkg.helper_problems:
        raise planner.PlanError("the base decoders call helpers that engine %s does not have: %s" % (
            engine_helpers, "; ".join(pkg.helper_problems)))
    files = emit.render(pkg, inv)
    files.update(quality.files(res["quality"]))
    tool = "rmig %s" % __version__
    report = build_report(inv, res["plan"]["items"], res["decisions"], res["classifier"].wanted_decisions(),
                          res["plan"]["stock_references"], tool, translated=True, package=pkg,
                          build={"out": "out/", "files": len(files)}, engine_limits=engine_limits)
    report["build"]["engine_helpers"] = pkg.engine_helpers
    res["report"] = report
    res["markdown"] = _with_engine_helpers(quality.attach(report, render(report), res["quality"]), pkg.engine_helpers)
    emit.check_paths(_out_dir(workdir), files)
    _write_plan(workdir, res)
    emit.write(_out_dir(workdir), files)
    return res, files


def _with_engine_helpers(markdown, dialect):
    """The dialect under the first line of the Build section of report.md."""
    marker = "\n## Build\n\n"
    i = markdown.find(marker)
    if i < 0:
        return markdown
    j = markdown.find("\n", i + len(marker))
    line = "Engine helper names: `%s` (`--engine-helpers`)." % dialect
    return markdown[:j + 1] + line + "\n" + markdown[j + 1:]


def _build_summary(workdir, res, files):
    summary = res["plan"]["summary"]
    pkg = res["package"]
    print("build: " + ", ".join("%s %d" % (s, summary[s]) for s in R.STATES))
    nrules = sum(len(i["rules"]) for i in pkg.integrations.values())
    ndec = sum(len(i["decoders"]) for i in pkg.integrations.values())
    nkv = sum(len(i["kvdbs"]) for i in pkg.integrations.values())
    print("build: %d integration(s), %d decoder(s), %d kvdb(s), %d rule(s), %d monitor(s), %d recipe(s) -> %s (%d file(s)), engine helpers %s" % (
        len(pkg.integrations), ndec, nkv, nrules, len(pkg.monitors), len(pkg.recipes), _out_dir(workdir), len(files),
        pkg.engine_helpers))
    _print_limits("build", res)
    return 1 if summary[R.DECISION] else 0


def cmd_build(args):
    try:
        res, files = _build(args.workdir, args.source, args.date, args.engine_helpers, _limits(args))
    except (planner.PlanError, D.DecisionsError, L.LimitError, emit.UnsafePath) as exc:
        return _err(str(exc))
    return _build_summary(args.workdir, res, files)


def cmd_migrate(args):
    rc = cmd_scan(args)
    if rc:
        return rc
    return cmd_build(args)


def _stats_text(report, what_if=None):
    s = report["summary"]
    total = s["items"]
    lines = ["Items: %d (source %s, %s layout)" % (total, report["source"]["name"], report["source"]["mode"]), ""]
    lines.append("%-16s %8s %8s" % ("State", "Items", "Share"))
    for state in R.STATES:
        n = s["by_state"][state]
        lines.append("%-16s %8d %7.1f%%" % (state, n, 100.0 * n / total if total else 0.0))
    lines.append("")
    lines.append("%-12s %8s %8s %8s %8s" % ("Kind", "AUTO", "DECISION", "RECIPE", "N/A"))
    for kind, row in s["by_kind"].items():
        lines.append("%-12s %8d %8d %8d %8d" % (kind, row["AUTO"], row["DECISION"], row["RECIPE"], row["NOT_APPLICABLE"]))
    lines.append("")
    label = "translated" if report.get("translated") else "provisional"
    lines.append("AUTO fidelity (%s): exact %d, approximate %d" % (label, s["by_fidelity"]["exact"], s["by_fidelity"]["approximate"]))
    lines.append("")
    lines.append("%-28s %-15s %8s" % ("Reason code", "State", "Items"))
    for code, n in sorted(s["by_code"].items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append("%-28s %-15s %8d" % (code, R.CATALOG[code].state, n))
    lines.append("")
    lines.append("Stock rules, groups and decoders most referenced as parent by custom content:")
    lines.append("%-40s %8s  %-12s %s" % ("Reference", "Items", "Equivalence", "Stock location"))
    for r in report["stock_references"][:25]:
        lines.append("%-40s %8d  %-12s %s" % (r["ref"], r["count"], "yes" if r["equivalence"] else "no", r["stock_location"] or ""))
    if what_if is not None:
        lines.append("")
        lines.append("What-if: items that would go from DECISION to AUTO if every undecided field were mapped and")
        lines.append("the N most referenced stock references without equivalence had an entry (nothing is written:")
        lines.append("the entries are hypothetical; N = 0 maps the fields only):")
        lines.append("%-6s %10s %10s  %s" % ("N", "DEC->AUTO", "DECISION", "References"))
        for row in what_if:
            refs = ", ".join(row["refs"][:5]) + (" and %d more" % (len(row["refs"]) - 5) if len(row["refs"]) > 5 else "")
            lines.append("%-6d %10d %10d  %s" % (row["n"], row["to_auto"], row["decision_after"], refs))
    return "\n".join(lines) + "\n"


def what_if(inv, decisions, base_res=None, ns=WHAT_IF_N):
    """Rows ``{n, refs, to_auto, decision_after}``: with every undecided
    field mapped and the ``n`` most referenced stock references without
    equivalence resolved in memory by a hypothetical entry (the integration of
    the tool's base, a selection on ``wazuh.integration.name``), how many
    items leave ``DECISION`` for ``AUTO``. Row ``n = 0`` maps the fields only.
    Nothing is written and no equivalence is invented."""
    base_res = base_res or pipeline.compute(inv, decisions)
    before = {it["uid"]: it["state"] for it in base_res["plan"]["items"]}
    cands = [r["ref"] for r in base_res["plan"]["stock_references"] if not r["equivalence"]]
    merged = base_res["decisions"]
    rows = []
    for n in (0,) + tuple(ns):
        refs = cands[:n]
        hyp = copy.deepcopy(decisions)
        hyp.setdefault("fields", {})
        hyp.setdefault("stock", {})
        for ref in refs:
            entry = {"integration": "wazuh-core"}
            if not ref.startswith("decoder:"):
                entry["selection"] = {"wazuh.integration.name": "what-if"}
            hyp["stock"][ref] = entry
        fields = merged.get("fields", {})
        res = None
        for _ in range(4):
            # a rule over stock content asks its fields only once its stock reference resolves: map, run again
            new = [k for k, e in fields.items() if e.get("action") is None and k not in hyp["fields"]]
            if not new and res is not None:
                break
            for name in new:
                hyp["fields"][name] = {"action": "map", "wcs": WHAT_IF_FIELD}
            res = pipeline.compute(inv, hyp)
            fields = res["decisions"].get("fields", {})
        after = {it["uid"]: it["state"] for it in res["plan"]["items"]}
        rows.append({"n": n, "refs": refs,
                     "to_auto": sum(1 for u, s in before.items() if s == R.DECISION and after.get(u) == R.AUTO),
                     "decision_after": sum(1 for s in after.values() if s == R.DECISION)})
    return rows


def cmd_stats(args):
    wi = None
    if args.source:
        try:
            inv = scan(args.source)
        except ScanError as exc:
            return _err(str(exc))
        try:
            decisions = D.load(planner.paths(args.workdir)["decisions"]) if args.workdir_given else D.empty()
        except D.DecisionsError as exc:
            return _err(str(exc))
        res = pipeline.compute(inv, decisions)
        report = res["report"]
        wi = what_if(inv, decisions, res)
    else:
        p = planner.paths(args.workdir)
        if os.path.exists(p["inventory"]):
            try:
                inv, decisions = read_json(p["inventory"]), D.load(p["decisions"])
            except D.DecisionsError as exc:
                return _err(str(exc))
            res = pipeline.compute(inv, decisions)
            report = read_json(p["report_json"]) if os.path.exists(p["report_json"]) else res["report"]
            wi = what_if(inv, decisions, res)
        elif os.path.exists(p["report_json"]):
            report = read_json(p["report_json"])
        else:
            return _err("nothing to report in %s: run scan and plan, or pass --source" % args.workdir)
    sys.stdout.write(_stats_text(report, wi))
    return 0


def _register_external(sub):
    """Commands of other parts (``rmig.api.commands.register``), if present."""
    try:
        mod = importlib.import_module("rmig.api.commands")
    except ModuleNotFoundError as exc:
        if exc.name in ("rmig.api", "rmig.api.commands"):
            return
        print("warning: rmig.api.commands could not be loaded: %s" % exc, file=sys.stderr)
        return
    except Exception as exc:  # pragma: no cover - a broken optional module must not stop scan/plan/build
        print("warning: rmig.api.commands could not be loaded: %s" % exc, file=sys.stderr)
        return
    register = getattr(mod, "register", None)
    if callable(register):
        register(sub)


def build_parser():
    ap = argparse.ArgumentParser(prog="rmig", description="Wazuh 4.14 ruleset migration to 5.x.")
    ap.add_argument("--version", action="version", version="rmig %s" % __version__)
    sub = ap.add_subparsers(dest="command")

    def add_workdir(p):
        p.add_argument("--workdir", default=None, help="working directory (default ./%s)" % DEFAULT_WORKDIR)

    def add_stock_dir(p):
        p.add_argument("--stock-dir", default=None, metavar="DIR",
                       help="the 4.x stock ruleset/ directory. Default on scan and migrate: the ruleset/ of a "
                            "--source that is a copy of the whole installation, else %s if it exists. Default on "
                            "the other commands: the index cached in the working directory by scan"
                            % S.DEFAULT_STOCK_DIR)

    def add_engine_helpers(p):
        p.add_argument("--engine-helpers", choices=H.DIALECTS, default=H.DEFAULT,
                       help="helper names of the target engine: 5.0 (wazuh main, default) or 5.0-rc1 (before the "
                            "renames of wazuh/wazuh#41150)")

    def add_engine_limits(p):
        p.add_argument("--engine-limit", action="append", default=[], metavar="NAME=N",
                       help="a limit of the target indexer, after its cluster setting is raised (repeatable): %s"
                            % ", ".join("%s (default %d)" % (n, L.LIMITS[n][0]) for n in L.NAMES))

    p = sub.add_parser("scan", help="read a 4.14 tree into work/inventory.json")
    p.add_argument("--source", required=True, help="copy of etc/ (with ossec.conf), of /var/ossec, or a tree of loose rule files")
    add_workdir(p)
    add_stock_dir(p)
    p.set_defaults(func=_stock_cmd(cmd_scan))

    p = sub.add_parser("plan", help="classify and translate the inventory; write plan.json, decisions.json and the report")
    add_workdir(p)
    add_engine_limits(p)
    add_stock_dir(p)
    p.set_defaults(func=_stock_cmd(cmd_plan))

    p = sub.add_parser("build", help="translate and write out/ (integrations, decoders, kvdbs, rules, monitors, recipes, mapping)")
    add_workdir(p)
    p.add_argument("--source", default=None, help="the 4.x tree scanned (needed for the content of the lists)")
    p.add_argument("--date", default=None, help="metadata.date of every resource (none by default: reproducible output)")
    add_engine_helpers(p)
    add_engine_limits(p)
    add_stock_dir(p)
    p.set_defaults(func=_stock_cmd(cmd_build))

    p = sub.add_parser("migrate", help="scan + plan + build")
    p.add_argument("--source", required=True, help="copy of etc/ (with ossec.conf), of /var/ossec, or a tree of loose rule files")
    add_workdir(p)
    p.add_argument("--date", default=None, help="metadata.date of every resource (none by default)")
    add_engine_helpers(p)
    add_engine_limits(p)
    add_stock_dir(p)
    p.set_defaults(func=_stock_cmd(cmd_migrate))

    p = sub.add_parser("stats", help="table by state and reason code, the most referenced stock content and a what-if")
    p.add_argument("--source", default=None, help="scan this tree in memory instead of reading the working directory")
    add_workdir(p)
    add_stock_dir(p)
    p.set_defaults(func=_stock_cmd(cmd_stats))

    _register_external(sub)
    return ap


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    if not getattr(args, "func", None):
        ap.print_help()
        return 2
    args.workdir_given = args.workdir is not None
    if args.workdir is None:
        args.workdir = DEFAULT_WORKDIR
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
