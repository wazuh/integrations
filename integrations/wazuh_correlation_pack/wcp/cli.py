"""wcp - deploy and manage the Wazuh correlation pack.

Offline commands (no indexer needed): validate, render.
Indexer commands: preflight, plan, apply, status, remove, rollback, execute.
"""

import argparse
import json
import os
import sys

from . import alerting as A
from . import config as C
from . import deploy as D
from . import sigma as S
from .client import DEFAULT_ENV_FILE, Client, load_env_file

PACK_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(args):
    base_rules, correlations = S.load_content(args.content)
    profile = C.load_profile(args.profile, args.override)
    names = {c.name for c in correlations}
    for n in (profile.get("correlations") or {}):
        if n not in names:
            raise C.ConfigError("profile references unknown correlation %r" % n)
    only = set(args.only.split(",")) if getattr(args, "only", None) else None
    if only and only - names:
        raise SystemExit("unknown correlation(s): %s" % ", ".join(sorted(only - names)))
    return base_rules, correlations, profile, only


def _client(args):
    """Load the selected env file, resolve the state directory, connect.

    Precedence of every setting, highest first: command-line option, process environment, the
    selected env file (``--env-file``, else ``WCP_ENV_FILE``, else the default file; it only fills
    variables not already set), built-in default. The state directory is resolved *after* the env
    file is read, so ``WCP_STATE_DIR`` in the env file is honoured.
    """
    in_env = os.environ.get("WCP_STATE_DIR")
    load_env_file(args.env_file)
    if args.state_dir:
        args.state_source = "--state-dir"
    elif in_env:
        args.state_dir, args.state_source = in_env, "environment"
    elif os.environ.get("WCP_STATE_DIR"):
        args.state_dir, args.state_source = os.environ["WCP_STATE_DIR"], "env file %s" % args.env_file
    else:
        args.state_dir, args.state_source = C.default_state_dir(), "default"
    return Client()


class ManifestRefused(SystemExit):
    pass


def _manifest(args, client, mutating=False):
    """The manifest of this target, checked against the connected cluster before it is used.

    A manifest records the ``cluster_uuid`` it was written for. A manifest of another cluster is
    refused for every command. An existing manifest without that identity (written before it was
    recorded) is never bound silently: read-only commands warn, commands that change resources
    refuse unless ``--bind-manifest`` is given. A new manifest is bound when it is first saved.
    """
    target = os.environ.get("WCP_TARGET") or "%s_%s" % (client.host, client.port)
    path = os.path.join(args.state_dir, "%s.manifest.json" % target.replace(":", "_").replace("/", "_"))
    m = D.Manifest(path, target)
    print("state: %s (%s)" % (path, getattr(args, "state_source", "?")))
    uuid = (client.get("/") or {}).get("cluster_uuid")
    bound = m.data.get("cluster_uuid")
    if bound and uuid and bound != uuid:
        raise ManifestRefused("refusing: manifest %s belongs to another cluster (cluster_uuid %s); the connected "
                              "cluster is %s. Use the state directory / WCP_TARGET of this cluster." % (path, bound, uuid))
    if not bound and os.path.isfile(path):
        if mutating and not getattr(args, "bind_manifest", False):
            raise ManifestRefused("refusing: manifest %s has no cluster identity (written before it was recorded). "
                                  "Check that it belongs to the connected cluster %s, then re-run with "
                                  "--bind-manifest to record it." % (path, uuid))
        if not mutating:
            print("warning: manifest %s has no cluster identity; it is not bound to cluster %s by read-only "
                  "commands" % (path, uuid))
    if not bound and uuid:
        m.data["cluster_uuid"] = uuid   # saved only by commands that change resources
    return m


def _print_steps(steps):
    for op, _cid, name, mid, _body, reason in steps:
        print("  %-7s %-70s %s  (%s)" % (op, name, mid or "-", reason))


def cmd_validate(args):
    base_rules, correlations, profile, _only = _load(args)
    for c in correlations:
        s = C.settings_for(profile, c.name)
        A.render_monitor(c, s, profile["version"])
        print("ok  %-36s %-11s group-by=%s timespan=%s %s %d%s rules=%s" % (
            c.name, c.type, "+".join(c.group_by), c.timespan_text, c.op, c.threshold,
            (" field=%s" % c.value_field) if c.value_field else "", ",".join(r.name for r in c.rules)))
        print("    interval=%s allowed_lateness=%s lookback=%ss indices=%s" % (
            s["interval"], s["allowed_lateness"], A.lookback_seconds(c, s), ",".join(s["indices"])))
    print("%d base rule(s), %d correlation(s) valid" % (len(base_rules), len(correlations)))
    return 0


def cmd_render(args):
    _b, correlations, profile, only = _load(args)
    out = {}
    for c in correlations:
        if only and c.name not in only:
            continue
        out[c.name] = A.render_monitor(c, C.settings_for(profile, c.name), profile["version"])
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        for name, body in out.items():
            with open(os.path.join(args.out, name + ".monitor.json"), "w", encoding="utf-8") as fh:
                json.dump(body, fh, indent=2, sort_keys=True)
                fh.write("\n")
        print("wrote %d monitor(s) to %s" % (len(out), args.out))
    else:
        json.dump(out, sys.stdout, indent=2, sort_keys=True)
        print()
    return 0


def cmd_preflight(args):
    _b, correlations, profile, only = _load(args)
    client = _client(args)
    sel = [c for c in correlations if not only or c.name in only]
    worst = 0
    for level, msg in D.preflight(client, sel, profile, C.settings_for):
        print("[%s] %s" % (level, msg))
        worst = max(worst, {"ok": 0, "warn": 1, "error": 2}[level])
    return 2 if worst == 2 else 0


def cmd_plan(args, do_apply=False):
    _b, correlations, profile, only = _load(args)
    client = _client(args)
    desired = D.desired_monitors(correlations, profile, C.settings_for, only)
    manifest = _manifest(args, client, mutating=do_apply)
    steps, foreign = D.plan(client, desired, prune=not args.no_prune, only=only, manifest=manifest)
    print("pack %s %s -> %s (%d unrelated monitor(s) left untouched)" % (
        profile["pack"], profile["version"], client.host + ":" + str(client.port), foreign))
    _print_steps(steps)
    changes = [s for s in steps if s[0] != "noop"]
    if not do_apply:
        print("plan: %d change(s); run 'apply' to execute" % len(changes))
        return 0
    res = D.apply_steps(client, steps, manifest, profile["version"], action="apply")
    print("applied: %d change(s), %d unchanged; manifest %s" % (
        len(changes), len(steps) - len(changes), manifest.path))
    for op, name, mid, _r in res:
        if op != "noop":
            print("  %s %s -> %s" % (op, name, mid))
    return 0


def cmd_status(args):
    _b, correlations, profile, only = _load(args)
    client = _client(args)
    desired = D.desired_monitors(correlations, profile, C.settings_for, only)
    rows, extra, foreign = D.status(client, desired, _manifest(args, client))
    if args.json:
        json.dump({"monitors": rows, "orphans": extra, "unrelated_monitors": foreign}, sys.stdout, indent=2)
        print()
        return 0
    for r in rows:
        if not r["deployed"]:
            print("%-36s NOT DEPLOYED" % r["correlation"])
            continue
        print("%-36s id=%s enabled=%s version=%s in_sync=%s active=%d total=%d" % (
            r["correlation"], r["monitor_id"], r["enabled"], r["pack_version"], r["in_sync"],
            r["active_alerts"], r["total_alerts"]))
        for k in r["active_keys"]:
            print("    active: %s" % k)
    for e in extra:
        print("%-36s id=%s %s" % (e["correlation"], e["monitor_id"], e["note"]))
    print("(%d unrelated monitor(s) not managed by the pack)" % foreign)
    return 0


def cmd_remove(args):
    _b, _c, profile, _only = _load(args)
    client = _client(args)
    manifest = _manifest(args, client, mutating=args.yes)
    steps, foreign = D.remove_all(client, manifest, profile["version"])
    print("remove: %d pack monitor(s); %d unrelated monitor(s) untouched" % (len(steps), foreign))
    _print_steps(steps)
    if not args.yes:
        print("dry run; add --yes to delete")
        return 0
    D.apply_steps(client, steps, manifest, profile["version"], action="remove")
    print("removed; manifest %s" % manifest.path)
    return 0


def cmd_rollback(args):
    _b, _c, profile, _only = _load(args)
    client = _client(args)
    manifest = _manifest(args, client, mutating=args.yes)
    steps, version = D.rollback_steps(client, manifest)
    print("rollback to pack version %s:" % version)
    _print_steps(steps)
    if not args.yes:
        print("dry run; add --yes to execute")
        return 0
    D.apply_steps(client, steps, manifest, version, action="rollback")
    return 0


def cmd_execute(args):
    """Run a deployed monitor once through the Alerting execute API (dry run: no alerts are written)."""
    _b, correlations, profile, only = _load(args)
    client = _client(args)
    owned, _f = D.list_owned_monitors(client, _manifest(args, client).monitor_ids())
    owned.pop("__duplicates__", None)
    for c in correlations:
        if only and c.name not in only:
            continue
        if c.id not in owned:
            print("%s: not deployed" % c.name)
            continue
        mid = owned[c.id][0]
        params = {"dryrun": "true"}
        res = client.post(D.MONITORS + "/%s/_execute" % mid, params=params)
        took = client.last_duration_ms
        tr = (res.get("trigger_results") or {})
        for _tid, t in tr.items():
            buckets = t.get("agg_result_buckets") or {}
            print("%s: %d triggering bucket(s) [%d ms]%s" % (c.name, len(buckets), took,
                                                            (" error=%s" % t.get("error")) if t.get("error") else ""))
            for _k, b in buckets.items():
                b = b.get("agg_alert_content", b)
                det = (b.get("bucket") or {}).get(A.DETAIL_AGG, {}).get("value")
                print("   %s %s" % (b.get("bucket_keys"), json.dumps(det, sort_keys=True)))
        ir = res.get("input_results") or {}
        if ir.get("error"):
            print("   input error: %s" % ir["error"])
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="wcp", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--content", default=PACK_ROOT, help="pack root holding rules/ and correlations/")
    p.add_argument("--profile", default=os.path.join(PACK_ROOT, "pack.yml"))
    p.add_argument("--override", help="local profile override (YAML)")
    p.add_argument("--env-file", default=os.environ.get("WCP_ENV_FILE", DEFAULT_ENV_FILE))
    p.add_argument("--state-dir", default=None,
                   help="manifest directory (default: WCP_STATE_DIR from the environment or the env file, else ~/.config/wazuh_correlation_pack/state)")
    sub = p.add_subparsers(dest="cmd")
    sub.required = True
    for name in ("validate", "render", "preflight", "plan", "apply", "status", "remove", "rollback", "execute"):
        sp = sub.add_parser(name)
        sp.add_argument("--only", help="comma-separated correlation names")
        if name == "render":
            sp.add_argument("--out", help="directory for <name>.monitor.json files")
        if name in ("plan", "apply"):
            sp.add_argument("--no-prune", action="store_true",
                            help="keep pack monitors whose correlation was removed from the pack")
        if name in ("remove", "rollback"):
            sp.add_argument("--yes", action="store_true")
        if name in ("apply", "remove", "rollback"):
            sp.add_argument("--bind-manifest", action="store_true",
                            help="record the connected cluster in an existing manifest that has no cluster identity")
        if name == "status":
            sp.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    try:
        if args.cmd == "validate":
            return cmd_validate(args)
        if args.cmd == "render":
            return cmd_render(args)
        if args.cmd == "preflight":
            return cmd_preflight(args)
        if args.cmd == "plan":
            return cmd_plan(args)
        if args.cmd == "apply":
            return cmd_plan(args, do_apply=True)
        if args.cmd == "status":
            return cmd_status(args)
        if args.cmd == "remove":
            return cmd_remove(args)
        if args.cmd == "rollback":
            return cmd_rollback(args)
        if args.cmd == "execute":
            return cmd_execute(args)
    except (S.SigmaError, C.ConfigError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    except RuntimeError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    return 0
