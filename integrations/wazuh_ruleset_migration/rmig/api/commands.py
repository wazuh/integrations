"""Networked commands: ``apply``, ``rollback``, ``verify`` and ``activate``.

``register(subparsers)`` adds them to the ``rmig`` parser (``cli.py`` calls
it). Exit codes: 0 correct; 1 an integration set aside by the engine,
a verification failure (``NOT_REPRODUCED``/``NOT_SILENCED``) or an activation
without a clean verification; 2 usage or environment error, including every
stop that protects content the tool does not own (``RM-P-*``).

Credentials: ``WAZUH_INDEXER_URL`` (or ``--url``), ``WAZUH_INDEXER_USER`` and
``WAZUH_INDEXER_PASSWORD``, or ``--credentials-file`` with one line
``USER:PASSWORD``. They are never written anywhere.
"""

import argparse
import os
import sys

from .client import ApiError, Client, ConnectionFailed, CredentialsError, resolve_connection, transport_warnings
from .outdir import OutError

DEFAULT_WORKDIR = "wazuh-ruleset-migration"


def _add_common(p):
    p.add_argument("--workdir", default=None, help="working directory (default ./%s)" % DEFAULT_WORKDIR)
    p.add_argument("--out", default=None, help="the build output (default <workdir>/out)")
    p.add_argument("--url", default=None, help="indexer URL (default: $WAZUH_INDEXER_URL)")
    p.add_argument("--credentials-file", default=None,
                   help="file with one line USER:PASSWORD (default: $WAZUH_INDEXER_USER and $WAZUH_INDEXER_PASSWORD)")
    p.add_argument("--ca", default=None, help="CA bundle that signs the indexer certificate")
    p.add_argument("--insecure", action="store_true", help="do not verify the indexer certificate")


def register(subparsers):
    p = subparsers.add_parser("apply", help="create the tool's content in draft and promote it to test, per integration")
    _add_common(p)
    p.add_argument("--dry-run", action="store_true", help="print the calls without writing anything")
    p.add_argument("--include-foreign-changes", action="store_true",
                   help="promote pending changes the tool did not make together with its own (recorded)")
    p.add_argument("--accept-unclassified-indexing", action="store_true",
                   help="go on although the custom policy indexes unclassified events (recorded)")
    p.add_argument("--engine-limit", action="append", default=[], metavar="NAME=N",
                   help="a limit of the indexer, after its cluster setting is raised (repeatable; see build)")
    p.set_defaults(func=cmd_apply)

    p = subparsers.add_parser("rollback", help="remove the tool's content from draft and test, and with --yes from "
                                               "custom with its detectors (wazuh4-base stays while its root is the "
                                               "policy root)")
    _add_common(p)
    p.add_argument("--dry-run", action="store_true", help="print the calls without writing anything")
    p.add_argument("--include-foreign-changes", action="store_true",
                   help="promote pending changes the tool did not make together with the removals (recorded)")
    p.add_argument("--yes", action="store_true",
                   help="also delete the tool's detectors and promote the removals test -> custom: this changes "
                        "what the manager runs")
    p.set_defaults(func=cmd_rollback)

    p = subparsers.add_parser("verify", help="re-inject the logs of 4.14 alerts and compare (verification.{md,json})")
    _add_common(p)
    p.add_argument("--alerts", nargs="+", required=True, metavar="FILE", help="alerts.json files (.json or .json.gz)")
    p.add_argument("--samples", default=None, metavar="DIR", help="directory with <4.x rule id>.log sample lines")
    p.add_argument("--via-detector", action="store_true",
                   help="also run a sample through a temporary detector of the tool's own")
    p.add_argument("--limit", type=int, default=None, metavar="N", help="samples per rule (default 20)")
    p.add_argument("--include-events", action="store_true", help="list the events in verification.md too")
    p.add_argument("--engine-socket", default=None, metavar="PATH",
                   help="no indexer: run the events through the 5.x engine on this unix socket (standalone package "
                        "or 5.0 manager) and check the rules locally; writes verification-offline.{md,json}")
    p.add_argument("--catalog", default=None, metavar="DIR",
                   help="with --engine-socket: a 5.x catalog snapshot directory, for the rules over stock events")
    p.set_defaults(func=cmd_verify, dry_run=False)

    p = subparsers.add_parser("activate", help="promote the tool's content test -> custom and create the detectors")
    _add_common(p)
    p.add_argument("--yes", action="store_true", help="required: this changes what the manager runs")
    p.add_argument("--force", action="store_true", help="activate without a clean verification (recorded)")
    p.add_argument("--include-foreign-changes", action="store_true",
                   help="promote pending changes the tool did not make together with its own (recorded)")
    p.add_argument("--dry-run", action="store_true", help="print the calls without writing anything")
    p.set_defaults(func=cmd_activate)


def _runner(args, env=None):
    from .apply import Runner

    url, user, secret = resolve_connection(args.url, args.credentials_file, env)
    if args.ca and not os.path.isfile(args.ca):
        raise CredentialsError("the CA file %s does not exist" % args.ca)
    for line in transport_warnings(url, args.insecure):
        print(line, file=sys.stderr)
    client = Client(url, user, secret, ca=args.ca, insecure=args.insecure)
    workdir = args.workdir or DEFAULT_WORKDIR
    return Runner(client, workdir, args.out, dry_run=getattr(args, "dry_run", False))


def _guard(fn, args):
    try:
        return fn(_runner(args, getattr(args, "env", None)))
    except CredentialsError as exc:
        print("error: %s" % exc, file=sys.stderr)
    except (OutError, ConnectionFailed) as exc:
        print("error: %s" % exc, file=sys.stderr)
    except ApiError as exc:
        print("error: %s" % exc, file=sys.stderr)
    return 2


def cmd_apply(args):
    from .. import limits as L
    from .apply import Apply

    try:
        lim = L.parse(args.engine_limit)
    except L.LimitError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    return _guard(lambda r: Apply(r, args.include_foreign_changes, args.accept_unclassified_indexing, lim).run(), args)


def cmd_rollback(args):
    from .apply import Rollback

    return _guard(lambda r: Rollback(r, args.include_foreign_changes, args.yes).run(), args)


def cmd_verify(args):
    from ..verify import Verify
    from ..verify.alerts import AlertsError

    for f in args.alerts:
        if not os.path.isfile(f):
            print("error: no alerts file %s" % f, file=sys.stderr)
            return 2
    if args.samples and not os.path.isdir(args.samples):
        print("error: no samples directory %s" % args.samples, file=sys.stderr)
        return 2
    if args.limit is not None and args.limit < 1:
        print("error: --limit must be at least 1", file=sys.stderr)
        return 2
    if args.catalog and not args.engine_socket:
        print("error: --catalog goes with --engine-socket (the indexer has its own stock content)", file=sys.stderr)
        return 2
    if args.engine_socket:
        return cmd_verify_offline(args)

    def run(r):
        try:
            return Verify(r, args.alerts, args.samples, args.via_detector, args.limit, args.include_events).run()
        except AlertsError as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 2

    return _guard(run, args)


def cmd_verify_offline(args, transport=None):
    """``verify --engine-socket``: no indexer, no credentials. ``transport`` replays recorded answers in the tests."""
    from ..verify import Verify
    from ..verify.alerts import AlertsError
    from ..verify.engine import EngineClient, EngineError, unix_sockets_available
    from ..verify.offline import OfflineEngine
    from .apply import Runner

    if args.via_detector:
        print("error: --via-detector needs the indexer; it does not go with --engine-socket", file=sys.stderr)
        return 2
    if args.catalog and not os.path.isdir(args.catalog):
        print("error: no catalog directory %s" % args.catalog, file=sys.stderr)
        return 2
    if transport is None and not unix_sockets_available():
        print("error: this Python has no unix sockets (Windows). Run rmig where the engine socket is: on the Linux "
              "host, in the engine's container, or in WSL with the socket", file=sys.stderr)
        return 2
    if transport is None and not os.path.exists(args.engine_socket):
        print("error: no engine socket %s (standalone package: <dir>/sockets/engine-api-http.sock; 5.0 manager: "
              "/var/wazuh-manager/queue/sockets/engine-api-http.sock)" % args.engine_socket, file=sys.stderr)
        return 2
    runner = Runner(None, args.workdir or DEFAULT_WORKDIR, args.out)
    engine = OfflineEngine(EngineClient(args.engine_socket, transport=transport), args.catalog, runner.say)
    try:
        return Verify(runner, args.alerts, args.samples, False, args.limit, args.include_events, offline=engine).run()
    except AlertsError as exc:
        print("error: %s" % exc, file=sys.stderr)
    except OutError as exc:
        print("error: %s" % exc, file=sys.stderr)
    except EngineError as exc:
        print("error: engine: %s" % exc, file=sys.stderr)
    return 2


def cmd_activate(args):
    from ..activate import Activate

    if not args.yes:
        print("error: activate changes what the manager runs; pass --yes to confirm", file=sys.stderr)
        return 2
    return _guard(lambda r: Activate(r, args.force, args.include_foreign_changes).run(), args)


def main(argv=None, env=None):
    """Stand-alone entry (tests, and until ``cli.py`` registers the commands)."""
    ap = argparse.ArgumentParser(prog="rmig")
    register(ap.add_subparsers(dest="command"))
    args = ap.parse_args(argv)
    if not getattr(args, "func", None):
        ap.print_help()
        return 2
    args.env = env
    return args.func(args)
