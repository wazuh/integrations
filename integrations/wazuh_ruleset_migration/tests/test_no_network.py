"""scan, plan and stats open no network connection."""

import contextlib
import importlib
import io
import os
import shutil
import socket
import sys
import tempfile
import unittest
from unittest import mock

from helpers import MYAPP_DECODER, STOCK_MINI, etc_tree, rules_xml


class NetworkUsed(AssertionError):
    pass


def _forbid(*args, **kwargs):
    raise NetworkUsed("network access attempted")


class TestNoNetwork(unittest.TestCase):
    def test_import_and_run_without_sockets(self):
        tree = etc_tree(decoders={"myapp.xml": MYAPP_DECODER},
                        rules={"local_rules.xml": rules_xml("local,", '<rule id="100001" level="3"><decoded_as>myapp</decoded_as><field name="myapp.user">x</field><description>x</description></rule>')})
        work = tempfile.mkdtemp(prefix="rmig-net-")
        patches = [
            mock.patch.object(socket, "socket", _forbid),
            mock.patch.object(socket, "create_connection", _forbid),
            mock.patch.object(socket, "getaddrinfo", _forbid),
        ]
        sink = io.StringIO()
        saved = {n: m for n, m in sys.modules.items() if n == "rmig" or n.startswith("rmig.")}
        try:
            with contextlib.ExitStack() as stack:
                for p in patches:
                    stack.enter_context(p)
                stack.enter_context(contextlib.redirect_stdout(sink))
                stack.enter_context(contextlib.redirect_stderr(sink))
                # fresh import of the whole package under the patch
                for name in [n for n in sys.modules if n == "rmig" or n.startswith("rmig.")]:
                    del sys.modules[name]
                cli = importlib.import_module("rmig.cli")
                for mod in ("rmig.scan", "rmig.planner", "rmig.classify", "rmig.load_order", "rmig.tree",
                            "rmig.report", "rmig.report.markdown", "rmig.translate", "rmig.decisions", "rmig.fields"):
                    importlib.import_module(mod)
                self.assertEqual(cli.main(["scan", "--source", tree.root, "--workdir", work, "--stock-dir", STOCK_MINI]), 0)
                # the field runs in the decoder (RM-F-DECODER-CHECK): nothing waits for a decision
                self.assertEqual(cli.main(["plan", "--workdir", work]), 0)
                self.assertEqual(cli.main(["stats", "--workdir", work]), 0)
                self.assertEqual(cli.main(["stats", "--source", tree.root, "--stock-dir", STOCK_MINI]), 0)
        finally:
            for name in [n for n in sys.modules if n == "rmig" or n.startswith("rmig.")]:
                del sys.modules[name]
            sys.modules.update(saved)
            tree.cleanup()
            shutil.rmtree(work, ignore_errors=True)

    def test_no_network_imports_in_offline_modules(self):
        # The online commands (apply, rollback, verify, activate) live in rmig/api, rmig/verify and rmig/activate
        # and may use the standard library HTTP client. Everything else is offline and must not import it.
        pkg = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rmig")
        online = {os.path.join(pkg, d) for d in ("api", "verify", "activate")}
        banned = ("socket", "urllib", "http", "requests", "yaml", "lxml", "ssl")
        for base, _d, files in os.walk(pkg):
            if any(base == o or base.startswith(o + os.sep) for o in online):
                continue
            for name in files:
                if not name.endswith(".py"):
                    continue
                with open(os.path.join(base, name), encoding="utf-8") as fh:
                    for line in fh:
                        s = line.strip()
                        if s.startswith("import ") or s.startswith("from "):
                            mod = s.split()[1].split(".")[0]
                            self.assertNotIn(mod, banned, "%s: %s" % (name, s))

    def test_online_modules_use_only_stdlib_http(self):
        pkg = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rmig")
        banned = ("requests", "yaml", "lxml", "httpx", "urllib3")
        for sub in ("api", "verify", "activate"):
            for base, _d, files in os.walk(os.path.join(pkg, sub)):
                for name in files:
                    if name.endswith(".py"):
                        with open(os.path.join(base, name), encoding="utf-8") as fh:
                            text = fh.read()
                        for mod in banned:
                            self.assertNotRegex(text, r"(?m)^\s*(import|from)\s+%s\b" % mod, "%s/%s" % (sub, name))


if __name__ == "__main__":
    unittest.main()
