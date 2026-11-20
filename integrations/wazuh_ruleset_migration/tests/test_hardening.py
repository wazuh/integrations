"""Masking of ossec.conf values, the local regular expression guard, the stock index cache and the out/ guard."""

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from helpers import HERE, STOCK_INDEX, STOCK_MINI

from rmig import cli, emit, stock
from rmig.parse.ossec_conf import MASK, mask_value, parse_ossec_conf
from rmig.verify import sigma

TOOL_ROOT = os.path.dirname(HERE)
EXAMPLE_ETC = os.path.join(TOOL_ROOT, "examples", "acmepay", "etc")


def run_cli(*argv):
    """The command line in a new process: no stock index is active there."""
    proc = subprocess.run([sys.executable, "-m", "rmig"] + list(argv), cwd=TOOL_ROOT, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, universal_newlines=True, timeout=300)
    return proc.returncode, proc.stdout


class TestMasking(unittest.TestCase):
    def test_secret_names_fail_closed(self):
        for name in ("secret_value", "account_key", "sas_token", "auth_token", "api_auth", "private_key",
                     "wodle.access_key", "bucket.Secret_Key", "client_credentials", "hook_url", "passphrase",
                     "options", "aws_session_token"):
            self.assertEqual(mask_value(name, "T0K"), MASK, name)
        for name in ("name", "level", "location", "log_format", "rules_id", "group", "executable", "timeout"):
            self.assertEqual(mask_value(name, "value"), "value", name)

    def test_extra_args_has_no_program(self):
        self.assertEqual(mask_value("extra_args", "S3CRET --verbose"), "*** --verbose")
        self.assertEqual(mask_value("command.extra_args", "S3CRET"), MASK)
        self.assertEqual(mask_value("extra_args", "-f /etc/app/list.conf"), "-f /etc/app/list.conf")

    def test_only_real_paths_are_kept(self):
        for cmd in ("sqlplus scott/T0K", "aws configure set aws_secret_access_key wJalrXUtnFEMI/K7MDENG/T0K",
                    "login.sh admin/T0K/x", "tool T0K/etc"):
            self.assertNotIn("T0K", mask_value("command", cmd), cmd)
        self.assertEqual(mask_value("command", "refresh.sh etc/lists/bad-ips /var/ossec/etc/lists/bad-ips ./etc/x"),
                         "refresh.sh etc/lists/bad-ips /var/ossec/etc/lists/bad-ips ./etc/x")

    def test_xml_errors_of_ossec_conf_quote_nothing(self):
        conf = '<ossec_config><integration><name junk T0KSECRET="x">a</name></integration></ossec_config></x T0KTAIL>'
        _config, problems = parse_ossec_conf(conf)
        self.assertTrue(problems["errors"])
        self.assertNotIn("T0K", json.dumps(problems))


class TestRegexGuard(unittest.TestCase):
    def test_counted_groups_and_alternation_chains_are_not_run(self):
        chain = "(a|a)" * 24 + "b"
        for pattern, value in (("(a?){30}a{30}", "a" * 30), ("(a+){20}b", "a" * 40), ("(.*a){12}", "a" * 40 + "b"),
                               ("(a+){2}b", "a" * 40), (chain, "a" * 40)):
            self.assertIsNotNone(sigma.catastrophic(pattern), pattern)
            started = time.time()
            why = []
            self.assertIsNone(sigma._one(value, pattern, "re", why))
            self.assertFalse(sigma._match_value(value, pattern, ["re"]))
            self.assertLess(time.time() - started, 1.0, pattern)
            self.assertTrue(why, pattern)

    def test_plain_counted_groups_still_run(self):
        for pattern in ("(ab){3}", "(a+){1}", "(a|b){0,1}c", "(ab){1,1}", "(x|y)(a|b)c"):
            self.assertIsNone(sigma.catastrophic(pattern), pattern)
        self.assertTrue(sigma._one("ababab", "(ab){3}", "re", []))


class TestStockCache(unittest.TestCase):
    def tearDown(self):
        stock.set_active(STOCK_INDEX)

    def test_corrupt_or_old_cache_is_rebuilt(self):
        with tempfile.TemporaryDirectory() as work:
            first = stock.use_stock_dir(STOCK_MINI, work)
            path = stock.cache_path(work)
            for text in ('{"rules": [', "[]", json.dumps({"version": stock.INDEX_VERSION, "fingerprint":
                                                         first.data["fingerprint"]})):
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(text)
                self.assertFalse(stock.use_cached(work))
                again = stock.use_stock_dir(STOCK_MINI, work)
                self.assertEqual(len(again.rules), len(first.rules))
            data = dict(first.data, version=stock.INDEX_VERSION + 1, rules=[])
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            self.assertEqual(len(stock.use_stock_dir(STOCK_MINI, work).rules), len(first.rules))

    def test_stock_dir_without_content_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "rules"))
            os.makedirs(os.path.join(tmp, "decoders"))
            with self.assertRaises(stock.StockMissing) as cm:
                stock.use_stock_dir(tmp)
            self.assertIn("no rule and no decoder", str(cm.exception))


class TestStockCommandLine(unittest.TestCase):
    """New processes: the tests above run with an index already active."""

    def test_migrate_then_plan_build_stats_from_the_cache(self):
        with tempfile.TemporaryDirectory() as work:
            rc, out = run_cli("migrate", "--source", EXAMPLE_ETC, "--stock-dir", STOCK_MINI, "--workdir", work)
            self.assertIn(rc, (0, 1), out)
            self.assertTrue(os.path.exists(stock.cache_path(work)))
            for argv in (("plan",), ("build", "--source", EXAMPLE_ETC), ("stats",)):
                rc, out = run_cli(*argv, "--workdir", work)
                self.assertIn(rc, (0, 1), out)
                self.assertNotIn("Traceback", out)

    def test_no_stock_and_broken_cache_stop_with_exit_2(self):
        if stock.ruleset_dir(stock.DEFAULT_STOCK_DIR):
            self.skipTest("this host has %s" % stock.DEFAULT_STOCK_DIR)
        with tempfile.TemporaryDirectory() as work:
            rc, out = run_cli("migrate", "--source", EXAMPLE_ETC, "--workdir", work)
            self.assertEqual(rc, 2, out)
            self.assertIn("--stock-dir", out)
            self.assertNotIn("Traceback", out)
            os.makedirs(os.path.join(work, "work"))
            with open(stock.cache_path(work), "w", encoding="utf-8") as fh:
                fh.write('{"version": 1, "rules": [')
            rc, out = run_cli("plan", "--workdir", work)
            self.assertEqual(rc, 2, out)
            self.assertIn("--stock-dir", out)
            self.assertNotIn("Traceback", out)

    def test_source_that_is_a_whole_installation_brings_its_ruleset(self):
        if stock.ruleset_dir(stock.DEFAULT_STOCK_DIR):
            self.skipTest("this host has %s" % stock.DEFAULT_STOCK_DIR)
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "ossec")
            shutil.copytree(EXAMPLE_ETC, os.path.join(root, "etc"))
            shutil.copytree(os.path.join(STOCK_MINI, "ruleset"), os.path.join(root, "ruleset"))
            work = os.path.join(tmp, "w")
            rc, out = run_cli("scan", "--source", root, "--workdir", work)
            self.assertEqual(rc, 0, out)
            self.assertIn("root layout", out)
            with open(stock.cache_path(work), "r", encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["counts"]["rule_files"], 3)


class TestOutGuard(unittest.TestCase):
    def test_a_foreign_out_directory_is_not_deleted(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            os.makedirs(out)
            keep = os.path.join(out, "thesis.txt")
            with open(keep, "w", encoding="utf-8") as fh:
                fh.write("mine")
            with self.assertRaises(emit.UnsafePath) as cm:
                emit.write(out, {"manifest.json": "{}"})
            self.assertIn("not an output of this tool", str(cm.exception))
            self.assertTrue(os.path.exists(keep))
            os.remove(keep)
            emit.write(out, {"manifest.json": "{}", "a/b.json": "{}"})
            emit.write(out, {"manifest.json": "{}"})
            self.assertEqual(os.listdir(out), ["manifest.json"])

    def test_error_text_shows_control_characters(self):
        sink = io.StringIO()
        with contextlib.redirect_stderr(sink):
            cli._err("bad name " + chr(27) + "]0;x")
        self.assertNotIn(chr(27), sink.getvalue())


if __name__ == "__main__":
    unittest.main()
