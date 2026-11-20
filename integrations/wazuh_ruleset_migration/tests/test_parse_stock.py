"""The parser reads a whole stock 4.x ruleset (real one gated on RMIG_STOCK_DIR)."""

import json
import os
import tempfile
import time
import unittest

from helpers import STOCK_FULL, STOCK_INDEX, STOCK_MINI, need_dir, use_full_stock

from rmig import fsutil, stock
from rmig.parse.decoders import parse_decoders_text
from rmig.parse.lists import parse_list_bytes
from rmig.parse.rules import parse_rules_text
from rmig.scan import scan


def count_tree(root):
    res = {"rule_files": 0, "rules": 0, "decoder_files": 0, "decoders": 0, "lists": 0,
           "problems": [], "level0": 0, "roots": 0}
    rdir = os.path.join(root, "ruleset", "rules")
    for name in fsutil.listdir_sorted(rdir):
        if name.endswith(".xml"):
            rules, prob = parse_rules_text(fsutil.read_text(os.path.join(rdir, name)), name)
            res["rule_files"] += 1
            res["rules"] += len(rules)
            res["level0"] += sum(1 for r in rules if r["level"] == 0)
            if prob["errors"] or prob["unknown"] or any(r["invalid"] or r["unknown"] for r in rules):
                res["problems"].append(name)
    ddir = os.path.join(root, "ruleset", "decoders")
    for name in fsutil.listdir_sorted(ddir):
        if name.endswith(".xml"):
            decs, prob = parse_decoders_text(fsutil.read_text(os.path.join(ddir, name)), name)
            res["decoder_files"] += 1
            res["decoders"] += len(decs)
            res["roots"] += sum(1 for d in decs if d["parent"] is None)
            if prob["errors"] or prob["unknown"] or any(d["invalid"] or d["unknown"] for d in decs):
                res["problems"].append(name)
    ldir = os.path.join(root, "ruleset", "lists")
    for rel in fsutil.walk_files(ldir):
        parse_list_bytes(fsutil.read_bytes(os.path.join(ldir, rel)), rel, rel)
        res["lists"] += 1
    return res


class TestParseStockFull(unittest.TestCase):
    def setUp(self):
        need_dir(os.path.join(STOCK_FULL, "ruleset"), "stock ruleset 4.14.13")
        use_full_stock()

    def tearDown(self):
        stock.set_active(STOCK_INDEX)

    def test_counts(self):
        res = count_tree(STOCK_FULL)
        self.assertEqual(res["rule_files"], 168)
        self.assertEqual(res["rules"], 4518)
        self.assertEqual(res["level0"], 672)
        self.assertEqual(res["decoder_files"], 120)
        self.assertEqual(res["decoders"], 1578)
        self.assertEqual(res["roots"], 210)
        self.assertEqual(res["lists"], 7)
        self.assertEqual(res["problems"], [])

    def test_index_counts(self):
        built = stock.build_index(STOCK_FULL)
        self.assertEqual(built["counts"], {"rules": 4518, "rule_files": 168, "decoders": 1578,
                                           "decoder_files": 120, "lists": 7})
        self.assertEqual(stock.build_index(os.path.join(STOCK_FULL, "ruleset"))["rules"], built["rules"])

    def test_whole_stock_tree_under_60s(self):
        t0 = time.time()
        inv = scan(STOCK_FULL)
        from rmig import decisions, planner
        planner.compute(inv, decisions.empty())
        self.assertLess(time.time() - t0, 60)
        # an untouched stock tree has nothing custom
        self.assertEqual(inv["rules"], [])
        self.assertEqual(inv["decoders"], [])
        total = sum(v["elements"] for v in inv["stock_dir_summary"].values())
        self.assertEqual(total, 4518 + 1578)


class TestParseStockMini(unittest.TestCase):
    """The synthetic stock tree, so the suite runs without a 4.x checkout."""

    def test_counts(self):
        res = count_tree(STOCK_MINI)
        self.assertEqual((res["rule_files"], res["rules"]), (3, 30))
        self.assertEqual((res["decoder_files"], res["decoders"]), (4, 8))
        self.assertEqual(res["lists"], 2)
        self.assertEqual(res["problems"], [])

    def test_index_is_deterministic_and_has_provenance(self):
        a = stock.dump_index(stock.build_index(STOCK_MINI, "src"))
        b = stock.dump_index(stock.build_index(os.path.join(STOCK_MINI, "ruleset"), "src"))
        self.assertEqual(a, b)
        data = json.loads(a)
        self.assertEqual(data["source"], "src")
        self.assertEqual(json.loads(stock.dump_index(stock.build_index(STOCK_MINI)))["source"], stock.STOCK_LABEL)

    def test_cache_is_reused_and_refreshed(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "ruleset")
            import shutil
            shutil.copytree(os.path.join(STOCK_MINI, "ruleset"), src)
            work = os.path.join(tmp, "w")
            try:
                first = stock.use_stock_dir(src, work)
                self.assertTrue(os.path.exists(stock.cache_path(work)))
                self.assertEqual(stock.use_stock_dir(src, work).data["fingerprint"], first.data["fingerprint"])
                with open(os.path.join(src, "rules", "0010-rules_config.xml"), "a", encoding="utf-8") as fh:
                    fh.write("<!-- changed -->\n")
                self.assertNotEqual(stock.use_stock_dir(src, work).data["fingerprint"], first.data["fingerprint"])
            finally:
                stock.set_active(STOCK_INDEX)

    def test_missing_stock_dir_is_a_clear_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(stock.StockMissing) as cm:
                stock.use_stock_dir(tmp)
            self.assertIn("--stock-dir", str(cm.exception))
        self.assertIs(stock.active(), STOCK_INDEX)

    def test_cli_without_stock_ruleset_exits_2(self):
        import contextlib
        import io
        from unittest import mock
        from rmig import cli
        with tempfile.TemporaryDirectory() as tmp:
            err = io.StringIO()
            stock.set_active(None)
            try:
                with mock.patch.object(stock, "DEFAULT_STOCK_DIR", os.path.join(tmp, "absent")), \
                        contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                    rc = cli.main(["scan", "--source", STOCK_MINI, "--workdir", os.path.join(tmp, "w")])
            finally:
                stock.set_active(STOCK_INDEX)
            self.assertEqual(rc, 2)
            self.assertIn("--stock-dir", err.getvalue())
            self.assertFalse(os.path.exists(os.path.join(tmp, "w", "work", "inventory.json")))

    def test_build_script_runs(self):
        import subprocess
        import sys
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "idx.json")
            for _ in range(2):
                subprocess.run([sys.executable, os.path.join(here, "scripts", "build_stock_index.py"),
                                "--stock-dir", STOCK_MINI, "--source", "mini", "--out", out],
                               check=True, stdout=subprocess.DEVNULL)
                with open(out, "rb") as fh:
                    data = fh.read()
                if _ == 0:
                    first = data
            self.assertEqual(first, data)

    def test_element_location_kept(self):
        rules, _ = parse_rules_text(fsutil.read_text(os.path.join(STOCK_MINI, "ruleset/rules/0095-sshd_rules.xml")), "f.xml")
        r5716 = [r for r in rules if r["id"] == "5716"][0]
        self.assertEqual(r5716["line"], 29)
        self.assertEqual(r5716["parents"]["if_sid"], ["5700"])
        self.assertEqual(r5716["conditions"][0]["engine"], "osmatch")


if __name__ == "__main__":
    unittest.main()
