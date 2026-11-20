"""Engine limits: the report of plan and build, the stop of apply, and the
split of detectors at 50 rules."""

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest

import helpers as H

import fake_indexer as F
from rmig import cli
from rmig import limits as L
from test_apply import ApiCase


def quiet(*argv):
    sink = io.StringIO()
    with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        rc = cli.main(list(argv))
    return rc, sink.getvalue()


def many_rules(n):
    body = "\n".join('<rule id="%d" level="5">\n  <decoded_as>myapp</decoded_as>\n  <match>word%d</match>\n'
                     '  <description>rule %d</description>\n</rule>' % (100000 + i, i, i) for i in range(n))
    return H.rules_xml("myapp,", body)


class TestCheck(unittest.TestCase):
    def test_defaults_not_exceeded(self):
        block = L.check([("a", 10, 2, 1, [{"name": "decoder/a/0"}])], [("a-1", "a", 10)])
        self.assertEqual(block["exceeded"], [])
        self.assertEqual(block["values"]["max_rules"], 200)
        self.assertEqual(block["totals"], {"integrations": 1, "rules": 10, "decoders": 2, "kvdbs": 1, "detectors": 1})

    def test_draft_limits_count_the_whole_package(self):
        block = L.check([("a", 150, 0, 0, []), ("b", 60, 0, 0, [])], [])
        ex = block["exceeded"]
        self.assertEqual([(e["limit"], e["scope"], e["value"], e["max"]) for e in ex], [("max_rules", "total", 210, 200)])
        self.assertIn("plugins.content_manager.max_rules", ex[0]["action"])
        self.assertIn("migrate in parts", ex[0]["action"])
        self.assertEqual([r["exceeded"] for r in block["integrations"]], [[], []])

    def test_one_integration_over_the_limit_is_listed_once(self):
        block = L.check([("a", 250, 0, 0, [])], [])
        self.assertEqual([e["scope"] for e in block["exceeded"]], ["total"])
        self.assertEqual([e["limit"] for e in block["integrations"][0]["exceeded"]], ["max_rules"])

    def test_decoder_body_and_detectors(self):
        big = {"name": "decoder/big/0", "parse|message": ["x" * 60000]}
        dets = [("a-%d" % k, "a", 50) for k in range(1, 12)]
        block = L.check([("a", 550, 1, 0, [big])], dets, {"max_rules": 1000})
        limits = sorted((e["limit"], e["scope"]) for e in block["exceeded"])
        self.assertEqual(limits, [("decoder_body_bytes", "a"), ("max_detectors", "total")])
        row = block["integrations"][0]
        self.assertEqual(row["largest_decoder"], "decoder/big/0")
        self.assertEqual(row["largest_decoder_bytes"], L.decoder_body_bytes(big))
        self.assertGreater(row["largest_decoder_bytes"], 60000)
        self.assertEqual(block["overridden"], ["max_rules"])

    def test_body_size_is_what_the_client_sends(self):
        res = {"name": "decoder/x/0", "check": "ñ"}
        body = json.dumps({"integration": "0" * 36, "resource": res}, sort_keys=True, ensure_ascii=False)
        self.assertEqual(L.decoder_body_bytes(res), len(body.encode("utf-8")))

    def test_parse(self):
        self.assertEqual(L.parse(["max_rules=500", "max_detectors=20"]), {"max_rules": 500, "max_detectors": 20})
        for bad in ("max_rule=5", "max_rules", "max_rules=x", "max_rules=0"):
            with self.assertRaises(L.LimitError):
                L.parse([bad])


class TestBuildReport(unittest.TestCase):
    def setUp(self):
        self.tree = H.etc_tree(rules={"local_rules.xml": many_rules(60)},
                               decoders={"local_decoder.xml": H.MYAPP_DECODER})
        self.work = tempfile.mkdtemp(prefix="rmig-limits-")

    def tearDown(self):
        self.tree.cleanup()
        shutil.rmtree(self.work, ignore_errors=True)

    def report(self):
        with open(os.path.join(self.work, "report.json"), encoding="utf-8") as fh:
            return json.load(fh)

    def test_detectors_are_split_at_50_rules(self):
        rc, log = quiet("migrate", "--source", self.tree.root, "--workdir", self.work)
        self.assertEqual(rc, 0, log)
        dets = sorted(os.listdir(os.path.join(self.work, "out", "detectors")))
        self.assertEqual(len(dets), 2, dets)
        sizes = []
        for name in dets:
            with open(os.path.join(self.work, "out", "detectors", name), encoding="utf-8") as fh:
                sizes.append(len(json.load(fh)["rules"]))
        self.assertEqual(sorted(sizes), [10, 50])
        block = self.report()["build"]["limits"]
        self.assertEqual(block["exceeded"], [])
        self.assertNotIn("warning: engine limit", log)
        with open(os.path.join(self.work, "report.md"), encoding="utf-8") as fh:
            md = fh.read()
        self.assertIn("## Engine limits", md)
        self.assertIn("No limit is exceeded by this build alone.", md)

    def test_warning_on_stdout_and_report(self):
        rc, log = quiet("migrate", "--source", self.tree.root, "--workdir", self.work,
                        "--engine-limit", "max_rules=40", "--engine-limit", "max_detectors=1")
        self.assertEqual(rc, 0, log)
        self.assertIn("build: warning: engine limit: 60 rules in the draft space in total, limit 40", log)
        self.assertIn("2 user-created detectors in the cluster in total, limit 1", log)
        block = self.report()["build"]["limits"]
        self.assertEqual(sorted(e["limit"] for e in block["exceeded"]), ["max_detectors", "max_rules"])
        self.assertEqual(block["values"]["max_rules"], 40)
        # plan reports the same block
        rc, log = quiet("plan", "--workdir", self.work, "--engine-limit", "max_rules=40")
        self.assertIn("plan: warning: engine limit: 60 rules", log)

    def test_bad_engine_limit_is_a_usage_error(self):
        rc, log = quiet("migrate", "--source", self.tree.root, "--workdir", self.work, "--engine-limit", "rules=1")
        self.assertEqual(rc, 2, log)


class TestNoFullLog(unittest.TestCase):
    def test_note_and_report_line(self):
        rules = H.rules_xml("myapp,", "\n".join([
            '<rule id="100001" level="5">', "  <decoded_as>myapp</decoded_as>", "  <match>quiet</match>",
            "  <options>no_full_log</options>", "  <description>quiet rule</description>", "</rule>",
            '<rule id="100002" level="5">', "  <decoded_as>myapp</decoded_as>", "  <match>loud</match>",
            "  <description>loud rule</description>", "</rule>"]))
        tree = H.etc_tree(rules={"local_rules.xml": rules}, decoders={"local_decoder.xml": H.MYAPP_DECODER})
        work = tempfile.mkdtemp(prefix="rmig-nfl-")
        try:
            rc, log = quiet("migrate", "--source", tree.root, "--workdir", work)
            self.assertEqual(rc, 0, log)
            with open(os.path.join(work, "report.json"), encoding="utf-8") as fh:
                rep = json.load(fh)
            self.assertEqual(rep["build"]["no_full_log"], ["rule:100001"])
            notes = {it["ref"]: it["notes"] for it in rep["items"]}
            self.assertTrue(any("verify --samples DIR" in n for n in notes["rule:100001"]))
            self.assertFalse(any("no_full_log" in n for n in notes["rule:100002"]))
            with open(os.path.join(work, "report.md"), encoding="utf-8") as fh:
                md = fh.read()
            self.assertIn("Rules with `no_full_log`", md)
            self.assertIn("`rule:100001`", md)
        finally:
            tree.cleanup()
            shutil.rmtree(work, ignore_errors=True)


class TestApplyLimits(ApiCase):
    def test_stops_before_any_write(self):
        n = len(self.fake.calls)
        out = self.apply("--engine-limit", "max_rules=2", expect=2)
        self.assertIn("plugins.content_manager.max_rules: 0 in draft now + 3 to create = 3, limit 2", out)
        self.assertEqual(F.writes(self.fake, n), [])

    def test_counts_what_is_already_in_draft(self):
        self.fake.seed("rule", {"title": "someone else's rule", "metadata": {"author": "someone"}})
        out = self.apply("--engine-limit", "max_rules=3", expect=2)
        self.assertIn("1 in draft now + 3 to create = 4, limit 3", out)

    def test_own_content_already_in_draft_is_not_counted_twice(self):
        self.apply()
        n = len(self.fake.calls)
        self.apply("--engine-limit", "max_rules=3")
        self.assertEqual(F.writes(self.fake, n), [])

    def test_decoder_body(self):
        out = self.apply("--engine-limit", "decoder_body_bytes=100", expect=2)
        self.assertIn("no cluster setting is known for this limit", out)
        self.assertIn("decoder decoder/wazuh4-root/0", out)

    def test_stop_line_has_the_code(self):
        out = self.apply("--engine-limit", "max_rules=2", expect=2)
        self.assertIn("apply: stopped (RM-P-ENGINE-LIMIT): ", out)

    def test_dry_run_stop_writes_the_report(self):
        out = self.apply("--dry-run", "--engine-limit", "max_rules=2", expect=2)
        self.assertIn("apply: stopped (RM-P-ENGINE-LIMIT): ", out)
        self.assertEqual(F.writes(self.fake), [])
        self.assertFalse(os.path.exists(os.path.join(self.work, "work", "state.json")))
        with open(os.path.join(self.work, "report.json"), encoding="utf-8") as fh:
            sec = json.load(fh)["apply"]
        self.assertTrue(sec["dry_run"])
        self.assertEqual(sec["stops"][0]["code"], "RM-P-ENGINE-LIMIT")
        with open(os.path.join(self.work, "report.md"), encoding="utf-8") as fh:
            md = fh.read()
        self.assertIn("dry run: nothing was written", md)
        self.assertIn("RM-P-ENGINE-LIMIT", md)

    def test_bad_value(self):
        code, out = self.run_cmd("apply", "--engine-limit", "max_rules=abc")
        self.assertEqual(code, 2, out)


if __name__ == "__main__":
    unittest.main()
