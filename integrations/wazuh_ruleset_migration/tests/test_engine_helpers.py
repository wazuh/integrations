"""Engine helper dialects (``--engine-helpers``, wazuh/wazuh#41150): one
internal dialect (5.0 names), the rc1 rewrite as the last step, and the
validator that keeps out anything the target engine does not register
(``RM-D-HELPER-UNAVAILABLE``)."""

import json
import os
import re
import shutil
import unittest
from unittest import mock

from helpers import HERE

from rmig import decisions as D
from rmig import reasons as R
from rmig.scan import scan
from rmig.translate import helpers as H
from rmig.translate import pipeline
from test_rules_golden import GOLDEN, _tree, run_case

NEW_NAMES = re.compile(r"\b(in_cidr|in_kvdb|not_in_kvdb|kvdb_lookup|parse_kv)\(")
OLD_NAMES = re.compile(r"\b(ip_cidr_match|kvdb_match|kvdb_not_match|kvdb_get|parse_key_value)\(")
T12_IN = os.path.join(GOLDEN, "t12-lists", "in")


class TestRewrite(unittest.TestCase):
    def rc1(self, res):
        return H.to_dialect(res, H.RC1)

    def test_cidr_expression_one_and_several_networks(self):
        out = self.rc1({"check": "in_kvdb($source.ip, 'kv') OR in_cidr($source.ip, '10.0.0.0/8', '172.16.0.0/16')"})
        self.assertEqual(out["check"], "kvdb_match($source.ip, 'kv') OR (ip_cidr_match($source.ip, '10.0.0.0', '8') "
                                       "OR ip_cidr_match($source.ip, '172.16.0.0', '16'))")
        out = self.rc1({"check": "not_in_kvdb($source.ip, 'kv') AND NOT in_cidr($source.ip, '10.0.0.0/8')"})
        self.assertEqual(out["check"], "kvdb_not_match($source.ip, 'kv') AND NOT ip_cidr_match($source.ip, '10.0.0.0', '8')")

    def test_value_form_and_kvdb_lookup(self):
        out = self.rc1({"normalize": [{"check": [{"source.ip": "in_cidr('192.0.2.0/24')"}],
                                       "map": [{"x": "kvdb_lookup('kv', $source.ip)"}, {"y": "$source.ip"}]}]})
        self.assertEqual(out["normalize"][0]["check"], [{"source.ip": "ip_cidr_match('192.0.2.0', '24')"}])
        self.assertEqual(out["normalize"][0]["map"], [{"x": "kvdb_get('kv', $source.ip)"}, {"y": "$source.ip"}])

    def test_no_rc1_form_is_left_and_flagged(self):
        # field: value form with two networks: rc1 takes one network per call
        res = {"check": [{"source.ip": "in_cidr('10.0.0.0/8', '172.16.0.0/16')"}]}
        out = self.rc1(res)
        self.assertEqual(out, res)
        self.assertEqual(H.unavailable(out, H.RC1), ["in_cidr"])

    def test_quotes_and_references_are_not_calls(self):
        res = {"check": "regex_match($message, 'in_cidr(x) kvdb_lookup(') AND $a.in_kvdb == b"}
        self.assertEqual(H.names_in(res), {"regex_match"})
        self.assertEqual(self.rc1(res), res)

    def test_current_is_identity_and_round_trip(self):
        res = {"check": "in_kvdb($f, 'kv') AND NOT in_cidr($f, '10.0.0.0/8')",
               "normalize": [{"map": [{"x": "parse_kv($a, '=', ' ', '\"', '\\\\')"}]}]}
        self.assertEqual(H.to_dialect(res, H.CURRENT), res)
        self.assertEqual(H.to_current(self.rc1(res)), res)

    def test_dialect_sets(self):
        cur, rc1 = H.known(H.CURRENT), H.known(H.RC1)
        for name in ("in_cidr", "in_kvdb", "not_in_kvdb", "kvdb_lookup", "parse_kv", "regex_extract_all"):
            self.assertIn(name, cur)
            self.assertNotIn(name, rc1)
        for name in ("ip_cidr_match", "kvdb_match", "kvdb_not_match", "kvdb_get", "parse_key_value", "int_calculate"):
            self.assertIn(name, rc1)
        with self.assertRaises(H.HelperError):
            H.known("4.14")

    def test_reason_code(self):
        self.assertEqual(R.CATALOG["RM-D-HELPER-UNAVAILABLE"].state, R.RECIPE)


class T12ListsRc1(unittest.TestCase):
    """The lists golden built for an rc1 engine: same states, rc1 names only."""

    @classmethod
    def setUpClass(cls):
        cls.work, cls.states, cls.rc, cls.log = run_case("t12-lists", ["--engine-helpers", H.RC1])
        cls.out = os.path.join(cls.work, "out")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work, ignore_errors=True)

    def json(self, rel):
        with open(os.path.join(self.out, rel), encoding="utf-8") as fh:
            return json.load(fh)

    def test_states_are_those_of_the_5_0_build(self):
        with open(os.path.join(GOLDEN, "t12-lists", "expected", "states.json"), encoding="utf-8") as fh:
            self.assertEqual(self.states, json.load(fh))

    def test_only_rc1_names(self):
        text = "".join(v.decode("utf-8") for v in _tree(self.out).values())
        self.assertIsNone(NEW_NAMES.search(text))
        res = self.json("integrations/wazuh4-myapp/decoders/02-wazuh4-myapp-auth.json")["resource"]
        checks = [b.get("check") for b in res["normalize"]]
        self.assertIn("kvdb_match($source.ip, 'wazuh4-bad-ips') OR (ip_cidr_match($source.ip, '10.0.0.0', '8') OR "
                      "ip_cidr_match($source.ip, '172.16.0.0', '16'))", checks)
        self.assertIn({"map": [{"_wazuh4_lv_100601_1": "kvdb_get('wazuh4-bad-ips', $source.ip)"}]}, res["normalize"])
        base = json.dumps(self.json("integrations/wazuh4-base/decoders/02-wazuh4-predecoder.json"))
        self.assertIn("regex_extract($event.original", base)
        self.assertIn("not_exists()", base)

    def test_manifest_and_report_record_the_dialect(self):
        self.assertEqual(self.json("manifest.json")["engine_helpers"], H.RC1)
        with open(os.path.join(self.work, "report.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["build"]["engine_helpers"], H.RC1)
        with open(os.path.join(self.work, "report.md"), encoding="utf-8") as fh:
            self.assertIn("Engine helper names: `5.0-rc1`", fh.read())

    def test_same_input_same_dialect_same_bytes(self):
        work2, _s, _rc, _log = run_case("t12-lists", ["--engine-helpers", H.RC1])
        try:
            self.assertEqual(_tree(os.path.join(work2, "out")), _tree(self.out))
        finally:
            shutil.rmtree(work2, ignore_errors=True)


def _compute_t12(missing):
    """The lists case translated with ``missing`` taken out of the 5.0 helper set."""
    real = H.known

    def known(dialect):
        return frozenset(real(dialect) - set(missing))

    with mock.patch.object(H, "known", known):
        return pipeline.compute(scan(T12_IN), D.empty(), source=T12_IN)


class TestHelperUnavailable(unittest.TestCase):
    def items(self, res):
        return {it["ref"]: it for it in res["plan"]["items"]}

    def emitted_text(self, res, key="wazuh4-myapp"):
        integ = res["package"].integrations.get(key) or {"decoders": []}
        return json.dumps([d["resource"] for d in integ["decoders"]])

    def test_label_block_helper_missing_makes_the_rule_recipe(self):
        res = _compute_t12({"in_kvdb"})
        it = self.items(res)["rule:100600"]
        self.assertEqual(it["state"], "RECIPE")
        codes = {c["code"]: c["details"] for c in it["codes"]}
        self.assertIn("RM-D-HELPER-UNAVAILABLE", codes)
        self.assertIn("in_kvdb", " ".join(codes["RM-D-HELPER-UNAVAILABLE"]))
        self.assertEqual(self.items(res)["rule:100601"]["state"], "AUTO")  # kvdb_lookup is still there
        self.assertNotIn("in_kvdb(", self.emitted_text(res))
        self.assertNotIn("100600", res["package"].integrations["wazuh4-myapp"]["rules"])
        self.assertIn("rule-100600.md", res["package"].recipes)

    def test_decoder_helper_missing_makes_the_decoder_and_its_rules_recipe(self):
        res = _compute_t12({"regex_extract"})
        items = self.items(res)
        self.assertEqual(items["decoder:myapp-auth"]["state"], "RECIPE")
        self.assertIn("RM-D-HELPER-UNAVAILABLE", {c["code"] for c in items["decoder:myapp-auth"]["codes"]})
        self.assertEqual(items["decoder:myapp"]["state"], "AUTO")
        self.assertNotEqual(items["rule:100600"]["state"], "AUTO")
        self.assertNotIn("regex_extract(", self.emitted_text(res))
        names = [d["resource"]["name"] for d in res["package"].integrations["wazuh4-myapp"]["decoders"]]
        self.assertEqual(names, ["decoder/wazuh4-myapp/0"])

    def test_base_helper_missing_stops_the_build(self):
        res = _compute_t12({"not_exists"})
        self.assertTrue(res["package"].helper_problems)
        self.assertIn("not_exists", res["package"].helper_problems[0])


if __name__ == "__main__":
    unittest.main()
