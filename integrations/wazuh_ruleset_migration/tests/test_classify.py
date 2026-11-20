"""every item has one state and catalog codes; the counts add up."""

import re
import unittest

from helpers import CORPUS, MYAPP_DECODER, compute, etc_tree, need_dir, rules_xml

from rmig import reasons as R
from rmig.scan import scan

DESIGN_CATALOG = """RM-R-FREQUENCY RM-R-CORRELATION RM-R-FTS RM-R-CHECK-DIFF RM-R-TIME RM-R-COMPILED
RM-R-IGNORE RM-R-OPTIONS RM-R-GROUPING-ONLY RM-R-SILENCER-STOCK RM-R-OVERWRITE-STOCK RM-R-SHADOWING
RM-R-NO-SOURCE RM-R-IF-LEVEL RM-R-RE-DIALECT RM-R-LONG-MESSAGE RM-R-PARENT-RECIPE RM-R-DUPLICATE-ID
RM-R-FILE-SHADOWED RM-R-PARENT-NOT-LOADED RM-R-TITLE-SUFFIXED RM-R-LABEL-UNAVAILABLE RM-F-UNMAPPED
RM-F-DROPPED RM-F-TYPE RM-S-NO-EQUIVALENT RM-S-INTEGRATION-DISABLED RM-D-PLUGIN RM-D-FTS RM-D-ACCUMULATE
RM-D-JSON-CATCHALL RM-D-REGEX-DIALECT RM-D-STOCK-PARENT RM-D-DUAL-DOCUMENT RM-L-STOCK
RM-L-PREFIX-KEYS RM-L-KEY-VALUE-INVERTED RM-L-MISSING RM-P-ROOT-OWNED RM-P-NAME-CONFLICT
RM-P-FOREIGN-POLICY-CHANGE RM-P-POLICY-LOCKED RM-P-UNCLASSIFIED-INDEXED RM-P-SECOND-POLICY
RM-X-UNKNOWN-ELEMENT""".split()

MIXED_RULES = rules_xml("local,", """
  <rule id="100001" level="3"><decoded_as>myapp</decoded_as><match>a</match><description>auto</description></rule>
  <rule id="100002" level="3"><decoded_as>myapp</decoded_as><field name="myapp.user">x</field><description>decision</description></rule>
  <rule id="100003" level="3"><decoded_as>myapp</decoded_as><time>9 am - 5 pm</time><description>time</description></rule>
  <rule id="100004" level="3"><decoded_as>myapp</decoded_as><weekday>monday</weekday><description>weekday</description></rule>
  <rule id="100005" level="3"><decoded_as>myapp</decoded_as><check_diff /><description>diff</description></rule>
  <rule id="100006" level="3"><decoded_as>myapp</decoded_as><compiled_rule>is_simple_http_request</compiled_rule><description>compiled</description></rule>
  <rule id="100007" level="3"><if_level>10</if_level><description>if_level</description></rule>
  <rule id="100008" level="3"><decoded_as>myapp</decoded_as><if_fts /><description>fts</description></rule>
  <rule id="100009" level="3"><match>anything</match><description>no source</description></rule>
  <rule id="100010" level="3" ignore="60"><decoded_as>myapp</decoded_as><options>no_full_log</options><description>ignore</description></rule>
  <rule id="100011" level="3"><decoded_as>myapp</decoded_as><list field="myapp.user" lookup="address_match_key_value" check_value="x">etc/lists/audit-keys</list><description>inverted</description></rule>
  <rule id="100012" level="3"><decoded_as>sshd</decoded_as><list field="a" lookup="match_key">etc/lists/audit-keys</list><description>label unavailable</description></rule>
  <rule id="100013" level="3"><decoded_as>myapp</decoded_as><field name="myapp.other">x</field><description>no decoder extracts it</description></rule>
""")

EXPECTED = {
    "rule:100001": ("AUTO", None),
    "rule:100002": ("AUTO", "RM-F-DECODER-CHECK"),
    "rule:100013": ("DECISION", "RM-F-UNMAPPED"),
    "rule:100003": ("RECIPE", "RM-R-TIME"),
    "rule:100004": ("RECIPE", "RM-R-TIME"),
    "rule:100005": ("RECIPE", "RM-R-CHECK-DIFF"),
    "rule:100006": ("RECIPE", "RM-R-COMPILED"),
    "rule:100007": ("RECIPE", "RM-R-IF-LEVEL"),
    "rule:100008": ("RECIPE", "RM-R-FTS"),
    "rule:100009": ("RECIPE", "RM-R-NO-SOURCE"),
    "rule:100010": ("AUTO", "RM-R-IGNORE"),
    "rule:100011": ("RECIPE", "RM-L-KEY-VALUE-INVERTED"),
    "rule:100012": ("RECIPE", "RM-R-LABEL-UNAVAILABLE"),
}


def check_accounting(test, inv, res):
    items = res["plan"]["items"]
    n_inv = len(inv["rules"]) + len(inv["decoders"]) + len(inv["lists"])
    test.assertEqual(len(items), n_inv)
    test.assertEqual(len({it["uid"] for it in items}), n_inv)
    for it in items:
        test.assertIn(it["state"], R.STATES, it["uid"])
        test.assertTrue(it["codes"], it["uid"])
        for c in it["codes"]:
            test.assertIn(c["code"], R.CATALOG, it["uid"])
        test.assertEqual(it["state"], R.state_of([c["code"] for c in it["codes"]]))
        if it["state"] == R.AUTO:
            test.assertIn(it["fidelity"], (R.EXACT, R.APPROXIMATE))
        else:
            test.assertIsNone(it["fidelity"])
    by_state = res["report"]["summary"]["by_state"]
    test.assertEqual(sum(by_state.values()), n_inv)
    test.assertEqual(sum(res["plan"]["summary"].values()), n_inv)
    test.assertEqual({it["uid"] for it in res["report"]["items"]}, {it["uid"] for it in items})
    # every code in the report links to its documentation section
    md = res["markdown"]
    for code in res["report"]["summary"]["by_code"]:
        test.assertIn("(%s#%s)" % (R.DOC_PAGE, code.lower()), md)


class TestCatalog(unittest.TestCase):
    def test_design_codes_present_and_well_formed(self):
        for code in DESIGN_CATALOG:
            self.assertIn(code, R.CATALOG)
        for code, reason in R.CATALOG.items():
            self.assertRegex(code, r"^RM-[RDLFSPX]-[A-Z0-9]+(-[A-Z0-9]+)*$")
            self.assertEqual(reason.anchor, R.DOC_PAGE + "#" + code.lower())
            self.assertIn(reason.state, R.STATES)
            self.assertTrue(reason.text and reason.text.isascii())

    def test_propagation_column(self):
        # NOT_APPLICABLE only propagates with PARENT-NOT-LOADED and L-MISSING
        na_prop = {c for c, r in R.CATALOG.items() if r.state == R.NOT_APPLICABLE and r.propagates}
        self.assertEqual(na_prop, {"RM-R-PARENT-NOT-LOADED", "RM-L-MISSING"})
        for code in ("RM-R-GROUPING-ONLY", "RM-R-DUPLICATE-ID", "RM-R-SILENCER-STOCK"):
            self.assertFalse(R.CATALOG[code].propagates)
        self.assertTrue(R.CATALOG["RM-R-PARENT-RECIPE"].propagates)

    def test_state_order(self):
        self.assertEqual(R.state_of(["RM-X-PROVISIONAL-AUTO"]), R.AUTO)
        self.assertEqual(R.state_of(["RM-F-UNMAPPED", "RM-R-OPTIONS"]), R.DECISION)
        self.assertEqual(R.state_of(["RM-F-UNMAPPED", "RM-R-FREQUENCY"]), R.RECIPE)
        self.assertEqual(R.state_of(["RM-R-FREQUENCY", "RM-R-GROUPING-ONLY"]), R.NOT_APPLICABLE)


class TestClassifySynthetic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = etc_tree(decoders={"myapp.xml": MYAPP_DECODER}, rules={"local_rules.xml": MIXED_RULES},
                            lists={"audit-keys": "custom:list\n"})
        cls.inv = scan(cls.tree.root)
        from rmig import decisions, planner
        cls.res = planner.compute(cls.inv, decisions.empty())

    @classmethod
    def tearDownClass(cls):
        cls.tree.cleanup()

    def test_accounting(self):
        check_accounting(self, self.inv, self.res)

    def test_constructs(self):
        items = {it["ref"]: it for it in self.res["plan"]["items"]}
        for ref, (state, code) in EXPECTED.items():
            self.assertEqual(items[ref]["state"], state, ref)
            if code:
                self.assertIn(code, {c["code"] for c in items[ref]["codes"]}, ref)
        self.assertEqual({c["code"] for c in items["rule:100001"]["codes"]}, {"RM-X-PROVISIONAL-AUTO"})


class TestClassifyCorpus(unittest.TestCase):
    def test_public_corpus(self):
        need_dir(CORPUS, "public corpus")
        inv = scan(CORPUS)
        res = compute(CORPUS)
        check_accounting(self, inv, res)
        self.assertEqual(len(inv["rules"]), 2235)
        self.assertEqual(len(inv["decoders"]), 105)
        self.assertTrue(re.match(r"^# Ruleset migration report", res["markdown"]))


if __name__ == "__main__":
    unittest.main()
