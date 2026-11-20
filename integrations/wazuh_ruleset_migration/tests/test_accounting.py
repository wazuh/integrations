"""Accounting after the translation: every item has one state
and catalog codes, the state follows from the codes, no provisional code is
left, and every emitted resource belongs to an ``AUTO`` item."""

import os
import unittest

from helpers import CORPUS, DATA, MYAPP_DECODER, etc_tree, need_dir, rules_xml
from test_classify import MIXED_RULES

from rmig import decisions as D
from rmig import reasons as R
from rmig.scan import scan
from rmig.translate import pipeline

SAMPLE = os.path.join(DATA, "sample-etc")


def check(test, inv, res):
    items = res["plan"]["items"]
    n_inv = len(inv["rules"]) + len(inv["decoders"]) + len(inv["lists"])
    test.assertEqual(len(items), n_inv)
    by_uid = {it["uid"]: it for it in items}
    for it in items:
        codes = [c["code"] for c in it["codes"]]
        test.assertTrue(codes, it["uid"])
        test.assertNotIn("RM-X-PROVISIONAL-AUTO", codes, it["uid"])
        for c in codes:
            test.assertIn(c, R.CATALOG)
        test.assertEqual(it["state"], R.state_of(codes), it["uid"])
        if it["state"] == R.AUTO:
            test.assertIn(it["fidelity"], (R.EXACT, R.APPROXIMATE))
            test.assertEqual(it["fidelity"], R.fidelity_of(codes))
    test.assertEqual(sum(res["report"]["summary"]["by_state"].values()), n_inv)
    pkg = res["package"]
    for integ in pkg.integrations.values():
        for doc in integ["rules"].values():
            src = doc["source"]
            uid = "rule:%s:%d" % (src["file"], src["line"])
            test.assertEqual(by_uid[uid]["state"], R.AUTO, uid)
            test.assertEqual(sorted(doc["reasons"]), sorted(c["code"] for c in by_uid[uid]["codes"]))
        for doc in integ["decoders"]:
            src = doc["source"]
            if src["kind"] == "decoder":
                test.assertEqual(by_uid["decoder:%s:%d" % (src["file"], src["line"])]["state"], R.AUTO)
    # every RECIPE item has its card
    recipes = [it for it in items if it["state"] == R.RECIPE]
    test.assertEqual(len(recipes), len(pkg.recipes))
    # one mapping row per rule of the inventory
    test.assertEqual(len(pkg.mapping), len(inv["rules"]))


class TestAccountingSynthetic(unittest.TestCase):
    def test_mixed_rules(self):
        tree = etc_tree(decoders={"myapp.xml": MYAPP_DECODER}, rules={"local_rules.xml": MIXED_RULES},
                        lists={"audit-keys": "custom:list\n"})
        try:
            inv = scan(tree.root)
            res = pipeline.compute(inv, D.empty(), source=tree.root)
        finally:
            tree.cleanup()
        check(self, inv, res)
        items = {it["ref"]: it for it in res["plan"]["items"]}
        self.assertEqual({c["code"] for c in items["rule:100001"]["codes"]}, {"RM-X-TRANSLATED"})
        self.assertEqual(items["rule:100001"]["fidelity"], "exact")

    def test_sample(self):
        inv = scan(SAMPLE)
        res = pipeline.compute(inv, D.empty(), source=SAMPLE)
        check(self, inv, res)

    def test_unsupported_pattern_is_recipe_and_children_follow(self):
        tree = etc_tree(decoders={"myapp.xml": MYAPP_DECODER}, rules={"local_rules.xml": rules_xml("local,", """
  <rule id="100001" level="5"><decoded_as>myapp</decoded_as><match type="pcre2">(?=x)y</match><description>lookahead</description></rule>
  <rule id="100002" level="6"><if_sid>100001</if_sid><match>z</match><description>child</description></rule>""")})
        try:
            inv = scan(tree.root)
            res = pipeline.compute(inv, D.empty(), source=tree.root)
        finally:
            tree.cleanup()
        check(self, inv, res)
        items = {it["ref"]: it for it in res["plan"]["items"]}
        self.assertEqual(items["rule:100001"]["state"], "RECIPE")
        self.assertIn("RM-R-RE-UNSUPPORTED", {c["code"] for c in items["rule:100001"]["codes"]})
        self.assertEqual(items["rule:100002"]["state"], "RECIPE")
        self.assertIn("RM-R-PARENT-RECIPE", {c["code"] for c in items["rule:100002"]["codes"]})


class TestAccountingCorpus(unittest.TestCase):
    def test_public_corpus(self):
        need_dir(CORPUS, "public corpus")
        inv = scan(CORPUS)
        res = pipeline.compute(inv, D.empty(), source=CORPUS)
        check(self, inv, res)


if __name__ == "__main__":
    unittest.main()
