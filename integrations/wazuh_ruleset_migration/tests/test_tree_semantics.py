"""Tree semantics: levels, frequency rules, grouping rules, overwrite of custom rules."""

import unittest

from helpers import MYAPP_DECODER, codes, compute, etc_tree, one, rules_xml

RULES = rules_xml("local,", """
  <!-- grandmother level 3, mother, silencer level 0, sister level 5 (+ her child) -->
  <rule id="100100" level="3">
    <decoded_as>myapp</decoded_as>
    <match>a</match>
    <description>grandmother</description>
  </rule>
  <rule id="100101" level="4">
    <if_sid>100100</if_sid>
    <match>b</match>
    <description>mother</description>
  </rule>
  <rule id="100102" level="0">
    <if_sid>100101</if_sid>
    <match>c</match>
    <description>silencer</description>
  </rule>
  <rule id="100103" level="5">
    <if_sid>100101</if_sid>
    <match>d</match>
    <description>sister</description>
  </rule>
  <rule id="100104" level="6">
    <if_sid>100103</if_sid>
    <match>e</match>
    <description>child of the sister</description>
  </rule>

  <!-- frequency rule and a child of it -->
  <rule id="100200" level="10" frequency="8" timeframe="120">
    <if_matched_sid>100100</if_matched_sid>
    <same_source_ip />
    <description>frequency</description>
  </rule>
  <rule id="100201" level="12">
    <if_sid>100200</if_sid>
    <match>x</match>
    <description>child of the frequency rule</description>
  </rule>
  <rule id="100202" level="13">
    <if_sid>100201</if_sid>
    <match>y</match>
    <description>grandchild of the frequency rule</description>
  </rule>

  <!-- child of a grouping-only rule -->
  <rule id="100300" level="0">
    <decoded_as>myapp</decoded_as>
    <description>grouping</description>
  </rule>
  <rule id="100301" level="5">
    <if_sid>100300</if_sid>
    <match>z</match>
    <description>child of the grouping rule</description>
  </rule>

  <!-- silencer of a stock rule -->
  <rule id="100400" level="0">
    <if_sid>5716</if_sid>
    <match>noise</match>
    <description>silences 5716</description>
  </rule>

  <!-- overwrite of a custom rule -->
  <rule id="100500" level="5">
    <decoded_as>myapp</decoded_as>
    <match>old</match>
    <description>original</description>
  </rule>
  <rule id="100500" level="6" overwrite="yes">
    <decoded_as>myapp</decoded_as>
    <match>new</match>
    <description>overwritten</description>
  </rule>
""")


class TestTreeSemantics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = etc_tree(decoders={"myapp.xml": MYAPP_DECODER}, rules={"local_rules.xml": RULES})
        cls.res = compute(cls.tree.root)

    @classmethod
    def tearDownClass(cls):
        cls.tree.cleanup()

    def uid(self, rid):
        return one(self.res, "rule:%s" % rid)["uid"]

    def test_t9_silencer_excludes_grandmother_mother_and_sister(self):
        s = one(self.res, "rule:100102")
        self.assertIn("RM-R-SILENCER", codes(s))
        self.assertEqual(s["state"], "AUTO")
        targets = set(s["exclusion_targets"])
        expected = {self.uid(r) for r in ("100100", "100101", "100103", "100104")}
        self.assertEqual(targets, expected)
        self.assertEqual(s["exclusion_stock_targets"], [])
        for r in ("100100", "100101", "100103"):
            self.assertIn(s["uid"], one(self.res, "rule:%s" % r)["excluded_by"])

    def test_t11_child_of_a_recipe_parent_is_recipe(self):
        freq = one(self.res, "rule:100200")
        self.assertIn("RM-R-FREQUENCY", codes(freq))
        self.assertEqual(freq["state"], "RECIPE")
        child = one(self.res, "rule:100201")
        self.assertEqual(child["state"], "RECIPE")
        self.assertIn("RM-R-PARENT-RECIPE", codes(child))
        self.assertIn("RM-R-FREQUENCY", codes(child))
        grandchild = one(self.res, "rule:100202")
        self.assertEqual(grandchild["state"], "RECIPE")
        self.assertIn("RM-R-PARENT-RECIPE", codes(grandchild))

    def test_t11_child_of_a_grouping_rule_stays_auto(self):
        grouping = one(self.res, "rule:100300")
        self.assertEqual(grouping["state"], "NOT_APPLICABLE")
        self.assertIn("RM-R-GROUPING-ONLY", codes(grouping))
        child = one(self.res, "rule:100301")
        self.assertEqual(child["state"], "AUTO")
        self.assertNotIn("RM-R-PARENT-RECIPE", codes(child))
        self.assertEqual(child["chains"], [{"stock_anchor": None, "rules": [grouping["uid"], child["uid"]]}])

    def test_silencer_of_a_stock_rule_is_recipe(self):
        s = one(self.res, "rule:100400")
        self.assertIn("RM-R-SILENCER-STOCK", codes(s))
        self.assertEqual(s["state"], "RECIPE")
        self.assertIn("rule:5716", s["exclusion_stock_targets"])

    def test_no_auto_child_under_a_recipe_parent(self):
        items = {it["uid"]: it for it in self.res["plan"]["items"]}
        for it in items.values():
            if it["kind"] != "rule" or not it.get("chains"):
                continue
            for chain in it["chains"]:
                for parent in chain["rules"][:-1]:
                    p = items[parent]
                    recipe_propagating = [c for c in p["codes"] if c["code"] in (
                        "RM-R-FREQUENCY", "RM-R-CORRELATION", "RM-R-PARENT-RECIPE", "RM-R-NO-SOURCE")]
                    if p["state"] == "RECIPE" and recipe_propagating:
                        self.assertNotEqual(it["state"], "AUTO", it["uid"])

    def test_shadowing_marks_children_approximate(self):
        mother = one(self.res, "rule:100101")
        self.assertIn("RM-R-SHADOWING", codes(mother))
        self.assertEqual(mother["fidelity"], "approximate")

    def test_s6_overwrite_of_a_custom_rule(self):
        items = sorted([it for it in self.res["plan"]["items"] if it["ref"] == "rule:100500"], key=lambda it: it["line"])
        original, over = items
        self.assertEqual(codes(over), {"RM-R-OVERWRITE-MERGED"})
        self.assertEqual(over["state"], "NOT_APPLICABLE")
        self.assertIn("content overwritten by %s" % over["uid"], original["notes"])
        self.assertNotEqual(original["state"], "NOT_APPLICABLE")


class TestIfGroup(unittest.TestCase):
    def test_if_group_links_to_loaded_rules_and_counts_the_group(self):
        rules = rules_xml("local,", """
  <rule id="100600" level="5">
    <if_group>authentication_failed</if_group>
    <match>root</match>
    <description>any failed login for root</description>
  </rule>""")
        tree = etc_tree(rules={"local_rules.xml": rules})
        try:
            res = compute(tree.root)
        finally:
            tree.cleanup()
        item = one(res, "rule:100600")
        self.assertIn("RM-S-NO-EQUIVALENT", codes(item))
        self.assertEqual(item["source"]["stock_refs"], ["group:authentication_failed"])
        refs = {r["ref"]: r["count"] for r in res["plan"]["stock_references"]}
        self.assertEqual(refs.get("group:authentication_failed"), 1)


if __name__ == "__main__":
    unittest.main()
