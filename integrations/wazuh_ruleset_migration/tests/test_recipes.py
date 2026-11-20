"""Recipes (one card per ``RECIPE`` item) and monitors."""

import json
import unittest

from rmig import reasons as R

from helpers import MYAPP_DECODER, etc_tree, rules_xml

from rmig import decisions as D
from rmig.scan import scan
from rmig.translate import pipeline

RULES = rules_xml("local,", """
  <rule id="100100" level="5"><decoded_as>myapp</decoded_as><match>fail</match><description>base</description></rule>
  <rule id="100101" level="10" frequency="5" timeframe="600">
    <if_matched_sid>100100</if_matched_sid>
    <same_user />
    <same_field>myapp.user</same_field>
    <description>repeated</description>
  </rule>
  <rule id="100102" level="9" frequency="4">
    <if_matched_sid>100100</if_matched_sid>
    <different_srcip />
    <description>correlation</description>
  </rule>
  <rule id="100103" level="7"><decoded_as>myapp</decoded_as><time>6 pm - 8 am</time><description>after hours</description></rule>
  <rule id="100104" level="0"><if_sid>5716</if_sid><match>noise</match><description>silences 5716</description></rule>
  <rule id="100105" level="8" frequency="3" timeframe="60">
    <if_matched_sid>5716</if_matched_sid>
    <description>on stock base</description>
  </rule>
""")


class TestRecipes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tree = etc_tree(decoders={"myapp.xml": MYAPP_DECODER}, rules={"local_rules.xml": RULES})
        try:
            cls.res = pipeline.compute(scan(tree.root), D.empty(), source=tree.root)
        finally:
            tree.cleanup()
        cls.pkg = cls.res["package"]
        cls.states = {it["ref"]: it["state"] for it in cls.res["plan"]["items"]}

    def test_one_card_per_recipe(self):
        recipes = sorted(r for r, s in self.states.items() if s == "RECIPE")
        self.assertEqual(sorted("rule:" + n[len("rule-"):-3] for n in self.pkg.recipes), recipes)
        text = self.pkg.recipes["rule-100103.md"]
        self.assertIn("# Recipe: Wazuh 4.x rule 100103", text)
        self.assertIn("[`RM-R-TIME`](%s#rm-r-time)" % R.DOC_PAGE, text)
        self.assertIn("## What you need to do", text)
        self.assertIn("## Starting point", text)  # the rest of the rule has a translation

    def test_monitor_with_window_threshold_and_groups(self):
        mon = self.pkg.monitors["100101"]
        q = mon["inputs"][0]["search"]["query"]
        self.assertEqual(mon["monitor_type"], "bucket_level_monitor")
        self.assertIn({"term": {"tags": "wazuh4.rule.100100"}}, q["query"]["bool"]["filter"])
        rng = [f for f in q["query"]["bool"]["filter"] if "range" in f][0]["range"]["@timestamp"]
        self.assertEqual(rng["gte"], "{{period_end}}||-600s")
        fields = [list(s.values())[0]["terms"]["field"] for s in q["aggregations"]["by_group"]["composite"]["sources"]]
        self.assertEqual(fields, ["wazuh.agent.name", "user.name"])  # same_field undecided: in the card
        self.assertIn("same_field myapp.user has no WCS field", self.pkg.recipes["rule-100101.md"])
        self.assertEqual(mon["triggers"][0]["bucket_level_trigger"]["condition"]["script"]["source"], "params.count >= 5")

    def test_correlation_has_no_monitor(self):
        self.assertNotIn("100102", self.pkg.monitors)
        self.assertEqual(self.states["rule:100102"], "RECIPE")

    def test_stock_base_without_equivalence_has_no_monitor(self):
        self.assertNotIn("100105", self.pkg.monitors)
        self.assertIn("complete decisions.json (stock rule:5716)", self.pkg.recipes["rule-100105.md"])

    def test_silencer_of_stock_lists_the_targets(self):
        text = self.pkg.recipes["rule-100104.md"]
        self.assertIn("RM-R-SILENCER-STOCK", text)
        self.assertIn("`rule:5716`", text)

    def test_monitor_is_json_serializable(self):
        json.dumps(self.pkg.monitors, sort_keys=True)


if __name__ == "__main__":
    unittest.main()
