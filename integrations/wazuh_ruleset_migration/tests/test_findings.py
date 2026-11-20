"""Findings per event, 4.x against 5.x."""

import unittest

from helpers import MYAPP_DECODER, etc_tree, rules_xml

from rmig import decisions as D
from rmig.scan import scan
from rmig.translate import pipeline


CHAIN = rules_xml("myapp,", """
  <rule id="100100" level="0"><decoded_as>myapp</decoded_as><description>myapp group</description></rule>
  <rule id="100101" level="5"><if_sid>100100</if_sid><match>login</match><description>myapp: login</description></rule>
  <rule id="100102" level="8"><if_sid>100101</if_sid><match>failed</match><description>myapp: login failed</description></rule>
  <rule id="100103" level="8"><if_sid>100101</if_sid><match>denied</match><description>myapp: login failed</description></rule>
  <rule id="100104" level="3"><if_sid>100100</if_sid><match>logout</match><description>myapp: logout</description></rule>""")


def run(rules, decisions=None):
    tree = etc_tree(rules={"r.xml": rules}, decoders={"d.xml": MYAPP_DECODER})
    try:
        return pipeline.compute(scan(tree.root), decisions or D.empty(), source=tree.root)
    finally:
        tree.cleanup()


class TestFindings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = run(CHAIN)
        cls.f = cls.res["quality"]["findings"]
        cls.rows = {r["rule"]: r for r in cls.f["rows"]}

    def test_child_fires_with_its_ancestor(self):
        self.assertEqual(self.rows["100102"]["always"], 2)
        self.assertEqual(self.rows["100102"]["ancestors"], ["100101"])
        self.assertIn("100103", self.rows["100102"]["maybe"])
        self.assertIn("100104", self.rows["100101"]["maybe"])

    def test_alternative_parents_count_per_chain(self):
        f = run(rules_xml("myapp,", """
  <rule id="100100" level="0"><decoded_as>myapp</decoded_as><description>myapp group</description></rule>
  <rule id="100101" level="5"><if_sid>100100</if_sid><match>alpha</match><description>myapp: alpha</description></rule>
  <rule id="100102" level="5"><if_sid>100100</if_sid><match>beta</match><description>myapp: beta</description></rule>
  <rule id="100103" level="6"><if_sid>100102</if_sid><match>gamma</match><description>myapp: beta gamma</description></rule>
  <rule id="100104" level="9"><if_sid>100101,100103</if_sid><match>delta</match><description>myapp: delta</description></rule>
"""))["quality"]["findings"]
        row = {r["rule"]: r for r in f["rows"]}["100104"]
        self.assertEqual((row["always"], row["up_to"], row["ancestors"]), (2, 3, []))
        self.assertIn("100101", row["maybe"])
        self.assertIn("100103", row["maybe"])

    def test_grouping_parent_adds_nothing(self):
        self.assertNotIn("100100", self.rows)
        for r in self.rows.values():
            self.assertNotIn("100100", r["ancestors"])

    def test_merge_candidates_reported_not_merged(self):
        self.assertEqual(self.f["merge_candidates"], [
            {"rules": ["100102", "100103"], "parent": "100101", "title": "myapp: login failed", "level": "medium"}])
        integ = self.res["package"].integrations["wazuh4-myapp"]
        self.assertIn("100102", integ["rules"])
        self.assertIn("100103", integ["rules"])
        self.assertEqual(self.f["histogram"], {"1": 2, "2": 2})

    def test_section(self):
        self.assertIn("## Findings per event", self.res["markdown"])


if __name__ == "__main__":
    unittest.main()
