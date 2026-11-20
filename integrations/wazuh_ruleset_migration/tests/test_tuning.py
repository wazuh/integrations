"""Tuning of stock rules to redo."""

import unittest

from helpers import MYAPP_DECODER, etc_tree, rules_xml

from rmig import decisions as D
from rmig.scan import scan
from rmig.translate import pipeline

TUNING = rules_xml("local,", """
  <rule id="100010" level="0"><if_sid>5716</if_sid><srcip>10.0.0.5</srcip>
    <description>ignore the scanner</description></rule>
  <rule id="5710" level="2" overwrite="yes"><if_sid>5700</if_sid><match>illegal user|invalid user</match>
    <description>sshd: Attempt to login using a non-existent user</description></rule>""")

def run(rules, decisions=None):
    tree = etc_tree(rules={"r.xml": rules}, decoders={"d.xml": MYAPP_DECODER})
    try:
        return pipeline.compute(scan(tree.root), decisions or D.empty(), source=tree.root)
    finally:
        tree.cleanup()


class TestTuning(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = run(TUNING)
        cls.rows = cls.res["quality"]["tuning"]

    def test_rows(self):
        kinds = [(r["rule"], r["kind"]) for r in self.rows]
        self.assertIn(("100010", "silencer"), kinds)
        self.assertIn(("5710", "overwrite"), kinds)
        sil = [r for r in self.rows if r["kind"] == "silencer"][0]
        self.assertEqual(sil["stock"]["ref"], "rule:5716")
        self.assertIn("<srcip>10.0.0.5</srcip>", sil["condition_4x"])
        self.assertEqual(sil["decision"], "needs customer decision")
        self.assertEqual(sil["verified"], "not live-verified")
        self.assertIsNone(sil["stock_5x"])
        ow = [r for r in self.rows if r["kind"] == "overwrite"][0]
        self.assertIn("level 5 -> 2", ow["change"])
        self.assertEqual(ow["options"], ["copy-level", "disable"])

    def test_decision_entry_names_the_5x_side(self):
        dec = D.empty()
        dec["stock"]["rule:5716"] = {"integration": "system-auth", "selection": {"event.action": "authentication-failure"}}
        rows = run(TUNING, dec)["quality"]["tuning"]
        sil = [r for r in rows if r["kind"] == "silencer"][0]
        self.assertEqual(sil["stock_5x"]["integration"], "system-auth")

    def test_report_section_and_no_state_change(self):
        self.assertIn("## Tuning to redo", self.res["markdown"])
        self.assertIn("needs your decision", self.res["markdown"])


class TestWindowsTuning(unittest.TestCase):
    def test_pack_names_the_integration(self):
        rows = run(rules_xml("local,", """
  <rule id="100020" level="0"><if_sid>60106</if_sid>
    <field name="win.eventdata.targetUserName">^svc_backup$</field><description>quiet</description></rule>"""))[
            "quality"]["tuning"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["stock_5x"]["source"], "Windows pack")
        self.assertTrue(rows[0]["stock_5x"]["paths"])


if __name__ == "__main__":
    unittest.main()
