"""Lists: CDB -> KVDB, lookups as label blocks in the
decoder of the rule, prefix keys as ``in_cidr``."""

import unittest

from helpers import etc_tree, rules_xml

from rmig import decisions as D
from rmig.scan import scan
from rmig.translate import pipeline
from rmig.translate.engine import prefix_to_cidr
from test_rules_golden import GoldenCase


class T12Lists(GoldenCase):
    CASE = "t12-lists"

    def test_kvdb_with_every_entry(self):
        kv = self.json("integrations/wazuh4-myapp/kvdbs/wazuh4-bad-ips.json")
        self.assertEqual(kv["resource"]["metadata"]["title"], "wazuh4-bad-ips")
        self.assertEqual(kv["resource"]["content"], {"1.2.3.4": "scanner", "10.": "internal-net", "172.16.": "lab"})
        self.assertEqual(kv["source"]["kind"], "list")

    def test_prefixes_become_in_cidr(self):
        res = self.json("integrations/wazuh4-myapp/decoders/02-wazuh4-myapp-auth.json")["resource"]
        checks = [b.get("check") for b in res["normalize"]]
        self.assertIn("in_kvdb($source.ip, 'wazuh4-bad-ips') OR in_cidr($source.ip, '10.0.0.0/8', '172.16.0.0/16')", checks)
        rule = self.rule("wazuh4-myapp", "100600")
        self.assertEqual(rule["resource"]["detection"]["selection"]["tags"], "wazuh4.list.bad-ips")
        self.assertIn("RM-L-PREFIX-KEYS", rule["reasons"])
        self.assertEqual(rule["fidelity"], "approximate")

    def test_match_key_value_reads_then_checks(self):
        res = self.json("integrations/wazuh4-myapp/decoders/02-wazuh4-myapp-auth.json")["resource"]
        blocks = res["normalize"]
        lookup = [b for b in blocks if "check" not in b and "kvdb_lookup" in str(b)]
        self.assertEqual(lookup, [{"map": [{"_wazuh4_lv_100601_1": "kvdb_lookup('wazuh4-bad-ips', $source.ip)"}]}])
        self.assertIn({"check": "regex_match($_wazuh4_lv_100601_1, '(?i)scanner')",
                       "map": [{"tags": "array_append_unique('wazuh4.list.bad-ips.2')"}]}, blocks)


class TestPrefixes(unittest.TestCase):
    def test_prefix_to_cidr(self):
        self.assertEqual(prefix_to_cidr("10."), "10.0.0.0/8")
        self.assertEqual(prefix_to_cidr("192.168."), "192.168.0.0/16")
        self.assertEqual(prefix_to_cidr("192.168.1."), "192.168.1.0/24")
        self.assertIsNone(prefix_to_cidr("a.b."))
        self.assertIsNone(prefix_to_cidr("1.2.3.4."))


class TestListOnStockEvents(unittest.TestCase):
    def test_label_unavailable_is_recipe(self):
        tree = etc_tree(rules={"local_rules.xml": rules_xml("local,", """
  <rule id="100001" level="5"><if_sid>5710</if_sid>
    <list field="srcip" lookup="address_match_key">etc/lists/mylist</list><description>x</description></rule>""")},
                        lists={"mylist": "1.2.3.4:\n"}, extra_ruleset="<list>etc/lists/mylist</list>")
        try:
            dec = D.empty()
            dec["stock"]["rule:5710"] = {"integration": "system-auth", "selection": {"event.action": "authentication-failure"}}
            res = pipeline.compute(scan(tree.root), dec, source=tree.root)
        finally:
            tree.cleanup()
        item = [it for it in res["plan"]["items"] if it["ref"] == "rule:100001"][0]
        self.assertEqual(item["state"], "RECIPE")
        self.assertIn("RM-R-LABEL-UNAVAILABLE", {c["code"] for c in item["codes"]})
        self.assertIn("rule-100001.md", res["package"].recipes)


if __name__ == "__main__":
    unittest.main()
