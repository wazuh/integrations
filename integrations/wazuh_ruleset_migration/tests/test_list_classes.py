"""List classes (stock, IoC, business) and the opt-in rewrite onto the 5.x IoC feeds."""

import unittest

from helpers import MYAPP_DECODER, etc_tree, rules_xml

from rmig import decisions as D
from rmig.quality import lists as LC
from rmig.scan import scan
from rmig.translate import pipeline


def use(rule="1", level=5, field="srcip", lookup="address_match_key"):
    return {"rule": rule, "level": level, "field": field, "lookup": lookup}


def item(name, shape):
    return {"name": name, "shape": shape, "entries": sum(shape.values())}


class TestKeyKind(unittest.TestCase):
    def test_kinds(self):
        self.assertEqual(LC.key_kind("1.2.3.4"), "ip")
        self.assertEqual(LC.key_kind("10."), "prefix")
        self.assertEqual(LC.key_kind("10.0.0.0/8"), "cidr")
        self.assertEqual(LC.key_kind("1.2.3.4:443"), "ip_port")
        self.assertEqual(LC.key_kind("d41d8cd98f00b204e9800998ecf8427e"), "md5")
        self.assertEqual(LC.key_kind("evil.example.com"), "domain")
        self.assertEqual(LC.key_kind("http://evil.example.com/x"), "url")
        self.assertEqual(LC.key_kind("jdoe"), "other")

    def test_shape(self):
        self.assertEqual(LC.list_shape(b"1.2.3.4:a\r\n10.:b\njdoe:c\n\"5.6.7.8\":x\nnoseparator\n"),
                         {"ip": 2, "other": 1, "prefix": 1})


class TestClassifier(unittest.TestCase):
    def test_stock_first(self):
        self.assertEqual(LC.classify_one(item("x", {"ip": 3}), [use()], "same content as stock list x")["class"], "stock")

    def test_alerting_lookup_on_ip_is_ioc(self):
        r = LC.classify_one(item("etc/lists/bad", {"ip": 9, "prefix": 1}), [use(level=10)], None)
        self.assertEqual(r["class"], "ioc")
        self.assertIsNone(r["unsure"])
        self.assertEqual(r["feed_types"], ["connection"])
        self.assertTrue(any("ip:port" in w for w in r["warnings"]))
        self.assertTrue(any("in_cidr" in w for w in r["warnings"]))

    def test_negated_or_level0_is_business(self):
        self.assertEqual(LC.classify_one(item("x", {"ip": 3}), [use(lookup="not_address_match_key")], None)["class"],
                         "business")
        self.assertEqual(LC.classify_one(item("x", {"ip": 3}), [use(level=0)], None)["class"], "business")

    def test_user_field_is_business(self):
        r = LC.classify_one(item("etc/lists/disabled", {"other": 4}), [use(field="win.eventdata.targetUserName",
                                                                           lookup="match_key")], None)
        self.assertEqual((r["class"], r["unsure"]), ("business", None))

    def test_windows_logon_domain_is_business(self):
        # a list of AD domains on targetDomainName is an allowlist, not DNS indicators
        r = LC.classify_one(item("etc/lists/domains", {"other": 3}), [use(field="win.eventdata.targetDomainName",
                                                                          lookup="match_key")], None)
        self.assertEqual((r["class"], r["unsure"]), ("business", None))
        r = LC.classify_one(item("etc/lists/dns", {"domain": 3}), [use(field="data.dns.query", lookup="match_key")],
                            None)
        self.assertEqual(r["class"], "ioc")

    def test_conflict_is_unsure_business(self):
        r = LC.classify_one(item("etc/lists/private-ips", {"ip": 3}), [use(level=7)], None)
        self.assertEqual(r["class"], "business")
        self.assertIn("name says business", r["unsure"])
        r = LC.classify_one(item("x", {"ip": 3}), [use(), use(lookup="not_match_key")], None)
        self.assertEqual(r["class"], "business")
        self.assertIn("both", r["unsure"])

    def test_shape_needs_the_name(self):
        self.assertEqual(LC.classify_one(item("etc/lists/ti-feodo-c2", {"ip": 10}), [], None)["class"], "ioc")
        r = LC.classify_one(item("etc/lists/hosts-x", {"ip": 10}), [], None)
        self.assertEqual(r["class"], "business")
        self.assertTrue(r["unsure"])
        r = LC.classify_one(item("etc/lists/plain", {"ip": 10}), [], None)
        self.assertEqual((r["class"], bool(r["unsure"])), ("business", True))

    def test_hash_list(self):
        r = LC.classify_one(item("etc/lists/x", {"sha256": 5}), [use(field="sha256", lookup="match_key")], None)
        self.assertEqual((r["class"], r["feed_types"]), ("ioc", ["hash_sha256"]))


RULES = rules_xml("myapp,", """
  <rule id="100100" level="0"><decoded_as>myapp</decoded_as><description>myapp group</description></rule>
  <rule id="100101" level="10"><if_sid>100100</if_sid>
    <list field="srcip" lookup="address_match_key">etc/lists/bad-ips</list>
    <description>myapp: login from a bad address</description></rule>
  <rule id="100102" level="5"><if_sid>100100</if_sid>
    <list field="srcuser" lookup="match_key">etc/lists/admins</list>
    <description>myapp: admin</description></rule>""")
DECODER = MYAPP_DECODER.replace("user=(\\S+) action=(\\w+)", "user=(\\S+) from (\\S+)").replace(
    "myapp.user, action", "srcuser, srcip")
REFRESH = """<ossec_config>
  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <list>etc/lists/bad-ips</list>
    <list>etc/lists/admins</list>
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>
  <wodle name="command"><command>/usr/local/bin/fetch.sh /var/ossec/etc/lists/bad-ips</command></wodle>
</ossec_config>
"""


def run(decisions=None):
    tree = etc_tree(rules={"r.xml": RULES}, decoders={"d.xml": DECODER},
                    lists={"bad-ips": "203.0.113.7:scanner\n198.51.100.1:c2\n", "admins": "root:\njdoe:\n"},
                    conf=REFRESH)
    try:
        return pipeline.compute(scan(tree.root), decisions or D.empty(), source=tree.root)
    finally:
        tree.cleanup()


def rule_doc(res, rid):
    for integ in res["package"].integrations.values():
        if rid in integ["rules"]:
            return integ, integ["rules"][rid]
    return None, None


class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = run()

    def test_classes_and_question(self):
        q = {c["name"]: c for c in self.res["quality"]["lists"]}
        self.assertEqual(q["etc/lists/bad-ips"]["class"], "ioc")
        self.assertEqual(q["etc/lists/admins"]["class"], "business")
        entry = self.res["decisions"]["lists"]["etc/lists/bad-ips"]
        self.assertEqual((entry["action"], entry["default_action"], entry["feed_types"]), (None, "kvdb", ["connection"]))
        self.assertNotIn("etc/lists/admins", self.res["decisions"]["lists"])
        self.assertEqual(self.res["report"]["actions"][0]["count"], run()["report"]["actions"][0]["count"])

    def test_refresh_evidence(self):
        q = {c["name"]: c for c in self.res["quality"]["lists"]}
        self.assertEqual(q["etc/lists/bad-ips"]["refresh"][0]["kind"], "wodle")
        self.assertIn("wazuh4-bad-ips", q["etc/lists/bad-ips"]["update_step"])
        self.assertEqual(q["etc/lists/admins"]["refresh"], [])

    def test_default_is_kvdb(self):
        integ, doc = rule_doc(self.res, "100101")
        self.assertEqual(doc["resource"]["detection"]["selection"]["tags"], "wazuh4.list.bad-ips")
        self.assertIn("wazuh4-bad-ips", integ["kvdbs"])

    def test_ioc_feed_rewrite(self):
        dec = D.empty()
        dec["lists"] = {"etc/lists/bad-ips": {"action": "ioc-feed"}}
        res = run(dec)
        integ, doc = rule_doc(res, "100101")
        det = doc["resource"]["detection"]
        self.assertIn("connection", [v.get(LC.IOC_FIELD) for v in det.values() if isinstance(v, dict)])
        self.assertNotIn("wazuh4.list.bad-ips", str(det))
        self.assertIn("RM-L-IOC-FEED", doc["reasons"])
        self.assertEqual(doc["fidelity"], "approximate")
        self.assertNotIn("wazuh4-bad-ips", integ["kvdbs"])

    def test_invalid_action(self):
        dec = D.empty()
        dec["lists"] = {"etc/lists/bad-ips": {"action": "feed"}}
        with self.assertRaises(D.DecisionsError):
            D.validate(dec)

    def test_report_section(self):
        self.assertIn("## Lists and the 5.x IoC feeds", self.res["markdown"])


if __name__ == "__main__":
    unittest.main()
