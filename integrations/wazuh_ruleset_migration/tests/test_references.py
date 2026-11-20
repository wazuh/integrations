"""Alerting blocks of ossec.conf and their 5.x references."""

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest

from helpers import MYAPP_DECODER, TempTree, etc_tree, rules_xml

from rmig import cli
from rmig import decisions as D
from rmig.quality import references as REF
from rmig.scan import scan
from rmig.translate import pipeline

RULES = rules_xml("myapp,", """
  <rule id="100100" level="0"><decoded_as>myapp</decoded_as><description>myapp group</description></rule>
  <rule id="100101" level="5"><if_sid>100100</if_sid><match>login failed</match>
    <description>myapp: login failed</description></rule>
  <rule id="100102" level="12"><if_sid>100100</if_sid><match>tamper</match>
    <description>myapp: tamper</description><group>tamper,</group></rule>
  <rule id="100103" level="10" frequency="5" timeframe="60"><if_matched_sid>100101</if_matched_sid>
    <description>myapp: brute force</description></rule>""")

BLOCKS = """
  <command><name>firewall-drop</name><executable>firewall-drop</executable><timeout_allowed>yes</timeout_allowed></command>
  <command><name>my-script</name><executable>my-script.sh</executable></command>
  <active-response><command>firewall-drop</command><location>local</location>
    <rules_id>100101,100103,5716,99999</rules_id><timeout>600</timeout></active-response>
  <active-response><command>my-script</command><location>server</location><level>10</level>
    <rules_group>tamper</rules_group><repeated_offenders>30,60</repeated_offenders></active-response>
  <integration><name>slack</name><hook_url>https://hooks.example/SECRET</hook_url><level>12</level>
    <group>myapp</group></integration>
  <integration><name>custom-ticket</name><api_key>SECRETKEY</api_key><rule_id>100102</rule_id>
    <event_location>web01</event_location></integration>
  <email_alerts><email_to>a@example.com</email_to><level>7</level></email_alerts>
  <alerts><log_alert_level>3</log_alert_level><email_alert_level>12</email_alert_level></alerts>
  <global><white_list>127.0.0.1</white_list><logall>no</logall></global>
  <localfile><log_format>syslog</log_format><location>/var/log/myapp.log</location></localfile>
"""


def conf(blocks):
    return """<ossec_config>
  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>
%s
</ossec_config>
""" % blocks


def run(blocks=BLOCKS):
    tree = etc_tree(rules={"r.xml": RULES}, decoders={"d.xml": MYAPP_DECODER}, conf=conf(blocks))
    try:
        res = pipeline.compute(scan(tree.root), D.empty(), source=tree.root)
    finally:
        tree.cleanup()
    return res


class TestLevels(unittest.TestCase):
    def test_band_from_level_upward(self):
        self.assertEqual(REF.levels_from(10), (["high", "critical"], False))
        self.assertEqual(REF.levels_from(12), (["high", "critical"], True))
        self.assertEqual(REF.levels_from(1), (["informational", "low", "medium", "high", "critical"], False))
        self.assertEqual(REF.levels_from(15), (["critical"], True))


class TestReferences(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = run()
        cls.refs = cls.res["quality"]["references"]
        cls.by = {}
        for r in cls.refs:
            cls.by.setdefault(r["kind"], []).append(r)

    def test_every_block_once(self):
        self.assertEqual([r["kind"] for r in self.refs],
                         ["active-response", "active-response", "integration", "integration", "email_alerts",
                          "alerts", "global", "localfile"])

    def test_ar_rule_ids(self):
        ar = self.by["active-response"][0]
        kinds = {r["id"]: r["kind"] for r in ar["rules"]}
        self.assertEqual(kinds, {"100101": "custom", "100103": "monitor", "5716": "stock", "99999": "unknown"})
        self.assertEqual(ar["query"], {"bool": {"should": [{"term": {"tags": "wazuh4.rule.100101"}}],
                                                "minimum_should_match": 1}})
        self.assertTrue(any("monitors/100103.json" in f for f in ar["flags"]))
        self.assertIn("Type Stateful, Stateful timeout 600s", ar["checklist"])
        self.assertTrue(ar["checklist"][0].startswith("Explore > Active Responses: create the channel (name, executable block-ip"))

    def test_ar_level_and_group_both_hold(self):
        ar = self.by["active-response"][1]
        should = ar["query"]["bool"]["should"]
        self.assertEqual(should, [{"bool": {"filter": [{"terms": {"wazuh.rule.level": ["high", "critical"]}},
                                                       {"terms": {"tags": ["wazuh4.group.tamper"]}}]}}])
        text = " ".join(ar["flags"])
        self.assertIn("location server", text)
        self.assertIn("repeated_offenders", text)
        self.assertIn("custom AR script my-script.sh", text)

    def test_integration_and_secrets(self):
        slack, custom = self.by["integration"]
        self.assertEqual(slack["query"], {"bool": {"filter": [
            {"terms": {"wazuh.rule.level": ["high", "critical"]}},
            {"terms": {"tags": ["wazuh4.group.myapp"]}}]}})
        self.assertTrue(any("inside the high band" in f for f in slack["flags"]))
        self.assertNotIn("SECRET", json.dumps(self.refs))
        self.assertIn("custom script", " ".join(custom["flags"]))
        self.assertIn("event_location", " ".join(custom["flags"]))
        self.assertEqual(custom["query"]["bool"]["should"], [{"term": {"tags": "wazuh4.rule.100102"}}])

    def test_unmapped_and_filter_gives_no_query(self):
        res = run("""
  <command><name>firewall-drop</name><executable>firewall-drop</executable></command>
  <active-response><command>firewall-drop</command><level>10</level><rules_group>sshd</rules_group></active-response>
  <integration><name>slack</name><level>10</level><group>sshd</group></integration>
  <integration><name>pagerduty</name><level>10</level><rule_id>5716</rule_id></integration>
""")
        ar, slack, pd = res["quality"]["references"][:3]
        self.assertIsNone(ar["query"])
        self.assertIn("level AND rules_group", " ".join(ar["flags"]))
        self.assertIsNone(slack["query"])
        self.assertIn("no monitor query: group", " ".join(slack["flags"]))
        self.assertIsNone(pd["query"])
        self.assertIn("no monitor query: rule_id", " ".join(pd["flags"]))

    def test_email_alerts_global(self):
        self.assertEqual(self.by["email_alerts"][0]["query"],
                         {"bool": {"filter": [{"terms": {"wazuh.rule.level": ["medium", "high", "critical"]}}]}})
        self.assertIn("log_alert_level 3", " ".join(self.by["alerts"][0]["flags"]))
        g = " ".join(self.by["global"][0]["flags"])
        self.assertIn("white_list", g)
        self.assertIn("logall", g)
        self.assertEqual(self.by["localfile"][0]["feeds"][0]["location"], "/var/log/myapp.log")

    def test_report_section(self):
        md = self.res["markdown"]
        self.assertIn("## ossec.conf references", md)
        self.assertLess(md.index("## ossec.conf references"), md.index("\n## Items\n"))
        self.assertEqual(self.res["plan"]["summary"], run("")["plan"]["summary"])  # no new items


class TestCompleteness(unittest.TestCase):
    def test_section(self):
        tree = etc_tree(rules={"r.xml": RULES}, decoders={"d.xml": MYAPP_DECODER}, conf=conf(BLOCKS))
        os.makedirs(os.path.join(tree.root, "shared", "web-servers"))
        try:
            res = pipeline.compute(scan(tree.root), D.empty(), source=tree.root)
        finally:
            tree.cleanup()
        c = res["quality"]["completeness"]
        self.assertEqual(c["agent_groups"], ["web-servers"])
        sections = {s["section"]: s for s in c["settings"]}
        self.assertEqual(sections["command"]["count"], 2)
        self.assertTrue(sections["integration"]["guide"].endswith("integratord-notifications.md"))
        whats = [m["what"] for m in c["monitors"]]
        self.assertEqual(whats[0], "frequency rule 100103")
        self.assertEqual(len(whats), 6)  # 1 frequency + 2 AR + 2 integrations + 1 email
        md = res["markdown"]
        self.assertIn("## Not migrated, and why", md)
        self.assertIn("Agent groups (1 in `etc/shared/`", md)


class TestOut(unittest.TestCase):
    def _build(self, blocks):
        tree = etc_tree(rules={"r.xml": RULES}, decoders={"d.xml": MYAPP_DECODER}, conf=conf(blocks))
        work = tempfile.mkdtemp(prefix="rmig-ref-")
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                cli.main(["migrate", "--source", tree.root, "--workdir", work])
            out = os.path.join(work, "out", "references")
            return sorted(os.listdir(out)) if os.path.isdir(out) else []
        finally:
            tree.cleanup()
            shutil.rmtree(work, ignore_errors=True)

    def test_files_per_block(self):
        names = self._build(BLOCKS)
        self.assertIn("01-active-response-firewall-drop.json", names)
        self.assertIn("01-active-response-firewall-drop.md", names)
        self.assertEqual(len(names), 16)

    def test_nothing_without_blocks(self):
        self.assertEqual(self._build(""), [])

    def test_no_secret_in_any_written_file(self):
        """work/inventory.json, report.json, report.md and out/ hold no secret of ossec.conf."""
        blocks = BLOCKS + """
  <wodle name="aws-s3"><bucket type="cloudtrail"><name>b</name><access_key>AKIASECRET1</access_key>
    <secret_key>SECRET2</secret_key></bucket></wodle>"""
        tree = etc_tree(rules={"r.xml": RULES}, decoders={"d.xml": MYAPP_DECODER}, conf=conf(blocks))
        work = tempfile.mkdtemp(prefix="rmig-ref-")
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                cli.main(["migrate", "--source", tree.root, "--workdir", work])
            seen = 0
            for base, _dirs, names in os.walk(work):
                for n in names:
                    with open(os.path.join(base, n), "rb") as f:
                        data = f.read()
                    seen += 1
                    self.assertNotIn(b"SECRET", data, os.path.join(base, n))
            self.assertTrue(os.path.isfile(os.path.join(work, "work", "inventory.json")))
            self.assertGreater(seen, 3)
        finally:
            tree.cleanup()
            shutil.rmtree(work, ignore_errors=True)


class TestAcmepay(unittest.TestCase):
    def test_example(self):
        from helpers import TOOL
        src = os.path.join(TOOL, "examples", "acmepay", "etc")
        dec = D.load(os.path.join(TOOL, "examples", "acmepay", "decisions.json"))
        res = pipeline.compute(scan(src), dec, source=src)
        refs = {r["kind"]: r for r in res["quality"]["references"]}
        self.assertEqual({r["id"]: r["kind"] for r in refs["active-response"]["rules"]},
                         {"100205": "custom", "100203": "monitor"})
        self.assertEqual({r["id"]: r["kind"] for r in refs["email_alerts"]["rules"]},
                         {"100204": "custom", "5716": "stock"})
        self.assertEqual(refs["integration"]["query"]["bool"]["filter"][1], {"terms": {"tags": ["wazuh4.group.acmepay"]}})
        lists = {r["name"]: r["class"] for r in res["quality"]["lists"]}
        self.assertEqual(lists, {"etc/lists/blocked-ips": "ioc"})
        self.assertIsNone(res["decisions"]["lists"]["etc/lists/blocked-ips"]["action"])


class TestLooseTree(unittest.TestCase):
    def test_fragment_is_read(self):
        tree = TempTree({"rules/r.xml": RULES, "decoders/d.xml": MYAPP_DECODER,
                         "integration/ossec.conf": "<integration><name>pagerduty</name><level>10</level></integration>\n"})
        try:
            inv = scan(tree.root)
        finally:
            tree.cleanup()
        self.assertEqual(inv["source"]["mode"], "loose")
        self.assertEqual([b["kind"] for c in inv["conf_files"] for b in c["blocks"]], ["integration"])

    def test_old_inventory_without_conf_files(self):
        tree = etc_tree(rules={"r.xml": RULES}, decoders={"d.xml": MYAPP_DECODER}, conf=conf(BLOCKS))
        try:
            inv = scan(tree.root)
            del inv["conf_files"]
            res = pipeline.compute(inv, D.empty(), source=tree.root)
        finally:
            tree.cleanup()
        self.assertEqual(res["quality"]["references"], [])


if __name__ == "__main__":
    unittest.main()
