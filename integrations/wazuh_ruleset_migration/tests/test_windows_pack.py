"""The Windows pack: stock Windows chains and the win.* field map without decisions."""

import json
import os
import tempfile
import unittest

from helpers import STOCK_INDEX, codes, etc_tree, one, rules_xml, use_full_stock

from rmig import decisions as D
from rmig import stock
from rmig.scan import scan
from rmig.translate import pipeline
from rmig.winpack import load_pack

PACK = load_pack()


def translate(rules, decisions=None):
    tree = etc_tree(rules={"local_rules.xml": rules_xml("local,", rules)})
    try:
        inv = scan(tree.root)
        return pipeline.compute(inv, decisions if decisions is not None else D.empty())
    finally:
        tree.cleanup()


def detection(res, rule_id):
    for integ in res["package"].integrations.values():
        doc = integ["rules"].get(rule_id)
        if doc:
            return doc["resource"]["detection"]
    raise AssertionError("rule %s not emitted" % rule_id)


def conds(alt):
    return [(c["name"].lower(), c.get("value")) for c in alt["conditions"]]


class TestDerivation(unittest.TestCase):
    """Chains of the real 4.14 ruleset flattened to rule 60000 (needs RMIG_STOCK_DIR)."""

    @classmethod
    def setUpClass(cls):
        global PACK
        use_full_stock()
        cls._saved, PACK = PACK, load_pack()

    @classmethod
    def tearDownClass(cls):
        global PACK
        PACK = cls._saved
        stock.set_active(STOCK_INDEX)

    def test_61603_sysmon_event_1(self):
        (alt,) = PACK.alternatives("rule:61603")
        self.assertEqual(alt["path"], ["60000", "60004", "61600", "61603"])
        self.assertEqual(alt["scope"], "sysmon")
        self.assertEqual(alt["event_ids"], ["1"])
        self.assertEqual(conds(alt), [("win.system.channel", "^Microsoft-Windows-Sysmon/Operational$"),
                                      ("win.system.severityvalue", "^INFORMATION$"),
                                      ("win.system.eventid", "^1$")])

    def test_61615_sysmon_event_13(self):
        (alt,) = PACK.alternatives("rule:61615")
        self.assertEqual(alt["event_ids"], ["13"])
        self.assertEqual(alt["path"][-1], "61615")

    def test_91802_two_parents_absorbed_and_override(self):
        # 91801 has if_sid 60000, 60010: the path through 60010 adds a condition and is absorbed
        (alt,) = PACK.alternatives("rule:91802")
        self.assertEqual(alt["path"], ["60000", "91801", "91802"])
        self.assertEqual(alt["scope"], "powershell-operational")
        self.assertEqual(alt["event_ids"], ["4104"])
        self.assertTrue(any(c.get("override") for c in alt["conditions"]))

    def test_60103_security_audit_success(self):
        (alt,) = PACK.alternatives("rule:60103")
        self.assertEqual(alt["scope"], "security")
        self.assertIsNone(alt["event_ids"])
        self.assertIn(("win.system.severityvalue", "^AUDIT_SUCCESS$|^success$"), conds(alt))

    def test_if_group_chain(self):
        # 92200 hangs from <if_group>sysmon_event_11</if_group>
        alts = PACK.alternatives("rule:92200")
        self.assertTrue(alts)
        self.assertTrue(all(a["path"][-2] == "61613" for a in alts))
        self.assertTrue(PACK.partial("rule:92200"))  # its legacy path through 185009 is left out
        self.assertTrue(PACK.knows("group:sysmon_event_11"))
        self.assertIn("61613", PACK.groups["sysmon_event_11"]["members"])
        # the legacy (WinEvtLog) member is left out, and said so
        self.assertIn("185009", PACK.groups["sysmon_event_11"]["dropped"])
        self.assertTrue(PACK.partial("group:sysmon_event_11"))

    def test_root_rule_condition_is_implied(self):
        (alt,) = PACK.alternatives("rule:60001")
        self.assertNotIn("win.system.providername", [c[0] for c in conds(alt)])


class TestFieldMap(unittest.TestCase):
    def test_lookups(self):
        self.assertEqual(PACK.eventdata("win.eventdata.image", [("sysmon", ["1"])])[0], "process.executable")
        self.assertEqual(PACK.eventdata("win.eventdata.commandLine", [("sysmon", ["1"])])[0], "process.command_line")
        self.assertEqual(PACK.eventdata("win.eventdata.targetFilename", [("sysmon", ["11"])])[0], "file.path")
        self.assertEqual(PACK.eventdata("win.eventdata.scriptBlockText", [("powershell-operational", ["4104"])])[0],
                         "message")
        self.assertEqual(PACK.eventdata("win.eventdata.ipAddress", [("security", ["4625"])])[0], "source.ip")
        self.assertEqual(PACK.system_direct("win.system.eventID", [("sysmon", ["1"])]), "event.code")

    def test_case_insensitive_names(self):
        a = PACK.eventdata("win.eventdata.Image", [("sysmon", ["1"])])
        b = PACK.eventdata("WIN.EVENTDATA.IMAGE", [("sysmon", ["1"])])
        self.assertEqual(a, b)

    def test_no_mapping_without_evidence(self):
        # Sysmon splits User into domain and name: no direct copy
        self.assertIsNone(PACK.eventdata("win.eventdata.user", [("sysmon", ["1"])]))
        # ScriptBlockText is message only in event 4104
        self.assertIsNone(PACK.eventdata("win.eventdata.scriptBlockText", [("powershell-operational", None)]))
        # Hashes is parsed into several fields
        self.assertIsNone(PACK.eventdata("win.eventdata.hashes", [("sysmon", ["1"])]))

    def test_per_event_id(self):
        # ImageLoaded is file.path in event 7; in event 1 file.path has no writer from it
        self.assertEqual(PACK.eventdata("win.eventdata.imageLoaded", [("sysmon", ["7"])])[0], "file.path")
        self.assertIsNone(PACK.eventdata("win.eventdata.targetFilename", [("sysmon", None)]))

    def test_every_target_is_wcs(self):
        from rmig.fields import wcs_fields
        wcs = wcs_fields()
        for name, by_scope in PACK.fields.items():
            for scope, by_eid in by_scope.items():
                for eid, ent in by_eid.items():
                    self.assertTrue(wcs.exists(ent["wcs"]), (name, scope, eid, ent["wcs"]))
                    self.assertTrue(ent["evidence"].startswith("decoder/windows-"), ent)

    def test_header_records_the_snapshot(self):
        src = PACK.data["source"]
        self.assertIn("offset 1497", src["catalog"])
        self.assertNotIn("stock", src)

    def test_chains_come_from_the_active_ruleset(self):
        (alt,) = PACK.alternatives("rule:61603")
        self.assertEqual(alt["path"], ["60000", "60004", "61600", "61603"])
        self.assertEqual(alt["scope"], "sysmon")
        self.assertEqual(alt["event_ids"], ["1"])
        (alt,) = PACK.alternatives("rule:91802")
        self.assertEqual(alt["path"], ["60000", "91801", "91802"])
        self.assertEqual(alt["event_ids"], ["4104"])
        self.assertIn("61613", PACK.groups["sysmon_event_11"]["members"])

    def test_no_stock_ruleset_means_no_chains(self):
        stock.set_active(None)
        try:
            pack = load_pack()
            self.assertFalse(pack.knows("rule:61603"))
            self.assertEqual(pack.integration, "windows")
        finally:
            stock.set_active(STOCK_INDEX)


class TestTranslation(unittest.TestCase):
    RULES = """
  <rule id="100100" level="10">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.commandLine">sekurlsa</field>
    <description>mimikatz</description>
  </rule>
  <rule id="100101" level="8">
    <if_sid>60104</if_sid>
    <field name="win.system.eventID">^4625$</field>
    <field name="win.eventdata.ipAddress">^10.1.1.1$</field>
    <description>failed logon</description>
  </rule>
  <rule id="100102" level="8">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4720$</field>
    <field name="win.eventdata.samAccountName">admin</field>
    <description>user created</description>
  </rule>"""

    @classmethod
    def setUpClass(cls):
        cls.res = translate(cls.RULES)

    def test_sysmon_event_1_with_zero_answers(self):
        item = one(self.res, "rule:100100")
        self.assertEqual(item["state"], "AUTO")
        self.assertNotIn("RM-S-NO-EQUIVALENT", codes(item))
        det = detection(self.res, "100100")
        sel = det["selection"]
        self.assertEqual(sel["event.code"], "1")
        self.assertEqual(sel["event.dataset"], "sysmon")
        # fix B: no log.level in the Sysmon scope, the item says so
        self.assertNotIn("log.level", json.dumps(det))
        self.assertIn("not selected in the Sysmon scope", json.dumps(item["codes"]))
        self.assertEqual(item["fidelity"], "approximate")
        self.assertEqual(sel["wazuh.integration.name"], "windows")
        self.assertIn("process.command_line|re", sel)

    def test_sysmon_error_keeps_log_level(self):
        rules = """
  <rule id="100150" level="8">
    <if_sid>61602</if_sid>
    <field name="win.system.eventID">^255$</field>
    <description>sysmon error</description>
  </rule>"""
        res = translate(rules)
        item = one(res, "rule:100150")
        self.assertEqual(item["state"], "AUTO")
        sel = detection(res, "100150")["selection"]
        self.assertEqual(sel["log.level"], "error")
        self.assertNotIn("not selected in the Sysmon scope", json.dumps(item["codes"]))
        self.assertIn("log.level on Sysmon findings is not proven", json.dumps(item["codes"]))
        self.assertEqual(item["fidelity"], "approximate")

    def test_security_value_tables(self):
        item = one(self.res, "rule:100101")
        self.assertEqual(item["state"], "AUTO")
        sel = detection(self.res, "100101")["selection"]
        self.assertEqual(sel["event.outcome"], "failure")
        self.assertEqual(sel["event.dataset"], "security")
        self.assertEqual(sel["event.code"], "4625")
        self.assertEqual(sel["source.ip"], "10.1.1.1")

    def test_unmapped_field_stays_a_question(self):
        item = one(self.res, "rule:100102")
        self.assertEqual(item["state"], "DECISION")
        self.assertIn("RM-F-UNMAPPED", codes(item))
        self.assertIn("win.eventdata.samAccountName", self.res["decisions"]["fields"])

    def test_no_stock_question_for_pack_references(self):
        for key in ("rule:61603", "rule:60104", "rule:60103"):
            self.assertNotIn(key, self.res["decisions"]["stock"])

    def test_user_decisions_win(self):
        dec = D.empty()
        dec["fields"]["win.eventdata.commandLine"] = {"action": "map", "wcs": "process.args"}
        dec["fields"]["win.eventdata.samAccountName"] = {"action": "map", "wcs": "user.name"}
        dec["stock"]["rule:60103"] = {"integration": "windows", "selection": {"event.code": "4720"}}
        res = translate(self.RULES, dec)
        self.assertIn("process.args|re", detection(res, "100100")["selection"])
        self.assertEqual(one(res, "rule:100102")["state"], "AUTO")
        sel = detection(res, "100102")["selection"]
        self.assertNotIn("event.dataset", sel)  # the user's selection replaced the pack chain
        self.assertIn("user.name|re", sel)

    def test_discarded_event_id_is_a_recipe(self):
        # the 5.x base decoder discards 4663: a custom rule on it cannot fire
        res = translate("""
  <rule id="100110" level="8">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4663$</field>
    <description>object access</description>
  </rule>""")
        item = one(res, "rule:100110")
        self.assertIn("RM-S-WIN-DISCARDED", codes(item))
        self.assertEqual(item["state"], "RECIPE")

    def test_match_on_windows_content_is_a_recipe(self):
        res = translate("""
  <rule id="100111" level="8">
    <if_sid>61603</if_sid>
    <match>mimikatz</match>
    <description>full log</description>
  </rule>""")
        item = one(res, "rule:100111")
        self.assertIn("RM-S-WIN-FULL-LOG", codes(item))
        self.assertEqual(item["state"], "RECIPE")

    def test_approximate_mapping_has_a_code(self):
        res = translate("""
  <rule id="100112" level="8">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4698$</field>
    <description>task</description>
  </rule>""")
        item = one(res, "rule:100112")
        self.assertEqual(item["state"], "AUTO")
        self.assertEqual(item["fidelity"], "approximate")
        self.assertIn("RM-S-WIN-APPROXIMATE", codes(item))

    def test_stock_condition_without_field_asks(self):
        # 60007: providerName Eventlog has no 5.x field: the reference becomes a question
        res = translate("""
  <rule id="100113" level="8">
    <if_sid>60007</if_sid>
    <description>eventlog</description>
  </rule>""")
        item = one(res, "rule:100113")
        self.assertEqual(item["state"], "DECISION")
        self.assertIn("RM-S-WIN-CONDITION", codes(item))
        self.assertIn("rule:60007", res["decisions"]["stock"])

    def test_deterministic(self):
        again = translate(self.RULES)
        self.assertEqual(detection(again, "100100"), detection(self.res, "100100"))


if __name__ == "__main__":
    unittest.main()
