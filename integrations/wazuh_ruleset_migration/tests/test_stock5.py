"""Offline "5.x stock for your sources".

Matching of each source to a stock 5.x integration with the bundled index
(``rmig/data/stock5-index.json``, RC3 offset 1497), the rule verdicts and the
report section. The decoders and rules are synthetic, written in the shape of
common custom rulesets."""

import json
import os
import unittest

from helpers import TOOL, compute, etc_tree, rules_xml

from rmig import stock5
from rmig.report.markdown import render

INDEX = stock5.load_index()

# synthetic auditd decoders and rules
AUDITD_DEC = """<decoder name="auditd-execve">
  <prematch>^type=EXECVE</prematch>
</decoder>
<decoder name="auditd-execve1">
  <parent>auditd-execve</parent>
  <regex>argc=(\\d+) a0="(\\S+)"</regex>
  <order>audit.argc, audit.execve.a0</order>
</decoder>
"""
AUDITD_RULES = rules_xml("auditd,", """
  <rule id="200110" level="3">
    <decoded_as>auditd-execve</decoded_as>
    <description>Auditd execve.</description>
  </rule>
  <rule id="200111" level="10">
    <if_sid>200110</if_sid>
    <field name="audit.execve.a0">tar</field>
    <description>Archive created via tar.</description>
    <mitre><id>T1560</id></mitre>
  </rule>
""")

# synthetic Sysmon for Linux decoder
SYSMON_LINUX_DEC = """<decoder name="sysmon-linux">
  <program_name>sysmon</program_name>
</decoder>
"""
SYSMON_LINUX_RULES = rules_xml("linux,sysmon,", """
  <rule id="200150" level="3">
    <decoded_as>sysmon-linux</decoded_as>
    <description>Sysmon for Linux event.</description>
  </rule>
""")

# synthetic FortiGate decoders and rules
FORTI_DEC = """<decoder name="fortinet-fortigate-firewall">
  <prematch>^date=\\S+ time=\\S+ devname="</prematch>
</decoder>
<decoder name="fortinet-fortigate-firewall-logid">
  <parent>fortinet-fortigate-firewall</parent>
  <prematch> logid="</prematch>
  <regex>logid="(\\d+)"</regex>
  <order>logid</order>
</decoder>
"""
FORTI_RULES = rules_xml("fortigate,", """
  <rule id="300000" level="3">
    <decoded_as>fortinet-fortigate-firewall</decoded_as>
    <description>FortiGate message.</description>
  </rule>
  <rule id="300001" level="8">
    <if_sid>300000</if_sid>
    <field name="logid">^0100032002$</field>
    <description>FortiGate admin login failed.</description>
    <mitre><id>T1110</id></mitre>
  </rule>
""")

# synthetic Sophos XGS decoder
SOPHOS_DEC = """<decoder name="sophos-xgs">
  <prematch>device_name="</prematch>
</decoder>
"""
SOPHOS_RULES = rules_xml("sophos,", """
  <rule id="300100" level="3">
    <decoded_as>sophos-xgs</decoded_as>
    <description>Sophos XGS event.</description>
  </rule>
""")

# synthetic MikroTik decoder
MIKROTIK_DEC = """<decoder name="mikrotik-ovpn-parent">
  <prematch>ovpn,info</prematch>
</decoder>
"""
MIKROTIK_RULES = rules_xml("mikrotik,", """
  <rule id="300200" level="5">
    <decoded_as>mikrotik-ovpn-parent</decoded_as>
    <description>MikroTik OpenVPN event.</description>
  </rule>
""")

# synthetic office365 feed (stock 4.x module location)
OFFICE_RULES = rules_xml("office365,", """
  <rule id="300300" level="3">
    <location>office365</location>
    <description>Office 365 operation.</description>
  </rule>
  <rule id="300301" level="10">
    <if_sid>300300</if_sid>
    <field name="office365.Operation">^UserLoginFailed$</field>
    <description>Office 365 login failure.</description>
    <mitre><id>T1110</id></mitre>
  </rule>
""")

# Sysmon rules over the stock Windows chain: one with a MITRE match, one with no stock candidate, one without MITRE,
# one silencer.
SYSMON_RULES = rules_xml("windows,sysmon,", """
  <rule id="300400" level="10">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.image">\\\\whoami.exe</field>
    <description>whoami executed.</description>
    <mitre><id>T1033</id></mitre>
  </rule>
  <rule id="300401" level="10">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.image">\\\\notepad.exe</field>
    <description>Notepad as endpoint denial of service.</description>
    <mitre><id>T1499</id></mitre>
  </rule>
  <rule id="300402" level="10">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.image">\\\\calc.exe</field>
    <description>Calculator executed.</description>
  </rule>
  <rule id="300404" level="10">
    <if_sid>61600</if_sid>
    <field name="win.eventdata.image">\\cmd.exe</field>
    <description>cmd in any Sysmon event.</description>
    <mitre><id>T1059</id></mitre>
  </rule>
  <rule id="300403" level="12">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.image">\\\\tasklist.exe</field>
    <description>Mitre ATT&amp;CK T1057, tasklist.</description>
  </rule>
""")


def _section(rules, decoders=None):
    tree = etc_tree(rules=rules, decoders=decoders or {})
    try:
        res = compute(tree.path())
    finally:
        tree.cleanup()
    return res, res["report"]["stock5"]


def _source(sec, key):
    found = [s for s in sec["sources"] if s["key"] == key]
    if len(found) != 1:
        raise AssertionError("source %s not found in %s" % (key, [s["key"] for s in sec["sources"]]))
    return found[0]


def _verdict(sec, ref):
    found = [r for r in sec["items"] if r["ref"] == ref]
    if len(found) != 1:
        raise AssertionError("rule %s: %d rows" % (ref, len(found)))
    return found[0]


class IndexTest(unittest.TestCase):
    def test_header_and_counts(self):
        self.assertEqual(INDEX.offset, 1497)
        self.assertEqual(len(INDEX.integrations), 132)
        self.assertFalse(INDEX.integrations["fortinet"]["enabled"])
        self.assertEqual(INDEX.integrations["fortinet"]["rules"], [])
        self.assertEqual(len(INDEX.rules_of("o365")), 16)
        # rules that select events by wazuh.integration.name count for that integration
        self.assertGreater(len(INDEX.rules_of("aws")), len(INDEX.integrations["aws"]["rules"]))

    def test_negated_literal_is_not_a_probe(self):
        probes = INDEX.decoders["decoder/linux-systemd/0"].get("probes", {})
        self.assertNotIn("pam_", probes.get("starts_with", []))

    def test_definitions_are_read(self):
        self.assertIn("sshd", INDEX.decoders["decoder/system-auth/0"]["probes"]["process_names"])

    def test_generator_regex_fragments(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("b5", os.path.join(TOOL, "scripts", "build_stock5_index.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertEqual(mod.regex_fragments("^(?i:wazuh-yara): (?:INFO|ERROR) - Scan result: \\S"),
                         ["wazuh-yara", "INFO", "ERROR", " - Scan result: "])


class LiteralTest(unittest.TestCase):
    def test_osregex_literals(self):
        self.assertEqual(stock5.literals_4x("^type=EXECVE", "osregex"), ["type=EXECVE"])
        self.assertEqual(stock5.literals_4x("CEF:0\\|Ubiquiti\\|UniFi", "osregex"), ["CEF:0|Ubiquiti|UniFi"])
        self.assertEqual(stock5.literals_4x("user \\S+ logged", "osregex"), ["user ", " logged"])

    def test_osmatch_alternatives(self):
        self.assertEqual(stock5.literals_4x("hostapd:|wpa_supplicant", "osmatch"), ["hostapd:", "wpa_supplicant"])

    def test_distinctive(self):
        self.assertTrue(stock5.distinctive("type="))
        self.assertTrue(stock5.distinctive("%ASA"))
        self.assertFalse(stock5.distinctive("user"))
        self.assertFalse(stock5.distinctive("CEF:0"))


class MatchTest(unittest.TestCase):
    def test_auditd(self):
        _res, sec = _section({"a.xml": AUDITD_RULES}, {"a.xml": AUDITD_DEC})
        s = _source(sec, "decoder:auditd-execve")
        self.assertEqual(s["integration"], "auditd")
        self.assertEqual(s["method"], "check-literal")
        self.assertTrue(s["enabled"])
        self.assertEqual(s["verdict"], stock5.S_RULES)
        self.assertIn("'type='", s["evidence"][0])
        # stock rule "Archive created via tar" has T1560
        self.assertEqual(_verdict(sec, "rule:200111")["verdict"], stock5.V_CANDIDATE)

    def test_sysmon_linux(self):
        _res, sec = _section({"s.xml": SYSMON_LINUX_RULES}, {"s.xml": SYSMON_LINUX_DEC})
        s = _source(sec, "decoder:sysmon-linux")
        self.assertEqual((s["integration"], s["method"], s["confidence"]), ("linux", "program-name", "high"))
        self.assertGreater(s["stock_rules"], 0)

    def test_fortigate_decode_only(self):
        _res, sec = _section({"f.xml": FORTI_RULES}, {"f.xml": FORTI_DEC})
        s = _source(sec, "decoder:fortinet-fortigate-firewall")
        self.assertEqual(s["integration"], "fortinet")
        self.assertNotEqual(s["method"], "name")
        self.assertEqual(s["verdict"], stock5.V_DECODE_ONLY)
        self.assertEqual(_verdict(sec, "rule:300001")["verdict"], stock5.V_DECODE_ONLY)
        self.assertIn("fortinet", [g["integration"] for g in sec["gaps"]])

    def test_sophos_decode_only(self):
        _res, sec = _section({"s.xml": SOPHOS_RULES}, {"s.xml": SOPHOS_DEC})
        s = _source(sec, "decoder:sophos-xgs")
        self.assertEqual((s["integration"], s["method"], s["confidence"]), ("sophos", "partial-literal", "medium"))
        self.assertEqual(s["verdict"], stock5.V_DECODE_ONLY)

    def test_mikrotik_none(self):
        _res, sec = _section({"m.xml": MIKROTIK_RULES}, {"m.xml": MIKROTIK_DEC})
        s = _source(sec, "decoder:mikrotik-ovpn-parent")
        self.assertIsNone(s["integration"])
        self.assertEqual(s["verdict"], stock5.V_NONE)
        self.assertEqual(_verdict(sec, "rule:300200")["verdict"], stock5.V_NONE)
        self.assertEqual([g["source"] for g in sec["gaps"]], ["decoder:mikrotik-ovpn-parent"])

    def test_office365_feed_covered_if_enabled(self):
        _res, sec = _section({"o.xml": OFFICE_RULES})
        s = _source(sec, "feed:office365#300300")
        self.assertEqual((s["integration"], s["method"], s["confidence"]), ("o365", "json-tag", "high"))
        self.assertFalse(s["enabled"])
        self.assertEqual(s["verdict"], stock5.S_RULES_IF_ENABLED)
        row = _verdict(sec, "rule:300301")
        self.assertEqual(row["verdict"], stock5.V_IF_ENABLED)
        self.assertIn("enable o365", row["why"])

    def test_unmatched_feed_roots_are_one_row(self):
        rules = rules_xml("misc,", """
  <rule id="300500" level="3">
    <location>appone</location>
    <description>App one.</description>
  </rule>
  <rule id="300510" level="3">
    <decoded_as>json</decoded_as>
    <field name="zzapp.kind">\\.+</field>
    <description>JSON app.</description>
  </rule>
  <rule id="300520" level="3">
    <decoded_as>json</decoded_as>
    <field name="yyapp.kind">\\.+</field>
    <description>Other JSON app.</description>
  </rule>
""")
        _res, sec = _section({"x.xml": rules})
        rows = [s for s in sec["sources"] if s["key"] == "feed:json-events#*"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["roots"], ["300510", "300520"])
        self.assertEqual(sec["feeds_by_verdict"][stock5.V_NONE], 2)

    def test_name_only_is_low(self):
        ev = stock5.Evidence("haproxy-custom")
        m = stock5.match_source(ev, INDEX)
        self.assertEqual((m["integration"], m["method"], m["confidence"]), ("haproxy", "name", "low"))
        # the first word of a title, when no other integration starts with it
        m = stock5.match_source(stock5.Evidence("json-events eset"), INDEX)
        self.assertEqual((m["integration"], m["confidence"]), ("eset-protect", "low"))
        self.assertIsNone(stock5.match_source(stock5.Evidence("cisco-router"), INDEX))
        # a generic integration is never matched by name
        self.assertIsNone(stock5.match_source(stock5.Evidence("windows-defender"), INDEX))


class WindowsVerdictTest(unittest.TestCase):
    def setUp(self):
        self.res, self.sec = _section({"w.xml": SYSMON_RULES})

    def test_source(self):
        s = _source(self.sec, "windows:sysmon")
        self.assertEqual((s["integration"], s["method"], s["dataset"]), ("windows", "windows-pack", "sysmon"))

    def test_mitre_and_event_code_match(self):
        row = _verdict(self.sec, "rule:300400")
        self.assertEqual(row["verdict"], stock5.V_CANDIDATE)
        self.assertIn("T1033", row["why"])
        self.assertIn("event code 1", row["why"])

    def test_mitre_without_stock_rule(self):
        self.assertEqual(_verdict(self.sec, "rule:300401")["verdict"], stock5.V_NO_CANDIDATE)

    def test_no_mitre(self):
        self.assertEqual(_verdict(self.sec, "rule:300402")["verdict"], stock5.V_NOT_COMPARABLE)

    def test_windows_without_event_id(self):
        row = _verdict(self.sec, "rule:300404")
        self.assertEqual(row["verdict"], stock5.V_NOT_COMPARABLE)
        self.assertIn("no known event id", row["why"])

    def test_technique_from_description(self):
        row = _verdict(self.sec, "rule:300403")
        self.assertIn("description", row["why"])

    def test_report_section(self):
        md = render(self.res["report"])
        self.assertIn("## 5.x stock for your sources", md)
        self.assertIn("offset 1497", md)
        self.assertIn("confirm it with the live coverage command", md)
        self.assertIn("### Gap list", md)
        self.assertEqual(sum(self.sec["by_verdict"].values()), self.sec["rules"])
        json.dumps(self.res["report"]["stock5"], sort_keys=True)


class TuningTest(unittest.TestCase):
    def test_level_zero_silencer(self):
        rules = rules_xml("auditd,", """
  <rule id="200110" level="3">
    <decoded_as>auditd-execve</decoded_as>
    <description>Auditd execve.</description>
  </rule>
  <rule id="200112" level="0">
    <if_sid>200110</if_sid>
    <field name="audit.execve.a0">ls</field>
    <description>Ignore ls.</description>
  </rule>
""")
        _res, sec = _section({"a.xml": rules}, {"a.xml": AUDITD_DEC})
        self.assertEqual(_verdict(sec, "rule:200112")["verdict"], stock5.V_TUNING)


if __name__ == "__main__":
    unittest.main()
