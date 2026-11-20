"""win.* values: 4.x keeps two backslashes per path separator, 5.x stores one.

Evidence of the 4.x form: the stock 4.14 Sysmon rules write four backslashes in PCRE2 (two literal backslashes)
for one separator, and custom rules written against real 4.x alerts do the same (the two synthetic rules below
follow that form). The 5.x form is replayed from recorded Windows events (data/windows-recorded-values.json).
"""

import json
import os
import re
import unittest

import helpers  # noqa: F401  (puts the tool on sys.path)
from rmig.translate.patterns import collapse_doubled_backslash
from test_windows_pack import detection, translate

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "data", "windows-recorded-values.json"), encoding="utf-8") as _f:
    REC = json.load(_f)["values"]

# Synthetic custom rules in the doubled-backslash form of 4.x.
RULES = r"""
  <rule id="100701" level="10">
    <if_sid>61615</if_sid>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)^HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\SpecialAccounts\\\\Userlist\\\\[^\\]+$</field>
    <description>Registry value set under the hidden accounts key</description>
  </rule>
  <rule id="100702" level="12">
    <if_group>sysmon_event_11</if_group>
    <field name="win.eventdata.TargetFilename">\\\\AppData\\\\Local\\\\Temp\\\\comctl32.dll</field>
    <description>DLL written to a user temporary folder</description>
  </rule>
"""


def re_values(det, field):
    out = []

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k == field + "|re":
                    out.extend(v if isinstance(v, list) else [v])
                else:
                    walk(v)
        elif isinstance(o, list):
            for x in o:
                walk(x)
    walk(det)
    return out


class TestCollapse(unittest.TestCase):
    def test_pairs_become_one(self):
        self.assertEqual(collapse_doubled_backslash("pcre2", r"a\\\\b"), r"a\\b")
        self.assertEqual(collapse_doubled_backslash("osregex", r"a\\\\b\\\\\\\\c"), r"a\\b\\\\c")
        self.assertEqual(collapse_doubled_backslash("osmatch", "a\\\\b"), "a\\b")

    def test_single_and_class_are_kept(self):
        self.assertEqual(collapse_doubled_backslash("pcre2", r"\\csc\.exe"), r"\\csc\.exe")
        self.assertEqual(collapse_doubled_backslash("pcre2", r"[^\\]+$"), r"[^\\]+$")
        self.assertEqual(collapse_doubled_backslash("pcre2", r"\d+\s"), r"\d+\s")


class TestRecordedValues(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = translate(RULES)

    def test_100701_matches_the_recorded_registry_path(self):
        value = REC["registry.path"]["value"]
        self.assertEqual(value.count("\\"), 8)  # one backslash per separator in 5.x
        pats = re_values(detection(self.res, "100701"), "registry.path")
        self.assertTrue(pats)
        # the detector reads |re as a whole-term regexp
        self.assertTrue(any(re.fullmatch(p, value) for p in pats), pats)

    def test_100702_matches_the_recorded_file_path(self):
        value = REC["file.path"]["value"]
        pats = re_values(detection(self.res, "100702"), "file.path")
        self.assertTrue(pats)
        self.assertTrue(any(re.fullmatch(p, value) for p in pats), pats)

    def test_field_mapped_by_decisions_is_collapsed_too(self):
        # a win.* field mapped in decisions.json skips the pack and goes to the generic field translation
        from rmig import decisions as D
        dec = D.empty()
        dec["fields"]["win.eventdata.targetObject"] = {"action": "map", "wcs": "registry.path"}
        res = translate(RULES, dec)
        value = REC["registry.path"]["value"]
        pats = re_values(detection(res, "100701"), "registry.path")
        self.assertTrue(pats)
        self.assertTrue(any(re.fullmatch(p, value) for p in pats), pats)

    def test_4x_form_still_matched_the_4x_value(self):
        # the 4.x pattern matches the doubled form, not the single one: the collapse is needed
        pat = r"(?i)^HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\SpecialAccounts\\\\Userlist\\\\[^\\]+$"
        value = REC["registry.path"]["value"]
        self.assertIsNone(re.search(pat, value))
        self.assertIsNotNone(re.search(pat, value.replace("\\", "\\\\")))


if __name__ == "__main__":
    unittest.main()
