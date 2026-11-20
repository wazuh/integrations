"""Tags of the emitted rules hold only [A-Za-z0-9_.-].

Security Analytics refused a detector with HTTP 500 "The query tag, wazuh4.group.MITRE ATT&amp;CK_sysmon, contains
an invalid character: [' ','[',']','{','}','(',')']" (POST /_plugins/_security_analytics/detectors, 5.0.0 rc3).
A custom group name with spaces and symbols, such as <group name="MITRE ATT&CK_sysmon">, gives such a tag.
"""

import re
import unittest

import helpers  # noqa: F401  (puts the tool on sys.path)
from rmig.quality import references as REF
from rmig.translate.meta import group_tag, groups_to_tags
from test_windows_pack import translate

SAFE = re.compile(r"^[A-Za-z0-9_.-]+$")

RULES = """
  <rule id="100700" level="10">
    <if_sid>61615</if_sid>
    <field name="win.eventdata.targetObject">Userlist</field>
    <description>registry change</description>
    <group>MITRE ATT&CK_sysmon,sysmon (event 13),</group>
  </rule>
"""


class TestGroupTag(unittest.TestCase):
    def test_normalized(self):
        self.assertEqual(group_tag("MITRE ATT&amp;CK_sysmon"), "wazuh4.group.MITRE_ATT_CK_sysmon")
        self.assertEqual(group_tag("MITRE ATT&CK_sysmon"), "wazuh4.group.MITRE_ATT_CK_sysmon")
        self.assertEqual(group_tag("a(b)[c]{d}"), "wazuh4.group.a_b__c__d_")
        self.assertEqual(group_tag("sysmon_event1"), "wazuh4.group.sysmon_event1")  # unchanged
        self.assertEqual(groups_to_tags(["x y", "x_y"])[0], ["wazuh4.group.x_y"])  # deterministic, deduplicated

    def test_emitted_tags_are_safe(self):
        res = translate(RULES)
        tags = []
        for integ in res["package"].integrations.values():
            for doc in integ["rules"].values():
                tags.extend(doc["resource"].get("tags", []))
        self.assertIn("wazuh4.group.MITRE_ATT_CK_sysmon", tags)
        self.assertIn("wazuh4.group.sysmon__event_13_", tags)
        for t in tags:
            self.assertRegex(t, SAFE)

    def test_monitor_query_uses_the_same_tag(self):
        res = translate(RULES)
        idx = REF.RuleIndex(res["package"].mapping, [], res["classifier"].stock, res["classifier"].winpack,
                            {it["id"]: [it] for it in res["classifier"].inv["rules"]})
        flags = []
        _refs, _ids, _lvl, grp, _g = REF._query_parts(idx, [], None, ["MITRE ATT&CK_sysmon"], flags)
        self.assertEqual(grp, {"terms": {"tags": ["wazuh4.group.MITRE_ATT_CK_sysmon"]}})


if __name__ == "__main__":
    unittest.main()
