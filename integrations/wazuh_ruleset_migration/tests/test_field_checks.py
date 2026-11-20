"""A custom field without a WCS field does not block: the rule
condition runs in the leaf decoder that extracts the field and sets a tag; the
rule matches the tag. Field names ignore letter case as in 4.x."""

import json
import unittest

from helpers import etc_tree, rules_xml

from rmig import decisions as D
from rmig.scan import scan
from rmig.translate import pipeline

DECODERS = """<decoder name="app">
  <program_name>app</program_name>
</decoder>
<decoder name="app-login">
  <parent>app</parent>
  <prematch>^login </prematch>
  <regex offset="after_prematch">^user=(\\S+) state=(\\w+)</regex>
  <order>user, app.state</order>
</decoder>
<decoder name="app-logout">
  <parent>app</parent>
  <prematch>^logout </prematch>
  <regex offset="after_prematch">^state=(\\w+)</regex>
  <order>app.state</order>
</decoder>
<decoder name="app-other">
  <parent>app</parent>
  <prematch>^other </prematch>
  <regex offset="after_prematch">^(\\w+)</regex>
  <order>app.code</order>
</decoder>
"""


def run(rules, decisions=None, decoders=DECODERS, lists=None, extra=""):
    tree = etc_tree(decoders={"app.xml": decoders}, rules={"local_rules.xml": rules_xml("local,", rules)},
                    lists=lists, extra_ruleset=extra)
    try:
        return pipeline.compute(scan(tree.root), decisions or D.empty(), source=tree.root)
    finally:
        tree.cleanup()


def item(res, ref):
    return [it for it in res["plan"]["items"] if it["ref"] == ref][0]


def codes(it):
    return {c["code"]: c["details"] for c in it["codes"]}


def decoder(res, name):
    for key in res["package"].ordered_keys():
        for doc in res["package"].integrations[key]["decoders"]:
            if doc["resource"]["name"] == "decoder/wazuh4-%s/0" % name:
                return doc["resource"]
    raise AssertionError("decoder %s not emitted" % name)


def rule(res, rid):
    for key in res["package"].ordered_keys():
        r = res["package"].integrations[key]["rules"].get(rid)
        if r:
            return r
    raise AssertionError("rule %s not emitted" % rid)


STATE_RULE = """
  <rule id="100100" level="5">
    <decoded_as>app</decoded_as>
    <field name="app.state">^fail</field>
    <description>app: $(app.state) for $(user)</description>
  </rule>"""


class TestDecoderCheck(unittest.TestCase):
    def test_condition_runs_in_each_leaf_that_extracts_it(self):
        res = run(STATE_RULE)
        r = item(res, "rule:100100")
        self.assertEqual(r["state"], "AUTO")
        self.assertEqual(r["fidelity"], "exact")
        self.assertEqual(codes(r)["RM-F-DECODER-CHECK"], ["app.state"])
        for name in ("app-login", "app-logout"):
            dec = item(res, "decoder:%s" % name)
            self.assertEqual(dec["state"], "AUTO")
            self.assertEqual(codes(dec)["RM-F-NOT-STORED"], ["app.state"])
        login = decoder(res, "app-login")["normalize"]
        extract = login[0]["map"][1]["_c2"]
        self.assertIn({"map": [{"_wazuh4_rule_100100_c1": extract}]}, login)
        self.assertIn({"check": "regex_match($_wazuh4_rule_100100_c1, '(?i)^fail')",
                       "map": [{"tags": "array_append_unique('wazuh4.rule.100100.c1')"}]}, login)
        logout = decoder(res, "app-logout")["normalize"]
        self.assertIn({"map": [{"_wazuh4_rule_100100_c1": logout[0]["map"][0]["_c1"]}]}, logout)
        # a leaf without the field and the parent get no block: 4.x never matches a missing field
        self.assertNotIn("wazuh4.rule.100100", json.dumps(decoder(res, "app-other")))
        self.assertNotIn("wazuh4.rule.100100", json.dumps(decoder(res, "app")))
        # the value is not stored, so the title keeps the 4.x field name as text
        self.assertEqual(rule(res, "100100")["resource"]["metadata"]["title"], "app: <app.state> for {{ user.name }}")
        det = rule(res, "100100")["resource"]["detection"]
        self.assertIn("wazuh4.rule.100100.c1", json.dumps(det))
        self.assertNotIn("app.state", json.dumps(det))
        dec = res["decisions"]["fields"]["app.state"]
        self.assertIsNone(dec["action"])
        self.assertIs(dec["required"], False)
        pending = res["report"]["actions"][0]["pending"]
        self.assertEqual(pending["fields"], [])
        self.assertIn("app.state", pending["not_stored"])

    def test_negate_needs_the_field(self):
        res = run("""
  <rule id="100101" level="5">
    <decoded_as>app</decoded_as>
    <field name="app.state" negate="yes">ok</field>
    <description>not ok</description>
  </rule>""")
        blocks = decoder(res, "app-login")["normalize"]
        self.assertIn({"check": "exists($_wazuh4_rule_100101_c1) AND NOT regex_match($_wazuh4_rule_100101_c1, '(?i)ok')",
                       "map": [{"tags": "array_append_unique('wazuh4.rule.100101.c1')"}]}, blocks)
        self.assertEqual(item(res, "rule:100101")["state"], "AUTO")

    def test_pcre2_keeps_case(self):
        res = run("""
  <rule id="100102" level="5">
    <decoded_as>app</decoded_as>
    <field name="app.state" type="pcre2">^Fail$</field>
    <description>x</description>
  </rule>""")
        checks = [b.get("check") for b in decoder(res, "app-login")["normalize"]]
        self.assertIn("regex_match($_wazuh4_rule_100102_c1, '^Fail$')", checks)

    def test_drop_also_runs_in_the_decoder(self):
        dec = D.empty()
        dec["fields"]["app.state"] = {"action": "drop", "wcs": None}
        res = run(STATE_RULE, dec)
        self.assertEqual(item(res, "rule:100100")["state"], "AUTO")
        self.assertNotIn("RM-F-NOT-STORED", codes(item(res, "decoder:app-login")))

    def test_mapped_field_is_unchanged(self):
        dec = D.empty()
        dec["fields"]["app.state"] = {"action": "map", "wcs": "event.reason"}
        res = run(STATE_RULE, dec)
        r = item(res, "rule:100100")
        self.assertNotIn("RM-F-DECODER-CHECK", codes(r))
        self.assertNotIn("_wazuh4_rule_100100", json.dumps(decoder(res, "app-login")))
        self.assertIn("event.reason", json.dumps(rule(res, "100100")["resource"]["detection"]))

    def test_same_bytes_twice(self):
        a = run(STATE_RULE)
        b = run(STATE_RULE)
        self.assertEqual(json.dumps(decoder(a, "app-login"), sort_keys=True),
                         json.dumps(decoder(b, "app-login"), sort_keys=True))


class TestFallback(unittest.TestCase):
    def test_no_leaf_extracts_it(self):
        res = run("""
  <rule id="100110" level="5">
    <decoded_as>app</decoded_as>
    <field name="app.missing">x</field>
    <description>x</description>
  </rule>""")
        r = item(res, "rule:100110")
        self.assertEqual(r["state"], "DECISION")
        self.assertEqual(codes(r)["RM-F-UNMAPPED"], ["app.missing (no decoder under app extracts it)"])
        self.assertIs(res["decisions"]["fields"]["app.missing"]["required"], True)
        self.assertEqual(res["report"]["actions"][0]["pending"]["fields"], ["app.missing"])

    def test_parent_with_children_does_not_count(self):
        # 4.x runs only the child's regex when the decoder has children
        decs = """<decoder name="p">
  <program_name>p</program_name>
  <regex>^(\\w+)</regex>
  <order>p.word</order>
</decoder>
<decoder name="p-child">
  <parent>p</parent>
  <prematch>^x</prematch>
</decoder>
"""
        res = run("""
  <rule id="100111" level="5"><decoded_as>p</decoded_as><field name="p.word">a</field><description>x</description></rule>""",
                  decoders=decs)
        self.assertIn("RM-F-UNMAPPED", codes(item(res, "rule:100111")))

    def test_extracted_twice_in_one_leaf(self):
        decs = DECODERS + """<decoder name="app-other">
  <parent>app</parent>
  <regex offset="after_regex">^ (\\w+)</regex>
  <order>app.code</order>
</decoder>
"""
        res = run("""
  <rule id="100112" level="5"><decoded_as>app</decoded_as><field name="app.code">a</field><description>x</description></rule>""",
                  decoders=decs)
        r = item(res, "rule:100112")
        self.assertEqual(r["state"], "DECISION")
        self.assertEqual(codes(r)["RM-F-UNMAPPED"], ["app.code (decoder app-other extracts it more than once)"])

    def test_dropped_fallback_is_recipe(self):
        dec = D.empty()
        dec["fields"]["app.missing"] = {"action": "drop", "wcs": None}
        res = run("""
  <rule id="100113" level="5"><decoded_as>app</decoded_as><field name="app.missing">x</field><description>x</description></rule>""", dec)
        self.assertEqual(item(res, "rule:100113")["state"], "RECIPE")


class TestChainsFromSiblingDecoders(unittest.TestCase):
    def test_if_sid_on_two_sibling_decoders_falls_back(self):
        res = run("""
  <rule id="100160" level="3"><decoded_as>app-login</decoded_as><match>a</match><description>a</description></rule>
  <rule id="100161" level="3"><decoded_as>app-logout</decoded_as><match>b</match><description>b</description></rule>
  <rule id="100162" level="5"><if_sid>100160, 100161</if_sid><field name="app.state">x</field><description>c</description></rule>""")
        r = item(res, "rule:100162")
        self.assertEqual(r["state"], "DECISION")
        self.assertEqual(codes(r)["RM-F-UNMAPPED"],
                         ["app.state (the chains of the rule come from decoders app-logout, app-login)"])


class TestChildrenAndSilencers(unittest.TestCase):
    def test_child_rule_carries_the_check(self):
        res = run(STATE_RULE + """
  <rule id="100120" level="7"><if_sid>100100</if_sid><match>root</match><description>child</description></rule>""")
        self.assertEqual(item(res, "rule:100120")["state"], "AUTO")
        self.assertIn("wazuh4.rule.100100.c1", json.dumps(rule(res, "100120")["resource"]["detection"]))

    def test_silencer_check_is_emitted(self):
        res = run(STATE_RULE + """
  <rule id="100121" level="0"><if_sid>100100</if_sid><field name="app.state">^failover</field><description>quiet</description></rule>""")
        self.assertEqual(item(res, "rule:100121")["state"], "AUTO")
        det = json.dumps(rule(res, "100100")["resource"]["detection"])
        self.assertIn("wazuh4.rule.100121.c1", det)
        checks = [b.get("check") for b in decoder(res, "app-login")["normalize"]]
        self.assertIn("regex_match($_wazuh4_rule_100121_c1, '(?i)^failover')", checks)


class TestListOnUnmappedField(unittest.TestCase):
    def test_lookup_reads_the_extracted_value(self):
        res = run("""
  <rule id="100130" level="5"><decoded_as>app</decoded_as>
    <list field="app.state" lookup="match_key">etc/lists/states</list><description>x</description></rule>""",
                  lists={"states": "fail:\n"}, extra="<list>etc/lists/states</list>")
        r = item(res, "rule:100130")
        self.assertEqual(r["state"], "AUTO")
        blocks = decoder(res, "app-login")["normalize"]
        self.assertIn({"check": "in_kvdb($_wazuh4_list_states, 'wazuh4-states')",
                       "map": [{"tags": "array_append_unique('wazuh4.list.states')"}]}, blocks)
        temps = [b for b in blocks if "check" not in b and "_wazuh4_list_states" in json.dumps(b)]
        self.assertEqual(len(temps), 1)

    def test_negated_lookup_needs_the_value(self):
        # 4.x rules.c RULE_DYNAMIC: a missing field never matches, not_match_key included
        res = run("""
  <rule id="100131" level="5"><decoded_as>app</decoded_as>
    <list field="app.state" lookup="not_match_key">etc/lists/states</list><description>x</description></rule>""",
                  lists={"states": "fail:\n"}, extra="<list>etc/lists/states</list>")
        self.assertEqual(item(res, "rule:100131")["state"], "AUTO")
        checks = [b["check"] for b in decoder(res, "app-login")["normalize"] if "check" in b]
        self.assertIn("exists($_wazuh4_list_states) AND not_in_kvdb($_wazuh4_list_states, 'wazuh4-states')", checks)


class TestFieldCase(unittest.TestCase):
    RULES = """
  <rule id="100140" level="5"><decoded_as>app</decoded_as><field name="APP.State">x</field><description>a</description></rule>
  <rule id="100141" level="5"><decoded_as>app</decoded_as><field name="app.STATE">y</field><description>b</description></rule>"""

    def test_one_question_for_every_spelling(self):
        res = run(self.RULES)
        fields = res["decisions"]["fields"]
        self.assertEqual([k for k in fields if k.lower() == "app.state"], ["app.state"])  # the decoder's spelling
        self.assertEqual(fields["app.state"]["used_by"],
                         ["decoder:app-login", "decoder:app-logout", "rule:100140", "rule:100141"])
        self.assertEqual(item(res, "rule:100140")["state"], "AUTO")

    def test_old_file_keyed_with_another_case(self):
        dec = D.empty()
        dec["fields"]["App.State"] = {"action": "map", "wcs": "event.reason"}
        res = run(self.RULES, dec)
        self.assertEqual([k for k in res["decisions"]["fields"] if k.lower() == "app.state"], ["App.State"])
        self.assertIn("event.reason", json.dumps(rule(res, "100141")["resource"]["detection"]))
        self.assertIn('"event.reason": "$_c2"', json.dumps(decoder(res, "app-login")))


class TestWhatIfResolvesFields(unittest.TestCase):
    def test_stock_rule_with_a_field(self):
        from rmig import cli
        tree = etc_tree(rules={"local_rules.xml": rules_xml("local,", """
  <rule id="100150" level="5"><if_sid>5716</if_sid><field name="sshd.extra">x</field><description>x</description></rule>""")})
        try:
            inv = scan(tree.root)
            rows = {r["n"]: r for r in cli.what_if(inv, D.empty())}
        finally:
            tree.cleanup()
        self.assertEqual(rows[0]["to_auto"], 0)
        # the stock entry alone would leave the rule waiting for its field (RM-F-UNMAPPED)
        self.assertEqual(rows[1]["refs"], ["rule:5716"])
        self.assertEqual(rows[1]["to_auto"], 1)


if __name__ == "__main__":
    unittest.main()
