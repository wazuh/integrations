"""Feeds : roots tied to their events by <location>, <field> or the stock JSON decoder."""

import json
import unittest

from helpers import codes, etc_tree, one, rules_xml

from rmig import decisions as D
from rmig import emit
from rmig.decisions import DecisionsError
from rmig.feeds import JSON_GATE, JSON_VAR, json_path
from rmig.scan import scan
from rmig.translate import pipeline

# Synthetic Office 365 rules on the 4.x module location.
OFFICE = rules_xml("office365,", """
  <rule id="150100" level="3">
    <location>office_365</location>
    <description>Office 365 operation.</description>
  </rule>
  <rule id="150101" level="5">
    <if_sid>150100</if_sid>
    <field name="office_365.Operation">^UserLoggedIn$</field>
    <description>Office 365 login.</description>
  </rule>
""")

# Synthetic rules over a JSON antivirus feed.
AVX = rules_xml("avx,", """
  <rule id="470010" level="3">
    <decoded_as>json</decoded_as>
    <field name="avx.vendorName">^AVX$</field>
    <description>Antivirus console event.</description>
  </rule>
  <rule id="470020" level="5">
    <if_sid>470010</if_sid>
    <field name="avx.category">^DETECTION_MALWARE$</field>
    <srcip>!10.0.0.0/8</srcip>
    <description>Antivirus detection.</description>
  </rule>
""")

OTHER = rules_xml("other,", """
  <rule id="430000" level="3">
    <field name="integration">^virustotal$</field>
    <description>VirusTotal event.</description>
  </rule>
  <rule id="430100" level="3"><match>only text</match><description>no source</description></rule>
  <rule id="430200" level="3"><field name="win.eventdata.targetObject">x</field><description>windows</description></rule>
  <rule id="430300" level="3"><decoded_as>json</decoded_as><field name="Event ID">4688</field><description>key with a space</description></rule>
""")


def _run(rules, decisions=None, helpers="5.0"):
    tree = etc_tree(rules=rules)
    try:
        inv = scan(tree.root)
        return pipeline.compute(inv, decisions if decisions is not None else D.empty(), source=tree.root,
                                engine_helpers=helpers)
    finally:
        tree.cleanup()


def _decisions(**sections):
    d = D.empty()
    for k, v in sections.items():
        d[k] = v
    return D.validate(d)


def _decoder(pkg, key, name):
    for doc in pkg.integrations[key]["decoders"]:
        if doc["resource"]["name"] == name:
            return doc
    raise AssertionError("no decoder %s in %s" % (name, key))


class TestLocationFeed(unittest.TestCase):
    def test_root_is_a_feed_not_a_recipe(self):
        res = _run({"office.xml": OFFICE})
        root = one(res, "rule:150100")
        self.assertEqual(root["state"], "AUTO")
        self.assertEqual(root["fidelity"], "approximate")
        self.assertTrue({"RM-R-FEED", "RM-R-FEED-LOCATION", "RM-D-FEED-JSON"} <= codes(root))
        self.assertNotIn("RM-R-NO-SOURCE", codes(root))
        child = one(res, "rule:150101")
        # on feeds: the field without a WCS destination is checked in the feed decoder
        self.assertEqual(child["state"], "AUTO")
        self.assertIn("RM-F-DECODER-CHECK", codes(child))
        self.assertEqual(codes(child) & {"RM-F-UNMAPPED", "RM-R-NO-SOURCE"}, set())
        entry = res["decisions"]["feeds"]["150100"]
        self.assertEqual(entry["integration"], "office_365")
        self.assertEqual(entry["kind"], "location")
        self.assertFalse(entry["selector_needed"])
        self.assertEqual(entry["default_selector"], "regex_match($wazuh.protocol.location, '(?i)office_365')")
        self.assertEqual(sorted(entry["used_by"]), ["rule:150100", "rule:150101"])
        self.assertEqual(res["report"]["actions"][0]["pending"]["feeds"], [])

    def test_generated_decoder_and_rule(self):
        dec = _decisions(fields={"office_365.Operation": {"action": "map", "wcs": "event.action"}})
        res = _run({"office.xml": OFFICE}, dec)
        self.assertEqual(one(res, "rule:150101")["state"], "AUTO")
        pkg = res["package"]
        doc = _decoder(pkg, "wazuh4-office_365", "decoder/wazuh4-office_365/0")
        r = doc["resource"]
        self.assertEqual(r["parents"], [JSON_GATE])
        self.assertEqual(r["check"], "regex_match($wazuh.protocol.location, '(?i)office_365')")
        self.assertEqual(r["normalize"], [{"map": [{"_c1": "$%s.office_365.Operation" % JSON_VAR},
                                                   {"event.action": "$_c1"}]}])
        self.assertEqual(doc["fidelity"], "approximate")
        self.assertIn("RM-D-DUAL-DOCUMENT", doc["reasons"])
        self.assertIn("RM-D-DUAL-DOCUMENT", codes(one(res, "rule:150100")))
        gate = _decoder(pkg, "wazuh4-base", JSON_GATE)["resource"]
        self.assertEqual(gate["normalize"], [{"map": [{JSON_VAR: "parse_json($message)"}]}])
        self.assertIn("not_exists($process.name)", gate["check"])
        rule = pkg.integrations["wazuh4-office_365"]["rules"]["150101"]["resource"]
        sel = json.dumps(rule["detection"], sort_keys=True)
        self.assertIn('"wazuh.integration.name": "wazuh4-office_365"', sel)
        self.assertIn("wazuh.protocol.location|re", sel)
        self.assertIn('"event.action|re"', sel)
        # feeds come after every migrated decoder
        self.assertEqual(pkg.ordered_keys()[0], "wazuh4-base")

    def test_plain_location_feed_hangs_from_the_predecoder(self):
        rules = rules_xml("x,", '<rule id="100500" level="3"><location>/var/log/app.log</location>'
                                '<match>error</match><description>app error</description></rule>')
        res = _run({"x.xml": rules})
        item = one(res, "rule:100500")
        self.assertEqual(item["state"], "AUTO")
        self.assertNotIn("RM-D-FEED-JSON", codes(item))
        pkg = res["package"]
        key = "wazuh4-var-log-app-log"
        r = _decoder(pkg, key, "decoder/%s/0" % key)["resource"]
        self.assertEqual(r["parents"], ["decoder/wazuh4-predecoder/0"])
        # no JSON fields: only the label block of the location pattern (no exact detector form)
        self.assertEqual([list(b) for b in r["normalize"]], [["check", "map"]])
        names = [d["resource"]["name"] for d in pkg.integrations["wazuh4-base"]["decoders"]]
        self.assertNotIn(JSON_GATE, names)


class TestJsonFeed(unittest.TestCase):
    def test_no_stock_question_for_the_json_decoder(self):
        res = _run({"avx.xml": AVX})
        self.assertNotIn("decoder:json", res["decisions"]["stock"])
        for ref in ("rule:470010", "rule:470020"):
            item = one(res, ref)
            self.assertNotIn("RM-S-NO-EQUIVALENT", codes(item), ref)
            self.assertIn("RM-D-FEED-JSON", codes(item), ref)
        entry = res["decisions"]["feeds"]["470010"]
        # informational: the derived check of the catch-all JSON feed (its first <field> key)
        self.assertEqual((entry["integration"], entry["kind"], entry["default_selector"]),
                         ("json-events", "json", "exists($_wazuh4_json.avx.vendorName)"))
        self.assertIsNone(entry["selector"])
        self.assertEqual(sorted(res["decisions"]["fields"]), ["avx.category", "avx.vendorName"])

    def test_json_keys_are_decoder_fields(self):
        dec = _decisions(fields={"avx.vendorName": {"action": "map", "wcs": "observer.vendor"},
                                 "avx.category": {"action": "map", "wcs": "event.category"}})
        res = _run({"avx.xml": AVX}, dec)
        self.assertEqual(one(res, "rule:470020")["state"], "AUTO")
        pkg = res["package"]
        r = _decoder(pkg, "wazuh4-json-events", "decoder/wazuh4-json-events/0")["resource"]
        # the feed with no selector checks the first positive <field> of its root (fix A)
        self.assertEqual(r["check"], "exists($_wazuh4_json.avx.vendorName)")
        self.assertEqual(r["parents"], [JSON_GATE])
        m = r["normalize"][0]["map"]
        self.assertEqual(m[:3], [{"_c1": "$_wazuh4_json.avx.category"}, {"_c2": "$_wazuh4_json.avx.vendorName"},
                                 {"_c3": "$_wazuh4_json.srcip"}])
        self.assertIn({"source.ip": "parse_ip($_c3)"}, m)
        # contract: the feed exposes its fields as field_exprs, keyed by the lower-cased 4.x name
        feed = res["classifier"].translation.feeds["feed:json-events"]
        self.assertEqual(feed.field_exprs["avx.vendorname"], ["$_wazuh4_json.avx.vendorName"])

    def test_decided_stock_json_keeps_the_old_route(self):
        dec = _decisions(stock={"decoder:json": {"integration": "avx"}})
        res = _run({"avx.xml": AVX}, dec)
        item = one(res, "rule:470010")
        self.assertEqual(item["source"]["kind"], "stock")
        self.assertNotIn("RM-R-FEED", codes(item))
        self.assertNotIn("feeds", res["decisions"])

    def test_field_only_root_joins_the_json_feed(self):
        res = _run({"other.xml": OTHER})
        item = one(res, "rule:430000")
        self.assertIn("RM-R-FEED", codes(item))
        self.assertIn("fields assumed", json.dumps(item["codes"]))
        self.assertEqual(res["decisions"]["feeds"]["430000"]["kind"], "field")

    def test_not_feeds(self):
        res = _run({"other.xml": OTHER})
        for ref in ("rule:430100", "rule:430200"):
            self.assertIn("RM-R-NO-SOURCE", codes(one(res, ref)), ref)
            self.assertNotIn(ref.split(":")[1], res["decisions"]["feeds"])

    def test_key_that_is_not_a_path(self):
        res = _run({"other.xml": OTHER})
        item = one(res, "rule:430300")
        self.assertEqual(item["state"], "RECIPE")
        self.assertIn("RM-F-JSON-PATH", codes(item))
        self.assertIsNone(json_path("Event ID"))
        self.assertEqual(json_path("a.b-c.d_e"), "$_wazuh4_json.a.b-c.d_e")


class TestFeedFieldChecks(unittest.TestCase):
    """On feeds: undecided fields of feed rules run in the feed decoder."""

    def _labels(self, normalize, tag):
        return [b for b in normalize if any(tag in json.dumps(v) for v in b.get("map", []))]

    def test_location_feed_condition_in_feed_decoder(self):
        res = _run({"office.xml": OFFICE})
        self.assertEqual(one(res, "rule:150101")["state"], "AUTO")
        self.assertFalse(res["decisions"]["fields"]["office_365.Operation"]["required"])
        self.assertEqual(res["report"]["actions"][0]["pending"]["fields"], [])
        pkg = res["package"]
        r = _decoder(pkg, "wazuh4-office_365", "decoder/wazuh4-office_365/0")["resource"]
        tag = "wazuh4.rule.150101.c1"
        self.assertIn({"map": [{"_wazuh4_rule_150101_c1": "$_wazuh4_json.office_365.Operation"}]}, r["normalize"])
        self.assertIn({"check": "regex_match($_wazuh4_rule_150101_c1, '(?i)^UserLoggedIn$')",
                       "map": [{"tags": "array_append_unique('%s')" % tag}]}, r["normalize"])
        rule = pkg.integrations["wazuh4-office_365"]["rules"]["150101"]["resource"]
        self.assertIn('"tags": "%s"' % tag, json.dumps(rule["detection"], sort_keys=True))

    def test_json_feed_conditions_in_feed_decoder(self):
        res = _run({"avx.xml": AVX})
        for ref in ("rule:470010", "rule:470020"):
            item = one(res, ref)
            self.assertEqual(item["state"], "AUTO", ref)
            self.assertIn("RM-F-DECODER-CHECK", codes(item), ref)
        pkg = res["package"]
        r = _decoder(pkg, "wazuh4-json-events", "decoder/wazuh4-json-events/0")["resource"]
        self.assertEqual(r["check"], "exists($_wazuh4_json.avx.vendorName)")
        checks = [b["check"] for b in r["normalize"] if "check" in b]
        self.assertIn("regex_match($_wazuh4_rule_470010_c1, '(?i)^AVX$')", checks)
        self.assertIn("regex_match($_wazuh4_rule_470020_c2, '(?i)^DETECTION_MALWARE$')", checks)
        # the temporaries are filled before the checks that read them
        names = [list(b["map"][0])[0] for b in r["normalize"] if "check" not in b and b.get("map")]
        self.assertIn("_wazuh4_rule_470020_c2", names)

    def test_root_without_positive_field_keeps_the_catch_all(self):
        rules = rules_xml("j,", """
  <rule id="440000" level="3"><decoded_as>json</decoded_as><match>alert</match><description>any JSON</description></rule>
  <rule id="440001" level="3"><decoded_as>json</decoded_as><field name="app.kind">^x$</field><description>app</description></rule>
""")
        res = _run({"j.xml": rules})
        r = _decoder(res["package"], "wazuh4-json-events", "decoder/wazuh4-json-events/0")["resource"]
        self.assertNotIn("check", r)
        self.assertIn("every JSON event", json.dumps(one(res, "rule:440000")["codes"]))

    def test_negated_first_field_is_the_probe(self):
        # 4.x never matches a missing field, negate included
        rules = rules_xml("j,", """
  <rule id="440100" level="3"><decoded_as>json</decoded_as><field name="a.b" negate="yes">x</field><field name="c">^y$</field><description>app</description></rule>
""")
        res = _run({"j.xml": rules})
        r = _decoder(res["package"], "wazuh4-json-events", "decoder/wazuh4-json-events/0")["resource"]
        self.assertEqual(r["check"], "exists($_wazuh4_json.a.b)")


class TestFeedDecisions(unittest.TestCase):
    def test_second_feed_without_selector_is_a_decision(self):
        dec = _decisions(feeds={"430000": {"integration": "virustotal", "category": "security", "selector": None}})
        res = _run({"avx.xml": AVX, "other.xml": OTHER}, dec)
        item = one(res, "rule:430000")
        self.assertEqual(item["state"], "DECISION")
        self.assertIn("RM-R-FEED-NO-SELECTOR", codes(item))
        self.assertEqual(res["report"]["actions"][0]["pending"]["feeds"], ["430000"])
        self.assertTrue(res["decisions"]["feeds"]["430000"]["selector_needed"])

    def test_selector_written_by_the_user(self):
        check = "$%s.integration == 'virustotal'" % JSON_VAR
        dec = _decisions(feeds={"430000": {"integration": "virustotal", "category": "security", "selector": check}},
                         fields={"integration": {"action": "map", "wcs": "event.provider"},
                                 "avx.vendorName": {"action": "map", "wcs": "observer.vendor"},
                                 "avx.category": {"action": "map", "wcs": "event.category"}})
        res = _run({"avx.xml": AVX, "other.xml": OTHER}, dec)
        item = one(res, "rule:430000")
        self.assertEqual(item["state"], "AUTO")
        pkg = res["package"]
        r = _decoder(pkg, "wazuh4-virustotal", "decoder/wazuh4-virustotal/0")["resource"]
        self.assertEqual(r["check"], check)
        self.assertEqual(pkg.integrations["wazuh4-virustotal"]["doc"]["resource"]["category"], "security")
        self.assertFalse(res["decisions"]["feeds"]["430000"]["selector_needed"])
        # the feed with a selector is tried before the one that takes every JSON event
        keys = pkg.ordered_keys()
        self.assertLess(keys.index("wazuh4-virustotal"), keys.index("wazuh4-json-events"))

    def test_user_name_that_collides_is_prefixed(self):
        dec = _decisions(feeds={"430000": {"integration": "json", "category": "other", "selector": None}})
        res = _run({"other.xml": OTHER}, dec)
        self.assertIn("feed-json", one(res, "rule:430000")["integration"])

    def test_validation(self):
        bad = D.empty()
        bad["feeds"] = {"1": {"integration": "Bad Name", "category": "other"}}
        with self.assertRaises(DecisionsError):
            D.validate(bad)
        bad["feeds"] = {"1": {"integration": "ok", "category": "nope"}}
        with self.assertRaises(DecisionsError):
            D.validate(bad)
        bad["feeds"] = {"1": {"integration": "ok", "category": "other", "selector": ""}}
        with self.assertRaises(DecisionsError):
            D.validate(bad)

    def test_no_feeds_section_without_feeds(self):
        merged = D.merge(D.load("does-not-exist.json"), {"fields": {}, "integrations": {}, "stock": {}, "feeds": {}})
        self.assertEqual(list(merged), ["version", "fields", "integrations", "stock"])

    def test_determinism(self):
        a = emit.render(_run({"office.xml": OFFICE, "avx.xml": AVX})["package"], scan_inv())
        b = emit.render(_run({"office.xml": OFFICE, "avx.xml": AVX})["package"], scan_inv())
        self.assertEqual(a, b)

    def test_rc1_dialect(self):
        res = _run({"office.xml": OFFICE}, helpers="5.0-rc1")
        self.assertEqual(one(res, "rule:150100")["state"], "AUTO")
        self.assertEqual(res["package"].helper_problems, [])


def scan_inv():
    return {"source": {"name": "test"}}


if __name__ == "__main__":
    unittest.main()


class TestReviewFixes(unittest.TestCase):
    def test_negated_field_is_a_probe(self):
        # 4.x rules.c: FindField returns NULL for a missing field and the rule fails, negate included
        rules = rules_xml("x,", """
  <rule id="440000" level="3"><decoded_as>json</decoded_as>
    <field name="app.mode" negate="yes">^test$</field><field name="app.kind">^login$</field>
    <description>negated first</description></rule>
""")
        res = _run({"x.xml": rules})
        r = _decoder(res["package"], "wazuh4-json-events", "decoder/wazuh4-json-events/0")["resource"]
        self.assertEqual(r["check"], "exists($_wazuh4_json.app.mode)")
        entry = res["decisions"]["feeds"]["440000"]
        self.assertEqual(entry["default_selector"], "exists($_wazuh4_json.app.mode)")
        self.assertIsNone(entry["selector"])
        self.assertFalse(entry["selector_needed"])

    def test_user_element_on_a_json_feed_reads_the_user_key(self):
        # 4.x json_decoder.c fillData: the key "user" fills dstuser; <user> reads dstuser, else srcuser
        rules = rules_xml("x,", """
  <rule id="440100" level="3"><decoded_as>json</decoded_as><field name="app.kind">^login$</field>
    <description>root</description></rule>
  <rule id="440101" level="5"><if_sid>440100</if_sid><user>^bob$</user><description>user</description></rule>
""")
        res = _run({"x.xml": rules})
        self.assertEqual(one(res, "rule:440101")["state"], "AUTO")
        r = _decoder(res["package"], "wazuh4-json-events", "decoder/wazuh4-json-events/0")["resource"]
        m = r["normalize"][0]["map"]
        temp = [list(x)[0] for x in m if list(x.values())[0] == "$_wazuh4_json.user"]
        self.assertEqual(len(temp), 1)
        self.assertIn({"user.name": "$%s" % temp[0]}, m)

    def test_location_feed_with_static_field_conditions_is_json(self):
        # <srcip>, <id>, <url> come from a decoder in 4.x: the feed reads them from the JSON decoder
        rules = rules_xml("x,", """
  <rule id="440200" level="3"><location>/var/log/app.log</location><description>root</description></rule>
  <rule id="440201" level="5"><if_sid>440200</if_sid><srcip>10.0.0.1</srcip><description>srcip</description></rule>
  <rule id="440202" level="5"><if_sid>440200</if_sid><id>^42$</id><description>id</description></rule>
""")
        res = _run({"x.xml": rules})
        for ref in ("rule:440201", "rule:440202"):
            self.assertIn("RM-D-FEED-JSON", codes(one(res, ref)), ref)
        key = "wazuh4-var-log-app-log"
        r = _decoder(res["package"], key, "decoder/%s/0" % key)["resource"]
        self.assertEqual(r["parents"], [JSON_GATE])
        m = r["normalize"][0]["map"]
        self.assertIn({"source.ip": "parse_ip($_c2)"}, m)
        self.assertIn({"_c2": "$%s.srcip" % JSON_VAR}, m)
        self.assertIn({"_c1": "$%s.id" % JSON_VAR}, m)

    def test_json_gate_reads_the_prematch_as_os_regex(self):
        res = _run({"avx.xml": AVX})
        gate = _decoder(res["package"], "wazuh4-base", JSON_GATE)["resource"]
        # OS_Regex \s is a space (os_regex_compile.c), not RE2 \s
        self.assertEqual(gate["check"], "not_exists($process.name) AND regex_match($message, '(?i)^\\\\{ *?\"')")
