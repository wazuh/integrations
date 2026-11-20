"""malformed or unknown input is reported per item and never aborts."""

import unittest

from helpers import codes, compute, etc_tree, one, rules_xml

from rmig.parse.decoders import parse_decoders_text
from rmig.parse.rules import parse_rules_text
from rmig.parse.xmlreader import read_xml


class TestXmlReader(unittest.TestCase):
    def test_several_roots_comments_and_bare_ampersand(self):
        text = ('<!-- a <rule id="1"> in a comment & more -->\n'
                '<var name="X">a&b</var>\n<group name="g,">\n</group>\n<decoder name="d"/>\n')
        roots, variables, errors = read_xml(text)
        self.assertEqual([r.tag for r in roots], ["var", "group", "decoder"])
        self.assertEqual(variables, {"x": "a&b"})
        self.assertEqual(errors, [])

    def test_escaped_less_than_is_content(self):
        roots, _v, errors = read_xml("<prematch>\\<log>\\.+\\</log></prematch>")
        self.assertEqual(errors, [])
        self.assertEqual(roots[0].text, "\\<log>\\.+\\</log>")

    def test_entities_are_not_decoded(self):
        roots, _v, _e = read_xml("<match>a&lt;b</match>")
        self.assertEqual(roots[0].text, "a&lt;b")

    def test_unclosed_element_reported_with_line(self):
        roots, _v, errors = read_xml("<group name=\"g\">\n<rule id=\"1\">\n<match>x</match>\n</group>\n")
        self.assertTrue(errors)
        self.assertEqual(errors[0].line, 4)
        self.assertEqual(roots[0].children[0].tag, "rule")

    def test_unclosed_comment(self):
        _r, _v, errors = read_xml("<a>x</a>\n<!-- never closed\n")
        self.assertEqual(errors[0].message, "comment not closed")

    def test_variable_substitution(self):
        text = ('<var name="FREQ">8</var>\n<var name="LIST">a|b</var>\n'
                '<group name="g,"><rule id="1" level="3" frequency="$FREQ"><match>$LIST|c</match>'
                '<description>$(srcip) end$</description></rule></group>')
        roots, _v, errors = read_xml(text)
        self.assertEqual(errors, [])
        rule = roots[2].children[0]
        self.assertEqual(rule.attr("frequency"), "8")
        self.assertEqual(rule.children[0].text, "a|b|c")
        self.assertEqual(rule.children[1].text, "$(srcip) end$")

    def test_unknown_variable_is_an_error_not_a_crash(self):
        roots, _v, errors = read_xml('<var name="A">1</var><x>$NOPE here</x>')
        self.assertEqual(len(errors), 1)
        self.assertIn("NOPE", errors[0].message)
        self.assertEqual(roots[1].text, "$NOPE here")


class TestRuleParser(unittest.TestCase):
    def test_unknown_element_and_bad_attributes_do_not_stop_the_file(self):
        text = rules_xml("g,", """
  <rule id="100001" level="3" color="red">
    <match>a</match>
    <frobnicate>x</frobnicate>
    <description>one</description>
  </rule>
  <rule id="abc" level="99">
    <description>bad id and level</description>
  </rule>
  <rule id="100003" level="3">
    <description>three</description>
  </rule>""")
        rules, problems = parse_rules_text(text, "r.xml")
        self.assertEqual([r["id"] for r in rules], ["100001", "abc", "100003"])
        self.assertEqual({u["element"] for u in rules[0]["unknown"]}, {"@color", "frobnicate"})
        self.assertEqual(len(rules[1]["invalid"]), 2)
        self.assertEqual(rules[2]["unknown"] + rules[2]["invalid"], [])
        self.assertEqual(problems["errors"], [])

    def test_repeated_match_and_regex_are_concatenated(self):
        text = rules_xml("g,", """
  <rule id="1" level="3">
    <match>abc</match>
    <match type="pcre2" negate="yes">def</match>
    <regex>\\d+</regex>
    <field name="a">x</field>
    <field name="b" type="pcre2" negate="yes">y</field>
    <srcip>10.0.0.1</srcip>
    <srcip>!10.0.0.2</srcip>
    <description>d</description>
  </rule>""")
        rule = parse_rules_text(text, "r.xml")[0][0]
        match = [c for c in rule["conditions"] if c["elem"] == "match"][0]
        self.assertEqual((match["value"], match["engine"], match["negate"]), ("abcdef", "pcre2", True))
        regex = [c for c in rule["conditions"] if c["elem"] == "regex"][0]
        self.assertEqual(regex["engine"], "osregex")
        self.assertEqual([(f["name"], f["engine"], f["negate"]) for f in rule["fields"]],
                         [("a", "osregex", False), ("b", "pcre2", True)])
        ip = [c for c in rule["conditions"] if c["elem"] == "srcip"][0]
        self.assertEqual(ip["values"], ["10.0.0.1", "!10.0.0.2"])

    def test_rule_outside_group_and_unknown_root(self):
        rules, problems = parse_rules_text('<rule id="1" level="1"><description>x</description></rule>\n<foo/>\n', "r.xml")
        self.assertEqual(len(rules), 1)
        self.assertTrue(any("outside" in e["message"] for e in problems["errors"]))
        self.assertEqual(problems["unknown"], [{"line": 2, "element": "foo"}])

    def test_group_string_and_if_sid(self):
        text = rules_xml("local,syslog,", """
  <rule id="2" level="3"><if_sid>1, 5 7</if_sid><group>a,b,</group><description>x</description></rule>""")
        rule = parse_rules_text(text, "r.xml")[0][0]
        self.assertEqual(rule["group_string"], "local,syslog,a,b,")
        self.assertEqual(rule["parents"]["if_sid"], ["1", "5", "7"])


class TestDecoderParser(unittest.TestCase):
    def test_decoder_elements(self):
        text = """<decoder name="d1">
  <prematch>^a</prematch><prematch> b</prematch>
</decoder>
<decoder name="d2">
  <parent>d1</parent>
  <regex offset="after_parent">(\\w+)</regex>
  <regex>(\\d+)</regex>
  <order>x, srcip</order>
  <weird>1</weird>
</decoder>
<decoder name="d3"><parent>d1</parent><order>x</order></decoder>
"""
        decs, problems = parse_decoders_text(text, "d.xml")
        self.assertEqual(problems["errors"], [])
        self.assertEqual(decs[0]["prematch"]["value"], "^a b")
        self.assertEqual(decs[1]["regex"]["value"], "(\\w+)(\\d+)")
        self.assertEqual(decs[1]["regex"]["offset"], "after_parent")
        self.assertEqual(decs[1]["order"], ["x", "srcip"])
        self.assertEqual(decs[1]["unknown"], [{"line": 9, "element": "weird"}])
        self.assertTrue(any("without <regex>" in i["message"] for i in decs[2]["invalid"]))


class TestUnknownElementClassification(unittest.TestCase):
    def test_unknown_element_is_reported_on_the_item_only(self):
        tree = etc_tree(
            decoders={"myapp.xml": '<decoder name="myapp"><program_name>myapp</program_name></decoder>\n'},
            rules={"local_rules.xml": rules_xml("local,", """
  <rule id="100001" level="3">
    <decoded_as>myapp</decoded_as>
    <frobnicate>x</frobnicate>
    <description>one</description>
  </rule>
  <rule id="100002" level="3">
    <decoded_as>myapp</decoded_as>
    <match>ok</match>
    <description>two</description>
  </rule>""")})
        try:
            res = compute(tree.root)
        finally:
            tree.cleanup()
        bad = one(res, "rule:100001")
        self.assertIn("RM-X-UNKNOWN-ELEMENT", codes(bad))
        self.assertEqual(bad["state"], "RECIPE")
        self.assertEqual(bad["file"], "etc/rules/local_rules.xml")
        self.assertEqual(bad["line"], 3)
        good = one(res, "rule:100002")
        self.assertNotIn("RM-X-UNKNOWN-ELEMENT", codes(good))
        self.assertEqual(good["state"], "AUTO")


if __name__ == "__main__":
    unittest.main()
