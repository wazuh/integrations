"""Small fixes: PCRE-style syntax that 4.x reads as text, and the
report naming integrations whose category is the default."""

import unittest

from helpers import etc_tree, rules_xml

from rmig import decisions as D
from rmig import reasons as R
from rmig.classify import literal_syntax
from rmig.scan import scan
from rmig.translate import pipeline

DECODERS = """<decoder name="box">
  <program_name>box</program_name>
  <prematch>user.*logged</prematch>
  <regex>from ([0-9.]+) port (\\d+)</regex>
  <order>srcip, dstport</order>
</decoder>
"""
RULES = """
  <rule id="100200" level="5"><decoded_as>box</decoded_as><match>err{2}</match><description>a</description></rule>
  <rule id="100201" level="5"><decoded_as>box</decoded_as><regex>^\\d+ \\.* ok</regex><description>b</description></rule>
  <rule id="100202" level="5"><decoded_as>box</decoded_as><regex type="pcre2">[0-9]+.*ok</regex><description>c</description></rule>"""


def run(decisions=None):
    tree = etc_tree(decoders={"box.xml": DECODERS}, rules={"local_rules.xml": rules_xml("local,", RULES)})
    try:
        return pipeline.compute(scan(tree.root), decisions or D.empty(), source=tree.root)
    finally:
        tree.cleanup()


def item(res, ref):
    return [it for it in res["plan"]["items"] if it["ref"] == ref][0]


def details(it, code):
    for c in it["codes"]:
        if c["code"] == code:
            return c["details"]
    return None


class TestLiteralSyntax(unittest.TestCase):
    def test_detection(self):
        self.assertEqual(literal_syntax("osregex", "from ([0-9.]+)"), ["class [...]"])
        self.assertEqual(literal_syntax("osmatch", "user.*logged"), [".* or .+"])
        self.assertEqual(literal_syntax("osregex", "\\d{4}"), ["count {n}"])
        self.assertEqual(literal_syntax("osregex", "\\.* ok \\d+"), [])  # \\. is the OS_Regex any character
        self.assertEqual(literal_syntax("pcre2", "[0-9]+.*"), [])
        # literal brackets, as OS_Regex has no \[ escape: not a class
        self.assertEqual(literal_syntax("osregex", "[error]"), [])
        self.assertEqual(literal_syntax("osregex", "pid [(\\S+)] at"), [])
        self.assertEqual(literal_syntax("osregex", "via ([^;]+)"), ["class [...]"])

    def test_warning_codes_keep_the_state(self):
        res = run()
        dec = item(res, "decoder:box")
        self.assertEqual(dec["state"], "AUTO")
        self.assertEqual(dec["fidelity"], "approximate")
        self.assertEqual(details(dec, "RM-X-LITERAL-SYNTAX"), [
            "<prematch> 'user.*logged': .* or .+ read as text",
            "<regex> 'from ([0-9.]+) port (\\\\d+)': class [...] read as text"])
        self.assertEqual(details(item(res, "rule:100200"), "RM-X-LITERAL-SYNTAX"), ["<match> 'err{2}': count {n} read as text"])
        self.assertIsNone(details(item(res, "rule:100201"), "RM-X-LITERAL-SYNTAX"))
        self.assertIsNone(details(item(res, "rule:100202"), "RM-X-LITERAL-SYNTAX"))
        reason = R.CATALOG["RM-X-LITERAL-SYNTAX"]
        self.assertEqual((reason.state, reason.propagates, reason.fidelity), (R.AUTO, False, R.APPROXIMATE))


class TestDefaultCategory(unittest.TestCase):
    def test_report_names_the_default(self):
        res = run()
        self.assertEqual(res["report"]["build"]["default_category"],
                         [{"key": "wazuh4-box", "decoder": "box", "category": "other"}])
        self.assertIn("Category by default, from the `<type>` of the 4.x decoder: `wazuh4-box` (`other`)", res["markdown"])

    def test_user_category_is_not_reported(self):
        dec = D.empty()
        dec["integrations"]["box"] = {"category": "network-activity", "category_source": "user"}
        res = run(dec)
        self.assertEqual(res["report"]["build"]["default_category"], [])
        self.assertNotIn("Category by default", res["markdown"])


if __name__ == "__main__":
    unittest.main()
