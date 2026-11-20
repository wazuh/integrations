"""RM-D-SHADOWED-ROOT: custom root decoders that an earlier root always beats in 4.x."""

import unittest

from helpers import codes, compute, etc_tree, one, rules_xml

from rmig import reasons as R
from rmig.root_shadow import covers, likely_shadows, shadows

CODE = "RM-D-SHADOWED-ROOT"

# Synthetic router decoders: two files that each define a root on the same prematch.
RTR_1 = """<decoder name="rtr-parent">
  <prematch>system,</prematch>
</decoder>

<decoder name="rtr-login-failed">
  <parent>rtr-parent</parent>
  <prematch>login failed for</prematch>
  <regex>user (\\w+) from (\\S+) via (\\w+)</regex>
  <order>dstuser,srcip,protocol</order>
</decoder>
"""

RTR_2 = """<decoder name="rtr-system-parent">
  <prematch>system,</prematch>
</decoder>

<decoder name="rtr-filter-rule">
  <parent>rtr-system-parent</parent>
  <prematch>filter changed by</prematch>
  <regex>changed by (\\w+)</regex>
  <order>dstuser</order>
</decoder>

<decoder name="rtr-ovpn-parent">
  <prematch>ovpn,</prematch>
</decoder>
"""

RTR_RULES = rules_xml("rtr,", """
  <rule id="100100" level="3"><decoded_as>rtr-system-parent</decoded_as><match>system</match><description>system event</description></rule>
  <rule id="100101" level="5"><if_sid>100100</if_sid><match>filter changed</match><description>filter changed</description></rule>
  <rule id="100102" level="3"><decoded_as>rtr-parent</decoded_as><match>login failed</match><description>login failed</description></rule>
  <rule id="100103" level="3"><decoded_as>rtr-ovpn-parent</decoded_as><match>ovpn</match><description>ovpn event</description></rule>
  <rule id="100104" level="7"><if_sid>100100, 100103</if_sid><match>x</match><description>one live parent</description></rule>
""")


def _pair(first, second, rules=None):
    """Two custom root decoders in load order (a.xml, then b.xml)."""
    tree = etc_tree(decoders={"a.xml": first, "b.xml": second}, rules=rules or {})
    try:
        return compute(tree.root)
    finally:
        tree.cleanup()


def _root(name, prematch=None, program_name=None, pm_type=None):
    body = ""
    if program_name is not None:
        body += "  <program_name>%s</program_name>\n" % program_name
    if prematch is not None:
        t = ' type="%s"' % pm_type if pm_type else ""
        body += "  <prematch%s>%s</prematch>\n" % (t, prematch)
    return '<decoder name="%s">\n%s</decoder>\n' % (name, body)


class TestRouter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tree = etc_tree(decoders={"rtr_decoders.xml": RTR_1, "rtr_decoders_2.xml": RTR_2},
                        rules={"rtr_rules.xml": RTR_RULES})
        try:
            cls.res = compute(tree.root)
        finally:
            tree.cleanup()

    def detail(self, ref):
        it = one(self.res, ref)
        return [c["details"] for c in it["codes"] if c["code"] == CODE]

    def test_shadowed_root(self):
        it = one(self.res, "decoder:rtr-system-parent")
        self.assertIn(CODE, codes(it))
        self.assertEqual(it["state"], R.AUTO)
        self.assertEqual(it["fidelity"], R.APPROXIMATE)
        detail = self.detail("decoder:rtr-system-parent")[0][0]
        self.assertIn("rtr-parent", detail)
        self.assertIn("decoders/rtr_decoders.xml:1", detail)

    def test_children_and_rules_of_the_shadowed_root(self):
        self.assertIn(CODE, codes(one(self.res, "decoder:rtr-filter-rule")))
        for ref in ("rule:100100", "rule:100101"):
            detail = self.detail(ref)[0][0]
            self.assertIn("decoder rtr-system-parent never matches", detail, ref)
            self.assertIn("rtr-parent (etc/decoders/rtr_decoders.xml:1)", detail, ref)

    def test_winner_and_unrelated_content_are_not_flagged(self):
        for ref in ("decoder:rtr-parent", "decoder:rtr-login-failed", "decoder:rtr-ovpn-parent",
                    "rule:100102", "rule:100103"):
            self.assertNotIn(CODE, codes(one(self.res, ref)), ref)

    def test_rule_with_one_live_parent_is_not_flagged(self):
        self.assertNotIn(CODE, codes(one(self.res, "rule:100104")))


class TestPairs(unittest.TestCase):
    def flagged(self, first, second, name="b"):
        return CODE in codes(one(_pair(first, second), "decoder:%s" % name))

    def test_different_prematch(self):
        self.assertFalse(self.flagged(_root("a", "system,"), _root("b", "firewall,")))

    def test_literal_substring(self):
        self.assertTrue(self.flagged(_root("a", "darktrace"), _root("b", "darktrace_audit")))
        # the longer one first does not take the shorter one's events
        self.assertFalse(self.flagged(_root("a", "darktrace_audit"), _root("b", "darktrace")))

    def test_anchors(self):
        self.assertTrue(self.flagged(_root("a", "^app: "), _root("b", "^app: login")))
        self.assertFalse(self.flagged(_root("a", "^app: "), _root("b", "app: login")))
        self.assertTrue(self.flagged(_root("a", "app"), _root("b", "^my app$")))

    def test_case_sensitivity(self):
        # PCRE2 is case-sensitive, OS_Regex is not: the OS_Regex decoder also takes "SYSTEM,"
        self.assertFalse(self.flagged(_root("a", "system,", pm_type="pcre2"), _root("b", "system,")))
        self.assertFalse(self.flagged(_root("a", "System,", pm_type="pcre2"), _root("b", "system,", pm_type="pcre2")))
        # OS_Regex ignores case: it takes every event of the PCRE2 decoder
        self.assertTrue(self.flagged(_root("a", "SYSTEM,"), _root("b", "system, ", pm_type="pcre2")))

    def test_program_name(self):
        self.assertTrue(self.flagged(_root("a", program_name="^myapp"), _root("b", "login", program_name="^myapp")))
        self.assertFalse(self.flagged(_root("a", "login", program_name="^myapp"), _root("b", program_name="^myapp")))
        # a root without program_name is not tried for events that have one (two lists in analysisd)
        self.assertFalse(self.flagged(_root("a", "login"), _root("b", "login", program_name="^myapp")))
        # and a root with program_name is not tried for events without one
        self.assertFalse(self.flagged(_root("a", "system,", program_name="^myapp"), _root("b", "system,")))
        self.assertFalse(self.flagged(_root("a", program_name="^myapp"), _root("b", "system,")))

    def test_regex_is_not_compared(self):
        self.assertFalse(self.flagged(_root("a", "^\\d+ system"), _root("b", "^12 system,")))
        self.assertTrue(self.flagged(_root("a", "^\\d+ system"), _root("b", "^\\d+ system")))

    def test_same_name_is_not_flagged(self):
        res = _pair(_root("a", "system,"), _root("a", "system, x"))
        for it in res["plan"]["items"]:
            self.assertNotIn(CODE, codes(it), it["uid"])


class TestStockWinner(unittest.TestCase):
    def test_stock_sshd_shadows_custom(self):
        # stock: <decoder name="sshd"><program_name>^sshd</program_name></decoder>
        tree = etc_tree(decoders={"local_decoder.xml": _root("my-sshd", "Accepted", program_name="^sshd")})
        try:
            res = compute(tree.root)
        finally:
            tree.cleanup()
        it = one(res, "decoder:my-sshd")
        self.assertIn(CODE, codes(it))
        detail = [c["details"] for c in it["codes"] if c["code"] == CODE][0][0]
        self.assertIn("sshd (ruleset/decoders/0310-ssh_decoders.xml:", detail)


class TestCovers(unittest.TestCase):
    def test_covers(self):
        osr = lambda v: {"engine": "osregex", "value": v, "offset": None}  # noqa: E731
        pcre = lambda v: {"engine": "pcre2", "value": v, "offset": None}  # noqa: E731
        osm = lambda v: {"engine": "osmatch", "value": v}  # noqa: E731
        self.assertTrue(covers(None, osr("x")))
        self.assertFalse(covers(osr("x"), None))
        self.assertTrue(covers(osm("SSHD"), osm("^sshd")))
        self.assertTrue(covers(osm("sshd|ftpd"), osm("sshd")))  # "|" is an OR in OS_Match
        self.assertFalse(covers(osm("sshd"), osm("sshd|ftpd")))
        self.assertTrue(covers(osr(r"^node=\S+ type=|^type="), osr(r"^type=CONFIG_CHANGE")))  # stock auditd
        self.assertFalse(covers(osr("a|b"), osr("a|c")))
        self.assertFalse(covers(osr(r"foo\|bar"), osr(r"bar")))  # escaped bar: not split
        self.assertTrue(covers(pcre(":"), osr("a:b")))      # no letters: case does not matter
        self.assertFalse(covers(pcre("a.b"), pcre("a.b x")))  # "." is a metacharacter in PCRE2
        self.assertFalse(covers(pcre("end$"), osr("the end$")))  # "$" differs between engines
        self.assertTrue(covers(osr("end$"), osr("the end$")))

    def test_shadows_needs_a_selector(self):
        self.assertFalse(shadows({"program_name": None, "prematch": None}, {"program_name": None, "prematch": {"engine": "osregex", "value": "x"}}))


if __name__ == "__main__":
    unittest.main()


# Oracle 4.14.10: custom auditd rules 200110-200114 and fortigate rules 100010+ never fired, because the stock
# auditd and fortigate-firewall-v5 roots are tried first.
AUDITD_CUSTOM = """<decoder name="my-auditd-execve">
  <prematch>^type=EXECVE</prematch>
</decoder>
"""
FORTIGATE_CUSTOM = r"""<decoder name="my-fortigate">
  <prematch type="pcre2">^date=\d{4}-\d{2}-\d{2}\s+time=\S+\s+devname="[^"]*"\s+devid="[^"]*"</prematch>
</decoder>
"""
STOCK_RULES = rules_xml("local,", """
  <rule id="100200" level="5"><decoded_as>my-auditd-execve</decoded_as><description>execve</description></rule>
  <rule id="100201" level="5"><decoded_as>my-fortigate</decoded_as><description>fortigate</description></rule>
  <rule id="100202" level="7"><if_sid>100201</if_sid><match>deny</match><description>fortigate deny</description></rule>
""")


class TestStockOracleShadows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tree = etc_tree(decoders={"a.xml": AUDITD_CUSTOM, "b.xml": FORTIGATE_CUSTOM}, rules={"r.xml": STOCK_RULES})
        try:
            cls.res = compute(tree.root)
        finally:
            tree.cleanup()

    def detail(self, ref, code):
        it = one(self.res, ref)
        return [c["details"] for c in it["codes"] if c["code"] == code]

    def test_auditd_is_proven(self):
        self.assertIn("auditd (ruleset/decoders/0040-auditd_decoders.xml:", self.detail("decoder:my-auditd-execve", CODE)[0][0])
        self.assertTrue(self.detail("rule:100200", CODE))

    def test_fortigate_is_likely(self):
        likely = "RM-D-SHADOWED-LIKELY"
        self.assertEqual(self.detail("decoder:my-fortigate", CODE), [])
        self.assertIn("fortigate-firewall-v5", self.detail("decoder:my-fortigate", likely)[0][0])
        self.assertTrue(self.detail("rule:100201", likely))
        self.assertTrue(self.detail("rule:100202", likely))  # through its parent rule

    def test_decoder_exclude_removes_the_stock_winner(self):
        tree = etc_tree(decoders={"b.xml": FORTIGATE_CUSTOM}, rules={"r.xml": STOCK_RULES},
                        extra_ruleset="<decoder_exclude>0100-fortigate_decoders.xml</decoder_exclude>")
        try:
            res = compute(tree.root)
        finally:
            tree.cleanup()
        it = one(res, "decoder:my-fortigate")
        self.assertNotIn("RM-D-SHADOWED-LIKELY", codes(it))

    def test_likely_needs_every_run_in_order(self):
        osr = lambda v: {"engine": "osregex", "value": v, "offset": None}  # noqa: E731
        a = {"program_name": None, "prematch": osr(r"date=\S+\.+time=\.+devname=\S+\.+devid=\p*FG")}
        b = lambda v: {"program_name": None, "prematch": osr(v)}  # noqa: E731
        self.assertTrue(likely_shadows(a, b(r"^date=\S+ time=\S+ devname=x devid=y")))
        self.assertFalse(likely_shadows(a, b(r"^date=\S+ devname=x time=\S+ devid=y")))  # order
        self.assertFalse(likely_shadows(a, b(r"^date=\S+ time=\S+ devid=y")))  # devname missing
        self.assertFalse(likely_shadows({"program_name": None, "prematch": osr(r"^\d+ x")}, b(r"^12 x")))  # no runs
