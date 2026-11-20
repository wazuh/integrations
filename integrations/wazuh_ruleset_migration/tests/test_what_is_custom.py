"""what is custom, and what 4.x itself discards."""

import os
import unittest

from helpers import STOCK_MINI, TempTree, codes, compute, etc_tree, items_by_ref, one, rules_xml

from rmig import fsutil

SSHD = fsutil.read_text(os.path.join(STOCK_MINI, "ruleset/rules/0095-sshd_rules.xml"))
SSHD_DEC = fsutil.read_text(os.path.join(STOCK_MINI, "ruleset/decoders/0310-ssh_decoders.xml"))
AUDIT_KEYS = fsutil.read_bytes(os.path.join(STOCK_MINI, "ruleset/lists/audit-keys"))

LOCAL = rules_xml("local,", """
  <rule id="100001" level="5">
    <if_sid>5716</if_sid>
    <srcip>1.1.1.1</srcip>
    <description>first 100001</description>
  </rule>
  <rule id="100001" level="7">
    <if_sid>5716</if_sid>
    <description>repeated id</description>
  </rule>
  <rule id="100002" level="5">
    <if_sid>5716</if_sid>
    <list field="srcip" lookup="match_key">etc/lists/undeclared</list>
    <description>list not declared</description>
  </rule>
  <rule id="100003" level="5">
    <if_sid>999999</if_sid>
    <description>parent never loaded</description>
  </rule>
  <rule id="100004" level="5">
    <if_sid>100003</if_sid>
    <description>child of a discarded rule</description>
  </rule>""")


def modified_sshd():
    old = '<rule id="5710" level="5">'
    assert old in SSHD
    return SSHD.replace(old, '<rule id="5710" level="7">')


class TestT3(unittest.TestCase):
    """etc/ with the stock lists, a modified copy of 0095-sshd_rules.xml with
    rule_exclude, and a repeated id."""

    @classmethod
    def setUpClass(cls):
        extra = ("<rule_exclude>ruleset/rules/0095-sshd_rules.xml</rule_exclude>\n"
                 "<list>etc/lists/mylist</list>")
        cls.tree = etc_tree(
            rules={"0095-sshd_rules.xml": modified_sshd(), "local_rules.xml": LOCAL},
            lists={"audit-keys": AUDIT_KEYS, "mylist": "1.2.3.4:\n", "undeclared": "a:b\n"},
            extra_ruleset=extra)
        cls.res = compute(cls.tree.root)
        cls.by_ref = items_by_ref(cls.res)

    @classmethod
    def tearDownClass(cls):
        cls.tree.cleanup()

    def test_stock_lists_are_not_applicable(self):
        item = one(self.res, "list:etc/lists/audit-keys")
        self.assertEqual(item["state"], "NOT_APPLICABLE")
        self.assertEqual(codes(item), {"RM-L-STOCK"})
        self.assertEqual(one(self.res, "list:etc/lists/mylist")["state"], "AUTO")
        und = one(self.res, "list:etc/lists/undeclared")
        self.assertEqual(codes(und), {"RM-L-MISSING"})

    def test_only_the_modified_rule_is_an_overwrite_of_stock(self):
        copy_items = [it for it in self.res["plan"]["items"] if it["file"] == "etc/rules/0095-sshd_rules.xml"]
        self.assertEqual(len(copy_items), 6)
        changed = [it for it in copy_items if "RM-R-OVERWRITE-STOCK" in codes(it)]
        self.assertEqual([it["ref"] for it in changed], ["rule:5710"])
        self.assertEqual(changed[0]["state"], "RECIPE")
        same = [it for it in copy_items if codes(it) == {"RM-R-STOCK-COPY"}]
        self.assertEqual(len(same), 5)
        self.assertTrue(all(it["state"] == "NOT_APPLICABLE" for it in same))

    def test_repeated_id(self):
        first, second = sorted(self.by_ref["rule:100001"], key=lambda it: it["line"])
        self.assertNotIn("RM-R-DUPLICATE-ID", codes(first))
        self.assertEqual(codes(second), {"RM-R-DUPLICATE-ID"})
        self.assertEqual(second["state"], "NOT_APPLICABLE")

    def test_what_4x_discards(self):
        self.assertEqual(codes(one(self.res, "rule:100002")), {"RM-L-MISSING"})
        self.assertEqual(codes(one(self.res, "rule:100003")), {"RM-R-PARENT-NOT-LOADED"})
        # NOT_APPLICABLE propagates with PARENT-NOT-LOADED: the child is not loaded either
        self.assertEqual(codes(one(self.res, "rule:100004")), {"RM-R-PARENT-NOT-LOADED"})

    def test_custom_rule_on_stock_parent(self):
        item = sorted(self.by_ref["rule:100001"], key=lambda it: it["line"])[0]
        self.assertIn("RM-S-NO-EQUIVALENT", codes(item))
        self.assertEqual(item["state"], "DECISION")
        self.assertIn("rule:5716", self.res["decisions"]["stock"])


class TestExclusionByBaseName(unittest.TestCase):
    """rule_exclude with a base name also excludes a custom file with that name
    (rules-config.c: file_in_list compares the full path or the entry name)."""

    def test_both_files_excluded(self):
        tree = etc_tree(rules={"0095-sshd_rules.xml": modified_sshd(), "local_rules.xml": LOCAL},
                        extra_ruleset="<rule_exclude>0095-sshd_rules.xml</rule_exclude>")
        try:
            res = compute(tree.root)
        finally:
            tree.cleanup()
        copy_items = [it for it in res["plan"]["items"] if it["file"] == "etc/rules/0095-sshd_rules.xml"]
        self.assertEqual(len(copy_items), 6)
        self.assertTrue(all(codes(it) == {"RM-R-FILE-SHADOWED"} for it in copy_items))
        first = sorted(items_by_ref(res)["rule:100001"], key=lambda it: it["line"])[0]
        self.assertEqual(codes(first), {"RM-R-PARENT-NOT-LOADED"})


class TestSameBaseNameWithoutExclusion(unittest.TestCase):
    """Without exclusion both files load (stock first): the copy's ids repeat."""

    def test_copy_is_ignored_as_duplicates(self):
        tree = etc_tree(rules={"0095-sshd_rules.xml": modified_sshd()})
        try:
            res = compute(tree.root)
        finally:
            tree.cleanup()
        copy_items = [it for it in res["plan"]["items"] if it["file"] == "etc/rules/0095-sshd_rules.xml"]
        self.assertEqual(len(copy_items), 6)
        self.assertTrue(all(codes(it) == {"RM-R-DUPLICATE-ID"} for it in copy_items))


class TestLoadOrder(unittest.TestCase):
    def test_custom_file_sorted_before_its_stock_parent(self):
        early = rules_xml("early,", """
  <rule id="100010" level="5"><if_sid>5716</if_sid><description>early</description></rule>""")
        tree = etc_tree(rules={"0001-early.xml": early, "local_rules.xml": rules_xml("local,", """
  <rule id="100011" level="5"><if_sid>5716</if_sid><description>late</description></rule>""")})
        try:
            res = compute(tree.root)
        finally:
            tree.cleanup()
        self.assertEqual(codes(one(res, "rule:100010")), {"RM-R-PARENT-NOT-LOADED"})
        self.assertNotIn("RM-R-PARENT-NOT-LOADED", codes(one(res, "rule:100011")))

    def test_overwrite_attribute_on_stock(self):
        tree = etc_tree(rules={"local_rules.xml": rules_xml("local,", """
  <rule id="5716" level="9" overwrite="yes"><if_sid>5700</if_sid><match>^Failed</match><description>x</description></rule>""")})
        try:
            res = compute(tree.root)
        finally:
            tree.cleanup()
        item = one(res, "rule:5716")
        self.assertIn("RM-R-OVERWRITE-STOCK", codes(item))
        self.assertEqual(item["state"], "RECIPE")


class TestDecoders(unittest.TestCase):
    def test_decoder_cases(self):
        stock_copy = SSHD_DEC[SSHD_DEC.index('<decoder name="sshd">'):]
        stock_copy = stock_copy[:stock_copy.index("</decoder>") + len("</decoder>")] + "\n"
        tree = etc_tree(decoders={
            "a_copy.xml": stock_copy,
            "b_child.xml": '<decoder name="sshd-custom">\n  <parent>sshd</parent>\n  <prematch>^Custom </prematch>\n  <regex>user (\\S+)</regex>\n  <order>srcuser</order>\n</decoder>\n',
            "c_orphan.xml": '<decoder name="orphan">\n  <parent>no-such-parent</parent>\n</decoder>\n',
        })
        try:
            res = compute(tree.root)
        finally:
            tree.cleanup()
        self.assertEqual(codes(one(res, "decoder:sshd")), {"RM-D-STOCK-COPY"})
        child = one(res, "decoder:sshd-custom")
        self.assertEqual(codes(child), {"RM-D-STOCK-PARENT", "RM-D-DUAL-DOCUMENT"})
        self.assertEqual(child["state"], "DECISION")
        self.assertEqual(codes(one(res, "decoder:orphan")), {"RM-D-PARENT-NOT-LOADED"})


class TestLooseTree(unittest.TestCase):
    def test_files_classified_by_content_and_lists_found(self):
        tree = TempTree({
            "App/app_decoders.xml": '<decoder name="app"><program_name>app</program_name></decoder>\n',
            "App/900-app.xml": rules_xml("app,", """
  <rule id="900001" level="3"><decoded_as>app</decoded_as><list field="srcip" lookup="match_key">etc/lists/badips</list><description>x</description></rule>"""),
            "App/badips": "1.2.3.4:\n10.:\n",
            "App/README.md": "nothing",
        })
        try:
            res = compute(tree.root)
        finally:
            tree.cleanup()
        self.assertEqual(res["plan"]["source"]["mode"], "loose")
        self.assertEqual(one(res, "decoder:app")["file"], "App/app_decoders.xml")
        rule = one(res, "rule:900001")
        self.assertNotIn("RM-L-MISSING", codes(rule))
        lst = one(res, "list:etc/lists/badips")
        self.assertEqual(codes(lst), {"RM-L-PREFIX-KEYS"})


class TestDefaultConf(unittest.TestCase):
    def test_conf_without_ruleset_uses_default(self):
        tree = etc_tree(conf="<ossec_config><global/></ossec_config>\n",
                        rules={"local_rules.xml": rules_xml("local,", '<rule id="100001" level="3"><if_sid>5716</if_sid><description>x</description></rule>')})
        try:
            res = compute(tree.root)
        finally:
            tree.cleanup()
        self.assertEqual(res["plan"]["ruleset"]["origin"], "default")
        self.assertNotIn("RM-R-PARENT-NOT-LOADED", codes(one(res, "rule:100001")))


if __name__ == "__main__":
    unittest.main()
