"""Golden cases of the decoder translation, and
the base integration."""

import json
import os
import re
import unittest

from helpers import etc_tree

from rmig import decisions as D
from rmig.scan import scan
from rmig.translate import pipeline
from test_rules_golden import GoldenCase

_NAME_REF = re.compile(r"decoder/([^/'\"\s]+)/\d+")
_KVDB_REF = re.compile(r"(?:in_kvdb|not_in_kvdb)\(\$[^,]+, '([^']+)'\)|kvdb_(?:lookup|get)\('?([A-Za-z0-9_.-]+)")


def unprefixed_references(out_dir):
    """Every decoder or KVDB name referenced by an emitted decoder that does
    not start with ``wazuh4-`` (must be empty)."""
    bad = []
    integ_dir = os.path.join(out_dir, "integrations")
    for base, _dirs, files in os.walk(integ_dir):
        if not base.endswith("decoders"):
            continue
        for name in files:
            with open(os.path.join(base, name), encoding="utf-8") as fh:
                res = dict(json.load(fh)["resource"])
            res.pop("metadata", None)  # descriptive references name the stock originals
            text = json.dumps(res)
            for m in _NAME_REF.finditer(text):
                if not m.group(1).startswith("wazuh4-"):
                    bad.append("%s: %s" % (name, m.group(0)))
            for m in _KVDB_REF.finditer(text):
                kv = m.group(1) or m.group(2)
                if kv and not kv.startswith("wazuh4-"):
                    bad.append("%s: kvdb %s" % (name, kv))
    return bad


class T8Decoders(GoldenCase):
    """Children of the stock ``sshd`` in two files: one recreated parent in the
    base; prematch + regex offset composed; a dynamic field decided."""

    CASE = "t08-decoders"

    def test_one_recreated_parent_in_the_base(self):
        base = os.listdir(os.path.join(self.out, "integrations", "wazuh4-base", "decoders"))
        self.assertEqual(sorted(base), ["01-wazuh4-core-wazuh-message.json", "02-wazuh4-predecoder.json",
                                        "03-wazuh4-sshd.json"])
        parent = self.json("integrations/wazuh4-base/decoders/03-wazuh4-sshd.json")["resource"]
        self.assertEqual(parent["parents"], ["decoder/wazuh4-predecoder/0"])
        self.assertEqual(parent["check"], "regex_match($process.name, '(?i)^sshd')")
        for key in ("wazuh4-sshd-tenant", "wazuh4-sshd-banner"):
            dec = os.listdir(os.path.join(self.out, "integrations", key, "decoders"))
            self.assertEqual(len(dec), 1)
            doc = self.json("integrations/%s/decoders/%s" % (key, dec[0]))
            self.assertEqual(doc["resource"]["parents"], ["decoder/wazuh4-sshd/0"])
            self.assertIn("RM-D-DUAL-DOCUMENT", doc["reasons"])

    def test_composed_regex_and_maps(self):
        doc = self.json("integrations/wazuh4-sshd-tenant/decoders/01-wazuh4-sshd-tenant.json")["resource"]
        self.assertEqual(doc["check"], "regex_match($message, '(?i:^Accepted )')")
        maps = doc["normalize"][0]["map"]
        self.assertEqual(maps[0], {"_c1": "regex_extract($message, '(?i:^Accepted )(?i:([^ ]+?) for (?:[^ ]+?) from "
                                          "(?:[^ ]+?) tenant=(?:[-0-9@A-Z_a-z]+))')"})
        self.assertIn({"event.action": "$_c1"}, maps)
        self.assertIn({"source.ip": "parse_ip($_c3)"}, maps)
        self.assertIn({"organization.name": "$_c4"}, maps)

    def test_no_unprefixed_reference(self):
        self.assertEqual(unprefixed_references(self.out), [])

    def test_rule_on_the_child(self):
        det = self.rule("wazuh4-sshd-tenant", "100400")["resource"]["detection"]
        self.assertEqual(det["selection"]["organization.name|re"], "[Aa][Cc][Mm][Ee]")
        self.assertEqual(det["selection"]["wazuh.integration.name"], "wazuh4-sshd-tenant")


class T8Undecided(unittest.TestCase):
    """The same decoder with the dynamic field undecided is emitted without
    storing the field (RM-F-NOT-STORED); the rule checks the field in it
    (RM-F-DECODER-CHECK)."""

    def test_undecided_field_is_not_stored(self):
        src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden", "t08-decoders", "in")
        inv = scan(src)
        res = pipeline.compute(inv, D.empty(), source=src)
        states = {it["ref"]: it["state"] for it in res["plan"]["items"]}
        self.assertEqual(states["decoder:sshd-tenant"], "AUTO")
        self.assertEqual(states["decoder:sshd-banner"], "AUTO")
        self.assertEqual(states["rule:100400"], "AUTO")
        keys = res["package"].ordered_keys()
        self.assertEqual(keys, ["wazuh4-base", "wazuh4-sshd-tenant", "wazuh4-sshd-banner"])
        dec = res["package"].integrations["wazuh4-sshd-tenant"]["decoders"][0]
        self.assertIn("RM-F-NOT-STORED", dec["reasons"])
        self.assertNotIn("organization.name", json.dumps(dec["resource"]))


class T10Labels(GoldenCase):
    """Two conditions with no exact Sigma form over one integration: one
    ``normalize`` block each in the decoder of the rule and in every
    descendant, never a child decoder of their own."""

    CASE = "t10-labels"

    def test_blocks_in_the_decoder_and_its_descendant(self):
        decs = sorted(os.listdir(os.path.join(self.out, "integrations", "wazuh4-myapp", "decoders")))
        self.assertEqual(decs, ["01-wazuh4-myapp.json", "02-wazuh4-myapp-auth.json"])  # no label decoders
        for name in decs:
            res = self.json("integrations/wazuh4-myapp/decoders/%s" % name)["resource"]
            tags = [b for b in res.get("normalize", []) if "check" in b and "array_append_unique" in json.dumps(b)]
            self.assertEqual([t["map"][0]["tags"] for t in tags],
                             ["array_append_unique('wazuh4.rule.100500.c1')", "array_append_unique('wazuh4.rule.100501.c1')"])
        root = self.json("integrations/wazuh4-myapp/decoders/01-wazuh4-myapp.json")["resource"]
        self.assertIn({"check": "regex_match($message, '(?i)disk full')",
                       "map": [{"tags": "array_append_unique('wazuh4.rule.100500.c1')"}]}, root["normalize"])
        self.assertIn({"check": "regex_match($message, '(?i)quota [0-9]+?/[0-9]+')",
                       "map": [{"tags": "array_append_unique('wazuh4.rule.100501.c1')"}]}, root["normalize"])

    def test_rules_require_the_label_and_are_exact(self):
        r = self.rule("wazuh4-myapp", "100500")
        self.assertEqual(r["resource"]["detection"]["selection"]["tags"], "wazuh4.rule.100500.c1")
        self.assertEqual(r["fidelity"], "exact")

    def test_no_unprefixed_reference(self):
        self.assertEqual(unprefixed_references(self.out), [])


class TestBaseOnlyWithDecoders(unittest.TestCase):
    def test_rules_only_migration_has_no_base(self):
        tree = etc_tree(rules={"local_rules.xml": '<group name="local,">\n<rule id="100001" level="5">'
                                                  '<if_sid>5710</if_sid><description>x</description></rule>\n</group>\n'})
        try:
            dec = D.empty()
            dec["stock"]["rule:5710"] = {"integration": "system-auth", "selection": {"event.action": "authentication-failure"}}
            res = pipeline.compute(scan(tree.root), dec, source=tree.root)
        finally:
            tree.cleanup()
        pkg = res["package"]
        self.assertEqual(pkg.ordered_keys(), ["wazuh4-on-system-auth"])
        self.assertIsNone(pkg.root)


if __name__ == "__main__":
    unittest.main()
