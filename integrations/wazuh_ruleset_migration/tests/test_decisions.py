"""A decision changes the state; a non-WCS name is rejected; regenerating never loses nor reorders what is written."""

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest

from helpers import MYAPP_DECODER, codes, etc_tree, one, rules_xml

from rmig import cli
from rmig import decisions as D

RULES = rules_xml("local,", """
  <rule id="100100" level="5">
    <decoded_as>myapp</decoded_as>
    <field name="myapp.user">^bob$</field>
    <description>user bob</description>
  </rule>
  <rule id="100101" level="7">
    <if_sid>100100</if_sid>
    <match>sudo</match>
    <description>bob runs sudo</description>
  </rule>
  <rule id="100102" level="3">
    <if_sid>5716</if_sid>
    <description>on stock</description>
  </rule>""")


def quiet(fn, *args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = fn(*args)
    return rc, out.getvalue(), err.getvalue()


class DecisionsCase(unittest.TestCase):
    def setUp(self):
        self.tree = etc_tree(decoders={"myapp.xml": MYAPP_DECODER}, rules={"local_rules.xml": RULES})
        self.work = tempfile.mkdtemp(prefix="rmig-work-")
        rc, _o, _e = quiet(cli.main, ["scan", "--source", self.tree.root, "--workdir", self.work])
        self.assertEqual(rc, 0)
        self.dpath = os.path.join(self.work, "decisions.json")

    def tearDown(self):
        self.tree.cleanup()
        shutil.rmtree(self.work, ignore_errors=True)

    def plan(self):
        return quiet(cli.main, ["plan", "--workdir", self.work])

    def plan_items(self):
        with open(os.path.join(self.work, "work", "plan.json"), encoding="utf-8") as fh:
            return {"plan": json.load(fh)}

    def read_decisions(self):
        with open(self.dpath, encoding="utf-8") as fh:
            return json.load(fh, object_pairs_hook=dict)

    def raw(self):
        with open(self.dpath, "rb") as fh:
            return fh.read()

    def write_decisions(self, data):
        with open(self.dpath, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)


class TestCA6(DecisionsCase):
    def test_unmapped_field_then_mapped(self):
        rc, _o, _e = self.plan()
        self.assertEqual(rc, 1)  # DECISION items pending: the stock reference of 100102
        res = self.plan_items()
        rule = one(res, "rule:100100")
        # the field has no WCS field yet: the condition runs in the decoder that extracts it
        self.assertEqual(rule["state"], "AUTO")
        self.assertIn("RM-F-DECODER-CHECK", codes(rule))
        self.assertNotIn("RM-F-UNMAPPED", codes(rule))
        child = one(res, "rule:100101")
        self.assertEqual(child["state"], "AUTO")
        self.assertEqual(one(res, "decoder:myapp-fields")["state"], "AUTO")
        self.assertIn("RM-F-NOT-STORED", codes(one(res, "decoder:myapp-fields")))
        dec = self.read_decisions()
        entry = dec["fields"]["myapp.user"]
        self.assertIsNone(entry["action"])
        self.assertIsNone(entry["wcs"])
        self.assertIs(entry["required"], False)  # optional: map it to keep the value
        self.assertEqual(entry["used_by"], ["decoder:myapp-fields", "rule:100100"])
        self.assertEqual(entry["seen_in"], "etc/decoders/myapp.xml:6")
        self.assertIn("rule:5716", dec["stock"])
        self.assertEqual(dec["integrations"]["myapp"]["category"], "other")
        self.assertEqual(dec["integrations"]["myapp"]["category_source"], "default")

        dec["fields"]["myapp.user"]["action"] = "map"
        dec["fields"]["myapp.user"]["wcs"] = "user.name"
        dec["stock"]["rule:5716"]["integration"] = "openssh"
        dec["stock"]["rule:5716"]["selection"] = "event.code: 5716"
        self.write_decisions(dec)
        rc, _o, _e = self.plan()
        self.assertEqual(rc, 0)
        res = self.plan_items()
        self.assertEqual(one(res, "rule:100100")["state"], "AUTO")
        self.assertEqual(one(res, "rule:100101")["state"], "AUTO")
        self.assertNotIn("RM-F-NOT-STORED", codes(one(res, "decoder:myapp-fields")))
        self.assertNotIn("RM-F-DECODER-CHECK", codes(one(res, "rule:100100")))
        self.assertNotIn("RM-S-NO-EQUIVALENT", codes(one(res, "rule:100102")))

    def test_drop_keeps_the_check_in_the_decoder(self):
        self.plan()
        dec = self.read_decisions()
        dec["fields"]["myapp.user"]["action"] = "drop"
        self.write_decisions(dec)
        self.plan()
        res = self.plan_items()
        self.assertEqual(one(res, "rule:100100")["state"], "AUTO")
        self.assertIn("RM-F-DECODER-CHECK", codes(one(res, "rule:100100")))
        self.assertNotIn("RM-F-NOT-STORED", codes(one(res, "decoder:myapp-fields")))

    def test_non_wcs_destination_is_rejected_by_name(self):
        self.plan()
        dec = self.read_decisions()
        dec["fields"]["myapp.user"]["action"] = "map"
        dec["fields"]["myapp.user"]["wcs"] = "user.nombre"
        self.write_decisions(dec)
        before = self.raw()
        rc, _o, err = self.plan()
        self.assertEqual(rc, 2)
        self.assertIn("user.nombre", err)
        self.assertIn("myapp.user", err)
        self.assertEqual(self.raw(), before)  # nothing rewritten

    def test_invalid_category_and_action(self):
        self.plan()
        dec = self.read_decisions()
        dec["integrations"]["myapp"]["category"] = "logs"
        self.write_decisions(dec)
        rc, _o, err = self.plan()
        self.assertEqual(rc, 2)
        self.assertIn("logs", err)
        with self.assertRaises(D.DecisionsError):
            D.validate({"fields": {"x": {"action": "rename"}}})


class TestCA7(DecisionsCase):
    def test_regenerate_keeps_order_and_values(self):
        self.plan()
        dec = self.read_decisions()
        # the user writes values and reorders entries; an entry no longer used stays
        fields = {"zz.unused": {"action": "drop", "wcs": None, "used_by": [], "seen_in": "x:1", "comment": "mine"}}
        fields.update(dec["fields"])
        fields["myapp.user"]["action"] = "map"
        fields["myapp.user"]["wcs"] = "user.name"
        dec["fields"] = fields
        self.write_decisions(dec)
        # a new rule adds two fields
        with open(os.path.join(self.tree.root, "rules", "local_rules.xml"), "a", encoding="utf-8") as fh:
            fh.write(rules_xml("local,", """
  <rule id="100200" level="5">
    <decoded_as>myapp</decoded_as>
    <field name="myapp.zone">x</field>
    <field name="myapp.app">y</field>
    <description>new</description>
  </rule>"""))
        quiet(cli.main, ["scan", "--source", self.tree.root, "--workdir", self.work])
        self.plan()
        after = self.read_decisions()
        self.assertEqual(list(after["fields"]), ["zz.unused", "myapp.user", "myapp.app", "myapp.zone"])
        self.assertEqual(after["fields"]["zz.unused"]["comment"], "mine")
        self.assertEqual(after["fields"]["zz.unused"]["action"], "drop")
        self.assertEqual(after["fields"]["myapp.user"]["wcs"], "user.name")
        self.assertIsNone(after["fields"]["myapp.app"]["action"])
        # a second regeneration changes nothing
        first = self.raw()
        self.plan()
        self.assertEqual(self.raw(), first)

    def test_merge_function(self):
        existing = D.empty()
        existing["fields"]["b"] = {"action": "map", "wcs": "user.name"}
        existing["fields"]["a"] = {"action": None, "wcs": None}
        wanted = {"fields": {"c": {"action": None, "wcs": None, "used_by": ["rule:1"], "seen_in": "f:1"},
                             "a": {"action": None, "wcs": None, "used_by": ["rule:2"], "seen_in": "f:2"},
                             "0": {"action": None, "wcs": None, "used_by": [], "seen_in": "f:3"}}}
        out = D.merge(existing, wanted)
        self.assertEqual(list(out["fields"]), ["b", "a", "0", "c"])
        self.assertEqual(out["fields"]["b"]["wcs"], "user.name")
        self.assertEqual(out["fields"]["a"]["used_by"], ["rule:2"])


if __name__ == "__main__":
    unittest.main()
