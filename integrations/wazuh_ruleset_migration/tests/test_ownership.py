"""Ownership: same title but not ours, and foreign pending
changes, of resources or of the policy; a policy PUT changes root_decoder only)."""

import json
import os
import unittest

from rmig import reasons as R

import fake_indexer as F
from test_apply import ApiCase

from rmig.api.content import policy_differences, policy_put_body


class TestNameConflict(ApiCase):
    def test_foreign_rule_with_the_same_title(self):
        iid = self.fake.seed("integration", {"metadata": {"title": "customer-app", "author": "someone"},
                                             "category": "other"}, spaces=("draft", "test"))
        rid = self.fake.seed("rule", {"metadata": {"title": "myapp: logout", "author": "someone"}, "enabled": True,
                                      "logsource": {"product": "customer-app"}, "detection": {"x": 1}},
                             spaces=("draft", "test"), integration=iid)
        before = json.dumps(self.fake.docs["draft"]["rule"][rid], sort_keys=True)
        out = self.apply(expect=2)
        self.assertIn("myapp: logout", out)
        self.assertEqual(F.writes(self.fake), [])
        self.assertEqual(json.dumps(self.fake.docs["draft"]["rule"][rid], sort_keys=True), before)
        with open(os.path.join(self.work, "report.json")) as fh:
            stop = json.load(fh)["apply"]["stops"][0]
        self.assertEqual(stop["code"], "RM-P-NAME-CONFLICT")
        self.assertTrue(stop["doc"].startswith(R.DOC_PAGE + "#rm-p-name-conflict"))
        # rollback does not touch it either
        code, out = self.run_cmd("rollback")
        self.assertEqual(code, 0, out)
        self.assertIn(rid, self.fake.docs["draft"]["rule"])

    def test_foreign_integration_with_the_same_title(self):
        self.fake.seed("integration", {"metadata": {"title": "wazuh4-myapp", "author": "someone"},
                                       "category": "other"}, spaces=("draft",))
        self.apply(expect=2)
        self.assertEqual(F.writes(self.fake), [])

    def test_marked_resource_of_another_build_is_not_adopted(self):
        self.fake.seed("rule", {"metadata": {"title": "an old migrated rule", "author": "wazuh-ruleset-migration",
                                             "references": ["wazuh4-migration:00000000-0000-5000-8000-000000000000"]},
                                "enabled": True, "logsource": {"product": "x"}, "detection": {}},
                       spaces=("draft", "test"), foreign=True)
        self.apply()  # same in draft and test: nothing pending, only a note
        code, out = self.run_cmd("rollback")
        self.assertEqual(code, 0, out)
        self.assertEqual(len(self.fake.docs["test"]["rule"]), 1)
        with open(os.path.join(self.work, "report.json")) as fh:
            notes = json.load(fh)["apply"]["notes"]
        self.assertTrue(any("left untouched" in n for n in notes))

    def test_root_decoder_set_by_someone_else(self):
        did = self.fake.seed("decoder", {"name": "decoder/customer-root/0", "metadata": {"author": "someone"}},
                             spaces=("draft", "test"))
        self.fake.policies["draft"]["root_decoder"] = did
        self.fake.policies["test"]["root_decoder"] = did
        out = self.apply(expect=2)
        self.assertIn("root_decoder %s" % did, out)
        with open(os.path.join(self.work, "report.json")) as fh:
            self.assertEqual(json.load(fh)["apply"]["stops"][0]["code"], "RM-P-ROOT-OWNED")
        self.assertEqual(F.writes(self.fake), [])

    def test_root_owned_stop_names_the_root(self):
        iid = self.fake.seed("integration", {"metadata": {"title": "customer-app", "author": "someone"},
                                             "category": "other"}, spaces=("draft", "test"))
        did = self.fake.seed("decoder", {"name": "decoder/customer-root/0",
                                         "metadata": {"title": "Customer root", "author": "someone"}},
                             spaces=("draft", "test"), integration=iid)
        self.fake.policies["draft"]["root_decoder"] = did
        self.fake.policies["test"]["root_decoder"] = did
        out = self.apply(expect=2)
        self.assertIn("apply: stopped (RM-P-ROOT-OWNED): ", out)
        self.assertIn("root decoder: id %s, name decoder/customer-root/0, title Customer root, integration "
                      "customer-app" % did, out)
        self.assertIn("cannot share: its name is decoder/customer-root/0, not the standard "
                      "decoder/core-wazuh-message/0", out)
        self.assertIn("migrate into a policy without a custom root decoder", out)
        self.assertNotIn("--take-root", out)
        with open(os.path.join(self.work, "report.json")) as fh:
            stop = json.load(fh)["apply"]["stops"][0]
        self.assertEqual(stop["items"], ["root decoder: id %s, name decoder/customer-root/0, title Customer root, "
                                         "integration customer-app" % did])
        self.assertEqual(F.writes(self.fake), [])


class _Own:
    def __init__(self, own=(), other=()):
        self.own, self.other = set(own), set(other)

    def is_own(self, sid):
        return sid in self.own

    def is_other_tool(self, sid):
        return sid in self.other


class TestOtherWorkdirPolicy(unittest.TestCase):
    # another workdir already applied its base: the test policy has the other workdir's integration and root decoder, custom has neither
    TEST = {"integrations": ["mine", "theirs"], "root_decoder": "their-root"}
    CUSTOM = {"integrations": ["mine"], "root_decoder": ""}

    def test_other_workdir_root_and_integration_are_not_foreign_when_allowed(self):
        own = _Own(own={"mine"}, other={"theirs", "their-root"})
        self.assertEqual(policy_differences(self.TEST, self.CUSTOM, own, None, other_tool_ok=True), [])

    def test_they_still_differ_without_the_allowance(self):
        own = _Own(own={"mine"}, other={"theirs", "their-root"})
        diffs = policy_differences(self.TEST, self.CUSTOM, own, None)
        self.assertEqual(len(diffs), 2, diffs)
        self.assertTrue(any(d.startswith("root_decoder") for d in diffs))

    def test_a_root_of_someone_else_stays_foreign(self):
        own = _Own(own={"mine"}, other={"theirs"})
        diffs = policy_differences(self.TEST, self.CUSTOM, own, None, other_tool_ok=True)
        self.assertEqual(diffs, ["root_decoder: '' -> 'their-root'"])


class TestForeignChanges(ApiCase):
    def seed_pending_rule(self):
        iid = self.fake.seed("integration", {"metadata": {"title": "customer-app", "author": "someone"},
                                             "category": "other"}, spaces=("draft", "test"))
        return self.fake.seed("rule", {"metadata": {"title": "pending customer rule", "author": "someone"},
                                       "enabled": True, "logsource": {"product": "customer-app"},
                                       "detection": {"condition": "s", "s": {"a": "b"}}},
                              spaces=("draft",), integration=iid)

    def test_pending_foreign_resource_stops_and_is_listed(self):
        rid = self.seed_pending_rule()
        out = self.apply(expect=2)
        self.assertIn("add rules %s" % rid, out)
        self.assertEqual(F.writes(self.fake), [])
        self.assertNotIn(rid, self.fake.docs["test"]["rule"])

    def test_include_foreign_changes_is_recorded(self):
        rid = self.seed_pending_rule()
        self.apply("--include-foreign-changes")
        self.assertIn(rid, self.fake.docs["test"]["rule"])
        ops = F.read_state(self.work)["operations"]
        self.assertEqual([o["op"] for o in ops], ["include-foreign-changes"])
        self.assertIn(rid, ops[0]["detail"])
        with open(os.path.join(self.work, "report.md")) as fh:
            self.assertIn("include-foreign-changes", fh.read())

    def test_foreign_flag_change_in_the_draft_policy(self):
        self.fake.policies["draft"]["index_discarded_events"] = True
        out = self.apply(expect=2)
        self.assertIn("index_discarded_events", out)
        self.assertEqual(F.writes(self.fake), [])
        with open(os.path.join(self.work, "report.json")) as fh:
            self.assertEqual(json.load(fh)["apply"]["stops"][0]["code"], "RM-P-FOREIGN-POLICY-CHANGE")
        self.assertFalse(self.fake.policies["test"]["index_discarded_events"])

    def test_foreign_integration_added_to_the_draft_policy(self):
        iid = self.fake.seed("integration", {"metadata": {"title": "customer-app", "author": "someone"},
                                             "category": "other"}, spaces=("draft",))
        out = self.apply(expect=2)
        self.assertIn(iid, out)

    def test_policy_put_changes_root_decoder_only(self):
        self.fake.policies["draft"]["metadata"]["description"] = "Customer description"
        self.fake.policies["test"]["metadata"]["description"] = "Customer description"
        self.fake.policies["draft"]["filters"] = ["f-1"]
        self.fake.policies["test"]["filters"] = ["f-1"]
        self.apply()
        puts = [b for m, p, b in self.fake.calls if m == "PUT" and p.endswith("/policy/draft")]
        self.assertEqual(len(puts), 1)
        res = puts[0]["resource"]
        self.assertEqual(res["filters"], ["f-1"])
        self.assertEqual(res["metadata"]["description"], "Customer description")
        self.assertEqual(self.fake.policies["draft"]["filters"], ["f-1"])  # the fake checked the rest is unchanged


class TestPolicyHelpers(unittest.TestCase):
    class _Own:
        def __init__(self, ids):
            self.ids = set(ids)

        def is_own(self, i):
            return i in self.ids

    def test_only_own_integrations_and_own_root(self):
        own = self._Own({"mine-1", "root-1"})
        base = {"id": "p", "metadata": {"title": "P", "modified": "a"}, "root_decoder": "", "integrations": ["c-1"],
                "filters": [], "enabled": True}
        draft = dict(base, integrations=["c-1", "mine-1"], root_decoder="root-1", metadata={"title": "P", "modified": "b"})
        self.assertEqual(policy_differences(draft, base, own, "root-1"), [])
        self.assertTrue(policy_differences(dict(draft, root_decoder="other"), base, own, "root-1"))
        self.assertTrue(policy_differences(dict(draft, integrations=["mine-1", "c-1", "c-2"]), base, own, "root-1"))
        self.assertTrue(policy_differences(dict(draft, enabled=False), base, own, "root-1"))
        # a root the tool set must not replace someone else's in the destination
        self.assertTrue(policy_differences(draft, dict(base, root_decoder="theirs"), own, "root-1"))

    def test_order_of_foreign_integrations(self):
        own = self._Own(set())
        a = {"integrations": ["c-1", "c-2"]}
        b = {"integrations": ["c-2", "c-1"]}
        self.assertTrue(policy_differences(a, b, own))

    def test_put_body_keeps_every_field(self):
        cur = {"id": "p", "metadata": {"title": "P", "author": "a", "description": "d", "documentation": "",
                                       "references": []}, "root_decoder": "", "integrations": ["x"],
               "filters": ["f"], "enrichments": ["e"], "enabled": True, "index_unclassified_events": False,
               "index_discarded_events": True}
        body = policy_put_body(cur, "root-1")["resource"]
        self.assertNotIn("id", body)
        self.assertEqual(body["root_decoder"], "root-1")
        self.assertEqual({k: v for k, v in body.items() if k != "root_decoder"},
                         {k: v for k, v in cur.items() if k not in ("id", "root_decoder")})


if __name__ == "__main__":
    unittest.main()
