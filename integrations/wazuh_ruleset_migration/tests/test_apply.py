"""apply and rollback against the fake indexer."""

import csv
import json
import os
import shutil
import unittest

import fake_indexer as F

OWN = "wazuh-ruleset-migration"


class ApiCase(unittest.TestCase):
    def setUp(self):
        self.fake = F.FakeIndexer().start()
        self.work = F.make_workdir()

    def tearDown(self):
        self.fake.stop()
        shutil.rmtree(self.work, ignore_errors=True)
        self.assertEqual(self.fake.violations, [], "forbidden calls were made")

    def run_cmd(self, *argv, env=None):
        return F.run_command(self.fake, list(argv), self.work, env)

    def apply(self, *extra, expect=0):
        self.fake.phase = "apply"
        code, out = self.run_cmd("apply", *extra)
        self.fake.phase = None
        self.assertEqual(code, expect, out)
        return out

    def owned(self, space):
        return {t: len(v) for t, v in self.fake.owned_docs(space).items()}

    def edit_out(self, rel, fn):
        path = os.path.join(self.work, "out", rel)
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        fn(data)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, sort_keys=True, indent=2)


class TestApply(ApiCase):
    def test_creates_in_draft_and_promotes_to_test(self):
        self.apply()
        expected = {"integration": 3, "kvdb": 1, "decoder": 4, "rule": 3}
        self.assertEqual(self.owned("draft"), expected)
        self.assertEqual(self.owned("test"), expected)
        self.assertEqual(self.owned("custom"), {"integration": 0, "kvdb": 0, "decoder": 0, "rule": 0})
        state = F.read_state(self.work)
        root = [e for e in state["resources"].values() if e["title"] == "decoder/wazuh4-root/0"][0]
        self.assertEqual(self.fake.policies["draft"]["root_decoder"], root["server_id"])
        self.assertEqual(self.fake.policies["test"]["root_decoder"], root["server_id"])
        self.assertTrue(all(e["space"] == "test" for e in state["resources"].values()))
        # promoted per integration: three POST /promote, each with only its own ids
        promotes = [b for m, p, b in self.fake.calls if m == "POST" and p.endswith("/promote")]
        self.assertEqual(len(promotes), 3)
        self.assertTrue(all(b["space"] == "draft" for b in promotes))
        self.assertEqual([len(b["changes"]["rules"]) for b in promotes], [0, 2, 1])

    def test_apply_twice_creates_nothing_new(self):
        self.apply()
        before = {s: self.owned(s) for s in ("draft", "test")}
        n = len(self.fake.calls)
        self.apply()
        self.assertEqual(F.writes(self.fake, n), [])
        self.assertEqual({s: self.owned(s) for s in ("draft", "test")}, before)

    def test_state_lost_adopts_by_mark(self):
        self.apply()
        os.remove(os.path.join(self.work, "work", "state.json"))
        n = len(self.fake.calls)
        self.apply()
        created = [w for w in F.writes(self.fake, n) if w[0] == "POST" and not w[1].endswith("/promote")]
        self.assertEqual(created, [])
        self.assertEqual(self.owned("draft")["rule"], 3)

    def test_only_draft_and_test_and_no_test_promote(self):
        self.apply()
        for m, p, b in self.fake.calls:
            if m == "POST" and p.endswith("/promote"):
                self.assertEqual(b["space"], "draft")
            self.assertNotIn("/space/", p)
            self.assertFalse(p.endswith("/policy/standard"))
        self.assertEqual(self.owned("custom"), {"integration": 0, "kvdb": 0, "decoder": 0, "rule": 0})

    def test_dry_run_writes_nothing(self):
        out = self.apply("--dry-run")
        self.assertEqual(F.writes(self.fake), [])
        self.assertIn("[dry-run] POST /_plugins/_content_manager/rules", out)
        self.assertIn("[dry-run] PUT /_plugins/_content_manager/policy/draft", out)
        self.assertFalse(os.path.exists(os.path.join(self.work, "work", "state.json")))
        self.assertFalse(os.path.exists(os.path.join(self.work, "report.json")))

    def test_changed_resource_is_updated_in_place(self):
        self.apply()
        self.edit_out("integrations/wazuh4-myapp/rules/100002.json", lambda d: d["resource"].update(level="high"))
        n = len(self.fake.calls)
        self.apply()
        w = F.writes(self.fake, n)
        puts = [p for m, p in w if m == "PUT"]
        self.assertEqual(len(puts), 1)
        self.assertIn("/rules/", puts[0])
        self.assertEqual(len([p for m, p in w if m == "POST"]), 1)  # the promote of wazuh4-myapp
        test_rules = [d for d in self.fake.docs["test"]["rule"].values() if d["metadata"]["title"] == "myapp: logout"]
        self.assertEqual(test_rules[0]["level"], "high")

    def test_rule_removed_from_out_is_deleted_and_promoted(self):
        self.apply()
        os.remove(os.path.join(self.work, "out", "integrations", "wazuh4-myapp", "rules", "100002.json"))
        self.apply()
        titles = {d["metadata"]["title"] for d in self.fake.docs["test"]["rule"].values()}
        self.assertNotIn("myapp: logout", titles)
        self.assertEqual(len(F.read_state(self.work)["resources"]), 10)

    def test_engine_refusal_sets_the_integration_aside(self):
        def reject(space, changes, new):
            if any(d.get("name") == "decoder/wazuh4-myapp-fields/0" for d in new["decoder"].values()):
                return "Engine: invalid decoder 'decoder/wazuh4-myapp-fields/0': bad regex"
            return None

        self.fake.engine_reject = reject
        out = self.apply(expect=1)
        self.assertIn("setting it aside", out)
        draft = self.owned("draft")
        self.assertEqual(draft["integration"], 2)          # base and on-system-auth stay
        self.assertEqual(self.owned("test")["rule"], 1)     # only the on-stock rule reached test
        with open(os.path.join(self.work, "report.json")) as fh:
            rep = json.load(fh)["apply"]
        aside = [i for i in rep["integrations"] if i["status"] == "set aside"]
        self.assertEqual([i["key"] for i in aside], ["wazuh4-myapp"])
        self.assertIn("bad regex", aside[0]["message"])
        with open(os.path.join(self.work, "report.md")) as fh:
            self.assertIn("## Apply", fh.read())
        # once fixed, the next apply promotes it
        self.fake.engine_reject = None
        self.apply()
        self.assertEqual(self.owned("test")["rule"], 3)
        self.assertEqual(F.read_state(self.work)["set_aside"], {})

    def test_400_on_create_sets_the_integration_aside_and_goes_on(self):
        # 5.0.0-rc1 engine: POST /decoders -> 400 "Operation builder 'in_cidr' not found"
        text = "Stage 'check' failed to build expression 'in_cidr($source.ip, '192.0.2.0/24')': " \
               "Operation builder 'in_cidr' not found"

        def reject(rtype, res):
            return text if rtype == "decoder" and res.get("name") == "decoder/wazuh4-myapp-fields/0" else None

        self.fake.create_reject = reject
        out = self.apply(expect=1)
        self.assertIn("setting it aside", out)
        draft = {t: [d["metadata"]["title"] if t != "decoder" else d["name"] for d in v]
                 for t, v in self.fake.owned_docs("draft").items()}
        # what wazuh4-myapp had created (integration, kvdb, decoder myapp/0) is gone from draft
        self.assertEqual(sorted(draft["integration"]), ["wazuh4-base", "wazuh4-on-system-auth"])
        self.assertEqual(draft["kvdb"], [])
        self.assertNotIn("decoder/wazuh4-myapp/0", draft["decoder"])
        # the next integration was still applied and promoted
        self.assertEqual(sorted(d["metadata"]["title"] for d in self.fake.owned_docs("test")["integration"]),
                         ["wazuh4-base", "wazuh4-on-system-auth"])
        self.assertEqual(self.owned("test")["rule"], 1)
        with open(os.path.join(self.work, "report.json")) as fh:
            rep = json.load(fh)["apply"]
        self.assertEqual(rep["result"], "set aside: 1")
        aside = [i for i in rep["integrations"] if i["status"] == "set aside"]
        self.assertEqual([i["key"] for i in aside], ["wazuh4-myapp"])
        self.assertIn("create decoder decoder/wazuh4-myapp-fields/0", aside[0]["message"])
        self.assertIn("Operation builder 'in_cidr' not found", aside[0]["message"])
        state = F.read_state(self.work)
        self.assertIn("wazuh4-myapp", state["set_aside"])
        self.assertNotIn("wazuh4-myapp", {e["integration"] for e in state["resources"].values()})
        # once the content is fixed, the next apply creates and promotes it
        self.fake.create_reject = None
        self.apply()
        self.assertEqual(self.owned("test")["rule"], 3)
        self.assertEqual(F.read_state(self.work)["set_aside"], {})

    def test_413_on_create_sets_the_integration_aside(self):
        # live: a decoder body above the indexer's size limit answers 413; with decoder_body_bytes raised past
        # what the indexer accepts, the preflight lets it through and the 413 sets the integration aside
        text = "Request body exceeds maximum allowed size of 50000 bytes for type 'decoder'"
        self.fake.create_reject = lambda rtype, res: (413, text) if res.get("name") == "decoder/wazuh4-myapp-fields/0" else None
        out = self.apply("--engine-limit", "decoder_body_bytes=900000", expect=1)
        self.assertIn("setting it aside", out)
        self.assertEqual(sorted(d["metadata"]["title"] for d in self.fake.owned_docs("draft")["integration"]),
                         ["wazuh4-base", "wazuh4-on-system-auth"])
        self.assertEqual(self.owned("test")["rule"], 1)
        with open(os.path.join(self.work, "report.json")) as fh:
            aside = [i for i in json.load(fh)["apply"]["integrations"] if i["status"] == "set aside"]
        self.assertEqual([i["key"] for i in aside], ["wazuh4-myapp"])
        self.assertIn(text, aside[0]["message"])

    def test_400_on_the_root_integration_stops(self):
        self.fake.create_reject = lambda rtype, res: "bad root" if res.get("name") == "decoder/wazuh4-syslog/0" else None
        out = self.apply(expect=1)
        self.assertIn("holds the root decoder", out)
        self.assertEqual(self.owned("test")["rule"], 0)

    def test_integration_removed_from_out_is_retired(self):
        self.apply()
        shutil.rmtree(os.path.join(self.work, "out", "integrations", "wazuh4-on-system-auth"))
        self.edit_out("manifest.json", lambda d: d.update(integrations=["wazuh4-base", "wazuh4-myapp"]))
        os.remove(os.path.join(self.work, "out", "detectors", "wazuh4-on-system-auth.json"))
        self.apply()
        for space in ("draft", "test"):
            titles = {d["metadata"]["title"] for d in self.fake.owned_docs(space)["integration"]}
            self.assertEqual(titles, {"wazuh4-base", "wazuh4-myapp"}, space)
        self.assertNotIn("wazuh4-on-system-auth",
                         {e["integration"] for e in F.read_state(self.work)["resources"].values()})

    def test_mapping_applied_has_server_ids(self):
        self.apply()
        with open(os.path.join(self.work, "work", "mapping-applied.csv"), newline="") as fh:
            rows = list(csv.DictReader(fh))
        by = {r["rule_id_4x"]: r for r in rows}
        state = F.read_state(self.work)["resources"]
        self.assertEqual(by["100001"]["server_id"], state[by["100001"]["local_id"]]["server_id"])
        self.assertEqual(by["100003"]["server_id"], "")
        self.assertTrue(by["100010"]["server_id"])

    def test_429_on_create_is_retried(self):
        self.fake.answer_429 = 1
        self.apply()
        self.assertEqual(self.owned("test")["rule"], 3)

    def test_policy_locked(self):
        self.fake.policy_locked = True
        out = self.apply(expect=2)
        with open(os.path.join(self.work, "report.json")) as fh:
            self.assertIn("RM-P-POLICY-LOCKED", fh.read())
        self.assertIn("403", out)

    def test_unclassified_indexed_stops_unless_accepted(self):
        self.fake.policies["custom"]["index_unclassified_events"] = True
        self.apply(expect=2)
        self.assertEqual(F.writes(self.fake), [])
        self.apply("--accept-unclassified-indexing")
        ops = F.read_state(self.work)["operations"]
        self.assertEqual([o["op"] for o in ops], ["accept-unclassified-indexing"])
        self.assertTrue(ops[0]["who"] and ops[0]["when"])

    def test_no_base_does_not_touch_the_policy(self):
        shutil.rmtree(os.path.join(self.work, "out", "integrations", "wazuh4-base"))
        shutil.rmtree(os.path.join(self.work, "out", "integrations", "wazuh4-myapp"))
        self.edit_out("manifest.json", lambda d: d.update(root_decoder=None, integrations=["wazuh4-on-system-auth"]))
        os.remove(os.path.join(self.work, "out", "detectors", "wazuh4-myapp.json"))
        self.apply()
        self.assertFalse([c for c in self.fake.calls if c[0] == "PUT" and "/policy/" in c[1]])
        self.assertEqual(self.fake.policies["test"]["root_decoder"], "")


class TestBaseUpgrade(ApiCase):
    def test_a_decoder_the_base_drops_is_deleted_after_its_children_move(self):
        """A newer build replaces a base decoder (wazuh4-syslog -> another parent): the old one is deleted
        only after the other integrations no longer hang from it."""
        self.apply()
        syslog_sid = [s for s, d in self.fake.docs["draft"]["decoder"].items()
                      if d.get("name") == "decoder/wazuh4-syslog/0"][0]
        os.remove(os.path.join(self.work, "out", "integrations", "wazuh4-base", "decoders", "01-wazuh4-syslog.json"))
        self.edit_out("integrations/wazuh4-myapp/decoders/00-wazuh4-myapp.json",
                      lambda d: d["resource"].update(parents=["decoder/wazuh4-root/0"]))
        n = len(self.fake.calls)
        self.apply()
        calls = F.writes(self.fake, n)
        delete = calls.index(("DELETE", "/_plugins/_content_manager/decoders/%s" % syslog_sid))
        myapp_sid = [s for s, d in self.fake.docs["draft"]["decoder"].items()
                     if d.get("name") == "decoder/wazuh4-myapp/0"][0]
        update = calls.index(("PUT", "/_plugins/_content_manager/decoders/%s" % myapp_sid))
        self.assertLess(update, delete)
        self.assertNotIn(syslog_sid, self.fake.docs["test"]["decoder"])
        self.assertEqual(self.fake.docs["test"]["decoder"][myapp_sid]["parents"], ["decoder/wazuh4-root/0"])


    def test_an_integration_that_leaves_out_goes_before_the_base_decoder_it_used(self):
        self.apply()
        docs = self.fake.docs["draft"]["decoder"]
        syslog = [s for s, d in docs.items() if d.get("name") == "decoder/wazuh4-syslog/0"][0]
        myapp = [s for s, d in docs.items() if d.get("name") == "decoder/wazuh4-myapp/0"][0]
        os.remove(os.path.join(self.work, "out", "integrations", "wazuh4-base", "decoders", "01-wazuh4-syslog.json"))
        shutil.rmtree(os.path.join(self.work, "out", "integrations", "wazuh4-myapp"))
        self.edit_out("manifest.json", lambda m: m.update(
            integrations=[i for i in m["integrations"] if i != "wazuh4-myapp"]))
        n = len(self.fake.calls)
        self.apply()
        calls = F.writes(self.fake, n)
        self.assertLess(calls.index(("DELETE", "/_plugins/_content_manager/decoders/%s" % myapp)),
                        calls.index(("DELETE", "/_plugins/_content_manager/decoders/%s" % syslog)))

    def test_base_resources_stay_while_an_integration_is_set_aside(self):
        self.apply()
        syslog = [s for s, d in self.fake.docs["draft"]["decoder"].items()
                  if d.get("name") == "decoder/wazuh4-syslog/0"][0]
        os.remove(os.path.join(self.work, "out", "integrations", "wazuh4-base", "decoders", "01-wazuh4-syslog.json"))
        self.edit_out("integrations/wazuh4-myapp/decoders/00-wazuh4-myapp.json",
                      lambda d: d["resource"].update(parents=["decoder/wazuh4-root/0"]))
        self.fake.create_reject = lambda rtype, res: None
        self.fake.update_reject = lambda rtype, res: ("bad" if res.get("name") == "decoder/wazuh4-myapp/0" else None)
        self.apply(expect=1)
        self.assertIn(syslog, self.fake.docs["test"]["decoder"])
        notes = json.dumps(self.report()["apply"]["notes"])
        self.assertIn("kept until wazuh4-myapp can be applied", notes)

    def report(self):
        with open(os.path.join(self.work, "report.json")) as fh:
            return json.load(fh)


class TestPolicyOrder(ApiCase):
    def test_own_integrations_follow_out_and_foreign_ones_stay(self):
        foreign = self.fake.seed("integration", {"metadata": {"title": "customer-app", "author": "someone"},
                                                 "category": "other"}, spaces=("draft", "test"))
        self.apply()
        self.edit_out("manifest.json", lambda d: d.update(
            integrations=["wazuh4-base", "wazuh4-on-system-auth", "wazuh4-myapp"]))
        out = self.apply()
        self.assertIn("4.x load order", out)
        titles = {sid: d["metadata"]["title"] for sid, d in self.fake.docs["draft"]["integration"].items()}
        for space in ("draft", "test"):
            order = [titles.get(i, i) for i in self.fake.policies[space]["integrations"]]
            self.assertEqual([t for t in order if t.startswith("wazuh4-")],
                             ["wazuh4-base", "wazuh4-on-system-auth", "wazuh4-myapp"], space)
            self.assertEqual(self.fake.policies[space]["integrations"].index(foreign), 0, space)
        # nothing to do the next time
        self.assertNotIn("4.x load order", self.apply())


class TestPolicyLocked(ApiCase):
    def test_a_refused_reorder_is_reported_and_apply_goes_on(self):
        self.apply()
        self.edit_out("manifest.json", lambda d: d.update(
            integrations=["wazuh4-base", "wazuh4-on-system-auth", "wazuh4-myapp"]))
        self.fake.policy_locked = True
        out = self.apply()
        self.assertIn("could not be reordered (403)", out)
        with open(os.path.join(self.work, "report.json")) as fh:
            notes = json.dumps(json.load(fh)["apply"]["notes"])
        self.assertIn("reorder them by hand", notes)


class TestRollback(ApiCase):
    def seed_foreign(self):
        iid = self.fake.seed("integration", {"metadata": {"title": "customer-app", "author": "someone"},
                                             "category": "other"}, spaces=("draft", "test"))
        self.fake.seed("rule", {"metadata": {"title": "customer rule", "author": "someone"}, "enabled": True,
                                "logsource": {"product": "customer-app"}, "detection": {}}, spaces=("draft", "test"),
                       integration=iid)
        return iid

    def test_rollback_leaves_base_and_foreign(self):
        self.seed_foreign()
        self.apply()
        code, out = self.run_cmd("rollback")
        self.assertEqual(code, 0, out)
        self.assertIn("wazuh4-base is kept", out)
        for space in ("draft", "test"):
            owned = self.fake.owned_docs(space)
            self.assertEqual([d["metadata"]["title"] for d in owned["integration"]], ["wazuh4-base"], space)
            self.assertEqual(owned["rule"], [])
            self.assertEqual(owned["kvdb"], [])
            self.assertEqual(sorted(d["name"] for d in owned["decoder"]),
                             ["decoder/wazuh4-root/0", "decoder/wazuh4-syslog/0"])
            titles = {d["metadata"]["title"] for d in self.fake.docs[space]["rule"].values()}
            self.assertEqual(titles, {"customer rule"})
        with open(os.path.join(self.work, "report.md")) as fh:
            self.assertIn("## Rollback", fh.read())
        # a second rollback has nothing to do
        n = len(self.fake.calls)
        code, out = self.run_cmd("rollback")
        self.assertEqual(code, 0, out)
        self.assertEqual(F.writes(self.fake, n), [])
        # and apply works again afterwards
        self.apply()
        self.assertEqual(self.owned("test")["rule"], 3)

    def test_rollback_without_base_removes_everything(self):
        shutil.rmtree(os.path.join(self.work, "out", "integrations", "wazuh4-base"))
        shutil.rmtree(os.path.join(self.work, "out", "integrations", "wazuh4-myapp"))
        self.edit_out("manifest.json", lambda d: d.update(root_decoder=None, integrations=["wazuh4-on-system-auth"]))
        self.apply()
        code, out = self.run_cmd("rollback")
        self.assertEqual(code, 0, out)
        for space in ("draft", "test"):
            self.assertEqual(self.owned(space), {"integration": 0, "kvdb": 0, "decoder": 0, "rule": 0})
        self.assertEqual(F.read_state(self.work)["resources"], {})

    def test_rollback_waits_for_a_log_type_in_one_run(self):
        shutil.rmtree(os.path.join(self.work, "out", "integrations", "wazuh4-base"))
        shutil.rmtree(os.path.join(self.work, "out", "integrations", "wazuh4-myapp"))
        self.edit_out("manifest.json", lambda d: d.update(root_decoder=None, integrations=["wazuh4-on-system-auth"]))
        self.apply()
        self.fake.logtype_lag["wazuh4-on-system-auth"] = 6  # seconds: free after the second wait (2 + 5)
        code, out = self.run_cmd("rollback")
        self.assertEqual(code, 0, out)
        self.assertIn("deleted after the next promotion", out)
        self.assertEqual(self.fake.slept, [2, 5])
        for space in ("draft", "test"):
            self.assertEqual(self.owned(space), {"integration": 0, "kvdb": 0, "decoder": 0, "rule": 0})
        rb = self.report()["rollback"]
        self.assertEqual([i["status"] for i in rb["integrations"]], ["removed"])

    def report(self):
        with open(os.path.join(self.work, "report.json")) as fh:
            return json.load(fh)

    def test_rollback_dry_run(self):
        self.apply()
        n = len(self.fake.calls)
        code, out = self.run_cmd("rollback", "--dry-run")
        self.assertEqual(code, 0, out)
        self.assertEqual(F.writes(self.fake, n), [])
        self.assertIn("[dry-run] DELETE", out)


if __name__ == "__main__":
    unittest.main()
