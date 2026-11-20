"""activate: --yes, the verification gate (--force recorded), test -> custom
only the tool's content, detectors idempotent."""

import json
import os
import shutil

import fake_indexer as F
from test_verify import VerifyCase


class TestActivate(VerifyCase):
    def activate(self, *extra, expect=0):
        code, out = self.run_cmd("activate", *extra)
        self.assertEqual(code, expect, out)
        return out

    def test_needs_yes(self):
        n = len(self.fake.calls)
        out = self.activate(expect=2)
        self.assertIn("--yes", out)
        self.assertEqual(self.fake.calls[n:], [])
        self.assertEqual(self.owned("custom")["rule"], 0)

    def test_needs_a_clean_verification(self):
        n = len(self.fake.calls)
        out = self.activate("--yes", expect=1)
        self.assertIn("run verify first", out)
        self.assertEqual(F.writes(self.fake, n), [])

    def test_force_is_recorded(self):
        self.activate("--yes", "--force")
        ops = F.read_state(self.work)["operations"]
        self.assertEqual([o["op"] for o in ops], ["force"])
        with open(os.path.join(self.work, "report.md")) as fh:
            md = fh.read()
        self.assertIn("## Activate", md)
        self.assertIn("`force`", md)
        self.assertEqual(self.owned("custom")["rule"], 3)

    def test_verification_must_match_what_is_applied(self):
        self.verify()
        self.edit_out("integrations/wazuh4-myapp/rules/100002.json", lambda d: d["resource"].update(level="high"))
        self.apply()
        out = self.activate("--yes", expect=1)
        self.assertIn("does not match what is applied", out)

    def test_promotes_own_content_and_creates_detectors(self):
        # someone else's content pending in test is left there
        iid = self.fake.seed("integration", {"metadata": {"title": "customer-app", "author": "someone"},
                                             "category": "other"}, spaces=("draft", "test", "custom"))
        self.fake.seed("rule", {"metadata": {"title": "customer rule", "author": "someone"}, "enabled": True,
                                "logsource": {"product": "customer-app"}, "detection": {}},
                       spaces=("draft", "test", "custom"), integration=iid)
        self.verify()
        out = self.activate("--yes")
        self.assertIn("monitor", out.lower() + json.dumps(self.report()["activate"]["notes"]).lower())
        self.assertEqual(self.owned("custom"), {"integration": 3, "kvdb": 1, "decoder": 4, "rule": 3})
        promotes = [b for m, p, b in self.fake.calls if m == "POST" and p.endswith("/promote") and b["space"] == "test"]
        self.assertEqual(len(promotes), 1)
        state = F.read_state(self.work)
        own_ids = {e["server_id"] for e in state["resources"].values()}
        for k, ops in promotes[0]["changes"].items():
            if k != "policy":
                self.assertTrue({op["id"] for op in ops} <= own_ids, k)
        dets = {d["name"]: d for d in self.fake.detectors.values()}
        self.assertEqual(sorted(dets), ["wazuh4-myapp-1", "wazuh4-on-system-auth-1"])
        my = dets["wazuh4-myapp-1"]
        di = my["inputs"][0]["detector_input"]
        self.assertEqual(di["indices"], ["wazuh-events-v5-other"])
        self.assertEqual(my["detector_type"], "wazuh4-myapp")
        self.assertTrue(my["enabled"])
        rule_ids = {e["title"]: e["server_id"] for e in state["resources"].values() if e["type"] == "rule"}
        self.assertEqual(sorted(r["id"] for r in di["custom_rules"]),
                         sorted([rule_ids["myapp: root login"], rule_ids["myapp: logout"]]))
        self.assertTrue(all(e["space"] == "custom" for e in state["resources"].values()))
        # activating again changes nothing
        n = len(self.fake.calls)
        self.activate("--yes")
        self.assertEqual(F.writes(self.fake, n), [])
        self.assertEqual(len(self.fake.detectors), 2)

    def test_detector_found_by_name_is_updated_not_duplicated(self):
        self.verify()
        self.activate("--yes")
        did = [k for k, d in self.fake.detectors.items() if d["name"] == "wazuh4-myapp-1"][0]
        self.fake.detectors[did]["inputs"][0]["detector_input"]["custom_rules"] = []
        os.remove(os.path.join(self.work, "work", "state.json"))  # state lost: found by name
        self.apply()
        self.verify()
        self.activate("--yes")
        self.assertEqual(len(self.fake.detectors), 2)
        self.assertEqual(len(self.fake.detectors[did]["inputs"][0]["detector_input"]["custom_rules"]), 2)

    def seed_foreign_detector(self, name):
        rid = self.fake.seed("rule", {"metadata": {"title": "other workdir rule", "author": "wazuh-ruleset-migration"},
                                      "enabled": True, "logsource": {"product": "wazuh4-myapp"}, "detection": {}},
                             spaces=("draft", "test", "custom"))
        did = "other-%s" % name
        self.fake.detectors[did] = {"name": name, "enabled": True, "inputs": [{"detector_input": {
            "indices": ["wazuh-events-v5-other"], "custom_rules": [{"id": rid}]}}]}
        return did

    def test_a_detector_with_the_tool_name_and_other_rules_is_not_adopted(self):
        did = self.seed_foreign_detector("wazuh4-myapp-1")
        before = json.dumps(self.fake.detectors[did], sort_keys=True)
        self.verify()
        out = self.activate("--yes", expect=1)
        self.assertIn("detector wazuh4-myapp-1 exists and is not the tool's", out)
        self.assertIn("activate: detectors left out: wazuh4-myapp-1", out)
        self.assertEqual(json.dumps(self.fake.detectors[did], sort_keys=True), before)
        self.assertIn("Rename or remove that detector", json.dumps(self.report()["activate"]["notes"]))

    def test_rollback_yes_leaves_a_detector_of_another_workdir(self):
        self.verify()
        self.activate("--yes")
        mine = [k for k, d in self.fake.detectors.items() if d["name"] == "wazuh4-myapp-1"][0]
        del self.fake.detectors[mine]          # this workdir's detector is gone ...
        state = F.read_state(self.work)
        state["detectors"].pop("wazuh4-myapp-1")
        with open(os.path.join(self.work, "work", "state.json"), "w") as fh:
            json.dump(state, fh)
        did = self.seed_foreign_detector("wazuh4-myapp-1")  # ... and another workdir has one with that name
        code, out = self.run_cmd("rollback", "--yes")
        self.assertIn(did, self.fake.detectors, out)
        self.assertIn("detector wazuh4-myapp-1 is not the tool's: left untouched", out)

    def test_rollback_yes_removes_detectors_left_without_custom_content(self):
        self.verify()
        self.activate("--yes")
        dets = dict(F.read_state(self.work)["detectors"])
        # custom no longer has anything of the tool (removed by hand), but its detectors are still there
        for rtype, docs in self.fake.docs["custom"].items():
            for sid in [k for k, d in docs.items() if (d.get("metadata") or {}).get("author") == "wazuh-ruleset-migration"]:
                del docs[sid]
        code, out = self.run_cmd("rollback", "--yes")
        self.assertEqual(code, 0, out)
        for name, d in dets.items():
            self.assertNotIn(d["id"], self.fake.detectors, name)
        self.assertEqual(F.read_state(self.work).get("detectors") or {}, {})

    def test_foreign_change_pending_in_test_stops(self):
        iid = self.fake.seed("integration", {"metadata": {"title": "customer-app", "author": "someone"},
                                             "category": "other"}, spaces=("draft", "test"))
        self.verify()
        n = len(self.fake.calls)
        out = self.activate("--yes", expect=2)
        self.assertIn("add integrations %s (customer-app)" % iid, out)
        self.assertIn("--include-foreign-changes: activate then promotes them to custom too", out)
        self.assertEqual(F.writes(self.fake, n), [])

    def test_rollback_after_activate_leaves_custom(self):
        self.verify()
        self.activate("--yes")
        code, out = self.run_cmd("rollback")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.owned("custom")["rule"], 3)
        self.assertEqual(self.owned("test")["rule"], 0)
        self.assertEqual(self.owned("draft")["rule"], 0)
        # Security Analytics keeps the log types while custom has their rules: the
        # integrations stay (empty) in draft and test, and the report says so
        rb = self.report()["rollback"]
        self.assertTrue(any(i["status"] == "partly removed" for i in rb["integrations"]))
        self.assertTrue(any("still used" in (i["message"] or "") for i in rb["integrations"]))
        # what stays in custom is listed with the step that removes it
        self.assertIn("stay in custom", out)
        self.assertIn("rollback --yes", out)
        self.assertIn("myapp: root login", out)
        self.assertIn("detector wazuh4-myapp-1", out)
        self.assertEqual(len(self.fake.detectors), 2)

    def test_rollback_yes_removes_custom_and_detectors(self):
        self.fake.seed("integration", {"metadata": {"title": "customer-app", "author": "someone"},
                                       "category": "other"}, spaces=("draft", "test", "custom"))
        self.verify()
        self.activate("--yes")
        code, out = self.run_cmd("rollback", "--yes")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.fake.detectors, {})
        for space in ("draft", "test", "custom"):
            owned = self.owned(space)
            # wazuh4-base stays while its root decoder is the policy root_decoder
            self.assertEqual(owned["rule"], 0, space)
            self.assertEqual(owned["kvdb"], 0, space)
            names = sorted(d["name"] for d in self.fake.owned_docs(space)["decoder"])
            self.assertNotIn("decoder/wazuh4-myapp/0", names, space)
        custom_titles = {(d.get("metadata") or {}).get("title") for d in self.fake.docs["custom"]["integration"].values()}
        self.assertIn("customer-app", custom_titles)  # someone else's content is untouched
        self.assertNotIn("wazuh4-myapp", custom_titles)
        rb = self.report()["rollback"]
        self.assertTrue(all(i["status"] == "removed" for i in rb["integrations"] if i["key"] != "wazuh4-base"), rb)
        self.assertIn("delete-detector", [o["op"] for o in rb["operations"]])
        promotes = [b for m, p, b in self.fake.calls if m == "POST" and p.endswith("/promote") and b["space"] == "test"]
        self.assertTrue(promotes)
        for b in promotes[1:]:  # after activate's own promotion: removals and updates only
            for k, ops in b["changes"].items():
                self.assertTrue(all(op["operation"] != "add" for op in ops), (k, ops))
        state = F.read_state(self.work)
        self.assertEqual(state.get("detectors"), {})
        self.assertTrue(all(e["integration"] == "wazuh4-base" for e in state["resources"].values()))
        # a second run has nothing left to do in custom
        n = len(self.fake.calls)
        code, out = self.run_cmd("rollback", "--yes")
        self.assertEqual(code, 0, out)
        self.assertEqual([w for w in F.writes(self.fake, n) if "detectors" in w[1]], [])

    def test_rollback_yes_stops_on_foreign_change_in_test(self):
        self.verify()
        self.activate("--yes")
        iid = self.fake.seed("integration", {"metadata": {"title": "customer-app", "author": "someone"},
                                             "category": "other"}, spaces=("draft", "test"))
        n = len(self.fake.calls)
        code, out = self.run_cmd("rollback", "--yes")
        self.assertEqual(code, 2, out)
        self.assertEqual(F.writes(self.fake, n), [])  # stopped before any write
        self.assertEqual(self.owned("custom")["rule"], 3)
        self.assertIn("add integrations %s (customer-app)" % iid, out)
        self.assertIn("never carries those changes there, not even with --include-foreign-changes", out)

    OTHER_MARK = {"author": "wazuh-ruleset-migration",
                  "references": ["wazuh4-migration:00000000-0000-5000-8000-0000000000aa"]}

    def test_rollback_yes_keeps_another_workdirs_content_in_test(self):
        # a second workdir applied its wazuh4-base to test; rollback --yes of the first one lists it as
        # the tool's content of another workdir, never removes or promotes it, and never stops on it
        self.verify()
        self.activate("--yes")
        iid = self.fake.seed("integration", {"metadata": dict(self.OTHER_MARK, title="wazuh4-base"),
                                             "category": "other"}, spaces=("draft", "test"))
        did = self.fake.seed("decoder", {"name": "decoder/wazuh4-predecoder/0",
                                         "metadata": dict(self.OTHER_MARK, references=[
                                             "wazuh4-migration:00000000-0000-5000-8000-0000000000ab"])},
                             spaces=("draft", "test"), integration=iid)
        code, out = self.run_cmd("rollback", "--yes")
        # the policy carries the other workdir's integration: it waits, so this workdir's integrations stay in
        # custom (empty) until that workdir is rolled back or activated
        self.assertEqual(code, 1, out)
        self.assertIn("integrations: %s added or removed by another rmig workdir" % iid, out)
        self.assertIn("Tool, other workdir", out)
        self.assertIn("add integrations %s (wazuh4-base)" % iid, out)
        self.assertIn("add decoders %s (decoder/wazuh4-predecoder/0)" % did, out)
        self.assertNotIn("never carries those changes there", out)
        # the other workdir's content stays where it was and never reaches custom
        for space in ("draft", "test"):
            self.assertIn(iid, self.fake.docs[space]["integration"])
            self.assertIn(did, self.fake.docs[space]["decoder"])
        self.assertNotIn(iid, self.fake.docs["custom"]["integration"])
        self.assertNotIn(did, self.fake.docs["custom"]["decoder"])
        self.assertNotIn(iid, self.fake.policies["custom"]["integrations"])
        # this workdir's rules left custom
        self.assertEqual(self.owned("custom")["rule"], 0)
        notes = self.report()["rollback"]["notes"]
        self.assertTrue(any(n.startswith("Tool, other workdir") and iid in n for n in notes), notes)

    def test_rollback_lists_another_workdirs_content_in_draft(self):
        self.verify()
        did = self.fake.seed("decoder", {"name": "decoder/wazuh4-other/0", "metadata": dict(self.OTHER_MARK)},
                             spaces=("draft",))
        code, out = self.run_cmd("rollback")
        self.assertEqual(code, 0, out)
        self.assertIn("Tool, other workdir: the draft space", out)
        self.assertIn("add decoders %s (decoder/wazuh4-other/0)" % did, out)
        self.assertIn(did, self.fake.docs["draft"]["decoder"])
        self.assertNotIn(did, self.fake.docs["test"]["decoder"])

    def test_rollback_lists_custom_when_the_state_is_lost(self):
        self.verify()
        self.activate("--yes")
        os.remove(os.path.join(self.work, "work", "state.json"))
        code, out = self.run_cmd("rollback")
        self.assertEqual(code, 0, out)
        self.assertIn("stay in custom", out)
        self.assertIn("myapp: root login (wazuh4-myapp)", out)

    def test_rollback_yes_never_carries_foreign_draft_content_to_custom(self):
        # someone else's integration pending in draft: with --include-foreign-changes it reaches test with the
        # removals, but rollback never promotes someone else's content to custom
        self.verify()
        self.activate("--yes")
        iid = self.fake.seed("integration", {"metadata": {"title": "customer-app", "author": "someone"},
                                             "category": "other"}, spaces=("draft",))
        n = len(self.fake.calls)
        code, out = self.run_cmd("rollback", "--yes", "--include-foreign-changes")
        self.assertEqual(code, 2, out)
        self.assertEqual(F.writes(self.fake, n), [])  # refused before any write
        self.assertNotIn(iid, self.fake.docs["custom"]["integration"])
        self.assertNotIn(iid, self.fake.docs["test"]["integration"])
        self.assertIn("add integrations %s" % iid, out)

    def test_rollback_yes_exits_1_when_custom_keeps_rolled_back_content(self):
        # a promotion to custom skipped as inconsistent: the run is not "ok" while custom still runs that content
        from unittest import mock

        from rmig.api import apply as apply_mod

        self.verify()
        self.activate("--yes")
        with mock.patch.object(apply_mod, "_custom_problem", lambda sel, snap: "simulated"):
            code, out = self.run_cmd("rollback", "--yes")
        self.assertEqual(code, 1, out)
        self.assertIn("not promoted to custom yet: simulated", out)
        self.assertEqual(self.owned("custom")["rule"], 3)
        self.assertEqual(self.report()["rollback"]["result"], "partly removed from custom")
        # once the cause is gone, a second run finishes the job
        code, out = self.run_cmd("rollback", "--yes")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.owned("custom")["rule"], 0)

    def test_rollback_yes_when_the_state_is_lost(self):
        # ownership from the marks and out/: the tool's content leaves custom, the detectors are found by name
        self.fake.seed("rule", {"metadata": {"title": "someone's rule", "author": "someone"}},
                       spaces=("draft", "test", "custom"))
        self.verify()
        self.activate("--yes")
        os.remove(os.path.join(self.work, "work", "state.json"))
        code, out = self.run_cmd("rollback", "--yes")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.fake.detectors, {})
        for space in ("draft", "test", "custom"):
            self.assertEqual(self.owned(space)["rule"], 0, space)
            titles = {(d.get("metadata") or {}).get("title") for d in self.fake.docs[space]["rule"].values()}
            self.assertIn("someone's rule", titles, space)

    def test_rollback_yes_dry_run_writes_nothing(self):
        self.verify()
        self.activate("--yes")
        n = len(self.fake.calls)
        code, out = self.run_cmd("rollback", "--yes", "--dry-run")
        self.assertEqual(code, 0, out)
        self.assertEqual([c for c in self.fake.calls[n:] if c[0] in ("PUT", "DELETE")
                          or (c[0] == "POST" and c[1].endswith("/promote"))], [])
        self.assertIn("[dry-run] DELETE /_plugins/_security_analytics/detectors/", out)
        self.assertIn("promote the removals test -> custom", out)
        self.assertEqual(len(self.fake.detectors), 2)

    def test_a_base_decoder_dropped_by_a_newer_build_leaves_custom_too(self):
        self.verify()
        self.activate("--yes")
        os.remove(os.path.join(self.work, "out", "integrations", "wazuh4-base", "decoders", "01-wazuh4-syslog.json"))
        self.edit_out("integrations/wazuh4-myapp/decoders/00-wazuh4-myapp.json",
                      lambda d: d["resource"].update(parents=["decoder/wazuh4-root/0"]))
        self.apply()
        self.verify()
        self.activate("--yes")
        names = sorted(d["name"] for d in self.fake.owned_docs("custom")["decoder"])
        self.assertNotIn("decoder/wazuh4-syslog/0", names)
        self.assertIn("decoder/wazuh4-myapp/0", names)

    def test_rollback_yes_never_promotes_a_newer_kept_base(self):
        # wazuh4-base stays (its root is the policy root) and test holds a newer version than custom: a changed
        # decoder and a new one. rollback --yes must not promote the base update (nor the integration that
        # lists the new decoder) to custom: rollback only removes.
        self.verify()
        self.activate("--yes")
        before = {sid: json.dumps(d, sort_keys=True) for sid, d in self.fake.docs["custom"]["decoder"].items()}
        before_int = {sid: json.dumps(d, sort_keys=True) for sid, d in self.fake.docs["custom"]["integration"].items()
                      if (d.get("metadata") or {}).get("title") == "wazuh4-base"}
        self.edit_out("integrations/wazuh4-base/decoders/01-wazuh4-syslog.json",
                      lambda d: d["resource"]["metadata"].update(description="4.x decoder base, newer"))
        src = os.path.join(self.work, "out", "integrations", "wazuh4-base", "decoders", "01-wazuh4-syslog.json")
        with open(src, encoding="utf-8") as fh:
            extra = json.load(fh)
        lid = "0b9a4f0e-6d1c-5c3e-9b7a-2f4e8d6c1a55"
        extra["local_id"] = lid
        extra["resource"]["name"] = "decoder/wazuh4-extra/0"
        extra["resource"]["metadata"].update(title="wazuh4-extra", references=["wazuh4-migration:%s" % lid])
        with open(os.path.join(os.path.dirname(src), "02-wazuh4-extra.json"), "w", encoding="utf-8") as fh:
            json.dump(extra, fh, sort_keys=True, indent=2)
        self.apply()
        n = len(self.fake.calls)
        code, out = self.run_cmd("rollback", "--yes")
        self.assertEqual(code, 0, out)
        # the tool's other content left custom; the base in custom is exactly what activate put there
        self.assertEqual(self.owned("custom")["rule"], 0)
        after = {sid: json.dumps(d, sort_keys=True) for sid, d in self.fake.docs["custom"]["decoder"].items()}
        self.assertEqual({s: v for s, v in after.items() if s in before},
                         {s: v for s, v in before.items() if s in after})
        names = sorted(d["name"] for d in self.fake.owned_docs("custom")["decoder"])
        self.assertNotIn("decoder/wazuh4-extra/0", names)
        self.assertIn("decoder/wazuh4-syslog/0", names)
        after_int = {sid: json.dumps(d, sort_keys=True) for sid, d in self.fake.docs["custom"]["integration"].items()
                     if (d.get("metadata") or {}).get("title") == "wazuh4-base"}
        self.assertEqual(after_int, before_int)
        for m, p, b in self.fake.calls[n:]:
            if m == "POST" and p.endswith("/promote") and b["space"] == "test":
                for k, ops in b["changes"].items():
                    self.assertTrue(all(op["operation"] == "remove" or op["id"] not in before_int
                                        and op["id"] not in before for op in ops if k != "policy"), (k, ops))

    def test_rollback_yes_with_an_integration_applied_after_activate(self):
        # wazuh4-on-system-auth is applied after activate: test (and its policy) has it, custom does not. The
        # removals reach custom without a policy that names an integration custom lacks.
        base = os.path.join(self.work, "out", "integrations", "wazuh4-on-system-auth")
        keep = os.path.join(self.work, "keep-on-system-auth")
        det = os.path.join(self.work, "out", "detectors", "wazuh4-on-system-auth.json")
        shutil.copytree(base, keep)
        with open(det, encoding="utf-8") as fh:
            det_doc = fh.read()
        shutil.rmtree(base)
        os.remove(det)
        self.edit_out("manifest.json", lambda d: d.update(integrations=["wazuh4-base", "wazuh4-myapp"]))
        self.apply()
        self.verify()
        self.activate("--yes")
        shutil.copytree(keep, base)
        with open(det, "w", encoding="utf-8") as fh:
            fh.write(det_doc)
        self.edit_out("manifest.json", lambda d: d.update(integrations=["wazuh4-base", "wazuh4-myapp",
                                                                      "wazuh4-on-system-auth"]))
        self.apply()
        self.assertEqual(self.owned("test")["rule"], 3)
        self.assertEqual(self.owned("custom")["rule"], 2)
        code, out = self.run_cmd("rollback", "--yes")
        self.assertEqual(code, 0, out)
        for space in ("draft", "test", "custom"):
            self.assertEqual(self.owned(space)["rule"], 0, space)
            titles = {(d.get("metadata") or {}).get("title") for d in self.fake.owned_docs(space)["integration"]}
            self.assertEqual(titles, {"wazuh4-base"}, space)

    def report(self):
        with open(os.path.join(self.work, "report.json")) as fh:
            return json.load(fh)


if __name__ == "__main__":
    import unittest

    unittest.main()
