"""verify: failure with the unmet condition and the oracle, exit code, silencers, samples, field parity and the detector path."""

import gzip
import json
import os

import fake_indexer as F
from test_apply import ApiCase

ALERTS = os.path.join(F.DATA_API, "alerts-basic.json")


class VerifyCase(ApiCase):
    def setUp(self):
        super().setUp()
        self.apply()

    def verify(self, *extra, expect=0, alerts=ALERTS):
        code, out = self.run_cmd("verify", "--alerts", alerts, *extra)
        self.assertEqual(code, expect, out)
        with open(os.path.join(self.work, "verification.json")) as fh:
            doc = json.load(fh)
        with open(os.path.join(self.work, "verification.md")) as fh:
            md = fh.read()
        return {r["rule_id_4x"]: r for r in doc["rules"]}, doc, md

    def write_decisions(self):
        with open(os.path.join(self.work, "decisions.json"), "w") as fh:
            json.dump({"version": 1, "fields": {"dstport": {"action": "map", "wcs": "destination.port"},
                                                "srcuser": {"action": "map", "wcs": "user.name"}},
                       "integrations": {}, "stock": {}}, fh)


class TestVerify(VerifyCase):
    def test_reproduced_with_oracles(self):
        self.write_decisions()
        rules, doc, md = self.verify()
        self.assertEqual(rules["100001"]["result"], "REPRODUCED")
        self.assertEqual(rules["100001"]["samples"], 2)  # the alert without full_log is not a sample
        self.assertEqual(rules["100002"]["result"], "REPRODUCED")
        self.assertEqual(rules["100010"]["result"], "REPRODUCED")
        self.assertEqual(rules["100010"]["oracle"], "logtest (normalization: standard, detection: test)")
        self.assertEqual(rules["100001"]["oracle"], "logtest (test)")
        self.assertEqual(doc["summary"]["failures"], 0)
        self.assertEqual(len(doc["unreadable_lines"]), 1)
        # field parity: data.srcuser = bob, user.name = bob for 100002; dstport for 100010
        self.assertEqual(rules["100002"]["field_parity"]["srcuser"]["equal"], 1)
        self.assertEqual(rules["100010"]["field_parity"]["dstport"]["equal"], 1)
        self.assertIn("## Field parity", md)
        # stable sample order: by (timestamp, id)
        self.assertEqual([e["alert_id"] for e in rules["100001"]["events"]], ["1761991201.1", "1761991202.2"])
        # the logtest calls: /logtest for own decoders, normalization in standard for on-stock
        paths = [(p, b.get("space")) for m, p, b in self.fake.calls if "/logtest" in p]
        self.assertIn(("/_plugins/_content_manager/logtest/normalization", "standard"), paths)
        self.assertIn(("/_plugins/_content_manager/logtest/detection", "test"), paths)
        self.assertIn(("/_plugins/_content_manager/logtest", "test"), paths)
        self.assertNotIn("draft", {s for _p, s in paths})

    def test_not_reproduced_names_the_condition(self):
        def normalizer(event, location):
            out = F.kv_normalizer(event, location)
            out.pop("user", None)  # the decoders "lose" user.name
            return out

        self.fake.normalizer = normalizer
        rules, doc, md = self.verify(expect=1)
        r = rules["100001"]
        self.assertEqual(r["result"], "NOT_REPRODUCED")
        self.assertEqual(r["matched"], 0)
        self.assertTrue(any("user.name" in w and "absent" in w for w in r["not_met"]), r["not_met"])
        self.assertIn("logtest", r["oracle"])
        self.assertIn("NOT_REPRODUCED", md)
        self.assertIn("Oracle: **logtest**", md)
        self.assertEqual(doc["summary"]["failures"], 1)

    def test_no_sample_and_limit(self):
        rules, doc, _md = self.verify("--limit", "1")
        self.assertEqual(rules["100001"]["samples"], 1)
        self.assertEqual(rules["100001"]["events"][0]["alert_id"], "1761991201.1")
        empty = os.path.join(self.work, "empty.json")
        open(empty, "w").close()
        rules, doc, _md = self.verify(alerts=empty)
        self.assertEqual({r["result"] for r in rules.values()}, {"NO_SAMPLE"})

    def test_gz_and_events_only_in_json(self):
        gz = os.path.join(self.work, "ossec-alerts-01.json.gz")
        with open(ALERTS, "rb") as src, gzip.open(gz, "wb") as dst:
            dst.write(src.read())
        rules, doc, md = self.verify(alerts=gz)
        self.assertEqual(rules["100002"]["result"], "REPRODUCED")
        self.assertIn("event.action=logout", json.dumps(doc))
        self.assertNotIn("event.action=logout", md)
        _r, _d, md = self.verify("--include-events", alerts=gz)
        self.assertIn("event.action=logout", md)

    def test_shadowing_is_informative(self):
        # make 100002 match the login events too
        self.edit_out("integrations/wazuh4-myapp/rules/100002.json",
                      lambda d: d["resource"].update(detection={"condition": "selection",
                                                                "selection": {"event.action|startswith": "log"}}))
        self.apply()
        rules, doc, _md = self.verify(expect=0)
        self.assertEqual(rules["100001"]["shadowing"], ["100002"])
        self.assertIn("RM-R-SHADOWING", rules["100001"]["codes"])

    def test_rule_not_applied_is_a_failure(self):
        state_path = os.path.join(self.work, "work", "state.json")
        with open(state_path) as fh:
            st = json.load(fh)
        for e in st["resources"].values():
            if e["integration"] == "wazuh4-myapp":
                e["space"] = "draft"
        with open(state_path, "w") as fh:
            json.dump(st, fh)
        rules, _d, _md = self.verify(expect=1)
        self.assertEqual(rules["100001"]["result"], "NOT_REPRODUCED")
        self.assertIn("not in the test space", rules["100001"]["not_met"][0])


class TestSilencer(VerifyCase):
    def setUp(self):
        super().setUp()
        plan = {"items": [
            {"uid": "rule:etc/rules/local_rules.xml:3", "kind": "rule", "ref": "rule:100001", "codes": []},
            {"uid": "rule:etc/rules/local_rules.xml:30", "kind": "rule", "ref": "rule:100005",
             "codes": [{"code": "RM-R-SILENCER", "details": []}],
             "exclusion_targets": ["rule:etc/rules/local_rules.xml:3"]},
        ]}
        os.makedirs(os.path.join(self.work, "work"), exist_ok=True)
        with open(os.path.join(self.work, "work", "plan.json"), "w") as fh:
            json.dump(plan, fh)
        self.samples = os.path.join(self.work, "samples")
        os.makedirs(self.samples)

    def test_silenced(self):
        with open(os.path.join(self.samples, "100005.log"), "w") as fh:
            fh.write("event.action=login user.name=svc\n")
        rules, _d, _md = self.verify("--samples", self.samples)
        self.assertEqual(rules["100005"]["result"], "SILENCED")
        self.assertEqual(rules["100005"]["silences"], ["100001"])

    def test_not_silenced(self):
        with open(os.path.join(self.samples, "100005.log"), "w") as fh:
            fh.write("event.action=login user.name=root\n")
        rules, doc, _md = self.verify("--samples", self.samples, expect=1)
        self.assertEqual(rules["100005"]["result"], "NOT_SILENCED")
        self.assertIn("100001", rules["100005"]["not_met"][-1])

    def test_silencer_without_samples(self):
        rules, _d, _md = self.verify()
        self.assertEqual(rules["100005"]["result"], "NO_SAMPLE")


class TestViaDetector(VerifyCase):
    def setUp(self):
        import importlib
        from unittest import mock

        super().setUp()
        patch = mock.patch.object(importlib.import_module("rmig.verify"), "FINDINGS_WAIT", 0)
        patch.start()
        self.addCleanup(patch.stop)

    def test_detector_path_and_cleanup(self):
        rules, doc, md = self.verify("--via-detector")
        self.assertEqual(rules["100001"]["detector"], {"samples": 2, "matched": 2, "differs_from_logtest": False})
        self.assertIn("+ detector", rules["100001"]["oracle"])
        self.assertTrue(doc["oracles"]["via_detector"])
        self.assertEqual(self.fake.detectors, {})
        self.assertFalse([i for i in self.fake.indices if i.startswith("wazuh-events-v5-rmig-verify-")])

    def test_existing_index_is_never_deleted(self):
        keep = "wazuh-events-v5-rmig-verify-wazuh4-myapp"
        self.fake.indices[keep] = {"theirs": {"a": 1}}
        rules, _doc, _md = self.verify("--via-detector")
        self.assertIn("error", rules["100001"]["detector"])
        self.assertEqual(self.fake.indices.get(keep), {"theirs": {"a": 1}})
        self.assertFalse([c for c in self.fake.calls if c[0] == "DELETE" and c[1] == "/" + keep])
        self.assertEqual(self.fake.detectors, {})

    def test_index_name_comes_from_a_safe_key_only(self):
        from rmig.verify import verify_index

        self.assertEqual(verify_index("wazuh4-myapp"), "wazuh-events-v5-rmig-verify-wazuh4-myapp")
        for key in ("wazuh4-*,*", "wazuh4-a,b", "wazuh4-*", "wazuh4-A", "wazuh4-../x", "wazuh4-a b", "other-x",
                    "wazuh4-a#b", "wazuh4-a:b", "wazuh4-" + "x" * 300, None):
            self.assertIsNone(verify_index(key), key)

    def test_detector_differs_from_logtest(self):
        sid = F.read_state(self.work)["resources"]
        rid = [e["server_id"] for e in sid.values() if e["title"] == "myapp: logout"][0]
        self.fake.detector_blind.add(rid)
        rules, _doc, md = self.verify("--via-detector")
        self.assertEqual(rules["100002"]["result"], "REPRODUCED")
        self.assertTrue(rules["100002"]["detector"]["differs_from_logtest"])
        self.assertIn("differs from logtest", md)


if __name__ == "__main__":
    import unittest

    unittest.main()
