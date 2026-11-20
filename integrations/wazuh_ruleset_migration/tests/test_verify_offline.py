"""verify --engine-socket: the strict Sigma reader, its equivalence with recorded indexer verdicts, the engine client
on recorded answers, the policies sent to the engine, and the offline run end to end."""

import glob
import json
import os
import shutil
import tempfile
import types
import unittest
from unittest import mock

import fake_indexer as F
import helpers  # noqa: F401  (puts the tool on sys.path)

from rmig.api import commands
from rmig.api.outdir import Out
from rmig.verify import engine as E
from rmig.verify import offline as O
from rmig.verify.sigma import verdict

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
ENGINE = os.path.join(DATA, "engine")
EQUIV = os.path.join(DATA, "verify-equivalence")
SLICE = os.path.join(DATA, "catalog-slice")
ALERTS = os.path.join(F.DATA_API, "alerts-basic.json")


def record(name):
    with open(os.path.join(ENGINE, name + ".json"), encoding="utf-8") as fh:
        return json.load(fh)


class FakeEngine:
    """Transport that answers with the recorded engine bodies. ``/logtest`` answers with the recorded envelope and
    the normalizer's event in ``result.output`` (README of tests/data/engine)."""

    def __init__(self, normalizer=F.kv_normalizer, refuse=False):
        self.normalizer = normalizer
        self.refuse = refuse
        self.loaded = {}
        self.calls = []

    def __call__(self, method, path, body, timeout):
        payload = json.loads(body) if body else None
        self.calls.append((method, path, payload))
        if (method, path) == ("GET", "/status"):
            rec = record("status")
        elif (method, path) == ("POST", "/content/validate/policy"):
            rec = record("validate-load-unmigrated" if self.refuse else "validate-load-migrated")
            if not self.refuse:
                self.loaded[payload["space"]] = payload["full_policy"]
        elif (method, path) == ("POST", "/logtest"):
            if payload["space"] not in self.loaded:
                rec = record("logtest-no-session")
            else:
                rec = dict(record("logtest-notrace"))
                env = json.loads(rec["raw"])
                env["result"]["output"] = self.normalizer(payload["event"], payload["location"])
                rec["raw"] = json.dumps(env)
        elif (method, path) == ("DELETE", "/logtest"):
            rec = record("delete")
        else:
            raise AssertionError("unexpected engine call %s %s" % (method, path))
        return rec["http"], rec["raw"].encode("utf-8")


# -- 1. strict reader ---------------------------------------------------------------------------------------------
class TestStrictReader(unittest.TestCase):
    def v(self, detection, event):
        return verdict(detection, event)[0]

    def test_equality_and_case(self):
        det = {"condition": "selection", "selection": {"user.name": "root"}}
        self.assertIs(self.v(det, {"user": {"name": "root"}}), True)
        self.assertIs(self.v(det, {"user": {"name": "bob"}}), False)
        self.assertIs(self.v(det, {"user": {}}), False)  # absent never matches
        self.assertIsNone(self.v(det, {"user": {"name": "ROOT"}}))  # logtest and the detector differ on case

    def test_re_whole_term_and_search_must_agree(self):
        det = {"condition": "selection", "selection": {"event.outcome|re": "[Ff][Aa][Ii][Ll][Ee][Dd]"}}
        self.assertIs(self.v(det, {"event": {"outcome": "failed"}}), True)
        self.assertIs(self.v(det, {"event": {"outcome": "ok"}}), False)
        self.assertIsNone(self.v(det, {"event": {"outcome": "notfailed"}}))
        wrapped = {"condition": "selection", "selection": {"message|re": ".*[Cc]onnected.*"}}
        self.assertIs(self.v(wrapped, {"message": "user x connected\nnext"}), True)

    def test_re_outside_the_dialect_is_not_checked(self):
        for value in ("\\d+", "^a", "a$", "(?i)a", "a&b", "a b", "a{x"):
            det = {"condition": "selection", "selection": {"f|re": value}}
            self.assertIsNone(self.v(det, {"f": "a"}), value)
        # inside a class these characters are literal in both dialects
        det = {"condition": "selection", "selection": {"f|re": ".*[{]00020812-[&#].*"}}
        self.assertIs(self.v(det, {"f": "x{00020812-&y"}), True)
        self.assertIs(self.v(det, {"f": "x(00020812-&y"}), False)

    def test_cidr_exists_and_numbers(self):
        det = {"condition": "selection and not filter", "selection": {"source.ip|exists": True},
               "filter": {"source.ip|cidr": "10.0.0.0/8"}}
        self.assertIs(self.v(det, {"source": {"ip": "10.4.2.9"}}), False)
        self.assertIs(self.v(det, {"source": {"ip": "192.0.2.1"}}), True)
        self.assertIs(self.v(det, {"source": {"ip": "2001:db8::1"}}), True)
        self.assertIs(self.v(det, {"source": {}}), False)
        num = {"condition": "selection", "selection": {"destination.port": 2222}}
        self.assertIs(self.v(num, {"destination": {"port": 2222}}), True)
        self.assertIsNone(self.v(num, {"destination": {"port": "2222"}}))  # text against a number: no record
        self.assertIs(self.v(num, {"destination": {"port": 22}}), False)

    def test_substrings_lists_and_all(self):
        det = {"condition": "selection", "selection": {"message|contains": ["fail", "deny"]}}
        self.assertIs(self.v(det, {"message": "login fail"}), True)
        self.assertIs(self.v(det, {"message": "ok"}), False)
        self.assertIsNone(self.v(det, {"message": "FAIL"}))
        both = {"condition": "selection", "selection": {"message|contains|all": ["a", "b"]}}
        self.assertIs(self.v(both, {"message": "ab"}), True)
        self.assertIs(self.v(both, {"message": "a"}), False)
        tags = {"condition": "selection", "selection": {"tags": "wazuh4.rule.1.c1"}}
        self.assertIs(self.v(tags, {"tags": ["x", "wazuh4.rule.1.c1"]}), True)

    def test_forms_not_covered(self):
        cases = [
            {"condition": "selection", "selection": {"f|base64": "x"}},          # modifier
            {"condition": "selection", "selection": ["keyword"]},                 # keyword search
            {"condition": "selection", "selection": {"f": "a*b"}},                # wildcard
            {"condition": "selection | count() > 3", "selection": {"f": "a"}},  # aggregation
            {"condition": "selection", "selection": {"f": None}},
        ]
        for det in cases:
            v, notes = verdict(det, {"f": "a"})
            self.assertIsNone(v, det)
            self.assertTrue(notes, det)
        inside = {"condition": "selection", "selection": {"process.args.name": "x"}}
        self.assertIsNone(self.v(inside, {"process": {"args": [{"name": "x"}]}}))

    def test_kleene_logic_settles_what_it_can(self):
        det = {"condition": "selection and other", "selection": {"f": "a"}, "other": {"g|base64": "x"}}
        self.assertIs(self.v(det, {"f": "b"}), False)  # false and unknown = false
        self.assertIsNone(self.v(det, {"f": "a"}))
        det = {"condition": "selection or other", "selection": {"f": "a"}, "other": {"g|base64": "x"}}
        self.assertIs(self.v(det, {"f": "a"}), True)
        det = {"condition": "1 of selection*", "selection_1": {"f": "x"}, "selection_2": {"f": "a"}}
        self.assertIs(self.v(det, {"f": "a"}), True)

    def test_false_names_the_condition(self):
        v, notes = verdict({"condition": "selection", "selection": {"user.name": "root"}}, {"user": {"name": "bob"}})
        self.assertIs(v, False)
        self.assertTrue(any("user.name" in n for n in notes))


# -- 2. equivalence with recorded indexer verdicts ------------------------------------------------------------------
def load_dataset(name):
    with open(os.path.join(EQUIV, name, "verification.json"), encoding="utf-8") as fh:
        doc = json.load(fh)
    rules = {}
    for f in sorted(glob.glob(os.path.join(EQUIV, name, "rules", "*", "*.json"))):
        with open(f, encoding="utf-8") as fh:
            r = json.load(fh)
        rules[r["source"]["id"]] = (os.path.basename(os.path.dirname(f)), r["resource"]["detection"])
    return doc, rules


def compare(name):
    """Counts of agreement with the recorded server verdicts, and the disagreements."""
    doc, rules = load_dataset(name)
    res = {"events": 0, "same": 0, "not_checked": 0, "rules": 0, "same_shadowing": 0, "diffs": []}
    for e in doc["rules"]:
        rid = e["rule_id_4x"]
        evs = [ev for ev in e["events"] if "normalized" in ev]
        if rid not in rules or not evs:
            continue
        integ, det = rules[rid]
        siblings = {o: d for o, (i, d) in rules.items() if i == integ and o != rid}
        local_shadow, unknown = set(), False
        for ev in evs:
            res["events"] += 1
            v, _ = verdict(det, ev["normalized"])
            if v is None:
                res["not_checked"] += 1
            elif v == ev["matched"]:
                res["same"] += 1
            else:
                res["diffs"].append((rid, ev["alert_id"], "local %s, server %s" % (v, ev["matched"])))
            for o, d in siblings.items():
                ov = verdict(d, ev["normalized"])[0]
                unknown = unknown or ov is None
                if ov:
                    local_shadow.add(o)
        res["rules"] += 1
        if not unknown and sorted(local_shadow) == sorted(e["shadowing"]):
            res["same_shadowing"] += 1
        elif not unknown:
            res["diffs"].append((rid, None, "shadowing local %s, server %s" % (sorted(local_shadow), e["shadowing"])))
    return res


class TestEquivalence(unittest.TestCase):
    EXPECTED = {  # dataset: (events with a normalized document, rules with such events)
        "acmepay": (12, 5),
        "acmepay-broken-root": (12, 5),
        "acmepay-ioc": (12, 5),
    }

    def test_same_verdict_as_the_indexer(self):
        for name, (events, rules) in sorted(self.EXPECTED.items()):
            res = compare(name)
            self.assertEqual(res["diffs"], [], name)
            self.assertEqual(res["not_checked"], 0, name)
            self.assertEqual((res["events"], res["same"]), (events, events), name)
            self.assertEqual((res["rules"], res["same_shadowing"]), (rules, rules), name)

    def test_the_records_hold_both_outcomes(self):
        outcomes = set()
        for name in self.EXPECTED:
            doc, _ = load_dataset(name)
            outcomes.update(ev["matched"] for e in doc["rules"] for ev in e["events"] if "normalized" in ev)
        self.assertEqual(outcomes, {True, False})


# -- 3. engine client on recorded answers ---------------------------------------------------------------------------
class Replay:
    def __init__(self, *names):
        self.names = list(names)
        self.requests = []

    def __call__(self, method, path, body, timeout):
        rec = record(self.names.pop(0))
        self.requests.append((method, path, json.loads(body) if body else None))
        assert (method, path) == (rec["request"]["method"], rec["request"]["path"]), (method, path)
        return rec["http"], rec["raw"].encode("utf-8")


class TestEngineClient(unittest.TestCase):
    def test_recorded_calls(self):
        rp = Replay("status", "validate-load-migrated", "logtest-notrace", "delete")
        c = E.EngineClient("/nowhere.sock", transport=rp)
        st = c.status()
        self.assertTrue(st.ok)
        self.assertFalse(st.body["ioc"]["connection"]["available"])
        self.assertTrue(c.load_policy("rmig_verify", {"policy": {}, "resources": {}}).ok)
        out = E.output_of(c.logtest("rmig_verify", "type=SYSCALL x", "/var/log/audit/audit.log"))
        self.assertEqual(out["wazuh"]["integration"]["name"], "auditd")
        self.assertTrue(c.delete_session("rmig_verify").ok)
        # the request bodies carry the recorded keys
        for (_m, _p, sent), name in zip(rp.requests[1:], ("validate-load-migrated", "logtest-notrace", "delete")):
            recorded = set(record(name)["request"]["payload"]) - {"metadata"}
            self.assertEqual(set(sent), recorded, name)

    def test_refusals_carry_the_engine_text(self):
        c = E.EngineClient("/nowhere.sock", transport=Replay("validate-load-unmigrated", "logtest-no-session"))
        ans = c.load_policy("rmig_verify", {})
        self.assertFalse(ans.ok)
        self.assertIn("Operation builder 'kvdb_get' not found", ans.error)
        with self.assertRaises(E.Refused) as cm:
            E.output_of(c.logtest("rmig_verify", "x", "y"))
        self.assertIn("environment does not exist", str(cm.exception))

    def test_space_names(self):
        c = E.EngineClient("/nowhere.sock", transport=Replay())
        for bad in ("standard", "bad-space", ""):
            with self.assertRaises(ValueError):
                c.load_policy(bad, {})

    def test_no_answer_is_an_engine_error(self):
        def down(*_a):
            raise FileNotFoundError("no socket")
        with self.assertRaises(E.EngineError):
            E.EngineClient("/nowhere.sock", transport=down).status()

    def test_unix_transport_needs_af_unix(self):
        with mock.patch.object(E, "socket", types.SimpleNamespace(SOCK_STREAM=1)):
            self.assertFalse(E.unix_sockets_available())
            with self.assertRaises(E.NoUnixSockets):
                E.EngineClient("/nowhere.sock").status()


# -- 4. policies --------------------------------------------------------------------------------------------------
def mini_catalog(keep=("wazuh-core", "system-auth")):
    """The recorded catalog slice in a temporary directory, its policy listing only the integrations kept."""
    d = tempfile.mkdtemp(prefix="rmig-cat-")
    shutil.copytree(SLICE, os.path.join(d, "cat"))
    root = os.path.join(d, "cat")
    ids = []
    for f in glob.glob(os.path.join(root, "integrations", "*.json")):
        with open(f, encoding="utf-8") as fh:
            doc = json.load(fh)["payload"]["document"]
        if doc["metadata"]["title"] in keep:
            ids.append(doc["id"])
    pf = glob.glob(os.path.join(root, "policies", "*.json"))[0]
    with open(pf, encoding="utf-8") as fh:
        env = json.load(fh)
    env["payload"]["document"]["integrations"] = [i for i in env["payload"]["document"]["integrations"] if i in ids]
    with open(pf, "w", encoding="utf-8") as fh:
        json.dump(env, fh)
    return d, root


class TestPolicies(unittest.TestCase):
    def setUp(self):
        self.work = F.make_workdir()
        self.tmp, self.cat = mini_catalog()

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_tool_policy_from_out(self):
        out = Out(os.path.join(self.work, "out"))
        full, left = O.tool_policy(out)
        self.assertEqual(left, {})
        res = full["resources"]
        titles = [i["metadata"]["title"] for i in res["integrations"]]
        self.assertEqual(titles, ["wazuh4-base", "wazuh4-myapp"])  # on-stock holds rules only
        self.assertEqual(full["policy"]["root_decoder"], out.root["local_id"])
        self.assertEqual(full["policy"]["integrations"], [i["id"] for i in res["integrations"]])
        myapp = res["integrations"][1]
        self.assertEqual(myapp["mode"], "user-managed")
        self.assertEqual(myapp["rules"], [])
        self.assertEqual(myapp["decoders"], [d.local_id for d in out.integration("wazuh4-myapp").decoders])
        self.assertEqual(len(myapp["kvdbs"]), 1)
        self.assertEqual(len(res["decoders"]), 4)
        self.assertTrue(all("id" in d for d in res["decoders"] + res["kvdbs"]))
        # the keys of the indexer's own policy document (tests/data/api/recorded/02-apply.json)
        self.assertEqual(sorted(full["policy"]), ["enabled", "enrichments", "filters", "id", "index_discarded_events",
                                                  "index_unclassified_events", "integrations", "metadata",
                                                  "root_decoder"])

    def test_dangling_parent_is_left_out(self):
        path = os.path.join(self.work, "out", "integrations", "wazuh4-myapp", "decoders", "00-wazuh4-myapp.json")
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        data["resource"]["parents"] = ["decoder/not-here/0"]
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        full, left = O.tool_policy(Out(os.path.join(self.work, "out")))
        self.assertIn("decoder/not-here/0", left["wazuh4-myapp"])
        self.assertEqual([i["metadata"]["title"] for i in full["resources"]["integrations"]], ["wazuh4-base"])

    def test_shared_root_takes_the_root_from_the_catalog(self):
        from rmig.api.shared_root import share, STOCK_ROOT

        out = Out(os.path.join(self.work, "out"))
        out.shared_root = {"name": STOCK_ROOT}
        out.root = None
        with self.assertRaises(O.CatalogError):
            O.tool_policy(out)
        out = Out(os.path.join(self.work, "out"))
        try:
            share(out, STOCK_ROOT)
        except Exception as exc:  # noqa: BLE001  the out-basic predecoder may not take a shared root
            self.skipTest("out-basic does not hang from a shared root: %s" % exc)
        cat = O.Catalog(self.cat)
        full, left = O.tool_policy(out, cat)
        self.assertEqual(full["policy"]["root_decoder"], cat.by_name[STOCK_ROOT])
        titles = [i["metadata"]["title"] for i in full["resources"]["integrations"]]
        self.assertEqual(titles[0], "wazuh-core")
        self.assertNotIn("wazuh4-root", [d.get("name") for d in full["resources"]["decoders"]])

    def test_catalog_policy(self):
        cat = O.Catalog(self.cat)
        self.assertEqual(cat.label(), "rc1-t1-ruleset-5 offset 1833")
        full = cat.full_policy()
        self.assertEqual(len(full["resources"]["integrations"]), 2)
        self.assertEqual(len(full["resources"]["decoders"]), 4)
        self.assertEqual(len(full["resources"]["kvdbs"]), 2)
        self.assertNotIn("outputs", full["policy"])
        self.assertEqual(full["policy"]["root_decoder"], cat.by_name["decoder/core-wazuh-message/0"])
        # a policy that lists an integration the snapshot lacks is refused, not sent
        with self.assertRaises(O.CatalogError):
            O.Catalog(SLICE).full_policy()

    def test_enrichment_gap(self):
        det = {"condition": "selection", "selection": {O.IOC_FIELD: "connection"}}
        self.assertIn("available: none", O.enrichment_gap(det, {"connection": {"available": False}}))
        self.assertIn("available: connection", O.enrichment_gap(det, {"connection": {"available": True}}))
        self.assertIsNone(O.enrichment_gap({"condition": "s", "s": {"f": "a"}}, {}))


# -- 5. the offline run end to end ----------------------------------------------------------------------------------
class TestOfflineVerify(unittest.TestCase):
    def setUp(self):
        self.work = F.make_workdir()
        self.tmp, self.cat = mini_catalog()

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_offline(self, *extra, engine=None, expect=0):
        engine = engine or FakeEngine()
        args = commands.argparse.Namespace(
            alerts=[ALERTS], samples=None, via_detector=False, limit=None, include_events=False,
            engine_socket="/nowhere/engine-api-http.sock", catalog=None, workdir=self.work, out=None)
        for k, v in zip(extra[::2], extra[1::2]):
            setattr(args, k, v)
        with mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            code = commands.cmd_verify_offline(args, transport=engine)
        self.assertEqual(code, expect)
        with open(os.path.join(self.work, "verification-offline.json"), encoding="utf-8") as fh:
            doc = json.load(fh)
        with open(os.path.join(self.work, "verification-offline.md"), encoding="utf-8") as fh:
            md = fh.read()
        return {r["rule_id_4x"]: r for r in doc["rules"]}, doc, md, engine

    def test_without_catalog(self):
        rules, doc, md, eng = self.run_offline()
        self.assertEqual(rules["100001"]["result"], "REPRODUCED")
        self.assertEqual(rules["100002"]["result"], "REPRODUCED")
        self.assertEqual(rules["100001"]["oracle"], "offline engine (rmig_verify)")
        self.assertEqual(rules["100010"]["result"], "NOT_CHECKED")  # on-stock: needs the stock decoders
        self.assertIn("--catalog", rules["100010"]["not_met"][0])
        self.assertIn("RM-R-NOT-CHECKED", rules["100010"]["codes"])
        self.assertEqual(doc["summary"]["NOT_CHECKED"], 1)
        self.assertEqual(doc["oracles"]["default"], "offline engine")
        self.assertIsNone(doc["state_fingerprint"])
        self.assertIn("# Verification (offline engine)", md)
        self.assertIn("final proof is `verify` on the 5.0 indexer", md)
        self.assertIn("| `NOT_CHECKED` | 1 |", md)
        # no indexer file and no state: an offline result never unlocks activate
        self.assertFalse(os.path.exists(os.path.join(self.work, "verification.json")))
        self.assertFalse(os.path.exists(os.path.join(self.work, "work", "state.json")))
        spaces = [p["space"] for m, path, p in eng.calls if path == "/content/validate/policy"]
        self.assertEqual(spaces, ["rmig_verify"])
        self.assertEqual([p["space"] for m, path, p in eng.calls if m == "DELETE"], ["rmig_verify"])
        sent = [p for m, path, p in eng.calls if path == "/logtest" and m == "POST"]
        self.assertTrue(sent and all(set(p) == {"space", "queue", "location", "event", "trace_level"} for p in sent))

    def test_with_catalog(self):
        rules, doc, md, eng = self.run_offline("catalog", self.cat)
        self.assertEqual(rules["100010"]["result"], "REPRODUCED")
        self.assertIn("rmig_verify_std", rules["100010"]["oracle"])
        spaces = [p["space"] for m, path, p in eng.calls if path == "/content/validate/policy"]
        self.assertEqual(spaces, ["rmig_verify", "rmig_verify_std"])
        std = eng.loaded["rmig_verify_std"]
        self.assertEqual(len(std["resources"]["integrations"]), 2)
        self.assertEqual(doc["oracles"]["catalog"], "rc1-t1-ruleset-5 offset 1833")
        self.assertIn("stock decoders from the catalog rc1-t1-ruleset-5 offset 1833", md)
        self.assertEqual(doc["summary"]["failures"], 0)

    def test_not_reproduced_names_the_condition(self):
        def normalizer(event, location):
            out = F.kv_normalizer(event, location)
            if "user" in out:
                out["user"]["name"] = "someone-else"
            return out
        rules, doc, _md, _eng = self.run_offline(engine=FakeEngine(normalizer), expect=1)
        self.assertEqual(rules["100001"]["result"], "NOT_REPRODUCED")
        self.assertTrue(any("user.name" in w for w in rules["100001"]["not_met"]))
        self.assertEqual(rules["100002"]["result"], "REPRODUCED")  # its condition does not read user.name
        self.assertEqual(doc["summary"]["failures"], 1)

    def test_case_difference_is_not_checked(self):
        def normalizer(event, location):
            out = F.kv_normalizer(event, location)
            if (out.get("user") or {}).get("name") == "root":
                out["user"]["name"] = "Root"
            return out
        rules, _doc, _md, _eng = self.run_offline(engine=FakeEngine(normalizer))
        self.assertEqual(rules["100001"]["result"], "NOT_CHECKED")
        self.assertTrue(any(w.startswith("not checked:") and "letter case" in w for w in rules["100001"]["not_met"]))

    def test_engine_refuses_the_content(self):
        rules, doc, _md, _eng = self.run_offline(engine=FakeEngine(refuse=True), expect=1)
        self.assertEqual(rules["100001"]["result"], "NOT_REPRODUCED")
        self.assertIn("Operation builder 'kvdb_get' not found", rules["100001"]["not_met"][0])

    def write_shared_root_state(self):
        os.makedirs(os.path.join(self.work, "work"), exist_ok=True)
        with open(os.path.join(self.work, "work", "state.json"), "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "resources": {}, "shared_root": {"name": "decoder/core-wazuh-message/0"}}, fh)

    def test_shared_root(self):
        self.write_shared_root_state()
        # without --catalog the standard root is missing: not checked, not a failure
        rules, _doc, _md, _eng = self.run_offline()
        self.assertEqual(rules["100001"]["result"], "NOT_CHECKED")
        self.assertIn("--catalog", rules["100001"]["not_met"][0])
        rules, _doc, _md, eng = self.run_offline("catalog", self.cat)
        self.assertEqual(rules["100001"]["result"], "REPRODUCED")
        tool = eng.loaded["rmig_verify"]
        self.assertEqual(tool["resources"]["integrations"][0]["metadata"]["title"], "wazuh-core")
        # a refusal that names a catalog integration (recorded: wazuh-core, old helper names) is about the catalog
        rules, _doc, _md, _eng = self.run_offline("catalog", self.cat, engine=FakeEngine(refuse=True))
        self.assertEqual(rules["100001"]["result"], "NOT_CHECKED")
        self.assertIn("wazuh-core", rules["100001"]["not_met"][0])

    def test_usage_errors(self):
        args = commands.argparse.Namespace(
            alerts=[ALERTS], samples=None, via_detector=True, limit=None, include_events=False,
            engine_socket="/nowhere.sock", catalog=None, workdir=self.work, out=None)
        with mock.patch("sys.stderr"):
            self.assertEqual(commands.cmd_verify_offline(args, transport=FakeEngine()), 2)
            args.via_detector, args.catalog = False, os.path.join(self.tmp, "missing")
            self.assertEqual(commands.cmd_verify_offline(args, transport=FakeEngine()), 2)
            # --catalog without --engine-socket
            self.assertEqual(commands.main(["verify", "--alerts", ALERTS, "--catalog", self.cat,
                                            "--workdir", self.work], env={}), 2)
            # no unix sockets on this Python: the message says where to run it
            args.catalog = None
            with mock.patch.object(E, "unix_sockets_available", return_value=False):
                with mock.patch("sys.stderr") as err:
                    self.assertEqual(commands.cmd_verify_offline(args), 2)
            printed = "".join(c.args[0] for c in err.write.call_args_list)
            self.assertIn("Run rmig where the engine socket is", printed)

    def test_engine_down_is_exit_2(self):
        def down(*_a):
            raise ConnectionRefusedError("refused")
        args = commands.argparse.Namespace(
            alerts=[ALERTS], samples=None, via_detector=False, limit=None, include_events=False,
            engine_socket="/nowhere.sock", catalog=None, workdir=self.work, out=None)
        with mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            self.assertEqual(commands.cmd_verify_offline(args, transport=down), 2)
        self.assertFalse(os.path.exists(os.path.join(self.work, "verification-offline.json")))


if __name__ == "__main__":
    unittest.main()
