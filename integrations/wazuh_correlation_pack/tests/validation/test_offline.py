"""Offline self-tests of the RC2 validation harness (no network, no lab, no credentials).

They check what can be checked without Wazuh: the safety gate keeps every live test disabled
unless explicitly configured; the 4625 builder, decoder model, sanitizer and receiver behave as
documented; the P1/P2 expectations follow from the specification and are decisive; the P5/P6
timelines keep their margins; every test's plan builds. They do NOT show anything about RC2.

Run: python -m unittest discover -s tests/validation -p "test_*.py"
"""

import contextlib
import datetime
import io
import json
import os
import random
import shutil
import sys
import tempfile
import unittest
import urllib.request
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import identity_scenarios as IS  # noqa: E402
import vlib as V  # noqa: E402
import webhook_listener as WHL  # noqa: E402
import winevents as W  # noqa: E402
import winlab as WL  # noqa: E402

import p1_windows_identity_replay as P1  # noqa: E402
import p2_reporting_subject_capture as P2  # noqa: E402
import p3_windows_collection as P3  # noqa: E402
import p4_least_privilege_scheduled as P4  # noqa: E402
import p5_notifications as P5  # noqa: E402
import p6_scheduler_recovery as P6  # noqa: E402
import ssh_live_burst as SSHL  # noqa: E402
import replay_batches as RB  # noqa: E402
import windows_sample_decoding as WSD  # noqa: E402

class _Batch(object):
    def __init__(self, batch):
        self.batch = batch

    def main(self, argv):
        return RB.main(list(argv) + ["--batch", self.batch])


TESTS = {"p1": P1, "p2": P2, "p3": P3, "p4": P4, "p5": P5, "p6": P6, "ssh_live": SSHL,
         "replay_ssh": _Batch("ssh"), "replay_windows": _Batch("windows"), "win_sample_decoding": WSD}


def nested(flat):
    d = {}
    for k, v in flat.items():
        cur = d
        parts = k.split(".")
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = v
    return d


class Gate(unittest.TestCase):
    """Live tests are disabled by default and refuse unconfigured or foreign targets before any request."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wcp-vt-")
        self.env = os.environ.pop("WCP_LAB_CONFIG", None)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
        if self.env is not None:
            os.environ["WCP_LAB_CONFIG"] = self.env

    def cfg(self, **kw):
        c = {"enabled": True, "tests_enabled": ["p1"], "allow": {}, "cluster": {"cluster_uuid": "<placeholder>"}}
        c.update(kw)
        p = os.path.join(self.tmp, "lab.yml")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(c, fh)          # JSON is YAML
        return p

    def args(self, live=True, cfg=None):
        return type("A", (), {"live": live, "lab_config": cfg, "evidence": None})()

    def test_no_live_flag(self):
        with self.assertRaises(V.NotEnabled):
            V.gate("p1", self.args(live=False, cfg=self.cfg()))

    def test_no_config(self):
        with self.assertRaises(V.NotEnabled):
            V.gate("p1", self.args(cfg=None))

    def test_disabled_config(self):
        with self.assertRaises(V.NotEnabled):
            V.gate("p1", self.args(cfg=self.cfg(enabled=False)))

    def test_example_config_is_disabled(self):
        with self.assertRaises(V.NotEnabled):
            V.gate("p1", self.args(cfg=os.path.join(HERE, "lab.example.yml")))

    def test_test_not_listed(self):
        with self.assertRaises(V.NotEnabled):
            V.gate("p4", self.args(cfg=self.cfg()))

    def test_resource_permission(self):
        with self.assertRaises(V.NotEnabled):
            V.gate("p1", self.args(cfg=self.cfg()), needs=("create_resources",))

    def test_cluster_uuid_required(self):
        with self.assertRaises(V.Refused):
            V.gate("p1", self.args(cfg=self.cfg()))

    def test_plan_mode_of_every_test(self):
        for tid, mod in TESTS.items():
            ev = os.path.join(self.tmp, "ev")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = mod.main(["--evidence", ev])
            self.assertEqual(rc, 0, tid)
            with open(os.path.join(ev, "%s_plan.json" % tid), encoding="utf-8") as fh:
                d = json.load(fh)
            self.assertEqual(d["status"], "NOT EXECUTED", tid)
            self.assertIn("NOT EXECUTED", out.getvalue())

    def test_reference_deployment_hash_is_not_frozen(self):
        self.assertFalse(set(V.REFERENCE_DEPLOYMENT_HASHES) & set(V.FROZEN_CONTENT_HASHES.values()))

    def test_frozen_hashes_match_expected_monitors(self):
        for name, h in V.FROZEN_CONTENT_HASHES.items():
            with open(os.path.join(V.PACK, "expected", "monitors", name + ".monitor.json"), encoding="utf-8") as fh:
                self.assertEqual(V.A.marker_of(json.load(fh))["content_hash"], h, name)

    def test_test_accounts(self):
        cfg = {"test_account_prefix": "wcpt-", "access_accounts": ["labadmin"]}
        self.assertEqual(V.check_test_account(cfg, "wcpt-p3-s01"), "wcpt-p3-s01")
        for bad in ("Administrator", "wcpt-labadmin"):
            with self.assertRaises(V.Refused):
                V.check_test_account(cfg, bad)

    def test_temp_names(self):
        with self.assertRaises(ValueError):
            V.temp_monitor_body("wcp_ssh_bruteforce", "wcp-test-x", "not a test name")
        with self.assertRaises(V.Refused):
            V.create_temp_index(None, "wazuh-events-v5-system-activity", {})


class Endpoints(unittest.TestCase):
    ECHO = [sys.executable, "-c", "import sys; sys.stdout.write(sys.argv[1])"]

    def test_posix_quoting(self):
        ep = V.Endpoint("x", {"exec": self.ECHO, "sudo": True})
        self.assertEqual(ep.run("echo 'a b'"), "sudo -n sh -c 'echo '\"'\"'a b'\"'\"''")

    def test_powershell_encoding(self):
        import base64
        ep = V.Endpoint("w", {"exec": self.ECHO, "shell": "powershell"})
        out = ep.run("Get-Date")
        self.assertTrue(out.startswith("powershell -NoProfile -NonInteractive -EncodedCommand "))
        script = base64.b64decode(out.split()[-1]).decode("utf-16-le")
        self.assertTrue(script.endswith("Get-Date"))

    def test_unconfigured(self):
        with self.assertRaises(V.Refused):
            V.endpoint({"endpoints": {}}, "windows")


class Machines(unittest.TestCase):
    """One VM serving several roles: aliases share a machine label, one lock, counted once."""

    def setUp(self):
        self.ids = {"vm-a": "id-a", "vm-b": "id-b"}
        self.locks = {}
        t = self

        def host(ep):
            return t.ids[ep.spec["host"]]

        def lock(ep, owner):
            if host(ep) in t.locks:
                return False
            t.locks[host(ep)] = owner
            return True

        fakes = {"fingerprint": lambda ep: "fp-" + host(ep), "lock": lock,
                 "unlock": lambda ep: t.locks.pop(host(ep), None),
                 "lock_owner": lambda ep: t.locks.get(host(ep), "")}
        self.patches = [mock.patch.object(V.Endpoint, n, f) for n, f in fakes.items()]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        V._SESSION = None

    @staticmethod
    def spec(host, machine=None):
        d = {"exec": ["unused"], "host": host}
        if machine:
            d["machine"] = machine
        return d

    def test_aliases_of_one_vm_counted_once_and_locked_once(self):
        cfg = {"endpoints": {"linux_replay": self.spec("vm-a", "linux-1"), "linux_source": self.spec("vm-a", "linux-1"),
                             "windows": self.spec("vm-b", "windows-1")}}
        V.begin_session("p3")
        for n in ("linux_replay", "linux_source", "windows", "linux_source"):
            V.endpoint(cfg, n)
        self.assertEqual(sorted(self.locks), ["id-a", "id-b"])
        summary = V.end_session()
        self.assertEqual(summary["distinct_machines"], 2)
        linux = [m for m in summary["machines"] if m["label"] == "linux-1"][0]
        self.assertEqual(linux["aliases"], ["linux_replay", "linux_source"])
        self.assertEqual(self.locks, {}, "locks released at the end of the run")

    def test_unlabelled_aliases_of_one_vm_refused(self):
        cfg = {"endpoints": {"linux_replay": self.spec("vm-a"), "linux_source": self.spec("vm-a")}}
        V.begin_session("p2")
        V.endpoint(cfg, "linux_replay")
        with self.assertRaises(V.Refused):
            V.endpoint(cfg, "linux_source")
        V.end_session()
        self.assertEqual(self.locks, {})

    def test_one_label_on_two_machines_refused(self):
        cfg = {"endpoints": {"linux_replay": self.spec("vm-a", "linux-1"), "linux_source": self.spec("vm-b", "linux-1")}}
        V.begin_session("p2")
        V.endpoint(cfg, "linux_replay")
        with self.assertRaises(V.Refused):
            V.endpoint(cfg, "linux_source")
        V.end_session()

    def test_concurrent_run_on_shared_machine_refused(self):
        self.locks["id-a"] = "p1 pid=1"
        cfg = {"endpoints": {"linux_source": self.spec("vm-a", "linux-1")}}
        V.begin_session("p3")
        with self.assertRaises(V.Refused) as cm:
            V.endpoint(cfg, "linux_source")
        self.assertIn("p1 pid=1", str(cm.exception))
        V.end_session()
        self.assertEqual(self.locks, {"id-a": "p1 pid=1"}, "another run's lock is left alone")

    def test_plan_mode_contacts_nothing(self):
        with mock.patch.object(V.Endpoint, "fingerprint", side_effect=AssertionError("contacted")):
            V.endpoint({"endpoints": {"linux_source": self.spec("vm-a", "linux-1")}}, "linux_source")


class P6Slots(unittest.TestCase):
    def test_missed_slots_exclude_the_slot_of_the_first_run(self):
        R = datetime.datetime(2026, 11, 22, 20, 5, 41, 357000, tzinfo=datetime.timezone.utc)
        stop = datetime.datetime(2026, 11, 22, 20, 8, 35, 257000, tzinfo=datetime.timezone.utc)
        first = datetime.datetime(2026, 11, 22, 20, 9, 41, 483000, tzinfo=datetime.timezone.utc)
        self.assertEqual(P6.missed_slots(R, stop, first, first), ["2026-11-22T20:08:41.357Z"])


class AccessAccounts(unittest.TestCase):
    def test_access_accounts_scrubbed(self):
        raw = "Accepted publickey for opsuser from 192.0.2.1; WIN\\Administrator; opsuserx; wcpt-opsuser-x"
        out = V.scrub_access_accounts(raw, ["opsuser", "Administrator"])
        self.assertNotIn("for opsuser ", out)
        self.assertIn("for <access-account> from", out)
        self.assertIn("WIN\\<access-account>", out)
        self.assertIn("opsuserx", out)
        self.assertIn("wcpt-opsuser-x", out)


class Times(unittest.TestCase):
    def test_parse_iso_keeps_utc(self):
        ref = datetime.datetime(2026, 11, 22, 19, 46, 47, 181000, tzinfo=datetime.timezone.utc)
        for s in ("2026-11-22T19:46:47.181Z", "2026-11-22T19:46:47.181000+00:00", "2026-11-22T19:46:47.181",
                  "2026-11-22T20:46:47.181+01:00", "2026-11-22T19:46:47.181000000Z"):
            self.assertEqual(V.parse_iso(s), ref, s)
        self.assertEqual(V.parse_iso("2026-11-22T19:46:47Z"), ref.replace(microsecond=0))
        now = V.utc()
        self.assertLess(abs((V.parse_iso(now.isoformat()) - now).total_seconds()), 0.001)
        self.assertLess(abs((V.parse_iso(V.iso(now)) - now).total_seconds()), 0.001)


class EvidencePaths(unittest.TestCase):
    def test_workstation_paths_scrubbed(self):
        tmp = tempfile.gettempdir()
        home = os.path.expanduser("~")
        raw = json.dumps({"a": os.path.join(tmp, "wcp-p4-state-x", "p4.manifest.json"), "b": home + "/x"})
        out = V.scrub_local_paths(raw)
        self.assertNotIn(json.dumps(tmp)[1:-1], out)
        self.assertNotIn(json.dumps(home)[1:-1], out)
        self.assertIn("<workstation-tmp>", out)
        self.assertIn("<workstation-home>", out)


class ReplayPort(unittest.TestCase):
    def test_only_two_endpoint_scenarios_deferred(self):
        import argparse
        for batch, deferred in (("ssh", {"bf_different_endpoints", "spray_split_endpoints"}), ("windows", set())):
            a = argparse.Namespace(batch=batch, ip_offset=0, only=None)
            run, dfr = RB.scenarios(a, agent="007", host="h")
            self.assertEqual({d["scenario"] for d in dfr}, deferred, batch)
            for s in run:
                self.assertTrue(all(ep["container"] == "linux_replay" for ep, _l in s["lines"]), s["name"])
                for c, m in s["expect"].items():
                    self.assertTrue(all(k[0] == "007" for k in m), (s["name"], c))
        a = argparse.Namespace(batch="ssh", ip_offset=0, only=None)
        self.assertEqual(len(RB.scenarios(a)[0]) + 2, 18)      # the 18 RC1 SSH scenarios


class _FakeCluster(object):
    """Monitor search, index and channel lookups only; records every call."""

    def __init__(self, hits=(), indices=(), channels=()):
        self.hits, self.indices, self.channels, self.calls = list(hits), set(indices), set(channels), []

    def post(self, path, body=None, **kw):
        self.calls.append(("POST", path))
        if path == V.MON + "/_search":
            return {"hits": {"hits": self.hits}}
        raise AssertionError("unexpected POST " + path)

    def get(self, path, **kw):
        self.calls.append(("GET", path))
        name = path.rsplit("/", 1)[-1]
        if (path == "/" + name and name in self.indices) or ("/configs/" in path and name in self.channels):
            return {}
        raise V.ApiError("GET", path, 404, {})

    def put(self, path, body=None, **kw):
        self.calls.append(("PUT", path))
        raise AssertionError("unexpected PUT")

    def delete(self, path, **kw):
        self.calls.append(("DELETE", path))
        raise AssertionError("unexpected DELETE")


class LeftoverGuard(unittest.TestCase):
    LEFT_UNWRAPPED = {"_id": "m1", "_source": {"type": "monitor", "name": "[wcp-test] p5 notify NEW", "enabled": False}}
    LEFT_WRAPPED = {"_id": "m2", "_source": {"monitor": {"name": "[wcp-test] p6 scheduler recovery", "enabled": True}}}
    OTHER = {"_id": "w1", "_source": {"workflow": {"name": "apache-http"}}}

    def ev(self):
        return V.Evidence("t", "t", None, {}, {})

    def test_disabled_leftover_monitor_refused_and_reported(self):
        c = _FakeCluster([self.LEFT_UNWRAPPED, self.OTHER])
        with self.assertRaises(V.Refused) as cm:
            V.refuse_on_leftovers(c, self.ev())
        self.assertIn("m1", str(cm.exception))
        self.assertIn("enabled=False", str(cm.exception))
        self.assertTrue(all(m in ("GET", "POST") for m, _p in c.calls))

    def test_wrapped_source_detected(self):
        self.assertEqual([f["id"] for f in V.leftover_test_resources(_FakeCluster([self.LEFT_WRAPPED]))], ["m2"])

    def test_index_and_channel_detected(self):
        c = _FakeCluster(indices=["wcp-test-p5"], channels=["wcp-test-p5-webhook"])
        kinds = sorted(f["kind"] for f in V.leftover_test_resources(c, ["wcp-test-p5"], ["wcp-test-p5-webhook"]))
        self.assertEqual(kinds, ["channel", "index"])

    def test_clean_cluster_passes(self):
        ev = self.ev()
        V.refuse_on_leftovers(_FakeCluster([self.OTHER]), ev, ["wcp-test-p5"], ["wcp-test-p5-webhook"])
        self.assertEqual(ev.d["observed"]["leftover_check"], [])

    def test_p5_and_p6_refuse_before_creating_anything(self):
        import argparse
        cfg = {"notifications": {"webhook_url": "http://127.0.0.1:1/wcp-p5/tok", "listener_bind": "127.0.0.1:1",
                                 "listener_token": "tok"}}
        for mod, args in ((P5, argparse.Namespace()), (P6, argparse.Namespace(part="a"))):
            c = _FakeCluster([self.LEFT_UNWRAPPED])
            with self.assertRaises(V.Refused):
                mod.run_live(args, cfg, c, self.ev(), {})
            self.assertTrue(all(m in ("GET", "POST") and (m == "GET" or p.endswith("/_search")) for m, p in c.calls),
                            (mod.__name__, c.calls))


class Records(unittest.TestCase):
    def test_build_and_parse(self):
        t = datetime.datetime(2026, 11, 22, 10, 0, 1, 234567, tzinfo=datetime.timezone.utc)
        x = W.build_4625(t, 4242, "HOST1", {"TargetUserName": "a&b", "TargetDomainName": None, "IpAddress": "192.0.2.9",
                                           "SubjectUserName": "svc"})
        p = W.parse_4625(x)
        self.assertEqual(p["record_id"], "4242")
        self.assertEqual(p["computer"], "HOST1")
        self.assertEqual(p["time_created"], "2026-11-22T10:00:01.2345670Z")
        self.assertEqual(p["data"]["TargetUserName"], "a&b")
        self.assertNotIn("TargetDomainName", p["data"])
        self.assertEqual(p["data"]["SubjectUserName"], "svc")
        self.assertEqual(W.record_id_of(x), "4242")
        self.assertNotIn("\n", x)
        self.assertFalse(p["has_rendering_info"])
        with self.assertRaises(KeyError):
            W.set_data(x, "NoSuchField", "1")

    def test_decoder_model_reproduces_rc1_observed_shapes(self):
        """The model applied to the 20 real sample records gives the shape observed on 5.0.0-rc1."""
        with open(os.path.join(V.PACK, "evidence", "2026-11-22-rc1-105573d", "platform_facts.json"), encoding="utf-8") as fh:
            shapes = json.load(fh)["windows_4625_identity_shapes"]
        observed = {(s["user_domain"], s["user_id"], s["user_target_id"], s["user_name_equals_target"],
                     s["user_target_domain"]) for s in shapes if s["host_name"] == "WCP-WIN-SAMPLE"}
        with open(W.SAMPLE, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        self.assertEqual(len(lines), 20)
        modeled = set()
        for line in lines:
            p = W.parse_4625(line)
            m = W.decoder_model(p["computer"], p["data"])
            modeled.add((m.get("user.domain"), m.get("user.id"), m.get("user.target.id"),
                         str(m.get("user.name") == m.get("user.target.name")).lower(),
                         m.get("user.target.domain", "(field not mapped)")))
        self.assertEqual(modeled, observed)

    def test_compare_identity_empty_equals_absent(self):
        self.assertEqual(W.compare_identity(nested({"user.domain": ""}), {}), [])
        self.assertEqual(W.compare_identity(nested({"user.domain": "X"}), {"user.domain": "X"}), [])
        self.assertEqual(len(W.compare_identity(nested({"user.domain": "X"}), {"user.domain": "Y"})), 1)

    def test_sanitizer(self):
        x = W.build_4625(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc), 1, "WINLAB7.corp.local",
                         {"SubjectUserName": "labadmin", "SubjectDomainName": "WINLAB7", "IpAddress": "10.20.30.40",
                          "SubjectUserSid": "S-1-5-21-111-222-333-500"})
        s = W.Sanitizer({"labadmin": "wcp-caller", "WINLAB7": "WCP-WIN-LAB"}, ["labadmin", "winlab7", "10.20.30.40"])
        y = s(x)
        self.assertEqual(s.leftovers(y), [])
        p = W.parse_4625(y)
        self.assertEqual(p["computer"], "WCP-WIN-LAB")
        self.assertEqual(p["data"]["SubjectUserName"], "wcp-caller")
        self.assertTrue(p["data"]["IpAddress"].startswith("203.0.113."))
        self.assertEqual(p["data"]["SubjectUserSid"], "S-1-5-21-1000000001-1000000002-1000000003-500")
        self.assertEqual(W.Sanitizer({}, ["labadmin"]).leftovers(x), ["labadmin"])

    def test_spec_account(self):
        p = {"computer": "WIN1.lab", "data": {"TargetUserName": "Bob", "TargetDomainName": ".",
                                               "SubjectDomainName": "WORKGROUP"}}
        self.assertEqual(WL.spec_account(p), "win1\\bob")
        p["data"]["SubjectDomainName"] = "-"            # no reporting subject: target domain not attributable
        self.assertEqual(WL.spec_account(p), "?\\bob")
        p["data"]["SubjectDomainName"] = "WORKGROUP"
        p["data"]["TargetDomainName"] = "-"
        self.assertEqual(WL.spec_account(p), "?\\bob")
        p["data"]["TargetUserName"] = "-"
        self.assertIsNone(WL.spec_account(p))


class IdentityScenarios(unittest.TestCase):
    """Expected accounts are written from the specification; check them against the frozen derivation
    applied to the modeled decoding, and check that each scenario is decisive."""

    def test_spec_vs_derivation_on_modeled_decoding(self):
        for s, r in IS.all_records():
            doc = nested(W.decoder_model(r["computer"], r["data"]))
            self.assertEqual(V.IDN.windows_target_account(doc), r["account"], "%s %s" % (s["name"], r["data"]))
            self.assertEqual(WL.spec_account({"computer": r["computer"], "data": r["data"]}), r["account"],
                             "%s %s" % (s["name"], r["data"]))

    @staticmethod
    def fallback_105573d(doc):
        """The previous derivation (realm falls back to user.domain when user.id == user.target.id)."""
        name = (V.IDN._first(doc, "user.target.name") or "").strip().lower()
        realm = V.IDN._norm(V.IDN._first(doc, "user.target.domain"))
        if realm is None and V.IDN._first(doc, "user.id") == V.IDN._first(doc, "user.target.id") \
                and V.IDN._first(doc, "user.id") is not None:
            realm = V.IDN._norm(V.IDN._first(doc, "user.domain"))
        if realm == ".":
            realm = (V.IDN._norm(V.IDN._first(doc, "host.name")) or "").split(".", 1)[0] or None
        return (realm or "?") + "\\" + name

    def test_scenarios_are_decisive(self):
        def alternatives(r):
            d = r["data"]
            name = (d["TargetUserName"] or "").lower()
            doc = nested(W.decoder_model(r["computer"], r["data"]))
            return {"user_name_only": name,
                    "case_sensitive": "%s\\%s" % (d.get("TargetDomainName"), d["TargetUserName"]),
                    "subject_domain": "%s\\%s" % (d["SubjectDomainName"].lower(), name),
                    "subject_account": "%s\\%s" % (d["SubjectDomainName"], d["SubjectUserName"]),
                    "fallback_105573d": self.fallback_105573d(doc),
                    "representation_keys": r["account"]}
        for s in IS.scenarios():
            spec = (len(s["expected_accounts"]) >= 5, s["expected_accounts"])
            differs = []
            for alt in ("user_name_only", "case_sensitive", "subject_domain", "subject_account", "fallback_105573d",
                        "representation_keys"):
                vals = sorted({alternatives(r)[alt] for r in s["records"]})
                if (len(vals) >= 5, vals) != spec:
                    differs.append(alt)
            self.assertTrue(differs, s["name"])
            self.assertEqual(s["expected_score"], len(s["expected_accounts"]))
            if s["name"].startswith("p2_ambiguous"):
                self.assertIn("fallback_105573d", differs, s["name"])   # the defect is caught
            if s["name"] in ("p2_mixed_shapes_three_accounts", "p2_subject_present_and_absent_counts_once"):
                self.assertIn("representation_keys", differs, s["name"])   # the double count is caught

    def test_same_accounts(self):
        b = "\\"
        want = ["contoso" + b + "alice", "contoso" + b + "bob", "contoso" + b + "carol"]
        self.assertTrue(IS.same_accounts(["?" + b + "carol", "contoso" + b + "alice", "contoso" + b + "bob"], want))
        self.assertTrue(IS.same_accounts(list(want), want))
        self.assertFalse(IS.same_accounts(["?" + b + "carol", "contoso" + b + "carol", "contoso" + b + "bob"], want))
        self.assertFalse(IS.same_accounts(["?" + b + "dave", "contoso" + b + "alice", "contoso" + b + "bob"], want))
        self.assertFalse(IS.same_accounts(["fabrikam" + b + "carol", "contoso" + b + "alice", "contoso" + b + "bob"], want))
        self.assertFalse(IS.same_accounts(want[:2], want))
        # ?\bob is ambiguous when two expected accounts are named bob
        self.assertFalse(IS.same_accounts(["?" + b + "bob", "?" + b + "x"],
                                          ["contoso" + b + "bob", "fabrikam" + b + "bob"]))

    def test_count_accounts_policy(self):
        b = "\\"
        self.assertEqual(sorted(IS.count_accounts(["?" + b + "a", "contoso" + b + "a", "?" + b + "b", "fabrikam" + b + "b",
                                                   "contoso" + b + "b", "?" + b + "c", None])),
                         ["?" + b + "c", "contoso" + b + "a", "contoso" + b + "b", "fabrikam" + b + "b"])
        self.assertEqual(len(IS.count_accounts(["?" + b + "n%d" % k for k in range(5)])), 5)

    def test_unique_and_bounded(self):
        names = [s["name"] for s in IS.scenarios()]
        self.assertEqual(len(names), len(set(names)))
        self.assertLessEqual(len(names) + 60, 255)       # source addresses 198.51.100.60+
        for s in IS.scenarios():
            self.assertLess(len(s["records"]), 10, s["name"])   # never a burst alert


class Timelines(unittest.TestCase):
    def test_counted_by_schedule(self):
        t0 = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        runs = [t0 + datetime.timedelta(seconds=60 * k) for k in range(10)]
        first, vis = t0 + datetime.timedelta(seconds=-200), t0 + datetime.timedelta(seconds=50)
        run, margin = V.counted_by_schedule(first, vis, runs, 300)
        self.assertEqual(run, runs[1])
        self.assertEqual(margin, 40)
        run, margin = V.counted_by_schedule(t0 + datetime.timedelta(seconds=-300), vis, runs, 300)
        self.assertIsNone(run)
        self.assertEqual(len(V.grid(t0, 60, t0 + datetime.timedelta(seconds=30), t0 + datetime.timedelta(seconds=300))), 5)

    def test_p5_single_run_margins(self):
        vis = 50.0                       # seconds after a run R
        first = vis - 260 - 7
        nxt, after = 60 - first, 120 - first
        self.assertGreaterEqual(P5.LOOKBACK - nxt, 15)
        self.assertGreaterEqual(after - P5.LOOKBACK, 15)

    def test_p6_margins(self):
        D = 0.0
        gap_first = D + 10 - 100 - P6.SPAN
        self.assertGreaterEqual(P6.LOOKBACK - ((D - 70 + 120) - gap_first), 15)     # suppressed run R+120 = D+50
        self.assertGreaterEqual(((D + 180 + 60) - gap_first) - P6.LOOKBACK, 15)     # first run after re-enable
        kept_first = D + 120 - 1 - P6.SPAN
        self.assertGreaterEqual(P6.LOOKBACK - ((D + 240) - kept_first), 15)
        M = 0.0
        gb = M - 15 - 248 - P6.SPAN
        self.assertGreaterEqual(P6.LOOKBACK - (M - gb), 15)
        self.assertGreaterEqual((M + 60 - gb) - P6.LOOKBACK, 15)

    def test_p3_window_counts_match_reference(self):
        rnd = random.Random(7)
        for _ in range(200):
            items = [(rnd.randint(0, 400000), rnd.choice(["?", "contoso", "fabrikam"]) + "\\" + "a%d" % rnd.randint(0, 7))
                     for _ in range(rnd.randint(1, 30))]
            ref_c = V.A.sliding_score([(t, None, None) for t, _v in items], 120000)[0]
            ref_d = V.A.sliding_score([(t, v, None) for t, v in items], 600000, distinct=True, unknown_realm=True)[0]
            self.assertEqual(P3.max_in_window([t for t, _v in items], 120000), ref_c)
            self.assertEqual(P3.max_distinct_in_window(items, 600000)[0], ref_d)


class Receiver(unittest.TestCase):
    def test_listener_records_and_classifies(self):
        li = WHL.Listener("127.0.0.1", 0, "tok123").start()
        try:
            msg = ("Monitor [wcp-test] p5 notify NEW (wcp_ssh_bruteforce: ...)\nNew: [[009, 192.0.2.101]] \n"
                   "Resolved:  \nPeriod end: 2026-11-22T10:00:00Z")
            for path in ("/wcp-p5/tok123", "/other"):
                req = urllib.request.Request("http://127.0.0.1:%d%s" % (li.port, path), data=msg.encode("utf-8"),
                                             method="POST", headers={"Content-Type": "text/plain"})
                with urllib.request.urlopen(req, timeout=10) as r:
                    self.assertEqual(r.status, 200)
            recs = li.snapshot()
        finally:
            li.stop()
        self.assertEqual([r["path_ok"] for r in recs], [True, False])
        names = [v[0] for v in P5.COPIES.values()]
        ips = list(P5.CASES.values())
        c = WHL.classify(recs[0]["body"], names, ips)
        self.assertEqual(c, {"monitor": "[wcp-test] p5 notify NEW", "new": ["192.0.2.101"], "completed": []})
        c = WHL.classify(json.dumps({"text": msg.replace("New: [[009, 192.0.2.101]]", "New:").replace(
            "Resolved: ", "Resolved: [[009, 192.0.2.103]]")}), names, ips)
        self.assertEqual(c["completed"], ["192.0.2.103"])
        self.assertEqual(c["new"], [])
        nc = msg.replace("p5 notify NEW (", "p5 notify NEW+COMPLETED (")
        self.assertEqual(WHL.classify(nc, names, ips)["monitor"], "[wcp-test] p5 notify NEW+COMPLETED")
        self.assertIsNone(WHL.classify("no monitor name", names, ips)["monitor"])

    def test_default_message_lines(self):
        """classify() relies on the pack's default message having 'New:' and 'Resolved:' lines."""
        lines = V.A.DEFAULT_MESSAGE.splitlines()
        self.assertTrue(any(l.startswith("New:") for l in lines))
        self.assertTrue(any(l.startswith("Resolved:") for l in lines))
        self.assertIn("{{ctx.monitor.name}}", V.A.DEFAULT_MESSAGE)


class SecurityDefinitions(unittest.TestCase):
    def test_role_covers_documented_minimum(self):
        with open(P4.ROLE_FILE, encoding="utf-8") as fh:
            role = json.load(fh)
        with open(os.path.join(V.PACK, "docs", "CONFIGURATION.md"), encoding="utf-8") as fh:
            doc = fh.read()
        for p in role["cluster_permissions"]:
            short = p.rsplit("/", 2)[-2] + "/" + p.rsplit("/", 1)[-1] if "alerting" in p else p
            self.assertTrue(short in doc or p in doc, p)
        self.assertEqual(role["index_permissions"][0]["index_patterns"], ["wazuh-events-v5-system-activity*"])
        minimal = P4.role(True)["cluster_permissions"]
        self.assertEqual(sorted(set(role["cluster_permissions"]) - set(minimal)), sorted(P4.PREFLIGHT_ONLY))

    def test_definition_files(self):
        d = os.path.join(HERE, "security")
        for f in os.listdir(d):
            with open(os.path.join(d, f), encoding="utf-8") as fh:
                txt = fh.read()
            json.loads(txt)
            self.assertNotRegex(txt.lower(), r'"password":\s*"[^<]', f)   # placeholders only
        with open(P5.CHANNEL_FILE, encoding="utf-8") as fh:
            ch = json.load(fh)
        self.assertTrue(ch["config"]["name"].startswith(V.TEST_NAME_PREFIX))
        self.assertEqual(ch["config"]["config_type"], "webhook")


if __name__ == "__main__":
    unittest.main()
