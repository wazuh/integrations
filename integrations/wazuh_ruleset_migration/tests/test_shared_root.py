"""apply under a root decoder the draft policy already has: the standard
core-wazuh-message is shared (the tool's root is not created, the policy root is never written, the predecoder
gets a check), any other root stops; rollback, activate and rollback --yes work in that mode."""

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest

import fake_indexer as F
from rmig.api.state import State
from helpers import TOOL
from test_apply import ApiCase

from rmig import cli
from rmig.api import shared_root as SR
from rmig.api.outdir import Out
from rmig.translate.patterns import helper_quote

ACMEPAY = os.path.join(TOOL, "examples", "acmepay")
STOCK = "decoder/core-wazuh-message/0"
PRE = "decoder/wazuh4-predecoder/0"
TOOL_ROOT = "decoder/wazuh4-core-wazuh-message/0"
# the stored document of the standard root, as the 5.x catalog has it (rc1-t1-ruleset-5 offset 1833, decoder
# ae0abc37-774a-5dc9-a888-647845c36bbe) and a fresh 5.x indexer seeds it in draft
STOCK_DOC = {
    "enabled": True,
    "metadata": {"author": "Wazuh, Inc.", "date": "2025-09-30", "modified": "2026-03-20", "documentation": "",
                 "description": "Base decoder to process Wazuh message format, parses location part and enriches "
                                "the events that comes from a Wazuh agent with the host information.",
                 "references": ["https://documentation.wazuh.com/"], "supports": [],
                 "title": "Wazuh message decoder"},
    "name": STOCK,
    "normalize": [{"map": [{"_tmp_json": "parse_json($event.original)"}]}],
}

_BUILT = {}


def built_out():
    """out/ of the acmepay example, built once per run."""
    if "out" not in _BUILT:
        work = tempfile.mkdtemp(prefix="rmig-shared-")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            cli.main(["migrate", "--source", os.path.join(ACMEPAY, "etc"), "--workdir", work,
                      "--engine-helpers", "5.0"])
        _BUILT["out"] = os.path.join(work, "out")
        _BUILT["work"] = work
    return _BUILT["out"]


def tearDownModule():
    if "work" in _BUILT:
        shutil.rmtree(_BUILT["work"], ignore_errors=True)


class SharedCase(ApiCase):
    SPACES = ("draft", "test")

    def setUp(self):
        self.fake = F.FakeIndexer().start()
        self.work = tempfile.mkdtemp(prefix="rmig-api-")
        shutil.copytree(built_out(), os.path.join(self.work, "out"))

    def seed_root(self, doc=None, spaces=None):
        spaces = spaces or self.SPACES
        iid = self.fake.seed("integration", {"metadata": {"title": "wazuh-core", "author": "Wazuh, Inc."},
                                             "category": "other"}, spaces=spaces)
        did = self.fake.seed("decoder", doc or STOCK_DOC, spaces=spaces, integration=iid)
        for s in spaces:
            self.fake.policies[s]["root_decoder"] = did
        return did

    def decoder(self, space, name):
        found = [d for d in self.fake.docs[space]["decoder"].values() if d.get("name") == name]
        return found[0] if found else None

    def policy_puts(self):
        return [b for m, p, b in self.fake.calls if m == "PUT" and p.endswith("/policy/draft")]

    def report(self):
        with open(os.path.join(self.work, "report.json"), encoding="utf-8") as fh:
            return json.load(fh)


class TestSharedApply(SharedCase):
    def test_apply_under_the_standard_root_and_rollback(self):
        did = self.seed_root()
        seeded = json.dumps(self.fake.docs["draft"]["decoder"][did], sort_keys=True)
        out = self.apply()
        self.assertIn("RM-P-SHARED-ROOT", out)
        for space in ("draft", "test"):
            self.assertEqual(self.fake.policies[space]["root_decoder"], did)
            self.assertIsNone(self.decoder(space, TOOL_ROOT))
            pre = self.decoder(space, PRE)
            self.assertEqual(pre["parents"], [STOCK])
            self.assertEqual(pre["check"], "regex_match($event.original, %s)" % helper_quote("(?i)acmepay"))
            self.assertEqual(self.decoder(space, "decoder/wazuh4-acmepay/0")["parents"], [PRE])
        # every PUT of the policy keeps the existing root
        self.assertTrue(all(b["resource"]["root_decoder"] == did for b in self.policy_puts()))
        state = F.read_state(self.work)
        self.assertEqual(state["shared_root"]["server_id"], did)
        self.assertEqual(state["shared_root"]["name"], STOCK)
        self.assertIsNone(state["root_decoder"])
        self.assertFalse(any(e["title"] == TOOL_ROOT for e in state["resources"].values()))
        self.assertTrue(any(n.startswith("RM-P-SHARED-ROOT") for n in self.report()["apply"]["notes"]))
        # again: nothing to write
        n = len(self.fake.calls)
        self.apply()
        self.assertFalse([w for w in F.writes(self.fake, n)
                          if (w[0] in ("POST", "DELETE") and "promote" not in w[1]) or
                          (w[0] == "PUT" and "/decoders/" in w[1])])
        # rollback removes only the tool's content; the root and the policy stay as they were
        code, out = self.run_cmd("rollback")
        self.assertEqual(code, 0, out)
        for space in ("draft", "test"):
            self.assertEqual(self.owned(space), {"integration": 0, "kvdb": 0, "decoder": 0, "rule": 0})
            self.assertEqual(self.fake.policies[space]["root_decoder"], did)
            self.assertEqual(json.dumps(self.fake.docs[space]["decoder"][did], sort_keys=True), seeded)
        self.assertTrue(all(b["resource"]["root_decoder"] == did for b in self.policy_puts()))
        self.assertIsNone(F.read_state(self.work)["shared_root"])

    def test_dry_run_writes_nothing(self):
        self.seed_root()
        out = self.apply("--dry-run")
        self.assertIn("RM-P-SHARED-ROOT", out)
        self.assertNotIn(TOOL_ROOT, out)
        self.assertEqual(F.writes(self.fake), [])

    def test_incompatible_standard_root_stops(self):
        doc = dict(STOCK_DOC, check="exists($event.original)")
        did = self.seed_root(doc)
        out = self.apply(expect=2)
        self.assertIn("apply: stopped (RM-P-ROOT-OWNED)", out)
        self.assertIn("its check is", out)
        self.assertIn("name %s" % STOCK, out)
        self.assertEqual(F.writes(self.fake), [])
        self.assertEqual(self.report()["apply"]["stops"][0]["code"], "RM-P-ROOT-OWNED")
        self.assertEqual(self.fake.policies["draft"]["root_decoder"], did)

    def test_other_normalize_stops(self):
        doc = dict(STOCK_DOC, normalize=[{"map": [{"event.kind": "event"}]}])
        self.seed_root(doc)
        out = self.apply(expect=2)
        self.assertIn("its normalize is", out)
        self.assertEqual(F.writes(self.fake), [])

    def test_other_root_name_stops(self):
        self.seed_root(dict(STOCK_DOC, name="decoder/customer-root/0"))
        out = self.apply(expect=2)
        self.assertIn("not the standard %s" % STOCK, out)
        self.assertEqual(F.writes(self.fake), [])

    def test_standard_root_with_its_syslog_child_goes_after_the_tool(self):
        # the shape of wazuh-core in the standard catalog (rmig/data/stock5-index.json): core-wazuh-message is the
        # root and decoder/syslog/0 hangs from it with no check; that integration comes first in the policy
        did = self.seed_root()
        iid = [i for i, d in self.fake.docs["draft"]["integration"].items() if did in d["decoders"]][0]
        self.fake.seed("integration", {"metadata": {"title": "customer-app", "author": "someone"},
                                               "category": "other"}, spaces=self.SPACES)
        self.fake.seed("decoder", {"name": "decoder/syslog/0", "parents": [STOCK], "enabled": True,
                                   "metadata": {"author": "Wazuh, Inc.", "title": "Syslog header"},
                                   "parse|event.original": ["<_tmp.hostname> <_TAG>: <message>"]},
                       spaces=self.SPACES, integration=iid)
        out = self.apply()
        self.assertIn("before the others (shared root)", out)
        notes = json.dumps(self.report()["apply"]["notes"])
        self.assertIn("decoder decoder/syslog/0", notes)
        titles = {k: (d.get("metadata") or {}).get("title") for k, d in self.fake.docs["draft"]["integration"].items()}
        for space in self.SPACES:
            order = [titles.get(k, k) for k in self.fake.policies[space]["integrations"]]
            tool = [t for t in order if t.startswith("wazuh4-")]
            self.assertEqual(order[:len(tool)], tool, space)            # the tool's integrations first
            self.assertEqual(order[len(tool):], ["wazuh-core", "customer-app"], space)  # the others keep their order
        self.assertEqual(self.fake.policies["draft"]["root_decoder"], did)

    def test_child_without_a_movable_test_stops(self):
        self.seed_root()
        rel = "integrations/wazuh4-acmepay/decoders/01-wazuh4-acmepay.json"
        self.edit_out(rel, lambda d: d["resource"].update(check="not_exists($process.name)"))
        out = self.apply(expect=2)
        self.assertIn("apply: stopped (RM-P-ROOT-CATCHALL)", out)
        self.assertIn("decoder/wazuh4-acmepay/0: its check (not_exists($process.name)) only tests", out)
        self.assertEqual(F.writes(self.fake), [])

    def test_out_rebuilt_after_a_shared_apply_is_not_checked_silently(self):
        self.seed_root()
        self.apply()
        rel = "integrations/wazuh4-acmepay/decoders/01-wazuh4-acmepay.json"
        self.edit_out(rel, lambda d: d["resource"].update(check="not_exists($process.name)"))
        state = State.load(self.work)
        out = SR.load_out(os.path.join(self.work, "out"), state)
        self.assertIn("no longer fits under the shared root", out.share_error)
        code, text = self.run_cmd("activate", "--yes", "--force")
        self.assertEqual(code, 2, text)
        self.assertIn("no longer fits under the shared root", text)

    def test_root_changed_after_a_shared_apply_stops(self):
        self.seed_root()
        self.apply()
        other = self.fake.seed("decoder", {"name": "decoder/customer-root/0", "metadata": {"author": "someone"}},
                               spaces=("draft",))
        self.fake.policies["draft"]["root_decoder"] = other
        n = len(self.fake.calls)
        out = self.apply(expect=2)
        self.assertIn("RM-P-ROOT-OWNED", out)
        self.assertIn("Run rollback, then apply again", out)
        self.assertEqual(F.writes(self.fake, n), [])

    def test_standard_root_updated_after_a_shared_apply_stops_with_its_own_text(self):
        did = self.seed_root()
        self.apply()
        self.fake.docs["draft"]["decoder"][did]["normalize"] = [{"map": [{"event.kind": "event"}]}]
        n = len(self.fake.calls)
        out = self.apply(expect=2)
        self.assertIn("apply: stopped (RM-P-ROOT-OWNED)", out)
        self.assertIn("has changed since apply", out)
        self.assertNotIn("migrate into a policy without", out)
        self.assertEqual(F.writes(self.fake, n), [])

    def test_root_in_draft_only_stops_as_a_foreign_policy_change(self):
        # the root was set in draft and never promoted: the promotion would carry someone else's policy change
        self.seed_root(spaces=("draft",))
        out = self.apply(expect=2)
        self.assertIn("RM-P-FOREIGN-POLICY-CHANGE", out)
        self.assertEqual(F.writes(self.fake), [])

    def test_no_policy_root_keeps_the_tool_root(self):
        self.apply()
        root = self.decoder("draft", TOOL_ROOT)
        self.assertIsNotNone(root)
        self.assertEqual(self.fake.policies["draft"]["root_decoder"], root["id"])
        self.assertNotIn("check", self.decoder("draft", PRE))
        self.assertIsNone(F.read_state(self.work).get("shared_root"))


class TestSharedActivate(SharedCase):
    SPACES = ("draft", "test", "custom")

    def test_activate_and_rollback_yes(self):
        did = self.seed_root()
        self.apply()
        code, out = self.run_cmd("activate", "--yes", "--force")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.fake.policies["custom"]["root_decoder"], did)
        self.assertIsNone(self.decoder("custom", TOOL_ROOT))
        self.assertEqual(self.decoder("custom", PRE)["parents"], [STOCK])
        self.assertGreater(self.owned("custom")["decoder"], 0)
        code, out = self.run_cmd("rollback", "--yes")
        self.assertEqual(code, 0, out)
        for space in ("draft", "test", "custom"):
            self.assertEqual(self.owned(space), {"integration": 0, "kvdb": 0, "decoder": 0, "rule": 0})
            self.assertEqual(self.fake.policies[space]["root_decoder"], did)
            self.assertIn(did, self.fake.docs[space]["decoder"])
        self.assertTrue(all(b["resource"]["root_decoder"] == did for b in self.policy_puts()))


class TestSharedActivateRootNotInCustom(SharedCase):
    # a fresh 5.x indexer seeds the root in draft and promotes it to test; custom does not have it
    def test_activate_stops_and_rollback_yes_stays_clean(self):
        did = self.seed_root()
        self.apply()
        n = len(self.fake.calls)
        code, out = self.run_cmd("activate", "--yes", "--force")
        self.assertEqual(code, 2, out)
        self.assertIn("RM-P-FOREIGN-POLICY-CHANGE", out)
        self.assertIn("root_decoder", out)
        self.assertEqual([w for w in F.writes(self.fake, n) if "promote" in w[1]], [])
        self.assertEqual(self.owned("custom")["decoder"], 0)
        code, out = self.run_cmd("rollback")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.fake.policies["test"]["root_decoder"], did)


class TestGate(unittest.TestCase):
    def test_drop_anchors(self):
        self.assertEqual(SR.drop_anchors(r"(?i)^acmepay$"), "(?i)acmepay")
        self.assertEqual(SR.drop_anchors(r"[^a$]x\$\^\Ay\z\b"), r"[^a$]x\$\^y")
        self.assertEqual(SR.drop_anchors(r"[[:alpha:]^]$"), r"[[:alpha:]^]")
        self.assertEqual(SR.drop_anchors(r"[]^]a"), r"[]^]a")

    def test_hoist(self):
        q = helper_quote
        self.assertEqual(SR.hoist("regex_match($process.name, %s)" % q(r"^sshd\d$")),
                         "regex_match($event.original, %s)" % q(r"sshd\d"))
        self.assertEqual(SR.hoist("not_exists($process.name) AND regex_match($message, %s)" % q("^{ \"")),
                         "regex_match($event.original, %s)" % q("{ \""))
        loc = "regex_match($wazuh.protocol.location, %s)" % q("^/var/log/x$")
        self.assertEqual(SR.hoist(loc), loc)
        self.assertIsNone(SR.hoist("NOT " + loc))
        self.assertIsNone(SR.hoist("not_exists($process.name)"))
        self.assertIsNone(SR.hoist("regex_match($message, %s) OR not_exists($process.name)" % q("a")))
        self.assertEqual(SR.hoist("(regex_match($message, %s) OR regex_match($message, %s))" % (q("^a"), q("b$"))),
                         "(regex_match($event.original, %s) OR regex_match($event.original, %s))" % (q("a"), q("b")))
        # nothing literal left, or \Q...\E: nothing can be kept
        self.assertIsNone(SR.hoist("regex_match($message, %s)" % q(r"^\S+")))
        self.assertIsNone(SR.hoist("regex_match($message, %s)" % q(r"^a?.*$")))
        self.assertIsNone(SR.hoist("regex_match($message, %s)" % q(r"\Q^x$\E")))
        # a quote and the word AND inside a literal do not split the check
        lit = q("x' AND y")
        self.assertEqual(SR.hoist("regex_match($message, %s)" % lit), "regex_match($event.original, %s)" % lit)

    def test_has_literal(self):
        self.assertTrue(SR.has_literal("(?i)acmepay"))
        self.assertTrue(SR.has_literal(r"\.x"))
        self.assertFalse(SR.has_literal(r"\S+\d{2,3}[a-z]"))
        self.assertFalse(SR.has_literal("(?i:a*)"))
        # every alternative needs a literal; optional groups, \p classes and whitespace give none
        for rx in (r"\S+ \S+ ", "^$|^ERROR", r"^(?:foo)?\d+", r"\pL+", "(ab|)", "a{0,3}"):
            self.assertFalse(SR.has_literal(SR.drop_anchors(rx)), rx)
        self.assertFalse(SR.has_literal("(?P<abc)x"))  # malformed: no answer, never a loop
        for rx in ("login |logout ", r"\p{Greek}x", "(?P<n>ab)|cd", "a{0,3}b", r"\|", "(?i)(?:^| )sudo"):
            self.assertTrue(SR.has_literal(SR.drop_anchors(rx)), rx)

    def test_gate(self):
        q = helper_quote
        one = "regex_match($process.name, %s)" % q("^a$")
        two = "regex_match($message, %s)" % q("^b")
        self.assertEqual(SR.gate([("d1", one)]), "regex_match($event.original, %s)" % q("a"))
        self.assertEqual(SR.gate([("d1", one), ("d2", two), ("d3", one)]),
                         "(regex_match($event.original, %s)) OR (regex_match($event.original, %s))" % (q("a"), q("b")))
        with self.assertRaises(SR.GateError) as cm:
            SR.gate([("d1", one), ("d2", None)])
        self.assertEqual(cm.exception.items, ["d2: no check, it accepts every event"])

    def test_compatibility_rule(self):
        out = Out(built_out())
        mine = SR.tool_root_resource(out)
        self.assertIsNone(SR.compatibility(STOCK_DOC, mine))
        self.assertIsNone(SR.compatibility(dict(STOCK_DOC, parents=[], check=""), mine))
        self.assertIn("parents", SR.compatibility(dict(STOCK_DOC, parents=["decoder/x/0"]), mine))
        self.assertIn("disabled", SR.compatibility(dict(STOCK_DOC, enabled=False), mine))
        self.assertIn("parse|event.original", SR.compatibility(dict(STOCK_DOC, **{"parse|event.original": ["<x>"]}),
                                                              mine))
        self.assertIn("not in the draft space", SR.compatibility(None, mine))

    def test_predecoder_name_matches_the_base(self):
        with open(os.path.join(TOOL, "rmig", "data", "wazuh4-base.json"), encoding="utf-8") as fh:
            base = json.load(fh)
        self.assertEqual(base["predecoder"], SR.PREDECODER)
        root = [d for d in base["decoders"] if d["resource"]["name"] == base["root"]][0]
        self.assertEqual(root["stock_name"], SR.STOCK_ROOT)
        self.assertEqual(root["resource"]["normalize"], STOCK_DOC["normalize"])

    def test_share_leaves_out_unchanged_on_a_stop(self):
        out = Out(built_out())
        n = len(out.by_local)
        acme = out.integration("wazuh4-acmepay")
        acme.decoders[0].resource = dict(acme.decoders[0].resource)
        acme.decoders[0].resource.pop("check", None)
        with self.assertRaises(SR.GateError):
            SR.share(out, STOCK)
        self.assertIsNotNone(out.root)
        self.assertEqual(len(out.by_local), n)


if __name__ == "__main__":
    unittest.main()
