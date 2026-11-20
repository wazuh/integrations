"""Golden cases of the rule translation.

Each case is ``tests/golden/<case>/`` with:

``in/``
    a 4.14 ``etc/`` copy (``ossec.conf``, ``rules/``, ``decoders/``, ``lists/``)
    and, optionally, ``in/decisions.json`` (copied to the working directory);
``expected/out/``
    the whole ``out/`` that ``build`` must write, byte for byte;
``expected/states.json``
    the final state of every item (``ref@line`` -> state).

``RMIG_UPDATE_GOLDEN=1`` rewrites ``expected/`` from the current output (review
the diff before committing it).
"""

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest

from helpers import HERE

from rmig import cli

GOLDEN = os.path.join(HERE, "golden")
UPDATE = os.environ.get("RMIG_UPDATE_GOLDEN") == "1"


def _tree(root):
    out = {}
    for base, _dirs, files in os.walk(root):
        for name in files:
            full = os.path.join(base, name)
            with open(full, "rb") as fh:
                out[os.path.relpath(full, root).replace(os.sep, "/")] = fh.read()
    return out


def run_case(name, build_args=()):
    """Run scan + build on a golden case. Returns (workdir, states, rc).
    ``build_args``: extra arguments of ``build`` (``--engine-helpers``)."""
    case = os.path.join(GOLDEN, name)
    tmp = tempfile.mkdtemp(prefix="rmig-golden-src-")
    src = os.path.join(tmp, name)  # the source name goes into manifest.json
    work = tempfile.mkdtemp(prefix="rmig-golden-work-")
    shutil.copytree(os.path.join(case, "in"), src, ignore=shutil.ignore_patterns("decisions.json"))
    dpath = os.path.join(case, "in", "decisions.json")
    sink = io.StringIO()
    with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        rc = cli.main(["scan", "--source", src, "--workdir", work])
        assert rc == 0, sink.getvalue()
        if os.path.exists(dpath):
            rc = cli.main(["plan", "--workdir", work])  # merges the generated entries
            with open(dpath, encoding="utf-8") as fh:
                wanted = json.load(fh)
            with open(os.path.join(work, "decisions.json"), encoding="utf-8") as fh:
                current = json.load(fh)
            for section, entries in wanted.items():
                if isinstance(entries, dict):
                    for key, entry in entries.items():
                        current.setdefault(section, {}).setdefault(key, {}).update(entry)
            with open(os.path.join(work, "decisions.json"), "w", encoding="utf-8") as fh:
                json.dump(current, fh, indent=2)
        rc = cli.main(["build", "--workdir", work, "--source", src] + list(build_args))
    with open(os.path.join(work, "work", "plan.json"), encoding="utf-8") as fh:
        plan = json.load(fh)
    states = {"%s@%d" % (it["ref"], it["line"]): it["state"] for it in plan["items"]}
    shutil.rmtree(tmp, ignore_errors=True)
    return work, states, rc, sink.getvalue()


class GoldenCase(unittest.TestCase):
    """Subclasses set ``CASE``."""

    CASE = None

    @classmethod
    def setUpClass(cls):
        if cls.CASE is None:
            raise unittest.SkipTest("base class")
        cls.work, cls.states, cls.rc, cls.log = run_case(cls.CASE)
        cls.out = os.path.join(cls.work, "out")
        expected = os.path.join(GOLDEN, cls.CASE, "expected")
        if UPDATE:
            shutil.rmtree(expected, ignore_errors=True)
            shutil.copytree(cls.out, os.path.join(expected, "out"))
            with open(os.path.join(expected, "states.json"), "w", encoding="utf-8") as fh:
                fh.write(json.dumps(cls.states, sort_keys=True, indent=2) + "\n")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "work", None):
            shutil.rmtree(cls.work, ignore_errors=True)

    def expected_dir(self):
        return os.path.join(GOLDEN, self.CASE, "expected")

    def test_out_matches_golden(self):
        got = _tree(self.out)
        want = _tree(os.path.join(self.expected_dir(), "out"))
        self.assertEqual(sorted(got), sorted(want))
        for rel in sorted(want):
            self.assertEqual(got[rel].decode("utf-8"), want[rel].decode("utf-8"), rel)

    def test_states_match_golden(self):
        with open(os.path.join(self.expected_dir(), "states.json"), encoding="utf-8") as fh:
            self.assertEqual(self.states, json.load(fh))

    # helpers for the specific assertions
    def json(self, rel):
        with open(os.path.join(self.out, rel), encoding="utf-8") as fh:
            return json.load(fh)

    def exists(self, rel):
        return os.path.exists(os.path.join(self.out, rel))

    def rule(self, key, rid):
        return self.json("integrations/%s/rules/%s.json" % (key, rid))


class T4Flatten(GoldenCase):
    """Child of 5710 (child of 5700): one self-contained rule; the stock
    chain contributes the selection of the equivalence (decisions.json)."""

    CASE = "t04-flatten-stock-chain"

    def test_one_rule_in_the_on_stock_integration(self):
        man = self.json("manifest.json")
        self.assertEqual(man["integrations"], ["wazuh4-on-system-auth"])
        self.assertIsNone(man["root_decoder"])  # rules only: no decoders, no base
        det = self.rule("wazuh4-on-system-auth", "100010")["resource"]["detection"]
        self.assertEqual(det["condition"], "selection")
        sel = det["selection"]
        self.assertEqual(sel["wazuh.integration.name"], "system-auth")
        self.assertEqual(sel["event.action"], "authentication-failure")
        self.assertEqual(sel["message|re"], ".*[Ss][Ss][Hh]2.*")
        integ = self.json("integrations/wazuh4-on-system-auth/integration.json")
        self.assertEqual(integ["kind"], "on-stock")
        self.assertEqual(integ["stock_integration"], "system-auth")
        self.assertEqual(integ["resource"]["category"], "system-activity")


class T5Negate(GoldenCase):
    CASE = "t05-negate"

    def test_exists_and_not(self):
        det = self.rule("wazuh4-myapp", "100100")["resource"]["detection"]
        self.assertEqual(det["condition"], "selection and not filter and not filter_2")
        self.assertIs(det["selection"]["user.name|exists"], True)
        self.assertIs(det["selection"]["source.ip|exists"], True)
        self.assertEqual(det["filter"], {"user.name|re": ["[Rr][Oo][Oo][Tt]", "[Aa][Dd][Mm][Ii][Nn]"]})
        self.assertEqual(det["filter_2"], {"source.ip|cidr": "192.168.0.0/16"})


class T6Titles(GoldenCase):
    CASE = "t06-title-suffix"

    def test_suffix_on_both(self):
        a = self.rule("wazuh4-myapp", "100100")
        b = self.rule("wazuh4-myapp", "100101")
        self.assertEqual(a["resource"]["metadata"]["title"], "myapp: login failed (4.x rule 100100)")
        self.assertEqual(b["resource"]["metadata"]["title"], "myapp: login failed (4.x rule 100101)")
        self.assertIn("RM-R-TITLE-SUFFIXED", a["reasons"])
        self.assertIn("RM-R-TITLE-SUFFIXED", b["reasons"])
        c = self.rule("wazuh4-myapp", "100102")
        self.assertEqual(c["resource"]["metadata"]["title"], "myapp: user {{ user.name }} ran {{ event.action }}")


class T7Patterns(GoldenCase):
    CASE = "t07-patterns"

    def test_letter_classes_and_dialect(self):
        res = self.rule("wazuh4-on-system-auth", "100020")
        sel = res["resource"]["detection"]["selection"]
        self.assertEqual(sel["message|re"], ".*[Ii][Nn][Vv][Aa][Ll][Ii][Dd].[Uu][Ss][Ee][Rr].*")
        self.assertEqual(res["fidelity"], "approximate")
        self.assertIn("RM-R-RE-DIALECT", res["reasons"])
        res = self.rule("wazuh4-on-system-auth", "100021")
        sel = res["resource"]["detection"]["selection"]
        self.assertEqual(sel["message|re"], ".*[Uu][Ss][Ee][Rr].([-A-Za-z0-9_@]+).[Ff][Rr][Oo][Mm].([!-~]+).*")
        res = self.rule("wazuh4-on-system-auth", "100022")
        self.assertEqual(res["resource"]["detection"]["selection"]["message|startswith"], ["Accepted", "Failed"])
        self.assertNotIn("RM-R-RE-DIALECT", res["reasons"])  # a PCRE2 literal is exact


class T9Silencer(GoldenCase):
    CASE = "t09-silencer"

    def test_exclusion_in_grandmother_mother_and_sister(self):
        excl = {"message|re": ".*[Cc].*"}
        for rid in ("100100", "100101", "100103", "100104"):
            det = self.rule("wazuh4-myapp", rid)["resource"]["detection"]
            self.assertIn("not", det["condition"], rid)
            filters = [v for k, v in det.items() if k.startswith("filter")]
            self.assertTrue(any(f.get("message|re") == excl["message|re"] or f == excl for f in filters), rid)
        self.assertFalse(self.exists("integrations/wazuh4-myapp/rules/100102.json"))  # the silencer itself


class T11Frequency(GoldenCase):
    CASE = "t11-frequency"

    def test_monitor_and_children(self):
        mon = self.json("monitors/100200.json")
        query = mon["inputs"][0]["search"]["query"]
        flt = query["query"]["bool"]["filter"]
        self.assertIn({"term": {"tags": "wazuh4.rule.100100"}}, flt)
        rng = [f for f in flt if "range" in f][0]["range"]["@timestamp"]
        self.assertEqual(rng["gte"], "{{period_end}}||-300s")
        fields = [list(s.values())[0]["terms"]["field"] for s in query["aggregations"]["by_group"]["composite"]["sources"]]
        self.assertEqual(fields, ["wazuh.agent.name", "source.ip"])
        trig = mon["triggers"][0]["bucket_level_trigger"]["condition"]["script"]["source"]
        self.assertEqual(trig, "params.count >= 8")
        self.assertEqual(self.states["rule:100200@10"], "RECIPE")
        self.assertEqual(self.states["rule:100201@15"], "RECIPE")
        self.assertEqual(self.states["rule:100301@26"], "AUTO")
        self.assertTrue(self.exists("recipes/rule-100200.md"))
        self.assertTrue(self.exists("recipes/rule-100201.md"))
        self.assertFalse(self.exists("monitors/100201.json"))


if __name__ == "__main__":
    unittest.main()
