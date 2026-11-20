"""``build`` and ``migrate`` on the demo sample (``tests/data/sample-etc``, a
copy of the sample ``/etc`` tree used for demos):

* without decisions only the ``AUTO`` items reach ``out/``;
* with a test ``decisions.json`` everything translatable does;
* two builds give the same sha256 of every file;
* ``out/`` follows the documented ``out/`` layout.
"""

import contextlib
import hashlib
import io
import json
import os
import shutil
import tempfile
import unittest

from helpers import DATA

from rmig import cli
from test_decoders_golden import unprefixed_references

SAMPLE = os.path.join(DATA, "sample-etc")

SAMPLE_DECISIONS = {
    "fields": {
        "acmepay.amount": {"action": "drop"},
        "acmepay.currency": {"action": "map", "wcs": "event.reason"},
        "acmepay.merchant": {"action": "map", "wcs": "service.name"},
        "acmepay.tenant": {"action": "map", "wcs": "organization.name"},
    },
    "stock": {"rule:5716": {"integration": "system-auth", "selection": {"event.action": "authentication-failure"}}},
}


def quiet(*argv):
    sink = io.StringIO()
    with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        rc = cli.main(list(argv))
    return rc, sink.getvalue()


def digest(root):
    out = {}
    for base, _d, files in os.walk(root):
        for name in files:
            full = os.path.join(base, name)
            with open(full, "rb") as fh:
                out[os.path.relpath(full, root)] = hashlib.sha256(fh.read()).hexdigest()
    return out


def apply_decisions(work, wanted):
    path = os.path.join(work, "decisions.json")
    with open(path, encoding="utf-8") as fh:
        cur = json.load(fh)
    for section, entries in wanted.items():
        for key, entry in entries.items():
            cur.setdefault(section, {}).setdefault(key, {}).update(entry)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(cur, fh, indent=2)


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


class BuildCase(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="rmig-build-")

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def out(self, *parts):
        return os.path.join(self.work, "out", *parts)

    def states(self):
        plan = load(os.path.join(self.work, "work", "plan.json"))
        return {it["ref"]: it for it in plan["items"]}


class TestWithoutDecisions(BuildCase):
    def test_only_auto_items_are_emitted(self):
        rc, log = quiet("migrate", "--source", SAMPLE, "--workdir", self.work)
        self.assertEqual(rc, 1, log)  # DECISION items pending
        items = self.states()
        mapping = load(self.out("mapping.json"))["rows"]
        emitted = {r["rule_id_4x"] for r in mapping if r["local_id"]}
        # the currency, tenant and merchant fields have no WCS field yet: the decoders check them
        self.assertEqual(emitted, {"100201", "100204", "100205", "100206"})
        for r in mapping:
            if r["local_id"]:
                self.assertEqual(r["state"], "AUTO")
                self.assertTrue(os.path.exists(self.out("integrations", r["integration"], "rules", r["rule_id_4x"] + ".json")))
        self.assertEqual(items["decoder:acmepay-login"]["state"], "AUTO")
        self.assertEqual(items["rule:100300"]["state"], "DECISION")  # stock rule 5716 waits
        decs = sorted(os.listdir(self.out("integrations", "wazuh4-acmepay", "decoders")))
        self.assertEqual(decs, ["01-wazuh4-acmepay.json", "02-wazuh4-acmepay-login.json",
                                "03-wazuh4-acmepay-payment.json"])
        self.assertTrue(os.path.exists(self.out("monitors", "100203.json")))
        self.assertTrue(os.path.exists(self.out("recipes", "rule-100203.md")))
        self.assertNotIn("RM-X-PROVISIONAL-AUTO", json.dumps(load(os.path.join(self.work, "report.json"))["summary"]))


class TestWithDecisions(BuildCase):
    def setUp(self):
        super().setUp()
        rc, log = quiet("migrate", "--source", SAMPLE, "--workdir", self.work)
        apply_decisions(self.work, SAMPLE_DECISIONS)
        self.rc, self.log = quiet("build", "--workdir", self.work, "--source", SAMPLE)

    def test_everything_translatable_is_emitted(self):
        self.assertEqual(self.rc, 0, self.log)
        items = self.states()
        expected = {
            "rule:100200": "NOT_APPLICABLE", "rule:100201": "AUTO", "rule:100202": "AUTO", "rule:100203": "RECIPE",
            "rule:100204": "AUTO", "rule:100205": "AUTO", "rule:100206": "AUTO", "rule:100300": "AUTO",
            "decoder:acmepay": "AUTO", "decoder:acmepay-login": "AUTO", "decoder:acmepay-payment": "AUTO",
            "list:etc/lists/blocked-ips": "AUTO", "list:etc/lists/audit-keys": "NOT_APPLICABLE",
        }
        self.assertEqual({k: v["state"] for k, v in items.items()}, expected)
        man = load(self.out("manifest.json"))
        self.assertEqual(man["integrations"], ["wazuh4-base", "wazuh4-acmepay", "wazuh4-on-system-auth"])
        self.assertEqual(man["root_decoder"]["integration"], "wazuh4-base")
        rules = sorted(os.listdir(self.out("integrations", "wazuh4-acmepay", "rules")))
        self.assertEqual(rules, ["100201.json", "100204.json", "100205.json", "100206.json"])
        self.assertEqual(os.listdir(self.out("integrations", "wazuh4-on-system-auth", "rules")), ["100300.json"])
        kv = load(self.out("integrations", "wazuh4-acmepay", "kvdbs", "wazuh4-blocked-ips.json"))
        self.assertEqual(kv["resource"]["content"]["203.0.113.7"], "scanner")
        self.assertEqual(unprefixed_references(self.out()), [])

    def test_silencer_exclusion_and_partial_recipe(self):
        det = load(self.out("integrations", "wazuh4-acmepay", "rules", "100201.json"))["resource"]["detection"]
        self.assertEqual(det["condition"], "selection and not filter")
        self.assertEqual(det["filter"]["user.name|re"], "[Hh][Ee][Aa][Ll][Tt][Hh][Cc][Hh][Ee][Cc][Kk]")
        with open(self.out("recipes", "rule-100203.md"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("## Starting point", text)
        self.assertIn("monitors/100203.json", text)

    def test_two_builds_are_identical(self):
        first = digest(self.out())
        rc, log = quiet("build", "--workdir", self.work, "--source", SAMPLE)
        self.assertEqual(rc, 0, log)
        self.assertEqual(digest(self.out()), first)

    def test_contract_shape(self):
        for base, _d, files in os.walk(self.out()):
            for name in files:
                path = os.path.join(base, name)
                with open(path, encoding="utf-8") as fh:
                    text = fh.read()
                self.assertTrue(text.endswith("\n"), path)
                self.assertNotIn("\r", text)
                if name.endswith(".json"):
                    data = json.loads(text)
                    self.assertEqual(text, json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False) + "\n", path)
        for key in load(self.out("manifest.json"))["integrations"]:
            integ = load(self.out("integrations", key, "integration.json"))
            self.assertEqual(set(integ), {"local_id", "kind", "stock_integration", "resource"})
            self.assertIn(integ["kind"], ("base", "custom", "on-stock"))
            meta = integ["resource"]["metadata"]
            self.assertEqual(meta["author"], "wazuh-ruleset-migration")
            self.assertIn("wazuh4-migration:%s" % integ["local_id"], meta["references"])
            for sub in ("kvdbs", "decoders", "rules"):
                d = self.out("integrations", key, sub)
                for name in (sorted(os.listdir(d)) if os.path.isdir(d) else []):
                    doc = load(os.path.join(d, name))
                    self.assertEqual(set(doc), {"local_id", "source", "fidelity", "reasons", "resource"}, name)
                    self.assertIn(doc["fidelity"], ("exact", "approximate"))
                    m = doc["resource"]["metadata"]
                    self.assertEqual(m["author"], "wazuh-ruleset-migration", name)
                    self.assertEqual(m["references"][0], "wazuh4-migration:%s" % doc["local_id"], name)
                    if sub == "decoders":
                        self.assertRegex(name, r"^\d{2}-wazuh4-[A-Za-z0-9._-]+\.json$")
                        self.assertTrue(doc["resource"]["name"].startswith("decoder/wazuh4-"))
                    if sub == "rules":
                        r = doc["resource"]
                        self.assertEqual(r["status"], "experimental")
                        self.assertEqual(r["logsource"]["product"], meta_title(self, key))
                        self.assertIn("wazuh4.rule.%s" % name[:-5], r["tags"])
                        self.assertIn("Migrated from Wazuh 4.x rule %s (etc/rules/local_rules.xml)" % name[:-5], m["references"])
        for name in os.listdir(self.out("detectors")):
            det = load(self.out("detectors", name))
            self.assertEqual(set(det), {"name", "integration", "category", "index", "rules"})
            self.assertEqual(det["index"], "wazuh-events-v5-%s" % det["category"])
            self.assertLessEqual(len(det["rules"]), 50)

    def test_part_c_reader_accepts_out(self):
        try:
            from rmig.api.outdir import Out
        except ImportError:  # pragma: no cover - part C not present
            self.skipTest("rmig.api.outdir not available")
        out = Out(self.out())
        self.assertEqual([i.key for i in out.integrations], ["wazuh4-base", "wazuh4-acmepay", "wazuh4-on-system-auth"])
        fields, rows = out.mapping_rows()
        self.assertEqual(fields, ["rule_id_4x", "state", "reasons", "integration", "resource_title", "local_id", "server_id"])
        self.assertEqual(len(rows), 8)


def meta_title(test, key):
    return load(test.out("integrations", key, "integration.json"))["resource"]["metadata"]["title"]


class TestBuildNeedsTheSourceForLists(BuildCase):
    def test_lists_without_source_is_a_usage_error(self):
        quiet("migrate", "--source", SAMPLE, "--workdir", self.work)
        apply_decisions(self.work, SAMPLE_DECISIONS)
        rc, log = quiet("build", "--workdir", self.work)
        self.assertEqual(rc, 2)
        self.assertIn("pass --source", log)

    def test_build_without_scan(self):
        rc, log = quiet("build", "--workdir", self.work)
        self.assertEqual(rc, 2)
        self.assertIn("run scan first", log)


class TestStatsWhatIf(BuildCase):
    def test_what_if_section(self):
        quiet("migrate", "--source", SAMPLE, "--workdir", self.work)
        rc, text = quiet("stats", "--workdir", self.work)
        self.assertEqual(rc, 0)
        self.assertIn("What-if", text)
        self.assertIn("rule:5716", text)
        row = [ln for ln in text.splitlines() if ln.startswith("1 ")][0].split()
        self.assertEqual(row[1], "1")  # rule 100300 leaves DECISION with an entry for 5716


if __name__ == "__main__":
    unittest.main()
