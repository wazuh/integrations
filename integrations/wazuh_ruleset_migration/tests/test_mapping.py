"""``out/mapping.{json,csv}``: one row per 4.x rule of the
inventory, the same in both files, ``server_id`` empty until ``apply``."""

import csv
import io
import os
import unittest

from helpers import DATA

from rmig import decisions as D
from rmig import emit
from rmig.scan import scan
from rmig.translate import pipeline
from test_build import SAMPLE_DECISIONS

SAMPLE = os.path.join(DATA, "sample-etc")
FIELDS = ["rule_id_4x", "state", "reasons", "integration", "resource_title", "local_id", "server_id"]


class TestMapping(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        inv = scan(SAMPLE)
        dec = D.empty()
        for section, entries in SAMPLE_DECISIONS.items():
            for key, entry in entries.items():
                dec[section][key] = dict(entry)
        cls.inv = inv
        cls.res = pipeline.compute(inv, dec, source=SAMPLE)
        cls.files = emit.render(cls.res["package"], inv)

    def test_one_row_per_rule_in_both_files(self):
        import json
        data = json.loads(self.files["mapping.json"])
        self.assertEqual(data["fields"], FIELDS)
        rows = data["rows"]
        self.assertEqual(len(rows), len(self.inv["rules"]))
        reader = csv.DictReader(io.StringIO(self.files["mapping.csv"]))
        self.assertEqual(reader.fieldnames, FIELDS)
        csv_rows = list(reader)
        self.assertEqual(len(csv_rows), len(rows))
        for j, c in zip(rows, csv_rows):
            self.assertEqual(c["reasons"], ";".join(j["reasons"]))
            for f in FIELDS:
                if f != "reasons":
                    self.assertEqual(c[f], j[f])
            self.assertEqual(j["server_id"], "")

    def test_rows_point_at_the_emitted_resources(self):
        import json
        rows = {r["rule_id_4x"]: r for r in json.loads(self.files["mapping.json"])["rows"]}
        r = rows["100201"]
        self.assertEqual(r["state"], "AUTO")
        self.assertEqual(r["integration"], "wazuh4-acmepay")
        doc = json.loads(self.files["integrations/wazuh4-acmepay/rules/100201.json"])
        self.assertEqual(r["local_id"], doc["local_id"])
        self.assertEqual(r["resource_title"], doc["resource"]["metadata"]["title"])
        self.assertEqual(rows["100300"]["integration"], "wazuh4-on-system-auth")
        for rid in ("100200", "100202", "100203"):  # grouping, silencer, recipe: nothing emitted
            self.assertEqual(rows[rid]["local_id"], "", rid)
            self.assertEqual(rows[rid]["resource_title"], "", rid)
        self.assertEqual(rows["100203"]["state"], "RECIPE")
        self.assertIn("RM-R-FREQUENCY", rows["100203"]["reasons"])

    def test_local_ids_are_stable(self):
        import json
        again = emit.render(pipeline.compute(self.inv, self.res["decisions"], source=SAMPLE)["package"], self.inv)
        self.assertEqual(json.loads(again["mapping.json"]), json.loads(self.files["mapping.json"]))


if __name__ == "__main__":
    unittest.main()
