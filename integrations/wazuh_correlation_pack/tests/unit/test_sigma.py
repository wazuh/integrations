import os
import sys
import tempfile
import textwrap
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, PACK)

from wcp import sigma as S  # noqa: E402
from wcp import query as Q  # noqa: E402

BASE = textwrap.dedent("""
    title: Test base
    id: 11111111-1111-4111-8111-111111111111
    name: t_base
    taxonomy: wcs
    logsource: {product: linux}
    detection:
      selection:
        process.name: [sshd, sshd-session]
        event.reason: Failed password
      filter:
        user.name|startswith: svc-
      condition: selection and not filter
""")

CORR = textwrap.dedent("""
    title: Test correlation
    id: 22222222-2222-4222-8222-222222222222
    name: t_corr
    correlation:
      type: event_count
      rules: [t_base]
      group-by: [wazuh.agent.id, source.ip]
      timespan: 2m
      condition: {gte: 8}
    level: high
""")


def write_pack(base=BASE, corr=CORR):
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "rules"))
    os.makedirs(os.path.join(d, "correlations"))
    with open(os.path.join(d, "rules", "b.yml"), "w") as fh:
        fh.write(base)
    with open(os.path.join(d, "correlations", "c.yml"), "w") as fh:
        fh.write(corr)
    return d


class TestLoad(unittest.TestCase):
    def test_valid_pack(self):
        rules, corrs = S.load_content(write_pack())
        self.assertEqual(len(rules), 1)
        c = corrs[0]
        self.assertEqual(c.type, "event_count")
        self.assertEqual(c.group_by, ["wazuh.agent.id", "source.ip"])
        self.assertEqual(c.timespan_s, 120)
        self.assertEqual(c.min_count, 8)
        self.assertIs(c.rules[0], rules[0])

    def test_gt_is_threshold_plus_one(self):
        _r, corrs = S.load_content(write_pack(corr=CORR.replace("gte: 8", "gt: 8")))
        self.assertEqual(corrs[0].min_count, 9)

    def test_rule_reference_by_id(self):
        _r, corrs = S.load_content(write_pack(corr=CORR.replace("[t_base]", "[11111111-1111-4111-8111-111111111111]")))
        self.assertEqual(corrs[0].rules[0].name, "t_base")

    def test_value_count_requires_field(self):
        bad = CORR.replace("event_count", "value_count")
        with self.assertRaisesRegex(S.SigmaError, "requires condition.field"):
            S.load_content(write_pack(corr=bad))

    def test_value_count_field_not_in_group_by(self):
        bad = CORR.replace("event_count", "value_count").replace("{gte: 8}", "{field: source.ip, gte: 3}")
        with self.assertRaisesRegex(S.SigmaError, "must not also be a group-by"):
            S.load_content(write_pack(corr=bad))

    def test_rejections(self):
        cases = [
            (CORR.replace("event_count", "temporal"), "temporal correlations"),
            (CORR.replace("event_count", "temporal_ordered"), "ordered sequences"),
            (CORR.replace("event_count", "value_sum"), "value_sum"),
            (CORR.replace("{gte: 8}", "{lt: 8}"), "not supported"),
            (CORR.replace("{gte: 8}", "{eq: 8}"), "not supported"),
            (CORR.replace("{gte: 8}", "{gte: 8, gt: 9}"), "exactly one operator"),
            (CORR.replace("timespan: 2m", "timespan: 2 minutes"), "timespan"),
            (CORR.replace("timespan: 2m", "timespan: 0m"), "timespan"),
            (CORR.replace("[t_base]", "[nope]"), "not found"),
            (CORR + "generate: true\n", "generate"),
            (CORR.replace("  type: event_count", "  type: event_count\n  aliases: {x: {t_base: user.name}}"), "aliases"),
        ]
        for corr, msg in cases:
            with self.assertRaisesRegex(S.SigmaError, msg, msg=corr):
                S.load_content(write_pack(corr=corr))

    def test_base_rejections(self):
        cases = [
            (BASE.replace("taxonomy: wcs", "taxonomy: sigma"), "taxonomy"),
            (BASE.replace("event.reason: Failed password", "event.reason|re: 'Failed.*'"), "modifier"),
            (BASE.replace("selection and not filter", "1 of selection*"), "not supported"),
            (BASE.replace("selection and not filter", "selection | count() > 5"), "aggregation"),
            (BASE.replace("selection and not filter", "selection and other"), "unknown selection"),
            (BASE.replace("event.reason: Failed password", "event.reason: Failed*"), "wildcards"),
        ]
        for base, msg in cases:
            with self.assertRaisesRegex(S.SigmaError, msg, msg=base):
                S.load_content(write_pack(base=base))

    def test_chained_correlation_rejected(self):
        d = write_pack()
        with open(os.path.join(d, "correlations", "d.yml"), "w") as fh:
            fh.write(CORR.replace("t_corr", "t_corr2").replace("[t_base]", "[t_corr]")
                     .replace("22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"))
        with self.assertRaisesRegex(S.SigmaError, "chained"):
            S.load_content(d)


class TestQuery(unittest.TestCase):
    def test_compile(self):
        rules, _c = S.load_content(write_pack())
        q = Q.rule_query(rules[0])
        self.assertEqual(q, {"bool": {"filter": [
            {"bool": {"filter": [
                {"terms": {"process.name": ["sshd", "sshd-session"]}},
                {"term": {"event.reason": "Failed password"}}]}},
            {"bool": {"must_not": [{"prefix": {"user.name": {"value": "svc-"}}}]}},
        ]}})

    def test_modifiers(self):
        self.assertEqual(Q._item_query("a", ("contains",), ["x*y"]), {"wildcard": {"a": {"value": "*x\\*y*"}}})
        self.assertEqual(Q._item_query("a", ("endswith",), ["$"]), {"wildcard": {"a": {"value": "*$"}}})
        self.assertEqual(Q._item_query("a", ("exists",), [False]), {"bool": {"must_not": [{"exists": {"field": "a"}}]}})
        self.assertEqual(Q._item_query("a", ("contains", "all"), ["x", "y"]),
                         {"bool": {"filter": [{"wildcard": {"a": {"value": "*x*"}}}, {"wildcard": {"a": {"value": "*y*"}}}]}})
        self.assertEqual(Q._item_query("event.code", (), [4625]), {"term": {"event.code": 4625}})

    def test_condition_precedence(self):
        tree = S.parse_condition("a or b and not c", {"a", "b", "c"}, "t")
        self.assertEqual(tree, ("or", [("sel", "a"), ("and", [("sel", "b"), ("not", ("sel", "c"))])]))
        tree = S.parse_condition("(a or b) and c", {"a", "b", "c"}, "t")
        self.assertEqual(tree, ("and", [("or", [("sel", "a"), ("sel", "b")]), ("sel", "c")]))


if __name__ == "__main__":
    unittest.main()
