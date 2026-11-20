"""Shared helpers for the tests (no network, no absolute paths required)."""

import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.dirname(HERE)
if TOOL not in sys.path:
    sys.path.insert(0, TOOL)

from rmig import decisions as D  # noqa: E402
from rmig import stock as _stock  # noqa: E402
from rmig import planner  # noqa: E402
from rmig.scan import scan  # noqa: E402

DATA = os.path.join(HERE, "data")
STOCK_MINI = os.path.join(DATA, "stock-mini")
# Full 4.14.13 tree (with ruleset/) and the public corpus; tests that need them
# skip when they are absent. Override with RMIG_STOCK_DIR / RMIG_CORPUS_DIR.
STOCK_FULL = os.environ.get("RMIG_STOCK_DIR", "")  # a checkout of wazuh 4.14.x (ruleset/, etc/); tests that need it skip without it
CORPUS = os.environ.get("RMIG_CORPUS_DIR", "")  # a public custom ruleset tree; tests that need it skip without it

# Every test runs against the synthetic stock ruleset unless it activates another one.
STOCK_INDEX = _stock.use_stock_dir(STOCK_MINI)


def use_full_stock():
    """Activate the real 4.x ruleset of RMIG_STOCK_DIR (skip without it); returns the index."""
    if not STOCK_FULL or _stock.ruleset_dir(STOCK_FULL) is None:
        raise unittest.SkipTest("RMIG_STOCK_DIR (a 4.14 checkout with ruleset/) is not set")
    return _stock.use_stock_dir(STOCK_FULL)

DEFAULT_RULESET = """<ossec_config>
  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    %(extra)s
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>
</ossec_config>
"""

MYAPP_DECODER = """<decoder name="myapp">
  <program_name>myapp</program_name>
</decoder>
<decoder name="myapp-fields">
  <parent>myapp</parent>
  <regex>user=(\\S+) action=(\\w+)</regex>
  <order>myapp.user, action</order>
</decoder>
"""


def need_dir(path, what):
    if not os.path.isdir(path):
        raise unittest.SkipTest("%s not found at %s (set the environment variable to run this test)" % (what, path))


class TempTree:
    """A temporary 4.14 tree built from a dict of relative path -> text."""

    def __init__(self, files):
        self.root = tempfile.mkdtemp(prefix="rmig-test-")
        for rel, text in files.items():
            path = os.path.join(self.root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            mode = "wb" if isinstance(text, bytes) else "w"
            with open(path, mode) as fh:
                fh.write(text)

    def path(self, *parts):
        return os.path.join(self.root, *parts)

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


def etc_tree(rules=None, decoders=None, lists=None, extra_ruleset="", conf=None):
    """An ``etc/`` copy: ossec.conf + rules/ + decoders/ + lists/."""
    files = {"ossec.conf": conf if conf is not None else DEFAULT_RULESET % {"extra": extra_ruleset}}
    for name, text in (rules or {}).items():
        files["rules/" + name] = text
    for name, text in (decoders or {}).items():
        files["decoders/" + name] = text
    for name, text in (lists or {}).items():
        files["lists/" + name] = text
    return TempTree(files)


def compute(source, decisions=None):
    inv = scan(source)
    return planner.compute(inv, decisions if decisions is not None else D.empty())


def items_by_ref(result):
    out = {}
    for it in result["plan"]["items"]:
        out.setdefault(it["ref"], []).append(it)
    return out


def one(result, ref):
    found = items_by_ref(result).get(ref, [])
    if len(found) != 1:
        raise AssertionError("expected one item %s, found %d" % (ref, len(found)))
    return found[0]


def codes(item):
    return {c["code"] for c in item["codes"]}


def rules_xml(group, body):
    return '<group name="%s">\n%s\n</group>\n' % (group, body)
