"""same input, files listed in reverse order, other locale and
time zone => byte-identical outputs."""

import contextlib
import hashlib
import io
import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

from helpers import CORPUS, MYAPP_DECODER, etc_tree, rules_xml

from rmig import cli

_real_listdir = os.listdir


def _reversed_listdir(path="."):
    return list(reversed(sorted(_real_listdir(path))))


def _digest_tree(root):
    out = {}
    for base, _dirs, files in os.walk(root):
        for name in files:
            full = os.path.join(base, name)
            with open(full, "rb") as fh:
                out[os.path.relpath(full, root)] = hashlib.sha256(fh.read()).hexdigest()
    return out


def _run(source, work, reverse):
    sink = io.StringIO()
    ctx = mock.patch("os.listdir", _reversed_listdir) if reverse else contextlib.nullcontext()
    env = {"TZ": "Pacific/Kiritimati" if reverse else "UTC", "LC_ALL": "C" if reverse else "C.UTF-8"}
    with ctx, mock.patch.dict(os.environ, env), contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        if hasattr(time, "tzset"):
            time.tzset()
        assert cli.main(["scan", "--source", source, "--workdir", work]) == 0
        assert cli.main(["plan", "--workdir", work]) in (0, 1)
    if hasattr(time, "tzset"):
        time.tzset()
    return _digest_tree(work)


class TestDeterminism(unittest.TestCase):
    def check(self, source):
        a = tempfile.mkdtemp(prefix="rmig-det-a-")
        b = tempfile.mkdtemp(prefix="rmig-det-b-")
        try:
            da = _run(source, a, reverse=False)
            db = _run(source, b, reverse=True)
        finally:
            shutil.rmtree(a, ignore_errors=True)
            shutil.rmtree(b, ignore_errors=True)
        self.assertEqual(sorted(da), ["decisions.json", "report.json", "report.md",
                                      os.path.join("work", "inventory.json"), os.path.join("work", "plan.json")])
        self.assertEqual(da, db)

    def test_synthetic_tree(self):
        tree = etc_tree(
            decoders={"myapp.xml": MYAPP_DECODER, "other.xml": '<decoder name="other"><prematch>^other</prematch></decoder>\n'},
            rules={"local_rules.xml": rules_xml("local,", """
  <rule id="100100" level="5"><decoded_as>myapp</decoded_as><field name="myapp.user">x</field><description>a</description></rule>
  <rule id="100101" level="0"><if_sid>100100</if_sid><match>quiet</match><description>s</description></rule>
  <rule id="100102" level="6"><if_sid>100100</if_sid><match>b</match><description>b</description></rule>"""),
                   "a_rules.xml": rules_xml("a,", """
  <rule id="100200" level="3"><if_group>authentication_failed</if_group><description>g</description></rule>""")},
            lists={"mylist": "a:b\n", "sub/other": "10.:x\n"},
            extra_ruleset="<list>etc/lists/mylist</list>")
        try:
            self.check(tree.root)
        finally:
            tree.cleanup()

    def test_public_corpus(self):
        if not os.path.isdir(CORPUS):
            self.skipTest("public corpus not found at %s" % CORPUS)
        self.check(CORPUS)

    def test_no_absolute_paths_in_outputs(self):
        tree = etc_tree(rules={"local_rules.xml": rules_xml("local,", '<rule id="100001" level="3"><if_sid>5716</if_sid><description>x</description></rule>')})
        work = tempfile.mkdtemp(prefix="rmig-det-")
        try:
            _run(tree.root, work, reverse=False)
            for name in ("work/inventory.json", "work/plan.json", "report.json", "report.md", "decisions.json"):
                with open(os.path.join(work, name), encoding="utf-8") as fh:
                    text = fh.read()
                self.assertNotIn(tree.root, text, name)
                self.assertNotIn("\r", text)
        finally:
            tree.cleanup()
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
