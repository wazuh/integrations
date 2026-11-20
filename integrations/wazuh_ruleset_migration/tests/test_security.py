"""Hostile input: names from the input never leave the work directory, secrets never reach the output,
the client never follows a redirect, hostile patterns never hang the local reader."""

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest

from helpers import DATA, etc_tree, rules_xml

from rmig import cli, emit
from rmig.translate import meta

SAMPLE = os.path.join(DATA, "sample-etc")


def quiet(*argv):
    sink = io.StringIO()
    with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        rc = cli.main(list(argv))
    return rc, sink.getvalue()


def all_files(root):
    out = []
    for base, _d, files in os.walk(root):
        for name in files:
            out.append(os.path.join(base, name))
    return out


def decoder(name, program):
    return '<decoder name="%s">\n  <program_name>%s</program_name>\n</decoder>\n' % (name, program)


def rule_over(rid, name):
    return ('<rule id="%d" level="5">\n  <decoded_as>%s</decoded_as>\n  <description>rule %d</description>\n'
            '</rule>' % (rid, name, rid))


class TestSlug(unittest.TestCase):
    def test_safe_names_are_kept(self):
        for name in ("myapp", "web-accesslog", "a_b-1", "x" * meta.SLUG_MAX):
            self.assertEqual(meta.slug(name), name)

    def test_other_names_get_a_safe_slug_with_a_hash(self):
        for name in ("../../ESCAPED", "C:\\x", "Foo", "a.b", "*,*", "x" * (meta.SLUG_MAX + 1), "", "..", "-x",
                     "\u00e9t\u00e9", "a/b"):
            s = meta.slug(name)
            self.assertTrue(meta.is_slug(s), (name, s))
            self.assertNotEqual(s, name)
            self.assertEqual(s, meta.slug(name))  # deterministic
        self.assertNotEqual(meta.slug("Foo"), meta.slug("foo"))
        self.assertNotEqual(meta.slug("a.b"), meta.slug("a/b"))


class TestOutputPaths(unittest.TestCase):
    def test_unsafe_parts_are_refused_on_every_os(self):
        for rel in ("../x.json", "a/../../x", "/abs.json", "a//b", "C:/x.json", "a/C:x", "a\\..\\..\\x",
                    "a/b\\c", "", "./x", "a/\x1b]x"):
            self.assertIsNotNone(emit.unsafe_part(rel), rel)
        for rel in ("integrations/wazuh4-a/integration.json", "detectors/wazuh4-a-2.json", "mapping.csv"):
            self.assertIsNone(emit.unsafe_part(rel), rel)

    def test_check_paths_refuses_before_any_write(self):
        d = tempfile.mkdtemp()
        try:
            out = os.path.join(d, "out")
            os.makedirs(out)
            keep = os.path.join(out, "keep.txt")
            with open(keep, "w") as fh:
                fh.write("x")
            with self.assertRaises(emit.UnsafePath) as cm:
                emit.write(out, {"a.json": "{}", "integrations/../../escaped.json": "{}"})
            self.assertIn("RM-P-UNSAFE-PATH", str(cm.exception))
            self.assertTrue(os.path.exists(keep))  # out/ was not removed
            self.assertFalse(os.path.exists(os.path.join(d, "escaped.json")))
            self.assertFalse(os.path.exists(os.path.join(out, "a.json")))
        finally:
            shutil.rmtree(d)


class TestHostileDecoderNames(unittest.TestCase):
    NAMES = ["../../../../../../ESCAPED", "..\\..\\..\\WINESC", "C:\\drive", "Foo", "foo", "*,*"]

    def test_names_never_leave_the_workdir(self):
        decs = "".join(decoder(n, "prog%d" % i) for i, n in enumerate(self.NAMES))
        rules = rules_xml("hostile", "\n".join(rule_over(100100 + i, n) for i, n in enumerate(self.NAMES)))
        tree = etc_tree(rules={"local_rules.xml": rules}, decoders={"local_decoder.xml": decs})
        base = tempfile.mkdtemp()
        try:
            work = os.path.join(base, "a", "b", "c", "w")
            rc, out = quiet("migrate", "--source", tree.root, "--workdir", work)
            self.assertIn(rc, (0, 1), out)
            real_work = os.path.realpath(work)
            for f in all_files(base):
                self.assertTrue(os.path.realpath(f).startswith(real_work + os.sep), f)
            with open(os.path.join(work, "out", "manifest.json"), encoding="utf-8") as fh:
                keys = json.load(fh)["integrations"]
            for key in keys:
                if key != "wazuh4-base":
                    self.assertTrue(meta.is_slug(key[len(meta.PREFIX):]), key)
            # Foo and foo stay two integrations (no overwrite on a case-insensitive file system)
            self.assertIn("wazuh4-foo", keys)
            self.assertIn("wazuh4-" + meta.slug("Foo"), keys)
            for name in os.listdir(os.path.join(work, "out", "detectors")):
                self.assertTrue(meta.is_slug(name[:-len(".json")]), name)
        finally:
            tree.cleanup()
            shutil.rmtree(base)

    def test_stock_integration_of_decisions_never_leaves_the_workdir(self):
        base = tempfile.mkdtemp()
        try:
            work = os.path.join(base, "a", "b", "w")
            rc, out = quiet("migrate", "--source", SAMPLE, "--workdir", work)
            self.assertIn(rc, (0, 1), out)
            path = os.path.join(work, "decisions.json")
            with open(path, encoding="utf-8") as fh:
                cur = json.load(fh)
            cur.setdefault("stock", {}).setdefault("rule:5716", {}).update(
                {"integration": "../../../../STOCKESC", "selection": {"event.action": "authentication-failure"}})
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(cur, fh)
            rc, out = quiet("build", "--source", SAMPLE, "--workdir", work)
            self.assertIn(rc, (0, 1), out)
            with open(os.path.join(work, "out", "manifest.json"), encoding="utf-8") as fh:
                keys = json.load(fh)["integrations"]
            self.assertIn("wazuh4-on-" + meta.slug("../../../../STOCKESC"), keys)
            for key in keys:
                self.assertTrue(meta.is_slug(key[len(meta.PREFIX):]), key)
            real_work = os.path.realpath(work)
            for f in all_files(base):
                self.assertTrue(os.path.realpath(f).startswith(real_work + os.sep), f)
        finally:
            shutil.rmtree(base)


SECRET_CONF = """<ossec_config>
  <global>
    <email_notification>yes</email_notification>
    <email_to>person.one@corp.example</email_to>
  </global>
  <integration>
    <name>custom-thing</name>
    <hook_url>https://hooks.example/services/HOOKSECRET1</hook_url>
    <api_url>https://svc:URLPASS2@api.example/v1/WEBHOOKPATH3</api_url>
    <options>{"token": "OPTSECRET4"}</options>
    <level>10</level>
  </integration>
  <localfile>
    <log_format>full_command</log_format>
    <command>mysql -uroot -pCMDSECRET5 -e "show processlist"</command>
  </localfile>
  <wodle name="command">
    <command>curl -H "Authorization: Bearer WODLESECRET6" https://x.example</command>
    <interval>1h</interval>
  </wodle>
  <email_alerts>
    <email_to>person.two@corp.example</email_to>
    <level>12</level>
  </email_alerts>
  <reports>
    <title>daily</title>
    <email_to>person.three@corp.example</email_to>
  </reports>
  <syslog_output>
    <server password="ATTRSECRET7">10.0.0.2</server>
  </syslog_output>
  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>
</ossec_config>
"""
SENTINELS = ("HOOKSECRET1", "URLPASS2", "WEBHOOKPATH3", "OPTSECRET4", "CMDSECRET5", "WODLESECRET6", "ATTRSECRET7",
             "person.one", "person.two", "person.three", "corp.example")


class TestSecretsMasked(unittest.TestCase):
    def test_no_secret_or_address_in_any_written_file(self):
        rules = rules_xml("x", rule_over(100100, "myapp"))
        tree = etc_tree(rules={"local_rules.xml": rules}, decoders={"local_decoder.xml": decoder("myapp", "myapp")},
                        conf=SECRET_CONF)
        work = tempfile.mkdtemp()
        try:
            rc, out = quiet("migrate", "--source", tree.root, "--workdir", work)
            self.assertIn(rc, (0, 1), out)
            files = all_files(work)
            self.assertTrue(any(os.sep + "references" + os.sep in f for f in files))
            for f in files:
                with open(f, "rb") as fh:
                    data = fh.read()
                for s in SENTINELS:
                    self.assertFalse(s.encode() in data, "%s in %s" % (s, f))
            for s in SENTINELS:
                self.assertNotIn(s, out)
        finally:
            tree.cleanup()
            shutil.rmtree(work)

    def test_mask_value(self):
        from rmig.parse.ossec_conf import MASK_EMAIL, mask_value

        self.assertEqual(mask_value("localfile.command", "mysql -pX"), "mysql ***")
        self.assertEqual(mask_value("command", "/usr/bin/fetch.sh /var/ossec/etc/lists/bad-ips"),
                         "/usr/bin/fetch.sh /var/ossec/etc/lists/bad-ips")
        for cmd in ('curl -H "Authorization: Bearer T0K" https://x.example', "curl -u admin:T0K https://x.example",
                    "tool --password T0K", "tool --api-key=T0K", "run.sh token=T0K", "x -H 'X-Api-Key: T0K'",
                    "sshpass -p T0K ssh h", "mysql -p'T0K'", "PGPASSWORD=T0K psql", "AWS_SECRET_ACCESS_KEY=T0K aws s3 ls",
                    """curl -d '{"token": "T0K"}' https://x""", 'run.sh token="T0K"', 'tool --password "two T0K"',
                    'broken "quote T0K'):
            self.assertNotIn("T0K", mask_value("command", cmd), cmd)
            self.assertNotIn("T0K", mask_value("extra_args", cmd), cmd)
        self.assertEqual(mask_value("command", "PGPASSWORD=x psql -h /tmp"), "PGPASSWORD=*** psql -h /tmp")
        self.assertEqual(mask_value("command", "firewall-drop"), "firewall-drop")
        self.assertEqual(mask_value("email_to", "a@b.c"), MASK_EMAIL)
        self.assertEqual(mask_value("api_url", "https://u:p@h.example/x?y"), "https://***@h.example/***")
        self.assertEqual(mask_value("location", "/var/log/app.log"), "/var/log/app.log")


class TestRedos(unittest.TestCase):
    def test_nested_quantifiers_are_not_run(self):
        import time

        from rmig.verify import sigma

        for pattern in ("(a+)+b", ".*(a+)+b.*", "(a*)*", "(a|aa)+", "(?:x+y?)*", "(a?)+", "(a+){2,}"):
            self.assertIsNotNone(sigma.catastrophic(pattern), pattern)
            why = []
            t = time.time()
            self.assertIsNone(sigma._one("a" * 40 + "!", pattern, "re", why))
            self.assertLess(time.time() - t, 1.0)
            self.assertTrue(why, pattern)
            t = time.time()
            self.assertFalse(sigma._match_value("a" * 40 + "!", pattern, ["re"]))
            self.assertLess(time.time() - t, 1.0)
        for pattern in ("(ab)+", "foo.*bar", "[(+]+", "(a+)?", r"\(a+\)+", "(a|b)?", "((a)+)"):
            self.assertIsNone(sigma.catastrophic(pattern), pattern)

    def test_adjacent_quantifiers_are_bounded(self):
        import time

        from rmig.verify import sigma

        for pattern in ("a*a*a*a*a*b", ".*a.*a.*a.*a.*b", "a+a+a+a+b", "[a-z]*[a-z]*[a-z]*[a-z]*x", ".*a.*b.*"):
            t = time.time()
            why = []
            self.assertIsNone(sigma._one("a" * 4096, pattern, "re", why))
            self.assertLess(time.time() - t, 2.0, pattern)
            self.assertTrue(why, pattern)
        self.assertEqual(sigma.unbounded_quantifiers(".*foo.*"), 0)
        self.assertEqual(sigma.unbounded_quantifiers("[*+]+a{2,}b{1,3}"), 2)
        self.assertTrue(sigma._one("x" * 4000 + "foo", ".*foo.*", "re", []))

    def test_long_values_are_not_run(self):
        from rmig.verify import sigma

        why = []
        self.assertIsNone(sigma._one("a" * (sigma.RE_MAX_INPUT + 1), "a+", "re", why))
        self.assertIn("longer than", why[0])
        self.assertTrue(sigma._one("a" * sigma.RE_MAX_INPUT, "a+", "re", []))


class TestSourceContainment(unittest.TestCase):
    def test_ruleset_paths_cannot_leave_the_source(self):
        from rmig.scan import scan

        base = tempfile.mkdtemp()
        try:
            outside = os.path.join(base, "outside")
            os.makedirs(outside)
            with open(os.path.join(outside, "x.xml"), "w") as fh:
                fh.write(rules_xml("x", '<rule id="100900" level="3"><match>OUTSIDESECRET</match>'
                                        '<description>d</description></rule>'))
            etc = os.path.join(base, "etc")
            os.makedirs(os.path.join(etc, "rules"))
            with open(os.path.join(etc, "ossec.conf"), "w") as fh:
                fh.write("<ossec_config><ruleset><rule_dir>etc/../outside</rule_dir>"
                         "<rule_include>etc/../outside/x.xml</rule_include>"
                         "<rule_dir>etc/rules</rule_dir></ruleset></ossec_config>")
            inv = scan(etc)
            self.assertNotIn("OUTSIDESECRET", json.dumps(inv))
            self.assertFalse(inv["rules"])
            msgs = [e["message"] for e in inv["conf_problems"]["errors"]]
            self.assertTrue(any("leaves the source tree" in m for m in msgs), msgs)
        finally:
            shutil.rmtree(base)

    def test_inside(self):
        from rmig import fsutil

        base = tempfile.mkdtemp()
        try:
            self.assertTrue(fsutil.inside(base, os.path.join(base, "a", "b")))
            self.assertFalse(fsutil.inside(base, os.path.join(base, "..", "x")))
            self.assertFalse(fsutil.inside(os.path.join(base, "a"), os.path.join(base, "ab")))
        finally:
            shutil.rmtree(base)

    def test_link_outside_is_skipped_and_named(self):
        from unittest import mock

        from rmig import fsutil
        from rmig.scan import scan

        base = tempfile.mkdtemp()
        try:
            etc = os.path.join(base, "etc")
            os.makedirs(os.path.join(etc, "lists"))
            with open(os.path.join(etc, "lists", "blocked"), "w") as fh:
                fh.write("LINKSECRET:x" + chr(10))
            with open(os.path.join(etc, "ossec.conf"), "w") as fh:
                fh.write("<ossec_config><ruleset><rule_dir>etc/rules</rule_dir></ruleset></ossec_config>")
            real_inside = fsutil.inside

            def fake_inside(root, path):
                return False if path.endswith("blocked") else real_inside(root, path)

            with mock.patch.object(fsutil.os.path, "islink", lambda p: p.endswith("blocked")), \
                    mock.patch.object(fsutil, "inside", fake_inside):
                inv = scan(etc)
            self.assertNotIn("LINKSECRET", json.dumps(inv))
            self.assertFalse(inv["lists"])
            msgs = [e["message"] for e in inv["conf_problems"]["errors"]]
            self.assertIn("etc/lists/blocked leaves the source tree: not read", msgs)
        finally:
            shutil.rmtree(base)

    def test_symlinked_list_outside_is_not_read(self):
        from rmig.scan import scan

        base = tempfile.mkdtemp()
        try:
            secret = os.path.join(base, "credentials")
            with open(secret, "w") as fh:
                fh.write("aws_secret:LINKSECRET" + chr(10))
            etc = os.path.join(base, "etc")
            os.makedirs(os.path.join(etc, "lists"))
            with open(os.path.join(etc, "ossec.conf"), "w") as fh:
                fh.write("<ossec_config><ruleset><rule_dir>etc/rules</rule_dir></ruleset></ossec_config>")
            try:
                os.symlink(secret, os.path.join(etc, "lists", "blocked"))
            except (OSError, NotImplementedError):
                self.skipTest("no symbolic links on this host")
            inv = scan(etc)
            self.assertNotIn("LINKSECRET", json.dumps(inv))
            self.assertFalse(inv["lists"])
        finally:
            shutil.rmtree(base)


class TestXmlReaderLimits(unittest.TestCase):
    def test_deep_nesting_is_an_error_not_a_crash(self):
        from rmig.parse.xmlreader import read_xml

        text = "<a>" * 1010 + "x" + "</a>" * 1010
        _roots, _vars, errors = read_xml(text)
        self.assertTrue(any("recursion" in e.message for e in errors))

    def test_many_comments_are_read_in_linear_time(self):
        import time

        from rmig.parse.xmlreader import read_xml

        text = "<!-- c -->" * 64000 + "<group name=\"x\"></group>"
        t = time.time()
        roots, _vars, errors = read_xml(text)
        self.assertLess(time.time() - t, 2.0)
        self.assertEqual([r.tag for r in roots], ["group"])
        self.assertFalse(errors)


HOSTILE = "x &lt;script&gt;alert(1)&lt;/script&gt; [click](javascript:alert(2)) ![t](https://tracker.example/p.png)"


class TestOutputEscaping(unittest.TestCase):
    def test_markdown_holds_no_html_link_or_image_from_input(self):
        rules = rules_xml("x", '<rule id="100700" level="5"><if_level>10</if_level><description>%s</description>'
                               '</rule>\n%s' % (HOSTILE, rule_over(100701, "myapp").replace("rule 100701", HOSTILE)))
        tree = etc_tree(rules={"local_rules.xml": rules}, decoders={"local_decoder.xml": decoder("myapp", "myapp")})
        work = tempfile.mkdtemp()
        try:
            rc, out = quiet("migrate", "--source", tree.root, "--workdir", work)
            self.assertIn(rc, (0, 1), out)
            mds = [f for f in all_files(work) if f.endswith(".md")]
            self.assertTrue(any(os.sep + "recipes" + os.sep in f for f in mds), mds)
            seen = False
            for f in mds:
                with open(f, encoding="utf-8") as fh:
                    text = fh.read()
                seen = seen or "alert(1)" in text
                for bad in ("<script>", " [click](javascript:", "![t](https://tracker"):
                    self.assertNotIn(bad, text, f)
            self.assertTrue(seen)
        finally:
            tree.cleanup()
            shutil.rmtree(work)

    def test_md_escapes_raw_html_and_links(self):
        from rmig.textsafe import md

        self.assertEqual(md("<img src=x onerror=alert(1)>"), "&lt;img src=x onerror=alert(1)&gt;")
        self.assertEqual(md("![a](http://t) [b](javascript:x)"), "!\\[a\\](http://t) \\[b\\](javascript:x)")
        self.assertEqual(md("a|b" + chr(10) + "c" + chr(27)), "a\\|b c\\x1b")

    def test_terminal_output_has_no_control_characters(self):
        from rmig.api.apply import Runner

        sink = io.StringIO()
        Runner(None, tempfile.gettempdir(), stream=sink).say("decoder " + chr(27) + "]0;owned" + chr(7) + " done")
        self.assertNotIn(chr(27), sink.getvalue())
        self.assertNotIn(chr(7), sink.getvalue())
        self.assertIn("x1b", sink.getvalue())


class TestEngineHelperHint(unittest.TestCase):
    def test_refusal_names_the_dialect(self):
        from rmig.verify.offline import helper_hint

        path = os.path.join(DATA, "engine", "validate-load-unmigrated.json")
        with open(path, encoding="utf-8") as fh:
            recorded = json.loads(json.load(fh)["raw"])["error"]
        hint = helper_hint(recorded)  # kvdb_get refused: the engine has the 5.0.0 names
        self.assertIn("--engine-helpers 5.0`", hint)
        # the answer text seen on the public 5.0.0 rc2 manager
        hint = helper_hint("Operation builder 'in_cidr' not found")
        self.assertIn("--engine-helpers 5.0-rc1", hint)
        self.assertIn("older than 5.0.0", hint)
        self.assertIsNone(helper_hint("Operation builder 'no_such_helper' not found"))
        self.assertIsNone(helper_hint("some other refusal"))


if __name__ == "__main__":
    unittest.main()
