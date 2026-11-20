"""The 4.x pre-decoding in wazuh4-base and how root decoders hang from it.

The expected values are what analysisd 4.14.10 extracts (``OS_CleanMSG``,
checked against wazuh-logtest on a 4.14.10 manager). The
predecoder is run here by a small interpreter of the engine operations it uses
(``regex_extract``, ``$field`` copies, ``exists``/``not_exists`` checks)."""

import contextlib
import io
import json
import os
import re
import shutil
import tempfile
import unittest

from helpers import etc_tree, rules_xml

from rmig import cli
from rmig.translate.engine import load_base

EXTRACT = re.compile(r"^regex_extract\(\$([^,]+), '(.*)'\)$", re.S)


def unquote(text):
    return text.replace("\\'", "'").replace("\\\\", "\\")


def run(decoder, line, **fields):
    """Fields the predecoder leaves for the decoders below it. An empty capture sets "" (the engine's
    regex_extract, opBuilderHelperMap.cpp); a failed match leaves the field absent."""
    ev = {"event.original": line}
    ev.update({k.replace("__", "."): v for k, v in fields.items()})
    for block in decoder["normalize"]:
        ok = True
        for cond in block.get("check", []):
            (field, helper), = cond.items()
            ok = ok and ((helper == "exists()") == (field in ev))
        if not ok:
            continue
        for op in block["map"]:
            (field, value), = op.items()
            m = EXTRACT.match(value)
            if m:
                src, pattern = m.group(1), unquote(m.group(2))
                found = re.search(pattern, ev[src]) if src in ev else None
                if found and found.group(1) is not None:
                    ev[field] = found.group(1)
            elif value.startswith("$"):
                if value[1:] in ev:
                    ev[field] = ev[value[1:]]
            else:
                ev[field] = value
    return {k: ev.get(k) for k in ("message", "process.name", "observer.hostname")}


class TestPredecoder(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base = load_base()
        cls.dec = [d["resource"] for d in base["decoders"] if d["resource"]["name"] == base["predecoder"]][0]

    def check(self, line, message, program, hostname, **fields):
        self.assertEqual(run(self.dec, line, **fields),
                         {"message": message, "process.name": program, "observer.hostname": hostname}, line)

    def test_program_and_pid(self):
        self.check("Nov 18 10:00:01 gw01 sshd[2311]: Failed password for root",
                   "Failed password for root", "sshd", "gw01")

    def test_cef_is_a_program_name_in_4x(self):
        self.check("Nov 18 10:15:02 UDM-Pro-Max CEF:0|Ubiquiti|UniFi Protect|5.1.200|2161|x",
                   "0|Ubiquiti|UniFi Protect|5.1.200|2161|x", "CEF", "UDM-Pro-Max")

    def test_no_program_name_keeps_the_text_after_the_hostname(self):
        self.check("Nov 18 10:15:02 UDM-Pro-Max UDM-Pro-Max dnsmasq-dhcp[3121]: DHCPRELEASE(br20)",
                   "UDM-Pro-Max dnsmasq-dhcp[3121]: DHCPRELEASE(br20)", None, "UDM-Pro-Max")
        self.check("Nov 18 10:15:02 rtr-core01 system,error login failure for user admin",
                   "system,error login failure for user admin", None, "rtr-core01")

    def test_solaris_without_hostname(self):
        self.check("Nov 18 10:00:01 sshd: x", "x", "sshd", None)

    def test_solaris_id_block_is_removed(self):
        self.check("Nov 18 10:00:01 host1 kernel: [ID 123 kern.info] disk full", "disk full", "kernel", "host1")

    def test_iso_timestamps(self):
        self.check("2022-12-19T15:02:53.288+00:00 host1 app: hello", "hello", "app", "host1")
        self.check("2009-05-22T09:36:46.214994-07:00 host1 app[7] hello", "hello", "app", "host1")

    def test_aix(self):
        self.check("Nov 18 10:00:01 host1 auth|security:info sshd: x", "x", "sshd", "host1")

    def test_no_header(self):
        self.check("vmware-esxi: Event 1 : Created virtual machine vm01 on esx01",
                   "vmware-esxi: Event 1 : Created virtual machine vm01 on esx01", None, None)

    def test_other_timestamps_only_remove_the_date(self):
        self.check("[Fri Feb 11 18:06:35 2004] [warn] child", "[warn] child", None, None)

    def test_a_multi_line_event(self):
        self.check("Nov 18 10:00:01 gw01 sshd[2311]: line one\nline two", "line one\nline two", "sshd", "gw01")

    def test_an_agent_event_keeps_no_header_hostname(self):
        # 4.x replaces the header hostname with the agent name for an agent's event
        self.check("Nov 18 10:00:01 gw01 sshd[2311]: x", "x", "sshd", None, wazuh__agent__id="001")
        self.check("Nov 18 10:00:01 gw01 sshd[2311]: x", "x", "sshd", "gw01", wazuh__agent__id="000")

    def test_empty_message_and_empty_program(self):
        self.check("Nov 18 10:00:01 host1 sshd: ", "", "sshd", "host1")
        self.check("Nov 18 10:00:01 : x", "x", "", None)

    def test_invalid_hostname_keeps_the_text_after_the_date(self):
        self.check("Nov 18 10:00:01 bad#host sshd: x", "bad#host sshd: x", None, None)


NOPN = """<decoder name="gw-text">
  <prematch>^GW </prematch>
</decoder>
"""
PN = """<decoder name="gw-prog">
  <program_name>gwd</program_name>
</decoder>
"""


class TestRootDecoders(unittest.TestCase):
    def setUp(self):
        self.tree = etc_tree(decoders={"local_decoder.xml": NOPN + PN},
                             rules={"local_rules.xml": rules_xml("local,", (
                                 '<rule id="100001" level="3"><decoded_as>gw-text</decoded_as><description>a</description></rule>\n'
                                 '<rule id="100002" level="3"><decoded_as>gw-prog</decoded_as><description>b</description></rule>'))})
        self.work = tempfile.mkdtemp(prefix="rmig-pre-")

    def tearDown(self):
        self.tree.cleanup()
        shutil.rmtree(self.work, ignore_errors=True)

    def decoder(self, integ, name):
        path = os.path.join(self.work, "out", "integrations", integ, "decoders")
        for f in os.listdir(path):
            with open(os.path.join(path, f), encoding="utf-8") as fh:
                doc = json.load(fh)["resource"]
            if doc["name"] == name:
                return doc
        raise AssertionError(name)

    def test_roots_hang_from_the_predecoder_by_program_name_list(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            cli.main(["migrate", "--source", self.tree.root, "--workdir", self.work])
        text = self.decoder("wazuh4-gw-text", "decoder/wazuh4-gw-text/0")
        prog = self.decoder("wazuh4-gw-prog", "decoder/wazuh4-gw-prog/0")
        self.assertEqual(text["parents"], ["decoder/wazuh4-predecoder/0"])
        self.assertEqual(prog["parents"], ["decoder/wazuh4-predecoder/0"])
        # only events without a 4.x program name reach a root without <program_name>
        self.assertTrue(text["check"].startswith("not_exists($process.name) AND regex_match($message, "), text["check"])
        self.assertNotIn("not_exists", prog["check"])
        self.assertIn("regex_match($process.name, ", prog["check"])


if __name__ == "__main__":
    unittest.main()
