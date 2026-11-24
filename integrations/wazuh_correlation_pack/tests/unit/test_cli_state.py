"""Deployment state: where the CLI keeps manifests, and that a manifest is used only with its cluster.

Regression for the RC2 run of 2026-11-22: ``WCP_STATE_DIR`` set only in the selected env file was
ignored (the ``--state-dir`` default was computed before the env file was read), so the first RC2
``apply`` wrote its manifest into the default state directory.

Each test runs the real CLI (``wcp.cli.main``) in-process against an in-memory Alerting API, with
a clean environment whose home directory is a temporary directory: nothing outside it is read or
written. Two fake clusters stand for an RC1-like and an RC2-like deployment (different
``cluster_uuid``, different tunnel ports).
"""

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, PACK)
sys.path.insert(0, HERE)

from wcp import cli  # noqa: E402
from test_deploy import FakeAlerting  # noqa: E402

CLUSTERS = {"https://127.0.0.1:9201": "uuid-rc1-like", "https://127.0.0.1:9202": "uuid-rc2-like"}


class FakeCluster(FakeAlerting):
    def __init__(self, uuid):
        FakeAlerting.__init__(self)
        self.uuid = uuid

    def get(self, path, **kw):
        if path == "/":
            return {"cluster_uuid": self.uuid, "cluster_name": "fake", "version": {"number": "3.6.0"}}
        return FakeAlerting.get(self, path, **kw)

    def mutations(self):
        return [c for c in self.calls if c[0] in ("PUT", "DELETE") or (c[0] == "POST" and not c[1].endswith("_search"))]


class CliStateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wcp-cli-state-")
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        self.default_state = os.path.join(self.home, ".config", "wazuh_correlation_pack", "state")
        self.clusters = {url: FakeCluster(u) for url, u in CLUSTERS.items()}
        env = {"HOME": self.home, "USERPROFILE": self.home, "PATH": os.environ.get("PATH", ""),
               "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")}
        self.env = mock.patch.dict(os.environ, env, clear=True)
        self.env.start()
        self.client = mock.patch.object(cli, "Client", side_effect=self.fake_client)
        self.client.start()

    def tearDown(self):
        self.client.stop()
        self.env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def fake_client(self, *a, **kw):
        url = os.environ["WCP_INDEXER_URL"]
        c = self.clusters[url]
        c.host, c.port = "127.0.0.1", int(url.rsplit(":", 1)[1])
        return c

    def env_file(self, name, url, state_dir=None, target=None):
        p = os.path.join(self.tmp, name)
        lines = ["WCP_INDEXER_URL=%s" % url, "WCP_INDEXER_USER=u", "WCP_INDEXER_PASSWORD=not-a-password"]
        if state_dir:
            lines.append("WCP_STATE_DIR=%s" % state_dir)
        if target:
            lines.append("WCP_TARGET=%s" % target)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        return p

    def run_cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            try:
                rc = cli.main(list(argv))
            except SystemExit as e:
                rc = e.code if isinstance(e.code, int) else 2
                out.write(str(e.code))
        return rc, out.getvalue()

    @staticmethod
    def read(path):
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def files_under(self, d):
        return sorted(os.path.relpath(os.path.join(r, f), self.tmp) for r, _d, fs in os.walk(d) for f in fs)

    # ---------------------------------------------------------------- precedence
    def test_state_dir_from_env_file_is_used(self):
        """The regression: WCP_STATE_DIR only in the selected env file."""
        sd = os.path.join(self.tmp, "rc2-state")
        ef = self.env_file("rc2.env", "https://127.0.0.1:9202", state_dir=sd, target="rc2")
        rc, out = self.run_cli("--env-file", ef, "apply")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.files_under(sd), [os.path.join("rc2-state", "rc2.manifest.json")])
        self.assertFalse(os.path.exists(self.default_state), "nothing may be written to the default state dir")

    def test_environment_beats_env_file(self):
        sd_env, sd_file = os.path.join(self.tmp, "from-env"), os.path.join(self.tmp, "from-file")
        ef = self.env_file("rc2.env", "https://127.0.0.1:9202", state_dir=sd_file, target="rc2")
        os.environ["WCP_STATE_DIR"] = sd_env
        rc, out = self.run_cli("--env-file", ef, "apply")
        self.assertEqual(rc, 0, out)
        self.assertTrue(os.path.isfile(os.path.join(sd_env, "rc2.manifest.json")))
        self.assertFalse(os.path.exists(sd_file))

    def test_option_beats_environment_and_env_file(self):
        sd_opt, sd_env, sd_file = (os.path.join(self.tmp, n) for n in ("from-option", "from-env", "from-file"))
        ef = self.env_file("rc2.env", "https://127.0.0.1:9202", state_dir=sd_file, target="rc2")
        os.environ["WCP_STATE_DIR"] = sd_env
        rc, out = self.run_cli("--env-file", ef, "--state-dir", sd_opt, "apply")
        self.assertEqual(rc, 0, out)
        self.assertTrue(os.path.isfile(os.path.join(sd_opt, "rc2.manifest.json")))
        self.assertFalse(os.path.exists(sd_env) or os.path.exists(sd_file))

    def test_default_when_nothing_is_set(self):
        ef = self.env_file("plain.env", "https://127.0.0.1:9202", target="rc2")
        rc, out = self.run_cli("--env-file", ef, "apply")
        self.assertEqual(rc, 0, out)
        self.assertTrue(os.path.isfile(os.path.join(self.default_state, "rc2.manifest.json")))

    def test_rc1_like_and_rc2_like_configurations_stay_separate(self):
        sd1, sd2 = os.path.join(self.tmp, "rc1-state"), os.path.join(self.tmp, "rc2-state")
        ef1 = self.env_file("rc1.env", "https://127.0.0.1:9201", state_dir=sd1, target="lab-rc1")
        ef2 = self.env_file("rc2.env", "https://127.0.0.1:9202", state_dir=sd2, target="lab-rc2")
        for ef in (ef1, ef2):
            rc, out = self.run_cli("--env-file", ef, "apply")
            self.assertEqual(rc, 0, out)
            # each process sees only its own env file: reset what load_env_file put into the environment
            for k in [k for k in os.environ if k.startswith("WCP_")]:
                del os.environ[k]
        for cmd in (["status"], ["plan"], ["remove"]):
            for ef in (ef1, ef2):
                rc, out = self.run_cli("--env-file", ef, *cmd)
                self.assertEqual(rc, 0, out)
                for k in [k for k in os.environ if k.startswith("WCP_")]:
                    del os.environ[k]
        self.assertEqual(self.files_under(sd1), [os.path.join("rc1-state", "lab-rc1.manifest.json")])
        self.assertEqual(self.files_under(sd2), [os.path.join("rc2-state", "lab-rc2.manifest.json")])
        self.assertFalse(os.path.exists(self.default_state))
        m1 = json.loads(self.read(os.path.join(sd1, "lab-rc1.manifest.json")))
        m2 = json.loads(self.read(os.path.join(sd2, "lab-rc2.manifest.json")))
        self.assertEqual((m1.get("cluster_uuid"), m2.get("cluster_uuid")), ("uuid-rc1-like", "uuid-rc2-like"))
        self.assertEqual(set(m1["current"]) and len(self.clusters["https://127.0.0.1:9201"].monitors), 4)
        self.assertEqual(len(self.clusters["https://127.0.0.1:9202"].monitors), 4)

    # ---------------------------------------------------------------- cross-cluster protection
    def shared_state(self):
        """Both clusters configured with the same state dir and manifest name (the dangerous case)."""
        sd = os.path.join(self.tmp, "shared")
        ef1 = self.env_file("a.env", "https://127.0.0.1:9201", state_dir=sd, target="same")
        ef2 = self.env_file("b.env", "https://127.0.0.1:9202", state_dir=sd, target="same")
        return sd, ef1, ef2

    def reset_env(self):
        for k in [k for k in os.environ if k.startswith("WCP_")]:
            del os.environ[k]

    def test_manifest_of_another_cluster_is_refused_before_any_mutation(self):
        sd, ef1, ef2 = self.shared_state()
        rc, out = self.run_cli("--env-file", ef1, "apply")
        self.assertEqual(rc, 0, out)
        self.reset_env()
        before = self.read(os.path.join(sd, "same.manifest.json"))
        other = self.clusters["https://127.0.0.1:9202"]
        for cmd in (["apply"], ["remove", "--yes"], ["rollback", "--yes"], ["plan"], ["status"]):
            rc, out = self.run_cli("--env-file", ef2, *cmd)
            self.reset_env()
            self.assertNotEqual(rc, 0, (cmd, out))
            self.assertIn("another cluster", out, cmd)
        self.assertEqual(other.mutations(), [], "nothing may be changed on the other cluster")
        self.assertEqual(self.read(os.path.join(sd, "same.manifest.json")), before,
                         "the other cluster's manifest must not be modified")

    def test_unbound_existing_manifest_needs_explicit_binding_for_mutations(self):
        sd = os.path.join(self.tmp, "legacy")
        os.makedirs(sd)
        legacy = {"pack": "wazuh_correlation_pack", "target": "old", "history": [],
                  "current": {"x": {"monitor_id": "m-legacy", "content_hash": "h"}}}
        p = os.path.join(sd, "old.manifest.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(legacy, fh)
        before = self.read(p)
        ef = self.env_file("old.env", "https://127.0.0.1:9202", state_dir=sd, target="old")
        api = self.clusters["https://127.0.0.1:9202"]
        rc, out = self.run_cli("--env-file", ef, "apply")
        self.reset_env()
        self.assertNotEqual(rc, 0, out)
        self.assertIn("--bind-manifest", out)
        self.assertEqual(api.mutations(), [])
        self.assertEqual(self.read(p), before, "no silent migration")
        rc, out = self.run_cli("--env-file", ef, "status")          # read-only: warns, does not write
        self.reset_env()
        self.assertEqual(rc, 0, out)
        self.assertIn("no cluster identity", out)
        self.assertEqual(self.read(p), before)
        rc, out = self.run_cli("--env-file", ef, "apply", "--bind-manifest")
        self.reset_env()
        self.assertEqual(rc, 0, out)
        self.assertEqual(json.loads(self.read(p))["cluster_uuid"], "uuid-rc2-like")


if __name__ == "__main__":
    unittest.main()
