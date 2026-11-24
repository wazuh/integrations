import copy
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, PACK)

from wcp import alerting as A  # noqa: E402
from wcp import config as C  # noqa: E402
from wcp import deploy as D  # noqa: E402
from wcp import sigma as S  # noqa: E402
from wcp.client import ApiError  # noqa: E402


class FakeAlerting(object):
    """In-memory stand-in for the Alerting monitor API (stores monitors like the 5.0.0-rc1 plugin:
    no ui_metadata, query kept verbatim)."""

    def __init__(self):
        self.monitors = {}
        self.n = 0
        self.calls = []

    def _store(self, body):
        b = copy.deepcopy(body)
        b.pop("ui_metadata", None)
        return b

    def post(self, path, body=None, **kw):
        self.calls.append(("POST", path))
        if path == D.MONITORS + "/_search":
            return {"hits": {"hits": [{"_id": k, "_source": copy.deepcopy(v)} for k, v in self.monitors.items()]}}
        if path == D.MONITORS:
            self.n += 1
            mid = "m%d" % self.n
            self.monitors[mid] = self._store(body)
            return {"_id": mid}
        raise AssertionError(path)

    def put(self, path, body=None, **kw):
        self.calls.append(("PUT", path))
        mid = path.rsplit("/", 1)[1]
        assert mid in self.monitors
        self.monitors[mid] = self._store(body)
        return {"_id": mid}

    def delete(self, path, **kw):
        self.calls.append(("DELETE", path))
        mid = path.rsplit("/", 1)[1]
        if mid not in self.monitors:
            raise ApiError("DELETE", path, 404, {})
        del self.monitors[mid]
        return {}

    def get(self, path, **kw):
        return {"alerts": [], "totalAlerts": 0}


FOREIGN = {"type": "monitor", "monitor_type": "query_level_monitor", "name": "someone else's monitor",
           "inputs": [{"search": {"indices": ["x"], "query": {"size": 0}}}]}


class TestDeploy(unittest.TestCase):
    def setUp(self):
        self.rules, self.corrs = S.load_content(PACK)
        self.profile = C.load_profile(os.path.join(PACK, "pack.yml"))
        self.api = FakeAlerting()
        self.api.monitors["foreign1"] = copy.deepcopy(FOREIGN)
        self.state = tempfile.mkdtemp()
        self.manifest = D.Manifest(os.path.join(self.state, "t.json"), "t")

    def desired(self, profile=None, only=None):
        return D.desired_monitors(self.corrs, profile or self.profile, C.settings_for, only)

    def apply(self, profile=None, only=None, prune=True):
        steps, foreign = D.plan(self.api, self.desired(profile, only), prune=prune, only=only, manifest=self.manifest)
        D.apply_steps(self.api, steps, self.manifest, (profile or self.profile)["version"])
        return [s[0] for s in steps], foreign

    def test_install_then_idempotent(self):
        ops, foreign = self.apply()
        self.assertEqual(ops, ["create"] * len(self.corrs))
        self.assertEqual(foreign, 1)
        ops, _ = self.apply()
        self.assertEqual(ops, ["noop"] * len(self.corrs))
        self.assertEqual(len(self.api.monitors), len(self.corrs) + 1)
        self.assertEqual(self.api.monitors["foreign1"], FOREIGN)

    def test_marker_alone_identifies_monitors(self):
        self.apply()
        # lose the manifest: the stored marker must still prevent duplicates
        self.manifest = D.Manifest(os.path.join(self.state, "other.json"), "t")
        ops, _ = self.apply()
        self.assertEqual(ops, ["noop"] * len(self.corrs))

    def test_update_on_setting_change(self):
        self.apply()
        prof = copy.deepcopy(self.profile)
        prof.setdefault("correlations", {})["wcp_ssh_bruteforce"] = {"interval": "2m"}
        ops, _ = self.apply(prof)
        self.assertEqual(sorted(ops), sorted(["update"] + ["noop"] * (len(self.corrs) - 1)))
        ops, _ = self.apply(prof)
        self.assertEqual(ops, ["noop"] * len(self.corrs))

    def test_update_on_version_change(self):
        self.apply()
        prof = dict(self.profile, version="9.9.9")
        ops, _ = self.apply(prof)
        self.assertEqual(ops, ["update"] * len(self.corrs))

    def test_prune_only_pack_monitors(self):
        self.apply()
        keep = [c for c in self.corrs if c.name != "wcp_ssh_password_spray"]
        steps, _ = D.plan(self.api, D.desired_monitors(keep, self.profile, C.settings_for), manifest=self.manifest)
        self.assertEqual(sorted(s[0] for s in steps), sorted(["delete"] + ["noop"] * len(keep)))
        D.apply_steps(self.api, steps, self.manifest, "0.1.0")
        self.assertIn("foreign1", self.api.monitors)
        self.assertEqual(len(self.api.monitors), len(keep) + 1)

    def test_only_does_not_prune(self):
        self.apply()
        ops, _ = self.apply(only={"wcp_ssh_bruteforce"})
        self.assertEqual(ops, ["noop"])
        self.assertEqual(len(self.api.monitors), len(self.corrs) + 1)

    def test_adopt_markerless_monitor_from_manifest(self):
        self.apply()
        mid = next(iter(self.manifest.monitor_ids()))
        self.api.monitors[mid]["inputs"][0]["search"]["query"]["aggregations"][A.GROUP_AGG].pop("meta")
        ops, _ = self.apply()
        self.assertEqual(sorted(ops), sorted(["update"] + ["noop"] * (len(self.corrs) - 1)))
        self.assertEqual(len(self.api.monitors), len(self.corrs) + 1)

    def test_duplicate_pack_monitor_is_removed(self):
        self.apply()
        mid = next(iter(self.manifest.monitor_ids()))
        self.api.monitors["dup"] = copy.deepcopy(self.api.monitors[mid])
        steps, _ = D.plan(self.api, self.desired(), manifest=self.manifest)
        dels = [s for s in steps if s[0] == "delete"]
        self.assertEqual(len(dels), 1)
        D.apply_steps(self.api, steps, self.manifest, "0.1.0")
        self.assertEqual(len(self.api.monitors), len(self.corrs) + 1)

    def test_remove_leaves_foreign(self):
        self.apply()
        steps, foreign = D.remove_all(self.api, self.manifest, "0.1.0")
        self.assertEqual(len(steps), len(self.corrs))
        self.assertEqual(foreign, 1)
        D.apply_steps(self.api, steps, self.manifest, "0.1.0", action="remove")
        self.assertEqual(list(self.api.monitors), ["foreign1"])
        self.assertEqual(self.manifest.data["current"], {})
        steps, _ = D.remove_all(self.api, self.manifest, "0.1.0")
        self.assertEqual(steps, [])

    def test_rollback_restores_previous_bodies(self):
        self.apply()
        before = {k: copy.deepcopy(v) for k, v in self.api.monitors.items()}
        prof = copy.deepcopy(self.profile)
        prof["correlations"] = {"wcp_ssh_bruteforce": {"interval": "5m"}}
        self.apply(prof)
        self.assertNotEqual(before, self.api.monitors)
        steps, ver = D.rollback_steps(self.api, self.manifest)
        D.apply_steps(self.api, steps, self.manifest, ver, action="rollback")
        self.assertEqual(before, self.api.monitors)


if __name__ == "__main__":
    unittest.main()
