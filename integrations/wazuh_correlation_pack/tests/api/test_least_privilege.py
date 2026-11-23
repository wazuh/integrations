"""Verify the documented minimum permissions (docs/CONFIGURATION.md#permissions).

STATUS: written but NOT executed in the recorded 2026-11-21 run (creating a security user on the
test server was not authorised). Run it only on a cluster where you may create a temporary user.

Creates a temporary role + internal user (random password, never printed), runs the deployment
tool as that user (preflight, plan, an update of one monitor, status, execute), restores the
monitor as the admin user, then deletes the temporary user and role.

Run with admin credentials configured: python tests/api/test_least_privilege.py --evidence DIR
"""

import argparse
import json
import os
import secrets
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, PACK)

from wcp.client import DEFAULT_ENV_FILE, ApiError, Client, load_env_file  # noqa: E402

NAME = "wcp_deployer_test"
ROLE = {
    "description": "wazuh_correlation_pack deployment (temporary test role)",
    "cluster_permissions": [
        "cluster:monitor/main",
        "cluster:admin/opendistro/alerting/monitor/get",
        "cluster:admin/opendistro/alerting/monitor/search",
        "cluster:admin/opendistro/alerting/monitor/write",
        "cluster:admin/opendistro/alerting/monitor/delete",
        "cluster:admin/opendistro/alerting/monitor/execute",
        "cluster:admin/opendistro/alerting/alerts/get",
    ],
    "index_permissions": [{
        "index_patterns": ["wazuh-events-v5-system-activity*"],
        "allowed_actions": ["read", "indices:admin/mappings/fields/get"],
    }],
}
TARGET = "wcp_windows_password_spray"


def run_wcp(args, env):
    r = subprocess.run([sys.executable, "-m", "wcp"] + args, cwd=PACK, env=env, capture_output=True, text=True,
                       timeout=300)
    return r.returncode, (r.stdout + r.stderr).strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence")
    a = ap.parse_args()
    load_env_file(os.environ.get("WCP_ENV_FILE", DEFAULT_ENV_FILE))
    admin = Client()
    pw = secrets.token_urlsafe(24) + "aA1!"
    res = {"layer": "query-api (permissions)", "role": ROLE, "steps": []}
    override = tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False)
    override.write("correlations:\n  %s:\n    interval: 2m\n" % TARGET)
    override.close()
    env = dict(os.environ, WCP_INDEXER_USER=NAME, WCP_INDEXER_PASSWORD=pw, WCP_ENV_FILE=os.devnull)
    ok_all = True
    try:
        admin.put("/_plugins/_security/api/roles/" + NAME, ROLE)
        admin.put("/_plugins/_security/api/internalusers/" + NAME,
                  {"password": pw, "opendistro_security_roles": [NAME],
                   "attributes": {"purpose": "wazuh_correlation_pack permission test"}})
        steps = [
            ("preflight", ["preflight"], None),
            ("plan (expect all no-op)", ["plan"], "0 change(s)"),
            ("apply override: update one monitor", ["--override", override.name, "apply", "--only", TARGET],
             "update"),
            ("status", ["--override", override.name, "status"], "in_sync=True"),
            ("execute (dry run)", ["--override", override.name, "execute", "--only", TARGET], "triggering bucket"),
            ("remove dry run", ["remove"], "dry run"),
        ]
        for label, args, expect in steps:
            rc, out = run_wcp(args, env)
            ok = rc == 0 and (expect is None or expect in out) and "403" not in out and "security_exception" not in out
            ok_all &= ok
            res["steps"].append({"step": label, "user": NAME, "rc": rc, "pass": ok, "output": out[-1500:]})
            print("[%s] %s (rc=%d)" % ("PASS" if ok else "FAIL", label, rc))
            if not ok:
                print(out[-800:])
    finally:
        # restore the monitor as admin (so it no longer runs with the temporary role), then clean up
        rc, out = run_wcp(["apply", "--only", TARGET], dict(os.environ))
        res["steps"].append({"step": "restore as admin", "rc": rc, "output": out[-800:]})
        print("[%s] restore monitor as admin" % ("PASS" if rc == 0 else "FAIL"))
        for path in ("/_plugins/_security/api/internalusers/" + NAME, "/_plugins/_security/api/roles/" + NAME):
            try:
                admin.delete(path)
            except ApiError as e:
                print("cleanup %s: %s" % (path, e))
        os.unlink(override.name)
        gone = []
        for path in ("/_plugins/_security/api/internalusers/" + NAME, "/_plugins/_security/api/roles/" + NAME):
            try:
                admin.get(path)
                gone.append(False)
            except ApiError as e:
                gone.append(e.status == 404)
        res["cleanup_verified"] = all(gone)
        print("[%s] temporary user and role deleted" % ("PASS" if all(gone) else "FAIL"))
    res["verdict"] = "PASS" if ok_all and res["cleanup_verified"] else "FAIL"
    if a.evidence:
        with open(os.path.join(a.evidence, "api_least_privilege.json"), "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=2)
    print(res["verdict"])
    return 0 if res["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
