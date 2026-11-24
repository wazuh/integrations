"""Deployment lifecycle against a real cluster: idempotency, update, rollback, remove, reinstall,
with proof that nothing outside the pack changed.

Before and after every step it snapshots every document returned by the Alerting monitor search
API (monitors and workflows: id, type, name, last_update_time, enabled). Documents that are not
pack monitors must stay byte-for-byte identical in that snapshot.

Run: python tests/e2e/test_deploy_lifecycle.py --evidence evidence/<run-id>
WARNING: ``remove`` deletes the pack's monitors and their active alerts during the test.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile

import harness as H

PACK = H.PACK


def wcp(args):
    r = subprocess.run([sys.executable, "-m", "wcp"] + args, cwd=PACK, capture_output=True, text=True, timeout=300)
    return r.returncode, (r.stdout + r.stderr).strip()


def snapshot(client):
    res = client.post(H.D.MONITORS + "/_search", {"size": 1000, "query": {"match_all": {}}})
    out = {}
    for h in res["hits"]["hits"]:
        s = h["_source"]
        m = s.get("monitor", s)
        out[h["_id"]] = {"type": m.get("type"), "kind": m.get("monitor_type") or m.get("workflow_type"),
                         "name": m.get("name"), "enabled": m.get("enabled"),
                         "last_update_time": m.get("last_update_time"), "pack": H.A.marker_of(m).get("pack")}
    return out


def foreign(snap):
    return {k: v for k, v in snap.items() if v["pack"] != H.A.PACK_ID}


def pack_ids(snap):
    return sorted(k for k, v in snap.items() if v["pack"] == H.A.PACK_ID)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", required=True)
    a = ap.parse_args()
    obs = H.Observer()
    ev = H.Evidence(a.evidence, "deploy_lifecycle", "deployment (real cluster)")
    n = len(obs.correlations)
    s0 = snapshot(obs.client)
    f0 = foreign(s0)
    ev.d["observed"]["foreign_documents_before"] = len(f0)
    ev.d["observed"]["pack_monitors_before"] = pack_ids(s0)
    steps = ev.d["observed"]["steps"] = []

    def step(label, args, check, expect_pack_count=n):
        rc, out = wcp(args)
        snap = snapshot(obs.client)
        steps.append({"step": label, "command": "wcp " + " ".join(args), "rc": rc, "output": out[-2500:],
                      "pack_monitors": pack_ids(snap)})
        ev.check("%s: rc=0" % label, rc == 0, rc)
        ev.check("%s: %s" % (label, check[0]), check[1](out), None)
        ev.check("%s: %d pack monitor(s) exist" % (label, expect_pack_count), len(pack_ids(snap)) == expect_pack_count,
                 len(pack_ids(snap)))
        ev.check("%s: %d non-pack document(s) unchanged" % (label, len(f0)), foreign(snap) == f0,
                 None if foreign(snap) == f0 else "changed")
        return snap

    ov = tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False)
    ov.write("correlations:\n  wcp_windows_password_spray:\n    interval: 2m\n")
    ov.close()
    try:
        step("re-run install (idempotent)", ["apply"], ("0 changes", lambda o: "applied: 0 change(s)" in o))
        step("plan after install", ["plan"], ("plan reports 0 changes", lambda o: "plan: 0 change(s)" in o))
        s1 = snapshot(obs.client)
        step("update one setting", ["--override", ov.name, "apply"],
             ("exactly 1 update", lambda o: o.count("\n  update  ") == 1 and "applied: 1 change(s)" in o))
        s2 = snapshot(obs.client)
        changed = sorted(k for k in pack_ids(s2) if s2[k]["last_update_time"] != s1[k]["last_update_time"])
        ev.d["observed"]["monitors_changed_by_update"] = changed
        ev.check("update changed exactly one pack monitor", len(changed) == 1, changed)
        step("plan after update (with override)", ["--override", ov.name, "plan"],
             ("0 changes", lambda o: "plan: 0 change(s)" in o))
        step("rollback to previous deployment", ["rollback", "--yes"],
             ("rollback lists 1 update", lambda o: o.count("  update  ") >= 1))
        step("plan after rollback (shipped profile)", ["plan"], ("0 changes", lambda o: "plan: 0 change(s)" in o))
        step("remove dry run", ["remove"], ("lists %d pack monitors, deletes nothing" % n,
                                            lambda o: ("remove: %d pack monitor(s)" % n) in o and "dry run" in o))
        step("remove", ["remove", "--yes"], ("removed", lambda o: "removed" in o), expect_pack_count=0)
        step("remove again (nothing left)", ["remove", "--yes"], ("0 pack monitors", lambda o: "remove: 0 pack" in o),
             expect_pack_count=0)
        step("reinstall", ["apply"], ("%d creates" % n, lambda o: ("applied: %d change(s)" % n) in o))
        step("re-run reinstall (idempotent)", ["apply"], ("0 changes", lambda o: "applied: 0 change(s)" in o))
    finally:
        os.unlink(ov.name)
    ev.d["observed"]["foreign_documents_after"] = len(foreign(snapshot(obs.client)))
    ev.d["observed"]["foreign_document_kinds"] = sorted({"%s/%s" % (v["type"], v["kind"]) for v in f0.values()})
    return 0 if ev.save() == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
