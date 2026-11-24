"""P4: installation and scheduled execution of the pack by a restricted user, with negative tests.

Role: ``tests/validation/security/wcp_deployer.role.json`` (created as ``wcp_p4_deployer`` for the
run; ``--minimal`` drops the two read-only preflight permissions ``cluster:monitor/state`` and
``cluster:monitor/nodes/info``). User: ``wcp_p4_deployer`` with a random password held in memory
only (never printed or written).

Steps (admin = the configured indexer credentials; restricted = the temporary user):

1. precondition (admin): the pack is **not** deployed (this test installs it) and the cluster has
   room for 4 monitors (``max_monitors``);
2. admin creates the role, the user, and the index ``wcp-test-p4-noaccess`` (one document);
3. restricted, through the real CLI (``python -m wcp``, separate state directory): ``preflight``
   (no error), ``plan`` (4 creates), ``apply`` (4 created), ``status`` (4 in sync), ``execute``
   (dry run, no error);
4. the stored monitors record the restricted user as their user (read from the Alerting config
   index on the server with the super-admin certificate through ``endpoints.server``, because the
   5.0.0-rc2 REST API does not return ``user``);
5. negative, harmless (restricted): ``GET _plugins/_security/api/internalusers`` and a search on
   ``wcp-test-p4-noaccess`` must both be refused (403); nothing is written by either;
6. scheduled execution: 9 sshd ``Failed password`` lines replayed on the Linux test agent; the
   brute-force monitor **saved by the restricted user** must raise an ACTIVE alert with score 9;
7. permission removal: admin removes the role's index permission and replays a second burst.
   Pass criterion: no ACTIVE alert for the second burst (the monitor runs with the role's
   permissions). How the platform surfaces the denied search is **recorded, not assumed**: ERROR
   alerts and their messages, and a dry-run ``_execute`` of the monitor as the restricted user
   (input error or empty result);
8. cleanup (always): admin runs ``wcp remove --yes`` for the monitors, deletes user, role and
   index, and verifies all are gone. The pack is left **not deployed**; re-deploy as admin
   (``python -m wcp apply``) before tests that need it.

Run:  python tests/validation/p4_least_privilege_scheduled.py [--live] [--evidence DIR] [--minimal]
Needs: allow.create_resources, endpoints.linux_replay (UTC clock), admin indexer credentials with
security-API access.
"""

import datetime
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import vlib as V  # noqa: E402

NAME = "wcp_p4_deployer"
NOACCESS = "wcp-test-p4-noaccess"
ROLE_FILE = os.path.join(V.HERE, "security", "wcp_deployer.role.json")
PREFLIGHT_ONLY = ["cluster:monitor/state", "cluster:monitor/nodes/info"]
BF = "wcp_ssh_bruteforce"
CONN_KEYS = ("WCP_INDEXER_URL", "WCP_CA_CERT", "WCP_TLS_SERVER_NAME", "WCP_INSECURE")


def args_extra(ap):
    ap.add_argument("--minimal", action="store_true", help="role without the read-only preflight permissions")
    ap.add_argument("--ip-offset", type=int, default=0)


def role(minimal):
    with open(ROLE_FILE, "r", encoding="utf-8") as fh:
        r = json.load(fh)
    if minimal:
        r["cluster_permissions"] = [p for p in r["cluster_permissions"] if p not in PREFLIGHT_ONLY]
    r["description"] = "[wcp-test] P4 temporary copy of wcp_deployer"
    return r


def build_plan(args):
    return {"role_name": NAME, "role": role(args.minimal), "user": NAME,
            "temporary_resources": ["role " + NAME, "internal user " + NAME, "index " + NOACCESS,
                                    "4 pack monitors (installed by the restricted user, removed at the end)"],
            "restricted_cli_steps": ["preflight", "plan", "apply", "status", "execute"],
            "negative_tests": ["GET _plugins/_security/api/internalusers -> 403",
                               "POST %s/_search -> 403" % NOACCESS],
            "scheduled_burst": {"lines": 9, "source_ip": "192.0.2.%d" % (210 + args.ip_offset),
                                "expected": "ACTIVE brute-force alert, score 9"},
            "after_permission_removal": {"source_ip": "192.0.2.%d" % (211 + args.ip_offset),
                                         "expected": "no ACTIVE alert for this burst",
                                         "recorded": ["ERROR alerts and messages (not assumed)",
                                                      "dry-run _execute as the restricted user"]}}


def wcp(args_list, env):
    r = subprocess.run([sys.executable, "-m", "wcp"] + args_list, cwd=V.PACK, env=env, capture_output=True,
                       text=True, timeout=300)
    return r.returncode, (r.stdout + r.stderr).strip()


def replay_burst(ep, ip, n=9):
    import lab   # tests/lab/lab.py: sshd line format of the recorded RC1 runs
    host = ep.spec.get("hostname") or "wcp-replay"
    t0 = V.utc().replace(microsecond=0)
    lines = [lab.sshd_failed_line(t0 - datetime.timedelta(seconds=30 - 3 * i), host, "wcpt-p4-user", ip) for i in range(n)]
    V.replay_lines(ep, lines)
    return t0


def run_live(args, cfg, client, ev, plan):
    ep = V.endpoint(cfg, "linux_replay")
    agent = str(ep.spec.get("agent_id") or "")
    ids, _h = V.pack_monitor_ids(client)
    if ids:
        raise V.Refused("the pack is deployed (%s); P4 installs it - remove it as admin first" % sorted(ids))
    V.require_capacity(client, 4, ev)
    ev.d["observed"]["filter_by_backend_roles"] = V.cluster_setting(client, "plugins.alerting.filter_by_backend_roles")
    pw = secrets.token_urlsafe(24) + "aA1!"
    state = tempfile.mkdtemp(prefix="wcp-p4-state-")
    admin_env = dict(os.environ, WCP_STATE_DIR=state, WCP_TARGET="p4")
    env = {k: v for k, v in os.environ.items() if not k.startswith("WCP_")}
    env.update({k: os.environ[k] for k in CONN_KEYS if os.environ.get(k)})
    env.update({"WCP_INDEXER_USER": NAME, "WCP_INDEXER_PASSWORD": pw, "WCP_ENV_FILE": os.devnull,
                "WCP_STATE_DIR": state, "WCP_TARGET": "p4"})
    created = []
    try:
        client.put("/_plugins/_security/api/roles/" + NAME, plan["role"])
        created.append("role")
        client.put("/_plugins/_security/api/internalusers/" + NAME,
                   {"password": pw, "opendistro_security_roles": [NAME],
                    "attributes": {"purpose": "wazuh_correlation_pack P4 test (temporary)"}})
        created.append("user")
        V.create_temp_index(client, NOACCESS, V.temp_index_mapping())
        V.bulk(client, NOACCESS, [V.ssh_fixture("p4", V.iso(V.utc()), "000", "192.0.2.1")])
        created.append("index")
        # 3. restricted user through the CLI
        steps = [("preflight", ["preflight"], lambda rc, o: rc == 0 and "[error]" not in o),
                 ("plan: 4 creates", ["plan"], lambda rc, o: rc == 0 and "plan: 4 change(s)" in o),
                 ("apply: 4 created", ["apply"], lambda rc, o: rc == 0 and "applied: 4 change(s)" in o),
                 ("status: 4 in sync", ["status"], lambda rc, o: rc == 0 and o.count("in_sync=True") == 4),
                 ("execute (dry run)", ["execute"], lambda rc, o: rc == 0 and "error" not in o.lower())]
        for label, a, ok in steps:
            rc, out = wcp(a, env)
            ev.d["observed"].setdefault("restricted_cli", []).append({"step": label, "rc": rc, "output": out[-2000:]})
            ev.check("restricted user: %s" % label, ok(rc, out), "rc=%d" % rc)
        ids, hashes = V.pack_monitor_ids(client)
        ev.d["observed"]["installed_content_hashes"] = hashes
        ev.check("installed monitors carry the frozen content hashes", hashes == V.FROZEN_CONTENT_HASHES, hashes)
        api_users = {name: client.get(V.MON + "/" + mid)["monitor"].get("user") for name, mid in ids.items()}
        ev.note("monitor user returned by GET monitor (REST API)", api_users)
        stored = V.stored_monitor_users(cfg, ids.values())
        users = {name: (stored or {}).get(mid) for name, mid in ids.items()} if stored is not None else None
        ev.d["observed"]["monitor_users_stored"] = users
        if users is None:
            ev.note("stored monitor user not checked", "endpoints.server is not configured")
        else:
            ev.check("each stored monitor records the restricted user (config index, read on the server)",
                     len(users) == 4 and all((u or {}).get("name") == NAME for u in users.values()),
                     {k: [(v or {}).get("name"), (v or {}).get("roles")] for k, v in users.items()})
        # 5. negative tests
        rcl = V.Client(user=NAME, password=pw)
        for label, fn in (("security API read refused", lambda: rcl.get("/_plugins/_security/api/internalusers")),
                          ("search on an index outside the role refused",
                           lambda: rcl.post("/%s/_search" % NOACCESS, {"size": 0}))):
            try:
                fn()
                status = 200
            except V.ApiError as e:
                status = e.status
            ev.check("negative: %s (403)" % label, status == 403, status)
        # 6. scheduled execution as the restricted user
        if BF not in ids:
            raise RuntimeError("brute-force monitor not installed")
        trk = V.AlertTracker(client, ids[BF])
        ip1 = plan["scheduled_burst"]["source_ip"]
        t1 = replay_burst(ep, ip1)
        n, w = V.wait_count(client, [{"term": {"wazuh.agent.id": agent}}, {"term": {"source.ip": ip1}},
                                     {"term": {"event.reason": "Failed password"}},
                                     {"range": {"event.start": {"gte": V.iso(t1 - datetime.timedelta(seconds=40)),
                                                                "lte": V.iso(t1 + datetime.timedelta(seconds=5))}}}],
                            9, timeout=240)
        ev.check("9 replayed events searchable with event.start = replay time (replay endpoint clock in UTC)",
                 n == 9, n)
        alert = None
        end = time.time() + 300
        while time.time() < end and not alert:
            trk.poll()
            act = [a for a in trk.for_keys([agent, ip1]) if a["states"][-1][1] == "ACTIVE"]
            alert = act[0] if act else None
            time.sleep(5)
        ev.d["observed"]["scheduled_alert"] = alert
        ev.check("scheduled run of the restricted user's monitor raised an ACTIVE alert", alert is not None)
        if alert:
            ev.check("alert score 9", alert["last"]["score"] == 9, alert["last"]["score"])
        # 7. permission removal
        reduced = dict(plan["role"], index_permissions=[])
        client.put("/_plugins/_security/api/roles/" + NAME, reduced)
        t_rm = V.utc()
        ev.d["observed"]["index_permission_removed_at"] = V.iso(t_rm)
        ip2 = plan["after_permission_removal"]["source_ip"]
        t2 = replay_burst(ep, ip2)
        n2, _w = V.wait_count(client, [{"term": {"wazuh.agent.id": agent}}, {"term": {"source.ip": ip2}},
                                       {"term": {"event.reason": "Failed password"}},
                                       {"range": {"event.start": {"gte": V.iso(t2 - datetime.timedelta(seconds=40))}}}],
                              9, timeout=240)
        ev.check("second burst indexed (9 events, read as admin)", n2 == 9, n2)
        t_vis = V.utc()
        # observe for 3 scheduler runs after the second burst became searchable; no early exit
        end = time.time() + 190
        while time.time() < end:
            trk.poll()
            time.sleep(5)
        trk.poll()
        errs = trk.errors()
        ev.d["observed"]["alerts_after_removal"] = list(trk.alerts.values())
        ev.note("ERROR alerts after the index permission was removed (recorded, not a pass criterion)",
                {"count": len(errs), "messages": [(e["last"].get("error_message") or "")[:400] for e in errs][:3]})
        rcl2 = V.Client(user=NAME, password=pw)
        try:
            res = rcl2.post(V.MON + "/%s/_execute" % ids[BF], {}, params={"dryrun": "true"})
            ir = res.get("input_results") or {}
            buckets = res.get("trigger_results") or {}
            ev.note("dry-run _execute as the restricted user after the removal",
                    {"http": 200, "input_error": (ir.get("error") or "")[:600] or None,
                     "trigger_bucket_counts": {k: len((v or {}).get("agg_result_buckets") or {}) for k, v in buckets.items()}})
        except V.ApiError as e:
            ev.note("dry-run _execute as the restricted user after the removal", {"http": e.status, "error": str(e)[:600]})
        act2 = [a for a in trk.for_keys([agent, ip2]) if any(s[1] == "ACTIVE" for s in a["states"])]
        ev.check("no ACTIVE alert for the burst replayed after the removal (observed until %s)" % V.iso(V.utc()),
                 not act2, len(act2))
        ev.d["timings_s"]["observed_after_second_burst_visible"] = round((V.utc() - t_vis).total_seconds())
        # the first alert: does it resolve once its burst leaves the lookback, or stay ACTIVE while the
        # monitor cannot read the data? observe until lookback (300 s) + 2 runs after the first burst
        until = t1 + datetime.timedelta(seconds=300 + 130)
        while V.utc() < until:
            trk.poll()
            time.sleep(5)
        trk.poll()
        first = (trk.alerts.get(alert["id"]) or {}) if alert else {}
        ev.note("first alert after the removal, observed until its burst left the lookback + 2 runs (%s)" % V.iso(until),
                {"states": first.get("states"), "last": first.get("last")})
    finally:
        cl = {}
        rc, out = wcp(["remove", "--yes"], admin_env)
        cl["wcp_remove_as_admin"] = {"rc": rc, "output": out[-1500:]}
        left, _h = V.pack_monitor_ids(client)
        cl["pack_monitors_left"] = sorted(left)
        cl["user"] = V.delete_verified(client, "/_plugins/_security/api/internalusers/" + NAME)
        cl["role"] = V.delete_verified(client, "/_plugins/_security/api/roles/" + NAME)
        cl["index"] = V.delete_verified(client, "/" + NOACCESS)
        shutil.rmtree(state, ignore_errors=True)
        cl["state_dir_removed"] = not os.path.exists(state)
        ev.d["cleanup"] = cl
        ev.check("cleanup: no pack monitor, user, role or index left",
                 not left and all(cl[k] in ("deleted", "absent") for k in ("user", "role", "index")), cl)
        print("NOTE: the pack is not deployed after P4; re-deploy as admin with 'python -m wcp apply'.")


def main(argv=None):
    return V.run_test("p4", "P4: least-privilege installation and scheduled execution", build_plan, run_live,
                      argv=argv, needs=("create_resources",), extra_args=args_extra)


if __name__ == "__main__":
    raise SystemExit(main())
