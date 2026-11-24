"""P5: notification delivery to an isolated lab receiver, including alerts that last one scheduler run.

Resources (temporary, deleted at the end): index ``wcp-test-p5``; two **test copies** of the frozen
brute-force monitor pointed at that index, each with one test-specific action (the pack's own
action rendering, ``wcp/alerting.py render_action``, with the default message):

* ``[wcp-test] p5 notify NEW``             - ``notify_on: [NEW]`` (the pack default)
* ``[wcp-test] p5 notify NEW+COMPLETED``   - ``notify_on: [NEW, COMPLETED]``

and, unless ``notifications.channel_id`` names an existing one, a webhook channel created from
``tests/validation/security/notifications_webhook_channel.json``. The deployed pack monitors are
not touched. The receiver is ``webhook_listener.py``, started in-process on
``notifications.listener_bind``; ``notifications.webhook_url`` is its address as seen from the
indexer (e.g. through ``ssh -R`` from the Wazuh server to the workstation).

Cases (each its own source address = its own alert group; event visibility controlled directly):

* probe  - a burst indexed immediately: measures each copy's run instants;
* normal - a burst indexed just after a run: NEW at the next run, then DEDUPED runs while it stays
  in the 300 s lookback, then COMPLETED;
* continued - a burst followed by one event every 10 s for 4 minutes: many DEDUPED runs;
* single_run - a burst with a ~260 s visibility delay made searchable 10 s before a run: counted by
  exactly one run (the lateness test's "before ~264 s" case), so the alert exists for ~60 s.

Assertions per copy and case: exactly one NEW notification; one COMPLETED notification for the
NEW+COMPLETED copy and none for the NEW copy; therefore none for DEDUPED runs; the single-run alert
is notified; every received body is attributable (copy + source address). Recorded: payloads,
duplicates, delivery delay (receipt - alert start/end), the channel test message.

Run:  python tests/validation/p5_notifications.py [--live] [--evidence DIR]
Needs: allow.create_resources, notifications.webhook_url / listener_bind / listener_token, admin
credentials with Notifications permissions (or an existing channel id).
"""

import datetime
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import vlib as V  # noqa: E402
import webhook_listener as WL  # noqa: E402

INDEX = V.TEST_INDEX_PREFIX + "p5"
CORR = "wcp_ssh_bruteforce"
COPIES = {"new": (V.TEST_NAME_PREFIX + "p5 notify NEW", ["NEW"]),
          "new_completed": (V.TEST_NAME_PREFIX + "p5 notify NEW+COMPLETED", ["NEW", "COMPLETED"])}
CHANNEL_FILE = os.path.join(V.HERE, "security", "notifications_webhook_channel.json")
with open(CHANNEL_FILE, "r", encoding="utf-8") as _fh:
    CHANNEL_ID = __import__("json").load(_fh)["config_id"]
CASES = {"probe": "192.0.2.250", "normal": "192.0.2.101", "continued": "192.0.2.102", "single_run": "192.0.2.103"}
LOOKBACK = 300


def expected_counts():
    return {copy: {case: {"NEW": 1, "COMPLETED": 1 if "COMPLETED" in pol else 0} for case in CASES}
            for copy, (_n, pol) in COPIES.items()}


def build_plan(args):
    return {"index": INDEX, "monitor_copies": {k: {"name": v[0], "notify_on": v[1]} for k, v in COPIES.items()},
            "cases": CASES, "expected_notifications": expected_counts(),
            "single_run_case": "burst of 8 (7 s span), last event 260 s before it becomes searchable, made "
                               "searchable 10 s before a run: next run counts it (277 s <= 300 s lookback), the "
                               "following does not (337 s)",
            "channel": "notifications.channel_id or a temporary channel from %s" % os.path.relpath(CHANNEL_FILE, V.PACK)}


def send_channel_test(client, cid):
    for method in ("POST", "GET"):
        try:
            return client.request(method, "/_plugins/_notifications/feature/test/" + cid), method
        except V.ApiError as e:
            if e.status not in (400, 404, 405):
                raise
            last = e
    raise last


def run_live(args, cfg, client, ev, plan):
    nc = cfg.get("notifications") or {}
    url, bind, token = nc.get("webhook_url"), nc.get("listener_bind"), nc.get("listener_token")
    if not (url and bind and token) or token not in url:
        raise V.Refused("notifications.webhook_url, listener_bind and listener_token are required "
                        "(the URL must contain the token)")
    V.refuse_on_leftovers(client, ev, indices=[INDEX], channels=[] if nc.get("channel_id") else [CHANNEL_ID])
    V.require_capacity(client, len(COPIES), ev)
    host, port = bind.rsplit(":", 1)
    li = WL.Listener(host, port, token).start()
    created_channel, cid, mids = False, nc.get("channel_id"), {}
    try:
        if cid:
            ch = client.get("/_plugins/_notifications/configs/" + cid)
            ev.d["observed"]["channel"] = {"id": cid, "existing": True, "type": json.dumps(ch)[:300]}
        else:
            with open(CHANNEL_FILE, "r", encoding="utf-8") as fh:
                body = json.load(fh)
            body["config"]["webhook"]["url"] = url
            cid = client.post("/_plugins/_notifications/configs", body).get("config_id") or body["config_id"]
            created_channel = True
            ev.d["observed"]["channel"] = {"id": cid, "existing": False}
        # Notifications refuses webhook targets in its host deny list (RC2 default: loopback and all
        # private/TEST-NET ranges); record the effective value the delivery depended on.
        ev.d["observed"]["notifications_host_deny_list"] = V.cluster_setting(
            client, "opensearch.notifications.core.http.host_deny_list")
        t = V.utc()
        res, method = send_channel_test(client, cid)
        ev.d["observed"]["channel_test"] = {"method": method, "response": json.dumps(res)[:500]}
        end = time.time() + 60
        while time.time() < end and not [r for r in li.snapshot() if r["path_ok"]]:
            time.sleep(1)
        got = [r for r in li.snapshot() if r["path_ok"]]
        ev.check("channel test message reached the lab receiver", bool(got),
                 (V.parse_iso(got[0]["received"]) - t).total_seconds() if got else None)
        if not got:
            raise RuntimeError("the receiver is not reachable from the indexer; fix notifications.webhook_url")
        n_test = len(li.snapshot())
        V.create_temp_index(client, INDEX, V.temp_index_mapping())
        for k, (name, pol) in COPIES.items():
            body, corr, st = V.temp_monitor_body(CORR, INDEX, name,
                                                 actions=[{"name": "p5-" + k, "channel_id": cid, "notify_on": pol}])
            mids[k] = client.post(V.MON, body)["_id"]
        ev.d["observed"]["monitors"] = mids
        trk = {k: V.AlertTracker(client, m) for k, m in mids.items()}

        def poll():
            for t_ in trk.values():
                t_.poll()

        # probe: run instants of each copy
        V.bulk(client, INDEX, V.burst_docs("probe", CASES["probe"], V.utc() - datetime.timedelta(seconds=1)))
        runs = {}
        end = time.time() + 150
        while time.time() < end and len(runs) < len(trk):
            poll()
            for k, t_ in trk.items():
                a = t_.for_keys(["009", CASES["probe"]])
                if a and k not in runs:
                    runs[k] = V.from_ms(a[0]["start_ms"])
            time.sleep(1)
        if len(runs) < len(trk):
            raise RuntimeError("probe did not alert on every copy: %s" % runs)
        ev.d["observed"]["probe_run_times"] = {k: V.iso(v) for k, v in runs.items()}
        base = runs["new"]
        k = 1
        while base + datetime.timedelta(seconds=60 * k) < V.utc() + datetime.timedelta(seconds=20):
            k += 1
        R = lambda j: base + datetime.timedelta(seconds=60 * (k + j))   # noqa: E731
        actions = [(R(0) + datetime.timedelta(seconds=10), "normal", 1)]
        actions.append((R(1) + datetime.timedelta(seconds=10), "continued", 1))
        for i in range(1, 25):
            actions.append((R(1) + datetime.timedelta(seconds=10 + 10 * i), "continued_tick", None))
        actions.append((R(3) + datetime.timedelta(seconds=50), "single_run", 260))
        actions.sort(key=lambda a: a[0])
        sched = []
        for when, case, delay in actions:
            V.sleep_until(when, poll)
            now = V.utc()
            if case == "continued_tick":
                V.bulk(client, INDEX, [V.ssh_fixture("continued", V.iso(now - datetime.timedelta(seconds=1)), "009",
                                                     CASES["continued"])])
                continue
            last = now - datetime.timedelta(seconds=delay)
            V.bulk(client, INDEX, V.burst_docs(case, CASES[case], last))
            sched.append({"case": case, "visible": V.iso(V.utc()), "last_event": V.iso(last),
                          "first_event": V.iso(last - datetime.timedelta(seconds=7))})
        ev.d["inputs"] = sched
        # single-run expectation from each copy's measured grid
        sr = [s for s in sched if s["case"] == "single_run"][0]
        for kk, r0 in runs.items():
            gr = V.grid(r0, 60, V.parse_iso(sr["visible"]), V.parse_iso(sr["visible"]) + datetime.timedelta(seconds=200))
            first = V.parse_iso(sr["first_event"])
            counting = [g for g in gr if (g - first).total_seconds() <= LOOKBACK]
            ev.d["expected"].setdefault("single_run_counting_runs", {})[kk] = [V.iso(g) for g in counting]
        # observe until every case has completed (or 15 min)
        t_done = actions[-1][0] + datetime.timedelta(seconds=LOOKBACK + 30)   # every burst out of the lookback
        end = time.time() + 900
        while time.time() < end:
            poll()
            open_ = [a for t_ in trk.values() for a in t_.alerts.values() if a["states"][-1][1] in ("ACTIVE", "ERROR")]
            if not open_ and V.utc() > t_done:
                break
            time.sleep(2)
        time.sleep(20)   # last deliveries
        poll()
        recs = li.snapshot()
        ev.d["observed"]["received"] = recs
        names = {v[0]: k for k, v in COPIES.items()}
        counts = {copy: {case: {"NEW": 0, "COMPLETED": 0} for case in CASES} for copy in COPIES}
        unattributed, delays = [], []
        for r in recs[n_test:]:
            if not r["path_ok"]:
                continue
            c = WL.classify(r["body"], list(names), list(CASES.values()))
            if not c["monitor"] or not (c["new"] or c["completed"]):
                unattributed.append(r["body"][:300])
                continue
            copy = names[c["monitor"]]
            for kind, ips in (("NEW", c["new"]), ("COMPLETED", c["completed"])):
                for ip in ips:
                    case = [k_ for k_, v in CASES.items() if v == ip][0]
                    counts[copy][case][kind] += 1
                    al = trk[copy].for_keys(["009", ip])
                    if al:
                        ref = al[0]["start_time"] if kind == "NEW" else (al[0]["last"].get("end_time") or None)
                        if ref:
                            delays.append({"copy": copy, "case": case, "kind": kind,
                                           "delay_s": round((V.parse_iso(r["received"]) - V.parse_iso(ref)).total_seconds(), 2)})
        ev.d["observed"]["notification_counts"] = counts
        ev.d["observed"]["unattributed_bodies"] = unattributed
        ev.d["timings_s"]["delivery"] = delays
        ev.d["observed"]["alerts"] = {k: list(t_.alerts.values()) for k, t_ in trk.items()}
        exp = expected_counts()
        for copy in COPIES:
            for case in CASES:
                al = trk[copy].for_keys(["009", CASES[case]])
                ev.check("%s / %s: one alert" % (copy, case), len(al) == 1, len(al))
                ev.check("%s / %s: notifications %s" % (copy, case, exp[copy][case]),
                         counts[copy][case] == exp[copy][case], counts[copy][case])
        ev.check("every received notification attributable to a copy and a case", not unattributed, len(unattributed))
        for copy in COPIES:
            al = trk[copy].for_keys(["009", CASES["single_run"]])
            ev.note("%s single_run alert states" % copy, al[0]["states"] if al else None)
    finally:
        cl = {}
        for k, m in mids.items():
            cl["monitor_" + k] = V.delete_verified(client, V.MON + "/" + m)
        cl["index"] = V.delete_verified(client, "/" + INDEX)
        if created_channel:
            cl["channel"] = V.delete_verified(client, "/_plugins/_notifications/configs/" + cid)
        li.stop()
        ev.d["cleanup"] = cl
        ev.check("cleanup: temporary monitors, index%s deleted" % (", channel" if created_channel else ""),
                 all(v in ("deleted", "absent") for v in cl.values()), cl)


def main(argv=None):
    return V.run_test("p5", "P5: notification delivery incl. single-run alerts", build_plan, run_live, argv=argv,
                      needs=("create_resources",))


if __name__ == "__main__":
    raise SystemExit(main())
