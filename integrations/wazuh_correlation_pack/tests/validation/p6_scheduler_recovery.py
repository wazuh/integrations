"""P6: missed scheduler runs and recovery - disabling a monitor vs an enabled monitor missing runs.

A temporary test copy of the frozen brute-force monitor (``[wcp-test] p6 scheduler recovery``) on
the temporary index ``wcp-test-p6``; event visibility is controlled directly (bulk with
refresh=wait_for), as in tests/api/test_lateness_scheduler.py. Lookback 300 s, interval 60 s.

Part a - **disabled, then re-enabled** (the monitor is switched off; nothing is "missed" from the
scheduler's point of view):

* ``continuing`` - a burst before the disable plus one event every 10 s until 130 s after the
  re-enable: records what happens to an ACTIVE alert across disable/enable and whether the
  re-enabled monitor deduplicates it or opens a NEW (duplicate) alert;
* ``gap``  - made searchable 10 s after the disable with a 100 s visibility delay: a run 40 s later
  would have counted it, the first run after the re-enable (>= 230 s later) cannot (outside the
  lookback): a detection gap caused by the disable;
* ``kept`` - made searchable 120 s after the disable (delay ~1 s): still inside the lookback at the
  first run after the re-enable: counted late;
* ``after`` - made searchable 65 s after the re-enable: measures the second run after it.

Checks: no run while disabled; the first run after the re-enable is ~1 interval after the new
``enabled_time`` (no immediate catch-up run), the second one interval later; ``gap`` never alerts;
``kept`` alerts at the first run after the re-enable.

Part b - **enabled monitor missing runs** (``--part b``; dedicated lab server only;
``allow.restart_indexer``): the indexer service is restarted while the monitor stays enabled.

* ``continuing`` - ACTIVE before the restart, more events after it: state of the alert after the
  restart (kept / deduplicated / completed) and any duplicate NEW alert are recorded;
* ``kept`` - searchable 10 s before a run that the restart is expected to miss (delay ~1 s);
* ``gap``  - searchable 15 s before that run with a 248 s delay: only that run can count it.

Both parts add a *heartbeat* group (a new burst) every 30 s, so every scheduled run creates an alert
and the alert creation times mark the run instants (a DEDUPED run leaves no trace in the alerts API:
on 5.0.0-rc1 ``last_notification_time`` did not change across runs without actions).

Recorded: stop/up times, the first run after the restart (from the heartbeat, ``kept`` and probe alerts),
missed grid slots, whether runs stay on the old grid or restart from the restart time; checks:
the cluster came back, the outcome of ``kept`` and ``gap`` is consistent with the measured runs
(counted iff a run after visibility has period end <= first event + 300 s).

Run:  python tests/validation/p6_scheduler_recovery.py [--live] [--evidence DIR] [--part a|b]
Needs: allow.create_resources; part b also allow.restart_indexer and endpoints.server.
"""

import datetime
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import vlib as V  # noqa: E402

INDEX = V.TEST_INDEX_PREFIX + "p6"
NAME = V.TEST_NAME_PREFIX + "p6 scheduler recovery"
CORR = "wcp_ssh_bruteforce"
LOOKBACK, INTERVAL, SPAN = 300, 60, 7
IPS = {"probe": "192.0.2.240", "continuing": "192.0.2.121", "gap": "192.0.2.122", "kept": "192.0.2.123",
       "after": "192.0.2.124", "probe2": "192.0.2.241"}
TOL = 5.0


def args_extra(ap):
    ap.add_argument("--part", choices=["a", "b"], default="a")
    ap.add_argument("--min-available-mb", type=int, default=1024, help="part b: abort if the server has less")


def build_plan(args):
    if args.part == "a":
        tl = [("R+10", "continuing burst + one event every 10 s until E+130"), ("D = R+70", "disable"),
              ("D+10", "gap: visible, last event 100 s earlier (first = D-97; lookback ends D+203)"),
              ("D+120", "kept: visible, delay ~1 s (first ~ D+112)"), ("E = D+180", "re-enable"),
              ("E+65", "after: visible, delay ~1 s")]
        exp = {"runs_while_disabled": 0, "first_run_after_enable": "E+60 (+-%ds)" % TOL,
               "second_run_after_enable": "E+120", "gap": "never counted (detection gap)",
               "kept": "counted at E+60", "continuing": "recorded: alert across disable/enable"}
    else:
        tl = [("R+10", "continuing burst + one event every 10 s until the restart and for 120 s after it"),
              ("M = R+120", "the run the restart is expected to miss"),
              ("M-15", "gap: visible, delay 248 s (first = M-270): only the run at M can count it "
                       "(M+60 is 330 s after its first event)"),
              ("M-10", "kept: visible, delay ~1 s"), ("M-8", "restart the indexer service")]
        exp = {"recorded": ["first run after the restart", "missed grid slots", "grid anchor after restart",
                            "state of the ACTIVE continuing alert", "duplicate NEW alerts"],
               "kept": "counted iff the first run after visibility has period end <= first event + 300 s",
               "gap": "counted iff the run at M happened"}
    return {"part": args.part, "index": INDEX, "monitor": NAME, "lookback_s": LOOKBACK, "interval_s": INTERVAL,
            "timeline": tl, "expected": exp, "source_ips": IPS}


class Run(object):
    def __init__(self, client, ev):
        self.c, self.ev, self.mid, self.body, self.trk = client, ev, None, None, None
        self.ticks = []

    def setup(self):
        V.require_capacity(self.c, 1, self.ev)
        V.create_temp_index(self.c, INDEX, V.temp_index_mapping())
        self.body, _c, _s = V.temp_monitor_body(CORR, INDEX, NAME)
        self.mid = self.c.post(V.MON, self.body)["_id"]
        self.trk = V.AlertTracker(self.c, self.mid)

    def poll(self):
        try:
            self.trk.poll()
        except (V.ApiError, OSError):
            pass       # indexer restarting

    def burst(self, case, delay=1.0):
        now = V.utc()
        last = now - datetime.timedelta(seconds=delay)
        V.bulk(self.c, INDEX, V.burst_docs(case, IPS[case], last))
        rec = {"case": case, "visible": V.utc(), "last_event": last,
               "first_event": last - datetime.timedelta(seconds=SPAN)}
        self.ev.d["inputs"].append({k: (V.iso(v) if isinstance(v, datetime.datetime) else v) for k, v in rec.items()})
        return rec

    def heartbeat(self):
        """A new 8-event group every call: each run that follows creates one alert for it, so the alert
        creation times mark the run instants (DEDUPED runs leave no other trace in the alerts API)."""
        self.hb = getattr(self, "hb", 0) + 1
        if self.hb > 50:
            return
        self.hb_times = getattr(self, "hb_times", []) + [V.utc()]
        V.bulk(self.c, INDEX, V.burst_docs("heartbeat", "192.0.2.%d" % (150 + self.hb), V.utc() - datetime.timedelta(seconds=1)))

    def tick(self):
        V.bulk(self.c, INDEX, [V.ssh_fixture("continuing", V.iso(V.utc() - datetime.timedelta(seconds=1)), "009",
                                             IPS["continuing"])])

    def first_alert(self, case):
        a = self.trk.for_keys(["009", IPS[case]])
        return V.from_ms(a[0]["start_ms"]) if a else None

    def wait_alert(self, case, timeout):
        end = time.time() + timeout
        while time.time() < end:
            self.poll()
            t = self.first_alert(case)
            if t:
                return t
            time.sleep(1)
        return None

    def set_enabled(self, enabled):
        self.c.put(V.MON + "/" + self.mid, dict(self.body, enabled=enabled))
        m = self.c.get(V.MON + "/" + self.mid)["monitor"]
        return m.get("enabled"), V.from_ms(m.get("enabled_time")) if isinstance(m.get("enabled_time"), int) else None

    def cleanup(self):
        cl = {}
        if self.mid:
            cl["monitor"] = V.delete_verified(self.c, V.MON + "/" + self.mid)
        cl["index"] = V.delete_verified(self.c, "/" + INDEX)
        self.ev.d["cleanup"] = cl
        self.ev.check("cleanup: temporary monitor and index deleted", all(v in ("deleted", "absent") for v in cl.values()), cl)


def measure_base(r):
    r.burst("probe")
    t = r.wait_alert("probe", 150)
    if not t:
        raise RuntimeError("probe did not alert")
    r.ev.d["observed"]["probe_run"] = V.iso(t)
    return t


def ticking_sleep(r, until, tick_until, heartbeat=True):
    """Sleep until ``until``, adding one continuing event every 10 s while now < tick_until and a
    heartbeat group every 30 s (skipped while the indexer is unreachable)."""
    nxt = V.utc()
    hb = getattr(r, "next_hb", V.utc())
    while V.utc() < until:
        if V.utc() >= nxt and V.utc() < tick_until:
            try:
                r.tick()
            except (V.ApiError, OSError):
                pass
            nxt = V.utc() + datetime.timedelta(seconds=10)
        if heartbeat and V.utc() >= hb:
            try:
                r.heartbeat()
            except (V.ApiError, OSError):
                pass
            hb = V.utc() + datetime.timedelta(seconds=30)
            r.next_hb = hb
        r.poll()
        time.sleep(1)


def part_a(r, ev):
    R = measure_base(r)
    while R < V.utc() + datetime.timedelta(seconds=5):
        R += datetime.timedelta(seconds=INTERVAL)
    R -= datetime.timedelta(seconds=INTERVAL)          # the last run before now
    far = V.utc() + datetime.timedelta(hours=1)
    ticking_sleep(r, R + datetime.timedelta(seconds=10), far)
    r.burst("continuing")
    ticking_sleep(r, R + datetime.timedelta(seconds=70), far)
    states_before = {a["id"]: a["states"][-1][1] for a in r.trk.for_keys(["009", IPS["continuing"]])}
    en, _t = r.set_enabled(False)
    D = V.utc()
    ev.d["observed"]["disabled_at"] = V.iso(D)
    ev.check("monitor disabled", en is False, en)
    ticking_sleep(r, D + datetime.timedelta(seconds=10), far)
    gap = r.burst("gap", delay=100)
    ticking_sleep(r, D + datetime.timedelta(seconds=120), far)
    kept = r.burst("kept")
    ticking_sleep(r, D + datetime.timedelta(seconds=180), far)
    alerts_while_disabled = [a for a in r.trk.alerts.values() if (a["start_ms"] or 0) >= V.ms(D)]
    ev.d["observed"]["heartbeats_indexed_while_disabled"] = len([x for x in getattr(r, "hb_times", []) if x >= D])
    en, E = r.set_enabled(True)
    E_obs = V.utc()
    ev.d["observed"]["enabled_time_after_reenable"] = V.iso(E)
    ev.check("monitor re-enabled with a new enabled_time", en is True and E is not None and E >= D, V.iso(E))
    E = E or E_obs
    ticking_sleep(r, E + datetime.timedelta(seconds=65), E + datetime.timedelta(seconds=130))
    r.burst("after")
    ticking_sleep(r, E + datetime.timedelta(seconds=200), E + datetime.timedelta(seconds=130))
    t_kept, t_after, t_gap = r.first_alert("kept"), r.first_alert("after"), r.first_alert("gap")
    ev.check("no alert created while the monitor was disabled", not alerts_while_disabled, len(alerts_while_disabled))
    ev.check("no catch-up run at re-enable: first run after it ~E+60 (kept alerted at E+60 +- %ds)" % TOL,
             t_kept is not None and abs((t_kept - E).total_seconds() - INTERVAL) <= TOL,
             None if t_kept is None else round((t_kept - E).total_seconds(), 2))
    ev.check("second run after re-enable ~E+120 (grid anchored to the new enabled_time)",
             t_after is not None and abs((t_after - E).total_seconds() - 2 * INTERVAL) <= TOL,
             None if t_after is None else round((t_after - E).total_seconds(), 2))
    would = R + datetime.timedelta(seconds=2 * INTERVAL)        # the run the disable suppressed
    ev.d["observed"]["gap"] = {"first_event": V.iso(gap["first_event"]), "visible": V.iso(gap["visible"]),
                               "would_have_been_counted_at": V.iso(would),
                               "margin_at_suppressed_run_s": round(
                                   (gap["first_event"] + datetime.timedelta(seconds=LOOKBACK) - would).total_seconds(), 1),
                               "margin_at_first_run_after_enable_s": round(
                                   (gap["first_event"] + datetime.timedelta(seconds=LOOKBACK) -
                                    (E + datetime.timedelta(seconds=INTERVAL))).total_seconds(), 1),
                               "alerted": V.iso(t_gap)}
    ev.check("gap: never counted (detection gap caused by the disable)", t_gap is None, V.iso(t_gap))
    ev.check("kept: counted by the first run after re-enable", t_kept is not None, V.iso(t_kept))
    cont = r.trk.for_keys(["009", IPS["continuing"]])
    ev.d["observed"]["continuing_alerts"] = cont
    ev.note("continuing group: alert states before the disable", states_before)
    ev.note("continuing group: alerts (id, start, states) across disable/enable",
            [(a["id"], a["start_time"], a["states"]) for a in cont])
    ev.note("continuing group: NEW alert(s) created after the re-enable (duplicates of an episode)",
            len([a for a in cont if (a["start_ms"] or 0) >= V.ms(E)]))


def part_b(r, ev, cfg, args):
    srv = V.endpoint(cfg, "server")
    svc = srv.spec.get("indexer_service") or "wazuh-indexer"
    mem = srv.run("free -m | awk '/^Mem:/ {print $7}'", sudo=False).strip()
    ev.d["observed"]["server_available_mb_before"] = mem
    if not mem.isdigit() or int(mem) < args.min_available_mb:
        raise V.Refused("server available memory %s MB < %d MB" % (mem, args.min_available_mb))
    R = measure_base(r)
    while R < V.utc() + datetime.timedelta(seconds=5):
        R += datetime.timedelta(seconds=INTERVAL)
    R -= datetime.timedelta(seconds=INTERVAL)
    far = V.utc() + datetime.timedelta(hours=1)
    ticking_sleep(r, R + datetime.timedelta(seconds=10), far)
    r.burst("continuing")
    M = R + datetime.timedelta(seconds=2 * INTERVAL)   # the run the restart is expected to miss
    ev.d["observed"]["run_expected_to_be_missed"] = V.iso(M)
    ticking_sleep(r, M - datetime.timedelta(seconds=15), far)
    gap = r.burst("gap", delay=248)
    ticking_sleep(r, M - datetime.timedelta(seconds=10), far)
    kept = r.burst("kept")
    ticking_sleep(r, M - datetime.timedelta(seconds=8), far)
    before = {a["id"]: a["states"][-1][1] for a in r.trk.for_keys(["009", IPS["continuing"]])}
    ev.note("continuing alert(s) before the restart", before)
    t_stop = V.utc()
    srv.run("systemctl restart %s" % svc, timeout=900, sudo=True)
    t_cmd = V.utc()
    up = None
    end = time.time() + 900
    while time.time() < end:
        try:
            h = r.c.get("/_cluster/health")
            if h.get("status") in ("green", "yellow"):
                up = V.utc()
                break
        except (V.ApiError, OSError):
            pass
        time.sleep(2)
    ev.d["observed"]["restart"] = {"stop_requested": V.iso(t_stop), "restart_command_returned": V.iso(t_cmd),
                                   "cluster_back": V.iso(up)}
    ev.check("cluster back after the restart", up is not None, V.iso(up))
    if not up:
        raise RuntimeError("indexer did not come back within 15 minutes")
    r.burst("probe2")
    ticking_sleep(r, up + datetime.timedelta(seconds=150), up + datetime.timedelta(seconds=120))
    t_kept, t_gap, t_p2 = r.first_alert("kept"), r.first_alert("gap"), r.first_alert("probe2")
    # run instants: alert creations of any group (heartbeats make one per run) and last_notification_time
    runs = sorted({V.from_ms(x) for x in r.trk.run_marks})
    runs_after = [x for x in runs if x >= t_stop]
    first_after = runs_after[0] if runs_after else None
    ev.d["observed"]["first_run_after_restart"] = V.iso(first_after)
    ev.d["observed"]["observed_run_instants"] = [V.iso(x) for x in runs]
    ev.check("a scheduled run happened after the restart (monitor still enabled)", first_after is not None,
             V.iso(first_after))
    missed = missed_slots(R, t_stop, first_after or up, first_after)
    ev.d["observed"]["missed_grid_slots"] = missed
    ev.d["observed"]["run_at_M_happened"] = run_m = t_kept is not None and t_kept <= M + datetime.timedelta(seconds=TOL)
    if first_after:
        off = ((first_after - R).total_seconds()) % INTERVAL
        ev.note("first run after restart: offset from the old grid (s)", round(min(off, INTERVAL - off), 2))
        ev.note("first run after restart: seconds after the cluster was back", round((first_after - up).total_seconds(), 2))
    for name, rec, t in (("kept", kept, t_kept), ("gap", gap, t_gap)):
        lim = rec["first_event"] + datetime.timedelta(seconds=LOOKBACK)
        ev.d["observed"][name] = {"first_event": V.iso(rec["first_event"]), "visible": V.iso(rec["visible"]),
                                  "lookback_end": V.iso(lim), "alerted": V.iso(t)}
    # gap can only be counted by the run at M; that run would also have counted kept (visible at M-10)
    ev.check("gap counted iff the run at M happened (kept alerted at M)", (t_gap is not None) == run_m,
             {"gap_alerted": V.iso(t_gap), "run_at_M": run_m})
    # kept must be counted by the first run after it became searchable, if that run is inside its lookback
    lim_k = kept["first_event"] + datetime.timedelta(seconds=LOOKBACK)
    first_vis = [x for x in runs if x >= kept["visible"]]
    should = bool(first_vis) and first_vis[0] <= lim_k
    ev.check("kept counted at the first observed run after it became searchable iff that run is inside its lookback",
             (t_kept is not None and abs((t_kept - first_vis[0]).total_seconds()) <= TOL) if should else t_kept is None,
             {"first_run_after_visible": V.iso(first_vis[0]) if first_vis else None, "kept_alerted": V.iso(t_kept)})
    ev.note("detection gap from the missed run(s)", "gap " + ("counted" if t_gap else "NOT counted") +
            ("; kept " + ("counted" if t_kept else "NOT counted")))
    ev.note("probe after restart alerted", V.iso(t_p2))
    cont = r.trk.for_keys(["009", IPS["continuing"]])
    ev.d["observed"]["continuing_alerts"] = cont
    ev.note("continuing group: alerts across the restart (id, start, states)", [(a["id"], a["start_time"], a["states"])
                                                                              for a in cont])
    ev.note("continuing group: NEW alerts started after the restart while one was ACTIVE before it",
            len([a for a in cont if (a["start_ms"] or 0) >= V.ms(t_stop)]))
    mem2 = srv.run("free -m | awk '/^Mem:/ {print $7}'", sudo=False).strip()
    ev.d["observed"]["server_available_mb_after"] = mem2


def missed_slots(anchor, t_stop, t_end, first_after):
    """Grid slots from the stop request until the first observed run after the restart, excluding the slot
    that run executed in (a run starts a fraction of a second after its nominal slot)."""
    return [V.iso(g) for g in V.grid(anchor, INTERVAL, t_stop, t_end)
            if not first_after or (first_after - g).total_seconds() > TOL]


def run_live(args, cfg, client, ev, plan):
    if ev.path:
        ev.path = os.path.join(os.path.dirname(ev.path), "p6_part_%s.json" % args.part)
    V.refuse_on_leftovers(client, ev, indices=[INDEX])     # before the try: a collision is reported, not cleaned
    r = Run(client, ev)
    try:
        r.setup()
        if args.part == "a":
            part_a(r, ev)
        else:
            if (cfg.get("allow") or {}).get("restart_indexer") is not True:
                raise V.Refused("allow.restart_indexer is not true")
            part_b(r, ev, cfg, args)
    finally:
        r.cleanup()


def main(argv=None):
    return V.run_test("p6", "P6: missed scheduler runs and recovery", build_plan, run_live, argv=argv,
                      needs=("create_resources",), extra_args=args_extra)


if __name__ == "__main__":
    raise SystemExit(main())
