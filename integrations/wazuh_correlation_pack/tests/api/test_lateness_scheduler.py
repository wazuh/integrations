"""Lateness versus scheduling phase, with the real Alerting scheduler (no ingestion pipeline).

A temporary monitor (the brute-force correlation rendered for the temporary index
``wcp-test-lateness``, *without* the pack marker) is created and run by the Alerting scheduler
every minute. Bursts of 8 events (event times spanning 7 s) are made searchable (bulk with
refresh=wait_for) at chosen *visibility delays* after their last event time and at chosen
*phases* of the schedule:

* phase "after":  10 s after a run executed (worst case: the next run is ~50 s away)
* phase "mid":    30 s after a run
* phase "before": 10 s before the next run (best case)

The run instants are measured first (probe bursts; alert ``start_time``). For each burst the
expected outcome follows from the monitor definition (lookback = 120 s window + 120 s lateness
+ 60 s interval = 300 s): it is counted iff some run executing after it became searchable has a
period end no later than (first event time + 300 s). Period end is taken as the run's execution
time (a run's period end is at or slightly before its execution; every case keeps a margin of
at least 15 s so this approximation cannot change the outcome).

What it shows: target delays of 110, 120 and 130 s (actual visibility delays ~110.5, ~121.5 and
~132.5 s, i.e. one within and two slightly beyond the 120 s allowed lateness) are counted in
every phase, and beyond that the outcome depends on the scheduling phase until the lookback is
exceeded. It does not sweep delays below ~110 s and does not hit exactly 120 s; the guarantee
for every delay <= 120 s follows from the lookback arithmetic and is confirmed at ~110 s.
What it does not show: ingestion delays (visibility is controlled directly), missed or late
scheduler runs, or behaviour under load.

The harness polls the alerts API every 2 s for the whole run: a burst counted by a single run
(events leaving the lookback at the next run) yields an alert that exists for only ~60 s when
alert history is disabled.

Run: python tests/api/test_lateness_scheduler.py --evidence DIR [--repetitions 2]
Creates and deletes: index wcp-test-lateness, monitor "[wcp-test] lateness scheduler probe".
"""

import argparse
import copy
import datetime
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, PACK)
sys.path.insert(0, HERE)

from wcp import alerting as A  # noqa: E402
from wcp import config as C  # noqa: E402
from wcp import sigma as S  # noqa: E402
from wcp.client import DEFAULT_ENV_FILE, ApiError, Client, load_env_file  # noqa: E402

from test_monitor_execute import MAPPING, ssh  # noqa: E402

INDEX = "wcp-test-lateness"
NAME = "[wcp-test] lateness scheduler probe"
MON = "/_plugins/_alerting/monitors"
SPAN = 7
LOOKBACK = 300
CASES = [("after", 10, d) for d in (110, 120, 130, 260)] + \
        [("mid", 30, d) for d in (110, 120, 130)] + \
        [("before", 50, d) for d in (110, 120, 130, 260, 330)]   # "before" = 50 s after a run = 10 s before the next


def utc():
    return datetime.datetime.now(datetime.timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def ms(dt):
    return int(dt.timestamp() * 1000)


def from_ms(v):
    return datetime.datetime.fromtimestamp(v / 1000.0, datetime.timezone.utc)


class Probe(object):
    def __init__(self, client, mid):
        self.client, self.mid, self.seen = client, mid, {}

    def poll(self):
        res = self.client.get(MON + "/alerts", params={"monitorId": self.mid, "alertState": "ALL", "size": 200})
        for a in res.get("alerts", []):
            k = tuple((a.get("agg_alert_content") or {}).get("bucket_keys") or [])
            self.seen.setdefault(k, {})
            self.seen[k].setdefault(a["id"], a.get("start_time"))
        return self.seen


def index_burst(client, ip, last_event, tag):
    docs = [ssh(tag, iso(last_event - datetime.timedelta(seconds=SPAN - i * SPAN / 7.0)), "009", ip, "a")
            for i in range(8)]
    body = "".join(json.dumps({"index": {"_index": INDEX}}) + "\n" + json.dumps(d) + "\n" for d in docs)
    t0 = utc()
    r = client.post("/_bulk", body, params={"refresh": "wait_for"})
    t1 = utc()
    assert not r.get("errors"), json.dumps(r)[:1000]
    return t0, t1, last_event - datetime.timedelta(seconds=SPAN)


def wait_until(t, poll=None):
    """Sleep until t, polling alerts every 2 s meanwhile: with alert history disabled (5.0.0-rc1
    default) an alert whose events stay in the lookback for a single run exists for only ~60 s."""
    last = 0.0
    while True:
        dt = (t - utc()).total_seconds()
        if dt <= 0:
            return
        if poll and time.time() - last >= 2:
            poll()
            last = time.time()
        time.sleep(min(dt, 0.5))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--repetitions", type=int, default=2)
    a = ap.parse_args()
    load_env_file(os.environ.get("WCP_ENV_FILE", DEFAULT_ENV_FILE))
    cl = Client()
    _r, cs = S.load_content(PACK)
    corr = [c for c in cs if c.name == "wcp_ssh_bruteforce"][0]
    prof = C.load_profile(os.path.join(PACK, "pack.yml"))
    st = dict(C.settings_for(prof, corr.name), indices=[INDEX])
    assert A.lookback_seconds(corr, st) == LOOKBACK
    body = A.render_monitor(corr, st, prof["version"])
    body["inputs"][0]["search"]["query"]["aggregations"][A.GROUP_AGG].pop("meta", None)   # not a pack monitor
    body["name"] = NAME
    ev = {"test": "lateness vs scheduling phase (real Alerting scheduler, controlled visibility)",
          "index": INDEX, "monitor_name": NAME, "lookback_s": LOOKBACK, "window_s": corr.timespan_s,
          "allowed_lateness_s": st["allowed_lateness_s"], "interval_s": st["interval_s"], "span_s": SPAN,
          "started": iso(utc()), "cases": [], "runs_observed": []}
    mid = None
    try:
        try:
            cl.delete("/" + INDEX)
        except ApiError as e:
            if e.status != 404:
                raise
        cl.put("/" + INDEX, MAPPING)
        mid = cl.post(MON, body)["_id"]
        mon = cl.get(MON + "/" + mid)["monitor"]
        ev["monitor_enabled_time"] = iso(from_ms(mon["enabled_time"])) if isinstance(mon.get("enabled_time"), int) \
            else mon.get("enabled_time")
        pr = Probe(cl, mid)
        # 1. measure run instants with two probes 35 s apart
        runs = []
        for i, ip in enumerate(("192.0.2.250", "192.0.2.251")):
            t0, t1, _a = index_burst(cl, ip, utc() - datetime.timedelta(seconds=2), "probe%d" % i)
            deadline = time.time() + 150
            while time.time() < deadline:
                got = pr.poll().get(("009", ip))
                if got:
                    runs.append(from_ms(list(got.values())[0]))
                    break
                time.sleep(1)
            if i == 0:
                wait_until(utc() + datetime.timedelta(seconds=35), pr.poll)
        if len(runs) < 2:
            raise RuntimeError("scheduler probes did not alert: %s" % runs)
        interval = (runs[1] - runs[0]).total_seconds()
        ev["probe_run_times"] = [iso(r) for r in runs]
        ev["probe_interval_s"] = round(interval, 3)
        base = runs[1]
        # 2. cases, `repetitions` cycles, starting at the first run >= now + 15 s
        k = 1
        while base + datetime.timedelta(seconds=60 * k) < utc() + datetime.timedelta(seconds=15):
            k += 1
        n = 0
        plan = []
        for rep in range(a.repetitions):
            run = base + datetime.timedelta(seconds=60 * (k + 2 * rep))
            for phase, off, d in CASES:
                n += 1
                plan.append({"rep": rep, "phase": phase, "phase_offset_s": off, "delay_s": d,
                             "ip": "192.0.2.%d" % (100 + n), "run_ref": run,
                             "visible_at": run + datetime.timedelta(seconds=off)})
        plan.sort(key=lambda c: c["visible_at"])
        for c in plan:
            wait_until(c["visible_at"], pr.poll)
            last_event = c["visible_at"] - datetime.timedelta(seconds=c["delay_s"])
            t0, t1, first = index_burst(cl, c["ip"], last_event, "case")
            c.update({"bulk_start": t0, "visible": t1, "first_event": first, "last_event": last_event})
            pr.poll()
        # 3. observe until every burst is older than the lookback at any possible run
        end = max(c["first_event"] for c in plan) + datetime.timedelta(seconds=LOOKBACK + 75)
        while utc() < end:
            pr.poll()
            time.sleep(2)
        seen = pr.poll()
        # all run instants seen (alert creation times), for the record
        allstarts = sorted({v for g in seen.values() for v in g.values() if v})
        ev["alert_creation_times"] = [iso(from_ms(v)) for v in allstarts]
        # 4. expectation from the measured schedule (runs every `interval` from `base`)
        fails = 0
        for c in plan:
            vis = c["visible"]
            j = 0
            while base + datetime.timedelta(seconds=interval * j) < vis:
                j += 1
            next_run = base + datetime.timedelta(seconds=interval * j)
            margin = (c["first_event"] + datetime.timedelta(seconds=LOOKBACK) - next_run).total_seconds()
            expected = margin >= 0
            alerts = seen.get(("009", c["ip"]), {})
            observed = bool(alerts)
            obs_run = iso(from_ms(min(alerts.values()))) if alerts else None
            ok = observed == expected and abs(margin) >= 15
            fails += 0 if ok else 1
            actual_delay = (vis - c["last_event"]).total_seconds()
            print("[%s] rep %d %-6s delay %5.1f s (target %3d): next run %s, margin %6.1f s -> expected %-9s observed %s" % (
                "PASS" if ok else "FAIL", c["rep"], c["phase"], actual_delay, c["delay_s"], iso(next_run), margin,
                "alert" if expected else "no alert", ("alert at %s" % obs_run) if observed else "no alert"))
            ev["cases"].append({
                "rep": c["rep"], "phase": c["phase"], "target_delay_s": c["delay_s"],
                "actual_visibility_delay_s": round(actual_delay, 2),
                "first_event": iso(c["first_event"]), "last_event": iso(c["last_event"]),
                "visible_at": iso(vis), "next_run_after_visible": iso(next_run),
                "margin_s": round(margin, 1), "expected_alert": expected, "observed_alert": observed,
                "alert_created": obs_run, "pass": ok})
        ev["verdict"] = "PASS" if not fails else "FAIL"
    finally:
        cleanup = {}
        if mid:
            try:
                cl.delete(MON + "/" + mid)
                cleanup["monitor_deleted"] = True
            except ApiError as e:
                cleanup["monitor_deleted"] = "error %s" % e.status
        try:
            cl.delete("/" + INDEX)
            cleanup["index_deleted"] = True
        except ApiError as e:
            cleanup["index_deleted"] = "error %s" % e.status
        ev["cleanup"] = cleanup
        ev["finished"] = iso(utc())
        os.makedirs(a.evidence, exist_ok=True)
        with open(os.path.join(a.evidence, "api_lateness_scheduler.json"), "w", encoding="utf-8") as fh:
            json.dump(ev, fh, indent=2, default=str)
        print("cleanup:", cleanup, "verdict:", ev.get("verdict"))
    return 0 if ev.get("verdict") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
