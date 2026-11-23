"""Replay batches (port of tests/e2e/test_replay.py from the RC1 container lab).

The scenarios, their lines and their expectations are the ones defined in
``tests/e2e/test_replay.py`` (``ssh_batch``, ``windows_batch``), unchanged. What changes is the
transport: lines are appended over SSH to the replay file of the configured Linux endpoint
(``endpoints.linux_replay``) instead of ``lxc exec`` into the RC1 containers, and the run uses the
validation gate (lab configuration, cluster identity, machine locks) and evidence format.

Scenarios that put lines on a **second monitored Linux endpoint** (``EP2`` in the definitions:
``bf_different_endpoints``, ``spray_split_endpoints``) need two agents and are recorded as
DEFERRED when only one Linux endpoint is configured - never as passed.

Per scenario, as in RC1: every counted event searchable; ``event.action:
authentication-failure`` counts where the scenario defines them; per correlation and group an
alert with the expected score, or no alert during ``--observe`` seconds of scheduled runs.

The score assertion compares the alert's score **at creation** (first snapshot), as the RC1 runner
did: an ACTIVE alert's bucket is refreshed by every later (DEDUPED) run, so its latest score
decreases as events leave the lookback (``replay_ssh_run1..3.json`` read the latest snapshot and
failed for that reason). The batch is replayed just after a scheduler run of its monitors (grid
from ``enabled_time``) and the scenarios are built at that moment (event ages relative to the
replay unchanged); the instant each group's counted events were all searchable is recorded, and an
alert created before that is labelled as timing.

Run:  python tests/validation/replay_batches.py --batch ssh|windows [--live] [--evidence DIR]
Needs: endpoints.linux_replay (agent_id, hostname, replay file, UTC clock), the pack deployed.
Creates nothing on the cluster.
"""

import datetime
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "e2e"))

import vlib as V  # noqa: E402
import test_replay as TR  # noqa: E402  scenario definitions of the RC1 run (tests/e2e/test_replay.py)

from wcp import query as Q  # noqa: E402

RC1_EP1_AGENT = "001"   # agent id written into the RC1 scenario expectations


def args_extra(ap):
    ap.add_argument("--batch", choices=["ssh", "windows"], required=True)
    ap.add_argument("--observe", type=int, default=240)
    ap.add_argument("--ip-offset", type=int, default=0)
    ap.add_argument("--only", help="comma-separated scenario names")


def scenarios(args, agent="001", host="wcp-replay"):
    TR.IP_OFFSET[0] = args.ip_offset
    TR.EP1 = {"container": "linux_replay", "agent": agent, "host": host}
    TR.EP2 = {"container": "SECOND_LINUX_ENDPOINT", "agent": "<second endpoint>", "host": "wcp-ep2"}
    t0 = V.utc().replace(microsecond=0)
    sc = TR.ssh_batch(t0) if args.batch == "ssh" else TR.windows_batch(t0)
    if args.only:
        sc = [s for s in sc if s["name"] in args.only.split(",")]

    def remap(d):
        return {((agent if k[0] == RC1_EP1_AGENT else k[0]), k[1]): v for k, v in d.items()}
    run, deferred = [], []
    for s in sc:
        if any(ep["container"] == "SECOND_LINUX_ENDPOINT" for ep, _l in s["lines"]):
            deferred.append({"scenario": s["name"], "description": s["desc"],
                             "reason": "needs a second monitored Linux endpoint (two agents)"})
            continue
        s["expect"] = {c: remap(m) for c, m in s["expect"].items()}
        s["counted"] = remap(s["counted"])
        if s.get("authfail"):
            s["authfail"] = remap(s["authfail"])
        run.append(s)
    return run, deferred


def build_plan(args):
    run, deferred = scenarios(args)
    return {"batch": args.batch, "source": "tests/e2e/test_replay.py (scenario definitions, unchanged)",
            "scenarios": [{"name": s["name"], "description": s["desc"], "lines": len(s["lines"]),
                           "expect": {c: {"%s|%s" % k: v for k, v in m.items()} for c, m in s["expect"].items()}}
                          for s in run],
            "deferred": deferred}


def align_after_run(client, monitor_ids, margin_s=2.0, max_spread_s=15.0):
    """Wait until just after the latest scheduled run of the given monitors (1-minute grids anchored to
    ``enabled_time``); returns the computed instants. Refuses if the grids are too far apart."""
    now = V.ms(V.utc())
    nxt = []
    for mid in monitor_ids:
        m = client.get(V.MON + "/" + mid)["monitor"]
        sch = (m.get("schedule") or {}).get("period") or {}
        step = int(sch.get("interval", 1)) * {"MINUTES": 60000, "SECONDS": 1000, "HOURS": 3600000}.get(
            sch.get("unit", "MINUTES"), 60000)
        en = int(m["enabled_time"])
        k = (now - en) // step + 1
        nxt.append(en + k * step)
    spread = (max(nxt) - min(nxt)) / 1000.0
    if spread > max_spread_s and spread < 60 - max_spread_s:
        raise V.Refused("the monitors' run grids are %.0f s apart; re-apply the pack so they share a grid" % spread)
    target = max(nxt) + int(margin_s * 1000)
    V.sleep_until(V.from_ms(target))
    return {"next_runs": [V.ms_iso(x) for x in nxt], "grid_spread_s": spread, "replay_after": V.ms_iso(target)}


def run_live(args, cfg, client, ev, plan):
    ep = V.endpoint(cfg, "linux_replay")
    agent = str(ep.spec.get("agent_id") or "")
    host = ep.spec.get("hostname") or "wcp-replay"
    if not agent:
        raise V.Refused("endpoints.linux_replay.agent_id is not set")
    run, deferred = scenarios(args, agent, host)
    ev.d["deferred"] = deferred
    for d in deferred:
        ev.note("DEFERRED %s" % d["scenario"], d["reason"])
    ids, hashes = V.pack_monitor_ids(client)
    corrs = sorted({c for s in run for c in s["expect"]})
    for c in corrs:
        ev.check("%s deployed with the candidate content hash" % c, hashes.get(c) == V.FROZEN_CONTENT_HASHES[c],
                 hashes.get(c))
    content, _p = V.pack_content()
    by_name = {c.name: c for c in content.values()}
    # groups must be quiet (no earlier events of these sources inside the longest lookback)
    for s in run:
        for (_a, ip) in s["counted"]:
            n = V.count_events(client, [{"term": {"source.ip": ip}}, {"range": {"event.start": {"gte": "now-15m"}}}])
            if n:
                raise V.Refused("source %s already has %d events in the last 15 min; use --ip-offset" % (ip, n))
    # replay just after a scheduler run of the batch's monitors, then build the scenarios at that moment
    grid = align_after_run(client, [ids[c] for c in corrs])
    ev.d["observed"]["alignment"] = grid
    run, deferred = scenarios(args, agent, host)
    t_replay = V.utc()
    lines = [l for s in run for _ep, l in s["lines"]]
    V.replay_lines(ep, lines)
    t_written = V.utc()
    ev.d["observed"]["replayed"] = {"lines": len(lines), "at": V.iso(t_written)}
    for s in run:
        ev.d["inputs"].append({"scenario": s["name"], "description": s["desc"], "lines": len(s["lines"]),
                               "first_lines": [l for _e, l in s["lines"][:3]]})
    since = V.iso(t_replay - datetime.timedelta(seconds=5))
    visible = {}   # (scenario, agent, ip) -> ms when all counted events were searchable
    pending = {}
    for s in run:
        sel = Q.correlation_selection(by_name[list(s["expect"])[0]])
        for (a, ip), n in s["counted"].items():
            pending[(s["name"], a, ip)] = ([{"term": {"wazuh.agent.id": a}}, {"term": {"source.ip": ip}}, sel,
                                           {"range": {"@timestamp": {"gte": since}}}], n)
    end = time.time() + 240
    counts = {}
    while pending and time.time() < end:
        for k, (filt, n) in list(pending.items()):
            counts[k] = V.count_events(client, filt)
            if counts[k] >= n:
                visible[k] = V.ms(V.utc())
                del pending[k]
        time.sleep(1)
    ev.d["observed"]["fully_searchable_after_replay_s"] = {
        "%s %s|%s" % k: round((v - V.ms(t_written)) / 1000.0, 1) for k, v in visible.items()}
    for s in run:
        for (a, ip), n in s["counted"].items():
            got = counts.get((s["name"], a, ip))
            ev.check("%s %s|%s: %d counted events searchable" % (s["name"], a, ip, n), got == n, got)
        for (a, ip), n in (s.get("authfail") or {}).items():
            filt = [{"term": {"wazuh.agent.id": a}}, {"term": {"source.ip": ip}},
                    {"term": {"event.action": "authentication-failure"}}, {"range": {"@timestamp": {"gte": since}}}]
            got, _w = V.wait_count(client, filt, n, timeout=120)
            ev.check("%s %s|%s: %d events normalized as authentication-failure (vs %d counted attempts)" % (
                s["name"], a, ip, n, s["counted"][(a, ip)]), got == n, got)
    trk = {c: V.AlertTracker(client, ids[c]) for c in corrs}
    deadline = time.time() + args.observe
    print("observing scheduled runs for %d s" % args.observe)
    while time.time() < deadline:
        for t in trk.values():
            t.poll()
        time.sleep(5)
    since_ms = V.ms(t_replay) - 1000
    for s in run:
        for c, m in s["expect"].items():
            for key, want in m.items():
                al = [x for x in trk[c].for_keys(list(key)) if (x["start_ms"] or 0) >= since_ms]
                k = "%s|%s" % key
                ev.d["observed"].setdefault(s["name"], {}).setdefault(c, {})[k] = al
                if want is None:
                    ev.check("%s %s %s: no alert in %d s of scheduled runs" % (s["name"], c, k, args.observe), not al,
                             len(al))
                else:
                    ev.check("%s %s %s: exactly one scheduler alert" % (s["name"], c, k), len(al) == 1, len(al))
                    vis = visible.get((s["name"],) + tuple(key))
                    if al and vis and (al[0]["start_ms"] or 0) < vis - 1000:
                        ev.note("%s %s %s: TIMING - the alert was created by a run before all counted events were "
                                "searchable (alert %s, searchable %s); its score is the partial count of that run"
                                % (s["name"], c, k, al[0]["start_time"], V.ms_iso(vis)), al[0]["first"]["score"])
                    if al:
                        ev.check("%s %s %s: score %s at alert creation" % (s["name"], c, k, want),
                                 al[0]["first"]["score"] == want, al[0]["first"]["score"])
                        if al[0]["last"]["score"] != al[0]["first"]["score"]:
                            ev.note("%s %s %s: score refreshed by later runs (latest snapshot %s)" % (
                                s["name"], c, k, al[0]["last_seen"]), al[0]["last"]["score"])


def main(argv=None):
    ap_args = list(argv if argv is not None else sys.argv[1:])
    batch = "ssh"
    if "--batch" in ap_args:
        batch = ap_args[ap_args.index("--batch") + 1]
    return V.run_test("replay_%s" % batch, "Replay batch %s (port of RC1 tests 7/8)" % batch, build_plan, run_live,
                      argv=argv, extra_args=args_extra)


if __name__ == "__main__":
    raise SystemExit(main())
