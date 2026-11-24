"""Replay scenarios: controlled event times and sources through the supported ingestion path.

Lines are appended to /var/log/wcp-replay/replay.log on a test endpoint and collected by the
wazuh-agent (log_format syslog) -> manager -> engine (stock decoders) -> events index ->
Alerting scheduler. sshd/journald (and, for Windows, the EventChannel collector) are NOT
exercised: see test_ssh_live.py for the live sshd path.

Every scenario uses its own TEST-NET source address, so it is its own alert group and all
scenarios of a batch run concurrently. The runner replays the batch, waits until every
event is searchable, then watches the scheduler for ``--observe`` seconds (default 4 runs)
and checks, per scenario and correlation, that an alert exists (with the expected score) or
that none was created.

Run:  python tests/e2e/test_replay.py --evidence evidence/<run-id> --batch ssh
"""

import argparse
import datetime
import time

import harness as H
import lab

EP1 = {"container": "wcp-ep1", "agent": "001", "host": "wcp-ep1"}
EP2 = {"container": "wcp-ep2", "agent": "002", "host": "wcp-ep2"}
USERS = ["wcpt-u%02d" % i for i in range(1, 400)]


def at(t0, s):
    return t0 + datetime.timedelta(seconds=s)


# --------------------------------------------------------------------- SSH scenarios
# Each returns dict(name, desc, lines=[(endpoint, line)], counted={(agent, ip): n},
#                   expect={correlation: {(agent, ip): score or None}})

def ssh_failed(ep, t, user, ip, invalid=False):
    return (ep, lab.sshd_failed_line(t, ep["host"], user, ip, invalid))


IP_OFFSET = [0]


def tn(prefix, octet):
    return "%s.%d" % (prefix, octet + IP_OFFSET[0])


def ssh_batch(t0):
    S = []
    BF, SP = "wcp_ssh_bruteforce", "wcp_ssh_password_spray"

    def sc(name, desc, lines, expect, counted=None):
        S.append({"name": name, "desc": desc, "lines": lines, "expect": expect, "counted": counted or {}})

    ip = tn("203.0.113", 11)
    sc("bf_below_threshold", "7 attempts in 60 s (threshold 8 in 2m)",
       [ssh_failed(EP1, at(t0, -70 + i * 10), "wcpt-alice", ip) for i in range(7)],
       {BF: {("001", ip): None}}, {("001", ip): 7})
    ip = tn("203.0.113", 12)
    sc("bf_exactly_threshold", "8 attempts in 70 s",
       [ssh_failed(EP1, at(t0, -80 + i * 10), "wcpt-alice", ip) for i in range(8)],
       {BF: {("001", ip): 8}}, {("001", ip): 8})
    ip = tn("203.0.113", 13)
    sc("bf_above_threshold", "12 attempts in 55 s",
       [ssh_failed(EP1, at(t0, -60 + i * 5), "wcpt-bob", ip) for i in range(12)],
       {BF: {("001", ip): 12}}, {("001", ip): 12})
    ip = tn("203.0.113", 14)
    offs = [0, 20, 40, 60, 80, 100, 110, 120]
    sc("bf_span_equals_window", "8 attempts whose first and last are exactly 120 s apart (half-open window: max 7)",
       [ssh_failed(EP1, at(t0, -130 + o), "wcpt-alice", ip) for o in offs],
       {BF: {("001", ip): None}}, {("001", ip): 8})
    ip = tn("203.0.113", 15)
    offs = [0, 20, 40, 60, 80, 100, 110, 119]
    sc("bf_span_inside_window", "8 attempts spanning 119 s",
       [ssh_failed(EP1, at(t0, -130 + o), "wcpt-alice", ip) for o in offs],
       {BF: {("001", ip): 8}}, {("001", ip): 8})
    ip = tn("203.0.113", 16)
    sc("bf_split_beyond_window", "4 attempts, then 4 more 150 s later (lookback holds all 8, the window does not)",
       [ssh_failed(EP1, at(t0, -200 + i), "wcpt-alice", ip) for i in range(4)] +
       [ssh_failed(EP1, at(t0, -50 + i), "wcpt-alice", ip) for i in range(4)],
       {BF: {("001", ip): None}}, {("001", ip): 8})
    a, b = tn("203.0.113", 17), tn("203.0.113", 18)
    sc("bf_different_sources", "5 attempts from each of two sources on one endpoint",
       [ssh_failed(EP1, at(t0, -40 + i * 3), "wcpt-alice", a) for i in range(5)] +
       [ssh_failed(EP1, at(t0, -39 + i * 3), "wcpt-alice", b) for i in range(5)],
       {BF: {("001", a): None, ("001", b): None}}, {("001", a): 5, ("001", b): 5})
    ip = tn("203.0.113", 19)
    sc("bf_different_endpoints", "5 attempts from one source on each of two endpoints",
       [ssh_failed(EP1, at(t0, -40 + i * 3), "wcpt-alice", ip) for i in range(5)] +
       [ssh_failed(EP2, at(t0, -39 + i * 3), "wcpt-alice", ip) for i in range(5)],
       {BF: {("001", ip): None, ("002", ip): None}}, {("001", ip): 5, ("002", ip): 5})
    ip = tn("203.0.113", 20)
    lines = []
    for i in range(5):
        for l in lab.sshd_attempt_lines(at(t0, -50 + i * 8), EP1["host"], "wcpt-nouser%d" % i, ip, invalid=True):
            lines.append((EP1, l))
    sc("bf_lines_vs_attempts", "5 invalid-user attempts = 25 sshd lines (15 normalized as authentication-failure)",
       lines, {BF: {("001", ip): None}}, {("001", ip): 5})
    S[-1]["authfail"] = {("001", ip): 15}
    ip = tn("203.0.113", 21)
    line = lab.sshd_failed_line(at(t0, -30), EP1["host"], "wcpt-alice", ip, pid=4242, port=50000)
    sc("bf_duplicate_delivery", "the same 4 records delivered twice (identical content, no event identity)",
       [(EP1, line.replace("port 50000", "port %d" % (50000 + i))) for i in range(4)] * 2,
       {BF: {("001", ip): 8}}, {("001", ip): 8})
    ip = tn("203.0.113", 22)
    sc("bf_late_within_lateness", "8 attempts stamped 120-113 s before delivery (delay = allowed lateness)",
       [ssh_failed(EP1, at(t0, -120 + i), "wcpt-alice", ip) for i in range(8)],
       {BF: {("001", ip): 8}}, {("001", ip): 8})
    ip = tn("203.0.113", 23)
    sc("bf_late_beyond_lookback", "8 attempts stamped 400 s before delivery (older than the 300 s lookback)",
       [ssh_failed(EP1, at(t0, -400 + i), "wcpt-alice", ip) for i in range(8)],
       {BF: {("001", ip): None}}, {("001", ip): 8})

    ip = tn("203.0.113", 31)
    sc("spray_one_user_repeated", "10 failures for one user: brute force yes, spray no",
       [ssh_failed(EP1, at(t0, -60 + i * 5), "wcpt-alice", ip) for i in range(10)],
       {BF: {("001", ip): 10}, SP: {("001", ip): None}}, {("001", ip): 10})
    ip = tn("203.0.113", 32)
    sc("spray_exactly_threshold", "5 distinct users, one failure each (threshold 5 in 10m)",
       [ssh_failed(EP1, at(t0, -60 + i * 10), USERS[i], ip, invalid=True) for i in range(5)],
       {SP: {("001", ip): 5}, BF: {("001", ip): None}}, {("001", ip): 5})
    ip = tn("203.0.113", 33)
    sc("spray_below_threshold_many_attempts", "4 distinct users, 3 failures each (12 attempts)",
       [ssh_failed(EP1, at(t0, -60 + i * 4), USERS[i % 4], ip, invalid=True) for i in range(12)],
       {SP: {("001", ip): None}, BF: {("001", ip): 12}}, {("001", ip): 12})
    ip = tn("203.0.113", 34)
    sc("spray_split_endpoints", "6 distinct users from one source, 3 on each endpoint",
       [ssh_failed(EP1, at(t0, -60 + i * 10), USERS[i], ip, invalid=True) for i in range(3)] +
       [ssh_failed(EP2, at(t0, -55 + i * 10), USERS[i + 3], ip, invalid=True) for i in range(3)],
       {SP: {("001", ip): None, ("002", ip): None}}, {("001", ip): 3, ("002", ip): 3})
    ip = tn("203.0.113", 35)
    sc("spray_beyond_window", "5 distinct users over 660 s (every 10-minute window holds at most 4)",
       [ssh_failed(EP1, at(t0, -660 + i * 165), USERS[i], ip, invalid=True) for i in range(5)],
       {SP: {("001", ip): None}}, {("001", ip): 5})
    ip = tn("203.0.113", 36)
    sc("spray_exact_distinct_300", "300 distinct users in 100 s (exact distinct count, no HLL estimate)",
       [ssh_failed(EP1, at(t0, -100 + i // 3), USERS[i], ip, invalid=True) for i in range(300)],
       {SP: {("001", ip): 300}, BF: {("001", ip): 300}}, {("001", ip): 300})
    return S


# --------------------------------------------------------------------- Windows scenarios

def win(ep, t, user, ip):
    return (ep, lab.win_4625_line(t, user, ip))


def windows_batch(t0):
    S = []
    BURST, SP = "wcp_windows_failed_logon_burst", "wcp_windows_password_spray"

    def sc(name, desc, lines, expect, counted=None):
        S.append({"name": name, "desc": desc, "lines": lines, "expect": expect, "counted": counted or {}})

    ip = tn("198.51.100", 41)
    sc("win_burst_below", "9 x 4625 for Administrator in 45 s (threshold 10 in 2m)",
       [win(EP1, at(t0, -50 + i * 5), "Administrator", ip) for i in range(9)],
       {BURST: {("001", ip): None}}, {("001", ip): 9})
    ip = tn("198.51.100", 42)
    sc("win_burst_exactly", "10 x 4625 for Administrator in 50 s",
       [win(EP1, at(t0, -55 + i * 5), "Administrator", ip) for i in range(10)],
       {BURST: {("001", ip): 10}, SP: {("001", ip): None}}, {("001", ip): 10})
    ip = tn("198.51.100", 43)
    sc("win_spray_exactly", "5 distinct accounts, one 4625 each",
       [win(EP1, at(t0, -50 + i * 10), "svc-user%02d" % i, ip) for i in range(5)],
       {SP: {("001", ip): 5}, BURST: {("001", ip): None}}, {("001", ip): 5})
    ip = tn("198.51.100", 44)
    sc("win_spray_below", "4 distinct accounts, 3 x 4625 each",
       [win(EP1, at(t0, -60 + i * 4), "svc-user%02d" % (i % 4), ip) for i in range(12)],
       {SP: {("001", ip): None}, BURST: {("001", ip): 12}}, {("001", ip): 12})
    return S


# --------------------------------------------------------------------- runner

def run_batch(obs, scenarios, run_dir, batch, observe_s):
    t_replay = H.utcnow()
    total = 0
    by_ep = {}
    for s in scenarios:
        for ep, line in s["lines"]:
            by_ep.setdefault(ep["container"], []).append(line)
    for c, lines in by_ep.items():
        total += lab.replay(c, lines)
    t_written = H.utcnow()
    print("replayed %d lines at %s" % (total, H.iso(t_written)))
    results = {}
    for s in scenarios:
        ev = H.Evidence(run_dir, "%s__%s" % (batch, s["name"]), "pipeline-replay")
        ev.d["description"] = s["desc"]
        ev.d["inputs"] = [{"endpoint": ep["container"], "line": l} for ep, l in s["lines"][:40]]
        ev.d["inputs_total_lines"] = len(s["lines"])
        ev.d["replayed_at"] = H.iso(t_written)
        ev.d["expected"] = {c: {"%s|%s" % k: v for k, v in m.items()} for c, m in s["expect"].items()}
        s["_ev"] = ev
        results[s["name"]] = ev
    # events searchable
    for s in scenarios:
        ev = s["_ev"]
        corr = obs.corr(list(s["expect"])[0])
        sel = H.A.Q.correlation_selection(corr) if hasattr(H.A, "Q") else None
        for (agent, ip), n in s["counted"].items():
            filt = [{"term": {"wazuh.agent.id": agent}}, {"term": {"source.ip": ip}}, sel,
                    {"range": {"@timestamp": {"gte": H.iso(t_replay - datetime.timedelta(seconds=5))}}}]
            got, waited = obs.wait_events(filt, n, timeout=240)
            ev.d["observed"].setdefault("counted_events", {})["%s|%s" % (agent, ip)] = got
            ev.d["timings_s"].setdefault("searchable_after_replay", {})["%s|%s" % (agent, ip)] = \
                round((H.utcnow() - t_written).total_seconds(), 1) if waited is not None else None
            ev.check("%s|%s: %d counted events searchable" % (agent, ip, n), got == n, got)
    for s in scenarios:
        for (agent, ip), n in (s.get("authfail") or {}).items():
            filt = [{"term": {"wazuh.agent.id": agent}}, {"term": {"source.ip": ip}},
                    {"term": {"event.action": "authentication-failure"}},
                    {"range": {"@timestamp": {"gte": H.iso(t_replay - datetime.timedelta(seconds=5))}}}]
            got, _w = obs.wait_events(filt, n, timeout=120)
            s["_ev"].d["observed"].setdefault("authentication_failure_events", {})["%s|%s" % (agent, ip)] = got
            s["_ev"].check("%s|%s: %d events normalized as authentication-failure (vs %d counted attempts)" % (
                agent, ip, n, s["counted"][(agent, ip)]), got == n, got)
    print("all events searchable at %s; observing scheduler for %d s" % (H.iso(H.utcnow()), observe_s))
    since = int(t_replay.timestamp() * 1000) - 1000
    deadline = time.time() + observe_s
    seen = {}  # (scenario, corr, key) -> {alert_id: (first snapshot, seconds after replay)}
    groups = [(s["name"], corr, key) for s in scenarios for corr, m in s["expect"].items() for key in m]
    while time.time() < deadline:
        by_corr = {}
        for _n, corr, _k in groups:
            if corr not in by_corr:
                by_corr[corr] = [a for a in obs.alerts(corr) if a.get("start_time", 0) >= since]
        for name, corr, key in groups:
            for a in by_corr[corr]:
                if (a.get("agg_alert_content") or {}).get("bucket_keys") == list(key):
                    d = seen.setdefault((name, corr, key), {})
                    if a["id"] not in d:
                        d[a["id"]] = (H.summarize_alert(a), round((H.utcnow() - t_written).total_seconds(), 1))
        time.sleep(10)
    for s in scenarios:
        ev = s["_ev"]
        for corr, m in s["expect"].items():
            for key, want in m.items():
                k = "%s|%s" % key
                got = seen.get((s["name"], corr, key), {})
                ev.d["observed"].setdefault("alerts", {}).setdefault(corr, {})[k] = [v[0] for v in got.values()]
                if want is None:
                    ev.check("%s %s: no alert in %d s of scheduled runs" % (corr, k, observe_s), not got, len(got))
                else:
                    ev.check("%s %s: exactly one scheduler alert" % (corr, k), len(got) == 1, len(got))
                    if got:
                        snap, secs = list(got.values())[0]
                        det = (snap or {}).get("detail") or {}
                        ev.check("%s %s: score %s" % (corr, k, want), det.get("score") == want, det.get("score"))
                        ev.d["timings_s"].setdefault("alert_seen_after_replay", {})["%s %s" % (corr, k)] = secs
        results[s["name"]] = ev.save()
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--batch", choices=["ssh", "windows"], required=True)
    ap.add_argument("--observe", type=int, default=240)
    ap.add_argument("--only", help="comma-separated scenario names")
    ap.add_argument("--ip-offset", type=int, default=0, help="added to every TEST-NET last octet (isolate re-runs)")
    a = ap.parse_args()
    IP_OFFSET[0] = a.ip_offset
    obs = H.Observer()
    print("monitors:", obs.monitors)
    t0 = H.utcnow().replace(microsecond=0)
    sc = ssh_batch(t0) if a.batch == "ssh" else windows_batch(t0)
    if a.only:
        sc = [s for s in sc if s["name"] in a.only.split(",")]
    res = run_batch(obs, sc, a.evidence, a.batch, a.observe)
    bad = [k for k, v in res.items() if v != "PASS"]
    print("PASS %d / %d%s" % (len(res) - len(bad), len(res), (" ; FAIL: %s" % ", ".join(bad)) if bad else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
