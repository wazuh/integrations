"""Live SSH burst (port of tests/e2e/test_ssh_live.py from the RC1 container lab).

Real failed SSH logins against the monitored Linux endpoint, through the full path:
client -> sshd on the endpoint -> journald -> wazuh-agent -> manager -> engine (stock
system-auth) -> wazuh-events-v5-system-activity -> Alerting bucket-level monitor (scheduler).

The RC1 run used a second Linux endpoint as the client. Here the client is a host that is **not**
a monitored endpoint (``ssh_live.client: workstation`` - the machine running this test), so a
single Linux endpoint suffices. Windows Server 2019's built-in OpenSSH client (7.7) cannot answer
password prompts non-interactively (``SSH_ASKPASS_REQUIRE`` needs OpenSSH >= 8.4), which is why
the workstation client is used.

Scenario (as RC1): 3 connections x 3 password prompts for non-existent test accounts
(``wcpt-alice``, ``wcpt-bob``, ``wcpt-carol``; sshd logs ``Failed password for invalid user``),
dummy password ``wcp-not-a-password`` answered by an askpass helper.

Checks:
1. pack monitors deployed with the frozen content hashes; target accounts carry the test prefix,
   are not access accounts and do not exist on the endpoint (no lockout, no success possible);
2. preconditions: no ACTIVE brute-force alert for the group; no counted attempt in the last 300 s;
3. ground truth: the endpoint's sshd journal has 9 ``Failed password`` lines from the client;
4. 9 indexed events with ``event.reason: Failed password`` (one per attempt);
5. the scheduler raises an ACTIVE brute-force alert for (agent, client address) with score 9;
6. no spray alert (3 distinct accounts < 5);
7. three further scheduled runs keep the same alert (no duplicates);
8. the alert leaves ACTIVE once the attempts leave the 300 s lookback; a dry run of the deployed
   monitor then shows the group no longer triggers;
9. a second burst after resolution creates a NEW alert with a different id.

Run:  python tests/validation/ssh_live_burst.py [--live] [--evidence DIR]
Needs: endpoints.linux_replay (agent_id, address), ssh_live.client_ip, the pack deployed.
Creates nothing on the cluster; the only side effect is failed logins of non-existent accounts.
"""

import datetime
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import vlib as V  # noqa: E402

BF = "wcp_ssh_bruteforce"
SPRAY = "wcp_ssh_password_spray"
USERS = ["wcpt-alice", "wcpt-bob", "wcpt-carol"]
PROMPTS = 3
LOOKBACK_S = 300


def build_plan(args):
    return {"client": "workstation (not a monitored endpoint)", "target": "endpoints.linux_replay",
            "users": USERS, "attempts_per_connection": PROMPTS, "attempts": len(USERS) * PROMPTS,
            "password": V.DUMMY_PASSWORD,
            "expected": {"failed_password_events": len(USERS) * PROMPTS,
                         "bruteforce_alert": "ACTIVE, score %d" % (len(USERS) * PROMPTS),
                         "spray_alert": "none (3 accounts < 5)",
                         "dedup": "same alert over 3 further runs",
                         "resolution": "leaves ACTIVE after the %d s lookback; dry run no longer triggers" % LOOKBACK_S,
                         "new_episode": "second burst -> new alert id"}}


def ssh_binary(cfg):
    b = (cfg.get("ssh_live") or {}).get("ssh_binary")
    if b:
        return b
    if os.name == "nt" and os.path.exists(r"C:\Windows\System32\OpenSSH\ssh.exe"):
        return r"C:\Windows\System32\OpenSSH\ssh.exe"
    return "ssh"


def askpass_helper(d):
    if os.name == "nt":
        p = os.path.join(d, "wcp-askpass.cmd")
        with open(p, "w", newline="\r\n") as fh:
            fh.write("@echo %s\n" % V.DUMMY_PASSWORD)
    else:
        p = os.path.join(d, "wcp-askpass")
        with open(p, "w") as fh:
            fh.write("#!/bin/sh\necho %s\n" % V.DUMMY_PASSWORD)
        os.chmod(p, 0o700)
    return p


def live_burst(cfg, target, helper):
    """One connection per user, PROMPTS password attempts each. Returns (start, end, attempts)."""
    env = dict(os.environ, SSH_ASKPASS=helper, SSH_ASKPASS_REQUIRE="force", DISPLAY="none")
    start = V.utc()
    for u in USERS:
        subprocess.run([ssh_binary(cfg), "-F", "none", "-o", "BatchMode=no", "-o", "PubkeyAuthentication=no",
                        "-o", "PreferredAuthentications=password", "-o", "NumberOfPasswordPrompts=%d" % PROMPTS,
                        "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", "%s@%s" % (u, target), "true"],
                       env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
    return start, V.utc(), len(USERS) * PROMPTS


def journal_failures(ep, since, client_ip):
    out = ep.run("journalctl -u ssh -u sshd --since '%s' --no-pager -o cat" % since.strftime("%Y-%m-%d %H:%M:%S UTC"),
                 sudo=True)
    return [l for l in out.splitlines() if "Failed password" in l and client_ip in l
            and any(" %s " % u in l for u in USERS)]


def counted(agent, ip, since):
    return [{"term": {"wazuh.agent.id": agent}}, {"term": {"source.ip": ip}},
            {"term": {"event.reason": "Failed password"}}, {"range": {"event.start": {"gte": V.iso(since)}}}]


def dry_run_groups(client, mid):
    res = client.post(V.MON + "/%s/_execute" % mid, {}, params={"dryrun": "true"})
    groups = []
    for t in (res.get("trigger_results") or {}).values():
        for b in (t.get("agg_result_buckets") or {}).values():
            groups.append((b.get("agg_alert_content") or b).get("bucket_keys"))
    return groups


def run_live(args, cfg, client, ev, plan):
    sl = cfg.get("ssh_live") or {}
    ep = V.endpoint(cfg, "linux_replay")
    agent, target, cip = str(ep.spec.get("agent_id") or ""), ep.spec.get("address"), sl.get("client_ip")
    if not (agent and target and cip):
        raise V.Refused("endpoints.linux_replay.agent_id/.address and ssh_live.client_ip are required")
    keys = [agent, cip]
    ids, hashes = V.pack_monitor_ids(client)
    for name in (BF, SPRAY):
        ev.check("%s deployed with the frozen content hash" % name,
                 hashes.get(name) == V.FROZEN_CONTENT_HASHES[name], hashes.get(name))
    if BF not in ids or SPRAY not in ids:
        raise RuntimeError("pack monitors not deployed")
    for u in USERS:
        V.check_test_account(cfg, u)
    exist = ep.run("for u in %s; do getent passwd $u >/dev/null && echo $u; done; true" % " ".join(USERS), sudo=False)
    ev.check("target accounts do not exist on the endpoint (no lockout, no success possible)",
             not exist.strip(), exist.strip())
    trk = {c: V.AlertTracker(client, ids[c]) for c in (BF, SPRAY)}
    for t_ in trk.values():
        t_.poll()
    active = [a for a in trk[BF].for_keys(keys) if a["states"][-1][1] == "ACTIVE"]
    ev.check("precondition: no ACTIVE brute-force alert for %s" % keys, not active, len(active))
    end_wait = time.time() + 600
    while time.time() < end_wait and V.count_events(client, counted(agent, cip, V.utc() - datetime.timedelta(
            seconds=LOOKBACK_S))):
        time.sleep(15)
    quiet = V.count_events(client, counted(agent, cip, V.utc() - datetime.timedelta(seconds=LOOKBACK_S)))
    ev.check("precondition: no counted attempt from %s in the last %d s" % (cip, LOOKBACK_S), quiet == 0, quiet)
    if active or quiet:
        raise RuntimeError("preconditions not met")
    tmp = tempfile.mkdtemp(prefix="wcp-sshlive-")
    try:
        helper = askpass_helper(tmp)
        start, end, n = live_burst(cfg, target, helper)
        since = start.replace(microsecond=0) - datetime.timedelta(seconds=1)
        ev.d["inputs"].append({"kind": "live ssh", "client": "workstation", "client_ip": cip, "target": target,
                               "users": USERS, "attempts_per_connection": PROMPTS,
                               "start": V.iso(start), "end": V.iso(end), "attempts": n})
        jl = journal_failures(ep, since, cip)
        ev.d["observed"]["journal_failed_password_lines"] = jl
        ev.check("ground truth: %d 'Failed password' lines in the endpoint's sshd journal" % n, len(jl) == n, len(jl))
        got, waited = V.wait_count(client, counted(agent, cip, since), n, timeout=240)
        ev.d["timings_s"]["events_searchable_after_last_attempt"] = round((V.utc() - end).total_seconds(), 1)
        time.sleep(5)
        got = V.count_events(client, counted(agent, cip, since))
        docs = V.search_events(client, [{"term": {"wazuh.agent.id": agent}}, {"term": {"source.ip": cip}},
                                        {"range": {"event.start": {"gte": V.iso(since)}}}],
                               source=["event.start", "@timestamp", "event.reason", "event.category", "event.outcome",
                                       "event.type", "user.name", "event.original"])
        ev.d["observed"]["all_events_for_source"] = docs
        ev.check("one counted event per attempt (event.reason Failed password == %d)" % n, got == n, got)
        ev.note("indexed events for the source by event.reason",
                {r: sum(1 for d in docs if (d.get("event") or {}).get("reason") == r)
                 for r in sorted({str((d.get("event") or {}).get("reason")) for d in docs})})
        # 5. scheduler alert
        alert, t_dead = None, time.time() + 300
        while time.time() < t_dead and not alert:
            for t_ in trk.values():
                t_.poll()
            act = [a for a in trk[BF].for_keys(keys) if a["states"][-1][1] == "ACTIVE" and (a["start_ms"] or 0) >= V.ms(start) - 1000]
            alert = act[0] if act else None
            time.sleep(5)
        ev.d["timings_s"]["alert_active_after_last_attempt"] = round((V.utc() - end).total_seconds(), 1) if alert else None
        ev.d["observed"]["bruteforce_alert"] = alert
        ev.check("scheduler created an ACTIVE brute-force alert for %s" % keys, alert is not None)
        if not alert:
            return
        ev.check("alert score == %d attempts" % n, alert["last"]["score"] == n, alert["last"]["score"])
        # 6./7. no spray; dedup over 3 runs
        t_obs = time.time() + 3 * 62
        while time.time() < t_obs:
            for t_ in trk.values():
                t_.poll()
            time.sleep(5)
        spray = [a for a in trk[SPRAY].for_keys(keys) if (a["start_ms"] or 0) >= V.ms(start) - 1000]
        ev.d["observed"]["spray_alerts"] = spray
        ev.check("no spray alert for 3 distinct accounts (< 5)", not spray, len(spray))
        bf_ids = sorted({a["id"] for a in trk[BF].for_keys(keys) if (a["start_ms"] or 0) >= V.ms(start) - 1000})
        ev.check("three further runs keep one alert for the group (no duplicates)", bf_ids == [alert["id"]], bf_ids)
        # 8. resolution
        t_res, gone = time.time() + 600, False
        while time.time() < t_res:
            trk[BF].poll()
            st = trk[BF].alerts[alert["id"]]["states"][-1][1]
            if st != "ACTIVE":
                gone = True
                break
            time.sleep(5)
        states = trk[BF].alerts[alert["id"]]["states"]
        ev.d["observed"]["alert_states"] = states
        ev.d["timings_s"]["alert_left_active_after_last_attempt"] = round(
            (V.parse_iso(states[-1][0]) - end).total_seconds(), 1) if gone else None
        ev.check("alert left ACTIVE after the attempts left the %d s lookback" % LOOKBACK_S, gone, states)
        groups = dry_run_groups(client, ids[BF])
        ev.d["observed"]["dry_run_after_resolution_triggering_groups"] = groups
        ev.check("dry run after resolution: group no longer triggers", keys not in groups, groups)
        # 9. new episode
        start2, end2, n2 = live_burst(cfg, target, helper)
        ev.d["inputs"].append({"kind": "live ssh (episode 2)", "start": V.iso(start2), "end": V.iso(end2),
                               "attempts": n2})
        alert2, t_dead = None, time.time() + 300
        while time.time() < t_dead and not alert2:
            trk[BF].poll()
            act = [a for a in trk[BF].for_keys(keys) if a["states"][-1][1] == "ACTIVE" and a["id"] != alert["id"]]
            alert2 = act[0] if act else None
            time.sleep(5)
        ev.d["observed"]["episode2_alert"] = alert2
        ev.d["timings_s"]["episode2_alert_active_after_last_attempt"] = round(
            (V.utc() - end2).total_seconds(), 1) if alert2 else None
        ev.check("second episode creates a NEW alert with a different id", alert2 is not None)
        if alert2:
            ev.check("episode 2 alert score == %d" % n2, alert2["last"]["score"] == n2, alert2["last"]["score"])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv=None):
    return V.run_test("ssh_live", "Live SSH burst against the monitored Linux endpoint (port of the RC1 test)",
                      build_plan, run_live, argv=argv)


if __name__ == "__main__":
    raise SystemExit(main())
