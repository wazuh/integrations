"""Live SSH scenarios through the full Wazuh path.

sshd (wcp-ep1) -> journald -> wazuh-agent 5.0.0-rc1 -> manager -> engine (stock system-auth)
-> wazuh-events-v5-system-activity -> Alerting bucket-level monitor (scheduler) -> alert.

Run:  python tests/e2e/test_ssh_live.py --evidence evidence/<run-id> [scenario ...]
Needs WCP_LAB_SSH (tests/lab/lab.py) and indexer credentials (wcp/client.py).
"""

import argparse
import os
import time

import harness as H
import lab

EP1 = {"container": "wcp-ep1", "ip": "10.231.40.14", "agent": "001"}
EP2 = {"container": "wcp-ep2", "ip": "10.231.40.118", "agent": "002"}
BF = "wcp_ssh_bruteforce"
SPRAY = "wcp_ssh_password_spray"


def failed_attempt_filters(agent, src_ip, since):
    return [{"term": {"wazuh.agent.id": agent}}, {"term": {"source.ip": src_ip}},
            {"terms": {"event.reason": ["Failed password", "Failed keyboard-interactive/pam"]}},
            {"range": {"event.start": {"gte": H.iso(since)}}}]


def authfail_filters(agent, src_ip, since):
    return [{"term": {"wazuh.agent.id": agent}}, {"term": {"source.ip": src_ip}},
            {"term": {"event.action": "authentication-failure"}},
            {"range": {"event.start": {"gte": H.iso(since)}}}]


def ensure_no_active(obs, corr, keys, timeout=480):
    """Wait until the group has no ACTIVE alert (a previous episode must be over)."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        if not obs.alerts(corr, keys, "ACTIVE"):
            return True
        time.sleep(15)
    return False


def ensure_quiet(obs, agent, ip, seconds=300, timeout=600):
    """Wait until the group had no counted event for ``seconds`` (so earlier tests cannot add to the score)."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        n = obs.count_events([{"term": {"wazuh.agent.id": agent}}, {"term": {"source.ip": ip}},
                              {"terms": {"event.reason": ["Failed password", "Failed keyboard-interactive/pam"]}},
                              {"range": {"event.start": {"gte": "now-%ds" % seconds}}}])
        if n == 0:
            return True
        time.sleep(15)
    return False


def s_live_burst(obs, run_dir):
    """9 failed password attempts (3 connections x 3 prompts) from ep2 to ep1 within ~30 s."""
    ev = H.Evidence(run_dir, "ssh_live_burst_and_lifecycle", "pipeline-live")
    keys = [EP1["agent"], EP2["ip"]]
    users = ["wcpt-alice", "wcpt-bob", "wcpt-carol"]  # 3 connections x 3 password prompts = 9 attempts
    ev.d["expected"] = {
        "failed_password_events": 9,
        "bruteforce_alert": "ACTIVE for bucket %s (9 >= 8 in 2m)" % keys,
        "spray_alert": "none (3 distinct users < 5)",
        "dedup": "same alert id across >= 3 scheduled runs while activity is inside the lookback",
        "resolution": "alert leaves ACTIVE once the qualifying window leaves the 300 s lookback (COMPLETED, "
                      "then deleted: alert history is disabled by default on 5.0.0-rc1)",
        "new_episode": "a second burst after resolution creates a NEW alert with a different id",
    }
    ev.check("precondition: no ACTIVE brute-force alert for %s" % keys, ensure_no_active(obs, BF, keys))
    ev.check("precondition: no attempts from this source in the last 300 s",
             ensure_quiet(obs, EP1["agent"], EP2["ip"], 300))
    start, end, n = lab.live_ssh(EP2["container"], EP1["ip"], users, attempts_per_connection=3)
    ev.d["inputs"].append({"kind": "live sshd", "src": EP2, "dst": EP1, "users": users, "attempts_per_connection": 3,
                           "start": H.iso(start), "end": H.iso(end), "expected_attempts": n})
    since = start.replace(microsecond=0) - __import__("datetime").timedelta(seconds=1)
    got, wait_s = obs.wait_events(failed_attempt_filters(EP1["agent"], EP2["ip"], since), n)
    ev.d["timings_s"]["events_searchable_after_last_attempt"] = None if wait_s is None else round(
        (H.utcnow() - end).total_seconds(), 1)
    time.sleep(5)
    got = obs.count_events(failed_attempt_filters(EP1["agent"], EP2["ip"], since))
    lines = obs.count_events(authfail_filters(EP1["agent"], EP2["ip"], since))
    docs = obs.events([{"term": {"wazuh.agent.id": EP1["agent"]}}, {"term": {"source.ip": EP2["ip"]}},
                       {"range": {"event.start": {"gte": H.iso(since)}}}],
                      fields=["event.start", "@timestamp", "event.action", "event.reason", "user.name", "message"])
    ev.d["observed"]["failed_password_events"] = got
    ev.d["observed"]["authentication_failure_events"] = lines
    ev.d["observed"]["all_events_for_source"] = docs
    ev.check("one counted event per attempt (Failed password events == %d)" % n, got == n, got)
    ev.check("event.action=authentication-failure over-counts attempts (documented)", lines > n, lines)

    alert, _w = obs.wait_alert(BF, keys, "ACTIVE", timeout=300, since=int(start.timestamp() * 1000) - 1000)
    ev.d["timings_s"]["alert_active_after_last_attempt"] = round((H.utcnow() - end).total_seconds(), 1) if alert else None
    ev.d["observed"]["bruteforce_alert"] = H.summarize_alert(alert)
    ev.check("scheduler created an ACTIVE brute-force alert for %s" % keys, alert is not None)
    if alert:
        det = (H.summarize_alert(alert) or {}).get("detail") or {}
        ev.check("alert score == %d attempts" % n, det.get("score") == n, det.get("score"))

    # spray must not fire: 3 distinct users
    time.sleep(70)
    spray = obs.alerts(SPRAY, keys)
    spray_new = [a for a in spray if a.get("start_time", 0) >= int(start.timestamp() * 1000) - 1000]
    ev.d["observed"]["spray_alerts"] = [H.summarize_alert(a) for a in spray_new]
    ev.check("no spray alert for 3 distinct users (< 5)", not spray_new, len(spray_new))

    if alert:
        # repeated scheduled executions: same alert, no new alert for the same group
        seen = []
        for _ in range(3):
            time.sleep(62)
            act = obs.alerts(BF, keys, "ACTIVE")
            seen.append([(a["id"], a.get("last_notification_time"), a.get("state")) for a in act])
        ev.d["observed"]["active_alerts_over_3_runs"] = seen
        all_bf = [a for a in obs.alerts(BF, keys) if a.get("start_time", 0) >= int(start.timestamp() * 1000) - 1000]
        ids = {a["id"] for a in all_bf}
        ev.check("repeated runs keep one alert for the group (no duplicates)", ids == {alert["id"]}, sorted(ids))
        # resolution. On 5.0.0-rc1 plugins.alerting.alert_history_enabled defaults to false: a COMPLETED
        # alert is deleted, so resolution is observed as the alert leaving the alerts API (a COMPLETED
        # state is recorded only if a poll happens to catch it), plus a dry run showing the group no
        # longer triggers.
        t0 = time.time()
        states, gone = [], False
        while time.time() - t0 < 600:
            cur = [a for a in obs.alerts(BF, keys) if a["id"] == alert["id"]]
            st = cur[0]["state"] if cur else "ABSENT"
            if not states or states[-1][1] != st:
                states.append((round((H.utcnow() - end).total_seconds(), 1), st))
            if st != "ACTIVE":
                gone = True
                break
            time.sleep(5)
        ev.d["observed"]["alert_state_after_last_attempt_s"] = states
        ev.d["timings_s"]["alert_resolved_after_last_attempt"] = states[-1][0] if gone else None
        ev.check("alert resolved after activity left the 300 s lookback", gone, states)
        dry = obs.client.post(H.D.MONITORS + "/%s/_execute" % obs.monitors[BF], params={"dryrun": "true"})
        trig = [b.get("agg_alert_content", b).get("bucket_keys") for t in (dry.get("trigger_results") or {}).values()
                for b in (t.get("agg_result_buckets") or {}).values()]
        ev.d["observed"]["dry_run_after_resolution_triggering_groups"] = trig
        ev.check("dry run after resolution: group no longer triggers", keys not in trig, trig)
        # new episode
        start2, end2, n2 = lab.live_ssh(EP2["container"], EP1["ip"], users, attempts_per_connection=3)
        ev.d["inputs"].append({"kind": "live sshd (episode 2)", "start": H.iso(start2), "end": H.iso(end2),
                               "expected_attempts": n2})
        alert2, _w = obs.wait_alert(BF, keys, "ACTIVE", timeout=300, not_ids=(alert["id"],))
        ev.d["timings_s"]["episode2_alert_active_after_last_attempt"] = round(
            (H.utcnow() - end2).total_seconds(), 1) if alert2 else None
        ev.d["observed"]["episode2_alert"] = H.summarize_alert(alert2)
        ev.check("second episode creates a NEW alert with a different id",
                 alert2 is not None and alert2["id"] != alert["id"])
    return ev.save()


SCENARIOS = {"live_burst": s_live_burst}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", required=True)
    ap.add_argument("scenarios", nargs="*", default=list(SCENARIOS))
    a = ap.parse_args()
    obs = H.Observer()
    print("monitors:", obs.monitors)
    results = {s: SCENARIOS[s](obs, a.evidence) for s in a.scenarios}
    print(results)
    return 0 if all(v == "PASS" for v in results.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
