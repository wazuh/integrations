"""P1 (and the synthetic part of P2): Windows account-identity scenarios through the ingestion pipeline.

Path: 4625 records (synthetic, derived from the real capture; tests/validation/identity_scenarios.py)
appended to the replay file of a Linux test agent -> agent logcollector -> manager -> engine (stock
Windows decoders) -> ``wazuh-events-v5-system-activity`` -> the **deployed** frozen pack monitors run
by the Alerting scheduler. The EventChannel collector is not exercised (that is P3).

Assertions, per scenario (each scenario has its own TEST-NET source address = its own alert group):

1. the deployed spray / burst monitors carry the frozen content hashes (frozen revision under test);
2. every record is indexed exactly once (matched by EventRecordID in ``event.original``);
3. decoded identity fields equal the decoder model (``winevents.decoder_model``, the RC1 decoder
   steps; for subject-present records this is the shape derived from the decoder and never
   observed before);
4. the Python reference ``wcp.identity`` on the decoded document gives the specified account;
5. a dry run of a threshold-1 copy of the spray monitor (nothing saved) shows the Painless
   identities = the specified account set;
6. the scheduler creates exactly one spray alert with score = distinct accounts and the account
   sample = the specified set when >= 5, and no spray alert otherwise; never a burst alert
   (fewer than 10 records per group).

Every scenario is checked against its specification; in addition, no failed-target account may
take its realm from a reporting subject's domain (the defect found on 5.0.0-rc2 with 105573d;
scenarios ``p2_ambiguous_*``). A failure is a detection defect.

Run:  python tests/validation/p1_windows_identity_replay.py [--live] [--evidence DIR] [--ip-offset N]
Needs: endpoints.linux_replay (agent with the replay localfile, tests/lab/README.md), the pack
deployed at the frozen revision, indexer credentials. Creates nothing on the cluster.
"""

import datetime
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import identity_scenarios as IS  # noqa: E402
import vlib as V  # noqa: E402
import winevents as W  # noqa: E402

SPRAY, BURST = "wcp_windows_password_spray", "wcp_windows_failed_logon_burst"


def ip_for(i, offset):
    return "198.51.100.%d" % (60 + i + offset)


def args_extra(ap):
    ap.add_argument("--ip-offset", type=int, default=0, help="added to every source address (isolate re-runs)")
    ap.add_argument("--observe", type=int, default=300, help="seconds of scheduled runs to observe")
    ap.add_argument("--only", help="comma-separated scenario names")


def selected(args):
    sc = IS.scenarios()
    if getattr(args, "only", None):
        sc = [s for s in sc if s["name"] in args.only.split(",")]
    return sc


def build_plan(args):
    out = []
    for i, s in enumerate(selected(args)):
        out.append({
            "scenario": s["name"], "priority": s["priority"], "provenance": s["provenance"],
            "description": s["description"], "source_ip": ip_for(i, args.ip_offset),
            "expected_accounts": s["expected_accounts"], "expected_score": s["expected_score"],
            "expected_spray_alert": s["expected_alert"], "expected_burst_alert": False,
            "discriminates": s["discriminates"], "known_limitation": s["known_limitation"],
            "records": [{"computer": r["computer"], "data": r["data"], "spec_account": r["account"],
                         "expected_decoded_identity": W.decoder_model(r["computer"], r["data"])}
                        for r in s["records"]]})
    return {"scenarios": out, "frozen_content_hashes": {k: V.FROZEN_CONTENT_HASHES[k] for k in (SPRAY, BURST)}}


def run_live(args, cfg, client, ev, plan):
    ep = V.endpoint(cfg, "linux_replay")
    agent = str(ep.spec.get("agent_id") or "")
    if not agent:
        raise V.Refused("endpoints.linux_replay.agent_id is not set")
    ids, hashes = V.pack_monitor_ids(client)
    ev.d["observed"]["deployed_content_hashes"] = hashes
    for name in (SPRAY, BURST):
        ev.check("%s deployed with the candidate content hash %s" % (name, V.FROZEN_CONTENT_HASHES[name]),
                 hashes.get(name) == V.FROZEN_CONTENT_HASHES[name], hashes.get(name))
    if SPRAY not in ids or BURST not in ids:
        raise RuntimeError("pack monitors not deployed: run 'python -m wcp apply' first")
    scen = selected(args)
    pl = {p["scenario"]: p for p in plan["scenarios"]}
    # groups must be quiet (no earlier events inside the 13-minute spray lookback)
    for s in scen:
        ip = pl[s["name"]]["source_ip"]
        n = V.count_events(client, [{"term": {"source.ip": ip}}, {"range": {"event.start": {"gte": "now-15m"}}}])
        if n:
            raise V.Refused("source %s already has %d events in the last 15 min; use --ip-offset" % (ip, n))
    t0 = V.utc().replace(microsecond=0)
    base = random.randint(700000000, 799999999)
    lines, rid = [], base
    for s in scen:
        ip = pl[s["name"]]["source_ip"]
        for j, r in enumerate(s["records"]):
            rid += 1
            t = t0 - datetime.timedelta(seconds=50 - 8 * j)
            data = dict(r["data"], IpAddress=ip, IpPort=str(random.randint(49152, 65535)))
            r["_rid"], r["_time"] = str(rid), V.iso(t)
            lines.append(W.build_4625(t, rid, r["computer"], data))
            ev.d["inputs"].append({"scenario": s["name"], "provenance": s["provenance"], "record_id": rid,
                                   "time_created": V.iso(t), "source_ip": ip, "data": r["data"]})
    t_replay = V.utc()
    V.replay_lines(ep, lines)
    ev.d["observed"]["replayed_at"] = V.iso(t_replay)
    since = V.iso(t_replay - datetime.timedelta(seconds=5))
    # 1. indexed and decoded
    for s in scen:
        ip = pl[s["name"]]["source_ip"]
        filt = [{"term": {"wazuh.agent.id": agent}}, {"term": {"source.ip": ip}}, {"term": {"event.code": "4625"}},
                {"range": {"@timestamp": {"gte": since}}}]
        n, waited = V.wait_count(client, filt, len(s["records"]), timeout=300)
        docs = V.search_events(client, filt)
        by_rid = {}
        for d in docs:
            by_rid.setdefault(W.record_id_of(W.get_field(d, "event.original")), []).append(d)
        obs = {"indexed": n, "searchable_after_s": waited, "records": []}
        for r in s["records"]:
            got = by_rid.get(r["_rid"], [])
            row = {"record_id": r["_rid"], "indexed_copies": len(got), "spec_account": r["account"]}
            if got:
                d = got[0]
                row["decoded_identity"] = W.flat_identity(d)
                row["diffs_vs_decoder_model"] = W.compare_identity(d, W.decoder_model(r["computer"], r["data"]))
                row["python_reference_account"] = V.IDN.windows_target_account(d)
            obs["records"].append(row)
        ev.d["observed"].setdefault("scenarios", {})[s["name"]] = obs
        label = s["name"]
        ev.check("%s: %d records indexed once each" % (label, len(s["records"])),
                 all(r["indexed_copies"] == 1 for r in obs["records"]),
                 [r["indexed_copies"] for r in obs["records"]])
        decoded_ok = all(r.get("diffs_vs_decoder_model") == [] for r in obs["records"])
        acct_ok = all(r.get("python_reference_account") == r["spec_account"] for r in obs["records"])
        tag = ""
        ev.check("%s: decoded identity fields = decoder model" % label, decoded_ok,
                 [r.get("diffs_vs_decoder_model") for r in obs["records"] if r.get("diffs_vs_decoder_model")])
        subj = {(r["data"].get("SubjectDomainName") or "").lower() for r in s["records"]} - {"", "-"}
        if subj:
            leaked = [r.get("python_reference_account") for r in obs["records"]
                      if (r.get("python_reference_account") or "").split("\\")[0] in subj
                      and r.get("python_reference_account") != r["spec_account"]]
            ev.check("%s: no failed-target account takes its realm from a reporting subject's domain" % label,
                     not leaked, {"accounts_with_subject_realm": leaked, "subject_domains": sorted(subj)})
        ev.check("%s%s: wcp.identity reference on decoded events = specified accounts" % (label, tag), acct_ok,
                 [r.get("python_reference_account") for r in obs["records"]])
        # 2. Painless identities on the indexed events (dry run of a threshold-1 test copy)
        probe = V.identity_probe(client, SPRAY, [{"term": {"source.ip": ip}}, {"range": {"@timestamp": {"gte": since}}}])
        det = probe.get((agent, ip)) or {}
        sample = sorted(det.get("distinct_values_sample") or [])
        ev.d["observed"]["scenarios"][s["name"]]["painless_probe"] = {"score": det.get("score"), "sample": sample}
        ev.check("%s%s: Painless identities = %s" % (label, tag, s["expected_accounts"]),
                 IS.same_accounts(sample, s["expected_accounts"][:25]) and det.get("score") == s["expected_score"],
                 {"score": det.get("score"), "sample": sample})
    # 3. scheduled runs of the deployed monitors
    trk = {c: V.AlertTracker(client, ids[c]) for c in (SPRAY, BURST)}
    t_end = time.time() + args.observe
    print("observing scheduled runs for %d s" % args.observe)
    while time.time() < t_end:
        for t in trk.values():
            t.poll()
        time.sleep(5)
    since_ms = V.ms(t_replay) - 1000
    for s in scen:
        ip = pl[s["name"]]["source_ip"]
        keys = [agent, ip]
        sp = [a for a in trk[SPRAY].for_keys(keys) if (a["start_ms"] or 0) >= since_ms]
        bu = [a for a in trk[BURST].for_keys(keys) if (a["start_ms"] or 0) >= since_ms]
        ev.d["observed"]["scenarios"][s["name"]]["spray_alerts"] = sp
        ev.d["observed"]["scenarios"][s["name"]]["burst_alerts"] = bu
        label = s["name"]
        if s["expected_alert"]:
            ok = len(sp) == 1
            ev.check("%s: exactly one scheduler spray alert" % label, ok, len(sp))
            if ok:
                last = sp[0]["last"]
                ev.check("%s: alert score %d and account sample" % (label, s["expected_score"]),
                         last["score"] == s["expected_score"] and
                         IS.same_accounts(last["distinct_values_sample"] or [], s["expected_accounts"][:25]),
                         {"score": last["score"], "sample": last["distinct_values_sample"]})
        else:
            ev.check("%s: no spray alert in %d s of scheduled runs" % (label, args.observe), not sp, len(sp))
        ev.check("%s: no burst alert (< 10 records)" % label, not bu, len(bu))


def main(argv=None):
    return V.run_test("p1", "P1/P2-synthetic: Windows account identity through the ingestion pipeline",
                      build_plan, run_live, argv=argv, extra_args=args_extra)


if __name__ == "__main__":
    raise SystemExit(main())
