"""P3: real Windows collection, traced record by record through collection, normalization and correlation.

Path: failed SMB (and optionally RDP) logons from the Linux source endpoint against the Windows lab
endpoint -> Security log (4625) -> Wazuh agent EventChannel collector -> manager -> engine (stock
decoders) -> ``wazuh-events-v5-system-activity`` -> the deployed frozen pack monitors (scheduler).

Generated: 5 spray attempts (``wcpt-p3-s01..s05``, one each) then 10 burst attempts
(``wcpt-p3-burst``), all non-existent accounts (no lockout), dummy password. ``--rdp`` adds 3
``xfreerdp +auth-only`` attempts (``wcpt-p3-rdp``) to record their LogonType.

Ground truth = the endpoint's Security log (Get-WinEvent, ``ToXml()``) for the test names since the
start. Assertions:

1. collection: the set of EventRecordIDs indexed for the agent = the set in the Security log, each
   indexed exactly once (duplicates recorded); one record per attempt;
2. ``event.original`` = the Windows rendering (CR/LF removed): single line, no RenderingInfo, the
   same EventData names as ``samples/windows/``;
3. normalization per record: event.code 4625, event.dataset security, event.action
   authentication-failure, source.ip = IpAddress, user.target.name = TargetUserName, error.code =
   SubStatus, event.start = TimeCreated (ms), identity fields = decoder model;
4. correlation: the burst alert's score = the maximum number of records in any 2-minute window and
   the spray alert's score / sample = the distinct target accounts in any 10-minute window, both
   computed from the Security log records (independent brute-force count), for the group
   [Windows agent id, source address].

Recorded (not pass/fail): LogonType of each record (SMB, RDP), whether any WCS field carries it,
delays event time -> @timestamp -> searchable.

Run:  python tests/validation/p3_windows_collection.py [--live] [--evidence DIR] [--rdp]
Needs: endpoints.windows (agent, Audit Logon failure enabled, PowerShell over SSH),
endpoints.linux_source (smbclient; xfreerdp for --rdp; address in endpoints.linux_source.ip),
the pack deployed at the frozen revision. Creates nothing on the cluster.
"""

import datetime
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import vlib as V  # noqa: E402
import identity_scenarios as IS  # noqa: E402
import winevents as W  # noqa: E402
import winlab as WL  # noqa: E402

PREFIX = "wcpt-p3-"
BURST, SPRAY = "wcp_windows_failed_logon_burst", "wcp_windows_password_spray"
SPRAY_USERS = ["%ss%02d" % (PREFIX, i) for i in range(1, 6)]
BURST_USERS = [PREFIX + "burst"] * 10
RDP_USERS = [PREFIX + "rdp"] * 3


def args_extra(ap):
    ap.add_argument("--rdp", action="store_true", help="also make 3 failed RDP logons (xfreerdp +auth-only)")
    ap.add_argument("--alert-timeout", type=int, default=420)


def build_plan(args):
    users = SPRAY_USERS + BURST_USERS + (RDP_USERS if args.rdp else [])
    return {"provenance": "captured (generated against the lab Windows endpoint)",
            "attempts": [{"user": u, "via": "rdp" if u in RDP_USERS else "smb"} for u in users],
            "expected_records": len(users),
            "expected_if_all_within_2_minutes": {
                "burst_score": len(users),
                "spray_accounts": sorted({"<realm>\\" + u for u in users}),
                "spray_alert": len(set(users)) >= 5, "burst_alert": len(users) >= 10},
            "note": "final expected scores are computed from the Security log records (TimeCreated, IpAddress)"}


def max_in_window(times_ms, window_ms):
    """Independent brute-force: max events with first..last < window."""
    t = sorted(times_ms)
    return max([sum(1 for x in t if s <= x < s + window_ms) for s in t] or [0])


def max_distinct_in_window(items, window_ms):
    items = sorted(items)
    best, sample = 0, []
    for s, _v in items:
        vals = sorted(IS.count_accounts(v for t, v in items if s <= t < s + window_ms and v))
        if len(vals) > best:
            best, sample = len(vals), vals
    return best, sample


def run_live(args, cfg, client, ev, plan):
    win = V.endpoint(cfg, "windows")
    src = V.endpoint(cfg, "linux_source")
    agent, host, src_ip = str(win.spec.get("agent_id") or ""), win.spec.get("address"), src.spec.get("ip")
    if not (agent and host and src_ip):
        raise V.Refused("endpoints.windows.agent_id/.address and endpoints.linux_source.ip are required")
    keys = [agent, src_ip]
    ids, hashes = V.pack_monitor_ids(client)
    for name in (BURST, SPRAY):
        ev.check("%s deployed with the frozen content hash" % name, hashes.get(name) == V.FROZEN_CONTENT_HASHES[name],
                 hashes.get(name))
    ok, raw = WL.audit_logon_failure_enabled(win)
    ev.check("precondition: Audit Logon failure enabled on the endpoint", ok, raw[-200:])
    quiet = V.count_events(client, [{"term": {"wazuh.agent.id": agent}}, {"term": {"source.ip": src_ip}},
                                    {"term": {"event.code": "4625"}}, {"range": {"event.start": {"gte": "now-15m"}}}])
    ev.check("precondition: no 4625 from the source on this agent in the last 15 min", quiet == 0, quiet)
    trk = {c: V.AlertTracker(client, ids[c]).poll() for c in (BURST, SPRAY)}
    active = [a for c in trk for a in trk[c].for_keys(keys) if a["states"][-1][1] == "ACTIVE"]
    ev.check("precondition: no ACTIVE alert for %s" % keys, not active, len(active))
    if not all(c["pass"] for c in ev.d["checks"]):
        raise RuntimeError("preconditions not met; wait 15 minutes and re-run")
    start = V.utc() - datetime.timedelta(seconds=2)
    s0, s1 = WL.smb_attempts(src, cfg, host, SPRAY_USERS, pause=2)
    b0, b1 = WL.smb_attempts(src, cfg, host, BURST_USERS, pause=1)
    ev.d["inputs"] += [{"kind": "smb spray", "users": SPRAY_USERS, "start": V.iso(s0), "end": V.iso(s1)},
                       {"kind": "smb burst", "users": BURST_USERS, "start": V.iso(b0), "end": V.iso(b1)}]
    if args.rdp:
        r0, r1, codes = WL.rdp_attempts(src, cfg, host, RDP_USERS)
        ev.d["inputs"].append({"kind": "rdp", "users": RDP_USERS, "start": V.iso(r0), "end": V.iso(r1),
                               "tool_output": codes})
    t_last = V.utc()
    time.sleep(5)
    truth = WL.security_4625(win, start, PREFIX)
    recs = {}
    for t in truth:
        p = W.parse_4625(t["xml"])
        recs[str(p["record_id"])] = {"xml": t["xml"], "parsed": p}
    attempts = [a["user"] for a in plan["attempts"]]
    per_user = {}
    for r in recs.values():
        u = r["parsed"]["data"].get("TargetUserName", "").lower()
        per_user[u] = per_user.get(u, 0) + 1
    want_user = {}
    for u in attempts:
        want_user[u] = want_user.get(u, 0) + 1
    ev.d["observed"]["security_log"] = {"records": len(recs), "per_user": per_user, "attempts_per_user": want_user}
    ev.check("one 4625 per attempt in the Security log", per_user == want_user, per_user)
    # collection
    filt = [{"term": {"wazuh.agent.id": agent}}, {"term": {"event.code": "4625"}}, {"prefix": {"user.target.name": PREFIX}},
            {"range": {"@timestamp": {"gte": V.iso(start - datetime.timedelta(seconds=5))}}}]
    n, waited = V.wait_count(client, filt, len(recs), timeout=600)
    ev.d["timings_s"]["all_indexed_after_last_attempt"] = None if waited is None else round(
        (V.utc() - t_last).total_seconds(), 1)
    docs = V.search_events(client, filt)
    by_rid = {}
    for d in docs:
        by_rid.setdefault(W.record_id_of(W.get_field(d, "event.original")), []).append(d)
    dup = {k: len(v) for k, v in by_rid.items() if len(v) > 1}
    ev.d["observed"]["indexed"] = {"documents": len(docs), "distinct_record_ids": len(by_rid), "duplicates": dup}
    ev.check("collection: indexed EventRecordIDs = Security log EventRecordIDs", set(by_rid) == set(recs),
             {"missing": sorted(set(recs) - set(by_rid)), "unexpected": sorted(set(by_rid) - set(recs))})
    ev.check("collection: each record indexed exactly once", not dup, dup)
    # format and normalization
    sample_names = set(W.parse_4625(W.template())["data"])
    fmt_bad, norm_bad, delays, rows = [], [], [], []
    for rid, r in sorted(recs.items()):
        d = (by_rid.get(rid) or [None])[0]
        if d is None:
            continue
        p = r["parsed"]
        orig = W.get_field(d, "event.original") or ""
        rendered = r["xml"].replace("\r", "").replace("\n", "")
        po = W.parse_4625(orig)
        f = {"equal_to_windows_rendering": orig == rendered, "single_line": "\n" not in orig,
             "no_rendering_info": not po["has_rendering_info"], "single_quoted": "Name='" in orig,
             "same_eventdata_names_as_sample": set(po["data"]) == sample_names}
        if not all(f.values()):
            fmt_bad.append((rid, f))
        data = p["data"]
        exp = {"event.code": "4625", "event.dataset": "security", "event.action": "authentication-failure",
               "source.ip": data.get("IpAddress"), "user.target.name": data.get("TargetUserName"),
               "error.code": data.get("SubStatus")}
        got = {k: W.get_field(d, k) for k in exp}
        diffs = {k: (exp[k], got[k]) for k in exp if str(exp[k]).lower() != str(got[k]).lower()}
        es, tc = W.get_field(d, "event.start"), p["time_created"]
        if not es or V.parse_iso(es).replace(microsecond=V.parse_iso(es).microsecond // 1000 * 1000) != \
                V.parse_iso(tc).replace(microsecond=V.parse_iso(tc).microsecond // 1000 * 1000):
            diffs["event.start"] = (tc, es)
        idd = W.compare_identity(d, W.decoder_model(p["computer"], data))
        if idd:
            diffs["identity"] = idd
        if diffs:
            norm_bad.append((rid, diffs))
        ts = W.get_field(d, "@timestamp")
        if es and ts:
            delays.append((V.parse_iso(ts) - V.parse_iso(es)).total_seconds())
        rows.append({"record_id": rid, "target": data.get("TargetUserName"), "logon_type": data.get("LogonType"),
                     "ip": data.get("IpAddress"), "time_created": tc, "event_start": es, "timestamp": ts,
                     "account": WL.spec_account(p)})
    ev.d["observed"]["records"] = rows
    ev.check("event.original = Windows rendering, sample format", not fmt_bad, fmt_bad[:5])
    ev.check("normalization of every record (fields, event time, identity)", not norm_bad, norm_bad[:5])
    if delays:
        ev.d["timings_s"]["event_time_to_timestamp"] = {"min": round(min(delays), 2), "max": round(max(delays), 2)}
    lt = sorted({r["logon_type"] for r in rows})
    ev.note("LogonType values (SMB%s)" % (" + RDP" if args.rdp else ""),
            {t: sorted({r["target"] for r in rows if r["logon_type"] == t}) for t in lt})
    if docs:
        flat = repr(docs[0])
        ev.note("LogonType values appearing in the indexed document of a record (other than event.original)",
                [t for t in lt if re.search(r"[\"']%s[\"']" % re.escape(str(t)), flat.replace(
                    W.get_field(docs[0], "event.original") or "", ""))])
    # correlation, expected from the Security log
    mine = [r for r in rows if r["ip"] == src_ip]
    times = [V.ms(V.parse_iso(r["time_created"])) for r in mine]
    exp_burst = max_in_window(times, 120000)
    exp_spray, exp_sample = max_distinct_in_window([(V.ms(V.parse_iso(r["time_created"])), r["account"]) for r in mine],
                                                   600000)
    ev.d["expected"] = {"burst_score": exp_burst, "burst_alert": exp_burst >= 10, "spray_score": exp_spray,
                        "spray_sample": exp_sample, "spray_alert": exp_spray >= 5}
    deadline = time.time() + args.alert_timeout
    final = {}
    while time.time() < deadline:
        for c, t in trk.items():
            t.poll()
            al = [a for a in t.for_keys(keys) if (a["start_ms"] or 0) >= V.ms(start) - 1000]
            final[c] = al
        b_ok = all(a["last"]["score"] == exp_burst for a in final.get(BURST, [])) and len(final.get(BURST, [])) == 1
        s_ok = all(a["last"]["score"] == exp_spray for a in final.get(SPRAY, [])) and len(final.get(SPRAY, [])) == 1
        if b_ok and s_ok:
            break
        time.sleep(5)
    ev.d["observed"]["alerts"] = final
    for c, score, sample in ((BURST, exp_burst, None), (SPRAY, exp_spray, exp_sample)):
        al = final.get(c, [])
        ev.check("%s: one scheduler alert for %s" % (c, keys), len(al) == 1, len(al))
        if al:
            last = al[0]["last"]
            ok = last["score"] == score and (sample is None or sorted(last["distinct_values_sample"] or []) == sample[:25])
            ev.check("%s: score %s%s (from the Security log)" % (c, score, "" if sample is None else " and account sample"),
                     ok, {"score": last["score"], "sample": last.get("distinct_values_sample")})
            ev.d["timings_s"]["%s_alert_after_last_attempt" % c] = round(
                (V.parse_iso(al[0]["start_time"]) - t_last).total_seconds(), 1) if al[0]["start_time"] else None
    import p2_reporting_subject_capture as P2   # same sanitizing and saving rules
    first = {}
    for rid, r in sorted(recs.items()):
        lt_ = r["parsed"]["data"].get("LogonType")
        first.setdefault(lt_, r)
    P2.save_sanitized(cfg, ev, args, list(first.values()), "p3_captured_4625.sanitized.xml.log")


def main(argv=None):
    return V.run_test("p3", "P3: real Windows EventChannel collection to correlation", build_plan, run_live,
                      argv=argv, extra_args=args_extra)


if __name__ == "__main__":
    raise SystemExit(main())
