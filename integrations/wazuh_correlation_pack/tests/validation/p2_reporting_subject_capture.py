"""P2 (captured part): real 4625 events whose reporting subject differs from the failed target.

The synthetic subject-present records run in P1 (scenarios ``p2_*``, provenance
``synthetic-derived``). This test captures **real** events (provenance ``captured``) on the Windows
lab endpoint:

* A - LogonUser(interactive) for 5 distinct non-existent targets in the explicit domain
  ``WCPOTHERDOM``, called by the SSH account: subject = the caller, target = the test account;
* B - 3 failures for one target (``WCPOTHERDOM\\wcpt-p2-same``), same caller;
* C - LogonUser(network) for 2 targets with realm ``.`` (local computer);
* D - one SMB failure from the Linux source endpoint with an explicit domain
  (``smbclient -U 'WCPOTHERDOM\\wcpt-p2-smb'``): subject absent, IpAddress present.

Assertions:

1. each attempt produced one 4625 in the Security log (Get-WinEvent ground truth, matched by name);
2. A/B/C records have a reporting subject that differs from the target (raw XML);
3. every captured record is collected and indexed once (EventRecordID in ``event.original``);
4. decoded identity fields = decoder model (``winevents.decoder_model``): for A/B/C this is the
   first check of the subject-present shape on a real event;
5. ``wcp.identity`` on the decoded event = the specified account from the raw *target* fields
   (``winlab.spec_account``); the realm is never the subject's domain;
6. a dry-run probe of the spray monitor at threshold 1, grouped by agent only (A-C have no
   ``source.ip``; test copy, nothing saved) returns exactly the specified target accounts: the
   count is 5 + 1 + 2 + 1 = 9 target accounts for one reporting subject.

The captured records are saved sanitized (``p2_captured_4625.sanitized.xml.log`` in the
evidence directory); copy one into ``samples/windows/`` with its README entry after review.

Run:  python tests/validation/p2_reporting_subject_capture.py [--live] [--evidence DIR]
Needs: endpoints.windows (agent, PowerShell over SSH, an account that may read the Security log),
endpoints.linux_source (smbclient). Creates nothing on the cluster.
"""

import datetime
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import vlib as V  # noqa: E402
import identity_scenarios as IS  # noqa: E402
import winevents as W  # noqa: E402
import winlab as WL  # noqa: E402

PREFIX = "wcpt-p2-"
SPRAY = "wcp_windows_password_spray"
DOMAIN = "WCPOTHERDOM"


def attempts_plan():
    A = [{"set": "A", "user": "%st%d" % (PREFIX, i), "domain": DOMAIN, "type": WL.LOGON_TYPES["interactive"]}
         for i in range(1, 6)]
    B = [{"set": "B", "user": PREFIX + "same", "domain": DOMAIN, "type": WL.LOGON_TYPES["interactive"]}
         for _ in range(3)]
    C = [{"set": "C", "user": "%sn%d" % (PREFIX, i), "domain": ".", "type": WL.LOGON_TYPES["network"]}
         for i in range(1, 3)]
    D = [{"set": "D", "user": PREFIX + "smb", "domain": DOMAIN, "via": "smbclient from linux_source"}]
    return A + B + C + D


def build_plan(args):
    at = attempts_plan()
    return {"attempts": at, "provenance": "captured (generated on the lab Windows endpoint)",
            "expected_records": len(at),
            "expected_target_accounts_if_realm_written_as_given": sorted(
                {("<computer>" if a["domain"] == "." else a["domain"].lower()) + "\\" + a["user"] for a in at}),
            "expected_distinct_target_accounts": len({(a["domain"], a["user"]) for a in at}),
            "expected_distinct_reporting_subjects_A_B_C": 1}


def run_live(args, cfg, client, ev, plan):
    win = V.endpoint(cfg, "windows")
    src = V.endpoint(cfg, "linux_source")
    agent = str(win.spec.get("agent_id") or "")
    host = win.spec.get("address")
    if not agent or not host:
        raise V.Refused("endpoints.windows.agent_id and .address are required")
    at = plan["attempts"]
    start = V.utc() - datetime.timedelta(seconds=2)
    local = [a for a in at if a["set"] in "ABC"]
    res = WL.logon_user(win, cfg, [{"user": a["user"], "domain": a["domain"], "type": a["type"]} for a in local])
    ev.d["inputs"].append({"kind": "LogonUser on the Windows endpoint", "results": res})
    d = [a for a in at if a["set"] == "D"]
    s0, s1 = WL.smb_attempts(src, cfg, host, [a["user"] for a in d], domain=DOMAIN)
    ev.d["inputs"].append({"kind": "smbclient from linux_source", "users": [a["user"] for a in d],
                           "domain": DOMAIN, "start": V.iso(s0), "end": V.iso(s1)})
    time.sleep(5)
    truth = WL.security_4625(win, start, PREFIX)
    recs = []
    for t in truth:
        p = W.parse_4625(t["xml"])
        recs.append({"record_id": str(p["record_id"]), "xml": t["xml"], "parsed": p,
                     "spec_account": WL.spec_account(p)})
    ev.d["observed"]["security_log_records"] = len(recs)
    per_user = {}
    for r in recs:
        per_user[r["parsed"]["data"].get("TargetUserName", "").lower()] = per_user.get(
            r["parsed"]["data"].get("TargetUserName", "").lower(), 0) + 1
    want_user = {}
    for a in at:
        want_user[a["user"].lower()] = want_user.get(a["user"].lower(), 0) + 1
    ev.check("one 4625 in the Security log per attempt", per_user == want_user, {"log": per_user, "attempts": want_user})
    subj = [r for r in recs if r["parsed"]["data"].get("SubjectUserName", "-") != "-"]
    ev.check("LogonUser records carry a reporting subject that differs from the target",
             len(subj) >= len(local) and all(
                 (r["parsed"]["data"].get("SubjectUserName", "").lower(),
                  r["parsed"]["data"].get("SubjectDomainName", "").lower()) !=
                 (r["parsed"]["data"].get("TargetUserName", "").lower(),
                  r["parsed"]["data"].get("TargetDomainName", "").lower()) for r in subj),
             len(subj))
    ev.d["observed"]["distinct_reporting_subjects"] = sorted({
        "%s\\%s" % (r["parsed"]["data"].get("SubjectDomainName"), r["parsed"]["data"].get("SubjectUserName"))
        for r in subj})
    ev.d["observed"]["logon_types"] = {r["record_id"]: r["parsed"]["data"].get("LogonType") for r in recs}
    # pipeline
    filt = [{"term": {"wazuh.agent.id": agent}}, {"term": {"event.code": "4625"}},
            {"prefix": {"user.target.name": PREFIX}},
            {"range": {"@timestamp": {"gte": V.iso(start - datetime.timedelta(seconds=5))}}}]
    n, waited = V.wait_count(client, filt, len(recs), timeout=300)
    docs = V.search_events(client, filt)
    ev.d["timings_s"]["all_indexed_after_first_poll"] = waited
    by_rid = {}
    for dd in docs:
        by_rid.setdefault(W.record_id_of(W.get_field(dd, "event.original")), []).append(dd)
    rows = []
    for r in recs:
        got = by_rid.get(r["record_id"], [])
        row = {"record_id": r["record_id"], "provenance": "captured", "indexed_copies": len(got),
               "spec_account": r["spec_account"], "logon_type": r["parsed"]["data"].get("LogonType"),
               "subject": "%s\\%s" % (r["parsed"]["data"].get("SubjectDomainName"),
                                      r["parsed"]["data"].get("SubjectUserName"))}
        if got:
            row["decoded_identity"] = W.flat_identity(got[0])
            row["diffs_vs_decoder_model"] = W.compare_identity(
                got[0], W.decoder_model(r["parsed"]["computer"], r["parsed"]["data"]))
            row["python_reference_account"] = V.IDN.windows_target_account(got[0])
            row["source_ip"] = W.get_field(got[0], "source.ip")
        rows.append(row)
    ev.d["observed"]["records"] = rows
    ev.check("every captured record indexed exactly once", all(r["indexed_copies"] == 1 for r in rows),
             [r["indexed_copies"] for r in rows])
    ev.check("decoded identity fields = decoder model (subject-present shape on real events)",
             all(r.get("diffs_vs_decoder_model") == [] for r in rows),
             [(r["record_id"], r.get("diffs_vs_decoder_model")) for r in rows if r.get("diffs_vs_decoder_model")])
    ev.check("wcp.identity on decoded events = account from the raw target fields",
             all(r.get("python_reference_account") == r["spec_account"] for r in rows),
             [(r["spec_account"], r.get("python_reference_account")) for r in rows])
    leaks = []
    raw_by_rid = {x["record_id"]: x["parsed"]["data"] for x in recs}
    for r in rows:
        sd = r["subject"].split("\\", 1)[0].lower()
        acct = r.get("python_reference_account") or ""
        td = (raw_by_rid[r["record_id"]].get("TargetDomainName") or "").lower()
        if sd not in ("-", "") and sd != td and acct.startswith(sd + "\\"):
            leaks.append(r["record_id"])
    ev.check("the realm is never the reporting subject's domain", not leaks, leaks)
    probe = V.identity_probe(client, SPRAY, filt[1:], group_by=["wazuh.agent.id"])
    det = probe.get((agent,)) or {}
    want = sorted(IS.count_accounts(r["spec_account"] for r in recs))
    ev.d["observed"]["painless_probe_by_agent"] = {"score": det.get("score"),
                                                  "sample": sorted(det.get("distinct_values_sample") or [])}
    ev.check("Painless probe: distinct accounts = target accounts (%d) for %d reporting subject(s)" % (
        len(want), len(ev.d["observed"]["distinct_reporting_subjects"])),
        det.get("score") == len(want) and sorted(det.get("distinct_values_sample") or []) == want[:25],
        ev.d["observed"]["painless_probe_by_agent"])
    smb = [r for r in rows if r["spec_account"] and r["spec_account"].endswith("\\" + PREFIX + "smb")]
    ev.note("SMB record with explicit domain: source.ip, subject, account",
            [(r.get("source_ip"), r["subject"], r.get("python_reference_account")) for r in smb])
    save_sanitized(cfg, ev, args, recs, "p2_captured_4625.sanitized.xml.log")


def save_sanitized(cfg, ev, args, recs, filename):
    names = dict(cfg.get("sanitize") or {})
    for acc in cfg.get("access_accounts") or []:
        names.setdefault(acc, "wcp-caller")
    forbidden = list(names) + [str((cfg.get("endpoints") or {}).get(n, {}).get(k) or "")
                               for n in ("windows", "linux_source", "linux_replay") for k in ("address", "hostname", "ip")]
    san = W.Sanitizer(names, forbidden)
    out = [san(r["xml"].replace("\r", "").replace("\n", "")) for r in recs]
    left = san.leftovers("\n".join(out))
    ev.d["observed"]["sanitized_file"] = {"file": filename, "records": len(out), "leftovers_found": len(left),
                                          "saved": not left and bool(args.evidence)}
    if left:
        ev.check("captured records sanitized before saving", False, "%d configured value(s) remain; not saved" % len(left))
        return
    if args.evidence:
        os.makedirs(args.evidence, exist_ok=True)
        with open(os.path.join(args.evidence, filename), "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(out) + "\n")


def main(argv=None):
    return V.run_test("p2", "P2-captured: reporting subject vs failed target on real 4625 events",
                      build_plan, run_live, argv=argv)


if __name__ == "__main__":
    raise SystemExit(main())
