"""Decode the real (sanitized) 4625 capture through the stock Wazuh 5.x pipeline and record the WCS
fields the Windows base rule and correlations depend on.

The 20 events carry their original 2016 event times, so no monitor can alert on them; this only
validates decoding and field mapping (replay through a Linux agent, not EventChannel collection).

Run: python tests/e2e/test_windows_sample_decoding.py --evidence evidence/<run-id>
"""

import argparse
import datetime
import re

import harness as H
import lab

FIELDS = ["event.code", "event.dataset", "event.action", "event.outcome", "event.start", "source.ip",
          "user.name", "user.target.name", "error.code", "event.reason", "host.name", "wazuh.integration.name",
          "wazuh.integration.decoders", "wazuh.agent.id"]


def get(d, path):
    for p in path.split("."):
        if not isinstance(d, dict):
            return None
        d = d.get(p)
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", required=True)
    a = ap.parse_args()
    obs = H.Observer()
    ev = H.Evidence(a.evidence, "windows_real_sample_decoding", "pipeline-replay (decoding only)")
    lines = open(lab.WIN_SAMPLE, encoding="utf-8").read().splitlines()
    # mark this run: unique source address per run so documents of earlier replays are not mixed in
    ip = "203.0.113.%d" % (150 + datetime.datetime.now().minute % 50)
    lines = [l.replace("203.0.113.149", ip) for l in lines]
    t0 = H.utcnow()
    lab.replay("wcp-ep1", lines)
    ev.d["inputs"] = {"file": "samples/windows/4625_smb_bruteforce.sanitized.xml.log", "lines": len(lines),
                      "source_ip_rewritten_to": ip, "replayed_at": H.iso(t0)}
    filt = [{"term": {"source.ip": ip}}, {"range": {"@timestamp": {"gte": H.iso(t0 - datetime.timedelta(seconds=5))}}}]
    n, _w = obs.wait_events(filt, len(lines), timeout=180)
    docs = obs.events(filt, fields=FIELDS + ["event.original"])
    rows = []
    for d, line in zip(docs, lines):
        row = {f: get(d, f) for f in FIELDS}
        orig = get(d, "event.original") or ""
        row["raw_TargetUserName"] = (re.search(r"TargetUserName'>([^<]*)<", orig) or [None, None])[1]
        row["raw_SubStatus"] = (re.search(r"SubStatus'>([^<]*)<", orig) or [None, None])[1]
        row["raw_TimeCreated"] = (re.search(r"SystemTime='([^']*)'", orig) or [None, None])[1]
        row["raw_LogonType"] = (re.search(r"LogonType'>([^<]*)<", orig) or [None, None])[1]
        rows.append(row)
    ev.d["observed"] = {"indexed": n, "decoded_events": rows}
    ev.check("all %d real events indexed" % len(lines), n == len(lines), n)
    ev.check("decoded by stock windows integration",
             all(r["wazuh.integration.name"] == "windows" for r in rows), sorted({r["wazuh.integration.name"] for r in rows}))
    ev.check("event.code == '4625' and event.dataset == 'security' (base rule selection)",
             all(r["event.code"] == "4625" and r["event.dataset"] == "security" for r in rows))
    ev.check("source.ip from IpAddress", all(r["source.ip"] == ip for r in rows))
    ev.check("user.target.name == TargetUserName", all(r["user.target.name"] == r["raw_TargetUserName"] for r in rows))
    ev.check("error.code == SubStatus", all(r["error.code"] == r["raw_SubStatus"] for r in rows))
    ev.check("event.start == TimeCreated (event time)",
             all((r["event.start"] or "")[:19] == (r["raw_TimeCreated"] or "")[:19] for r in rows))
    ev.check("event.action == authentication-failure, event.outcome == failure",
             all(r["event.action"] == "authentication-failure" and r["event.outcome"] == "failure" for r in rows))
    has_logon_type = [f for f in FIELDS if any(str(r.get(f)) == r["raw_LogonType"] for r in rows)]
    ev.d["observed"]["logon_type_values_in_raw"] = sorted({r["raw_LogonType"] for r in rows})
    ev.check("LogonType is not exposed in any recorded WCS field (no RDP-specific selection possible)",
             not has_logon_type, has_logon_type)
    return 0 if ev.save() == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
