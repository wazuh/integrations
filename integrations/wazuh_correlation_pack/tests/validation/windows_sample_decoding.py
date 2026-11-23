"""Decoding of the real sanitized 4625 capture (port of tests/e2e/test_windows_sample_decoding.py).

The 20 events of ``samples/windows/4625_smb_bruteforce.sanitized.xml.log`` are appended to the
replay file of the configured Linux endpoint (instead of the RC1 container) and decoded by the
stock pipeline. They keep their 2016 event times, so no monitor can alert on them; this validates
decoding and field mapping only (replay through a Linux agent, not EventChannel collection - that
is P3). Checks as in RC1.

Run:  python tests/validation/windows_sample_decoding.py [--live] [--evidence DIR]
Needs: endpoints.linux_replay. Creates nothing on the cluster.
"""

import datetime
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import vlib as V  # noqa: E402
import lab  # noqa: E402  tests/lab/lab.py: sample path

FIELDS = ["event.code", "event.dataset", "event.action", "event.outcome", "event.start", "source.ip",
          "user.name", "user.target.name", "error.code", "event.reason", "host.name", "wazuh.integration.name",
          "wazuh.integration.decoders", "wazuh.agent.id"]


def get(d, path):
    for p in path.split("."):
        if not isinstance(d, dict):
            return None
        d = d.get(p)
    return d


def build_plan(args):
    with open(lab.WIN_SAMPLE, encoding="utf-8") as fh:
        n = sum(1 for _l in fh)
    return {"file": os.path.relpath(lab.WIN_SAMPLE, V.PACK).replace("\\", "/"), "lines": n,
            "checks": ["all indexed", "stock windows integration", "event.code/event.dataset", "source.ip",
                       "user.target.name", "error.code", "event.start", "event.action/outcome", "LogonType not exposed"]}


def run_live(args, cfg, client, ev, plan):
    ep = V.endpoint(cfg, "linux_replay")
    with open(lab.WIN_SAMPLE, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    ip = "203.0.113.%d" % (150 + datetime.datetime.now().minute % 50)
    n_before = V.count_events(client, [{"term": {"source.ip": ip}}, {"range": {"@timestamp": {"gte": "now-30m"}}}])
    if n_before:
        raise V.Refused("source %s was used in the last 30 min; retry in a minute" % ip)
    lines = [l.replace("203.0.113.149", ip) for l in lines]
    t0 = V.utc()
    V.replay_lines(ep, lines)
    ev.d["inputs"] = [{"file": plan["file"], "lines": len(lines), "source_ip_rewritten_to": ip, "replayed_at": V.iso(t0)}]
    filt = [{"term": {"source.ip": ip}}, {"range": {"@timestamp": {"gte": V.iso(t0 - datetime.timedelta(seconds=5))}}}]
    n, _w = V.wait_count(client, filt, len(lines), timeout=180)
    docs = V.search_events(client, filt, source=FIELDS + ["event.original"])
    rows = []
    for d in docs:
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
             all(r["wazuh.integration.name"] == "windows" for r in rows), sorted({str(r["wazuh.integration.name"]) for r in rows}))
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
    ev.d["observed"]["logon_type_values_in_raw"] = sorted({str(r["raw_LogonType"]) for r in rows})
    ev.check("LogonType is not exposed in any recorded WCS field (no RDP-specific selection possible)",
             not has_logon_type, has_logon_type)


def main(argv=None):
    return V.run_test("win_sample_decoding", "Decoding of the real sanitized 4625 capture (port of RC1 test 9)",
                      build_plan, run_live, argv=argv)


if __name__ == "__main__":
    raise SystemExit(main())
