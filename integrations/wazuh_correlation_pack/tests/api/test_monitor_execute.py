"""Query/API tests: indexed fixtures + Alerting _execute API (no ingestion pipeline).

Creates the pack-owned index ``wcp-test-fixtures`` with the field types of the Wazuh 5.x
events data stream, indexes fixture documents with event times relative to "now", executes
each monitor body (pointed at the fixture index, not saved) through
``POST _plugins/_alerting/monitors/_execute?dryrun=true`` and compares the triggered buckets
and their scores with the expected values. The index is deleted at the end.

This layer proves the query, the Painless evaluation and the bucket-level trigger at
millisecond precision. It does NOT prove collection or decoding (see tests/e2e).

Run: python tests/api/test_monitor_execute.py [--keep] [--evidence DIR]
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

from wcp import alerting as A  # noqa: E402
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "validation"))
import identity_scenarios as IS  # noqa: E402  (same_accounts: representation-aware sample check)
from wcp import config as C  # noqa: E402
from wcp import identity as IDN  # noqa: E402
from wcp import sigma as S  # noqa: E402
from wcp.client import DEFAULT_ENV_FILE, ApiError, Client, load_env_file  # noqa: E402

INDEX = "wcp-test-fixtures"
KW = {"type": "keyword"}
MAPPING = {"mappings": {"dynamic": "strict", "properties": {
    "@timestamp": {"type": "date"},
    "event": {"properties": {"start": {"type": "date"}, "reason": KW, "action": KW, "code": KW, "dataset": KW}},
    "process": {"properties": {"name": KW}},
    "source": {"properties": {"ip": {"type": "ip"}}},
    "user": {"properties": {"name": KW, "domain": KW, "id": KW,
                            "target": {"properties": {"name": KW, "domain": KW, "id": KW}}}},
    "host": {"properties": {"name": KW}},
    "wazuh": {"properties": {"agent": {"properties": {"id": KW, "name": KW}}, "event": {"properties": {"id": KW}}}},
    "fixture": KW,
}}, "settings": {"number_of_shards": 1, "number_of_replicas": 0}}


def ssh(case, t, agent, ip, user, reason="Failed password", proc="sshd", ident=None):
    d = {"fixture": case, "@timestamp": t, "event": {"start": t, "reason": reason, "action": "authentication-failure"},
         "process": {"name": proc}, "wazuh": {"agent": {"id": agent, "name": "ep-%s" % agent}}}
    if ip is not None:
        d["source"] = {"ip": ip}
    if user is not None:
        d["user"] = {"name": user}
    if ident:
        d["wazuh"]["event"] = {"id": ident}
    return d


def win(case, t, agent, ip, target):
    return {"fixture": case, "@timestamp": t, "event": {"start": t, "code": "4625", "dataset": "security",
                                                         "action": "authentication-failure"},
            "source": {"ip": ip}, "user": {"name": target, "target": {"name": target}},
            "wazuh": {"agent": {"id": agent, "name": "ep-%s" % agent}}}


def winacct(case, t, agent, ip, user, host=None):
    """4625 fixture with explicit decoded identity fields (see tests/unit/test_identity.py)."""
    d = {"fixture": case, "@timestamp": t, "event": {"start": t, "code": "4625", "dataset": "security",
                                                      "action": "authentication-failure"},
         "source": {"ip": ip}, "user": user, "wazuh": {"agent": {"id": agent, "name": "ep-%s" % agent}}}
    if host:
        d["host"] = {"name": host}
    return d


def absent(name, domain, sid="S-1-0-0"):
    """Observed rc1 shape, reporting subject '-': user.domain = TargetDomainName, user.id == user.target.id."""
    u = {"name": name, "id": sid, "target": {"name": name, "id": sid}}
    if domain is not None:
        u["domain"] = domain
    return u


def present(name, tdomain, sdomain="WORKGROUP", sname="WIN10$", ssid="S-1-5-18"):
    """Decoder-derived shape (not yet observed), reporting subject present."""
    u = {"name": sname, "domain": sdomain, "id": ssid, "target": {"name": name, "id": "S-1-0-0"}}
    if tdomain is not None:
        u["target"]["domain"] = tdomain
    return u


def build_cases(now):
    """(case, correlation, docs, expected {(agent, ip): score or None}, settings_override)"""
    def ts(sec):
        return (now + datetime.timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    cases = []
    BF, SP, WB, WS = "wcp_ssh_bruteforce", "wcp_ssh_password_spray", "wcp_windows_failed_logon_burst", \
        "wcp_windows_password_spray"

    def add(name, corr, docs, expect, ov=None):
        cases.append((name, corr, docs, expect, ov or {}))

    add("below", BF, [ssh("below", ts(-60 + i), "001", "192.0.2.1", "a") for i in range(7)], {("001", "192.0.2.1"): None})
    add("exact", BF, [ssh("exact", ts(-60 + i), "001", "192.0.2.2", "a") for i in range(8)], {("001", "192.0.2.2"): 8})
    add("above", BF, [ssh("above", ts(-60 + i), "001", "192.0.2.3", "a") for i in range(20)], {("001", "192.0.2.3"): 20})
    # half-open window at millisecond precision
    d = [ssh("ms_edge_out", ts(-200 + i), "001", "192.0.2.4", "a") for i in range(7)] + \
        [ssh("ms_edge_out", ts(-200 + 120), "001", "192.0.2.4", "a")]
    add("ms_edge_out", BF, d, {("001", "192.0.2.4"): None})
    d = [ssh("ms_edge_in", ts(-200 + i), "001", "192.0.2.5", "a") for i in range(7)] + \
        [ssh("ms_edge_in", ts(-200 + 119.999), "001", "192.0.2.5", "a")]
    add("ms_edge_in", BF, d, {("001", "192.0.2.5"): 8})
    # selection: only Failed password / keyboard-interactive, only sshd processes
    d = [ssh("selection", ts(-30), "001", "192.0.2.6", "a", reason=r) for r in
         ["Failed publickey", "Failed none", "Accepted password", None] * 3] + \
        [ssh("selection", ts(-30), "001", "192.0.2.6", "a", proc="sudo") for _ in range(8)] + \
        [ssh("selection", ts(-20 + i), "001", "192.0.2.6", "a", reason="Failed keyboard-interactive/pam") for i in range(7)]
    add("selection", BF, d, {("001", "192.0.2.6"): None})
    # missing group field: never merged into an empty group
    add("no_source_ip", BF, [ssh("no_source_ip", ts(-30 + i), "001", None, "a") for i in range(10)], {})
    # groups
    d = [ssh("groups", ts(-30 + i), "001", "192.0.2.7", "a") for i in range(8)] + \
        [ssh("groups", ts(-30 + i), "002", "192.0.2.7", "a") for i in range(7)] + \
        [ssh("groups", ts(-30 + i), "001", "192.0.2.8", "a") for i in range(7)]
    add("groups", BF, d, {("001", "192.0.2.7"): 8, ("002", "192.0.2.7"): None, ("001", "192.0.2.8"): None})
    # identity dedup (enabled via profile override): 4 records delivered twice = 4
    for case, ov, want in (("identity_dedup_on", {"event_identity_field": "wazuh.event.id"}, None),
                           ("identity_dedup_off", {}, 8)):
        d = [ssh(case, ts(-30 + i), "001", "192.0.2.9", "a", ident="evt-%d" % i) for i in range(4)] * 2
        add(case, BF, copy.deepcopy(d), {("001", "192.0.2.9"): want}, ov)
    # value_count
    add("spray_exact", SP, [ssh("spray_exact", ts(-300 + i * 30), "001", "192.0.2.10", "u%d" % i) for i in range(5)],
        {("001", "192.0.2.10"): 5})
    add("spray_repeat", SP, [ssh("spray_repeat", ts(-100 + i), "001", "192.0.2.11", "u%d" % (i % 4)) for i in range(40)],
        {("001", "192.0.2.11"): None})
    add("spray_window", SP, [ssh("spray_window", ts(-700 + i * 150), "001", "192.0.2.12", "u%d" % i) for i in range(5)],
        {("001", "192.0.2.12"): None})
    add("spray_large", SP, [ssh("spray_large", ts(-300 + i * 0.05), "001", "192.0.2.13", "user%05d" % i)
                            for i in range(5000)], {("001", "192.0.2.13"): 5000})
    # Windows
    add("win_burst", WB, [win("win_burst", ts(-60 + i), "003", "192.0.2.20", "Administrator") for i in range(10)],
        {("003", "192.0.2.20"): 10})
    add("win_spray", WS, [win("win_spray", ts(-60 + i), "003", "192.0.2.21", "acct%d" % (i % 6)) for i in range(12)],
        {("003", "192.0.2.21"): 6})
    # Windows account identity (wcp.windows_target_account); expected identities from the Python reference
    ip = "192.0.2.30"
    add("win_id_observed_shape", WS, [winacct("win_id_observed_shape", ts(-50 + i), "003", ip,
                                              absent("User%d" % i, "."), "WCP-WIN-LAB1") for i in range(5)],
        {("003", ip): 5})
    ip = "192.0.2.31"
    add("win_id_same_name_five_domains", WS,
        [winacct("win_id_same_name_five_domains", ts(-50 + i), "003", ip, present("bob", dom), "WIN10")
         for i, dom in enumerate(["CONTOSO", "FABRIKAM", "NORTHWIND", "ADATUM", "TAILSPIN"])], {("003", ip): 5})
    ip = "192.0.2.32"
    add("win_id_case_and_local_computer", WS,
        [winacct("win_id_case_and_local_computer", ts(-50 + i), "003", ip, u, "WIN-LAB1.corp.example") for i, u in
         enumerate([absent("admin", "."), absent("Admin", "WIN-LAB1"), absent("ADMIN", "win-lab1"),
                    present("admin", "CONTOSO"), present("Admin", "contoso")])], {("003", ip): None})
    ip = "192.0.2.33"
    add("win_id_missing_domain", WS,
        [winacct("win_id_missing_domain", ts(-50 + i), "003", ip, u, "WIN10") for i, u in
         enumerate([absent("bob", None), present("bob", "CONTOSO"), absent("alice", "-"), present("alice", "CONTOSO"),
                    absent("carol", "")])], {("003", ip): None})   # ?\\bob/contoso\\bob and ?\\alice/contoso\\alice
                                                                    # are one account each: 3 accounts
    ip = "192.0.2.34"
    add("win_id_subject_not_used", WS,
        [winacct("win_id_subject_not_used", ts(-50 + i), "003", ip, present("u%d" % i, None), "WIN10")
         for i in range(5)], {("003", ip): 5})
    ip = "192.0.2.35"
    mism = [absent("v%d" % i, "CONTOSO") for i in range(4)]
    for u in mism:
        u["target"]["id"] = "S-1-5-21-1-2-3-11%02d" % len(u["target"]["name"])
    add("win_id_sid_mismatch", WS, [winacct("win_id_sid_mismatch", ts(-50 + i), "003", ip, u, "WIN10")
                                    for i, u in enumerate(mism)], {("003", ip): None})
    # the 5.0.0-rc2 defect of 105573d: a subject name with the NULL SID, no attributable target domain
    # ('-' or element absent): user.id == user.target.id and user.domain = the SUBJECT's domain.
    # Specification: one account ?\bob for five subject domains -> no alert (105573d: 5, alert).
    ip = "192.0.2.36"
    amb = []
    for i in range(5):
        u = {"name": "svc", "domain": "SUBJ%d" % i, "id": "S-1-0-0", "target": {"name": "bob", "id": "S-1-0-0"}}
        if i % 2 == 0:
            u["target"]["domain"] = "-"
        amb.append(u)
    add("win_id_ambiguous_subject_domain", WS, [winacct("win_id_ambiguous_subject_domain", ts(-50 + i), "003", ip, u,
                                                        "WIN10") for i, u in enumerate(amb)], {("003", ip): None})
    # no reporting subject: the target domain is in user.domain, not attributable -> the same name in five
    # domains is one account ?\bob (documented loss) -> no alert (105573d: 5, alert)
    ip = "192.0.2.37"
    add("win_id_no_subject_same_name", WS,
        [winacct("win_id_no_subject_same_name", ts(-50 + i), "003", ip, absent("bob", dom), "WIN10")
         for i, dom in enumerate(["CONTOSO", "FABRIKAM", "NORTHWIND", "ADATUM", "TAILSPIN"])], {("003", ip): None})
    # mixed decoded shapes of the same failed-target accounts. Ground truth from the raw target fields:
    # every record below has TargetDomainName CONTOSO, so the actual accounts are CONTOSO\alice, CONTOSO\bob,
    # CONTOSO\carol - each seen once without a reporting subject (decoded realm unknown) and once with one
    # (explicit user.target.domain). 3 actual accounts -> no spray alert (threshold 5).
    ip = "192.0.2.38"
    mixed = []
    for n in ("alice", "bob", "carol"):
        mixed += [absent(n, "CONTOSO"), present(n, "CONTOSO")]
    add("win_id_mixed_shapes_three_accounts", WS,
        [winacct("win_id_mixed_shapes_three_accounts", ts(-50 + i), "003", ip, u, "WIN10") for i, u in enumerate(mixed)],
        {("003", ip): None})
    # five genuinely distinct target user names across both shapes and missing/'-' domains -> 5 accounts, alert 5
    ip = "192.0.2.39"
    five = [absent("u0", "CONTOSO"), present("u1", "CONTOSO"), absent("u2", None), present("u3", "-"), absent("u4", "-")]
    add("win_id_mixed_shapes_five_names", WS,
        [winacct("win_id_mixed_shapes_five_names", ts(-50 + i), "003", ip, u, "WIN10") for i, u in enumerate(five)],
        {("003", ip): 5})
    return cases


def execute(client, corr, settings, version, fixture):
    s = dict(settings, indices=[INDEX], extra_filters=[{"term": {"fixture": fixture}}])
    body = A.render_monitor(corr, s, version)
    body["inputs"][0]["search"]["query"]["aggregations"][A.GROUP_AGG].pop("meta", None)
    t0 = time.time()
    res = client.post("/_plugins/_alerting/monitors/_execute", body, params={"dryrun": "true"})
    took = round((time.time() - t0) * 1000)
    ir = res.get("input_results") or {}
    if ir.get("error"):
        raise RuntimeError("input error: %s" % ir["error"])
    out, details = {}, {}
    for _tid, tr in (res.get("trigger_results") or {}).items():
        if tr.get("error"):
            raise RuntimeError("trigger error: %s" % tr["error"])
        for _k, b in (tr.get("agg_result_buckets") or {}).items():
            b = b.get("agg_alert_content", b)
            det = (b.get("bucket") or {}).get(A.DETAIL_AGG, {}).get("value") or {}
            out[tuple(b["bucket_keys"])] = det.get("score")
            details[tuple(b["bucket_keys"])] = det
    query_ms = None
    try:
        query_ms = ir["results"][0]["took"]
    except (KeyError, IndexError, TypeError):
        pass
    return out, took, query_ms, details


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="keep the fixture index")
    ap.add_argument("--evidence")
    a = ap.parse_args()
    load_env_file(os.environ.get("WCP_ENV_FILE", DEFAULT_ENV_FILE))
    client = Client()
    _r, corrs = S.load_content(PACK)
    corrs = {c.name: c for c in corrs}
    prof = C.load_profile(os.path.join(PACK, "pack.yml"))
    try:
        client.delete("/" + INDEX)
    except ApiError as e:
        if e.status != 404:
            raise
    client.put("/" + INDEX, MAPPING)
    now = datetime.datetime.now(datetime.timezone.utc)
    cases = build_cases(now)
    bulk = []
    for _n, _c, docs, _e, _o in cases:
        for d in docs:
            bulk.append(json.dumps({"index": {"_index": INDEX}}))
            bulk.append(json.dumps(d))
    for i in range(0, len(bulk), 4000):
        r = client.post("/_bulk?refresh=wait_for", "\n".join(bulk[i:i + 4000]) + "\n")
        assert not r.get("errors"), json.dumps(r)[:2000]
    results, fails = [], 0
    for name, cname, docs, expect, ov in cases:
        st = dict(C.settings_for(prof, cname), **ov)
        assert all(d["fixture"] == name for d in docs), name
        got, took, qms, details = execute(client, corrs[cname], st, prof["version"], name)
        want = {k: v for k, v in expect.items() if v is not None}
        ok = got == want
        ident_check = None
        if IDN.is_virtual(corrs[cname].value_field):
            ident = IDN.get(corrs[cname].value_field)
            ref = {v for v in (ident.python(d) for d in docs) if v is not None}
            # parity with the monitor's counting: with unknown-realm counting, ?\name is not counted when the
            # same user name has a known realm (ground truth is the expected score of each case)
            ref = sorted(A.unknown_realm_score(ref) if ident.unknown_realm_merge else ref)
            ident_check = {"python_reference": ref,
                           "painless": {"|".join(k): sorted(v.get("distinct_values_sample") or [])
                                        for k, v in details.items()}}
            for k in want:
                ok = ok and IS.same_accounts(details[k].get("distinct_values_sample") or [], ref[:25])
            if not want:
                # nothing triggers at the real threshold: probe at threshold 1 to read the identities
                probe = copy.copy(corrs[cname])
                probe.min_count = 1
                _g, _t, _q, pdet = execute(client, probe, st, prof["version"], name)
                ident_check["painless_probe_threshold_1"] = {"|".join(k): sorted(v.get("distinct_values_sample") or [])
                                                            for k, v in pdet.items()}
                for k in expect:
                    ok = ok and IS.same_accounts((pdet.get(k) or {}).get("distinct_values_sample") or [], ref[:25])
            print("      identities python=%s painless=%s%s" % (ref, ident_check["painless"], (
                " probe=%s" % ident_check["painless_probe_threshold_1"]) if "painless_probe_threshold_1" in ident_check else ""))
        fails += 0 if ok else 1
        print("[%s] %-20s %-32s docs=%-5d expected=%s got=%s (execute %d ms, query %s ms)" % (
            "PASS" if ok else "FAIL", name, cname, len(docs), want, got, took, qms))
        results.append({"case": name, "correlation": cname, "docs": len(docs), "settings_override": ov,
                        "expected_triggered": {"|".join(k): v for k, v in want.items()},
                        "triggered": {"|".join(k): v for k, v in got.items()}, "pass": ok,
                        "identity_check": ident_check,
                        "execute_ms": took, "query_took_ms": qms})
    if not a.keep:
        client.delete("/" + INDEX)
    if a.evidence:
        os.makedirs(a.evidence, exist_ok=True)
        with open(os.path.join(a.evidence, "api_monitor_execute.json"), "w", encoding="utf-8") as fh:
            json.dump({"layer": "query-api (indexed fixtures, _execute dry run)", "run_at": now.isoformat(),
                       "index": INDEX, "index_deleted": not a.keep, "cases": results,
                       "verdict": "PASS" if not fails else "FAIL"}, fh, indent=2)
    print("%d/%d passed" % (len(results) - fails, len(results)))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
