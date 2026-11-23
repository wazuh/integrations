"""Read-only collection of the platform facts the pack relies on (RC2 plan, step 2).

Writes ``platform_facts.json``: indexer version, events/findings data streams, mapped types of
every field the pack reads, alert-history default, Alerting / job-scheduler / search limits, and
the decoded identity shapes of indexed Windows 4625 events (which fields hold the target realm).
It changes nothing on the cluster.

Run: python tests/api/collect_platform_facts.py --evidence DIR
"""

import argparse
import datetime
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, PACK)

from wcp import identity as IDN  # noqa: E402
from wcp import sigma as S  # noqa: E402
from wcp.client import DEFAULT_ENV_FILE, ApiError, Client, load_env_file  # noqa: E402

EVENTS = "wazuh-events-v5-system-activity"
LIMIT_KEYS = ("plugins.alerting.alert_history_enabled", "plugins.alerting.input_timeout",
              "plugins.alerting.request_timeout", "plugins.alerting.monitor.max_monitors",
              "plugins.alerting.monitor.max_triggers", "plugins.alerting.index_timeout",
              "plugins.jobscheduler.jitter_limit", "plugins.jobscheduler.sweeper.period",
              "search.max_buckets", "search.default_search_timeout", "search.cancel_after_time_interval",
              "script.max_compilations_rate", "indices.breaker.request.limit", "indices.breaker.total.limit")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", required=True)
    a = ap.parse_args()
    load_env_file(os.environ.get("WCP_ENV_FILE", DEFAULT_ENV_FILE))
    c = Client()
    facts = {"collected_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "read_only": True}
    root = c.get("/")
    facts["indexer"] = {"distribution": root["version"].get("distribution"), "number": root["version"].get("number"),
                        "build_hash": root["version"].get("build_hash")}
    ds = c.get("/_data_stream/wazuh-*")["data_streams"]
    facts["data_streams"] = sorted(d["name"] for d in ds if "events" in d["name"] or "findings" in d["name"])
    _r, corrs = S.load_content(PACK)
    fields = {"@timestamp", "event.start", "wazuh.event.id", "wazuh.agent.name"}
    for corr in corrs:
        fields |= set(corr.group_by) | set().union(*[r.fields() for r in corr.rules])
        if IDN.is_virtual(corr.value_field):
            fields |= set(IDN.get(corr.value_field).required) | set(IDN.get(corr.value_field).optional)
        elif corr.value_field:
            fields.add(corr.value_field)
    fm = c.get("/%s/_mapping/field/%s" % (EVENTS, ",".join(sorted(fields))))
    types = {}
    for _ix, m in fm.items():
        for f, spec in (m.get("mappings") or {}).items():
            for _leaf, d in (spec.get("mapping") or {}).items():
                types[f] = d.get("type")
    facts["field_types"] = {f: types.get(f, "NOT MAPPED") for f in sorted(fields)}
    st = c.get("/_cluster/settings", params={"include_defaults": "true", "flat_settings": "true"})
    merged = {}
    for scope in ("defaults", "persistent", "transient"):
        merged.update(st.get(scope) or {})
    facts["settings"] = {k: merged.get(k) for k in LIMIT_KEYS}
    facts["settings_explicit"] = {k: v for scope in ("persistent", "transient") for k, v in (st.get(scope) or {}).items()}
    # decoded identity shapes of 4625 events
    sources = []
    for name, f in (("user_domain", "user.domain"), ("user_target_domain", "user.target.domain"),
                    ("user_id", "user.id"), ("user_target_id", "user.target.id"), ("host_name", "host.name")):
        if types.get(f):
            sources.append({name: {"terms": {"field": f, "missing_bucket": True}}})
        else:
            sources.append({name: {"terms": {"script": {"source": "'(field not mapped)'", "lang": "painless"}}}})
    sources.append({"user_name_equals_target": {"terms": {"script": {"lang": "painless", "source":
        "doc.containsKey('user.name') && doc['user.name'].size() > 0 && doc.containsKey('user.target.name') && "
        "doc['user.target.name'].size() > 0 && doc['user.name'].value == doc['user.target.name'].value"}}}})
    try:
        r = c.post("/%s/_search" % EVENTS, {"size": 0, "query": {"bool": {"filter": [{"term": {"event.code": "4625"}}]}},
                                           "aggs": {"shape": {"composite": {"size": 100, "sources": sources}}}})
        facts["windows_4625_identity_shapes"] = [dict(b["key"], doc_count=b["doc_count"])
                                                 for b in r["aggregations"]["shape"]["buckets"]]
    except ApiError as e:
        facts["windows_4625_identity_shapes"] = "error: %s" % e
    os.makedirs(a.evidence, exist_ok=True)
    with open(os.path.join(a.evidence, "platform_facts.json"), "w", encoding="utf-8") as fh:
        json.dump(facts, fh, indent=2, sort_keys=True)
    print(json.dumps(facts, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
