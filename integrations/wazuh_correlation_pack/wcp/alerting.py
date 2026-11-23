"""Alerting-plugin backend: render a correlation as a bucket-level monitor.

Timing model (all durations are configurable and kept separate):

* ``window`` (Sigma ``timespan``)  - event-time span that the counted events
  must fall into: an event set qualifies when ``last - first < window``.
* ``interval``                    - how often the Alerting scheduler runs the monitor.
* ``allowed_lateness``            - how late (ingest time minus event time) an
  event may arrive and still be counted.
* ``lookback`` = window + allowed_lateness + interval - the event-time range the
  monitor reads on each run. The window itself is *not* widened: inside the
  lookback a Painless ``scripted_metric`` computes, per group, the maximum
  number of events (``event_count``) or of distinct values (``value_count``)
  inside any sliding window of exactly ``window`` length.

Grouping is a ``composite`` aggregation over the correlation's ``group-by``
fields, so every combination (e.g. agent id + source ip) is an independent
bucket and an independent Alerting alert.
"""

import copy
import hashlib
import json

from . import identity as IDN
from . import query as Q

SEVERITY = {"critical": "1", "high": "2", "medium": "3", "low": "4", "informational": "5"}
PACK_ID = "wazuh_correlation_pack"
NAME_PREFIX = "[wcp] "
GROUP_AGG = "wcp_groups"
SCORE_AGG = "wcp_score"
DETAIL_AGG = "wcp_detail"

# --------------------------------------------------------------------- painless
# The same algorithm is implemented in Python by ``sliding_score`` below and
# unit-tested there; keep them in sync.
PAINLESS_INIT = "state.p = new ArrayList();"
PAINLESS_MAP = """
if (!doc.containsKey(params.ts) || doc[params.ts].size() == 0) { return; }
long t = doc[params.ts].value.toInstant().toEpochMilli();
def v = null;
if (params.vf != '') {
  if (!doc.containsKey(params.vf) || doc[params.vf].size() == 0) { return; }
  v = doc[params.vf].value.toString();
}
def id = null;
if (params.idf != '' && doc.containsKey(params.idf) && doc[params.idf].size() > 0) { id = doc[params.idf].value.toString(); }
state.p.add([t, v, id]);
""".strip()
PAINLESS_VALUE_BLOCK = """if (params.vf != '') {
  if (!doc.containsKey(params.vf) || doc[params.vf].size() == 0) { return; }
  v = doc[params.vf].value.toString();
}"""
assert PAINLESS_VALUE_BLOCK in PAINLESS_MAP
PAINLESS_COMBINE = "return state.p;"
PAINLESS_REDUCE = """
List p = new ArrayList();
for (s in states) { if (s != null) { p.addAll(s); } }
p.sort((x, y) -> Long.compare((long) x.get(0), (long) y.get(0)));
int overflow = 0;
if (p.size() > params.max_events) { overflow = p.size() - params.max_events; p = p.subList(p.size() - params.max_events, p.size()); }
Set seen = new HashSet();
List q = new ArrayList();
int dups = 0;
for (e in p) {
  def id = e.get(2);
  if (id != null) { if (seen.contains(id)) { dups++; continue; } seen.add(id); }
  q.add(e);
}
long w = params.window_ms;
int best = 0; long bs = 0; long be = 0; int i = 0; List sample = new ArrayList();
Map cnt = new HashMap();
for (int j = 0; j < q.size(); ++j) {
  long tj = (long) q.get(j).get(0);
  def vj = q.get(j).get(1);
  if (vj != null) { cnt.put(vj, cnt.getOrDefault(vj, 0) + 1); }
  while (tj - (long) q.get(i).get(0) >= w) {
    def vi = q.get(i).get(1);
    if (vi != null) { int c = cnt.get(vi) - 1; if (c == 0) { cnt.remove(vi); } else { cnt.put(vi, c); } }
    i++;
  }
  int score = params.distinct ? cnt.size() : (j - i + 1);
  if (score > best) {
    best = score; bs = (long) q.get(i).get(0); be = tj;
    if (params.detail && params.distinct) { sample = new ArrayList(cnt.keySet()); }
  }
}
if (!params.detail) { return best; }
if (sample.size() > 25) { sample = sample.subList(0, 25); }
Collections.sort(sample);
return ['score': best, 'events_in_lookback': q.size(), 'duplicates_skipped': dups, 'overflow_dropped': overflow,
        'window_start': bs, 'window_end': be, 'distinct_values_sample': sample];
""".strip()


# Variant of PAINLESS_REDUCE for derived accounts ``<realm>\\<user>`` whose realm may be unknown
# (``?``): an unknown-realm value adds an account only if no value with a known realm and the same
# user name is in the window (a representation of the same failed target never counts twice).
# Score = distinct known-realm values + distinct user names seen only with the unknown realm.
PAINLESS_REDUCE_UNKNOWN_REALM = PAINLESS_REDUCE.replace(
    """Map cnt = new HashMap();
for (int j = 0; j < q.size(); ++j) {
  long tj = (long) q.get(j).get(0);
  def vj = q.get(j).get(1);
  if (vj != null) { cnt.put(vj, cnt.getOrDefault(vj, 0) + 1); }
  while (tj - (long) q.get(i).get(0) >= w) {
    def vi = q.get(i).get(1);
    if (vi != null) { int c = cnt.get(vi) - 1; if (c == 0) { cnt.remove(vi); } else { cnt.put(vi, c); } }
    i++;
  }
  int score = params.distinct ? cnt.size() : (j - i + 1);
  if (score > best) {
    best = score; bs = (long) q.get(i).get(0); be = tj;
    if (params.detail && params.distinct) { sample = new ArrayList(cnt.keySet()); }
  }
}""",
    """Map cnt = new HashMap();
Map known = new HashMap();
Set unknown = new HashSet();
int nKnown = 0; int nUnknownOnly = 0;
for (int j = 0; j < q.size(); ++j) {
  long tj = (long) q.get(j).get(0);
  String vj = (String) q.get(j).get(1);
  if (vj != null) {
    int c0 = cnt.getOrDefault(vj, 0);
    cnt.put(vj, c0 + 1);
    if (c0 == 0) {
      int k = vj.indexOf('\\\\'); String r = vj.substring(0, k); String nm = vj.substring(k + 1);
      if (r == '?') { unknown.add(nm); if (known.getOrDefault(nm, 0) == 0) { nUnknownOnly++; } }
      else { nKnown++; int kn = known.getOrDefault(nm, 0); if (kn == 0 && unknown.contains(nm)) { nUnknownOnly--; } known.put(nm, kn + 1); }
    }
  }
  while (tj - (long) q.get(i).get(0) >= w) {
    String vi = (String) q.get(i).get(1);
    if (vi != null) {
      int c = cnt.get(vi) - 1;
      if (c == 0) {
        cnt.remove(vi);
        int k = vi.indexOf('\\\\'); String r = vi.substring(0, k); String nm = vi.substring(k + 1);
        if (r == '?') { unknown.remove(nm); if (known.getOrDefault(nm, 0) == 0) { nUnknownOnly--; } }
        else { nKnown--; int kn = known.get(nm) - 1; if (kn == 0) { known.remove(nm); if (unknown.contains(nm)) { nUnknownOnly++; } } else { known.put(nm, kn); } }
      } else { cnt.put(vi, c); }
    }
    i++;
  }
  int score = nKnown + nUnknownOnly;
  if (score > best) {
    best = score; bs = (long) q.get(i).get(0); be = tj;
    if (params.detail) {
      sample = new ArrayList();
      for (String v : cnt.keySet()) { int k = v.indexOf('\\\\'); if (v.substring(0, k) != '?' || known.getOrDefault(v.substring(k + 1), 0) == 0) { sample.add(v); } }
    }
  }
}""")
assert PAINLESS_REDUCE_UNKNOWN_REALM != PAINLESS_REDUCE


def unknown_realm_score(values):
    """Accounts counted by PAINLESS_REDUCE_UNKNOWN_REALM for a set of ``<realm>\\<user>`` values."""
    vals = set(values)
    known = {v for v in vals if v.split("\\", 1)[0] != "?"}
    known_names = {v.split("\\", 1)[1] for v in known}
    unknown_only = {v for v in vals if v.split("\\", 1)[0] == "?" and v.split("\\", 1)[1] not in known_names}
    return known | unknown_only


def sliding_score(events, window_ms, distinct=False, max_events=None, unknown_realm=False):
    """Reference implementation of PAINLESS_REDUCE (``unknown_realm``: PAINLESS_REDUCE_UNKNOWN_REALM,
    recomputed from scratch at every step - deliberately not the incremental algorithm).

    ``events``: iterable of (epoch_ms, value_or_None, identity_or_None).
    Returns (best_score, window_start, window_end, duplicates_skipped).
    """
    p = sorted(events, key=lambda e: e[0])
    if max_events is not None and len(p) > max_events:
        p = p[len(p) - max_events:]
    seen, q, dups = set(), [], 0
    for e in p:
        if e[2] is not None:
            if e[2] in seen:
                dups += 1
                continue
            seen.add(e[2])
        q.append(e)
    best, bs, be, i = 0, 0, 0, 0
    cnt = {}
    for j, (tj, vj, _id) in enumerate(q):
        if vj is not None:
            cnt[vj] = cnt.get(vj, 0) + 1
        while tj - q[i][0] >= window_ms:
            vi = q[i][1]
            if vi is not None:
                cnt[vi] -= 1
                if cnt[vi] == 0:
                    del cnt[vi]
            i += 1
        if unknown_realm:
            score = len(unknown_realm_score(cnt))
        else:
            score = len(cnt) if distinct else (j - i + 1)
        if score > best:
            best, bs, be = score, q[i][0], tj
    return best, bs, be, dups


def map_script(corr):
    """Map script: the shared one, or, for a derived value (``wcp.*``), the same script with the
    value block replaced by the derivation (see wcp/identity.py)."""
    if corr.type == "value_count" and IDN.is_virtual(corr.value_field):
        ident = IDN.get(corr.value_field)
        return ident.functions + "\n" + PAINLESS_MAP.replace(PAINLESS_VALUE_BLOCK, ident.body)
    return PAINLESS_MAP


def _scripted_metric(corr, settings, detail):
    virtual = corr.type == "value_count" and IDN.is_virtual(corr.value_field)
    return {"scripted_metric": {
        "init_script": {"source": PAINLESS_INIT, "lang": "painless"},
        "map_script": {"source": map_script(corr), "lang": "painless"},
        "combine_script": {"source": PAINLESS_COMBINE, "lang": "painless"},
        "reduce_script": {"source": PAINLESS_REDUCE_UNKNOWN_REALM if virtual and IDN.get(corr.value_field).unknown_realm_merge
                          else PAINLESS_REDUCE, "lang": "painless"},
        "params": {
            "ts": settings["timestamp_field"],
            # OpenSearch deep-copies scripted_metric params and rejects null values: '' means "not set"
            "vf": corr.value_field if corr.type == "value_count" and not virtual else "",
            "idf": settings.get("event_identity_field") or "",
            "distinct": corr.type == "value_count",
            "window_ms": corr.timespan_s * 1000,
            "max_events": int(settings["max_events_per_group"]),
            "detail": detail,
        },
    }}


def lookback_seconds(corr, settings):
    return corr.timespan_s + settings["allowed_lateness_s"] + settings["interval_s"]


def search_body(corr, settings):
    """Search request evaluated on each run (``{{period_end}}`` is filled in by Alerting)."""
    lb = lookback_seconds(corr, settings)
    filters = [Q.correlation_selection(corr)]
    for f in corr.group_by:
        filters.append({"exists": {"field": f}})
    if corr.type == "value_count":
        if IDN.is_virtual(corr.value_field):
            for f in IDN.get(corr.value_field).required:
                filters.append({"exists": {"field": f}})
        else:
            filters.append({"exists": {"field": corr.value_field}})
    for extra in settings.get("extra_filters") or []:
        filters.append(copy.deepcopy(extra))
    filters.append({"range": {settings["timestamp_field"]: {
        "gte": "{{period_end}}||-%ds" % lb, "lte": "{{period_end}}", "format": "epoch_millis"}}})
    sources = [{"g%d_%s" % (i, f.replace(".", "_").replace("@", "")): {"terms": {"field": f}}}
               for i, f in enumerate(corr.group_by)]
    aggs = {SCORE_AGG: _scripted_metric(corr, settings, detail=False),
            DETAIL_AGG: _scripted_metric(corr, settings, detail=True)}
    for f in settings.get("context_fields") or []:
        aggs["ctx_" + f.replace(".", "_")] = {"terms": {"field": f, "size": 5}}
    return {
        "size": 0,
        "query": {"bool": {"filter": filters}},
        "aggregations": {GROUP_AGG: {
            "composite": {"size": int(settings["composite_size"]), "sources": sources},
            "aggregations": aggs,
        }},
    }


def trigger_script(corr):
    return "params.score >= %d" % corr.min_count


def render_monitor(corr, settings, pack_version):
    """Full Alerting monitor body for one correlation."""
    body = {
        "type": "monitor",
        "monitor_type": "bucket_level_monitor",
        "name": NAME_PREFIX + corr.title,
        "enabled": bool(settings["enabled"]),
        "schedule": {"period": {"interval": settings["interval_s"] // 60, "unit": "MINUTES"}}
        if settings["interval_s"] % 60 == 0 else
        {"period": {"interval": settings["interval_s"], "unit": "SECONDS"}},
        "inputs": [{"search": {"indices": list(settings["indices"]), "query": search_body(corr, settings)}}],
        "triggers": [{"bucket_level_trigger": {
            "name": "%s: %s %s %d in %s per %s" % (
                corr.name,
                "events" if corr.type == "event_count" else "distinct %s" % corr.value_field,
                ">=" if corr.op == "gte" else ">",
                corr.threshold, corr.timespan_text, " + ".join(corr.group_by)),
            "severity": SEVERITY[corr.level],
            "condition": {
                "buckets_path": {"score": "%s.value" % SCORE_AGG},
                "parent_bucket_path": GROUP_AGG,
                "script": {"source": trigger_script(corr), "lang": "painless"},
            },
            "actions": [render_action(a, corr) for a in settings.get("actions") or []],
        }}],
    }
    marker = {
        "pack": PACK_ID,
        "pack_version": pack_version,
        "correlation_id": corr.id,
        "correlation_name": corr.name,
        "content_hash": None,
    }
    marker["content_hash"] = content_hash(body)
    # The Alerting plugin of 5.0.0-rc1 does not persist monitor ui_metadata, so the ownership
    # marker lives in the composite aggregation's "meta" object, which is part of the stored query.
    body["inputs"][0]["search"]["query"]["aggregations"][GROUP_AGG]["meta"] = {"wcp": marker}
    return body


def marker_of(monitor):
    """The pack marker stored in a monitor body (as returned by the API), or {}."""
    try:
        agg = monitor["inputs"][0]["search"]["query"]["aggregations"][GROUP_AGG]
        return (agg.get("meta") or {}).get("wcp") or {}
    except (KeyError, IndexError, TypeError):
        return {}


def render_action(action, corr):
    """A notification action. Only the per-alert NEW (and optionally COMPLETED) policy is offered so that
    unchanged ongoing activity (DEDUPED) never re-notifies."""
    policy = action.get("notify_on", ["NEW"])
    for p in policy:
        if p not in ("NEW", "COMPLETED", "DEDUPED"):
            raise ValueError("notify_on values must be NEW, COMPLETED or DEDUPED")
    return {
        "name": action["name"],
        "destination_id": action["channel_id"],
        "message_template": {"source": action.get("message") or DEFAULT_MESSAGE, "lang": "mustache"},
        "subject_template": {"source": action.get("subject") or ("[wcp] %s" % corr.title), "lang": "mustache"},
        "throttle_enabled": False,
        "action_execution_policy": {"action_execution_scope": {"per_alert": {"actionable_alerts": policy}}},
    }


DEFAULT_MESSAGE = (
    "Monitor {{ctx.monitor.name}} ({{ctx.trigger.name}})\n"
    "New: {{#ctx.newAlerts}}[{{bucket_keys}}] {{/ctx.newAlerts}}\n"
    "Resolved: {{#ctx.completedAlerts}}[{{bucket_keys}}] {{/ctx.completedAlerts}}\n"
    "Period end: {{ctx.periodEnd}}"
)


def content_hash(body):
    """Stable hash of the parts of the monitor the pack controls (not ids, not ui_metadata)."""
    b = {k: v for k, v in body.items() if k not in ("ui_metadata", "last_update_time", "enabled_time",
                                                       "schema_version", "user", "owner", "data_sources",
                                                       "delegate_monitor", "associated_workflows")}
    b = json.loads(json.dumps(b))
    try:
        b["inputs"][0]["search"]["query"]["aggregations"][GROUP_AGG].pop("meta", None)
    except (KeyError, IndexError, TypeError):
        pass
    return hashlib.sha256(json.dumps(b, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:16]
