"""Recipes (one Markdown card per ``RECIPE`` item, in English) and the
bucket-level monitor of a frequency rule."""

import json

from .. import model4 as m
from .. import reasons as R
from ..textsafe import md

MIN_WINDOW = 300

# same_* options -> WCS field of the composite source.
SAME_TO_WCS = {
    "same_source_ip": "source.ip",
    "same_srcip": "source.ip",
    "same_src_port": "source.port",
    "same_srcport": "source.port",
    "same_dst_port": "destination.port",
    "same_dstport": "destination.port",
    "same_dstip": "destination.ip",
    "same_srcuser": "user.name",
    "same_user": "user.name",
    "same_location": "wazuh.protocol.location",
    "same_id": "event.code",
    "same_url": "url.original",
    "same_protocol": "network.protocol",
    "same_action": "event.action",
    "same_status": "event.outcome",
    "same_system_name": "host.name",
    "same_srcgeoip": "source.geo.country_iso_code",
    "same_dstgeoip": "destination.geo.country_iso_code",
    "same_agent": "wazuh.agent.name",
}

# What the user does, per RECIPE code (shown on every card that has the code).
ADVICE = {
    "RM-R-FREQUENCY": "Create the Alerting monitor in monitors/<id>.json (Dev Tools: POST _plugins/_alerting/monitors). It counts the findings of the base rule; add an action to its trigger to be notified.",
    "RM-R-CORRELATION": "5.0 has no correlation rules. Count or join the findings with an Alerting monitor or an external query; see the guide section 'Alerting on repeated events'.",
    "RM-R-FTS": "First-time-seen keeps state: use an Alerting monitor or an external job that remembers the values already seen.",
    "RM-R-CHECK-DIFF": "Compare the outputs with an external job or a scheduled query.",
    "RM-R-TIME": "Rules have no time conditions in 5.x: filter by @timestamp in a monitor or a dashboard query.",
    "RM-R-COMPILED": "Rewrite the C check as conditions on the decoded fields.",
    "RM-R-SILENCER-STOCK": "Stock rules are read only in 5.x and one stock rule cannot be disabled or given an exclusion. Pick an option of the 'Tuning to redo' section of report.md: a custom copy of the stock rule with this condition as a not selection (and the stock integration or detector disabled), an engine filter that drops the events, or disabling the whole stock integration. Not live-verified.",
    "RM-R-OVERWRITE-STOCK": "Stock rules are read only in 5.x and one stock rule cannot be disabled or changed. Pick an option of the 'Tuning to redo' section of report.md: a custom copy with your changes (and the stock integration or detector disabled), or disabling the whole stock integration. Not live-verified.",
    "RM-R-NO-SOURCE": "Add a decoded_as or a parent rule that ties the rule to a log source, or write the 5.x rule by hand in the integration that decodes its events.",
    "RM-R-IF-LEVEL": "Write one rule per parent you need, or a monitor over the findings of the levels you want.",
    "RM-R-PARENT-RECIPE": "Apply the recipe of the parent first; this rule depends on it.",
    "RM-R-LABEL-UNAVAILABLE": "The events come from a stock integration, which cannot be changed: decode the field you need in a decoder of your own, or match it with a condition on WCS fields.",
    "RM-R-RE-UNSUPPORTED": "Rewrite the pattern with literals, character classes and .* (no backslash, $, ^ outside [^, space or /), or match on a decoded field.",
    "RM-R-MULTI-SOURCE": "Split the rule: one 5.x rule per integration its chains reach.",
    "RM-F-DROPPED": "The rule depends on a field marked drop in decisions.json: map the field to a WCS field, or rewrite the condition.",
    "RM-D-PLUGIN": "Decode the format with parse_json, kv, csv or xml in a decoder of your own.",
    "RM-D-FTS": "Decoders are stateless in 5.x: drop the first-time-seen part or move it to a monitor.",
    "RM-D-ACCUMULATE": "Decoders are stateless in 5.x: join the lines before they reach the manager.",
    "RM-D-REGEX-UNSUPPORTED": "Rewrite the pattern without lookarounds, back references or other PCRE2-only constructs.",
    "RM-D-HELPER-UNAVAILABLE": "Build again with the --engine-helpers of the engine that will run the content, or write the block by hand with a helper that engine has (its helper reference lists them).",
    "RM-L-IOC-FEED-UNSUPPORTED": "Set the action of the list back to kvdb in decisions.json (lists), or write the condition by hand on wazuh.threat.enrichments.",
    "RM-L-KEY-VALUE-INVERTED": "Check by hand what the 4.14 rule really matched (the condition is inverted there), then write a decoder block with kvdb_lookup and a check.",
    "RM-X-UNKNOWN-ELEMENT": "4.14 refuses the element: fix the 4.x source or write the 5.x content by hand.",
    "RM-X-INVALID": "4.14 refuses the element: fix the 4.x source or write the 5.x content by hand.",
}


def _same_fields(tr, item):
    fields, notes = ["wazuh.agent.name"], []
    for key, vals in sorted(item["correlation"].items()):
        if not key.startswith("same_"):
            continue
        if key == "same_field":
            for v in vals:
                action, wcs = tr.clf.field_action(v)
                if action == "map":
                    fields.append(wcs)
                else:
                    notes.append("same_field %s has no WCS field in decisions.json: add it to the composite sources by hand" % v)
            continue
        wcs = SAME_TO_WCS.get(key)
        if wcs is None:
            notes.append("%s has no WCS field: add it to the composite sources by hand" % key)
        elif wcs not in fields:
            fields.append(wcs)
    return fields, notes


def monitor(tr, uid):
    """(monitor body or None, notes) for a frequency rule."""
    item = tr.items[uid]
    notes = []
    base_id = item["parents"].get("if_matched_sid")
    if not base_id:
        return None, ["the rule has no if_matched_sid: no monitor"]
    base_uid = tr.load.by_id.get(base_id)
    filters = []
    if base_uid is not None and not tr.tree.is_stock(base_uid):
        filters.append({"term": {"tags": "wazuh4.rule.%s" % base_id}})
        if tr.state(base_uid) != R.AUTO:
            notes.append("the base rule %s is %s: it must be migrated first for the monitor to count anything" % (base_id, tr.state(base_uid)))
    else:
        from .engine import Build
        e = tr.stock_entry("rule:%s" % base_id, Build())
        if e is None or e["selection"] is None:
            return None, ["the base rule %s is stock content with no equivalence: complete decisions.json (stock rule:%s) and build again" % (base_id, base_id)]
        filters.append({"term": {"wazuh.integration.name": e["integration"]}})
        for k, v in sorted(e["selection"][1].items()):
            if "|" in k or isinstance(v, (list, dict)):
                notes.append("selection key %s is not a plain value: add it to the filter by hand" % k)
                continue
            filters.append({"term": {k: v}})
    try:
        freq = int(item["attrs"]["frequency"])
    except (KeyError, ValueError):
        return None, ["frequency %r is not a number" % item["attrs"].get("frequency")]
    try:
        timeframe = int(item["attrs"].get("timeframe", "360"))
    except ValueError:
        timeframe = 360
    window = max(timeframe, MIN_WINDOW)
    if window != timeframe:
        notes.append("window %d s instead of %d s: findings arrive one or two minutes late" % (window, timeframe))
    if item["conditions"] or item["fields"] or item["lists"]:
        notes.append("the 4.x rule also had conditions of its own on the last event; the monitor counts the base findings only")
    group_fields, gnotes = _same_fields(tr, item)
    notes.extend(gnotes)
    sources = [{f.replace(".", "_"): {"terms": {"field": f}}} for f in group_fields]
    filters.append({"range": {"@timestamp": {"gte": "{{period_end}}||-%ds" % window, "lte": "{{period_end}}",
                                             "format": "epoch_millis"}}})
    from .meta import title_from_description
    desc = title_from_description(item["description"] or "", lambda f: None)[0]
    body = {
        "type": "monitor",
        "monitor_type": "bucket_level_monitor",
        "name": "wazuh4 rule %s: %s" % (item["id"], desc)[:200],
        "enabled": True,
        "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
        "inputs": [{"search": {"indices": ["wazuh-findings-v5-*"], "query": {
            "size": 0,
            "query": {"bool": {"filter": filters}},
            "aggregations": {"by_group": {"composite": {"sources": sources}}},
        }}}],
        "triggers": [{"bucket_level_trigger": {
            "name": "%d or more in %d s (4.x rule %s)" % (freq, window, item["id"]),
            "severity": "2",
            "condition": {"buckets_path": {"count": "_count"}, "parent_bucket_path": "by_group",
                          "script": {"source": "params.count >= %d" % freq, "lang": "painless"}},
            "actions": [],
        }}],
    }
    return body, notes


def recipe_name(item):
    if item["kind"] == m.RULE:
        return "rule-%s" % item["id"]
    from .meta import safe_name
    if item["kind"] == m.DECODER:
        return "decoder-%s" % safe_name(item["name"])
    return "list-%s" % safe_name(item["name"])


def render(tr, uid, monitor_body=None, monitor_notes=(), partial=None):
    item = tr.items[uid]
    acc = tr.clf.acc[uid]
    lines = []
    w = lines.append
    if item["kind"] == m.RULE:
        w("# Recipe: Wazuh 4.x rule %s" % md(item["id"]))
        w("")
        w("%s" % md((item["description"] or "").strip()))
    elif item["kind"] == m.DECODER:
        w("# Recipe: Wazuh 4.x decoder %s" % md(item["name"]))
    else:
        w("# Recipe: Wazuh 4.x list %s" % md(item["name"]))
    w("")
    w("- Origin: `%s:%d`" % (item["file"], item["line"]))
    w("- State: `RECIPE` (no direct translation)")
    w("")
    w("## Why")
    w("")
    for code in sorted(acc.codes):
        r = R.CATALOG[code]
        detail = "; ".join(acc.codes[code])
        w("- [`%s`](%s) (%s): %s%s" % (code, r.anchor, r.state, r.text, (" Detail: %s." % detail) if detail else ""))
    w("")
    w("## What you need to do")
    w("")
    done = set()
    n = 0
    for code in sorted(acc.codes):
        if R.CATALOG[code].state != R.RECIPE:
            continue
        text = ADVICE.get(code)
        if text and text not in done:
            done.add(text)
            n += 1
            w("%d. %s" % (n, text.replace("<id>", item.get("id") or "")))
    if code_in(acc, "RM-R-SILENCER-STOCK"):
        targets = tr.clf.extra.get(uid, {}).get("exclusion_stock_targets", [])
        n += 1
        w("%d. Stock rules it silenced in 4.x: %s." % (n, ", ".join("`%s`" % t for t in targets)))
    if not done:
        n += 1
        w("%d. Write the 5.x content by hand from the 4.x source above." % n)
    w("")
    if monitor_body is not None or monitor_notes:
        w("## Monitor")
        w("")
        if monitor_body is not None:
            w("The definition is in `monitors/%s.json` (bucket-level monitor over `wazuh-findings-v5-*`; the build does not create it)." % item["id"])
        for note in monitor_notes:
            w("- %s" % note)
        w("")
    if partial is not None:
        w("## Starting point")
        w("")
        w("The part of the rule that has a translation (not emitted; review it before you create it):")
        w("")
        w("```json")
        w(json.dumps(partial, sort_keys=True, indent=2, ensure_ascii=False))
        w("```")
        w("")
    if acc.notes:
        w("## Notes")
        w("")
        for note in acc.notes:
            w("- %s" % note)
        w("")
    return "\n".join(lines).rstrip("\n") + "\n"


def code_in(acc, code):
    return code in acc.codes
