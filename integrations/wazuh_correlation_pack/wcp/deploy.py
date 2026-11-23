"""Idempotent deployment of the pack's Alerting monitors.

Ownership: a monitor belongs to the pack only when its marker (composite aggregation ``meta.wcp.pack``)
equals ``wazuh_correlation_pack``. Nothing else is read for modification,
updated or deleted. The local manifest records what the pack created and the
full body of every deployed version so that ``rollback`` and ``remove`` can
revert the pack's own changes.
"""

import datetime
import json
import os

from . import alerting as A
from .client import ApiError

MONITORS = "/_plugins/_alerting/monitors"


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ------------------------------------------------------------------ cluster side

def list_owned_monitors(client, manifest_ids=None):
    """{correlation_id: (monitor_id, monitor_body)} for pack monitors, and the count of other monitors.

    A monitor is the pack's when it carries the pack marker (composite aggregation ``meta.wcp``),
    or when its id is recorded in this target's manifest as created by the pack (adoption of
    monitors whose marker was lost). Nothing else is ever returned for modification.
    """
    manifest_ids = manifest_ids or {}
    body = {"size": 1000, "query": {"bool": {"filter": [{"term": {"monitor.type": "monitor"}}]}}}
    res = client.post(MONITORS + "/_search", body)
    owned, foreign = {}, 0
    for hit in (res.get("hits") or {}).get("hits", []):
        src = hit.get("_source") or {}
        mon = src.get("monitor", src)
        marker = A.marker_of(mon)
        if marker.get("pack") == A.PACK_ID:
            cid = marker.get("correlation_id")
        elif hit["_id"] in manifest_ids:
            cid = manifest_ids[hit["_id"]]
            mon = dict(mon, _wcp_adopted=True)
        else:
            foreign += 1
            continue
        if cid in owned:
            # two monitors claim the same correlation: report both, never guess
            owned.setdefault("__duplicates__", []).append((hit["_id"], mon, cid))
            continue
        owned[cid] = (hit["_id"], mon)
    return owned, foreign


def get_monitor(client, mid):
    res = client.get(MONITORS + "/" + mid)
    return res.get("monitor", res)


# ------------------------------------------------------------------ manifest

class Manifest(object):
    def __init__(self, path, target):
        self.path = path
        self.data = {"pack": A.PACK_ID, "target": target, "current": {}, "history": []}
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as fh:
                self.data = json.load(fh)

    def save(self):
        d = os.path.dirname(self.path)
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=2, sort_keys=True)
        os.replace(tmp, self.path)

    def monitor_ids(self):
        """{monitor_id: correlation_id} of monitors this manifest says the pack created."""
        return {rec["monitor_id"]: cid for cid, rec in (self.data.get("current") or {}).items()
                if rec.get("monitor_id")}

    def record(self, action, pack_version, current):
        self.data["current"] = current
        self.data["history"].append({"at": now_iso(), "action": action, "pack_version": pack_version,
                                     "resources": current})
        self.data["history"] = self.data["history"][-20:]


# ------------------------------------------------------------------ plan / apply

def desired_monitors(correlations, profile, settings_fn, only=None):
    out = {}
    for corr in correlations:
        if only and corr.name not in only:
            continue
        s = settings_fn(profile, corr.name)
        out[corr.id] = (corr, A.render_monitor(corr, s, profile["version"]))
    return out


def plan(client, desired, prune=True, only=None, manifest=None):
    """List of steps: (op, correlation_id, name, monitor_id, body, reason)."""
    owned, foreign = list_owned_monitors(client, manifest.monitor_ids() if manifest else None)
    steps = []
    dups = owned.pop("__duplicates__", [])
    for mid, mon, cid in dups:
        steps.append(("delete", cid, mon.get("name"), mid, None, "duplicate pack monitor for the same correlation"))
    for cid, (corr, body) in sorted(desired.items(), key=lambda kv: kv[1][0].name):
        if cid not in owned:
            steps.append(("create", cid, body["name"], None, body, "not deployed"))
            continue
        mid, cur = owned[cid]
        cur_hash = A.marker_of(cur).get("content_hash")
        want = A.marker_of(body)
        want_hash = want["content_hash"]
        cur_ver = A.marker_of(cur).get("pack_version")
        if cur.get("_wcp_adopted"):
            steps.append(("update", cid, body["name"], mid, body, "adopted from manifest (marker missing)"))
        elif cur_hash != want_hash:
            steps.append(("update", cid, body["name"], mid, body, "content %s -> %s" % (cur_hash, want_hash)))
        elif cur_ver != want["pack_version"]:
            steps.append(("update", cid, body["name"], mid, body, "pack version %s -> %s" % (
                cur_ver, want["pack_version"])))
        else:
            steps.append(("noop", cid, body["name"], mid, None, "up to date"))
    if prune and not only:
        for cid, (mid, cur) in sorted(owned.items()):
            if cid not in desired:
                steps.append(("delete", cid, cur.get("name"), mid, None, "correlation no longer in the pack"))
    return steps, foreign


def apply_steps(client, steps, manifest, pack_version, action="apply"):
    results = []
    current = dict(manifest.data.get("current") or {})
    for op, cid, name, mid, body, reason in steps:
        if op == "noop":
            results.append((op, name, mid, "unchanged"))
            if cid not in current:
                current[cid] = {"monitor_id": mid, "name": name}
            continue
        if op == "create":
            res = client.post(MONITORS, body)
            mid = res["_id"]
        elif op == "update":
            client.put(MONITORS + "/" + mid, body)
        elif op == "delete":
            try:
                client.delete(MONITORS + "/" + mid)
            except ApiError as e:
                if e.status != 404:
                    raise
            current.pop(cid, None)
            results.append((op, name, mid, reason))
            continue
        current[cid] = {"monitor_id": mid, "name": name,
                        "content_hash": A.marker_of(body)["content_hash"],
                        "pack_version": pack_version, "body": body}
        results.append((op, name, mid, reason))
    manifest.record(action, pack_version, current)
    manifest.save()
    return results


def remove_all(client, manifest, pack_version):
    owned, foreign = list_owned_monitors(client, manifest.monitor_ids())
    dups = owned.pop("__duplicates__", [])
    steps = [("delete", cid, mon.get("name"), mid, None, "remove") for cid, (mid, mon) in sorted(owned.items())]
    steps += [("delete", cid, mon.get("name"), mid, None, "remove duplicate") for mid, mon, cid in dups]
    return steps, foreign


def rollback_steps(client, manifest):
    """Steps that restore the pack's previous recorded deployment (create/update/delete of pack monitors only)."""
    hist = manifest.data.get("history") or []
    if len(hist) < 2:
        raise RuntimeError("no previous deployment recorded in %s" % manifest.path)
    prev = hist[-2]["resources"]
    owned, _foreign = list_owned_monitors(client, manifest.monitor_ids())
    owned.pop("__duplicates__", None)
    steps = []
    for cid, rec in sorted(prev.items()):
        body = rec.get("body")
        if body is None:
            continue
        if cid in owned:
            steps.append(("update", cid, body["name"], owned[cid][0], body, "rollback to %s" % rec.get("pack_version")))
        else:
            steps.append(("create", cid, body["name"], None, body, "rollback (recreate)"))
    for cid, (mid, mon) in sorted(owned.items()):
        if cid not in prev:
            steps.append(("delete", cid, mon.get("name"), mid, None, "not in previous deployment"))
    return steps, hist[-2].get("pack_version")


# ------------------------------------------------------------------ status / checks

def alerts_for(client, monitor_id, state="ALL", size=100):
    res = client.get(MONITORS + "/alerts", params={"monitorId": monitor_id, "alertState": state, "size": size,
                                                   "sortString": "start_time", "sortOrder": "desc"})
    return res.get("alerts", []), res.get("totalAlerts", 0)


def status(client, desired, manifest=None):
    owned, foreign = list_owned_monitors(client, manifest.monitor_ids() if manifest else None)
    owned.pop("__duplicates__", None)
    rows = []
    for cid, (corr, body) in sorted(desired.items(), key=lambda kv: kv[1][0].name):
        if cid not in owned:
            rows.append({"correlation": corr.name, "deployed": False})
            continue
        mid, cur = owned[cid]
        marker = A.marker_of(cur)
        active, n_active = alerts_for(client, mid, "ACTIVE")
        _all, n_all = alerts_for(client, mid, "ALL", size=1)
        rows.append({
            "correlation": corr.name, "deployed": True, "monitor_id": mid, "enabled": cur.get("enabled"),
            "pack_version": marker.get("pack_version"),
            "in_sync": marker.get("content_hash") == A.marker_of(body)["content_hash"],
            "active_alerts": n_active, "total_alerts": n_all,
            "active_keys": [a.get("agg_alert_content", {}).get("bucket_keys") for a in active][:20],
        })
    extra = [{"correlation": A.marker_of(cur).get("correlation_name") or cid, "monitor_id": mid,
              "note": "pack-owned monitor not in current content"} for cid, (mid, cur) in owned.items()
             if cid not in desired]
    return rows, extra, foreign


def preflight(client, correlations, profile, settings_fn):
    """Prerequisite checks. Returns list of (level, message)."""
    from . import query as Q
    out = []
    try:
        root = client.get("/")
        out.append(("ok", "indexer reachable: %s %s" % (root.get("version", {}).get("distribution", "opensearch"),
                                                        root.get("version", {}).get("number"))))
    except ApiError as e:
        out.append(("error", "indexer not reachable or not authorised: %s" % e))
        return out
    try:
        plugins = client.get("/_cat/plugins", params={"format": "json"})
        names = sorted({p.get("component") for p in plugins})
        need = [n for n in names if "alerting" in n]
        out.append(("ok" if need else "error", "alerting plugin: %s" % (", ".join(need) or "NOT INSTALLED")))
    except ApiError as e:
        out.append(("warn", "cannot list plugins (%s); continuing" % e.status))
    try:
        st = client.get("/_cluster/settings", params={"include_defaults": "true", "flat_settings": "true"})
        val = None
        for scope in ("transient", "persistent", "defaults"):
            val = val if val is not None else (st.get(scope) or {}).get("plugins.alerting.alert_history_enabled")
        if str(val).lower() == "false":
            out.append(("warn", "plugins.alerting.alert_history_enabled is false: resolved (COMPLETED) alerts are "
                                "deleted and disappear from Alerting > Alerts; enable it to keep alert history"))
        else:
            out.append(("ok", "alert history enabled"))
    except ApiError as e:
        out.append(("warn", "cannot read cluster settings (%s); alert history state unknown" % e.status))
    try:
        client.post(MONITORS + "/_search", {"size": 0, "query": {"match_all": {}}})
        out.append(("ok", "alerting monitor search permitted"))
    except ApiError as e:
        out.append(("error", "alerting API not usable by this user: %s" % e))
    for corr in correlations:
        s = settings_fn(profile, corr.name)
        idx = ",".join(s["indices"])
        from . import identity as IDN
        virt = IDN.get(corr.value_field) if IDN.is_virtual(corr.value_field) else None
        value_fields = set(virt.required) if virt else ({corr.value_field} if corr.value_field else set())
        fields = sorted(set(corr.group_by) | {s["timestamp_field"]} | value_fields
                        | set().union(*[r.fields() for r in corr.rules]))
        try:
            fm = client.get("/%s/_mapping/field/%s" % (idx, ",".join(fields)))
        except ApiError as e:
            out.append(("error", "%s: cannot read mappings of %s: %s" % (corr.name, idx, e)))
            continue
        if not fm:
            out.append(("error", "%s: no index matches %s" % (corr.name, idx)))
            continue
        types = {}
        for _ix, m in fm.items():
            for f, spec in (m.get("mappings") or {}).items():
                for _leaf, d in (spec.get("mapping") or {}).items():
                    types.setdefault(f, set()).add(d.get("type"))
        if virt:
            try:
                om = client.get("/%s/_mapping/field/%s" % (idx, ",".join(virt.optional)))
                seen = {f for m in om.values() for f in (m.get("mappings") or {})}
            except ApiError:
                seen = set()
            missing = [f for f in virt.optional if f not in seen]
            if missing:
                out.append(("warn", "%s: %s uses optional field(s) not mapped yet in %s: %s (mapped on first "
                                    "use; until then the realm falls back as documented)" % (
                                        corr.name, virt.name, idx, ", ".join(missing))))
        for f in fields:
            t = types.get(f)
            if not t:
                out.append(("error", "%s: field %s is not mapped in %s" % (corr.name, f, idx)))
            elif t - {"keyword", "ip", "date", "date_nanos", "long", "integer", "boolean", "constant_keyword"}:
                out.append(("warn", "%s: field %s has type(s) %s; exact matching expects keyword/ip"
                            % (corr.name, f, sorted(t))))
        q = {"size": 0, "track_total_hits": True, "query": {"bool": {"filter": [
            Q.correlation_selection(corr),
            {"range": {s["timestamp_field"]: {"gte": "now-7d"}}}]}}}
        try:
            r = client.post("/%s/_search" % idx, q)
            n = r["hits"]["total"]["value"]
            out.append(("ok" if n else "warn", "%s: %d matching event(s) in the last 7 days%s" % (
                corr.name, n, "" if n else " (is the source collected and the stock integration enabled?)")))
        except ApiError as e:
            out.append(("error", "%s: selection query failed: %s" % (corr.name, e)))
    return out
