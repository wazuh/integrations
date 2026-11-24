"""Behavioural test harness: drive the lab, observe the indexer and the Alerting scheduler.

Only alerts created by the Alerting scheduler (read back through
``GET _plugins/_alerting/monitors/alerts``) count as detections here; a search
query returning the right numbers is not treated as proof that the monitor works.
"""

import datetime
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, PACK)
sys.path.insert(0, os.path.join(PACK, "tests", "lab"))

from wcp import alerting as A  # noqa: E402
from wcp import config as C  # noqa: E402
from wcp import deploy as D  # noqa: E402
from wcp import sigma as S  # noqa: E402
from wcp.client import DEFAULT_ENV_FILE, Client, load_env_file  # noqa: E402

EVENTS = "/wazuh-events-v5-system-activity/_search"


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Observer(object):
    def __init__(self, state_dir=None):
        load_env_file(os.environ.get("WCP_ENV_FILE", DEFAULT_ENV_FILE))
        self.client = Client()
        _r, self.correlations = S.load_content(PACK)
        self.profile = C.load_profile(os.path.join(PACK, "pack.yml"))
        state_dir = state_dir or C.default_state_dir()
        target = os.environ.get("WCP_TARGET") or "%s_%s" % (self.client.host, self.client.port)
        self.manifest = D.Manifest(os.path.join(state_dir, "%s.manifest.json" % target), target)
        self.refresh_monitors()

    def refresh_monitors(self):
        owned, _f = D.list_owned_monitors(self.client, self.manifest.monitor_ids())
        owned.pop("__duplicates__", None)
        self.monitors = {}
        for c in self.correlations:
            if c.id in owned:
                self.monitors[c.name] = owned[c.id][0]

    def corr(self, name):
        return [c for c in self.correlations if c.name == name][0]

    # ------------------------------------------------------------- events
    def count_events(self, filters):
        r = self.client.post(EVENTS, {"size": 0, "track_total_hits": True, "query": {"bool": {"filter": filters}}})
        return r["hits"]["total"]["value"]

    def wait_events(self, filters, expected, timeout=180, poll=2):
        """Wait until at least ``expected`` events match; returns (count, seconds_waited)."""
        t0 = time.time()
        n = 0
        while time.time() - t0 < timeout:
            n = self.count_events(filters)
            if n >= expected:
                return n, round(time.time() - t0, 1)
            time.sleep(poll)
        return n, None

    def events(self, filters, size=500, fields=None):
        body = {"size": size, "sort": [{"event.start": "asc"}, {"@timestamp": "asc"}],
                "query": {"bool": {"filter": filters}}}
        if fields:
            body["_source"] = fields
        return [h["_source"] for h in self.client.post(EVENTS, body)["hits"]["hits"]]

    # ------------------------------------------------------------- alerts
    def alerts(self, corr_name, keys=None, state="ALL"):
        mid = self.monitors[corr_name]
        res = self.client.get(D.MONITORS + "/alerts", params={
            "monitorId": mid, "alertState": state, "size": 500, "sortString": "start_time", "sortOrder": "asc"})
        out = []
        for a in res.get("alerts", []):
            bk = (a.get("agg_alert_content") or {}).get("bucket_keys")
            if keys is not None and bk != list(keys):
                continue
            out.append(a)
        return out

    def wait_alert(self, corr_name, keys, state="ACTIVE", timeout=300, poll=5, since=None, not_ids=()):
        """Wait for an alert of the group in ``state``; returns (alert or None, seconds_waited)."""
        t0 = time.time()
        while time.time() - t0 < timeout:
            for a in self.alerts(corr_name, keys):
                if a["state"] != state or a["id"] in not_ids:
                    continue
                if since and a.get("start_time", 0) < since:
                    continue
                return a, round(time.time() - t0, 1)
            time.sleep(poll)
        return None, None

    def monitor_runs(self, corr_name):
        """Last run time of the monitor (from the monitor document)."""
        m = self.client.get(D.MONITORS + "/" + self.monitors[corr_name])["monitor"]
        return m.get("last_update_time"), m.get("enabled_time")


def summarize_alert(a):
    if not a:
        return None
    agg = a.get("agg_alert_content") or {}
    bucket = agg.get("bucket") or {}
    detail = (bucket.get(A.DETAIL_AGG) or {}).get("value")
    return {
        "id": a.get("id"), "state": a.get("state"), "severity": a.get("severity"),
        "bucket_keys": agg.get("bucket_keys"),
        "start_time": ms_iso(a.get("start_time")), "end_time": ms_iso(a.get("end_time")),
        "last_notification_time": ms_iso(a.get("last_notification_time")),
        "acknowledged_time": ms_iso(a.get("acknowledged_time")),
        "doc_count": bucket.get("doc_count"),
        "detail": detail,
        "trigger_name": a.get("trigger_name"),
    }


def ms_iso(v):
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return iso(datetime.datetime.fromtimestamp(v / 1000.0, datetime.timezone.utc))
    return v


class Evidence(object):
    def __init__(self, run_dir, name, layer):
        self.path = os.path.join(run_dir, "%s.json" % name)
        os.makedirs(run_dir, exist_ok=True)
        self.d = {"scenario": name, "layer": layer, "started": iso(utcnow()), "inputs": [], "expected": {},
                  "observed": {}, "timings_s": {}, "checks": [], "verdict": None}

    def check(self, label, ok, detail=None):
        self.d["checks"].append({"check": label, "pass": bool(ok), "detail": detail})
        print("   [%s] %s%s" % ("PASS" if ok else "FAIL", label, (" -- %s" % detail) if detail is not None else ""))
        return ok

    def save(self):
        self.d["finished"] = iso(utcnow())
        self.d["verdict"] = "PASS" if self.d["checks"] and all(c["pass"] for c in self.d["checks"]) else "FAIL"
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(self.d, fh, indent=2, sort_keys=True, default=str)
        print("== %s: %s (%s)" % (self.d["scenario"], self.d["verdict"], self.path))
        return self.d["verdict"]
