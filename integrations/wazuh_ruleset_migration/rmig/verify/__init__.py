"""``verify``.

Re-injects the original log of 4.14 alerts of migrated rules and reports, per
rule, ``REPRODUCED`` / ``NOT_REPRODUCED`` / ``SILENCED`` / ``NOT_SILENCED`` /
``NO_SAMPLE``, the parity of the mapped fields and the oracle that backs each
result:

* logtest (default): ``POST /logtest`` in ``test`` for integrations with their
  own decoders; for rules over stock events, ``/logtest/normalization`` in
  ``standard`` and ``/logtest/detection`` in ``test``;
* ``--via-detector``: on a sample, index the normalized event in an index of
  the tool's own, run a temporary detector of the tool's own over it
  (``_plugins/_alerting/monitors/{id}/_execute``), read the findings, clean up.

``--engine-socket`` (no indexer, :mod:`.offline`): the events run through a
5.x engine on its unix socket and the strict local Sigma reader
(:func:`.sigma.verdict`) gives the rule verdict, ``NOT_CHECKED`` where it does
not cover the rule. Results go to ``verification-offline.{md,json}``, labelled
``offline engine``; ``state.json`` and ``verification.json`` are not touched, so
an offline result never unlocks ``activate``.

Exit code 1 when a rule is ``NOT_REPRODUCED`` or ``NOT_SILENCED``.
"""

import json
import os
import time

from .. import __version__
from ..api.client import ApiError
from ..api.content import BASE
from ..api.shared_root import load_out
from ..api.state import State, now
from ..fsutil import read_text
from ..jsonio import read_json, write_json, write_text
from ..textsafe import md
from ..translate.meta import PREFIX as KEY_PREFIX, is_slug
from .alerts import original_log, read_alerts, rule_id, sort_key
from .sigma import evaluate, flatten, verdict

REPRODUCED = "REPRODUCED"
NOT_REPRODUCED = "NOT_REPRODUCED"
SILENCED = "SILENCED"
NOT_SILENCED = "NOT_SILENCED"
NO_SAMPLE = "NO_SAMPLE"
NOT_CHECKED = "NOT_CHECKED"  # --engine-socket only
RESULTS = (REPRODUCED, NOT_REPRODUCED, SILENCED, NOT_SILENCED, NO_SAMPLE)
OFFLINE_RESULTS = RESULTS + (NOT_CHECKED,)
OFFLINE_ORACLE = "offline engine"
FAILURES = (NOT_REPRODUCED, NOT_SILENCED)
DEFAULT_LIMIT = 20
DETECTOR_SAMPLE = 5
LONG_MESSAGE = 4096
QUEUE = 1  # the queue id of log lines read from files (localfile), as the manager sends them to the engine
SAMPLE_LOCATION = "rmig-sample"
# Security Analytics only creates detectors on `wazuh-events-v5` data sources (400 otherwise, 5.0.0-rc1). The
# name stays outside every category pattern (wazuh-events-v5-<category>*) so no standard detector reads these
# temporary documents.
VERIFY_PREFIX = "wazuh-events-v5-rmig-verify-"
_INDEX_FORBIDDEN = set('\\/*?"<>| ,#:')


def verify_index(key):
    """The temporary index of ``verify --via-detector`` for the integration ``key``, or None when ``key`` is not
    a key the tool makes (``wazuh4-<slug>``) or the name breaks the index name rules (lower case, none of
    backslash ``/ * ? " < > | , # :`` or space, no leading ``_ - +``, at most 255 bytes). A wildcard or a list of
    indices can never come out of it."""
    if not isinstance(key, str) or not key.startswith(KEY_PREFIX) or not is_slug(key[len(KEY_PREFIX):]):
        return None
    index = VERIFY_PREFIX + key
    if (index != index.lower() or set(index) & _INDEX_FORBIDDEN or index[0] in "_-+"
            or index in (".", "..") or len(index.encode("utf-8")) > 255):
        return None
    return index
SAP = "/_plugins/_security_analytics"
ALERTING = "/_plugins/_alerting"
FINDINGS_INDEX = "wazuh-findings-v5-*"
FINDINGS_POLLS = 5
FINDINGS_WAIT = 2


def _id_key(rid):
    return (0, int(rid)) if str(rid).isdigit() else (1, str(rid))


class Verify:
    def __init__(self, runner, alert_files, samples_dir=None, via_detector=False, limit=None, include_events=False,
                 offline=None):
        self.r = runner
        self.client = runner.client
        self.offline = offline  # an offline.OfflineEngine: verify --engine-socket
        self.alert_files = alert_files
        self.samples_dir = samples_dir
        self.via_detector = via_detector
        self.limit = limit or DEFAULT_LIMIT
        self.include_events = include_events

    # -- inputs -------------------------------------------------------------------
    def load(self):
        self.state = State.load(self.r.workdir)
        self.out = load_out(self.r.out_dir, self.state)
        if getattr(self.out, "share_error", None):
            self.r.say("verify: warning: %s" % self.out.share_error)
        self.rules = {}
        for integ in self.out.integrations:
            for res in integ.rules:
                rid = str(res.source.get("id") or "")
                if not rid:
                    continue
                e = self.state.get(res.local_id) or {}
                self.rules[rid] = {"rule_id_4x": rid, "local_id": res.local_id, "title": res.title,
                                   "integration": integ, "detection": res.resource.get("detection") or {},
                                   "server_id": e.get("server_id"), "space": e.get("space")}
        self.silencers = self._silencers()
        self.decisions = {}
        dpath = self.r.paths["decisions"]
        if os.path.isfile(dpath):
            self.decisions = read_json(dpath).get("fields", {})

    def _silencers(self):
        """``{silencer 4.x id: [4.x ids it silences]}`` from ``work/plan.json``
        (``RM-R-SILENCER``, ``exclusion_targets``)."""
        out = {}
        ppath = self.r.paths["plan"]
        if not os.path.isfile(ppath):
            return out
        items = read_json(ppath).get("items") or []
        by_uid = {it["uid"]: it for it in items}
        for it in items:
            if it.get("kind") != "rule" or not any(c.get("code") == "RM-R-SILENCER" for c in it.get("codes") or []):
                continue
            sid = it["ref"].partition(":")[2]
            targets = []
            for uid in it.get("exclusion_targets") or []:
                t = by_uid.get(uid)
                if t:
                    targets.append(t["ref"].partition(":")[2])
            out[sid] = sorted(set(targets), key=_id_key)
        return out

    def samples(self):
        alerts, problems = read_alerts(self.alert_files)
        self.problems = problems
        wanted = set(self.rules) | set(self.silencers)
        per = {}
        self.skipped = {}
        for a in alerts:
            rid = rule_id(a)
            if rid not in wanted:
                continue
            log, why = original_log(a)
            if log is None:
                self.skipped.setdefault(rid, []).append(why)
                continue
            per.setdefault(rid, []).append(a)
        out = {}
        for rid in wanted:
            chosen = sorted(per.get(rid, []), key=sort_key)[:self.limit]
            evs = [{"source": "alert", "alert_id": a.get("id"), "timestamp": a.get("timestamp"),
                    "location": a.get("location") or SAMPLE_LOCATION, "event": a["full_log"], "data": a.get("data") or {}}
                   for a in chosen]
            if self.samples_dir:
                spath = os.path.join(self.samples_dir, "%s.log" % rid)
                if os.path.isfile(spath):
                    for n, line in enumerate(read_text(spath).split("\n"), 1):
                        if line.strip() and len(evs) < self.limit:
                            evs.append({"source": "%s:%d" % (spath, n), "alert_id": None, "timestamp": None,
                                        "location": SAMPLE_LOCATION, "event": line, "data": {}})
            out[rid] = evs
        return out

    # -- oracles ------------------------------------------------------------------
    def integration_id(self, integ):
        e = self.state.get(integ.me.local_id) or {}
        if e.get("space") in ("test", "custom") and integ.key not in (self.state.data.get("set_aside") or {}):
            return e.get("server_id")
        return None

    def logtest(self, integ, ev):
        """``(normalized output, [matched rule titles], [matched rule ids])``."""
        iid = self.integration_id(integ)
        if integ.kind == "on-stock":
            norm = self.client.request("POST", BASE + "/logtest/normalization", {
                "space": "standard", "queue": QUEUE, "location": ev["location"], "event": ev["event"],
                "trace_level": "NONE"})
            output = ((norm.get("message") or {}).get("output")) or {}
            det = self.client.request("POST", BASE + "/logtest/detection", {
                "space": "test", "integration": iid, "input": output})
            detection = det.get("message") or {}
        else:
            res = self.client.request("POST", BASE + "/logtest", {
                "space": "test", "integration": iid, "queue": QUEUE, "location": ev["location"],
                "event": ev["event"], "trace_level": "NONE"})
            msg = res.get("message") or {}
            output = (msg.get("normalization") or {}).get("output") or {}
            detection = msg.get("detection") or {}
        titles, ids = [], []
        for m in detection.get("matches") or []:
            rule = m.get("rule") or {}
            titles.append(rule.get("title"))
            ids.append(rule.get("id"))
        return output, titles, ids

    @staticmethod
    def matched(rule, titles, ids):
        return rule["title"] in titles or (rule.get("server_id") and rule["server_id"] in ids)

    def parity(self, ev, output):
        flat_out = flatten(output)
        flat_data = flatten(ev.get("data") or {})
        res = {}
        for k, v in sorted(flat_data.items()):
            d = self.decisions.get(k)
            if not d or d.get("action") != "map" or not d.get("wcs"):
                continue
            got = flat_out.get(d["wcs"])
            if got is None:
                res[k] = ("absent", d["wcs"])
            elif str(got) == str(v) or (isinstance(got, list) and str(v) in [str(x) for x in got]):
                res[k] = ("equal", d["wcs"])
            else:
                res[k] = ("different", d["wcs"])
        return res

    # -- run ----------------------------------------------------------------------
    def run(self):
        if self.offline is not None:
            return self.run_offline()
        self.load()
        samples = self.samples()
        titles_all = {r["title"]: rid for rid, r in self.rules.items()}
        results = []
        detector_jobs = {}
        for rid in sorted(set(self.rules) | set(self.silencers), key=_id_key):
            evs = samples.get(rid, [])
            if rid in self.silencers and rid not in self.rules:
                results.append(self.run_silencer(rid, evs))
                continue
            rule = self.rules[rid]
            integ = rule["integration"]
            entry = {"rule_id_4x": rid, "title": rule["title"], "integration": integ.key,
                     "oracle": "logtest (normalization: standard, detection: test)" if integ.kind == "on-stock"
                     else "logtest (test)", "samples": len(evs), "matched": 0, "not_met": [], "shadowing": [],
                     "field_parity": {}, "codes": [], "events": []}
            if not evs:
                entry["result"] = NO_SAMPLE
                why = sorted(set(self.skipped.get(rid, [])))
                entry["not_met"] = why or ["no 4.14 alert of this rule in the files given, and no samples/%s.log" % rid]
                results.append(entry)
                continue
            if self.integration_id(integ) is None or rule.get("space") not in ("test", "custom"):
                entry["result"] = NOT_REPRODUCED
                entry["not_met"] = ["the rule is not in the test space: run apply (or its integration was set aside)"]
                results.append(entry)
                continue
            shadow = set()
            for ev in evs:
                if len(ev["event"].encode("utf-8")) > LONG_MESSAGE and "RM-R-LONG-MESSAGE" not in entry["codes"]:
                    entry["codes"].append("RM-R-LONG-MESSAGE")
                output, titles, ids = self.logtest(integ, ev)
                ok = self.matched(rule, titles, ids)
                entry["matched"] += 1 if ok else 0
                why = [] if ok else (evaluate(rule["detection"], output)[1] or ["the server reported no match"])
                for w in why:
                    if w not in entry["not_met"]:
                        entry["not_met"].append(w)
                for t in titles:
                    if t != rule["title"] and t in titles_all:
                        shadow.add(titles_all[t])
                for field, (verdict, wcs) in self.parity(ev, output).items():
                    fp = entry["field_parity"].setdefault(field, {"wcs": wcs, "equal": 0, "different": 0, "absent": 0})
                    fp[verdict] += 1
                entry["events"].append({"source": ev["source"], "alert_id": ev["alert_id"], "timestamp": ev["timestamp"],
                                        "location": ev["location"], "event": ev["event"], "matched": ok,
                                        "normalized": output})
                if self.via_detector and len(detector_jobs.setdefault(integ.key, {}).setdefault(rid, [])) < min(DETECTOR_SAMPLE, self.limit):
                    detector_jobs[integ.key][rid].append(output)
            entry["shadowing"] = sorted(shadow, key=_id_key)
            if entry["shadowing"]:
                entry["codes"].append("RM-R-SHADOWING")
            entry["result"] = REPRODUCED if entry["matched"] == len(evs) else NOT_REPRODUCED
            results.append(entry)
        if self.via_detector:
            self.run_detector(detector_jobs, {e["rule_id_4x"]: e for e in results})
        return self.write(results)

    def run_silencer(self, rid, evs):
        targets = [t for t in self.silencers[rid] if t in self.rules]
        entry = {"rule_id_4x": rid, "title": None, "integration": None, "oracle": "logtest (test)",
                 "samples": len(evs), "matched": 0, "not_met": [], "shadowing": [], "field_parity": {},
                 "codes": [], "events": [], "silences": targets}
        if not evs:
            entry["result"] = NO_SAMPLE
            entry["not_met"] = ["a level 0 rule has no alerts: give its lines in samples/%s.log" % rid]
            return entry
        if not targets:
            entry["result"] = NO_SAMPLE
            entry["not_met"] = ["the rules it silences are not migrated (work/plan.json)"]
            return entry
        fired = set()
        for ev in evs:
            hit = []
            for integ in sorted({self.rules[t]["integration"].key: self.rules[t]["integration"] for t in targets}.values(),
                                key=lambda i: i.key):
                if self.integration_id(integ) is None:
                    entry["not_met"].append("integration %s is not in the test space" % integ.key)
                    continue
                entry["integration"] = entry["integration"] or integ.key
                if integ.kind == "on-stock":
                    entry["oracle"] = "logtest (normalization: standard, detection: test)"
                _out, titles, ids = self.logtest(integ, ev)
                hit.extend(t for t in targets if self.rules[t]["integration"].key == integ.key
                           and self.matched(self.rules[t], titles, ids))
            fired.update(hit)
            entry["events"].append({"source": ev["source"], "alert_id": ev["alert_id"], "timestamp": ev["timestamp"],
                                    "location": ev["location"], "event": ev["event"], "fired": sorted(set(hit), key=_id_key)})
        if fired:
            entry["result"] = NOT_SILENCED
            entry["not_met"].append("rule(s) %s still fire on the silencer's samples" % ", ".join(sorted(fired, key=_id_key)))
        elif entry["not_met"]:
            entry["result"] = NOT_SILENCED
        else:
            entry["result"] = SILENCED
        return entry

    # -- offline engine (--engine-socket) ------------------------------------------------
    def run_offline(self):
        from .offline import enrichment_gap

        self.load()
        samples = self.samples()
        eng = self.offline
        wanted = set(self.rules) | set(self.silencers)
        on_stock = set()  # one entry per kind of integration that has samples to run: True for on-stock
        for rid in wanted:
            if not samples.get(rid):
                continue
            targets = [rid] if rid in self.rules else [t for t in self.silencers.get(rid, []) if t in self.rules]
            on_stock.update(self.rules[t]["integration"].kind == "on-stock" for t in targets)
        try:
            eng.prepare(self.out, need_tool=False in on_stock, need_stock=True in on_stock)
            results = []
            for rid in sorted(wanted, key=_id_key):
                evs = samples.get(rid, [])
                if rid in self.silencers and rid not in self.rules:
                    results.append(self.offline_silencer(rid, evs))
                    continue
                rule = self.rules[rid]
                integ = rule["integration"]
                entry = {"rule_id_4x": rid, "title": rule["title"], "integration": integ.key,
                         "oracle": eng.oracle(integ), "samples": len(evs), "matched": 0, "not_met": [],
                         "shadowing": [], "field_parity": {}, "codes": [], "events": []}
                results.append(entry)
                if not evs:
                    entry["result"] = NO_SAMPLE
                    why = sorted(set(self.skipped.get(rid, [])))
                    entry["not_met"] = why or ["no 4.14 alert of this rule in the files given, and no samples/%s.log" % rid]
                    continue
                stop = eng.blocked(integ)
                gap = enrichment_gap(rule["detection"], eng.ioc)
                if stop or gap:
                    entry["result"], why = stop or (NOT_CHECKED, gap)
                    entry["not_met"] = [why]
                    continue
                siblings = {o: r for o, r in self.rules.items() if o != rid and r["integration"].key == integ.key}
                shadow, verdicts = set(), []
                for ev in evs:
                    if len(ev["event"].encode("utf-8")) > LONG_MESSAGE and "RM-R-LONG-MESSAGE" not in entry["codes"]:
                        entry["codes"].append("RM-R-LONG-MESSAGE")
                    output, err = eng.logtest(integ, ev)
                    if err:
                        ok, notes = None, [err]
                    else:
                        ok, notes = verdict(rule["detection"], output)
                        for o, other in siblings.items():
                            if verdict(other["detection"], output)[0] is True:
                                shadow.add(o)
                        for field, (v, wcs) in self.parity(ev, output).items():
                            fp = entry["field_parity"].setdefault(field, {"wcs": wcs, "equal": 0, "different": 0,
                                                                          "absent": 0})
                            fp[v] += 1
                    verdicts.append(ok)
                    entry["matched"] += 1 if ok is True else 0
                    for w in ([] if ok is True else notes or ["no match"]):
                        w = ("not checked: %s" % w) if ok is None else w
                        if w not in entry["not_met"]:
                            entry["not_met"].append(w)
                    entry["events"].append({"source": ev["source"], "alert_id": ev["alert_id"],
                                            "timestamp": ev["timestamp"], "location": ev["location"],
                                            "event": ev["event"], "matched": ok, "normalized": output})
                entry["shadowing"] = sorted(shadow, key=_id_key)
                if entry["shadowing"]:
                    entry["codes"].append("RM-R-SHADOWING")
                entry["result"] = (NOT_REPRODUCED if False in verdicts else
                                   NOT_CHECKED if None in verdicts else REPRODUCED)
        finally:
            eng.close()
        for e in results:
            if e["result"] == NOT_CHECKED:
                e["codes"].append("RM-R-NOT-CHECKED")
        return self.write_offline(results)

    def offline_silencer(self, rid, evs):
        eng = self.offline
        targets = [t for t in self.silencers[rid] if t in self.rules]
        entry = {"rule_id_4x": rid, "title": None, "integration": None, "oracle": "offline engine",
                 "samples": len(evs), "matched": 0, "not_met": [], "shadowing": [], "field_parity": {},
                 "codes": [], "events": [], "silences": targets}
        if not evs:
            entry["result"] = NO_SAMPLE
            entry["not_met"] = ["a level 0 rule has no alerts: give its lines in samples/%s.log" % rid]
            return entry
        if not targets:
            entry["result"] = NO_SAMPLE
            entry["not_met"] = ["the rules it silences are not migrated (work/plan.json)"]
            return entry
        fired, unknown, failed = set(), [], []
        integs = sorted({self.rules[t]["integration"].key: self.rules[t]["integration"] for t in targets}.values(),
                        key=lambda i: i.key)
        for ev in evs:
            hit = []
            for integ in integs:
                entry["integration"] = entry["integration"] or integ.key
                entry["oracle"] = eng.oracle(integ)
                stop = eng.blocked(integ)
                if stop:
                    (failed if stop[0] == NOT_REPRODUCED else unknown).append(stop[1])
                    continue
                output, err = eng.logtest(integ, ev)
                if err:
                    unknown.append(err)
                    continue
                for t in targets:
                    if self.rules[t]["integration"].key != integ.key:
                        continue
                    ok, notes = verdict(self.rules[t]["detection"], output)
                    if ok is True:
                        hit.append(t)
                    elif ok is None:
                        unknown.append("rule %s: %s" % (t, "; ".join(notes)))
            fired.update(hit)
            entry["events"].append({"source": ev["source"], "alert_id": ev["alert_id"], "timestamp": ev["timestamp"],
                                    "location": ev["location"], "event": ev["event"],
                                    "fired": sorted(set(hit), key=_id_key)})
        for w in failed:
            if w not in entry["not_met"]:
                entry["not_met"].append(w)
        if fired:
            entry["result"] = NOT_SILENCED
            entry["not_met"].append("rule(s) %s still fire on the silencer's samples" % ", ".join(sorted(fired, key=_id_key)))
        elif failed:
            entry["result"] = NOT_SILENCED
        elif unknown:
            entry["result"] = NOT_CHECKED
            for w in unknown:
                w = "not checked: %s" % w
                if w not in entry["not_met"]:
                    entry["not_met"].append(w)
        else:
            entry["result"] = SILENCED
        return entry

    def write_offline(self, results):
        summary = {r: sum(1 for e in results if e["result"] == r) for r in OFFLINE_RESULTS}
        summary["rules"] = len(results)
        summary["failures"] = summary[NOT_REPRODUCED] + summary[NOT_SILENCED]
        eng = self.offline
        doc = {
            "version": 1,
            "tool": "rmig %s" % __version__,
            "when": now(),
            "alerts": list(self.alert_files),
            "samples_dir": self.samples_dir,
            "limit": self.limit,
            "oracles": {"default": OFFLINE_ORACLE, "via_detector": False,
                        "engine_socket": eng.client.socket_path,
                        "catalog": eng.catalog.label() if eng.catalog is not None else None},
            # an offline result is never a verification of what is applied: activate reads verification.json only
            "state_fingerprint": None,
            "summary": summary,
            "unreadable_lines": self.problems[:100],
            "rules": results,
        }
        write_json(self.r.paths["verification_offline_json"], doc)
        write_text(self.r.paths["verification_offline_md"], render(doc, self.include_events))
        self.r.say("verify (offline engine): " + ", ".join("%s %d" % (k, summary[k]) for k in OFFLINE_RESULTS))
        return 1 if summary["failures"] else 0

    # -- detector path ---------------------------------------------------------------
    def run_detector(self, jobs, by_rule):
        for key in sorted(jobs):
            integ = self.out.integration(key)
            rules = {rid: self.rules[rid] for rid in jobs[key] if jobs[key][rid]}
            if not rules:
                continue
            index = verify_index(key)
            if index is None:
                msg = "the integration key %r cannot name a temporary index: the detector path is skipped" % key
                for rid in rules:
                    by_rule[rid]["detector"] = {"error": msg}
                    by_rule[rid]["not_met"].append("detector path failed: %s" % msg)
                self.r.say("verify: %s" % msg)
                continue
            name = VERIFY_PREFIX + key
            det_id = None
            created = False  # DELETE only an index this run created: the PUT answered 2xx, so it did not exist
            try:
                # A document-level monitor only reads documents indexed after it starts (its sequence number
                # checkpoint): create the index and the detector first, then index the samples, then run it.
                # The samples need the field types of the real events index (keyword, not analyzed text), or
                # a term or a whole-term regexp never matches: copy the mapping of the category's data stream.
                path = "/%s" % index
                self.r.say("PUT %s  (temporary index of the detector path)" % path)
                status, res = self.client.call("PUT", path, {"mappings": self.events_mapping(integ)})
                if status >= 300:
                    raise ApiError("PUT", path, status, res)
                created = True
                body = {"type": "detector", "detector_type": integ.title, "name": name, "enabled": True,
                        "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
                        "inputs": [{"detector_input": {"description": "rmig verify (temporary)", "indices": [index],
                                                       "custom_rules": [{"id": r["server_id"]} for r in rules.values()],
                                                       "pre_packaged_rules": []}}],
                        "triggers": []}
                res = self.r.write("POST", SAP + "/detectors", body, "temporary detector %s" % name)
                det_id = res.get("_id")
                cfg = self.client.request("GET", "/.opensearch-sap-detectors-config/_doc/%s" % det_id)
                monitors = (((cfg.get("_source") or {}).get("detector") or {}).get("monitor_id")) or []
                docs = {}
                for rid, outputs in sorted(rules.items()):
                    for output in jobs[key][rid]:
                        doc = dict(output)
                        doc.setdefault("@timestamp", now())
                        res = self.r.write("POST", "/%s/_doc" % index, doc, "index a normalized sample of rule %s" % rid)
                        docs.setdefault(rid, []).append(res.get("_id"))
                self.client.request("POST", "/%s/_refresh" % index)
                hits = {}
                for mid in monitors:
                    run = self.r.write("POST", "%s/monitors/%s/_execute" % (ALERTING, mid), None,
                                       "run the detector monitor")
                    for did, titles in _execute_matches(run, self.client.request(
                            "GET", "%s/monitors/%s" % (ALERTING, mid))).items():
                        hits.setdefault(did, set()).update(titles)
                if not hits:
                    # an older Alerting without per-query results in _execute: fall back to the findings index
                    hits = self.read_findings(integ.title, [d for ids in docs.values() for d in ids])
                for rid, ids in docs.items():
                    rule = rules[rid]
                    n = sum(1 for d in ids if rule["title"] in hits.get(d, set()) or rule["server_id"] in hits.get(d, set()))
                    e = by_rule[rid]
                    logtest_rate = e["matched"] / e["samples"] if e["samples"] else 0
                    e["detector"] = {"samples": len(ids), "matched": n,
                                     "differs_from_logtest": (n == len(ids)) != (logtest_rate == 1.0)}
                    e["oracle"] += " + detector (%d sample(s))" % len(ids)
            except ApiError as exc:
                # The detector path is a second oracle: its failure is reported per rule and does not discard
                # the logtest results. Security Analytics only builds detectors from rules in the custom space,
                # so before `activate` this path is expected to fail (5.0.0-rc1).
                msg = _reason(exc)
                for rid in rules:
                    by_rule[rid]["detector"] = {"error": msg}
                    by_rule[rid]["not_met"].append("detector path failed: %s" % msg)
                self.r.say("verify: the detector path failed for %s: %s" % (key, msg))
            finally:
                if det_id:
                    self.client.call("DELETE", "%s/detectors/%s" % (SAP, det_id))
                if created:
                    self.r.say("DELETE /%s  (temporary index of the detector path)" % index)
                    self.client.call("DELETE", "/%s" % index)

    def events_mapping(self, integ):
        """The mapping of ``wazuh-events-v5-<category>`` without its data stream parts; ``{}`` if unreadable."""
        category = getattr(integ, "category", None) or (getattr(integ, "resource", None) or {}).get("category")
        status, res = self.client.call("GET", "/wazuh-events-v5-%s/_mapping" % category)
        if status >= 300 or not isinstance(res, dict) or not res:
            return {}
        mapping = dict(next(iter(res.values())).get("mappings") or {})
        mapping.pop("_data_stream_timestamp", None)
        return mapping

    def read_findings(self, integration_title, doc_ids):
        """``{event doc id: {rule titles}}`` from the enriched findings
        (``wazuh-findings-v5-*``: ``event.doc_id`` and ``wazuh.rule.title``,
        as observed against a live 5.0.0-rc1 indexer).
        Findings are written asynchronously: read again a few times until every
        sample has one or the attempts run out."""
        hits = {}
        body = {"size": 1000, "query": {"bool": {"must": [
            {"term": {"wazuh.integration.name": integration_title}},
            {"terms": {"event.doc_id": sorted(doc_ids)}}]}}}
        for attempt in range(FINDINGS_POLLS):
            self.client.call("POST", "/%s/_refresh" % FINDINGS_INDEX)
            status, res = self.client.call("POST", "/%s/_search" % FINDINGS_INDEX, body)
            if status < 300:
                for h in (res.get("hits") or {}).get("hits") or []:
                    src = h.get("_source") or {}
                    did = (src.get("event") or {}).get("doc_id")
                    rule = ((src.get("wazuh") or {}).get("rule") or {})
                    if did:
                        hits.setdefault(did, set()).update(x for x in (rule.get("title"), rule.get("id")) if x)
            if all(d in hits for d in doc_ids) or attempt == FINDINGS_POLLS - 1:
                break
            time.sleep(FINDINGS_WAIT)
        return hits

    # -- output ---------------------------------------------------------------------
    def write(self, results):
        summary = {r: sum(1 for e in results if e["result"] == r) for r in RESULTS}
        summary["rules"] = len(results)
        summary["failures"] = summary[NOT_REPRODUCED] + summary[NOT_SILENCED]
        doc = {
            "version": 1,
            "tool": "rmig %s" % __version__,
            "when": now(),
            "alerts": list(self.alert_files),
            "samples_dir": self.samples_dir,
            "limit": self.limit,
            "oracles": {"default": "logtest", "via_detector": self.via_detector},
            "state_fingerprint": self.state.fingerprint(),
            "summary": summary,
            "unreadable_lines": self.problems[:100],
            "rules": results,
        }
        if not self.r.dry_run:
            write_json(self.r.paths["verification_json"], doc)
            write_text(self.r.paths["verification_md"], render(doc, self.include_events))
            self.state.data["last_verification"] = {"when": doc["when"], "failures": summary["failures"],
                                                    "fingerprint": doc["state_fingerprint"]}
            self.state.save()
        self.r.say("verify: " + ", ".join("%s %d" % (k, summary[k]) for k in RESULTS))
        return 1 if summary["failures"] else 0


def _esc(s):
    return md(s or "")


def render(doc, include_events=False):
    s = doc["summary"]
    offline = doc["oracles"]["default"] == OFFLINE_ORACLE
    out = ["# Verification" + (" (offline engine)" if offline else ""), ""]
    w = out.append
    if offline:
        w("Run %s with %s. Oracle: **offline engine** for every result: the events ran through the 5.x engine on %s "
          "(no indexer)%s, and the rules were read by the tool's own Sigma reader. `NOT_CHECKED`: the reader does not "
          "cover the rule's form, or its events need content this engine does not have. Samples: the first %d alerts "
          "per rule by (timestamp, id)." % (
              doc["when"], doc["tool"], doc["oracles"]["engine_socket"],
              ", stock decoders from the catalog %s" % doc["oracles"]["catalog"] if doc["oracles"].get("catalog") else "",
              doc["limit"]))
        w("")
        w("This is a check before 5.0 is installed (RM-R-OFFLINE-ENGINE). The final proof is `verify` on the 5.0 "
          "indexer after `apply`; `activate` reads only that verification.")
    else:
        w("Run %s with %s. Oracle: **logtest** for every result%s. Samples: the first %d alerts per rule by (timestamp, id)." % (
            doc["when"], doc["tool"], "; **detector** too where the row says so" if doc["oracles"]["via_detector"] else "",
            doc["limit"]))
    w("")
    w("| Result | Rules |")
    w("|---|---:|")
    for r in OFFLINE_RESULTS if offline else RESULTS:
        w("| `%s` | %d |" % (r, s[r]))
    w("")
    w("| 4.x rule | Result | Oracle | Samples | Matched | Detector | Detail |")
    w("|---|---|---|---:|---:|---|---|")
    for e in doc["rules"]:
        det = e.get("detector")
        if not det:
            dtext = ""
        elif "error" in det:
            dtext = "failed"
        else:
            dtext = "%d/%d%s" % (det["matched"], det["samples"], ", differs from logtest" if det["differs_from_logtest"] else "")
        detail = "; ".join(e.get("not_met") or [])
        if e.get("shadowing"):
            detail += ("; " if detail else "") + "also matched (RM-R-SHADOWING): %s" % ", ".join(e["shadowing"])
        if "RM-R-LONG-MESSAGE" in e.get("codes", []):
            detail += ("; " if detail else "") + "RM-R-LONG-MESSAGE"
        w("| %s | `%s` | %s | %d | %d | %s | %s |" % (e["rule_id_4x"], e["result"], e["oracle"], e["samples"],
                                                     e["matched"], dtext, _esc(detail)[:500]))
    parity = [(e["rule_id_4x"], f, v) for e in doc["rules"] for f, v in sorted(e.get("field_parity", {}).items())]
    if parity:
        w("")
        w("## Field parity")
        w("")
        w("| 4.x rule | 4.x field | WCS field | Equal | Different | Absent |")
        w("|---|---|---|---:|---:|---:|")
        for rid, f, v in parity:
            w("| %s | `%s` | `%s` | %d | %d | %d |" % (rid, f, v["wcs"], v["equal"], v["different"], v["absent"]))
    if include_events:
        w("")
        w("## Events")
        w("")
        for e in doc["rules"]:
            for ev in e.get("events", []):
                w("- %s (%s): `%s`" % (e["rule_id_4x"], ev["source"], _esc(ev["event"])[:2000]))
    else:
        w("")
        w("Events are kept only in verification.json (pass --include-events to list them here).")
    return "\n".join(out) + "\n"

def _reason(exc):
    """The short reason of a Security Analytics or engine error, not its whole JSON body."""
    text = exc.server_message or str(exc)
    try:
        body = json.loads(text)
    except ValueError:
        return text[:300]
    if isinstance(body, dict):
        for k in ("reason", "message"):
            if isinstance(body.get(k), str):
                return body[k][:300]
    return text[:300]


def _execute_matches(run, monitor):
    """``{document id: {rule titles}}`` from a document-level monitor run. ``_execute`` answers synchronously with
    ``input_results.results: [{<query id>: ["<doc id>|<index>", ...]}]``; the monitor's queries give each id its
    name, which is the rule title (5.0.0-rc1). The findings index is written later and is
    not needed."""
    names = {}
    for inp in ((monitor or {}).get("monitor") or {}).get("inputs") or []:
        for q in (inp.get("doc_level_input") or {}).get("queries") or []:
            names[q.get("id")] = q.get("name")
    out = {}
    for block in (((run or {}).get("input_results") or {}).get("results") or []):
        for qid, refs in (block or {}).items():
            for ref in refs or []:
                did = str(ref).split("|", 1)[0]
                if names.get(qid):
                    out.setdefault(did, set()).add(names[qid])
    return out
