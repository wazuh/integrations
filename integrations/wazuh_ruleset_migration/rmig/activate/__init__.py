"""``activate --yes``.

Requires a verification without failures that matches what is applied
(``--force`` skips it and is recorded). Promotes test -> custom **only the
tool's content**, with the same policy check as ``apply``, then creates one
Security Analytics detector per ``out/detectors/<key>.json``: deterministic
name, looked up before it is created, at most 50 rules, the category's events
index and the rules' server ids. Monitors of ``out/monitors/`` are not created.
"""

import os

from ..api.apply import PROMOTE, Stop, _is_empty, _merge_foreign, _select
from ..api.client import ApiError
from ..api.content import CHANGE_LISTS, KEY_TYPE, Ownership, Snapshot, foreign_changes, policy_differences
from ..api.outdir import doc_title
from ..api.shared_root import load_out
from ..api.report import stop_entry, stop_line, update_report
from ..api.state import State
from ..fsutil import listdir_sorted
from ..jsonio import read_json

SAP = "/_plugins/_security_analytics"
DETECTORS = SAP + "/detectors"
MAX_RULES = 50
FOREIGN_TEST_TEXT = ("The test space has changes that the tool did not make and that are not in custom yet (listed "
                     "below: someone else's content, or a policy change). activate promotes only the tool's content "
                     "and the policy travels as one document, so it stops. Promote or discard them first, or pass "
                     "--include-foreign-changes: activate then promotes them to custom too, together with the tool's "
                     "content (recorded).")


def foreign_items(foreign, snap):
    """``<operation> <type> <id> (<title>)``: the title from test, or from custom for a removal."""
    out = []
    for f in foreign:
        rtype = KEY_TYPE.get(f["type"])
        doc = None
        if rtype:
            doc = snap.get("test", rtype, f["id"]) or snap.get("custom", rtype, f["id"])
        title = doc_title(rtype, doc) if doc else None
        out.append("%s %s %s%s" % (f["operation"], f["type"], f["id"], " (%s)" % title if title else ""))
    return out


def detector_body(name, detector_type, index, rule_ids):
    return {
        "type": "detector",
        "detector_type": detector_type,
        "name": name,
        "enabled": True,
        "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
        "inputs": [{"detector_input": {
            "description": "Wazuh 4.x ruleset migration (%s)" % name,
            "indices": [index],
            "custom_rules": [{"id": r} for r in rule_ids],
            "pre_packaged_rules": [],
        }}],
        "triggers": [],
    }


def find_detector(client, name):
    """``(id, detector)`` of the detector with exactly this name, or None."""
    # "detector" is a nested field in Security Analytics: a plain query on detector.name finds nothing, and
    # activate then created a second detector with the same name (5.0.0-rc1)
    body = {"size": 100, "query": {"nested": {"path": "detector", "query": {"match_phrase": {"detector.name": name}}}}}
    status, res = client.call("POST", DETECTORS + "/_search", body)
    if status == 404:
        return None
    if status >= 300:
        raise ApiError("POST", DETECTORS + "/_search", status, res)
    for hit in (res.get("hits") or {}).get("hits") or []:
        det = (hit.get("_source") or {}).get("detector") or hit.get("_source") or {}
        if det.get("name") == name:
            return hit.get("_id"), det
    return None


def foreign_rules(det, own):
    """Rule ids of a detector that exist in some space and are not the tool's. A detector found by name is
    adopted only when this is empty: another workdir of the same customer generates the same detector names."""
    rules, _ = _detector_rules(det)
    present = {sid for docs in own.snap.docs.values() for sid in (docs.get("rule") or {})}
    return [r for r in rules if r in present and not own.is_own(r)]


def _detector_rules(det):
    inputs = det.get("inputs") or []
    if not inputs:
        return [], []
    di = inputs[0].get("detector_input") or {}
    return sorted(r.get("id") for r in di.get("custom_rules") or []), list(di.get("indices") or [])


class Activate:
    def __init__(self, runner, force=False, include_foreign=False):
        self.r = runner
        self.client = runner.client
        self.force = force
        self.include_foreign = include_foreign
        self.sec = runner.section("activate")
        self.sec["detectors"] = []

    def run(self):
        r = self.r
        self.state = State.load(r.workdir)
        self.out = load_out(r.out_dir, self.state)
        try:
            if getattr(self.out, "share_error", None):
                raise Stop(stop_entry(None, self.out.share_error))
            self.check_verification()
            self.promote()
            self.detectors()
            skipped = [d["name"] for d in self.sec["detectors"] if d.get("status", "").startswith("skipped (a detector")]
            result, code = ("ok", 0) if not skipped else ("detectors left out: %s" % ", ".join(skipped), 1)
        except Stop as stop:
            self.sec["stops"].append(stop.entry)
            r.say(stop_line("activate", stop.entry))
            for it in stop.entry["items"]:
                r.say("  - %s" % it)
            result, code = "stopped", stop.exit_code
        mons = [n for n in listdir_sorted(os.path.join(r.out_dir, "monitors")) if n.endswith(".json")]
        if mons:
            self.sec["notes"].append(
                "%d Alerting monitor definition(s) in out/monitors/ are not created by the tool. Create each one "
                "with: POST _plugins/_alerting/monitors --data @out/monitors/<rule id>.json" % len(mons))
        self.sec["result"] = result
        if not r.dry_run:
            self.state.data["last_activate"] = self.sec["when"]
            self.state.save()
            update_report(r.paths, "activate", self.sec)
        r.say("activate: %s" % result)
        return code

    def check_verification(self):
        path = self.r.paths["verification_json"]
        problem = None
        if not os.path.isfile(path):
            problem = "no verification.json: run verify first"
        else:
            v = read_json(path)
            s = v.get("summary") or {}
            if s.get("failures", 1):
                problem = "the last verification has %s failure(s)" % s.get("failures")
            elif v.get("state_fingerprint") != self.state.fingerprint():
                problem = "the last verification does not match what is applied now (apply ran after it)"
        if problem is None:
            return
        if not self.force:
            raise Stop(stop_entry(None, "Activation needs a verification without failures: %s. Pass --force to "
                                  "activate anyway (recorded)." % problem), exit_code=1)
        op = self.state.operation("force", "activate", problem) if not self.r.dry_run else {
            "op": "force", "command": "activate", "who": "-", "when": "-", "detail": problem}
        self.sec["operations"].append(op)

    def promote(self):
        snap = Snapshot(self.client)
        self.own = own = Ownership(snap, self.state, set(self.out.by_local) | set(self.state.resources))
        changes = self.r.promote_preview("test")
        foreign = foreign_changes(changes, own)
        rd = (self.state.data.get("root_decoder") or {}).get("server_id")
        pol = []
        if changes.get("policy"):
            pol = policy_differences(snap.policy.get("test"), snap.policy.get("custom"), own, rd)
        if foreign or pol:
            items = foreign_items(foreign, snap) + ["policy: %s" % d for d in pol]
            if not self.include_foreign:
                raise Stop(stop_entry("RM-P-FOREIGN-POLICY-CHANGE" if pol else None, FOREIGN_TEST_TEXT, items))
            if not self.r.dry_run:
                self.sec["operations"].append(self.state.operation("include-foreign-changes", "activate", "; ".join(items)))
        aside = set(self.state.data.get("set_aside") or {})
        ids = {sid for sid, lid in own.owned.items()
               if (self.state.get(lid) or {}).get("integration") not in aside}
        sel = _select(changes, ids)
        if self.include_foreign:
            _merge_foreign(sel, changes, own)
        if changes.get("policy"):
            sel["policy"] = list(changes["policy"])
        if _is_empty(sel):
            self.r.say("activate: test and custom already match for the tool's content")
            self._mark_custom(snap, ids)
            return
        what = ", ".join("%d %s" % (len(sel[k]), k) for k in CHANGE_LISTS if sel[k])
        if self.r.dry_run:
            self.r.say("[dry-run] POST %s  (promote test -> custom: %s)" % (PROMOTE, what))
            return
        self.r.say("POST %s  (promote test -> custom: %s)" % (PROMOTE, what))
        status, body = self.client.call("POST", PROMOTE, {"space": "test", "changes": sel})
        if status >= 300:
            raise Stop(stop_entry(None, "The promotion test -> custom failed.",
                                  [ApiError("POST", PROMOTE, status, body).server_message]), exit_code=1)
        self._mark_custom(snap, ids)
        self.state.save()

    def _mark_custom(self, snap, ids):
        """After the promotion, the tool's content of test is also in custom."""
        for sid in ids:
            lid = self.own.owned.get(sid)
            e = self.state.get(lid)
            if e and e.get("server_id") == sid and sid in snap.docs["test"].get(e.get("type"), {}):
                self.state.set_space(lid, "custom")

    def detectors(self):
        aside = set(self.state.data.get("set_aside") or {})
        for d in self.out.detectors:
            name = d["name"]
            key = d.get("integration")
            integ = self.out.integration(key)
            entry = {"name": name, "integration": key, "index": d.get("index"), "rules": 0, "status": ""}
            self.sec["detectors"].append(entry)
            if integ is None or key in aside:
                entry["status"] = "skipped (integration set aside or missing)"
                continue
            ids = []
            missing = []
            for lid in d.get("rules") or []:
                e = self.state.get(lid)
                if e and e.get("server_id") and e.get("space") == "custom":
                    ids.append(e["server_id"])
                else:
                    missing.append(lid)
            if missing:
                self.sec["notes"].append("%s: %d rule(s) are not in custom and are left out: %s" % (
                    name, len(missing), ", ".join(missing[:10])))
            if not ids:
                entry["status"] = "skipped (no rule in custom)"
                continue
            if len(ids) > MAX_RULES:
                raise Stop(stop_entry(None, "%s lists %d rules; a detector takes at most %d." % (name, len(ids), MAX_RULES)))
            entry["rules"] = len(ids)
            body = detector_body(name, integ.title, d.get("index"), ids)
            if self.r.dry_run:
                self.r.say("[dry-run] POST %s/_search, then POST or PUT %s  (detector %s, %d rule(s))" % (
                    DETECTORS, DETECTORS, name, len(ids)))
                entry["status"] = "dry run"
                continue
            found = find_detector(self.client, name)
            if found is None:
                res = self.r.write("POST", DETECTORS, body, "create detector %s (%d rules)" % (name, len(ids)))
                det_id = res.get("_id")
                entry["status"] = "created"
            else:
                det_id, det = found
                recorded = (self.state.data.get("detectors") or {}).get(name, {}).get("id")
                other = [] if det_id == recorded else foreign_rules(det, self.own)
                if other:
                    entry["status"] = "skipped (a detector with this name is not the tool's)"
                    self.sec["notes"].append(
                        "Detector %s (%s) has the name the tool would use but rules that are not its own (%s): it "
                        "is left as it is and the tool's rules of %s have no detector. Rename or remove that "
                        "detector, then run activate again." % (det_id, name, ", ".join(other[:5]), name))
                    self.r.say("activate: detector %s exists and is not the tool's: left untouched" % name)
                    continue
                rules, indices = _detector_rules(det)
                if rules == sorted(ids) and indices == [d.get("index")] and det.get("enabled", True):
                    entry["status"] = "unchanged"
                else:
                    self.r.write("PUT", "%s/%s" % (DETECTORS, det_id), body, "update detector %s" % name)
                    entry["status"] = "updated"
            self.state.data["detectors"][name] = {"id": det_id, "rules": sorted(ids), "index": d.get("index")}
            self.state.save()
