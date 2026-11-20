"""A fake Wazuh indexer for the API tests.

An HTTP server on 127.0.0.1 with an ephemeral port that imitates the content
manager contract of ``wazuh-indexer-plugins@5.0.0``:
server-side UUIDs, unique titles of rules and integrations in draft, a draft
policy that gains each integration created, ``GET /promote`` computed by hash
between a space and the next, ``POST /promote`` that requires the six lists
and only ``update`` for the policy and validates the destination space (the
engine), ``_search`` over the ``wazuh-threatintel-*`` indices, logtest with a
configurable normalizer, and the Security Analytics / Alerting calls used by
``activate`` and ``verify --via-detector``.

Every call of the forbidden list is recorded in
``violations``; the tests fail when it is not empty. No recorded answers of a
live indexer were available when it was written, so the
shapes come from the plugin's code and its e2e tests.
"""

import copy
import hashlib
import json
import os
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.dirname(HERE)
if TOOL not in sys.path:
    sys.path.insert(0, TOOL)

from rmig.verify.sigma import evaluate  # noqa: E402

CM = "/_plugins/_content_manager"
SAP = "/_plugins/_security_analytics"
SPACES = ("draft", "test", "custom", "standard")
RTYPES = ("integration", "kvdb", "decoder", "rule")
PLURAL = {"integrations": "integration", "kvdbs": "kvdb", "decoders": "decoder", "rules": "rule"}
INDEX = {"wazuh-threatintel-integrations": "integration", "wazuh-threatintel-kvdbs": "kvdb",
         "wazuh-threatintel-decoders": "decoder", "wazuh-threatintel-rules": "rule",
         "wazuh-threatintel-policies": "policy"}
NEXT = {"draft": "test", "test": "custom"}
LISTS = ("policy", "integrations", "kvdbs", "decoders", "filters", "rules")


def _hash(doc):
    return hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()


def kv_normalizer(event, location):
    """Default normalization: ``key=value`` tokens become fields."""
    out = {"event": {"original": event}, "message": event}
    for tok in event.split():
        k, sep, v = tok.partition("=")
        if sep and k:
            cur = out
            parts = k.split(".")
            for p in parts[:-1]:
                cur = cur.setdefault(p, {}) if isinstance(cur.get(p, {}), dict) else cur
            cur[parts[-1]] = v
    return out


class FakeIndexer:
    def __init__(self):
        self.lock = threading.RLock()
        self.docs = {s: {t: {} for t in RTYPES} for s in SPACES}
        self.policy_id = str(uuid.uuid4())
        self.policies = {}
        for s in SPACES:
            self.policies[s] = {
                "id": self.policy_id,
                "metadata": {"title": "Policy", "author": "Wazuh Inc.", "description": "Default policy",
                             "documentation": "", "references": []},
                "root_decoder": "", "integrations": [], "filters": [], "enrichments": [], "enabled": True,
                "index_unclassified_events": False, "index_discarded_events": False,
            }
        self.calls = []
        self.violations = []
        self.foreign_ids = set()
        # Security Analytics lag: integration title -> seconds during which its log type stays busy after its
        # rules have left test (seen live: a log type is not always freed right away). Time passes only
        # through sleep(), which run_command puts in place of time.sleep in rmig.api.apply.
        self.logtype_lag = {}
        self.slept = []
        self.phase = None
        self.engine_reject = None
        self.create_reject = None  # fn(rtype, resource) -> message: a 400 on POST, as the engine build check
        self.update_reject = None  # the same for PUT
        self.policy_locked = False
        self.normalizer = kv_normalizer
        self.detectors = {}
        self.indices = {}
        self.findings = []
        self.answer_429 = 0
        self.detector_blind = set()
        self.server = None
        self.thread = None

    # -- life cycle ----------------------------------------------------------------
    def start(self):
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self, method):
                parts = urlsplit(self.path)
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                body = json.loads(raw) if raw else None
                if self.headers.get("Authorization", "")[:6] != "Basic ":
                    status, obj = 401, {"error": "no auth"}
                else:
                    status, obj = fake.handle(method, parts.path, parse_qs(parts.query), body)
                data = b"" if obj is None else json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._do("GET")

            def do_POST(self):
                self._do("POST")

            def do_PUT(self):
                self._do("PUT")

            def do_DELETE(self):
                self._do("DELETE")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.server.server_address[1]

    # -- seeding (content the tool does not own) -------------------------------------------
    def seed(self, rtype, document, spaces=("draft",), integration=None, foreign=True):
        with self.lock:
            sid = document.get("id") or str(uuid.uuid4())
            doc = copy.deepcopy(document)
            doc["id"] = sid
            if rtype == "integration":
                for k in ("rules", "decoders", "kvdbs"):
                    doc.setdefault(k, [])
            for s in spaces:
                self.docs[s][rtype][sid] = copy.deepcopy(doc)
                if rtype == "integration" and sid not in self.policies[s]["integrations"]:
                    self.policies[s]["integrations"].append(sid)
                if integration and rtype != "integration":
                    integ = self.docs[s]["integration"][integration]
                    integ[rtype + "s"].append(sid)
            if foreign:
                self.foreign_ids.add(sid)
            return sid

    def owned_docs(self, space, author="wazuh-ruleset-migration"):
        return {t: [d for d in self.docs[space][t].values() if (d.get("metadata") or {}).get("author") == author]
                for t in RTYPES}

    # -- dispatch ----------------------------------------------------------------------
    def violation(self, text):
        self.violations.append(text)
        return 599, {"error": "FORBIDDEN CALL: " + text}

    def handle(self, method, path, query, body):
        with self.lock:
            self.calls.append((method, path, copy.deepcopy(body)))
            try:
                return self._route(method, path, query, body or {})
            except Exception as exc:  # noqa: BLE001
                return 500, {"error": "fake failure: %r" % exc}

    def _route(self, method, path, query, body):
        p = path.rstrip("/").split("/")[1:]
        if path.startswith(CM + "/space"):
            return self.violation("%s %s" % (method, path))
        if path.startswith(CM + "/filters"):
            return self.violation("filters are never written: %s %s" % (method, path))
        if path.startswith(CM + "/policy/"):
            return self.put_policy(method, p[-1], body)
        if path == CM + "/promote":
            return self.get_promote(query) if method == "GET" else self.post_promote(body)
        if path.startswith(CM + "/logtest"):
            return self.logtest(path[len(CM):], body)
        if path.startswith(CM + "/") and len(p) >= 3 and p[2] in PLURAL:
            rtype = PLURAL[p[2]]
            sid = p[3] if len(p) > 3 else None
            if method in ("POST", "PUT") and self.answer_429 > 0:
                self.answer_429 -= 1
                return 429, None  # only the status is modeled: no recorded 429 answer
            if method == "POST" and sid is None:
                return self.create(rtype, body)
            if method == "PUT" and sid:
                return self.update(rtype, sid, body)
            if method == "DELETE" and sid:
                return self.delete(rtype, sid)
        if path.startswith(SAP + "/detectors"):
            return self.detector_call(method, p, body)
        if path == "/wazuh-findings-v5-*/_search":
            return self.search_findings(body)
        if path == "/wazuh-findings-v5-*/_refresh":
            return 200, {"_shards": {"total": 1, "successful": 1, "failed": 0}}
        if path.startswith("/.opensearch-sap-detectors-config/_doc/"):
            did = p[-1]
            if did not in self.detectors:
                return 404, {"found": False}
            return 200, {"found": True, "_source": {"detector": {"monitor_id": ["mon-" + did]}}}
        if path.startswith("/_plugins/_alerting/monitors/") and path.endswith("/_execute"):
            return self.execute_monitor(p[-2][4:])
        if path.startswith("/_plugins/_alerting/monitors/") and method == "GET":
            return self.get_monitor(p[-1][4:])
        if len(p) == 2 and p[1] == "_mapping" and method == "GET" and p[0].startswith("wazuh-events-v5-"):
            # the mapping of a category data stream (only its shape matters here)
            return 200, {".ds-%s-000001" % p[0]: {"mappings": {"dynamic": "strict_allow_templates",
                                                              "_data_stream_timestamp": {"enabled": True},
                                                              "properties": {"tags": {"type": "keyword"}}}}}
        if len(p) == 1 and method == "PUT" and p[0] not in INDEX and p[0].startswith("wazuh-events-v5-rmig-verify-"):
            if "_data_stream_timestamp" in ((body or {}).get("mappings") or {}):
                return 400, {"error": "unknown mapping field [_data_stream_timestamp]"}
            if p[0] in self.indices:
                return 400, {}  # the index exists: only the status is modeled (no recorded answer)
            self.indices.setdefault(p[0], {})
            return 200, {"acknowledged": True, "index": p[0]}
        if len(p) == 2 and p[1] == "_search" and p[0] in INDEX:
            return self.search(INDEX[p[0]], body)
        if len(p) == 2 and p[1] == "_refresh":
            return 200, {"_shards": {"total": 1, "successful": 1, "failed": 0}}
        if len(p) == 2 and p[1] == "_doc" and method == "POST" and p[0] not in INDEX:
            did = str(uuid.uuid4())
            self.indices.setdefault(p[0], {})[did] = body
            return 201, {"_id": did, "result": "created", "_shards": {"total": 1, "successful": 1, "failed": 0}}
        if len(p) == 1 and method == "DELETE" and p[0] not in INDEX:
            self.indices.pop(p[0], None)
            return 200, {"acknowledged": True}
        return self.violation("unexpected call %s %s" % (method, path))

    # -- content manager ------------------------------------------------------------------
    def _draft_integration(self, iid):
        return self.docs["draft"]["integration"].get(iid)

    def create(self, rtype, body):
        res = body.get("resource")
        if not isinstance(res, dict):
            return 400, {"message": "Missing [resource] field.", "status": 400}
        meta = res.get("metadata") or {}
        draft = self.docs["draft"]
        if self.create_reject:
            msg = self.create_reject(rtype, res)
            status = 400
            if isinstance(msg, tuple):  # (status, message)
                status, msg = msg
            if msg:
                return status, {"message": msg, "status": status}
        if rtype == "integration":
            if not meta.get("title") or not meta.get("author") or not res.get("category"):
                return 400, {"message": "Missing [title, author, category]", "status": 400}
            if any((d.get("metadata") or {}).get("title") == meta["title"] for d in draft["integration"].values()):
                return 400, {"message": "An integration with the title '%s' already exists in draft." % meta["title"], "status": 400}
            sid = str(uuid.uuid4())
            doc = copy.deepcopy(res)
            doc.update({"id": sid, "rules": [], "decoders": [], "kvdbs": [], "mode": "user-managed"})
            draft["integration"][sid] = doc
            self.policies["draft"]["integrations"].append(sid)
            return 201, {"message": sid, "status": 201}
        iid = body.get("integration")
        integ = self._draft_integration(iid)
        if integ is None:
            return 400, {"message": "Integration [%s] not found." % iid, "status": 400}
        if rtype == "rule":
            if not meta.get("title"):
                return 400, {"message": "Missing [title]", "status": 400}
            if any((d.get("metadata") or {}).get("title") == meta["title"] for d in draft["rule"].values()):
                return 400, {"message": "A rule with the title '%s' already exists in draft." % meta["title"], "status": 400}
            if (res.get("logsource") or {}).get("product") != (integ.get("metadata") or {}).get("title"):
                return 400, {"message": "logsource.product must match the integration title", "status": 400}
        if rtype == "kvdb" and not res.get("content"):
            return 400, {"message": "Missing [content]", "status": 400}
        if rtype == "decoder" and not res.get("name"):
            return 400, {"message": "Invalid decoder: name is required", "status": 400}
        sid = str(uuid.uuid4())
        doc = copy.deepcopy(res)
        doc["id"] = sid
        draft[rtype][sid] = doc
        integ[rtype + "s"].append(sid)
        return 201, {"message": sid, "status": 201}

    def _where(self, rtype, sid):
        return [s for s in SPACES if sid in self.docs[s][rtype]]

    def update(self, rtype, sid, body):
        if sid in self.foreign_ids:
            return self.violation("PUT of a resource the tool does not own: %s %s" % (rtype, sid))
        if sid in self.docs["standard"][rtype]:
            return self.violation("write in standard: PUT %s %s" % (rtype, sid))
        cur = self.docs["draft"][rtype].get(sid)
        if cur is None:
            return 404, {"message": "%s [%s] not found." % (rtype, sid), "status": 404}
        res = body.get("resource") or {}
        if self.update_reject:
            msg = self.update_reject(rtype, res)
            if msg:
                return 400, {"message": msg, "status": 400}
        if rtype == "integration":
            for k in ("rules", "decoders", "kvdbs"):
                if sorted(res.get(k) or []) != sorted(cur.get(k) or []):
                    return 400, {"message": "Content of '%s' cannot be added or removed via update" % k, "status": 400}
        if rtype == "rule":
            meta = res.get("metadata") or {}
            if "enabled" not in res or not meta.get("title") or not meta.get("author"):
                return 400, {"message": "Missing [enabled, metadata.title, metadata.author]", "status": 400}
        doc = copy.deepcopy(res)
        doc["id"] = sid
        if rtype == "integration":
            doc["mode"] = cur.get("mode")
        self.docs["draft"][rtype][sid] = doc
        return 200, {"message": sid, "status": 200}

    def sleep(self, seconds):
        self.slept.append(seconds)
        for k in list(self.logtype_lag):
            self.logtype_lag[k] = max(0, self.logtype_lag[k] - seconds)

    def delete(self, rtype, sid):
        if sid in self.foreign_ids:
            return self.violation("DELETE of a resource the tool does not own: %s %s" % (rtype, sid))
        if sid in self.docs["standard"][rtype]:
            return self.violation("write in standard: DELETE %s %s" % (rtype, sid))
        cur = self.docs["draft"][rtype].get(sid)
        if cur is None:
            return 404, {"message": "%s [%s] not found." % (rtype, sid), "status": 404}
        if rtype == "integration":
            if cur.get("rules") or cur.get("decoders") or cur.get("kvdbs"):
                return 400, {"message": "Cannot delete integration with existing decoders, rules or kvdbs.", "status": 400}
            # Security Analytics keeps the log type while another space has rules of it
            # (recorded live: tests/data/api/recorded/07-rollback.json)
            lag = self.logtype_lag.get((cur.get("metadata") or {}).get("title"), 0) > 0
            if lag or any(self.docs[s]["integration"].get(sid, {}).get("rules") for s in ("test", "custom")):
                return 500, {"message": "Failed to delete from external service: Log Type with id %s cannot be "
                                        "deleted because active rules exist" % sid, "status": 500}
            pol = self.policies["draft"]
            pol["integrations"] = [i for i in pol["integrations"] if i != sid]
        else:
            if rtype == "decoder" and self.policies["draft"].get("root_decoder") == sid:
                return 400, {"message": "Cannot delete the root decoder of the policy.", "status": 400}
            for integ in self.docs["draft"]["integration"].values():
                if sid in integ.get(rtype + "s", []):
                    integ[rtype + "s"].remove(sid)
        del self.docs["draft"][rtype][sid]
        return 200, {"message": sid, "status": 200}

    def put_policy(self, method, space, body):
        if method != "PUT":
            return self.violation("%s on the policy" % method)
        if space == "standard":
            return self.violation("PUT /policy/standard")
        if space != "draft":
            return 400, {"message": "Invalid space", "status": 400}
        if self.policy_locked:
            return 403, {"message": "Policy updates are disabled.", "status": 403}
        res = copy.deepcopy(body.get("resource") or {})
        cur = self.policies["draft"]
        missing = [k for k in ("enabled", "index_unclassified_events", "index_discarded_events") if res.get(k) is None]
        meta = res.get("metadata") or {}
        missing += [k for k in ("author", "description") if not meta.get(k)]
        missing += [k for k in ("documentation", "references") if meta.get(k) is None]
        if missing:
            return 400, {"message": "Missing [%s]" % ", ".join(missing), "status": 400}
        before = {k: v for k, v in cur.items() if k not in ("id", "root_decoder", "integrations")}
        after = {k: v for k, v in res.items() if k not in ("id", "root_decoder", "integrations")}
        if before != after:
            changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
            return self.violation("PUT /policy/draft changes more than root_decoder: %s" % ", ".join(changed))
        # the tool may only reorder the integrations, and only its own ones (accepted by 5.0.0-rc1)
        old_i, new_i = list(cur.get("integrations") or []), list(res.get("integrations") or [])
        if sorted(old_i) != sorted(new_i):
            return self.violation("PUT /policy/draft adds or removes integrations")
        if [i for i in old_i if i in self.foreign_ids] != [i for i in new_i if i in self.foreign_ids]:
            return self.violation("PUT /policy/draft moves integrations the tool does not own")
        cur["integrations"] = new_i
        cur["root_decoder"] = res.get("root_decoder") or ""
        return 200, {"message": self.policy_id, "status": 200}

    def get_promote(self, query):
        space = (query.get("space") or [""])[0]
        if space not in NEXT:
            return 400, {"message": "Space [%s] cannot be promoted." % space, "status": 400}
        return 200, {"changes": self.diff(space, NEXT[space])}

    def diff(self, src, dst):
        ch = {k: [] for k in LISTS}
        for rtype in RTYPES:
            a, b = self.docs[src][rtype], self.docs[dst][rtype]
            key = rtype + "s"
            for sid in sorted(a):
                if sid not in b:
                    ch[key].append({"operation": "add", "id": sid})
                elif _hash(a[sid]) != _hash(b[sid]):
                    ch[key].append({"operation": "update", "id": sid})
            for sid in sorted(b):
                if sid not in a:
                    ch[key].append({"operation": "remove", "id": sid})
        if _hash(self.policies[src]) != _hash(self.policies[dst]):
            ch["policy"].append({"operation": "update", "id": self.policy_id})
        return ch

    def post_promote(self, body):
        space = body.get("space")
        if space not in NEXT:
            return 400, {"message": "Space [%s] cannot be promoted." % space, "status": 400}
        if space == "test" and self.phase == "apply":
            return self.violation("POST /promote with space test during apply")
        ch = body.get("changes")
        if not isinstance(ch, dict) or any(not isinstance(ch.get(k), list) for k in LISTS):
            return 400, {"message": "All resource type lists (policy, integrations, kvdbs, decoders, filters, rules) are required in changes", "status": 400}
        if any(op.get("operation") != "update" for op in ch["policy"]):
            return 400, {"message": "Only update is allowed for the policy", "status": 400}
        if ch["filters"]:
            return self.violation("promote of filters")
        dst = NEXT[space]
        new = {t: copy.deepcopy(self.docs[dst][t]) for t in RTYPES}
        for rtype in RTYPES:
            for op in ch[rtype + "s"]:
                sid, o = op.get("id"), op.get("operation")
                if o == "add":
                    if sid not in self.docs[space][rtype]:
                        return 400, {"message": "Resource '%s' not found in %s for ADD operation" % (sid, rtype), "status": 400}
                    if sid in new[rtype]:
                        return 400, {"message": "Resource '%s' already exists in target space '%s', use UPDATE operation instead" % (sid, dst), "status": 400}
                    new[rtype][sid] = copy.deepcopy(self.docs[space][rtype][sid])
                elif o == "update":
                    if sid not in self.docs[space][rtype]:
                        return 400, {"message": "Resource '%s' not found in %s for UPDATE operation" % (sid, rtype), "status": 400}
                    new[rtype][sid] = copy.deepcopy(self.docs[space][rtype][sid])
                elif o == "remove":
                    new[rtype].pop(sid, None)
                else:
                    return 400, {"message": "bad operation %r" % o, "status": 400}
        new_policy = copy.deepcopy(self.policies[space]) if ch["policy"] else copy.deepcopy(self.policies[dst])
        # the engine validates the whole destination space
        for iid in new_policy["integrations"]:
            if iid not in new["integration"]:
                return 400, {"message": "Engine: integration [%s] of the policy is not in space '%s'" % (iid, dst), "status": 400}
        for iid, integ in new["integration"].items():
            for t in ("decoder", "kvdb", "rule"):
                for x in integ.get(t + "s", []):
                    if x not in new[t]:
                        return 400, {"message": "Engine: %s [%s] of integration [%s] is not in space '%s'" % (t, x, iid, dst), "status": 400}
        if new_policy.get("root_decoder") and new_policy["root_decoder"] not in new["decoder"]:
            return 400, {"message": "Engine: root decoder [%s] not found" % new_policy["root_decoder"], "status": 400}
        if self.engine_reject:
            msg = self.engine_reject(space, ch, new)
            if msg:
                return 400, {"message": msg, "status": 400}
        for t in RTYPES:
            self.docs[dst][t] = new[t]
        self.policies[dst] = new_policy
        return 200, {"message": "Promotion completed", "status": 200}

    def search(self, rtype, body):
        q = (body or {}).get("query") or {}
        terms = []
        if "term" in q:
            terms.append(q["term"])
        for t in ((q.get("bool") or {}).get("must") or []):
            if "term" in t:
                terms.append(t["term"])
        conds = []
        for t in terms:
            for field, v in t.items():
                conds.append((field, v.get("value") if isinstance(v, dict) else v))
        hits = []
        sources = []
        for s in SPACES:
            if rtype == "policy":
                sources.append((s, self.policies[s]))
            else:
                sources.extend((s, d) for d in self.docs[s][rtype].values())
        for s, doc in sources:
            ok = True
            for field, value in conds:
                if field == "space.name":
                    ok = ok and s == value
                elif field.startswith("document."):
                    cur = doc
                    for part in field.split(".")[1:]:
                        cur = cur.get(part) if isinstance(cur, dict) else None
                    ok = ok and (cur == value or (isinstance(cur, list) and value in cur))
                else:
                    ok = False
            if ok:
                hits.append({"_id": "%s-%s" % (s, doc["id"]), "_source": {"document": copy.deepcopy(doc), "space": {"name": s}}})
        return 200, {"_shards": {"total": 1, "successful": 1, "failed": 0},
                     "hits": {"total": {"value": len(hits)}, "hits": hits}}

    # -- logtest ------------------------------------------------------------------------
    def _detect(self, space, iid, output):
        integ = self.docs[space]["integration"].get(iid)
        if integ is None:
            return None
        matches = []
        for rid in integ.get("rules", []):
            rule = self.docs[space]["rule"].get(rid)
            if rule is None:
                continue
            ok, _ = evaluate(rule.get("detection"), output)
            if ok:
                matches.append({"rule": {"id": rid, "title": (rule.get("metadata") or {}).get("title"),
                                         "level": rule.get("level"), "tags": rule.get("tags", [])},
                                "matched_conditions": [rule.get("detection", {}).get("condition")]})
        return {"status": "success", "rules_evaluated": len(integ.get("rules", [])), "rules_matched": len(matches),
                "matches": matches}

    def logtest(self, sub, body):
        space = body.get("space")
        if space not in ("test", "custom", "standard"):
            return 400, {"message": "Invalid space [%s]" % space, "status": 400}
        if sub == "/logtest/detection":
            det = self._detect(space, body.get("integration"), body.get("input") or {})
            if det is None:
                return 400, {"message": "Integration [%s] not found in the '%s' space." % (body.get("integration"), space), "status": 400}
            return 200, {"status": 200, "message": det}
        output = self.normalizer(body.get("event") or "", body.get("location"))
        norm = {"output": output, "asset_traces": [], "validation": {"valid": True, "errors": []}}
        if sub == "/logtest/normalization":
            return 200, {"status": 200, "message": norm}
        if body.get("integration") is None:
            det = {"status": "skipped"}
        else:
            det = self._detect(space, body.get("integration"), output)
            if det is None:
                return 400, {"message": "Integration [%s] not found in the '%s' space." % (body.get("integration"), space), "status": 400}
        return 200, {"status": 200, "message": {"normalization": norm, "detection": det}}

    # -- Security Analytics / Alerting -----------------------------------------------------
    def detector_call(self, method, p, body):
        if p[-1] == "_search" and method == "POST":
            # "detector" is a nested field: only a nested query finds a detector by name (a query on
            # detector.name outside "nested" matches nothing, 5.0.0-rc1)
            query = body.get("query") or {}
            name = None
            if "nested" in query:
                name = ((query["nested"].get("query") or {}).get("match_phrase") or {}).get("detector.name")
            elif "match_all" not in query and query:
                return 200, {"hits": {"total": {"value": 0}, "hits": []}}
            hits = [{"_id": did, "_source": {"detector": copy.deepcopy(d)}} for did, d in sorted(self.detectors.items())
                    if name is None or d["name"] == name]
            return 200, {"hits": {"total": {"value": len(hits)}, "hits": hits}}
        did = p[-1] if p[-1] != "detectors" else None
        if method == "DELETE":
            if did not in self.detectors:
                return 404, {"error": "not found"}
            del self.detectors[did]
            return 200, {"_id": did}
        if method in ("POST", "PUT"):
            rules = [r["id"] for r in body["inputs"][0]["detector_input"]["custom_rules"]]
            if len(rules) > 50:
                return 400, {"error": "more than 50 rules"}
            for r in rules:
                if r not in self.docs["custom"]["rule"] and r not in self.docs["test"]["rule"]:
                    return 400, {"error": "rule %s not found" % r}
            if method == "POST":
                did = uuid.uuid4().hex
            elif did not in self.detectors:
                return 404, {"error": "not found"}
            self.detectors[did] = copy.deepcopy(body)
            return (201 if method == "POST" else 200), {"_id": did, "detector": body}
        return self.violation("unexpected detector call %s" % method)

    def execute_monitor(self, did):
        det = self.detectors.get(did)
        if det is None:
            return 404, {"error": "no monitor"}
        di = det["inputs"][0]["detector_input"]
        before = len(self.findings)
        for index in di["indices"]:
            for doc_id, doc in self.indices.get(index, {}).items():
                for r in di["custom_rules"]:
                    rule = self.docs["custom"]["rule"].get(r["id"]) or self.docs["test"]["rule"].get(r["id"])
                    if rule is None or r["id"] in self.detector_blind:
                        continue
                    ok, _ = evaluate(rule.get("detection"), doc)
                    if ok:
                        # as observed against a live 5.0.0-rc1 indexer: the finding names the SAP copy of the
                        # rule (another id) and the title, and points at the event by event.doc_id
                        self.findings.append({"event": {"doc_id": doc_id, "index": index},
                                              "wazuh": {"integration": {"name": det["detector_type"]},
                                                        "rule": {"id": "sap-" + r["id"],
                                                                 "title": (rule.get("metadata") or {}).get("title")}}})
        # as observed live: _execute answers synchronously with the documents each query matched
        per_query = {}
        for f in self.findings[before:]:
            per_query.setdefault("q-" + f["wazuh"]["rule"]["id"][4:], []).append(
                "%s|%s" % (f["event"]["doc_id"], f["event"]["index"]))
        return 200, {"monitor_name": det["name"], "input_results": {"results": [per_query] if per_query else []}}

    def get_monitor(self, did):
        det = self.detectors.get(did)
        if det is None:
            return 404, {"error": "no monitor"}
        di = det["inputs"][0]["detector_input"]
        queries = []
        for r in di["custom_rules"]:
            rule = self.docs["custom"]["rule"].get(r["id"]) or self.docs["test"]["rule"].get(r["id"])
            if rule is not None:
                queries.append({"id": "q-" + r["id"], "name": (rule.get("metadata") or {}).get("title")})
        return 200, {"monitor": {"name": det["name"], "inputs": [{"doc_level_input": {"indices": di["indices"],
                                                                                   "queries": queries}}]}}

    def search_findings(self, body):
        must = ((body.get("query") or {}).get("bool") or {}).get("must") or []
        name, ids = None, None
        for m in must:
            name = (m.get("term") or {}).get("wazuh.integration.name", name)
            ids = (m.get("terms") or {}).get("event.doc_id", ids)
        hits = [{"_id": uuid.uuid4().hex, "_source": copy.deepcopy(f)} for f in self.findings
                if (name is None or f["wazuh"]["integration"]["name"] == name)
                and (ids is None or f["event"]["doc_id"] in ids)]
        return 200, {"_shards": {"total": 1, "successful": 1, "failed": 0}, "hits": {"total": {"value": len(hits)}, "hits": hits}}


# -- helpers shared by the API tests ----------------------------------------------------------
DATA_API = os.path.join(HERE, "data", "api")


def make_workdir(out_name="out-basic"):
    """A temporary work directory with a copy of ``tests/data/api/<out_name>``
    as its ``out/``."""
    import shutil
    import tempfile

    work = tempfile.mkdtemp(prefix="rmig-api-")
    shutil.copytree(os.path.join(DATA_API, out_name), os.path.join(work, "out"))
    return work


def run_command(fake, argv, workdir, extra_env=None):
    """Run ``rmig.api.commands.main`` against the fake; ``(exit code, output)``."""
    import contextlib
    import io
    from unittest import mock

    from rmig.api import apply as apply_mod
    from rmig.api import commands

    env = {"WAZUH_INDEXER_URL": fake.url, "WAZUH_INDEXER_USER": "tester", "WAZUH_INDEXER_PASSWORD": "not-a-real-secret"}
    env.update(extra_env or {})
    sink = io.StringIO()
    with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink), \
            mock.patch.object(apply_mod.time, "sleep", fake.sleep):
        code = commands.main(argv + ["--workdir", workdir], env=env)
    return code, sink.getvalue()


def read_state(workdir):
    with open(os.path.join(workdir, "work", "state.json"), encoding="utf-8") as fh:
        return json.load(fh)


def writes(fake, since=0):
    return [(m, p) for m, p, _b in fake.calls[since:]
            if m in ("PUT", "DELETE") or (m == "POST" and not p.endswith("/_search") and not p.endswith("/_refresh")
                                           and "/logtest" not in p)]
