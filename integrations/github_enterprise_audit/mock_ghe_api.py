#!/usr/bin/env python3
"""Mock of the GHE.com enterprise audit log API, for testing github_audit_wodle.py
without a real tenant. Stdlib only.

  python3 mock_ghe_api.py --port 8765 --backfill 250 --live-every 5

Serves GET /enterprises/<slug>/audit-log with the same contract GitHub documents:
phrase=created:<from>..<to>, include=web|git|all, order=asc, per_page, cursor
pagination through Link rel="next" (after=). Token must be "test-token".

Fault injection (consumed one per request, in order), via --faults:
  429      HTTP 429 with Retry-After: 2
  403rl    HTTP 403 with X-RateLimit-Remaining: 0 and a reset 2s ahead
  500      HTTP 500
  big      next page carries one event larger than 60000 bytes
"""
import argparse
import json
import re
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlencode, urlsplit

TOKEN = "test-token"
ACTIONS = ["repo.create", "org.add_member", "repo.destroy", "protected_branch.destroy",
           "org.update_member", "git.clone", "git.push"]
EVENTS = []
LOCK = threading.Lock()
FAULTS = []


def make_event(ts_ms, n, big=False):
    action = ACTIONS[n % len(ACTIONS)]
    ev = {
        "@timestamp": ts_ms, "created_at": ts_ms, "_document_id": "doc-%06d" % n,
        "action": action, "actor": "alice", "actor_id": 1001, "actor_ip": "203.0.113.%d" % (n % 250 + 1),
        "actor_location": {"country_code": "FR"}, "business": "example", "business_id": 42,
        "org": "example-org", "org_id": 7, "repo": "example-org/repo-%d" % (n % 5),
        "user": "bob", "operation_type": "create",
    }
    if action.startswith("git."):
        ev["transport_protocol_name"] = "http"
    if big:
        ev["payload_blob"] = "x" * 70000
    return ev


def add_event(ts_ms, big=False):
    with LOCK:
        EVENTS.append(make_event(ts_ms, len(EVENTS), big))


def parse_iso(s):
    return int(datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("mock: " + (fmt % args) + "\n")

    def reply(self, code, body, headers=None):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlsplit(self.path)
        if not re.match(r"^/enterprises/[^/]+/audit-log$", u.path):
            return self.reply(404, {"message": "Not Found"})
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            return self.reply(403, {"message": "Must have admin rights to Repository."})
        fault = FAULTS.pop(0) if FAULTS else None
        if fault == "429":
            return self.reply(429, {"message": "secondary rate limit"}, {"Retry-After": "2"})
        if fault == "403rl":
            return self.reply(403, {"message": "API rate limit exceeded"},
                              {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(int(time.time()) + 2)})
        if fault == "500":
            return self.reply(500, {"message": "Server Error"})

        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        m = re.match(r"^created:(\S+)\.\.(\S+)$", q.get("phrase", ""))
        if not m:
            return self.reply(422, {"message": "bad phrase %r" % q.get("phrase")})
        lo, hi = parse_iso(m.group(1)) * 1000, parse_iso(m.group(2)) * 1000 + 999  # inclusive
        include = q.get("include", "web")
        per_page = min(int(q.get("per_page", 30)), 100)
        after = int(q.get("after", 0))
        with LOCK:
            sel = [e for e in EVENTS if lo <= e["@timestamp"] <= hi and (
                include == "all" or (include == "git") == e["action"].startswith("git."))]
        sel.sort(key=lambda e: e["@timestamp"], reverse=q.get("order") == "desc")
        page = sel[after:after + per_page]
        if fault == "big" and page:
            page = [dict(page[0], payload_blob="x" * 70000)] + page[1:]
        headers = {}
        if after + per_page < len(sel):
            nq = dict(q, after=str(after + per_page))
            host = self.headers.get("Host")
            headers["Link"] = '<http://%s%s?%s>; rel="next"' % (host, u.path, urlencode(nq))
        self.reply(200, page, headers)


class Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--backfill", type=int, default=250, help="events spread over the last hour")
    p.add_argument("--live-every", type=float, default=0, help="seconds between new live events")
    p.add_argument("--faults", default="", help="comma list: 429,403rl,500,big")
    a = p.parse_args()
    FAULTS.extend(f for f in a.faults.split(",") if f)
    now = int(time.time())
    for i in range(a.backfill):
        add_event((now - 3600 + i * 3600 // max(a.backfill, 1)) * 1000 - 120000)
    if a.live_every:
        def live():
            while True:
                time.sleep(a.live_every)
                add_event(int(time.time() * 1000) - 90000)  # appears 90s after it happened
        threading.Thread(target=live, daemon=True).start()
    Server(("127.0.0.1", a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
