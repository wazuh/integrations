"""Isolated lab webhook receiver for the P5 notification test.

Records every request it receives (time, path, whether the path carries the run's token, selected
headers, body) and answers 200. Requests to other paths are recorded too but flagged
``path_ok: false`` and ignored by the attribution. It never forwards anything.

Bind it to an address the Wazuh indexer can reach (the Notifications plugin sends from the
indexer node) and that is not exposed beyond the lab network. Plain HTTP: the payloads are test
alerts only.

Stand-alone (e.g. to check reachability before the run, or to run it on another lab host):

    python tests/validation/webhook_listener.py --bind 0.0.0.0:8765 --token <random> --out received.jsonl
"""

import argparse
import datetime
import http.server
import json
import re
import threading

MAX_BODY = 1024 * 1024
HEADERS = ("Content-Type", "User-Agent", "Content-Length")


class Listener(object):
    def __init__(self, host, port, token, out=None):
        self.host, self.port, self.token, self.out = host, int(port), token, out
        self.records = []
        self.lock = threading.Lock()
        self.httpd = None
        listener = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _record(self):
                n = min(int(self.headers.get("Content-Length") or 0), MAX_BODY)
                body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
                rec = {"received": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                       "method": self.command, "path_ok": bool(listener.token) and listener.token in self.path,
                       "headers": {h: self.headers.get(h) for h in HEADERS if self.headers.get(h)},
                       "body": body}
                with listener.lock:
                    listener.records.append(rec)
                    if listener.out:
                        with open(listener.out, "a", encoding="utf-8") as fh:
                            fh.write(json.dumps(rec) + "\n")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"ok")

            do_POST = do_PUT = _record

            def log_message(self, *a):
                pass

        self.handler = Handler

    def start(self):
        self.httpd = http.server.ThreadingHTTPServer((self.host, self.port), self.handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()

    def snapshot(self):
        with self.lock:
            return list(self.records)


def message_text(body):
    """The notification text: the raw body, or the string inside a JSON body that holds it."""
    try:
        v = json.loads(body)
    except ValueError:
        return body
    stack = [v]
    while stack:
        x = stack.pop()
        if isinstance(x, str) and ("New:" in x or "Resolved:" in x):
            return x
        if isinstance(x, dict):
            stack.extend(x.values())
        elif isinstance(x, list):
            stack.extend(x)
    return body


def classify(body, monitor_names, ips):
    """Attribute one received body produced by the pack's default action message
    (wcp/alerting.py DEFAULT_MESSAGE): which monitor copy, and which source addresses appear on the
    ``New:`` and ``Resolved:`` lines. Unattributable bodies return monitor None."""
    text = message_text(body).replace("\\n", "\n")
    mon = sorted([m for m in monitor_names if m in text], key=len)
    # one name may contain another ("... NEW" in "... NEW+COMPLETED"): the longest match wins when
    # every other match is part of it; anything else is ambiguous
    pick = mon[-1] if mon and all(m in mon[-1] for m in mon) else None
    out = {"monitor": pick, "new": [], "completed": []}
    for line in text.splitlines():
        s = line.strip()
        kind = "new" if s.startswith("New:") else "completed" if s.startswith("Resolved:") else None
        if kind:
            out[kind] = sorted({ip for ip in ips if re.search(r"(?<![\d.])%s(?![\d])" % re.escape(ip), s)})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="127.0.0.1:8765")
    ap.add_argument("--token", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    host, port = a.bind.rsplit(":", 1)
    li = Listener(host, port, a.token, a.out).start()
    print("listening on %s:%d (path must contain the token); Ctrl+C to stop" % (host, li.port))
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        li.stop()


if __name__ == "__main__":
    main()
