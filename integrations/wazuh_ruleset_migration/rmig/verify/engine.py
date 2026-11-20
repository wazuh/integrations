"""Client of the Wazuh 5.x engine API on its unix socket (``verify --engine-socket``).

Contract (the engine's public API, as recorded on 5.0.0 rc2 and a 5.0.0 nightly, 2026-11-16): HTTP over a unix
socket, one request per connection.

* ``GET /status``: ``{"status": "OK", "spaces": {...}, "ioc": {<type>: {"available": bool, ...}}, ...}``;
* ``POST /content/validate/policy`` ``{"space", "load_in_tester", "full_policy"}``: ``{"status": "OK"}`` or HTTP 400
  ``{"status": "ERROR", "error": "..."}``;
* ``POST /logtest`` ``{"space", "queue", "location", "event", "trace_level"}``:
  ``{"status": "OK", "result": {"output": {...}, "asset_traces": [], "validation": {...}}}``;
* ``DELETE /logtest`` ``{"space"}``: ``{"status": "OK"}``.

The same API is served by the standalone engine package (``sockets/engine-api-http.sock``) and by the 5.0 manager
(``/var/wazuh-manager/queue/sockets/engine-api-http.sock``). Standard library only. ``AF_UNIX`` is looked up when a
connection opens, so the module imports on every platform.
"""

import http.client
import json
import re
import socket

SPACE_RE = re.compile(r"^[A-Za-z0-9_]+$")  # the engine refuses any other space name (recorded: validate-bad-space)
TIMEOUT = 300.0


class EngineError(Exception):
    """No usable answer: the socket is missing or refused, or the body is not the recorded shape."""


class NoUnixSockets(EngineError):
    pass


class Refused(EngineError):
    """The engine answered, with an error (its text is the message)."""


def unix_sockets_available():
    return hasattr(socket, "AF_UNIX")


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        family = getattr(socket, "AF_UNIX", None)
        if family is None:
            raise NoUnixSockets("this Python has no unix sockets")
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._path)
        self.sock = sock


def unix_transport(path):
    """``send(method, path, body bytes or None, timeout) -> (status, body bytes)``; one connection per call."""

    def send(method, url, body, timeout):
        conn = _UnixHTTPConnection(path, timeout)
        try:
            headers = {"Content-Type": "application/json"} if body is not None else {}
            conn.request(method, url, body=body, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    return send


class Answer:
    def __init__(self, status, raw):
        self.status = status
        self.text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else (raw or "")
        try:
            self.body = json.loads(self.text) if self.text else {}
        except ValueError:
            self.body = None

    @property
    def ok(self):
        return self.status == 200 and isinstance(self.body, dict) and self.body.get("status") == "OK"

    @property
    def error(self):
        if isinstance(self.body, dict) and self.body.get("error"):
            return str(self.body["error"])
        return "HTTP %d: %s" % (self.status, self.text[:300])


class EngineClient:
    """``transport`` is injectable: the tests replay recorded answers."""

    def __init__(self, socket_path, transport=None, timeout=TIMEOUT):
        self.socket_path = socket_path
        self.timeout = timeout
        self._send = transport or unix_transport(socket_path)

    def call(self, method, path, payload=None, timeout=None):
        body = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        try:
            status, raw = self._send(method, path, body, timeout or self.timeout)
        except NoUnixSockets:
            raise
        except (OSError, http.client.HTTPException) as exc:
            raise EngineError("%s %s: no answer from %s: %s" % (method, path, self.socket_path, exc))
        return Answer(status, raw)

    def status(self):
        return self.call("GET", "/status", timeout=30.0)

    def load_policy(self, space, full_policy):
        if not SPACE_RE.match(space or "") or space == "standard":
            raise ValueError("space %r: letters, digits and _ only, never 'standard'" % space)
        return self.call("POST", "/content/validate/policy",
                         {"space": space, "load_in_tester": True, "full_policy": full_policy})

    def logtest(self, space, event, location, queue=1):
        return self.call("POST", "/logtest", {"space": space, "queue": int(queue), "location": location,
                                              "event": event, "trace_level": "NONE"}, timeout=60.0)

    def delete_session(self, space):
        return self.call("DELETE", "/logtest", {"space": space}, timeout=60.0)


def output_of(answer):
    """The normalized event of a ``/logtest`` answer, or raise :class:`Refused` with the engine's text."""
    if not answer.ok:
        raise Refused(answer.error)
    out = (answer.body.get("result") or {}).get("output")
    if not isinstance(out, dict):
        raise Refused("logtest answer without result.output")
    return out
