"""Minimal indexer REST client (standard library only).

Connection settings come from environment variables, optionally loaded from
an env file (default ``~/.config/wazuh_correlation_pack/indexer.env``):

    WCP_INDEXER_URL       e.g. https://127.0.0.1:9200 (default)
    WCP_INDEXER_USER      indexer user (required)
    WCP_INDEXER_PASSWORD  indexer password (required)
    WCP_CA_CERT           path to the indexer root CA (PEM); recommended
    WCP_TLS_SERVER_NAME   name to verify in the server certificate when it
                          differs from the URL host (e.g. through an SSH tunnel)
    WCP_INSECURE          "1" disables certificate verification (lab only)

Credentials are never printed; error messages include method, path and the
indexer's error type/reason only.
"""

import base64
import http.client
import json
import os
import ssl
import time
from urllib.parse import urlsplit

DEFAULT_ENV_FILE = os.path.join(os.path.expanduser("~"), ".config", "wazuh_correlation_pack", "indexer.env")


class ApiError(RuntimeError):
    def __init__(self, method, path, status, body):
        self.status = status
        self.body = body
        reason = ""
        if isinstance(body, dict) and "error" in body:
            err = body["error"]
            if isinstance(err, dict):
                reason = "%s: %s" % (err.get("type"), err.get("reason"))
            else:
                reason = str(err)
        RuntimeError.__init__(self, "%s %s -> HTTP %s %s" % (method, path, status, reason[:500]))


def load_env_file(path):
    """Read KEY=VALUE lines into os.environ (existing variables win)."""
    if not path or not os.path.isfile(path):
        return False
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            if k.startswith("export "):
                k = k[7:].strip()
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                v = v[1:-1]
            os.environ.setdefault(k, v)
    return True


class Client(object):
    def __init__(self, url=None, user=None, password=None, ca_cert=None, server_name=None, insecure=None,
                 timeout=60):
        url = url or os.environ.get("WCP_INDEXER_URL", "https://127.0.0.1:9200")
        user = user or os.environ.get("WCP_INDEXER_USER")
        password = password or os.environ.get("WCP_INDEXER_PASSWORD")
        if not user or not password:
            raise RuntimeError("indexer credentials missing: set WCP_INDEXER_USER and WCP_INDEXER_PASSWORD "
                               "(environment or %s)" % DEFAULT_ENV_FILE)
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise RuntimeError("WCP_INDEXER_URL must be https")
        self.host = parts.hostname
        self.port = parts.port or 9200
        self.base = parts.path.rstrip("/")
        self.timeout = timeout
        self._auth = "Basic " + base64.b64encode(("%s:%s" % (user, password)).encode("utf-8")).decode("ascii")
        insecure = insecure if insecure is not None else os.environ.get("WCP_INSECURE") == "1"
        ca_cert = ca_cert or os.environ.get("WCP_CA_CERT")
        self.server_name = server_name or os.environ.get("WCP_TLS_SERVER_NAME") or self.host
        if insecure:
            ctx = ssl._create_unverified_context()
        else:
            ctx = ssl.create_default_context(cafile=ca_cert) if ca_cert else ssl.create_default_context()
        self.ctx = ctx
        self.user = user

    def __repr__(self):
        return "Client(%s:%s user=%s)" % (self.host, self.port, self.user)

    def request(self, method, path, body=None, params=None, ok=(200, 201), raw=False):
        if params:
            from urllib.parse import urlencode
            path = path + ("&" if "?" in path else "?") + urlencode(params)
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self.ctx)
        if self.server_name != self.host:
            # verify the certificate against server_name while connecting to host (SSH tunnels)
            conn._tunnel_host = None
            sock_ctx = self.ctx

            def _connect(c=conn, name=self.server_name):
                import socket
                sock = socket.create_connection((c.host, c.port), c.timeout)
                c.sock = sock_ctx.wrap_socket(sock, server_hostname=name)
            conn.connect = _connect
        headers = {"Authorization": self._auth, "Accept": "application/json"}
        data = None
        if body is not None:
            if isinstance(body, (bytes, str)):
                data = body.encode("utf-8") if isinstance(body, str) else body
                headers["Content-Type"] = "application/x-ndjson"
            else:
                data = json.dumps(body).encode("utf-8")
                headers["Content-Type"] = "application/json"
        t0 = time.time()
        try:
            conn.request(method, self.base + path, body=data, headers=headers)
            resp = conn.getresponse()
            payload = resp.read()
        finally:
            conn.close()
        self.last_duration_ms = int((time.time() - t0) * 1000)
        text = payload.decode("utf-8", "replace")
        try:
            parsed = json.loads(text) if text else None
        except ValueError:
            parsed = text
        if resp.status not in ok:
            raise ApiError(method, path, resp.status, parsed)
        return text if raw else parsed

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self.request("POST", path, body=body, **kw)

    def put(self, path, body=None, **kw):
        return self.request("PUT", path, body=body, **kw)

    def delete(self, path, **kw):
        return self.request("DELETE", path, **kw)
