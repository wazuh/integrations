"""Minimal HTTP client for the Wazuh indexer.

Standard library only. Basic authentication; TLS verified by default (system
trust store, or ``--ca``), ``--insecure`` only when asked. Credentials come
from ``WAZUH_INDEXER_USER``/``WAZUH_INDEXER_PASSWORD`` or a
``--credentials-file`` holding ``user:password``; they are kept in memory only
and never written to disk, to the log or to a report.

The HTTP modules are loaded through :func:`importlib.import_module` the first
time a request is sent, so importing :mod:`rmig` (``scan``, ``plan``,
``build``) never loads them.

Known traps: a 200 answer whose ``_shards.failed`` is greater than 0 is an
error; 429 is retried with an exponential wait, at most :data:`RETRY_BUDGET`
seconds per call (the Content Manager serialises creates with a lock, retries
it 20 times at 100 ms and then answers 429). A redirect is never followed: the
indexer API does not redirect, and following one would send the credentials to
another host. A URL with user information is refused; only ``http`` and
``https`` are accepted.
"""

import base64
import importlib
import json
import os
import time

ENV_URL = "WAZUH_INDEXER_URL"
ENV_USER = "WAZUH_INDEXER_USER"
ENV_PASSWORD = "WAZUH_INDEXER_PASSWORD"
BODY_LIMIT = 2000
RETRY_BUDGET = 30.0  # seconds of waiting on 429 per call, Retry-After included
RETRY_FIRST = 0.5
RETRY_MAX_WAIT = 8.0


class ApiError(Exception):
    """A non-2xx answer (or a 2xx with failed shards). Carries method, path,
    HTTP status and the server's body; never the credentials."""

    def __init__(self, method, path, status, body):
        self.method = method
        self.path = path
        self.status = status
        self.body = body
        text = body if isinstance(body, str) else json.dumps(body, sort_keys=True, ensure_ascii=False)
        if len(text) > BODY_LIMIT:
            text = text[:BODY_LIMIT] + "..."
        super().__init__("%s %s -> HTTP %s: %s" % (method, path, status, text))

    @property
    def server_message(self):
        if isinstance(self.body, dict):
            msg = self.body.get("message", self.body.get("error"))
            if msg is not None:
                return msg if isinstance(msg, str) else json.dumps(msg, sort_keys=True, ensure_ascii=False)
        return self.body if isinstance(self.body, str) else json.dumps(self.body, sort_keys=True, ensure_ascii=False)


class ConnectionFailed(Exception):
    """The indexer cannot be reached (DNS, TCP, TLS, timeout)."""


class CredentialsError(Exception):
    pass


class RedirectRefused(ConnectionFailed):
    """The indexer answered a 3xx: never followed."""


def check_url(url):
    """Raise :class:`CredentialsError` unless ``url`` is ``http(s)://host[:port][/path]`` with no user
    information. The message never repeats the URL (it could hold a password)."""
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url)
    except ValueError:
        raise CredentialsError("the indexer URL cannot be read")
    if parts.scheme.lower() not in ("http", "https"):
        raise CredentialsError("the indexer URL must start with https:// (or http://), not %r" % (parts.scheme + ":"))
    if "@" in parts.netloc:
        raise CredentialsError("the indexer URL must not hold a user or a password: use %s and %s, or "
                               "--credentials-file" % (ENV_USER, ENV_PASSWORD))
    if not parts.hostname:
        raise CredentialsError("the indexer URL has no host")
    return url


def strip_userinfo(url):
    """``url`` without ``user:password@`` (for any message)."""
    scheme, sep, rest = (url or "").partition("://")
    if not sep:
        return url
    host, slash, path = rest.partition("/")
    return "%s://%s%s%s" % (scheme, host.rsplit("@", 1)[-1], slash, path)


def transport_warnings(url, insecure):
    """The warnings to print before the first call."""
    out = []
    if url.lower().startswith("http://"):
        out.append("WARNING: %s is plain http: the password and every answer travel in clear text" % strip_userinfo(url))
    if insecure:
        out.append("WARNING: --insecure: the indexer certificate is not checked; anyone on the path can read the "
                   "password")
    return out


def _net():
    names = ("urllib.request", "urllib.error", "urllib.parse", "ssl")
    return [importlib.import_module(n) for n in names]


def resolve_connection(url=None, credentials_file=None, env=None):
    """``(url, user, password)`` from the arguments and the environment.

    Raises :class:`CredentialsError` naming what is missing (never a value)."""
    env = os.environ if env is None else env
    url = url or env.get(ENV_URL)
    if not url:
        raise CredentialsError("no indexer URL: pass --url or set %s" % ENV_URL)
    check_url(url)
    if credentials_file:
        try:
            with open(credentials_file, "r", encoding="utf-8") as fh:
                line = fh.readline().rstrip("\r\n")
        except OSError as exc:
            raise CredentialsError("cannot read the credentials file %s: %s" % (credentials_file, exc.strerror))
        user, sep, secret = line.partition(":")
        if not sep or not user:
            raise CredentialsError("the credentials file %s must hold one line user:password" % credentials_file)
        return url, user, secret
    user = env.get(ENV_USER)
    secret = env.get(ENV_PASSWORD)
    if not user or secret is None:
        raise CredentialsError("no credentials: set %s and %s, or pass --credentials-file" % (ENV_USER, ENV_PASSWORD))
    return url, user, secret


class Client:
    def __init__(self, url, user, secret, ca=None, insecure=False, timeout=60, retries=10, sleep=time.sleep,
                 retry_budget=RETRY_BUDGET):
        self.base = strip_userinfo(url).rstrip("/")
        self.user = user
        self._auth = "Basic " + base64.b64encode(("%s:%s" % (user, secret)).encode("utf-8")).decode("ascii")
        self.ca = ca
        self.insecure = insecure
        self.timeout = timeout
        self.retries = retries
        self.sleep = sleep
        self.retry_budget = retry_budget
        self._ctx = None
        self._opener = None
        self.calls = 0

    def __repr__(self):
        return "Client(%s, user=%s)" % (self.base, self.user)

    def _context(self, ssl):
        if self._ctx is None:
            if self.insecure:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            else:
                ctx = ssl.create_default_context(cafile=self.ca) if self.ca else ssl.create_default_context()
            self._ctx = ctx
        return self._ctx

    def _open(self, request_mod, ssl, req):
        if self._opener is None:

            class NoRedirect(request_mod.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    raise RedirectRefused("%s %s: the indexer answered HTTP %s (a redirect); redirects are never "
                                          "followed, so the credentials stay with %s" % (
                                              req.get_method(), req.selector, code, req.host))

            handlers = [NoRedirect()]
            if self.base.lower().startswith("https:"):
                handlers.append(request_mod.HTTPSHandler(context=self._context(ssl)))
            self._opener = request_mod.build_opener(*handlers)
        return self._opener.open(req, timeout=self.timeout)

    def call(self, method, path, body=None, params=None):
        """Send one request; returns ``(status, parsed body)``. Retries 429 with an exponential wait, at most
        ``retry_budget`` seconds in all. Never follows a redirect (:class:`RedirectRefused`)."""
        request_mod, error_mod, parse_mod, ssl = _net()
        full = path
        if params:
            full = path + "?" + parse_mod.urlencode(sorted(params.items()))
        data = None
        headers = {"Authorization": self._auth, "Accept": "application/json"}
        if body is not None:
            data = json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        attempt = 0
        waited = 0.0
        while True:
            attempt += 1
            self.calls += 1
            req = request_mod.Request(self.base + full, data=data, method=method, headers=headers)
            retry_after = None
            try:
                with self._open(request_mod, ssl, req) as resp:
                    status, raw = resp.status, resp.read()
            except error_mod.HTTPError as exc:
                status, raw = exc.code, exc.read()
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
            except (error_mod.URLError, OSError) as exc:
                reason = getattr(exc, "reason", exc)
                raise ConnectionFailed("%s %s: cannot reach the indexer at %s: %s" % (method, path, self.base, reason))
            parsed = _parse(raw)
            if status == 429 and attempt <= self.retries:
                wait = min(RETRY_MAX_WAIT, RETRY_FIRST * 2 ** (attempt - 1))
                if retry_after:
                    try:
                        wait = max(wait, float(int(retry_after)))
                    except ValueError:
                        pass
                wait = min(wait, self.retry_budget - waited)
                if wait > 0:
                    self.sleep(wait)
                    waited += wait
                    continue
            return status, parsed

    def request(self, method, path, body=None, params=None, ok_missing=False):
        """Like :meth:`call`, raising :class:`ApiError` on an error answer.
        ``ok_missing`` returns ``None`` on 404 instead."""
        status, parsed = self.call(method, path, body, params)
        if status == 404 and ok_missing:
            return None
        if status >= 300:
            raise ApiError(method, path, status, parsed)
        if isinstance(parsed, dict):
            shards = parsed.get("_shards")
            if isinstance(shards, dict) and (shards.get("failed") or 0) > 0:
                raise ApiError(method, path, status, parsed)
        return parsed


def _parse(raw):
    if not raw:
        return {}
    text = raw.decode("utf-8", "replace")
    try:
        return json.loads(text)
    except ValueError:
        return text
