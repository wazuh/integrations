"""whisper_client — shared stdlib HTTP/TLS/auth client for the Whisper API.

Imported by BOTH the enrichment connector (custom-whisper.py, run per-alert by integratord)
and the analyst CLI (whisper-investigate.py, run on demand). It holds the load-bearing
operational knowledge that must live in exactly one place so it can never drift:
  - the non-default User-Agent — the API WAF 403s urllib's default `Python-urllib/x.y`;
  - the CA-bundle resolution — the Wazuh framework Python loads ZERO CAs by default, so a
    verifying context has to locate a real bundle itself;
  - the retry / Retry-After taxonomy and the Whisper* exception classes.

Both callers install into /var/ossec/integrations/, so this module is a sibling on
sys.path[0] at runtime — no path gymnastics. stdlib only (Python 3.10).

Logging is decoupled: `log_api` defaults to a no-op here; the connector overrides
`whisper_client.log_api` with its debug logger, and the CLI can point it at a verbose sink.
"""

import http.client
import ipaddress  # noqa: F401 — re-exported for callers that build on parse_ip's return type
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

# --- paths & constants --------------------------------------------------------------------
# Wazuh home is one level up from integrations/ (realpath so a symlinked install still
# resolves inside /var/ossec — the stock virustotal.py idiom).
_pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
KEY_FILE = f'{_pwd}/etc/whisper.key'
API_KEY_PLACEHOLDER = 'WHISPER_API_KEY_PLACEHOLDER'
DEFAULT_API_URL = 'https://graph.whisper.online'
DEFAULT_TIMEOUT = 10
DEFAULT_RETRIES = 3

API_QUERY_PATH = '/api/query'
CONNECTOR_VERSION = '1.0'
# Must NOT start with 'Python-urllib' — the Whisper API WAF blocks that default UA.
USER_AGENT = f'whisper-wazuh-connector/{CONNECTOR_VERSION}'
BACKOFF_BASE = 0.5
# A few seconds, not 60: the connector runs inside a SYNCHRONOUS integratord callout (one alert
# at a time, every other integration blocked behind it), so a long backoff sleep stalls the whole
# manager. Retry-After values above the cap are clamped to it.
BACKOFF_CAP = 5.0
# Common CA-bundle locations, tried when the interpreter's compiled-in paths are empty.
_CA_BUNDLE_CANDIDATES = (
    '/etc/ssl/certs/ca-certificates.crt',  # Debian/Ubuntu (Wazuh manager image)
    '/etc/pki/tls/certs/ca-bundle.crt',  # RHEL/CentOS
    '/etc/ssl/cert.pem',  # Alpine/BSD
)

_DOMAIN_RE = re.compile(
    r'^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+' r'(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$'
)


# --- error taxonomy (mirrors whisper-opencti; drives the `error class=` log line) ---------
class WhisperError(Exception):
    """Base for Whisper-boundary failures."""

    log_class = 'query'


class WhisperAuthError(WhisperError):
    """401/403 — terminal: the same key fails for every candidate, so stop the run."""

    log_class = 'auth'


class WhisperTransportError(WhisperError):
    """Network / 5xx / 429-after-retries — transient."""

    log_class = 'transport'


class WhisperDeadlineError(WhisperTransportError):
    """The caller's wall-clock budget ran out (before a request, during a backoff sleep, or — via
    the connector's SIGALRM hard ceiling — inside a stalled socket operation). A transport-class
    outage from the operator's point of view, but typed so callers can tell budget-exhaustion
    apart from an API error whose text happens to mention a deadline."""


class WhisperQueryError(WhisperError):
    """Other 4xx / malformed body — likely a caller bug."""

    log_class = 'query'


# --- logging hook (overridable) -----------------------------------------------------------
def log_api(url: str, ms: int) -> None:
    """No-op by default. The connector overrides this with its debug logger; the CLI may
    point it at a stderr/verbose sink. Keeping the client silent-by-default means importing
    it never writes to a log file the caller didn't ask for."""


# --- TLS / transport ----------------------------------------------------------------------
def _ssl_context() -> 'ssl.SSLContext':
    """A verifying TLS context that actually has CAs loaded, wherever the bundle lives.

    Resolution: the interpreter default → `SSL_CERT_FILE` → well-known bundle paths → the
    bundled `certifi` (ships with the framework Python). Verification stays ON throughout.
    """
    ctx = ssl.create_default_context()
    if ctx.get_ca_certs():
        return ctx
    candidates = [os.environ.get('SSL_CERT_FILE'), *_CA_BUNDLE_CANDIDATES]
    for path in candidates:
        if path and os.path.exists(path):
            try:
                ctx.load_verify_locations(path)
            except (ssl.SSLError, OSError):
                continue
            if ctx.get_ca_certs():  # an empty/placeholder PEM loads 0 certs without raising
                return ctx
    try:
        import certifi  # bundled with the Wazuh framework Python; last-resort only

        ctx.load_verify_locations(certifi.where())
    except (ImportError, ssl.SSLError, OSError):
        pass  # nothing found — verification will fail loudly (better than silently trusting all)
    return ctx


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects. urllib's default handler re-sends ALL request headers (X-API-Key
    is a custom header, so CPython's cross-origin Authorization-stripping does not cover it) on a
    3xx — including an https->http downgrade — which would leak the API key to the redirect
    target. Refusing to follow surfaces a 3xx as an HTTPError instead (handled below)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _http_post(url: str, body: dict, headers: dict, timeout: int) -> 'tuple[int, bytes, dict]':
    """Thin transport seam (tests monkeypatch this). Returns (status, raw, lower-cased headers).

    Generic POST-JSON: the connector uses it for /api/query, the CLI reuses it for the MCP
    JSON-RPC endpoint — same TLS context, same WAF-safe requirement on the caller's UA header,
    and redirects are never followed (the API key must not travel to a redirect target).
    """
    req = urllib.request.Request(url, data=json.dumps(body).encode('utf-8'), headers=headers, method='POST')
    handlers: list = [_NoRedirect()]
    if url.startswith('https'):
        handlers.append(urllib.request.HTTPSHandler(context=_ssl_context()))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as resp:  # noqa: S310 — https URL from config
            return resp.status, resp.read(), {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), {k.lower(): v for k, v in (exc.headers or {}).items()}


def _retry_after_seconds(headers: dict) -> 'float | None':
    value = headers.get('retry-after')
    if value is None:
        return None
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return None


def _remaining(deadline: 'float | None') -> 'float | None':
    """Seconds left before the caller's wall-clock deadline (a time.monotonic() stamp), or None
    when the caller set no deadline."""
    return None if deadline is None else deadline - time.monotonic()


def _effective_timeout(deadline: 'float | None', timeout: int) -> float:
    """The per-request socket timeout, shrunk to whatever is left of the deadline. Raises once the
    deadline has passed so a caller never starts a request it cannot finish in budget."""
    remaining = _remaining(deadline)
    if remaining is None:
        return timeout
    if remaining <= 0:
        raise WhisperDeadlineError('deadline exceeded before request')
    return max(0.1, min(timeout, remaining))


def _sleep_within(delay: float, deadline: 'float | None', after: str) -> None:
    """Back off for `delay` seconds (capped at BACKOFF_CAP) — but never past the deadline. If the
    sleep would consume the remaining budget, fail now rather than sleep and then fail anyway.
    `after` names what triggered the retry so the operator-facing error keeps its cause."""
    delay = min(delay, BACKOFF_CAP)
    remaining = _remaining(deadline)
    if remaining is not None and delay >= remaining:
        raise WhisperDeadlineError(f'deadline exceeded during backoff after {after}')
    time.sleep(delay)


def execute_query(
    api_url: str,
    api_key: 'str | None',
    cypher: str,
    params: 'dict | None' = None,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    deadline: 'float | None' = None,
) -> 'list[dict]':
    """POST one Cypher query to /api/query; return `rows` (list of dicts keyed by column name).

    Error taxonomy (drives the `error class=` log line):
      401/403                    → WhisperAuthError (terminal)
      429 / 5xx after retries    → WhisperTransportError (Retry-After honoured per attempt)
      network failure            → WhisperTransportError
      other 4xx / bad body       → WhisperQueryError

    `deadline` (an optional time.monotonic() stamp) bounds the WHOLE call, retries included: each
    request's socket timeout shrinks to what is left, and a retry that would sleep past the
    deadline raises WhisperTransportError instead of sleeping. This is what keeps a synchronous
    integratord callout to seconds when the API is slow or unreachable.
    """
    # An explicit User-Agent is REQUIRED: the Whisper API's WAF 403s urllib's default
    # `Python-urllib/x.y` UA (verified live 2026-07-11). Any non-default UA passes.
    headers = {'Content-Type': 'application/json', 'User-Agent': USER_AGENT}
    if api_key:
        headers['X-API-Key'] = api_key
    body: dict = {'query': cypher}
    if params:
        body['parameters'] = params
    url = f'{api_url}{API_QUERY_PATH}'

    attempt = 0
    while True:
        started = time.monotonic()
        try:
            status, raw, resp_headers = _http_post(url, body, headers, _effective_timeout(deadline, timeout))
        except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
            # http.client.HTTPException (BadStatusLine/IncompleteRead) is NOT an OSError —
            # catch it explicitly so a garbled response stays inside the retry budget and
            # the taxonomy instead of crashing with an unhandled traceback.
            log_api(api_url, int((time.monotonic() - started) * 1000))
            if attempt < retries:
                attempt += 1
                _sleep_within(BACKOFF_BASE * (2 ** (attempt - 1)), deadline, f'network error ({exc})')
                continue
            raise WhisperTransportError(f'network error after {retries} retries: {exc}') from exc
        log_api(api_url, int((time.monotonic() - started) * 1000))

        if status in (401, 403):
            raise WhisperAuthError(f'HTTP {status} from Whisper API')
        if status == 429 or status >= 500:
            if attempt < retries:
                attempt += 1
                delay = _retry_after_seconds(resp_headers)
                if delay is None:
                    delay = BACKOFF_BASE * (2 ** (attempt - 1))
                _sleep_within(delay, deadline, f'HTTP {status}')
                continue
            raise WhisperTransportError(f'HTTP {status} after {retries} retries')
        if status >= 400:
            raise WhisperQueryError(f'HTTP {status}: {raw[:500].decode("utf-8", "replace")}')

        try:
            parsed = json.loads(raw)
        except ValueError as exc:
            raise WhisperQueryError('non-JSON response body') from exc
        if parsed.get('success') is False:
            raise WhisperQueryError(str(parsed.get('error', 'unknown query error'))[:500])
        rows = parsed.get('rows')
        if not isinstance(rows, list):
            raise WhisperQueryError('malformed response: missing rows')
        return rows


# --- IOC primitives -----------------------------------------------------------------------
def _strip_port(value: str) -> str:
    """'1.2.3.4:56' → '1.2.3.4'; '[::1]:56' → '::1'; anything else unchanged."""
    if value.startswith('[') and ']' in value:
        return value[1 : value.index(']')]
    if value.count(':') == 1:
        host, _, port = value.partition(':')
        if '.' in host and port.isdigit():
            return host
    return value


def parse_ip(value: str) -> 'ipaddress.IPv4Address | ipaddress.IPv6Address | None':
    """The ipaddress object for a raw field value, or None when it isn't an IP.

    Strips an ip:port suffix and unwraps IPv4-mapped IPv6 (::ffff:a.b.c.d).
    """
    try:
        ip = ipaddress.ip_address(_strip_port(value))
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip


def classify_domain(value: str) -> 'str | None':
    """Normalize + validate a domain-hinted value; None when it isn't a plausible domain."""
    candidate = value.strip().rstrip('.').lower()
    if _DOMAIN_RE.match(candidate):
        return candidate
    return None


def extract_url_host(value: str) -> 'str | None':
    """Host component of an ABSOLUTE url; None for path-only values (nginx/apache logs)."""
    if '://' not in value:
        return None
    try:
        return urlsplit(value).hostname or None
    except ValueError:
        return None


# --- config resolution --------------------------------------------------------------------
def resolve_api_url(options: dict, environ: dict) -> str:
    """<options>.api_url → WHISPER_API_URL → default (mapping §2.3)."""
    for candidate in (options.get('api_url'), environ.get('WHISPER_API_URL')):
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip().rstrip('/')
    return DEFAULT_API_URL


def resolve_api_key(argv_key: str, environ: dict, key_file: 'str | None' = None) -> 'str | None':
    """WHISPER_API_KEY env → key file (640 root:wazuh) → argv_key; placeholder never counts.

    `key_file` defaults to the module global at CALL time so tests can monkeypatch KEY_FILE.
    """
    if key_file is None:
        key_file = KEY_FILE
    env_key = environ.get('WHISPER_API_KEY', '').strip()
    if env_key and env_key != API_KEY_PLACEHOLDER:
        return env_key
    try:
        with open(key_file) as f:
            file_key = f.read().strip()
        if file_key and file_key != API_KEY_PLACEHOLDER:
            return file_key
    except OSError:
        pass
    argv_key = (argv_key or '').strip()
    if argv_key and argv_key != API_KEY_PLACEHOLDER:
        return argv_key
    return None
