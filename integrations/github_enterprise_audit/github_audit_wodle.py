#!/usr/bin/env python3
"""
GitHub audit log -> Wazuh agent queue socket.

Works with GitHub.com and GitHub Enterprise Cloud with data residency
(GHE.com, api.<subdomain>.ghe.com). Each audit event is sent straight to the
local Wazuh agent's queue socket (/var/ossec/queue/sockets/queue), exactly
like the native Wazuh GitHub module does:

    1:github:{"integration":"github","github":{ ...original audit event... }}

so the built-in ruleset (0750-github_rules.xml, rules 91100-91449) applies
unchanged and events show location "github", as with the native module.

Run it with the agent's command wodle (recommended) or any scheduler, as root
on a host with a running Wazuh agent. Edit the CONFIG block below (or pass the
same settings as command-line options), then add to the agent's ossec.conf:

  <wodle name="command">
    <disabled>no</disabled>
    <tag>github-audit</tag>
    <command>/usr/bin/python3 /var/ossec/wodles/github-audit/github_audit_wodle.py</command>
    <interval>5m</interval>
    <run_on_start>yes</run_on_start>
    <timeout>300</timeout>
    <ignore_output>yes</ignore_output>
  </wodle>

Manual test without sending anything to Wazuh (prints the events instead):

  python3 github_audit_wodle.py --dry-run --initial-lookback 60 --log-stderr \
      --state-file /tmp/github-test.json

Requires Python 3.6+ standard library only.
"""

# ==========================================================================
# CONFIG - edit these values
# ==========================================================================
CONFIG = {
    # REST API base. GHE.com: https://api.<subdomain>.ghe.com  (e.g. https://api.example.ghe.com)
    "api_url": "https://api.github.com",
    # Set ONE of these: enterprise slug (enterprise audit log) or organization name.
    "enterprise": "CHANGE_ME",
    "org": "",
    # Token of an enterprise owner (classic PAT scope: read:audit_log).
    # Prefer token_file (chmod 600, owned by root). "token" is used if token_file is empty.
    "token_file": "/var/ossec/wodles/github-audit/token",
    "token": "",
    # Audit event types: "web", "git" or "all" (git events are high-volume).
    "include": "web",
    # Wazuh agent queue socket and the location name events are tagged with.
    "queue_socket": "/var/ossec/queue/sockets/queue",
    "location": "github",
    # Events per second sent to the agent (the native module uses wazuh_modules.max_eps,
    # default 100). Keep it at or below the agent's <client_buffer> events_per_second.
    "max_eps": 100,
    # Where the bookmark and the script's own log are kept.
    "state_file": "/var/ossec/wodles/github-audit/state.json",
    "log_file": "/var/ossec/logs/github_audit_wodle.log",
    # Minutes of history fetched on the very first run (0 = only new events).
    "initial_lookback": 0,
    # Seconds behind "now" each window ends (audit log indexing lag).
    "delay": 60,
    # Seconds each run re-reads before the bookmark; repeats are de-duplicated.
    "overlap": 600,
    # Per-run limits. Keep max_runtime below the wodle <timeout>; anything not
    # collected within the limits is picked up by the next run.
    "max_runtime": 240,
    "max_events": 20000,
    # HTTP
    "timeout": 60,
    "retries": 3,
}
# ==========================================================================

import argparse
import errno
import fcntl
import hashlib
import json
import logging
import logging.handlers
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

VERSION = "2.0.0"
API_VERSION = "2022-11-28"
PER_PAGE = 100
MAX_EVENT_BYTES = 60000      # Wazuh limit is 65535 bytes per message incl. header
ESSENTIAL_FIELDS = (
    "@timestamp", "_document_id", "action", "actor", "actor_id", "actor_ip",
    "actor_location", "business", "business_id", "created_at", "enterprise",
    "operation_type", "org", "org_id", "repo", "repository", "user",
    "user_id", "team", "visibility", "permission", "transport_protocol_name",
    "repository_public", "external_identity_nameid", "programmatic_access_type",
    "token_scopes", "hashed_token", "user_agent", "country_code",
)
FAILURE_ALERT_AT = 3       # same threshold as the native module (rule 91448)
FAILURE_ALERT_EVERY = 12   # repeat every N further consecutive failures

log = logging.getLogger("github-audit-wodle")


class CollectorError(Exception):
    pass


class BudgetExhausted(Exception):
    pass


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def iso(ts):
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def event_epoch(ev):
    for key in ("@timestamp", "created_at"):
        val = ev.get(key)
        if isinstance(val, (int, float)):
            return val / 1000.0 if val > 1e11 else float(val)
    return None


def event_id(ev):
    doc_id = ev.get("_document_id")
    if doc_id:
        return str(doc_id)
    raw = json.dumps(ev, sort_keys=True, separators=(",", ":")).encode()
    return "sha1:" + hashlib.sha1(raw).hexdigest()


def to_json(ev):
    msg = json.dumps({"integration": "github", "github": ev},
                     separators=(",", ":"), ensure_ascii=False)
    if len(msg.encode("utf-8")) <= MAX_EVENT_BYTES:
        return msg
    slim = {k: ev[k] for k in ESSENTIAL_FIELDS if k in ev}
    slim["wazuh_truncated"] = True
    log.warning("event %s exceeds %d bytes, sending essential fields only",
                event_id(ev), MAX_EVENT_BYTES)
    return json.dumps({"integration": "github", "github": slim},
                      separators=(",", ":"), ensure_ascii=False)


def parse_next_link(header):
    if not header:
        return None
    for part in header.split(","):
        m = re.match(r'\s*<([^>]+)>\s*;\s*rel="next"', part)
        if m:
            return m.group(1)
    return None


# --------------------------------------------------------------------------
# Wazuh queue
# --------------------------------------------------------------------------
class WazuhQueue(object):
    """Sends events to the agent queue socket ("1:<location>:<event>"),
    throttled to max_eps, and tracks the per-run budget."""

    def __init__(self, path, location, max_eps, max_events, dry_run=False):
        self.path = path
        self.header = "1:%s:" % location
        self.interval = 1.0 / max_eps if max_eps > 0 else 0
        self.max_events = max_events
        self.dry_run = dry_run
        self.count = 0
        self._next = 0.0
        self.sock = None

    def connect(self):
        if self.dry_run:
            return
        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self.sock.connect(self.path)
        except OSError as exc:
            self.sock = None
            raise CollectorError("cannot connect to Wazuh queue %s (is the agent running?): %s"
                                 % (self.path, exc))

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def full(self):
        return self.count >= self.max_events

    def send(self, msg):
        # throttle
        now = time.time()
        if now < self._next:
            time.sleep(self._next - now)
        self._next = max(now, self._next) + self.interval

        if self.dry_run:
            sys.stdout.write(self.header + msg + "\n")
            self.count += 1
            return

        data = (self.header + msg).encode("utf-8")
        for attempt in range(20):
            try:
                self.sock.send(data)
                self.count += 1
                return
            except OSError as exc:
                if exc.errno in (errno.ENOBUFS, errno.EAGAIN, errno.EWOULDBLOCK) and attempt < 19:
                    time.sleep(0.1 * (attempt + 1))  # socket buffer full, back off
                    continue
                if exc.errno in (errno.ECONNREFUSED, errno.ENOENT, errno.ENOTCONN):
                    raise CollectorError("Wazuh queue not available (is the agent running?): %s" % exc)
                if exc.errno == errno.EMSGSIZE:
                    log.error("event too large for the socket buffer, dropped")
                    return
                raise CollectorError("cannot send to Wazuh queue: %s" % exc)


# --------------------------------------------------------------------------
# state
# --------------------------------------------------------------------------
class State(object):
    def __init__(self, path):
        self.path = path
        self.last_end = None
        self.seen = {}
        self.failures = 0
        if os.path.exists(path):
            try:
                with open(path) as fh:
                    data = json.load(fh)
                self.last_end = data.get("last_end")
                self.seen = data.get("seen", {})
                self.failures = int(data.get("failures", 0))
            except (ValueError, OSError) as exc:
                raise CollectorError("cannot read state file %s: %s" % (path, exc))

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump({"version": VERSION, "last_end": self.last_end,
                       "last_end_iso": iso(self.last_end) if self.last_end else None,
                       "failures": self.failures, "seen": self.seen}, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def prune(self, keep_after):
        self.seen = {k: v for k, v in self.seen.items() if v is None or v >= keep_after}


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
class GitHubClient(object):
    def __init__(self, api_url, token, timeout, retries, deadline):
        self.api = urllib.parse.urlsplit(api_url)
        self.token = token
        self.timeout = timeout
        self.retries = retries
        self.deadline = deadline

    def same_host(self, url):
        u = urllib.parse.urlsplit(url)
        return (u.scheme, u.netloc.lower()) == (self.api.scheme, self.api.netloc.lower())

    def _sleep(self, seconds, why):
        if time.time() + seconds >= self.deadline:
            raise BudgetExhausted("%s, wait of %ds exceeds the run time budget" % (why, seconds))
        log.warning("%s, sleeping %ds", why, seconds)
        time.sleep(seconds)

    def get(self, url):
        attempt = 0
        while True:
            attempt += 1
            remaining = self.deadline - time.time()
            if remaining <= 1:
                raise BudgetExhausted("run time budget reached")
            req = urllib.request.Request(url, headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "wazuh-github-audit-wodle/" + VERSION,
            })
            try:
                with urllib.request.urlopen(req, timeout=min(self.timeout, remaining)) as resp:
                    body = resp.read()
                    return json.loads(body.decode("utf-8") or "[]"), resp.headers
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", "replace")[:500]
                wait = self._rate_limit_wait(exc)
                if wait is not None:
                    self._sleep(wait, "rate limited (HTTP %s)" % exc.code)
                    continue
                if exc.code >= 500 and attempt <= self.retries:
                    self._sleep(min(30, 2 ** attempt), "HTTP %s from GitHub, retry %d" % (exc.code, attempt))
                    continue
                raise CollectorError("HTTP %s: %s" % (exc.code, body))
            except (urllib.error.URLError, OSError, ValueError) as exc:
                if attempt <= self.retries:
                    self._sleep(min(30, 2 ** attempt), "request failed (%s), retry %d" % (exc, attempt))
                    continue
                raise CollectorError("request failed: %s" % exc)

    @staticmethod
    def _rate_limit_wait(exc):
        if exc.code not in (403, 429):
            return None
        hdr = exc.headers
        if hdr.get("Retry-After"):
            try:
                return max(1, int(hdr.get("Retry-After")))
            except ValueError:
                return 60
        if hdr.get("X-RateLimit-Remaining") == "0" and hdr.get("X-RateLimit-Reset"):
            try:
                return max(1, int(hdr.get("X-RateLimit-Reset")) - int(time.time()) + 1)
            except ValueError:
                return 60
        if exc.code == 429:
            return 60
        return None  # plain 403 = permissions, do not retry


# --------------------------------------------------------------------------
# collection
# --------------------------------------------------------------------------
def build_url(cfg, start, end):
    base = cfg.api_url.rstrip("/")
    if cfg.enterprise:
        path = "/enterprises/%s/audit-log" % urllib.parse.quote(cfg.enterprise, safe="")
    else:
        path = "/orgs/%s/audit-log" % urllib.parse.quote(cfg.org, safe="")
    query = urllib.parse.urlencode({
        "phrase": "created:%s..%s" % (iso(start), iso(end)),
        "include": cfg.include,
        "order": "asc",
        "per_page": PER_PAGE,
    })
    return base + path + "?" + query


def collect(cfg, state, client, queue):
    end = int(time.time()) - cfg.delay
    if state.last_end is None:
        if cfg.initial_lookback <= 0:
            state.last_end = end
            log.info("first run: bookmark set to %s, only newer events will be collected", iso(end))
            return
        start = end - cfg.initial_lookback * 60
    else:
        start = int(state.last_end) - cfg.overlap

    if start >= end:
        log.info("nothing to do (window %s..%s)", iso(start), iso(end))
        return

    url = build_url(cfg, start, end)
    log.info("collecting %s..%s", iso(start), iso(end))
    dupes = pages = 0
    newest = None
    complete = False
    try:
        while url:
            data, headers = client.get(url)
            pages += 1
            if not isinstance(data, list):
                raise CollectorError("unexpected API response: %s" % json.dumps(data)[:300])
            for ev in data:
                if not isinstance(ev, dict):
                    continue
                eid = event_id(ev)
                if eid in state.seen:
                    dupes += 1
                    continue
                if queue.full():
                    raise BudgetExhausted("per-run event limit reached (%d events)" % queue.count)
                if time.time() >= client.deadline:
                    raise BudgetExhausted("run time budget reached")
                queue.send(to_json(ev))
                ts = event_epoch(ev)
                state.seen[eid] = ts or end
                if ts and (newest is None or ts > newest):
                    newest = ts
            # events are delivered as they are sent: persist progress per page
            state.save()
            nxt = parse_next_link(headers.get("Link"))
            if nxt and not client.same_host(nxt):
                raise CollectorError("refusing pagination link to another host: %s" % nxt)
            url = nxt
        complete = True
    except BudgetExhausted as exc:
        log.warning("%s; the rest of the window is collected on the next run", exc)
    finally:
        if complete:
            state.last_end = end
        elif newest is not None and newest > (state.last_end or 0):
            # events arrive in ascending order: resume from the newest one sent
            state.last_end = int(newest)
        if state.last_end is not None:
            state.prune(state.last_end - cfg.overlap - 300)
        log.info("%s: %d new events sent, %d duplicates skipped, %d page(s), bookmark %s",
                 "done" if complete else "partial", queue.count, dupes, pages,
                 iso(state.last_end) if state.last_end else "-")


def failure_json(cfg, message):
    ev = {"actor": "wazuh", "organization": cfg.enterprise or cfg.org or "unknown",
          "event_type": cfg.include, "response": message[:2000]}
    return json.dumps({"integration": "github", "github": ev}, separators=(",", ":"))


def report_failure(cfg, queue, message):
    """Send an internal event (rule 91448). Best effort: the queue may be the problem."""
    try:
        if queue.sock is None:
            queue.connect()
        queue.send(failure_json(cfg, message))
    except CollectorError as exc:
        log.error("could not send failure event to Wazuh: %s", exc)


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------
def parse_args(argv):
    p = argparse.ArgumentParser(description="GitHub audit log collector that sends events to the "
                                            "local Wazuh agent. Defaults come from the CONFIG block.")
    for key in ("api_url", "enterprise", "org", "token_file", "state_file", "log_file",
                "queue_socket", "location"):
        p.add_argument("--" + key.replace("_", "-"), dest=key, default=CONFIG[key])
    p.add_argument("--include", choices=("web", "git", "all"), default=CONFIG["include"])
    for key in ("initial_lookback", "delay", "overlap", "max_runtime", "max_events",
                "max_eps", "timeout", "retries"):
        p.add_argument("--" + key.replace("_", "-"), dest=key, type=int, default=CONFIG[key])
    p.add_argument("--dry-run", action="store_true",
                   help="print events to stdout instead of sending them to Wazuh")
    p.add_argument("--log-stderr", action="store_true", help="also log to stderr (manual runs)")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--version", action="version", version=VERSION)
    return p.parse_args(argv)


def setup_logging(cfg):
    log.setLevel(logging.DEBUG if cfg.debug else logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    try:
        d = os.path.dirname(os.path.abspath(cfg.log_file))
        if not os.path.isdir(d):
            os.makedirs(d, mode=0o750)
        fh = logging.handlers.RotatingFileHandler(cfg.log_file, maxBytes=5 * 1024 * 1024, backupCount=3)
        fh.setFormatter(fmt)
        log.addHandler(fh)
    except OSError:
        pass
    if cfg.log_stderr:
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(fmt)
        log.addHandler(sh)
    if not log.handlers:
        log.addHandler(logging.NullHandler())


def validate(cfg):
    if cfg.enterprise == "CHANGE_ME":
        cfg.enterprise = ""
    if bool(cfg.enterprise) == bool(cfg.org):
        raise CollectorError("set exactly one of 'enterprise' or 'org' in CONFIG")
    if urllib.parse.urlsplit(cfg.api_url).scheme not in ("https", "http"):
        raise CollectorError("invalid api_url %r" % cfg.api_url)
    token = ""
    if cfg.token_file and os.path.exists(cfg.token_file):
        with open(cfg.token_file) as fh:
            token = fh.read().strip()
    token = token or CONFIG.get("token", "").strip() or os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        raise CollectorError("no token: create %s or set CONFIG['token']" % cfg.token_file)
    return token


def main(argv=None):
    cfg = parse_args(argv if argv is not None else sys.argv[1:])
    setup_logging(cfg)
    started = time.time()
    queue = WazuhQueue(cfg.queue_socket, cfg.location, cfg.max_eps, cfg.max_events, cfg.dry_run)

    try:
        token = validate(cfg)
        d = os.path.dirname(os.path.abspath(cfg.state_file))
        if not os.path.isdir(d):
            os.makedirs(d, mode=0o750)
    except (CollectorError, OSError) as exc:
        log.error("configuration error: %s", exc)
        report_failure(cfg, queue, "configuration error: %s" % exc)
        return 2

    lock_fh = open(cfg.state_file + ".lock", "w")
    try:
        fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        log.warning("previous run still in progress, skipping")
        return 0

    try:
        state = State(cfg.state_file)
    except CollectorError as exc:
        log.error("%s", exc)
        report_failure(cfg, queue, str(exc))
        return 2

    client = GitHubClient(cfg.api_url, token, cfg.timeout, cfg.retries, started + cfg.max_runtime)
    rc = 0
    try:
        queue.connect()
        collect(cfg, state, client, queue)
        if state.failures:
            log.info("recovered after %d failed run(s)", state.failures)
        state.failures = 0
    except Exception as exc:
        if not isinstance(exc, CollectorError):
            log.exception("unexpected error")
            exc = CollectorError("unexpected error: %s" % exc)
        rc = 1
        state.failures += 1
        log.error("run failed (%d consecutive): %s", state.failures, exc)
        n = state.failures
        if n == FAILURE_ALERT_AT or (n > FAILURE_ALERT_AT and (n - FAILURE_ALERT_AT) % FAILURE_ALERT_EVERY == 0):
            report_failure(cfg, queue, str(exc))
    finally:
        state.save()
        queue.close()
        sys.stdout.flush()
    return rc


if __name__ == "__main__":
    sys.exit(main())
