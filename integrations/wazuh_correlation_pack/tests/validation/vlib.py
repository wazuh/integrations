"""Shared library of the RC2 validation tests P1-P6 (docs/VALIDATION_TESTS.md).

Safety model - every live test is **disabled by default** and runs only when all of these hold:

1. ``--live`` is given on the command line (without it the test prints its plan: inputs and
   expected results, computed offline, status ``NOT EXECUTED``);
2. a lab configuration file is given (``--lab-config`` or ``WCP_LAB_CONFIG``; template
   ``tests/validation/lab.example.yml``) with ``enabled: true`` and the test listed in
   ``tests_enabled``;
3. the indexer the credentials point at reports the ``cluster.cluster_uuid`` written in that file;
4. no pack monitor on that cluster has a content hash of the 5.0.0-rc1 reference deployment
   (``REFERENCE_DEPLOYMENT_HASHES``), so the RC1 reference server is refused even if configured;
5. tests that create cluster resources need ``allow.create_resources: true``; the indexer
   restart of P6 part b needs ``allow.restart_indexer: true``.

Endpoint roles (``linux_replay``, ``linux_source``, ``windows``, ``server``) are aliases. When one
VM serves several roles, its aliases carry the same ``machine`` label; the harness verifies the
machine identity behind every alias, records distinct machines (not aliases) in the evidence, and
holds a lock on each machine for the whole test, so tests sharing a machine run one at a time.

The lab configuration holds no credentials: indexer credentials come from the ``wcp`` env file
(wcp/client.py), SSH authentication from the user's SSH agent or keys.

Every temporary cluster resource is named ``[wcp-test] ...`` (monitors, channel) or
``wcp-test-*`` / ``wcp_p4_*`` (indices, role, user) and is deleted in a ``finally`` block, with
the deletion verified and recorded.
"""

import argparse
import base64
import copy
import datetime
import hashlib
import json
import os
import shlex
import socket
import subprocess
import sys
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.abspath(os.path.join(HERE, "..", ".."))
for _p in (PACK, os.path.join(PACK, "tests", "lab"), os.path.join(PACK, "tests", "api")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import yaml  # noqa: E402

from wcp import alerting as A  # noqa: E402
from wcp import config as C  # noqa: E402
from wcp import deploy as D  # noqa: E402
from wcp import identity as IDN  # noqa: E402
from wcp import sigma as S  # noqa: E402
from wcp.client import DEFAULT_ENV_FILE, ApiError, Client, load_env_file  # noqa: E402

# Detection baseline the harness validates: 6ee2300 (failed-target realm only from user.target.domain,
# d090875, plus unknown-realm counting). Earlier baselines: 38ad481 (evidence/2026-11-22-rc2/, Windows
# spray 0603b54f3c657714) and d090875 (evidence/2026-11-22-rc2-candidate/, 4564e84945edcf3a).
FROZEN_COMMIT = "6ee23001184108654b461bdff9347a6d1325dc5c"
FROZEN_CONTENT_HASHES = {
    "wcp_ssh_bruteforce": "007c0a436059d016",
    "wcp_ssh_password_spray": "172cc43b9dfcc25c",
    "wcp_windows_failed_logon_burst": "d31fc5d758665c2e",
    "wcp_windows_password_spray": "98f4090ad6dfc58f",
}
# Pack monitors as applied from 25e52cc on the 5.0.0-rc1 reference server (kept unchanged there).
REFERENCE_DEPLOYMENT_HASHES = {"409a902d80326aad": "wcp_windows_password_spray from 25e52cc (RC1 reference server)"}

MON = D.MONITORS
EVENTS_INDEX = "wazuh-events-v5-system-activity"
TEST_NAME_PREFIX = "[wcp-test] "
TEST_INDEX_PREFIX = "wcp-test-"
DUMMY_PASSWORD = "wcp-not-a-password"   # never a real credential; target accounts do not exist or are locked


class NotEnabled(Exception):
    """The live test is not enabled; the plan is printed instead."""


class Refused(Exception):
    """Enabled, but the target does not pass a safety check."""


# ------------------------------------------------------------------ time helpers

def utc():
    return datetime.datetime.now(datetime.timezone.utc)


def iso(dt):
    return None if dt is None else dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def ms(dt):
    return int(dt.timestamp() * 1000)


def from_ms(v):
    return None if v is None else datetime.datetime.fromtimestamp(v / 1000.0, datetime.timezone.utc)


def ms_iso(v):
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return iso(from_ms(v))
    return v


def parse_iso(s):
    if s is None:
        return None
    s = s.strip().replace("Z", "+00:00")
    if "." in s:
        head, rest = s.split(".", 1)
        i = 0
        while i < len(rest) and rest[i].isdigit():   # only the fraction digits, not the offset's
            i += 1
        s = "%s.%s%s" % (head, (rest[:i] + "000000")[:6], rest[i:])
    dt = datetime.datetime.fromisoformat(s)
    if dt.tzinfo is None:                            # naive input is UTC, never the workstation's zone
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def sleep_until(t, poll=None, every=2.0):
    last = 0.0
    while True:
        left = (t - utc()).total_seconds()
        if left <= 0:
            return
        if poll and time.time() - last >= every:
            poll()
            last = time.time()
        time.sleep(min(left, 0.5))


# ------------------------------------------------------------------ pack content

def pack_content():
    _rules, corrs = S.load_content(PACK)
    prof = C.load_profile(os.path.join(PACK, "pack.yml"))
    return {c.name: c for c in corrs}, prof


def harness_revision():
    """HEAD of the checkout the test runs from, and whether tests/ or the detection files differ from it."""
    def git(*a):
        try:
            r = subprocess.run(["git"] + list(a), cwd=PACK, capture_output=True, text=True, timeout=30)
            return r.stdout.strip() if r.returncode == 0 else None
        except (OSError, subprocess.SubprocessError):
            return None
    return {"head": git("rev-parse", "HEAD"),
            "uncommitted_changes_in_pack": bool(git("status", "--porcelain", "--", ".")),
            "detection_files_differ_from_frozen": bool(git("diff", "--name-only", FROZEN_COMMIT, "--",
                                                           "wcp", "rules", "correlations", "pack.yml")),
            "frozen_detection_commit": FROZEN_COMMIT}


# ------------------------------------------------------------------ lab configuration and gate

def load_lab_config(path=None):
    path = path or os.environ.get("WCP_LAB_CONFIG")
    if not path:
        return None, None
    path = os.path.expanduser(path)
    with open(path, "r", encoding="utf-8") as fh:
        return (yaml.safe_load(fh) or {}), path


def common_args(ap):
    ap.add_argument("--live", action="store_true",
                    help="run against the configured lab (default: print the plan only, nothing is contacted)")
    ap.add_argument("--lab-config", help="lab configuration file (default: $WCP_LAB_CONFIG)")
    ap.add_argument("--evidence", help="directory for the evidence JSON")
    return ap


def gate(test_id, args, needs=()):
    """(cfg, client, cluster_root) when the live run is allowed; NotEnabled / Refused otherwise."""
    if not getattr(args, "live", False):
        raise NotEnabled("--live not given")
    cfg, path = load_lab_config(getattr(args, "lab_config", None))
    if cfg is None:
        raise NotEnabled("no lab configuration (--lab-config or WCP_LAB_CONFIG)")
    if cfg.get("enabled") is not True:
        raise NotEnabled("%s: enabled is not true" % os.path.basename(path))
    if test_id not in (cfg.get("tests_enabled") or []):
        raise NotEnabled("%s: %s not in tests_enabled" % (os.path.basename(path), test_id))
    allow = cfg.get("allow") or {}
    for n in needs:
        if allow.get(n) is not True:
            raise NotEnabled("%s: allow.%s is not true (needed by %s)" % (os.path.basename(path), n, test_id))
    want = str((cfg.get("cluster") or {}).get("cluster_uuid") or "").strip()
    if not want or want.startswith("<"):
        raise Refused("cluster.cluster_uuid is not set in the lab configuration")
    load_env_file(os.environ.get("WCP_ENV_FILE", DEFAULT_ENV_FILE))
    client = Client()
    root = client.get("/")
    if root.get("cluster_uuid") != want:
        raise Refused("the indexer's cluster_uuid does not match the lab configuration; nothing was changed")
    for cid, val in owned_pack_monitors(client).items():
        h = A.marker_of(val[1]).get("content_hash")
        if h in REFERENCE_DEPLOYMENT_HASHES:
            raise Refused("this cluster holds the RC1 reference deployment (%s); live tests never run there"
                          % REFERENCE_DEPLOYMENT_HASHES[h])
    cfg["_path"] = path
    return cfg, client, root


def owned_pack_monitors(client):
    owned, _f = D.list_owned_monitors(client)
    owned.pop("__duplicates__", None)
    return owned


def pack_monitor_ids(client):
    """{correlation name: monitor id} of the deployed pack monitors, and their content hashes."""
    corrs, _p = pack_content()
    by_id = {c.id: c.name for c in corrs.values()}
    ids, hashes = {}, {}
    for cid, (mid, mon) in owned_pack_monitors(client).items():
        if cid in by_id:
            ids[by_id[cid]] = mid
            hashes[by_id[cid]] = A.marker_of(mon).get("content_hash")
    return ids, hashes


def run_test(test_id, title, build_plan, run_live, argv=None, needs=(), extra_args=None):
    """Common entry point: plan-only unless the gate passes; writes ``<evidence>/<test_id>*.json``."""
    ap = common_args(argparse.ArgumentParser(description=title))
    if extra_args:
        extra_args(ap)
    args = ap.parse_args(argv)
    plan = build_plan(args)
    try:
        cfg, client, root = gate(test_id, args, needs)
    except NotEnabled as e:
        out = {"test": test_id, "title": title, "status": "NOT EXECUTED", "reason": str(e),
               "harness": harness_revision(), "plan": plan}
        print("%s: NOT EXECUTED (%s). Plan:" % (test_id, e))
        print(json.dumps(plan, indent=1, sort_keys=True, default=str)[:20000])
        if args.evidence:
            write_json(os.path.join(args.evidence, "%s_plan.json" % test_id), out)
        return 0
    except Refused as e:
        print("%s: REFUSED - %s" % (test_id, e))
        return 2
    ev = Evidence(test_id, title, args.evidence, cfg, root)
    ev.d["plan"] = plan
    del COMPILE_LIMIT_RETRIES[:]
    begin_session(test_id)
    try:
        run_live(args, cfg, client, ev, plan)
    except Exception as e:   # recorded, then re-raised as a non-zero exit
        ev.error(e)
    finally:
        ev.d["environment"]["endpoint_machines"] = end_session()
        ev.d["environment"]["compile_limit_retries"] = list(COMPILE_LIMIT_RETRIES)
    return 0 if ev.save() == "PASS" else 1


def local_path_forms():
    """Workstation home and temp directories (long and short forms) -> placeholders for evidence."""
    import tempfile
    forms = {}
    for real, ph in ((tempfile.gettempdir(), "<workstation-tmp>"), (os.path.expanduser("~"), "<workstation-home>")):
        variants = {real, os.path.realpath(real)}
        if os.name == "nt":
            try:
                import ctypes
                buf = ctypes.create_unicode_buffer(1024)
                for v in list(variants):
                    if ctypes.windll.kernel32.GetShortPathNameW(v, buf, 1024):
                        variants.add(buf.value)
                    if ctypes.windll.kernel32.GetLongPathNameW(v, buf, 1024):
                        variants.add(buf.value)
            except Exception:
                pass
        for v in variants:
            if v and len(v) > 3:
                forms[v] = ph
    return sorted(forms.items(), key=lambda kv: -len(kv[0]))   # longest (temp under home) first


def scrub_local_paths(text):
    for real, ph in local_path_forms():
        for form in (real, real.replace("\\", "/"), json.dumps(real)[1:-1]):
            text = text.replace(form, ph)
    return text


def scrub_access_accounts(text, accounts):
    """Replace configured access-account names (lab login accounts, never test targets) by a placeholder.

    Whole words only, case-insensitive (``opsuser`` but not ``opsuserx``); such names reach evidence
    through raw log lines of the harness's own logins or as the reporting subject of captured events.
    """
    import re
    for acc in sorted({a for a in accounts if a}, key=len, reverse=True):
        text = re.sub(r"(?<![A-Za-z0-9_.-])%s(?![A-Za-z0-9_-])" % re.escape(acc), "<access-account>", text,
                      flags=re.IGNORECASE)
    return text


def write_json(path, data):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=2, sort_keys=True, default=str)
        fh.write("\n")


class Evidence(object):
    """One JSON per test: environment, inputs (with provenance), expectations, observations, checks."""

    def __init__(self, test_id, title, run_dir, cfg, root):
        self.path = os.path.join(run_dir, "%s.json" % test_id) if run_dir else None
        self.access_accounts = [str(x) for x in (cfg.get("access_accounts") or []) if x]
        self.d = {"test": test_id, "title": title, "started": iso(utc()), "status": None,
                  "environment": {"lab": cfg.get("lab_name"), "cluster_uuid_matches_config": True,
                                  "indexer": (root.get("version") or {}).get("number"),
                                  "distribution": (root.get("version") or {}).get("distribution")},
                  "harness": harness_revision(), "inputs": [], "expected": {}, "observed": {},
                  "observations": [], "checks": [], "timings_s": {}, "cleanup": {}}

    def check(self, label, ok, detail=None):
        self.d["checks"].append({"check": label, "pass": bool(ok), "detail": detail})
        print("   [%s] %s%s" % ("PASS" if ok else "FAIL", label, (" -- %s" % (detail,)) if detail is not None else ""))
        return bool(ok)

    def note(self, label, value):
        """A recorded observation that is not a pass criterion."""
        self.d["observations"].append({"observation": label, "value": value})
        print("   [NOTE] %s: %s" % (label, json.dumps(value, default=str)[:300]))

    def error(self, exc):
        self.d["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:2000])
        self.d["traceback"] = traceback.format_exc()[-4000:]
        print("   [ERROR] %s" % self.d["error"])

    def save(self):
        self.d["finished"] = iso(utc())
        if self.d.get("error"):
            self.d["status"] = "ERROR"
        elif self.d["checks"] and all(c["pass"] for c in self.d["checks"]):
            self.d["status"] = "PASS"
        else:
            self.d["status"] = "FAIL"
        if self.path:
            text = scrub_access_accounts(scrub_local_paths(json.dumps(self.d, indent=2, sort_keys=True, default=str)),
                                         self.access_accounts)
            d = os.path.dirname(self.path)
            if d:
                os.makedirs(d, exist_ok=True)
            with open(self.path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text + "\n")
        print("== %s: %s%s" % (self.d["test"], self.d["status"], (" (%s)" % self.path) if self.path else ""))
        return self.d["status"]


# ------------------------------------------------------------------ endpoints

class Endpoint(object):
    """A lab host reached by a command prefix (normally ssh). shell: posix | powershell."""

    def __init__(self, name, spec):
        if not spec or not spec.get("exec"):
            raise Refused("endpoint %r is not configured (endpoints.%s.exec)" % (name, name))
        self.name = name
        self.spec = spec
        self.prefix = [os.path.expanduser(str(x)) for x in spec["exec"]]
        self.shell = spec.get("shell", "posix")
        self.sudo = bool(spec.get("sudo", False))

    def run(self, cmd, stdin=None, timeout=300, check=True, sudo=None):
        if self.shell == "powershell":
            script = "[Console]::OutputEncoding = [Text.Encoding]::UTF8; $ProgressPreference = 'SilentlyContinue'; " + cmd
            enc = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
            argv = self.prefix + ["powershell -NoProfile -NonInteractive -EncodedCommand " + enc]
        else:
            use_sudo = self.sudo if sudo is None else sudo
            argv = self.prefix + [("sudo -n sh -c %s" if use_sudo else "sh -c %s") % shlex.quote(cmd)]
        data = stdin.encode("utf-8") if isinstance(stdin, str) else stdin
        r = subprocess.run(argv, input=data, capture_output=True, timeout=timeout)
        out = r.stdout.decode("utf-8", "replace").lstrip("﻿")
        err = r.stderr.decode("utf-8", "replace")
        if check and r.returncode != 0:
            raise RuntimeError("%s: command failed (%d): %s\n%s" % (self.name, r.returncode, cmd[:160], err[-1500:]))
        return out

    def run_json(self, cmd, timeout=300):
        if self.shell == "powershell":
            cmd = "& {\n" + cmd + "\n} | ConvertTo-Json -Depth 6 -Compress"
        out = self.run(cmd, timeout=timeout).strip()
        if not out:
            return []
        v = json.loads(out)
        return v if isinstance(v, list) else [v]


    def fingerprint(self):
        """Short hash of the machine identity (/etc/machine-id or the Windows MachineGuid)."""
        if self.shell == "powershell":
            raw = self.run("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography').MachineGuid")
        else:
            raw = self.run("cat /etc/machine-id", sudo=False)
        raw = raw.strip().lower()
        if not raw:
            raise Refused("%s: could not read the machine identity" % self.name)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def lock(self, owner):
        """Create the per-machine validation lock; False if another run holds it."""
        if self.shell == "powershell":
            out = self.run("try { New-Item -ItemType Directory -Path '%s' -ErrorAction Stop | Out-Null; "
                           "Set-Content -Path '%s\\owner' -Value '%s'; 'LOCKED' } catch { 'BUSY' }"
                           % (LOCK_DIR_WINDOWS, LOCK_DIR_WINDOWS, owner))
        else:
            out = self.run("mkdir %s 2>/dev/null && printf '%%s\\n' %s > %s/owner && echo LOCKED || echo BUSY"
                           % (LOCK_DIR_POSIX, shlex.quote(owner), LOCK_DIR_POSIX), sudo=False)
        return out.strip().endswith("LOCKED")

    def lock_owner(self):
        if self.shell == "powershell":
            return self.run("Get-Content -Path '%s\\owner' -ErrorAction SilentlyContinue" % LOCK_DIR_WINDOWS,
                            check=False).strip()
        return self.run("cat %s/owner 2>/dev/null" % LOCK_DIR_POSIX, sudo=False, check=False).strip()

    def unlock(self):
        if self.shell == "powershell":
            self.run("Remove-Item -Recurse -Force -Path '%s' -ErrorAction SilentlyContinue" % LOCK_DIR_WINDOWS,
                     check=False)
        else:
            self.run("rm -rf %s" % LOCK_DIR_POSIX, sudo=False, check=False)


# ------------------------------------------------------------------ machines
# One VM may serve several endpoint roles (e.g. linux_replay and linux_source). Each role is an
# alias; the harness identifies the machine behind it, requires aliases of one machine to share
# the same ``machine`` label, records distinct machines (never aliases) in the evidence, and holds
# one lock per machine for the whole test so that conflicting scenarios run sequentially.

LOCK_DIR_POSIX = "/tmp/wcp-validation.lock"
LOCK_DIR_WINDOWS = "C:\\ProgramData\\wcp-validation.lock"
_SESSION = None   # set by run_test for a live run: {"test", "owner", "machines": {fp: {...}}, "aliases": {}}


def begin_session(test_id):
    global _SESSION
    _SESSION = {"test": test_id, "machines": {}, "aliases": {},
                "owner": "%s pid=%d host=%s since=%s" % (test_id, os.getpid(), socket.gethostname(), iso(utc()))}
    return _SESSION


def register_machine(ep, fp):
    """Bind alias ``ep.name`` to machine fingerprint ``fp``; returns the machine record."""
    s = _SESSION
    label = str(ep.spec.get("machine") or ep.name)
    for other_fp, m in s["machines"].items():
        if other_fp == fp and m["label"] != label:
            raise Refused("endpoints %s and %s are the same machine; give both the same 'machine' label so they "
                          "are not counted as independent endpoints" % (", ".join(m["aliases"]), ep.name))
        if other_fp != fp and m["label"] == label:
            raise Refused("endpoints %s and %s share the machine label %r but are different machines"
                          % (", ".join(m["aliases"]), ep.name, label))
    m = s["machines"].setdefault(fp, {"label": label, "fingerprint": fp, "aliases": [], "locked": False,
                                      "_ep": ep})
    if ep.name not in m["aliases"]:
        m["aliases"].append(ep.name)
    s["aliases"][ep.name] = fp
    return m


def end_session():
    """Release every machine lock taken by this run; returns the machine summary for the evidence."""
    global _SESSION
    s, _SESSION = _SESSION, None
    if not s:
        return None
    for m in s["machines"].values():
        if m["locked"]:
            try:
                m["_ep"].unlock()
                m["locked"] = False
            except Exception as e:   # recorded; the lock directory then has to be removed by hand
                m["unlock_error"] = str(e)[:300]
    return machine_summary(s)


def machine_summary(s):
    ms = [{k: v for k, v in m.items() if not k.startswith("_")} for m in s["machines"].values()]
    return {"distinct_machines": len(ms), "machines": sorted(ms, key=lambda m: m["label"])}


def endpoint(cfg, name):
    ep = Endpoint(name, (cfg.get("endpoints") or {}).get(name))
    if _SESSION is None:            # plan-only / offline use: nothing is contacted
        return ep
    if name in _SESSION["aliases"]:
        return ep
    m = register_machine(ep, ep.fingerprint())
    if not m["locked"]:
        if not ep.lock(_SESSION["owner"]):
            raise Refused("machine %r (%s) is in use by another validation run (%s); run the tests one after "
                          "another, or remove %s on that machine if no run is active"
                          % (m["label"], name, ep.lock_owner() or "owner unknown",
                             LOCK_DIR_WINDOWS if ep.shell == "powershell" else LOCK_DIR_POSIX))
        m["locked"] = True
    return ep


def leftover_test_resources(client, indices=(), channels=()):
    """Temporary resources of an earlier run that would collide with this one: every monitor whose name
    starts with ``[wcp-test] `` (enabled or disabled; the monitor search returns monitor documents with or
    without a ``monitor`` wrapper), the given test indices and notification channel ids. Read-only."""
    found = []
    res = client.post(MON + "/_search", {"size": 1000, "query": {"match_all": {}}})
    for h in (res.get("hits") or {}).get("hits") or []:
        src = h.get("_source") or {}
        m = src.get("monitor") if isinstance(src.get("monitor"), dict) else src
        name = m.get("name") or ""
        if name.startswith(TEST_NAME_PREFIX):
            found.append({"kind": "monitor", "id": h.get("_id"), "name": name, "enabled": m.get("enabled")})
    for ix in indices:
        try:
            client.get("/" + ix)
            found.append({"kind": "index", "name": ix})
        except ApiError as e:
            if e.status != 404:
                raise
    for cid in channels:
        try:
            client.get("/_plugins/_notifications/configs/" + cid)
            found.append({"kind": "channel", "name": cid})
        except ApiError as e:
            if e.status != 404:
                raise
    return found


def refuse_on_leftovers(client, ev, indices=(), channels=()):
    """Fail fast before anything is created: report leftover temporary resources, never delete them."""
    found = leftover_test_resources(client, indices, channels)
    ev.d["observed"]["leftover_check"] = found
    if found:
        raise Refused("leftover temporary resources of an earlier run (%s); review and delete them, then re-run. "
                      "Nothing was created or deleted." % "; ".join(
                          "%s %s%s" % (f["kind"], f["name"], (" id=%s enabled=%s" % (f["id"], f["enabled"]))
                                       if f["kind"] == "monitor" else "") for f in found))


def stored_monitor_users(cfg, monitor_ids):
    """{monitor id: stored ``monitor.user``} read from the Alerting config index on the server.

    The 5.0.0-rc2 Alerting REST API (GET monitor, monitors/_search) does not return ``user``; the
    stored document is read on the server with the indexer's super-admin client certificate
    (read-only ``_search`` of ``.opendistro-alerting-config``) through ``endpoints.server``
    (``admin_cert_dir``, default ``/etc/wazuh-indexer/certs``). None if no server endpoint is set.
    """
    spec = (cfg.get("endpoints") or {}).get("server")
    if not spec or not spec.get("exec"):
        return None
    ep = endpoint(cfg, "server")
    d = spec.get("admin_cert_dir") or "/etc/wazuh-indexer/certs"
    body = json.dumps({"size": len(monitor_ids), "query": {"ids": {"values": list(monitor_ids)}},
                       "_source": ["monitor.user"]})
    out = ep.run("curl -sS --max-time 20 --cacert {d}/root-ca.pem --cert {d}/admin.pem --key {d}/admin-key.pem "
                 "-H 'Content-Type: application/json' https://127.0.0.1:9200/.opendistro-alerting-config/_search "
                 "-d {b}".format(d=shlex.quote(d), b=shlex.quote(body)), sudo=True)
    hits = json.loads(out).get("hits", {}).get("hits", [])
    return {h["_id"]: (h.get("_source") or {}).get("monitor", {}).get("user") for h in hits}


def check_test_account(cfg, name):
    """Target accounts must carry the configured test prefix and never be an access account."""
    prefix = cfg.get("test_account_prefix") or "wcpt-"
    low = name.lower()
    if not low.startswith(prefix.lower()):
        raise Refused("target account %r lacks the test prefix %r" % (name, prefix))
    for acc in cfg.get("access_accounts") or []:
        if acc and acc.lower() in low:
            raise Refused("target account %r contains an access account name" % name)
    return name


def replay_lines(ep, lines):
    """Append lines to the replay file collected by the agent of a Linux endpoint (LF only)."""
    path = ep.spec.get("replay_file") or "/var/log/wcp-replay/replay.log"
    data = "".join(l.rstrip("\r\n") + "\n" for l in lines)
    ep.run("cat >> %s" % shlex.quote(path), stdin=data, timeout=120)
    return len(lines)


# ------------------------------------------------------------------ indexer helpers

def search_events(client, filters, size=1000, index=EVENTS_INDEX, source=None):
    body = {"size": size, "sort": [{"event.start": "asc"}], "query": {"bool": {"filter": filters}}}
    if source:
        body["_source"] = source
    return [h["_source"] for h in client.post("/%s/_search" % index, body)["hits"]["hits"]]


def count_events(client, filters, index=EVENTS_INDEX):
    r = client.post("/%s/_search" % index, {"size": 0, "track_total_hits": True,
                                             "query": {"bool": {"filter": filters}}})
    return r["hits"]["total"]["value"]


def wait_count(client, filters, expected, timeout=300, poll=3, index=EVENTS_INDEX):
    t0 = time.time()
    n = 0
    while time.time() - t0 < timeout:
        n = count_events(client, filters, index)
        if n >= expected:
            return n, round(time.time() - t0, 1)
        time.sleep(poll)
    return n, None


def monitor_capacity(client):
    """(monitor documents, max_monitors setting) - see docs/CONFIGURATION.md 'Monitor capacity'."""
    res = client.post(MON + "/_search", {"size": 0, "track_total_hits": True,
                                         "query": {"bool": {"filter": [{"term": {"monitor.type": "monitor"}}]}}})
    tot = (res.get("hits") or {}).get("total")
    n = tot.get("value") if isinstance(tot, dict) else tot
    st = client.get("/_cluster/settings", params={"include_defaults": "true", "flat_settings": "true"})
    val = None
    for scope in ("transient", "persistent", "defaults"):
        val = val if val is not None else (st.get(scope) or {}).get("plugins.alerting.monitor.max_monitors")
    return n, (int(val) if val is not None else None)


def require_capacity(client, extra, ev):
    n, mx = monitor_capacity(client)
    ev.d["observed"]["monitor_capacity_before"] = {"monitor_documents": n, "max_monitors": mx, "to_create": extra}
    if mx is not None and n + extra > mx:
        raise Refused("max_monitors %d would be exceeded (%d existing + %d temporary)" % (mx, n, extra))


def cluster_setting(client, key):
    st = client.get("/_cluster/settings", params={"include_defaults": "true", "flat_settings": "true"})
    for scope in ("transient", "persistent", "defaults"):
        v = (st.get(scope) or {}).get(key)
        if v is not None:
            return v
    return None


def create_temp_index(client, name, mapping):
    if not name.startswith(TEST_INDEX_PREFIX):
        raise Refused("temporary index names must start with %s" % TEST_INDEX_PREFIX)
    try:
        client.delete("/" + name)       # a leftover of an earlier run of this test (pack-owned name)
    except ApiError as e:
        if e.status != 404:
            raise
    client.put("/" + name, mapping)


def bulk(client, index, docs, refresh="wait_for"):
    body = "".join(json.dumps({"index": {"_index": index}}) + "\n" + json.dumps(d) + "\n" for d in docs)
    r = client.post("/_bulk", body, params={"refresh": refresh})
    if r.get("errors"):
        raise RuntimeError("bulk errors: %s" % json.dumps(r)[:800])


def delete_verified(client, path):
    """Delete and confirm 404 afterwards. Returns 'deleted', 'absent' or an error string."""
    state = "deleted"
    try:
        client.delete(path)
    except ApiError as e:
        if e.status != 404:
            return "delete error %s" % e.status
        state = "absent"
    try:
        client.get(path)
        return "still present"
    except ApiError as e:
        return state if e.status == 404 else "verify error %s" % e.status


def temp_monitor_body(corr_name, index, name, actions=None, enabled=True, min_count=None, group_by=None,
                      extra_filters=None):
    """A test copy of a pack correlation as a monitor body: test name, no pack marker (so ``wcp`` never
    treats it as the pack's), pointed at ``index``. Detection logic is the frozen rendering."""
    if not name.startswith(TEST_NAME_PREFIX):
        raise ValueError("temporary monitor names must start with %r" % TEST_NAME_PREFIX)
    corrs, prof = pack_content()
    corr = copy.copy(corrs[corr_name])
    if min_count is not None:
        corr.min_count = min_count
    if group_by is not None:
        corr.group_by = list(group_by)
    st = dict(C.settings_for(prof, corr_name), indices=[index], enabled=enabled,
              actions=list(actions or []), extra_filters=list(extra_filters or []))
    body = A.render_monitor(corr, st, prof["version"])
    body["inputs"][0]["search"]["query"]["aggregations"][A.GROUP_AGG].pop("meta", None)
    body["name"] = name
    return body, corr, st


COMPILE_LIMIT_RETRIES = []   # (utc, attempt) of dry runs retried after the script compilation rate limit


def compile_limit_hit(client):
    """compilation_limit_triggered summed over the nodes (script compilation rate limit)."""
    st = client.get("/_nodes/stats/script")
    return sum(int((n.get("script") or {}).get("compilation_limit_triggered") or 0) for n in st.get("nodes", {}).values())


def dry_run(client, body, retries=3, wait_s=75):
    """POST _execute?dryrun=true of an unsaved monitor body -> {bucket key tuple: detail}.

    Every unsaved body is a new search template to compile; many in a row can hit the indexer's script
    compilation rate limit (seen on 5.0.0-rc2 right after the query/API suite). Such a run is retried
    (recorded in COMPILE_LIMIT_RETRIES) only when an input or trigger error coincides with an increase of
    the node counter ``compilation_limit_triggered``; any other error is raised at once."""
    for attempt in range(retries + 1):
        before = compile_limit_hit(client) if attempt < retries else None
        res = client.post(MON + "/_execute", body, params={"dryrun": "true"})
        ir = res.get("input_results") or {}
        err = str(ir.get("error") or "") + "".join(str((tr or {}).get("error") or "")
                                                     for tr in (res.get("trigger_results") or {}).values())
        # the limit surfaces as an input compile error or as a trigger error over an empty input
        if err and attempt < retries and compile_limit_hit(client) > before:
            COMPILE_LIMIT_RETRIES.append((iso(utc()), attempt + 1))
            print("   [retry] script compilation rate limit hit; waiting %d s (attempt %d)" % (wait_s, attempt + 1))
            time.sleep(wait_s)
            continue
        break
    if ir.get("error"):
        raise RuntimeError("input error: %s" % str(ir["error"])[:500])
    out = {}
    for _t, tr in (res.get("trigger_results") or {}).items():
        if tr.get("error"):
            raise RuntimeError("trigger error: %s" % str(tr["error"])[:500])
        for _k, b in (tr.get("agg_result_buckets") or {}).items():
            b = b.get("agg_alert_content", b)
            out[tuple(b["bucket_keys"])] = (b.get("bucket") or {}).get(A.DETAIL_AGG, {}).get("value") or {}
    return out


def identity_probe(client, corr_name, extra_filters, group_by=None, index=EVENTS_INDEX):
    """Dry run of a test copy of a value_count correlation at threshold 1: the Painless identities the
    frozen monitor computes for the matching (already indexed) events. Creates nothing."""
    body, _c, _s = temp_monitor_body(corr_name, index, TEST_NAME_PREFIX + "identity probe (dry run)",
                                     min_count=1, group_by=group_by, extra_filters=extra_filters)
    return dry_run(client, body)


def summarize_alert(a):
    agg = a.get("agg_alert_content") or {}
    det = ((agg.get("bucket") or {}).get(A.DETAIL_AGG) or {}).get("value") or {}
    return {"id": a.get("id"), "state": a.get("state"), "bucket_keys": agg.get("bucket_keys"),
            "start_time": ms_iso(a.get("start_time")), "end_time": ms_iso(a.get("end_time")),
            "last_notification_time": ms_iso(a.get("last_notification_time")),
            "error_message": a.get("error_message"), "score": det.get("score"),
            "distinct_values_sample": det.get("distinct_values_sample"),
            "action_execution_results": a.get("action_execution_results")}


class AlertTracker(object):
    """Polls the alerts of one monitor and keeps every alert ever seen with its state history.

    With alert history disabled (5.0.0-rc1 default) a COMPLETED alert is deleted, so it is seen as
    ACTIVE -> (COMPLETED) -> ABSENT; poll often enough (every 2 s) to see single-run alerts.
    An ACTIVE alert's bucket (score, sample) is refreshed by every DEDUPED run (observed on 5.0.0-rc2):
    ``first`` is the snapshot when the alert was first seen (the creating run), ``last`` the latest.
    """

    def __init__(self, client, monitor_id):
        self.client, self.mid, self.alerts = client, monitor_id, {}
        self.run_marks = set()   # start / last_notification times seen (ms): instants at which runs happened

    def poll(self):
        res = self.client.get(MON + "/alerts", params={"monitorId": self.mid, "alertState": "ALL", "size": 500})
        now = iso(utc())
        present = set()
        for a in res.get("alerts", []):
            present.add(a["id"])
            for k in ("start_time", "last_notification_time"):
                if isinstance(a.get(k), (int, float)):
                    self.run_marks.add(int(a[k]))
            s = summarize_alert(a)
            rec = self.alerts.setdefault(a["id"], {"id": a["id"], "keys": list(s["bucket_keys"] or []),
                                                   "first_seen": now, "start_time": s["start_time"],
                                                   "start_ms": a.get("start_time"), "states": [], "first": s})
            if not rec["states"] or rec["states"][-1][1] != a.get("state"):
                rec["states"].append([now, a.get("state")])
            rec["last_seen"] = now
            rec["last"] = s
        for aid, rec in self.alerts.items():
            if aid not in present and rec["states"][-1][1] != "ABSENT":
                rec["states"].append([now, "ABSENT"])
        return self

    def for_keys(self, keys):
        return sorted([r for r in self.alerts.values() if r["keys"] == list(keys)], key=lambda r: r["start_ms"] or 0)

    def errors(self):
        return [r for r in self.alerts.values() if any(s[1] == "ERROR" for s in r["states"])]


def ssh_fixture(tag, t_iso, agent, ip, user="a"):
    """An sshd 'Failed password' event document for a temporary index (fields as the events stream)."""
    return {"fixture": tag, "@timestamp": t_iso,
            "event": {"start": t_iso, "reason": "Failed password", "action": "authentication-failure"},
            "process": {"name": "sshd"}, "source": {"ip": ip}, "user": {"name": user},
            "wazuh": {"agent": {"id": agent, "name": "ep-%s" % agent}}}


def burst_docs(tag, ip, last_event, n=8, span_s=7.0, agent="009"):
    """n brute-force events whose event times end at last_event and span span_s seconds."""
    step = span_s / (n - 1) if n > 1 else 0
    return [ssh_fixture(tag, iso(last_event - datetime.timedelta(seconds=span_s - i * step)), agent, ip)
            for i in range(n)]


def temp_index_mapping():
    from test_monitor_execute import MAPPING   # tests/api/test_monitor_execute.py (field types of the events stream)
    return copy.deepcopy(MAPPING)


def counted_by_schedule(first_event, visible_at, run_times, lookback_s):
    """First run (from ``run_times``) that counts a burst: a run executing after the burst became
    searchable whose period end (taken as its execution time) is no later than first_event + lookback.
    Returns (run time or None, margin seconds of the first run after visibility)."""
    after = [r for r in sorted(run_times) if r >= visible_at]
    if not after:
        return None, None
    margin = (first_event + datetime.timedelta(seconds=lookback_s) - after[0]).total_seconds()
    return (after[0] if margin >= 0 else None), margin


def grid(base, interval_s, start, end):
    """Run instants base + k*interval within [start, end]."""
    out = []
    k = int(((start - base).total_seconds()) // interval_s) - 1
    while True:
        t = base + datetime.timedelta(seconds=k * interval_s)
        if t > end:
            return out
        if t >= start:
            out.append(t)
        k += 1
