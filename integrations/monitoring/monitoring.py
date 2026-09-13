#!/var/ossec/framework/python/bin/python3
"""
Wazuh Environment Health Checker
Wazuh Inc.
Nicolás Curioni <nicolas.curioni@wazuh.com>
=====================================================
Supports bare-metal, Docker, and Kubernetes Wazuh deployments, from
all-in-one servers up to fully distributed clusters.

The script is meant to be installed **only on the Wazuh Manager master node**.
From there it reaches out to every other server of the deployment (manager
workers, indexer cluster nodes and dashboards) using the addresses declared in
the *Cluster topology* section below (or their `--*-nodes` CLI equivalents).

Checks performed:

    0. Container / Pod health                                          [docker/k8s]
    1. Manager API availability (JWT auth)                             [local]
    2. Indexer API / cluster health                                    [indexer]
    3. Dashboard accessibility                                         [dashboard]
    4. Disk space usage (alerts at >= 75% by default)                  [local]
   4b. Indexer disk space via API                                      [indexer]
    5. Shards configured per node (max_shards_per_node x node_count)   [indexer]
    6. Active shards closeness to limit (>= 80% of limit by default)   [indexer]
    7. JVM Xms/Xmx vs total system RAM (via API)                       [indexer]
    8. Unassigned shards                                               [indexer]
    9. TCP port reachability (1514 - events, 1515 - enrollment)        [manager]
   10. Agent summary (active / disconnected / pending / never_connected)[manager]
   11. ISM policies configured and actually applied in the Indexer     [indexer]
   12. Cron jobs for alert/archive log rotation in the Manager         [manager]
   13. Retention feasibility (disk + shards vs ISM retention days)     [indexer]
   14. Filebeat service status                                         [manager]
   15. Filebeat output connectivity                                    [manager]
   16. Wazuh Manager cluster nodes (via API)              [multi-node] [manager]
   17. Wazuh Indexer cluster nodes (_cat/nodes)           [multi-node] [indexer]
   18. Alert volume trend drop (current vs previous window)            [indexer]
   19. Manager API reachable on every manager node        [multi-node] [manager]
   20. Indexer reachable / same cluster on every node     [multi-node] [indexer]
   21. Dashboard reachable on every dashboard node        [multi-node] [dashboard]

Deploy modes (--deploy-mode):
    bare-metal – traditional installation (default)
    docker     – Wazuh Docker Compose deployment
    kubernetes – Wazuh Kubernetes deployment

Node roles (--node-role):
    all       – run every check (default)
    manager   – checks 1, 4, 9, 10, 12, 14, 15, 16, 19
    indexer   – checks 1, 2, 4, 4b, 5, 6, 7, 8, 11, 13, 17, 18, 20
    dashboard – checks 1, 3, 4, 21

Supported topologies (see the "Cluster topology" section below):

    A) All-in-one       – manager + indexer + dashboard on a single server.
                          Nothing to configure, the localhost defaults work.

    B) Split services   – e.g. 1 server with the manager and 1 server with
                          indexer + dashboard. Declare the remote addresses in
                          DEFAULT_INDEXER_NODES / DEFAULT_DASHBOARD_NODES.

    C) Distributed      – e.g. 6 servers: 1 manager master (where this script
                          runs), 1 manager worker, 1 indexer master, 2 indexer
                          data nodes and 1 dashboard. Declare every address in
                          DEFAULT_MANAGER_NODES / DEFAULT_INDEXER_NODES /
                          DEFAULT_DASHBOARD_NODES.

Usage:
    python3 monitoring.py [options]

Examples:
    # A) All-in-one, bare-metal
    python3 monitoring.py

    # B) Manager here, indexer + dashboard on 10.0.0.2
    python3 monitoring.py \\
        --indexer-nodes 10.0.0.2 \\
        --dashboard-nodes 10.0.0.2

    # C) Distributed cluster driven from the manager master
    python3 monitoring.py \\
        --manager-nodes   10.0.0.1,10.0.0.2 \\
        --indexer-nodes   10.0.0.3,10.0.0.4,10.0.0.5 \\
        --dashboard-nodes 10.0.0.6

    # Docker single-node
    python3 monitoring.py --deploy-mode docker \\
        --docker-compose-dir /path/to/wazuh-docker/single-node/

    # Kubernetes
    python3 monitoring.py --deploy-mode kubernetes \\
        --k8s-namespace wazuh

Changelog:
    2026-09-13 – Matías Mercado <matias.mercado@wazuh.com>
        Fixes found while validating the integration against a real 2-manager +
        2-indexer Wazuh 4.14.7 cluster:
          * Checks 16 and 17 rejected FQDN entries. The configuration accepts an
            IP, host:port, a URL or an FQDN, but a cluster reports its members by
            IP and node name, so an FQDN matched neither and a perfectly
            reachable node was reported as missing from the cluster. Declared
            entries are now matched against every identity they resolve to
            (_host_identities).
          * Check 19 queried GET /cluster/node, which does not exist and answers
            404 on every node, so the check could never pass. The endpoint is
            GET /cluster/local/info, whose response shape the check already
            expected.
          * `--init-config --yes` ignored credentials supplied as environment
            variables, so it could not run non-interactively on a step-by-step
            installation - which has no /root/wazuh-install-files.tar to read.

    2026-09-13 – Matías Mercado <matias.mercado@wazuh.com>
        Consolidated every setting into ONE configuration file,
        /etc/wazuh-health-checker.conf (root:root, chmod 600), in the same
        KEY=VALUE format the old secrets file used. Configuring a multi-node
        deployment previously meant editing four separate files - node lists in
        this script, the webhook in slack_notifier.py, the SMTP credentials in
        email_notifier.py and the paths in wrapper.sh - while wrapper.sh passed
        no arguments at all, so none of the CLI flags were reachable from the
        documented installation.
          * wrapper.sh now sources the configuration file and exports it, so the
            notifier scripts receive the same values as environment variables;
            it also resolves its own directory instead of hard-coding
            /opt/scripts, skips a notifier that is not installed (it used to
            fail on every run looking for teams_notifier.py) and forwards its
            arguments to monitoring.py.
          * `--init-config` writes that file: it reads the credentials
            wazuh-install.sh left in /root/wazuh-install-files.tar when they are
            still available, discovers the manager topology through
            GET /cluster/nodes and the indexer topology through _cat/nodes, and
            writes the result with chmod 600 for review. A standalone manager is
            reported as such rather than as an error - GET /cluster/nodes answers
            400 (error 3013) whenever clustering is disabled, so GET
            /cluster/status is consulted first. Use `--yes` for a
            non-interactive run.
          * The topology is discovered once and stored, deliberately: checks 16
            and 17 verify that every declared node is still present in the
            cluster, which only works when the expected list is a reviewed
            declaration rather than something rediscovered on every run.
          * Precedence is CLI flag > environment variable > config file >
            legacy /etc/health-checker.secrets > built-in default. Existing
            installations are unaffected: the legacy secrets file and the
            DEFAULT_*_NODES lists are still read when the new file is absent.
          * LOG_FILE is defined once instead of being repeated in three files.

    2026-09-13 – Matías Mercado <matias.mercado@wazuh.com>
        Reworked ISM retention detection in checks 11 and 13, which reported
        "No ISM policies found. Projecting with default 90d." on clusters that
        had a valid retention policy applied to every index:
          * A state is now recognised as a delete phase by its `delete` action
            rather than only by its name. The Wazuh documentation names that
            state `delete_alerts`, so matching the literal names
            "delete"/"deleted" never matched a documented policy.
          * Checks 11 and 13 share the same ISM parsing, so they can no longer
            disagree about whether a policy exists, and check 11 now also
            verifies that policies are effectively applied to indices
            (_ism/explain) instead of only that they are defined.
          * `_parse_age_to_days()` now follows the OpenSearch time units the
            indexer really accepts for `min_index_age`: 'h' is an hour rather
            than a full day (a "4320h" policy was read as 4320 days instead of
            180), and 'm'/'s'/'ms' are supported - "259200m" and "15552000s"
            were previously unparsable. Upper-case days and hours are also
            tolerated.
          * Both ISM reads request `size=ISM_POLICY_PAGE_SIZE` (1000);
            /_plugins/_ism/policies returns only 20 policies by default. The
            _opendistro/_ism prefix is tried as a fallback.
          * A failed ISM read (auth, permissions - e.g. HTTP 403 without
            'cluster:admin/opendistro/ism/*' - or connectivity) is reported as
            such instead of being indistinguishable from an empty cluster, and
            so is a policy that exists but defines no age-based delete phase.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any

# ── optional but lightweight dependencies ────────────────────────────────────
try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("ERROR: 'requests' is not installed. Run: pip3 install requests", file=sys.stderr)
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Defaults
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_MANAGER_URL    = "https://localhost:55000"
DEFAULT_INDEXER_URL    = "https://localhost:9200"
DEFAULT_DASHBOARD_URL  = "https://localhost:443"
DEFAULT_LOG_FILE       = "/var/log/health-checker.json"
DEFAULT_DISK_PATH      = "/"
DEFAULT_DISK_THRESHOLD = 75
DEFAULT_SHARD_THRESHOLD = 80
DEFAULT_SECRETS_FILE   = "/etc/health-checker.secrets"   # legacy, still honoured
DEFAULT_CONFIG_FILE    = "/etc/wazuh-health-checker.conf"
REQUEST_TIMEOUT = 10

# Default TCP ports used when a topology entry is written as a bare IP/hostname
MANAGER_API_PORT   = 55000
INDEXER_PORT       = 9200
DASHBOARD_PORT     = 443


# ─────────────────────────────────────────────────────────────────────────────
# Cluster topology
# ─────────────────────────────────────────────────────────────────────────────
# Install this script ONLY on the Wazuh Manager master node. It reaches every
# other server of the deployment over the network, so the addresses of those
# servers have to be declared here (or with the equivalent CLI flags:
# --manager-nodes / --indexer-nodes / --dashboard-nodes).
#
# Each list entry accepts any of these forms:
#
#     "10.0.0.11"               -> https://10.0.0.11:<default port>
#     "10.0.0.11:9200"          -> https://10.0.0.11:9200
#     "https://indexer-1:9200"  -> used verbatim
#     "http://10.0.0.11:9200"   -> used verbatim (plain HTTP)
#
# Leave a list empty to fall back to the localhost defaults above, which is
# what an all-in-one deployment needs.
#
# ── Scenario A – all-in-one (manager + indexer + dashboard on this server) ──
#     DEFAULT_MANAGER_NODES   = []
#     DEFAULT_INDEXER_NODES   = []
#     DEFAULT_DASHBOARD_NODES = []
#
# ── Scenario B – manager here, indexer + dashboard on another server ────────
#     DEFAULT_MANAGER_NODES   = []
#     DEFAULT_INDEXER_NODES   = ["10.0.0.2"]
#     DEFAULT_DASHBOARD_NODES = ["10.0.0.2"]
#
# ── Scenario C – distributed: manager master + worker, 3 indexers, dashboard ─
#     DEFAULT_MANAGER_NODES   = ["10.0.0.1", "10.0.0.2"]          # master + worker
#     DEFAULT_INDEXER_NODES   = ["10.0.0.3", "10.0.0.4", "10.0.0.5"]
#     DEFAULT_DASHBOARD_NODES = ["10.0.0.6"]
#
# Include the local master node in DEFAULT_MANAGER_NODES as well: check 16
# validates that every declared node shows up in the Wazuh cluster response.
#
DEFAULT_MANAGER_NODES:   list[str] = []
DEFAULT_INDEXER_NODES:   list[str] = []
DEFAULT_DASHBOARD_NODES: list[str] = []

# Docker image patterns used to auto-discover containers
DOCKER_IMAGE_MANAGER   = "wazuh/wazuh-manager"
DOCKER_IMAGE_INDEXER   = "wazuh/wazuh-indexer"
DOCKER_IMAGE_DASHBOARD = "wazuh/wazuh-dashboard"

# Kubernetes defaults
K8S_DEFAULT_NAMESPACE    = "wazuh"
K8S_POD_MANAGER_MASTER   = "wazuh-manager-master-0"
K8S_POD_INDEXER          = "wazuh-indexer-0"
K8S_LABEL_MANAGER        = "app=wazuh-manager"
K8S_LABEL_INDEXER        = "app=wazuh-indexer"
K8S_LABEL_DASHBOARD      = "app=wazuh-dashboard"

# Cache for discovered Docker container names (populated at runtime)
_docker_container_cache: dict[str, str] = {}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _gb(value_bytes: int) -> float:
    return round(value_bytes / (1024 ** 3), 2)


def _make_check(status: str, notify: bool, **details: Any) -> dict:
    return {"status": status, "notify": notify, **details}


def _make_skip(node_role: str) -> dict:
    return {"status": "skipped", "notify": False,
            "details": f"Not applicable for node role '{node_role}'"}

# ─────────────────────────────────────────────────────────────────────────────
# Cluster topology helpers
# ─────────────────────────────────────────────────────────────────────────────
def _normalize_node_url(entry: str, default_port: int,
                        default_scheme: str = "https") -> str:
    """
    Turn a topology entry into a full base URL.

    "10.0.0.11"              -> "https://10.0.0.11:<default_port>"
    "10.0.0.11:9200"         -> "https://10.0.0.11:9200"
    "http://10.0.0.11:9200"  -> "http://10.0.0.11:9200"
    "[fd00::1]:9200"         -> "https://[fd00::1]:9200"
    """
    entry = entry.strip().rstrip("/")
    if not entry:
        return ""

    if "://" in entry:
        scheme, _, rest = entry.partition("://")
    else:
        scheme, rest = default_scheme, entry

    # Split off an explicit port, taking bracketed IPv6 literals into account.
    if rest.startswith("["):
        host, _, tail = rest.partition("]")
        host += "]"
        port = tail[1:] if tail.startswith(":") else ""
    elif rest.count(":") == 1:
        host, _, port = rest.partition(":")
    elif rest.count(":") > 1:
        # Bare IPv6 literal without brackets.
        host, port = f"[{rest}]", ""
    else:
        host, port = rest, ""

    if not port:
        port = str(default_port)
    return f"{scheme}://{host}:{port}"


def _node_host(url: str) -> str:
    """Extract the bare host (no scheme, no port) from a normalized node URL."""
    rest = url.split("://", 1)[-1].rstrip("/")
    if rest.startswith("["):
        return rest.partition("]")[0].lstrip("[")
    return rest.split(":", 1)[0]


def _short_error(err: str) -> str:
    """
    Condense a requests/urllib3 exception into something readable in a Slack
    or email alert. The full text is still kept in the per-node payload.
    """
    text = str(err)
    lowered = text.lower()
    if "connection refused" in lowered or "max retries" in lowered:
        return "connection refused"
    if "timed out" in lowered or "timeout" in lowered:
        return "timed out"
    if "name or service not known" in lowered or "nodename nor servname" in lowered:
        return "host name could not be resolved"
    if "certificate" in lowered:
        return "TLS certificate error"
    return text if len(text) <= 140 else text[:137] + "…"


def _node_label(url: str) -> str:
    """Short 'host:port' label used in per-node messages."""
    return url.split("://", 1)[-1].rstrip("/")


def _parse_node_list(cli_value: str | None, fallback: list[str],
                     default_port: int) -> list[str]:
    """
    Build the list of node base URLs from the CLI flag (comma separated) or,
    when the flag is absent, from the in-file topology defaults.
    Duplicates are removed while preserving order.
    """
    raw = ([e for e in cli_value.split(",")] if cli_value else list(fallback))
    urls: list[str] = []
    for entry in raw:
        url = _normalize_node_url(entry, default_port)
        if url and url not in urls:
            urls.append(url)
    return urls


def _resolve_endpoints(explicit_url: str | None, node_urls: list[str],
                       default_url: str) -> list[str]:
    """
    Merge an explicitly requested URL with the declared cluster nodes.

    - Nothing declared            -> [default_url]        (all-in-one)
    - Only nodes declared         -> the node URLs        (split / distributed)
    - Both declared               -> explicit URL first, then the nodes
    """
    urls: list[str] = []
    if explicit_url:
        urls.append(explicit_url.rstrip("/"))
    for url in node_urls:
        if url not in urls:
            urls.append(url)
    return urls or [default_url]


def _first_reachable(urls: list[str], probe) -> tuple[str, list[str]]:
    """
    Return the first URL for which ``probe(url)`` is truthy, together with the
    list of URLs that failed. Falls back to ``urls[0]`` when none answers, so
    the cluster-wide checks still report a meaningful connection error.
    """
    unreachable: list[str] = []
    for url in urls:
        if probe(url):
            return url, unreachable
        unreachable.append(url)
    return urls[0], unreachable


def _probe_indexer(user: str, password: str):
    """Build a probe callable that returns True when an indexer node answers."""
    def _probe(url: str) -> bool:
        try:
            resp = requests.get(f"{url}/_cluster/health", auth=(user, password),
                                verify=False, timeout=REQUEST_TIMEOUT)
            return resp.status_code == 200
        except Exception:
            return False
    return _probe


# ─────────────────────────────────────────────────────────────────────────────
# Container exec abstractions
# ─────────────────────────────────────────────────────────────────────────────
def _docker_find_container(image_pattern: str) -> str | None:
    cached = _docker_container_cache.get(image_pattern)
    if cached:
        return cached

    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Image}}",
             "--filter", "status=running"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.strip().splitlines():
                parts = line.split("\t", 1)
                if len(parts) == 2 and image_pattern in parts[1]:
                    _docker_container_cache[image_pattern] = parts[0]
                    return parts[0]
    except Exception:
        pass
    return None


def _docker_exec(container_name: str, cmd: list[str],
                 timeout: int = 30) -> subprocess.CompletedProcess:
    full_cmd = ["docker", "exec", container_name] + cmd
    return subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)


def _kubectl_exec(pod: str, cmd: list[str], namespace: str,
                  container: str | None = None,
                  timeout: int = 30) -> subprocess.CompletedProcess:
    full_cmd = ["kubectl", "exec", pod, "-n", namespace]
    if container:
        full_cmd += ["-c", container]
    full_cmd += ["--"] + cmd
    return subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)


def _container_exec(deploy_mode: str, target: str, cmd: list[str],
                    namespace: str = K8S_DEFAULT_NAMESPACE,
                    timeout: int = 30) -> subprocess.CompletedProcess:
    if deploy_mode == "docker":
        container_name = _docker_find_container(target)
        if not container_name:
            raise FileNotFoundError(
                f"No running Docker container found for image '{target}'")
        return _docker_exec(container_name, cmd, timeout)
    elif deploy_mode == "kubernetes":
        return _kubectl_exec(target, cmd, namespace, timeout=timeout)
    else:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


# ─────────────────────────────────────────────────────────────────────────────
# Node-role check routing
# ─────────────────────────────────────────────────────────────────────────────
LOCAL_CHECKS = {"manager_api", "disk_space", "container_health"}
INDEXER_CHECKS = {
    "indexer_api", "indexer_disk_space", "shards_per_node", "active_shards",
    "jvm_options", "unassigned_shards", "ilm_policies", "retention_feasibility",
    "indexer_nodes", "alert_volume_trend", "indexer_node_endpoints",
}
MANAGER_CHECKS = {
    "ports", "agents", "cron_rotation", "filebeat_service",
    "filebeat_output", "manager_cluster_nodes", "manager_node_endpoints",
}
DASHBOARD_CHECKS = {"dashboard", "dashboard_nodes"}


def should_run(check_name: str, node_role: str) -> bool:
    if node_role == "all":
        return True
    if check_name in LOCAL_CHECKS:
        return True
    if node_role == "indexer" and check_name in INDEXER_CHECKS:
        return True
    if node_role == "manager" and check_name in MANAGER_CHECKS:
        return True
    if node_role == "dashboard" and check_name in DASHBOARD_CHECKS:
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
# Everything the integration needs lives in ONE file – /etc/wazuh-health-checker.conf
# (root:root, chmod 600) – in the same KEY=VALUE format the old secrets file used.
# wrapper.sh sources that file, so the notifier scripts receive exactly the same
# values as environment variables and nothing has to be edited inside the code.
#
# Precedence, highest first:
#     CLI flag  >  environment variable  >  config file  >  legacy secrets file
#     >  built-in default
#
# Generate a ready-to-review file, with the cluster topology discovered
# automatically, using:   monitoring.py --init-config
#
_REQUIRED_SECRETS = ("MANAGER_USER", "MANAGER_PASS", "INDEXER_USER", "INDEXER_PASS")

# Populated by load_config(); read through cfg() / cfg_int() / cfg_list().
_config_values: dict[str, str] = {}


def _read_kv_file(path: str) -> dict[str, str]:
    """Parse a KEY=VALUE file. Blank lines and '#' comments are ignored, and a
    leading 'export ' is tolerated so the same file can be sourced by a shell."""
    values: dict[str, str] = {}
    if not os.path.isfile(path):
        return values
    try:
        with open(path) as f:
            for lineno, raw in enumerate(f, 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[len("export "):].lstrip()
                if "=" not in line:
                    print(f"WARNING: {path}:{lineno}: skipping invalid line",
                          file=sys.stderr)
                    continue
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip().strip('"').strip("'")
    except PermissionError:
        print(f"ERROR: Cannot read {path}. Run as root.", file=sys.stderr)
        sys.exit(1)
    return values


def load_config(config_file: str, secrets_file: str) -> dict[str, str]:
    """Merge the legacy secrets file with the config file; the latter wins.

    Reading both keeps every existing installation working: an environment that
    only has /etc/health-checker.secrets behaves exactly as before.
    """
    global _config_values
    values = _read_kv_file(secrets_file)
    values.update(_read_kv_file(config_file))
    _config_values = values
    return values


def cfg(key: str, default: Any = None) -> Any:
    """Environment variable, then config file, then the built-in default."""
    value = os.environ.get(key) or _config_values.get(key)
    return default if value in (None, "") else value


def cfg_int(key: str, default: int) -> int:
    value = cfg(key)
    try:
        return int(value) if value is not None else default
    except (TypeError, ValueError):
        print(f"WARNING: {key}='{value}' is not an integer, using {default}.",
              file=sys.stderr)
        return default


def cfg_float(key: str, default: float) -> float:
    value = cfg(key)
    try:
        return float(value) if value is not None else default
    except (TypeError, ValueError):
        print(f"WARNING: {key}='{value}' is not a number, using {default}.",
              file=sys.stderr)
        return default


def _load_secrets(config_file: str, secrets_file: str) -> dict[str, str]:
    """Return the four credentials, or exit explaining exactly what is missing."""
    if not os.path.isfile(config_file) and not os.path.isfile(secrets_file):
        print(f"INFO: Neither '{config_file}' nor '{secrets_file}' exists – "
              f"relying on environment variables. "
              f"Run '{os.path.basename(sys.argv[0])} --init-config' to create one.",
              file=sys.stderr)

    secrets: dict[str, str] = {}
    missing: list[str] = []
    for key in _REQUIRED_SECRETS:
        value = cfg(key)
        if not value:
            missing.append(key)
        else:
            secrets[key] = value

    if missing:
        print(
            f"ERROR: Missing credentials: {', '.join(missing)}.\n"
            f"  Provide them in '{config_file}', as environment variables, or run\n"
            f"  '{os.path.basename(sys.argv[0])} --init-config' to generate the file.",
            file=sys.stderr,
        )
        sys.exit(1)
    return secrets


# ─────────────────────────────────────────────────────────────────────────────
# Shared – Manager JWT token
# ─────────────────────────────────────────────────────────────────────────────
def _get_manager_token(url: str, user: str, password: str) -> tuple[str | None, str | None]:
    auth_endpoint = f"{url}/security/user/authenticate?raw=true"
    try:
        resp = requests.post(auth_endpoint, auth=(user, password),
                             verify=False, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            return resp.text.strip(), None
        return None, f"HTTP {resp.status_code} from {auth_endpoint}"
    except requests.exceptions.ConnectionError as exc:
        return None, f"Connection refused: {exc}"
    except requests.exceptions.Timeout:
        return None, "Request timed out"
    except Exception as exc:
        return None, str(exc)


# ─────────────────────────────────────────────────────────────────────────────
# Check 0 – Container / Pod Health
# ─────────────────────────────────────────────────────────────────────────────
def check_container_health_docker() -> dict:
    wazuh_images = [DOCKER_IMAGE_MANAGER, DOCKER_IMAGE_INDEXER, DOCKER_IMAGE_DASHBOARD]
    try:
        result = subprocess.run(
            ["docker", "ps", "--format",
             "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.State}}",
             "--filter", "status=running",
             "--filter", "status=exited",
             "--filter", "status=restarting"],
            capture_output=True, text=True, timeout=15,
        )
    except FileNotFoundError:
        return _make_check("error", True,
                           details="'docker' command not found in PATH")
    except subprocess.TimeoutExpired:
        return _make_check("error", True,
                           details="'docker ps' timed out")
    except Exception as exc:
        return _make_check("error", True, details=str(exc))

    if result.returncode != 0:
        return _make_check("error", True,
                           details=f"docker ps failed: {result.stderr.strip()}")

    containers: list[dict] = []
    for line in result.stdout.strip().splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        name, image, status_text, state = parts[0], parts[1], parts[2], parts[3]
        if any(img in image for img in wazuh_images):
            containers.append({
                "name": name, "image": image,
                "status": status_text, "state": state,
            })

    if not containers:
        return _make_check("error", True,
                           details="No Wazuh containers found. Is the stack running?")

    issues: list[str] = []
    services_info: list[dict] = []
    for c in containers:
        name = c["name"]
        image = c["image"]
        state = c["state"]

        info = {"name": name, "image": image, "state": state,
                "status_text": c["status"]}

        if state.lower() != "running":
            issues.append(f"{name} ({image}): state='{state}' (expected 'running')")
        services_info.append(info)

    notify = bool(issues)
    status = "error" if issues else "ok"
    return _make_check(status, notify,
                       container_count=len(services_info),
                       containers=services_info,
                       issues=issues or None)


def check_container_health_k8s(namespace: str) -> dict:
    try:
        result = subprocess.run(
            ["kubectl", "get", "pods", "-n", namespace, "-o", "json"],
            capture_output=True, text=True, timeout=15,
        )
    except FileNotFoundError:
        return _make_check("error", True,
                           details="'kubectl' command not found in PATH")
    except subprocess.TimeoutExpired:
        return _make_check("error", True,
                           details="'kubectl get pods' timed out")
    except Exception as exc:
        return _make_check("error", True, details=str(exc))

    if result.returncode != 0:
        return _make_check("error", True,
                           details=f"kubectl failed: {result.stderr.strip()}")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return _make_check("error", True,
                           details="Could not parse kubectl JSON output")

    pods = data.get("items", [])
    if not pods:
        return _make_check("error", True,
                           details=f"No pods found in namespace '{namespace}'")

    issues: list[str] = []
    pods_info: list[dict] = []
    for pod in pods:
        name = pod.get("metadata", {}).get("name", "unknown")
        phase = pod.get("status", {}).get("phase", "unknown")

        container_statuses = pod.get("status", {}).get("containerStatuses", [])
        ready_count = sum(1 for cs in container_statuses if cs.get("ready"))
        total_count = len(container_statuses)
        restarts = sum(cs.get("restartCount", 0) for cs in container_statuses)

        info = {
            "name": name, "phase": phase,
            "ready": f"{ready_count}/{total_count}",
            "restarts": restarts,
        }

        if phase != "Running":
            issues.append(f"{name}: phase='{phase}' (expected 'Running')")
        elif ready_count < total_count:
            issues.append(f"{name}: only {ready_count}/{total_count} containers ready")

        if restarts > 5:
            issues.append(f"{name}: high restart count ({restarts})")

        pods_info.append(info)

    notify = bool(issues)
    status = "error" if issues else "ok"
    return _make_check(status, notify,
                       pod_count=len(pods_info),
                       pods=pods_info,
                       issues=issues or None)


# ─────────────────────────────────────────────────────────────────────────────
# Check 1 – Manager API
# ─────────────────────────────────────────────────────────────────────────────
def check_manager_api(url: str, user: str, password: str) -> dict:
    query_endpoint = f"{url}/?pretty=true"
    info_endpoint = f"{url}/manager/info"
    try:
        token, err = _get_manager_token(url, user, password)
        if err:
            return _make_check("error", True,
                               details=f"Authentication failed: {err}",
                               url=f"{url}/security/user/authenticate?raw=true")
        resp = requests.get(query_endpoint,
                            headers={"Authorization": f"Bearer {token}"},
                            verify=False, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            version = data.get("data", {}).get("api_version", "unknown")
            result = _make_check("ok", False, http_code=resp.status_code,
                                 api_version=version, url=query_endpoint)

            info_resp = requests.get(info_endpoint,
                                     headers={"Authorization": f"Bearer {token}"},
                                     verify=False, timeout=REQUEST_TIMEOUT)
            if info_resp.status_code == 200:
                items = (info_resp.json().get("data", {})
                         .get("affected_items", []))
                if items:
                    item = items[0]
                    result["manager_version"] = item.get("version", "unknown")
                    result["manager_uuid"] = item.get("uuid", "unknown")
                else:
                    result["status"] = "warning"
                    result["notify"] = True
                    result["details"] = "Manager info endpoint returned no affected_items"
            else:
                result["status"] = "warning"
                result["notify"] = True
                result["details"] = (
                    f"Manager API is reachable but /manager/info failed with HTTP "
                    f"{info_resp.status_code}")
                result["manager_info_url"] = info_endpoint

            return result
        return _make_check("error", True, http_code=resp.status_code,
                           details=f"Unexpected status code: {resp.status_code}",
                           url=query_endpoint)
    except requests.exceptions.ConnectionError as exc:
        return _make_check("error", True, details=f"Connection refused: {exc}", url=url)
    except requests.exceptions.Timeout:
        return _make_check("error", True, details="Request timed out", url=url)
    except Exception as exc:
        return _make_check("error", True, details=str(exc), url=url)


# ─────────────────────────────────────────────────────────────────────────────
# Check 18 – Alert volume trend (Indexer)
# ─────────────────────────────────────────────────────────────────────────────
def check_alert_volume_trend(indexer_url: str, user: str, password: str,
                             window_days: int, drop_threshold_pct: float) -> dict:
    endpoint = f"{indexer_url}/wazuh-alerts-*/_count"

    if window_days <= 0:
        return _make_check("error", True,
                           details="alerts-trend-days must be > 0",
                           comparison_window_days=window_days)

    def _count_for_range(gte_expr: str, lt_expr: str) -> tuple[int | None, str | None]:
        payload = {
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": gte_expr,
                        "lt": lt_expr,
                    }
                }
            }
        }
        try:
            resp = requests.post(endpoint, auth=(user, password),
                                 verify=False, timeout=REQUEST_TIMEOUT,
                                 json=payload)
            if resp.status_code != 200:
                return None, f"HTTP {resp.status_code}"
            return int(resp.json().get("count", 0)), None
        except requests.exceptions.ConnectionError as exc:
            return None, f"Connection refused: {exc}"
        except requests.exceptions.Timeout:
            return None, "Request timed out"
        except Exception as exc:
            return None, str(exc)

    current_gte = f"now-{window_days}d/d"
    current_lt = "now/d"
    previous_gte = f"now-{window_days * 2}d/d"
    previous_lt = f"now-{window_days}d/d"

    current_count, err_current = _count_for_range(current_gte, current_lt)
    if err_current:
        return _make_check("error", True,
                           details=f"Failed current window count: {err_current}",
                           url=endpoint)

    previous_count, err_previous = _count_for_range(previous_gte, previous_lt)
    if err_previous:
        return _make_check("error", True,
                           details=f"Failed previous window count: {err_previous}",
                           url=endpoint)

    if previous_count == 0:
        return _make_check(
            "ok", False,
            comparison_window_days=window_days,
            drop_threshold_pct=drop_threshold_pct,
            current_alerts=current_count,
            previous_alerts=previous_count,
            drop_pct=None,
            details="Previous window has zero alerts; drop percentage is not computable.",
            current_window={"gte": current_gte, "lt": current_lt},
            previous_window={"gte": previous_gte, "lt": previous_lt},
            url=endpoint,
        )

    drop_pct = round(((previous_count - current_count) / previous_count) * 100, 2)
    notify = drop_pct >= drop_threshold_pct
    status = "warning" if notify else "ok"

    return _make_check(
        status, notify,
        comparison_window_days=window_days,
        drop_threshold_pct=drop_threshold_pct,
        current_alerts=current_count,
        previous_alerts=previous_count,
        drop_pct=drop_pct,
        current_window={"gte": current_gte, "lt": current_lt},
        previous_window={"gte": previous_gte, "lt": previous_lt},
        url=endpoint,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Check 2 – Indexer API
# ─────────────────────────────────────────────────────────────────────────────
def check_indexer_api(url: str, user: str, password: str) -> dict:
    endpoint = f"{url}/_cluster/health"
    try:
        resp = requests.get(endpoint, auth=(user, password),
                            verify=False, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            return _make_check("ok", False, http_code=resp.status_code,
                               cluster_name=data.get("cluster_name"),
                               cluster_status=data.get("status"), url=endpoint)
        return _make_check("error", True, http_code=resp.status_code,
                           details=f"Unexpected status code: {resp.status_code}", url=endpoint)
    except requests.exceptions.ConnectionError as exc:
        return _make_check("error", True, details=f"Connection refused: {exc}", url=endpoint)
    except requests.exceptions.Timeout:
        return _make_check("error", True, details="Request timed out", url=endpoint)
    except Exception as exc:
        return _make_check("error", True, details=str(exc), url=endpoint)


# ─────────────────────────────────────────────────────────────────────────────
# Check 3 – Dashboard
# ─────────────────────────────────────────────────────────────────────────────
def check_dashboard(url: str) -> dict:
    try:
        resp = requests.get(url, verify=False, timeout=REQUEST_TIMEOUT,
                            allow_redirects=True)
        if resp.status_code in (200, 302, 301):
            return _make_check("ok", False, http_code=resp.status_code, url=url)
        return _make_check("error", True, http_code=resp.status_code,
                           details=f"Unexpected status code: {resp.status_code}", url=url)
    except requests.exceptions.ConnectionError as exc:
        return _make_check("error", True, details=f"Connection refused: {exc}", url=url)
    except requests.exceptions.Timeout:
        return _make_check("error", True, details="Request timed out", url=url)
    except Exception as exc:
        return _make_check("error", True, details=str(exc), url=url)


# ─────────────────────────────────────────────────────────────────────────────
# Check 4 – Disk Space
# ─────────────────────────────────────────────────────────────────────────────
def check_disk_space(path: str, threshold_pct: int) -> dict:
    try:
        usage = shutil.disk_usage(path)
        used_pct = round(usage.used / usage.total * 100, 2)
        notify = used_pct >= threshold_pct
        status = "warning" if notify else "ok"
        return _make_check(status, notify, path=path, used_pct=used_pct,
                           threshold_pct=threshold_pct, used_gb=_gb(usage.used),
                           total_gb=_gb(usage.total), free_gb=_gb(usage.free))
    except Exception as exc:
        return _make_check("error", True, details=str(exc), path=path)


# ─────────────────────────────────────────────────────────────────────────────
# Check 4b – Indexer Disk Space (via API)
# ─────────────────────────────────────────────────────────────────────────────
def check_indexer_disk_space(indexer_url: str, user: str, password: str,
                             threshold_pct: int) -> dict:
    endpoint = (f"{indexer_url}/_cat/nodes?format=json"
                f"&h=name,ip,disk.total,disk.used,disk.used_percent&bytes=b")
    try:
        resp = requests.get(endpoint, auth=(user, password),
                            verify=False, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.ConnectionError as exc:
        return _make_check("error", True, details=f"Connection refused: {exc}", url=endpoint)
    except requests.exceptions.Timeout:
        return _make_check("error", True, details="Request timed out", url=endpoint)
    except Exception as exc:
        return _make_check("error", True, details=str(exc), url=endpoint)

    if resp.status_code != 200:
        return _make_check("error", True, details=f"HTTP {resp.status_code}", url=endpoint)

    raw_nodes = resp.json()
    per_node: list[dict] = []
    global_issues: list[str] = []

    for n in raw_nodes:
        ip = n.get("ip", "?")
        name = n.get("name", "")
        try:
            total_b = int(n.get("disk.total", 0) or 0)
            used_b = int(n.get("disk.used", 0) or 0)
            used_pct_str = n.get("disk.used_percent")
            used_pct = float(used_pct_str) if used_pct_str else 0.0
        except ValueError:
            total_b = used_b = 0
            used_pct = 0.0

        notify_node = used_pct >= threshold_pct
        if notify_node:
            global_issues.append(
                f"[{ip}] ({name}) Disk usage {used_pct}% >= {threshold_pct}%")
        per_node.append({
            "node": ip, "name": name,
            "status": "warning" if notify_node else "ok",
            "used_pct": used_pct, "total_gb": _gb(total_b), "used_gb": _gb(used_b),
        })

    any_notify = len(global_issues) > 0
    status = "warning" if any_notify else "ok"
    return _make_check(status, any_notify, node_count=len(per_node), nodes=per_node,
                       issues=global_issues if global_issues else None,
                       threshold_pct=threshold_pct, url=endpoint)


# ─────────────────────────────────────────────────────────────────────────────
# Check 5 & 6 – Shard counts
# ─────────────────────────────────────────────────────────────────────────────
def _get_max_shards_per_node(indexer_url: str, user: str, password: str) -> int:
    try:
        resp = requests.get(f"{indexer_url}/_cluster/settings",
                            auth=(user, password), verify=False,
                            timeout=REQUEST_TIMEOUT,
                            params={"include_defaults": "true"})
        if resp.status_code == 200:
            data = resp.json()
            for section in ("persistent", "transient", "defaults"):
                val = (data.get(section, {})
                           .get("cluster", {})
                           .get("max_shards_per_node"))
                if val is not None:
                    return int(val)
    except Exception:
        pass
    return 1000


def _get_data_node_count(indexer_url: str, user: str, password: str) -> int:
    try:
        resp = requests.get(f"{indexer_url}/_nodes/stats",
                            auth=(user, password), verify=False,
                            timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            nodes = resp.json().get("nodes", {})
            data_nodes = [n for n in nodes.values()
                          if "data" in n.get("roles", [])]
            return len(data_nodes) if data_nodes else max(1, len(nodes))
    except Exception:
        pass
    return 1


def check_shards(indexer_url: str, user: str, password: str,
                 shard_threshold_pct: int) -> tuple[dict, dict]:
    max_shards_per_node = _get_max_shards_per_node(indexer_url, user, password)
    node_count = _get_data_node_count(indexer_url, user, password)
    total_limit = max_shards_per_node * node_count

    active_shards = 0
    health_error = None
    try:
        resp = requests.get(f"{indexer_url}/_cluster/health",
                            auth=(user, password), verify=False,
                            timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            active_shards = resp.json().get("active_shards", 0)
        else:
            health_error = f"HTTP {resp.status_code}"
    except Exception as exc:
        health_error = str(exc)

    shards_per_node_result = {
        "status": "ok", "notify": False,
        "max_shards_per_node": max_shards_per_node,
        "node_count": node_count, "total_limit": total_limit,
        "active_shards": active_shards if not health_error else None,
    }
    if health_error:
        shards_per_node_result["details"] = f"Could not fetch health: {health_error}"

    if health_error:
        active_shard_result = _make_check(
            "error", True,
            details=f"Could not fetch cluster health: {health_error}")
    else:
        pct_used = round(active_shards / total_limit * 100, 2) if total_limit else 0.0
        notify = pct_used >= shard_threshold_pct
        status = "warning" if notify else "ok"
        active_shard_result = _make_check(
            status, notify, active=active_shards, limit=total_limit,
            pct_used=pct_used, threshold_pct=shard_threshold_pct)

    return shards_per_node_result, active_shard_result


# ─────────────────────────────────────────────────────────────────────────────
# Check 7 – JVM Options (API-based)
# ─────────────────────────────────────────────────────────────────────────────
def check_jvm_api(indexer_url: str, user: str, password: str) -> dict:
    endpoint_nodes = f"{indexer_url}/_nodes"
    endpoint_stats = f"{indexer_url}/_nodes/stats"
    try:
        resp_nodes = requests.get(endpoint_nodes, auth=(user, password),
                                  verify=False, timeout=REQUEST_TIMEOUT)
        resp_stats = requests.get(endpoint_stats, auth=(user, password),
                                  verify=False, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.ConnectionError as exc:
        return _make_check("error", True, details=f"Connection refused: {exc}",
                           url=endpoint_nodes)
    except requests.exceptions.Timeout:
        return _make_check("error", True, details="Request timed out",
                           url=endpoint_nodes)
    except Exception as exc:
        return _make_check("error", True, details=str(exc), url=endpoint_nodes)

    if resp_nodes.status_code != 200 or resp_stats.status_code != 200:
        return _make_check("error", True,
                           details=f"HTTP {resp_nodes.status_code} / {resp_stats.status_code}",
                           url=endpoint_nodes)

    nodes_data = resp_nodes.json().get("nodes", {})
    stats_data = resp_stats.json().get("nodes", {})
    per_node: list[dict] = []
    global_issues: list[str] = []

    for node_id, n_info in nodes_data.items():
        ip = n_info.get("ip", "unknown")
        name = n_info.get("name", "unknown")
        jvm_mem = n_info.get("jvm", {}).get("mem", {})
        xms = jvm_mem.get("heap_init_in_bytes")
        xmx = jvm_mem.get("heap_max_in_bytes")
        n_stats = stats_data.get(node_id, {})
        total_ram = n_stats.get("os", {}).get("mem", {}).get("total_in_bytes")
        heap_used_pct = n_stats.get("jvm", {}).get("mem", {}).get("heap_used_percent")

        if total_ram is None or xms is None or xmx is None:
            per_node.append({"node": ip, "name": name, "status": "warning",
                             "details": "Missing RAM or JVM values in API response"})
            global_issues.append(f"[{ip}] Missing RAM or JVM values")
            continue

        recommended_max = total_ram // 2
        node_issues: list[str] = []
        if xms < recommended_max:
            node_issues.append(
                f"Xms ({_gb(xms)} GB) is below 50% of RAM ({_gb(recommended_max)} GB)")
        if xmx < recommended_max:
            node_issues.append(
                f"Xmx ({_gb(xmx)} GB) is below 50% of RAM ({_gb(recommended_max)} GB)")
        if xmx > total_ram:
            node_issues.append(
                f"Xmx ({_gb(xmx)} GB) exceeds total RAM ({_gb(total_ram)} GB)")

        node_status = "warning" if node_issues else "ok"
        per_node.append({
            "node": ip, "name": name, "status": node_status,
            "xms_gb": _gb(xms), "xmx_gb": _gb(xmx),
            "total_ram_gb": _gb(total_ram),
            "recommended_heap_gb": _gb(recommended_max),
            "heap_used_pct": heap_used_pct,
            "issues": node_issues if node_issues else None,
        })
        if node_issues:
            for issue in node_issues:
                global_issues.append(f"[{ip}] ({name}) {issue}")

    any_problems = any(n["status"] != "ok" for n in per_node)
    status = "warning" if any_problems else "ok"
    return _make_check(status, any_problems, node_count=len(per_node),
                       nodes=per_node,
                       issues=global_issues if global_issues else None,
                       url=endpoint_nodes)


# ─────────────────────────────────────────────────────────────────────────────
# Check 8 – Unassigned Shards
# ─────────────────────────────────────────────────────────────────────────────
def check_unassigned_shards(indexer_url: str, user: str, password: str) -> dict:
    endpoint = f"{indexer_url}/_cluster/health"
    try:
        resp = requests.get(endpoint, auth=(user, password),
                            verify=False, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            count = resp.json().get("unassigned_shards", 0)
            notify = count > 0
            return _make_check("warning" if notify else "ok", notify, count=count)
        return _make_check("error", True,
                           details=f"HTTP {resp.status_code}", url=endpoint)
    except requests.exceptions.ConnectionError as exc:
        return _make_check("error", True, details=f"Connection refused: {exc}",
                           url=endpoint)
    except requests.exceptions.Timeout:
        return _make_check("error", True, details="Request timed out", url=endpoint)
    except Exception as exc:
        return _make_check("error", True, details=str(exc), url=endpoint)


# ─────────────────────────────────────────────────────────────────────────────
# Check 9 – Ports 1514 / 1515
# ─────────────────────────────────────────────────────────────────────────────
def check_ports(hosts: str | list[str], ports: list[int],
                timeout: int = REQUEST_TIMEOUT) -> dict:
    """
    Probe the agent-facing TCP ports on every manager node.

    Agents enroll and report against workers as well as the master, so in a
    manager cluster each node has to be probed individually.
    """
    if isinstance(hosts, str):
        hosts = [hosts]

    per_host: dict[str, dict[str, str]] = {}
    issues: list[str] = []
    for host in hosts:
        results: dict[str, str] = {}
        for port in ports:
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    results[str(port)] = "open"
            except (ConnectionRefusedError, socket.timeout, OSError) as exc:
                results[str(port)] = f"closed/unreachable ({exc})"
                issues.append(f"{host}:{port} closed/unreachable ({exc})")
        per_host[host] = results

    notify = bool(issues)
    status = "error" if notify else "ok"
    result = _make_check(status, notify, hosts=per_host,
                         host_count=len(per_host), issues=issues or None)
    # Preserve the single-host shape consumed by the notifiers and the summary.
    if len(per_host) == 1:
        only_host = next(iter(per_host))
        result["host"] = only_host
        result["ports"] = per_host[only_host]
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Check 10 – Agent summary
# ─────────────────────────────────────────────────────────────────────────────
def check_agents(url: str, user: str, password: str) -> dict:
    token, err = _get_manager_token(url, user, password)
    if err:
        return _make_check("error", True, details=f"Authentication failed: {err}", url=url)

    endpoint = f"{url}/agents/summary/status"
    try:
        resp = requests.get(endpoint,
                            headers={"Authorization": f"Bearer {token}"},
                            verify=False, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            return _make_check("error", True, http_code=resp.status_code,
                               details=f"HTTP {resp.status_code}", url=endpoint)

        conn = resp.json().get("data", {}).get("connection", {})
        total        = conn.get("total", 0)
        active       = conn.get("active", 0)
        disconnected = conn.get("disconnected", 0)
        pending      = conn.get("pending", 0)
        never        = conn.get("never_connected", 0)

        def pct(n: int) -> float:
            return round(n / total * 100, 1) if total else 0.0

        return _make_check(
            "ok", True, total=total,
            active=active, active_pct=pct(active),
            disconnected=disconnected, disconnected_pct=pct(disconnected),
            pending=pending, pending_pct=pct(pending),
            never_connected=never, never_connected_pct=pct(never),
        )
    except requests.exceptions.ConnectionError as exc:
        return _make_check("error", True, details=f"Connection refused: {exc}", url=endpoint)
    except requests.exceptions.Timeout:
        return _make_check("error", True, details="Request timed out", url=endpoint)
    except Exception as exc:
        return _make_check("error", True, details=str(exc), url=endpoint)


# ─────────────────────────────────────────────────────────────────────────────
# ISM (Index State Management) helpers – shared by checks 11 and 13
# ─────────────────────────────────────────────────────────────────────────────
# The ISM plugin is exposed under two different prefixes depending on the
# OpenSearch / Open Distro version shipped with the Wazuh Indexer. Both are
# tried before concluding that no policy exists.
ISM_API_PREFIXES = ("_plugins/_ism", "_opendistro/_ism")

# GET /_plugins/_ism/policies returns only 20 policies unless a size is given,
# which silently hides policies on environments with many of them.
ISM_POLICY_PAGE_SIZE = 1000

# Index patterns whose ISM management actually matters for a Wazuh deployment.
ISM_EXPLAIN_PATTERN = "wazuh-*"

# States are considered "delete" states when they run a delete action or when
# they are named like one (some policies only shrink/close under such a name).
_DELETE_STATE_NAMES = ("delete", "deleted", "delete_state", "deletion")


def _ism_request(indexer_url: str, user: str, password: str, path: str,
                 params: dict | None = None) -> tuple[dict | None, str | None, str]:
    """
    GET an ISM endpoint, trying every known API prefix.

    Returns (payload, error, endpoint_used). ``error`` is None on success and
    distinguishes a genuine failure (auth, permissions, connectivity) from an
    empty-but-valid answer, so callers never report "no policies" when the
    request itself could not be completed.
    """
    last_error = "unknown error"
    endpoint = ""
    for prefix in ISM_API_PREFIXES:
        endpoint = f"{indexer_url}/{prefix}/{path.lstrip('/')}"
        try:
            resp = requests.get(endpoint, auth=(user, password), verify=False,
                                timeout=REQUEST_TIMEOUT, params=params)
        except requests.exceptions.ConnectionError as exc:
            return None, f"Connection refused: {exc}", endpoint
        except requests.exceptions.Timeout:
            return None, "Request timed out", endpoint
        except Exception as exc:
            return None, str(exc), endpoint

        if resp.status_code == 200:
            try:
                return resp.json(), None, endpoint
            except ValueError:
                return None, "Malformed JSON in ISM response", endpoint
        if resp.status_code in (401, 403):
            return None, (f"HTTP {resp.status_code}: the '{user}' user is not allowed to "
                          f"read ISM policies. Grant the 'cluster:admin/opendistro/ism/*' "
                          f"permissions or use an admin account."), endpoint
        # 404 / 400 usually just means "wrong prefix for this version" – retry.
        last_error = f"HTTP {resp.status_code}"
    return None, last_error, endpoint


def _ism_condition_age(conditions: dict) -> str | None:
    """Pick whichever age condition an ISM transition uses."""
    for key in ("min_index_age", "min_rollover_age", "min_age"):
        value = conditions.get(key)
        if value:
            return value
    return None


def _analyze_ism_policy(item: dict) -> dict:
    """
    Extract the meaningful parts of an ISM policy document.

    A policy is considered to define retention when *any* state performs a
    delete action (or is named like a delete state). The retention age is read
    from the transition that leads into that state; transitions that use
    min_doc_count / min_size instead of an age are reported as non-age
    conditions rather than being discarded, which is what previously made the
    script report a perfectly working policy as missing.
    """
    policy = item.get("policy", {}) or {}
    name = policy.get("policy_id") or item.get("_id") or "unknown"

    states = policy.get("states", []) or []
    state_names = [s.get("name") for s in states]

    delete_states: set[str] = set()
    rollover_age = rollover_size = None
    for state in states:
        state_name = state.get("name", "")
        for action in state.get("actions", []) or []:
            if "delete" in action:
                delete_states.add(state_name)
            if "rollover" in action:
                rollover = action.get("rollover") or {}
                rollover_age = rollover.get("min_index_age") or rollover_age
                rollover_size = (rollover.get("min_size")
                                 or rollover.get("min_primary_shard_size")
                                 or rollover_size)
        if state_name.lower() in _DELETE_STATE_NAMES:
            delete_states.add(state_name)

    delete_min_age = None
    delete_conditions: dict = {}
    for state in states:
        for transition in state.get("transitions", []) or []:
            target = transition.get("state_name", "")
            if target not in delete_states:
                continue
            conditions = transition.get("conditions", {}) or {}
            delete_conditions = conditions or delete_conditions
            age = _ism_condition_age(conditions)
            if age:
                delete_min_age = age

    # ism_template is what makes a policy apply automatically to new indices.
    ism_template = policy.get("ism_template") or []
    if isinstance(ism_template, dict):
        ism_template = [ism_template]
    index_patterns: list[str] = []
    for tmpl in ism_template:
        index_patterns.extend((tmpl or {}).get("index_patterns", []) or [])

    return {
        "name": name,
        "states": state_names,
        "default_state": policy.get("default_state"),
        "delete_states": sorted(delete_states),
        "delete_min_age": delete_min_age,
        "delete_conditions": delete_conditions or None,
        "rollover_age": rollover_age,
        "rollover_size": rollover_size,
        "index_patterns": index_patterns,
        "has_delete_phase": bool(delete_states),
        "has_age_retention": delete_min_age is not None,
    }


def _fetch_ism_policies(indexer_url: str, user: str,
                        password: str) -> tuple[list[dict], str | None, str]:
    """Return (analyzed policies, error, endpoint)."""
    payload, error, endpoint = _ism_request(
        indexer_url, user, password, "policies",
        params={"from": 0, "size": ISM_POLICY_PAGE_SIZE})
    if error:
        return [], error, endpoint
    raw = (payload or {}).get("policies", []) or []
    return [_analyze_ism_policy(item) for item in raw], None, endpoint


def _fetch_ism_explain(indexer_url: str, user: str, password: str,
                       pattern: str = ISM_EXPLAIN_PATTERN) -> tuple[dict, str | None]:
    """
    Ask ISM which indices are actually managed, and by which policy.

    This is what tells apart "no policy exists" from "policies exist but are
    not attached to any index" – the two situations the previous version
    reported identically.
    """
    payload, error, _ = _ism_request(
        indexer_url, user, password, f"explain/{pattern}")
    if error:
        return {}, error

    managed: dict[str, dict] = {}
    for index_name, info in (payload or {}).items():
        if not isinstance(info, dict):
            continue  # skips total_managed_indices and similar scalars
        policy_id = (info.get("policy_id")
                     or info.get("index.plugins.index_state_management.policy_id")
                     or info.get("index.opendistro.index_state_management.policy_id"))
        if not policy_id:
            continue
        managed[index_name] = {
            "policy_id": policy_id,
            "enabled": info.get("enabled", True),
            "state": (info.get("state") or {}).get("name"),
            "action": (info.get("action") or {}).get("name"),
            "failed": bool((info.get("action") or {}).get("failed")),
            "info": (info.get("info") or {}).get("message"),
        }
    return managed, None


# ─────────────────────────────────────────────────────────────────────────────
# Check 11 – ISM Policies
# ─────────────────────────────────────────────────────────────────────────────
def check_ilm_policies(indexer_url: str, user: str, password: str) -> dict:
    """
    Verify that ISM policies exist AND are effectively applied.

    The check reports four clearly separated situations instead of the single
    "no policies found" verdict used previously:

      * the ISM API could not be queried (auth / permissions / connectivity)
      * no policy is defined at all
      * policies are defined but no index is managed by them
      * policies are defined and managed, optionally without a delete phase
    """
    policies, error, endpoint = _fetch_ism_policies(indexer_url, user, password)
    if error:
        return _make_check("error", True, details=f"Could not read ISM policies: {error}",
                           url=endpoint)

    managed, explain_error = _fetch_ism_explain(indexer_url, user, password)

    issues: list[str] = []
    managed_by_policy: dict[str, int] = {}
    failed_indices: list[str] = []
    disabled_indices: list[str] = []
    for index_name, info in managed.items():
        managed_by_policy[info["policy_id"]] = managed_by_policy.get(info["policy_id"], 0) + 1
        if info["failed"]:
            failed_indices.append(f"{index_name} ({info.get('info') or 'action failed'})")
        elif not info["enabled"]:
            disabled_indices.append(index_name)

    for policy in policies:
        policy["managed_indices"] = managed_by_policy.get(policy["name"], 0)

    if not policies:
        if managed:
            # Indices reference a policy that the API did not return: almost
            # always a permissions or API-prefix problem, not a missing policy.
            return _make_check(
                "warning", True, policies=[], managed_indices=len(managed),
                details=(f"{len(managed)} index(es) are managed by ISM but no policy "
                         f"document could be retrieved from {endpoint}."),
                url=endpoint)
        return _make_check(
            "warning", True, policies=[], managed_indices=0,
            details="No ISM policies found. Log retention may be unmanaged.",
            url=endpoint)

    if explain_error:
        issues.append(f"Could not verify which indices are managed: {explain_error}")
    elif not managed:
        issues.append(
            f"{len(policies)} ISM policy(ies) are defined but no {ISM_EXPLAIN_PATTERN} "
            f"index is currently managed by them. Check the 'ism_template' index "
            f"patterns or attach the policy to the existing indices.")

    if failed_indices:
        issues.append("ISM action failed on: " + ", ".join(sorted(failed_indices)[:5]))
    if disabled_indices:
        issues.append("ISM is disabled on: " + ", ".join(sorted(disabled_indices)[:5]))

    with_retention = [p for p in policies if p["has_delete_phase"]]
    if not with_retention:
        issues.append(
            f"{len(policies)} ISM policy(ies) found, but none defines a delete phase, "
            f"so indices are never removed.")
    else:
        for policy in with_retention:
            if not policy["has_age_retention"] and policy["delete_conditions"]:
                issues.append(
                    f"{policy['name']}: deletes by "
                    f"{', '.join(policy['delete_conditions'])} instead of index age; "
                    f"retention in days cannot be projected.")

    notify = bool(issues)
    return _make_check(
        "warning" if notify else "ok", notify,
        policy_count=len(policies),
        policies=policies,
        managed_indices=len(managed),
        policies_with_retention=len(with_retention),
        issues=issues or None,
        url=endpoint)


# ─────────────────────────────────────────────────────────────────────────────
# Check 12 – Cron rotation (deploy-mode aware)
# ─────────────────────────────────────────────────────────────────────────────
def check_cron_rotation(deploy_mode: str = "bare-metal",
                        namespace: str = K8S_DEFAULT_NAMESPACE) -> dict:
    TARGETS = {
        "alerts":   "/var/ossec/logs/alerts",
        "archives": "/var/ossec/logs/archives",
    }
    cron_dirs_files = ["/etc/crontab", "/etc/cron.d",
                       "/var/spool/cron", "/var/spool/cron/crontabs"]

    all_cron_lines: list[str] = []

    if deploy_mode == "bare-metal":
        def _scan_file(path: str) -> list[str]:
            lines = []
            try:
                with open(path) as f:
                    for line in f:
                        stripped = line.strip()
                        if stripped and not stripped.startswith("#"):
                            lines.append(stripped)
            except (PermissionError, FileNotFoundError):
                pass
            return lines

        for loc in cron_dirs_files:
            if os.path.isfile(loc):
                all_cron_lines.extend(_scan_file(loc))
            elif os.path.isdir(loc):
                try:
                    fnames = os.listdir(loc)
                except (PermissionError, OSError):
                    # /var/spool/cron/crontabs is root-only on Debian/Ubuntu;
                    # skip it instead of aborting the whole run.
                    continue
                for fname in fnames:
                    fpath = os.path.join(loc, fname)
                    if os.path.isfile(fpath):
                        all_cron_lines.extend(_scan_file(fpath))
    else:
        if deploy_mode == "docker":
            target = DOCKER_IMAGE_MANAGER
        else:
            target = K8S_POD_MANAGER_MASTER

        try:
            result = _container_exec(
                deploy_mode, target, ["crontab", "-l"],
                namespace=namespace, timeout=15)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        all_cron_lines.append(stripped)
        except Exception:
            pass

        for cron_dir in ["/etc/cron.d"]:
            try:
                ls_result = _container_exec(
                    deploy_mode, target,
                    ["sh", "-c", f"cat {cron_dir}/* 2>/dev/null || true"],
                    namespace=namespace, timeout=15)
                if ls_result.returncode == 0:
                    for line in ls_result.stdout.splitlines():
                        stripped = line.strip()
                        if stripped and not stripped.startswith("#"):
                            all_cron_lines.append(stripped)
            except Exception:
                pass

    found: dict[str, list[str]] = {k: [] for k in TARGETS}
    for label, target_path in TARGETS.items():
        for line in all_cron_lines:
            if target_path in line:
                found[label].append(line)

    missing = [k for k, v in found.items() if not v]
    notify = bool(missing)
    status = "warning" if notify else "ok"

    result = _make_check(status, notify,
                         alerts_jobs=found["alerts"],
                         archives_jobs=found["archives"],
                         deploy_mode=deploy_mode)
    if missing:
        result["missing_rotation_for"] = missing
        result["details"] = (
            f"No cron job found for: {', '.join('/var/ossec/logs/' + m + '/' for m in missing)}")
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Check 13 – Retention feasibility
# ─────────────────────────────────────────────────────────────────────────────
def _parse_age_to_days(age_str: str) -> float | None:
    """
    Convert an OpenSearch time value into days.

    OpenSearch time units are case sensitive: 'm' is minutes while 'M' is
    months, and 'h' is hours - the previous version mapped 'h' to a full day
    and rejected 'm'/'s' outright, which silently dropped valid policies.

    Days and hours are additionally accepted in upper case ('180D', '4320H')
    for tolerance: the indexer accepts those spellings on policy creation, and
    although it normalises them to lower case before storing, the value may
    reach this parser from elsewhere. 'M', 'w' and 'y' are likewise kept for
    tolerance only - the indexer rejects them when the policy is created.
    """
    if not age_str:
        return None
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*(ms|[smhdDHwMy])", str(age_str).strip())
    if not m:
        return None
    n, unit = float(m.group(1)), m.group(2)
    days_per_unit = {
        "ms": 1 / 86_400_000,
        "s":  1 / 86_400,
        "m":  1 / 1_440,
        "h":  1 / 24,
        "H":  1 / 24,
        "d":  1,
        "D":  1,
        "w":  7,
        "M":  30,
        "y":  365,
    }
    days = n * days_per_unit[unit]
    return int(days) if days.is_integer() else round(days, 3)


def _eval_retention(label, retention_days, scope, avg_daily_size_gb,
                    avg_shards_per_day, total_disk_gb, shard_limit,
                    analyses, issues):
    projected_disk_gb = round(avg_daily_size_gb * retention_days, 2)
    projected_shards  = round(avg_shards_per_day * retention_days)
    disk_feasible     = (total_disk_gb is None) or projected_disk_gb <= total_disk_gb
    shards_feasible   = projected_shards <= shard_limit
    analysis = {
        "scope": scope, "policy": label, "retention_days": retention_days,
        "projected_disk_gb": projected_disk_gb, "total_disk_gb": total_disk_gb,
        "disk_feasible": disk_feasible, "projected_shards": projected_shards,
        "shard_limit": shard_limit, "shards_feasible": shards_feasible,
    }
    if not disk_feasible:
        issues.append(f"[{label}] {retention_days}d retention needs ~{projected_disk_gb} GB "
                      f"but only {total_disk_gb} GB available on disk")
    if not shards_feasible:
        issues.append(f"[{label}] {retention_days}d retention needs ~{projected_shards} shards "
                      f"but shard limit is {shard_limit}")
    analyses.append(analysis)


def check_retention_feasibility(indexer_url, user, password,
                                disk_path="/", default_ism_days=90,
                                default_alerts_days=365) -> dict:
    issues: list[str] = []
    cat_ep = (f"{indexer_url}/_cat/indices/wazuh-alerts-*?format=json&bytes=b"
              f"&h=index,store.size,pri,rep,creation.date.string")
    try:
        resp = requests.get(cat_ep, auth=(user, password),
                            verify=False, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            return _make_check("error", True,
                               details=f"Could not fetch indices: HTTP {resp.status_code}",
                               url=cat_ep)
        indices = resp.json()
    except Exception as exc:
        return _make_check("error", True, details=f"Could not fetch indices: {exc}")

    if not indices:
        return _make_check("warning", False,
                           details="No wazuh-alerts-* indices found yet.",
                           index_count=0)

    total_size_bytes = total_primaries = valid_count = 0
    for idx in indices:
        try:
            size = int(idx.get("store.size") or 0)
            pri  = int(idx.get("pri") or 1)
            rep  = int(idx.get("rep") or 0)
            total_size_bytes += size
            total_primaries  += pri * (1 + rep)
            valid_count += 1
        except (ValueError, TypeError):
            continue

    if valid_count == 0:
        return _make_check("warning", False, details="Could not parse index size data.",
                           index_count=len(indices))

    avg_daily_size_gb  = round(total_size_bytes / valid_count / (1024**3), 3)
    avg_shards_per_day = round(total_primaries / valid_count, 1)
    shard_limit = (_get_max_shards_per_node(indexer_url, user, password) *
                   _get_data_node_count(indexer_url, user, password))

    try:
        du = shutil.disk_usage(disk_path)
        total_disk_gb = round(du.total / (1024**3), 2)
        free_disk_gb  = round(du.free  / (1024**3), 2)
    except Exception:
        total_disk_gb = free_disk_gb = None

    # Reuse the same ISM parsing as check 11 so both checks agree on whether a
    # policy exists. Only fall back to the default projection when there is
    # genuinely no usable age-based retention, and say why.
    retention_analyses: list[dict] = []
    policies, ism_error, _ = _fetch_ism_policies(indexer_url, user, password)
    for policy in policies:
        retention_days = _parse_age_to_days(policy["delete_min_age"])
        if retention_days is None:
            continue
        _eval_retention(policy["name"], retention_days, "ism",
                        avg_daily_size_gb, avg_shards_per_day,
                        total_disk_gb, shard_limit,
                        retention_analyses, issues)

    no_ism_policies = not policies and not ism_error
    no_ism_retention = not retention_analyses
    if no_ism_retention:
        if ism_error:
            reason = f"ISM policies could not be read ({ism_error})."
        elif not policies:
            reason = "No ISM policies found."
        else:
            reason = (f"{len(policies)} ISM policy(ies) found, but none defines an "
                      f"age-based delete phase.")
        issues.append(f"{reason} Projecting with default {default_ism_days}d.")
        _eval_retention(f"default ({default_ism_days}d)", default_ism_days, "ism",
                        avg_daily_size_gb, avg_shards_per_day,
                        total_disk_gb, shard_limit,
                        retention_analyses, issues)

    local_projected_gb = round(avg_daily_size_gb * default_alerts_days, 2)
    local_disk_feasible = (total_disk_gb is None) or local_projected_gb <= total_disk_gb
    retention_analyses.append({
        "scope": "local_logs", "source": "default",
        "retention_days": default_alerts_days,
        "projected_disk_gb": local_projected_gb, "total_disk_gb": total_disk_gb,
        "disk_feasible": local_disk_feasible,
        "note": "Projection for /var/ossec/logs/alerts + archives.",
    })
    if not local_disk_feasible:
        issues.append(f"Local logs: {default_alerts_days}d needs ~{local_projected_gb} GB "
                      f"but only {total_disk_gb} GB on disk.")

    notify = bool(issues)
    return _make_check(
        "warning" if notify else "ok", notify,
        index_count=valid_count, avg_daily_size_gb=avg_daily_size_gb,
        avg_shards_per_day=avg_shards_per_day, shard_limit=shard_limit,
        total_disk_gb=total_disk_gb, free_disk_gb=free_disk_gb,
        no_ism_policies=no_ism_policies,
        no_ism_retention=no_ism_retention,
        ism_policy_count=len(policies),
        retention_analyses=retention_analyses,
        issues=issues if issues else None,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Check 14 – Filebeat service (deploy-mode aware)
# ─────────────────────────────────────────────────────────────────────────────
def check_filebeat_service(deploy_mode: str = "bare-metal",
                           namespace: str = K8S_DEFAULT_NAMESPACE) -> dict:
    if deploy_mode == "bare-metal":
        try:
            result = subprocess.run(["systemctl", "is-active", "filebeat"],
                                    capture_output=True, text=True, timeout=10)
            state = result.stdout.strip()
            if state == "active":
                return _make_check("ok", False, service="filebeat", state=state)
            return _make_check("error", True, service="filebeat",
                               state=state or "unknown",
                               details=f"Filebeat is '{state}' (expected 'active')")
        except FileNotFoundError:
            return _make_check("error", True, service="filebeat",
                               details="'systemctl' not found")
        except subprocess.TimeoutExpired:
            return _make_check("error", True, service="filebeat",
                               details="systemctl timed out")
        except Exception as exc:
            return _make_check("error", True, service="filebeat", details=str(exc))

    if deploy_mode == "docker":
        target = DOCKER_IMAGE_MANAGER
    else:
        target = K8S_POD_MANAGER_MASTER

    try:
        result = _container_exec(
            deploy_mode, target, ["pgrep", "-a", "filebeat"],
            namespace=namespace, timeout=15)
        if result.returncode == 0 and result.stdout.strip():
            return _make_check("ok", False, service="filebeat",
                               state="running",
                               deploy_mode=deploy_mode,
                               details=f"Filebeat process found (PID: {result.stdout.strip()})")
        return _make_check("error", True, service="filebeat",
                           state="not running",
                           deploy_mode=deploy_mode,
                           details="Filebeat process not found inside manager container/pod")
    except FileNotFoundError:
        tool = "docker" if deploy_mode == "docker" else "kubectl"
        return _make_check("error", True, service="filebeat",
                           details=f"'{tool}' not found in PATH")
    except subprocess.TimeoutExpired:
        return _make_check("error", True, service="filebeat",
                           details="Container exec timed out")
    except Exception as exc:
        return _make_check("error", True, service="filebeat", details=str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Check 15 – Filebeat output connectivity (deploy-mode aware)
# ─────────────────────────────────────────────────────────────────────────────
def check_filebeat_output(deploy_mode: str = "bare-metal",
                          namespace: str = K8S_DEFAULT_NAMESPACE) -> dict:
    cmd = ["filebeat", "test", "output"]

    if deploy_mode == "bare-metal":
        target_cmd = cmd
        run_fn = lambda: subprocess.run(target_cmd, capture_output=True,
                                        text=True, timeout=30)
    else:
        if deploy_mode == "docker":
            target = DOCKER_IMAGE_MANAGER
        else:
            target = K8S_POD_MANAGER_MASTER

        run_fn = lambda: _container_exec(  # noqa: E731
            deploy_mode, target, cmd,
            namespace=namespace, timeout=30)

    try:
        result = run_fn()
        combined = (result.stdout.strip() + "\n" + result.stderr.strip()).strip()
        if result.returncode == 0:
            return _make_check("ok", False,
                               details="Filebeat output test passed",
                               deploy_mode=deploy_mode,
                               output=combined or None)
        return _make_check("error", True,
                           details="Filebeat output test failed",
                           deploy_mode=deploy_mode,
                           output=combined or None,
                           returncode=result.returncode)
    except FileNotFoundError:
        tool = "filebeat" if deploy_mode == "bare-metal" else (
            "docker" if deploy_mode == "docker" else "kubectl")
        return _make_check("error", True,
                           details=f"'{tool}' not found in PATH")
    except subprocess.TimeoutExpired:
        return _make_check("error", True,
                           details="Filebeat output test timed out (30s)")
    except Exception as exc:
        return _make_check("error", True, details=str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Check 16 – Manager cluster nodes (API-based)
# ─────────────────────────────────────────────────────────────────────────────
def check_manager_cluster_nodes(
    expected_nodes: list[str],
    url: str, user: str, password: str,
) -> dict:
    """
    Uses the Manager API GET /cluster/nodes to verify that all expected
    node names/IPs are present in the cluster response.

    NOTE: The Wazuh API /cluster/nodes response does NOT include a 'status'
    field per node. A node's presence in the response already implies it is
    connected (only reachable nodes are returned). Validation is therefore
    based on presence alone, not on a status field.
    """
    token, err = _get_manager_token(url, user, password)
    if err:
        return _make_check("error", True,
                           details=f"Authentication failed: {err}", url=url)

    endpoint = f"{url}/cluster/nodes"
    try:
        resp = requests.get(endpoint,
                            headers={"Authorization": f"Bearer {token}"},
                            verify=False, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.ConnectionError as exc:
        return _make_check("error", True,
                           details=f"Connection refused: {exc}", url=endpoint)
    except requests.exceptions.Timeout:
        return _make_check("error", True,
                           details="Request timed out", url=endpoint)
    except Exception as exc:
        return _make_check("error", True, details=str(exc), url=endpoint)

    if resp.status_code != 200:
        return _make_check("error", True, http_code=resp.status_code,
                           details=f"HTTP {resp.status_code}", url=endpoint)

    data = resp.json()

    # Top-level API error check
    if data.get("error", 0) != 0:
        return _make_check("error", True,
                           details=f"API returned error: {data.get('message', 'unknown')}",
                           url=endpoint)

    items = data.get("data", {}).get("affected_items", [])
    nodes_found: list[dict] = []
    for n in items:
        nodes_found.append({
            "name":    n.get("name", ""),
            "type":    n.get("type", ""),
            "version": n.get("version", ""),
            "ip":      n.get("ip", ""),
        })

    # A node is considered present (and therefore healthy) if it appears in
    # affected_items. Absence means it did not respond to the cluster query.
    found_ids = {n["ip"] for n in nodes_found} | {n["name"] for n in nodes_found}
    issues: list[str] = []
    # Expected entries may be an IP, a host:port, a full URL or an FQDN, while
    # the cluster reports its members by IP and node name - so compare against
    # every identity the entry can resolve to, not just the literal string.
    resolved = [(e, _host_identities(e)) for e in expected_nodes]
    expected_nodes = [_node_host(e) if "://" in e or ":" in e else e
                      for e in expected_nodes]
    for entry, identities in resolved:
        if not (identities & found_ids):
            issues.append(f"{entry}: not found in cluster response")

    notify = bool(issues)
    status = "error" if issues else "ok"
    return _make_check(status, notify,
                       node_count=len(nodes_found),
                       expected=expected_nodes,
                       nodes=nodes_found,
                       issues=issues or None,
                       url=endpoint)


# ─────────────────────────────────────────────────────────────────────────────
# Check 17 – Indexer cluster nodes
# ─────────────────────────────────────────────────────────────────────────────
def check_indexer_nodes(
    expected_nodes: list[str],
    user: str, password: str, indexer_url: str,
) -> dict:
    endpoint = (f"{indexer_url}/_cat/nodes?format=json"
                "&h=ip,name,node.role,heap.percent,disk.used_percent,master")
    try:
        resp = requests.get(endpoint, auth=(user, password),
                            verify=False, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.ConnectionError as exc:
        return _make_check("error", True,
                           details=f"Connection refused: {exc}", url=endpoint)
    except requests.exceptions.Timeout:
        return _make_check("error", True,
                           details="Request timed out", url=endpoint)
    except Exception as exc:
        return _make_check("error", True, details=str(exc), url=endpoint)

    if resp.status_code != 200:
        return _make_check("error", True, http_code=resp.status_code,
                           details=f"HTTP {resp.status_code}", url=endpoint)

    raw_nodes = resp.json()
    found_ips = {n.get("ip", "") for n in raw_nodes}
    nodes_info = [
        {"ip": n.get("ip"), "name": n.get("name"), "role": n.get("node.role"),
         "heap_pct": n.get("heap.percent"), "disk_pct": n.get("disk.used_percent"),
         "master": n.get("master")}
        for n in raw_nodes
    ]

    found_names = {n.get("name", "") for n in raw_nodes}
    issues: list[str] = []
    # As in check 16: an entry may be an IP, host:port, URL or FQDN, so match
    # on every identity it resolves to rather than on the literal string.
    resolved = [(e, _host_identities(e)) for e in expected_nodes]
    expected_nodes = [_node_host(e) if "://" in e or ":" in e else e
                      for e in expected_nodes]
    for entry, identities in resolved:
        if not (identities & (found_ips | found_names)):
            issues.append(f"{entry}: not found in indexer node list")

    notify = bool(issues)
    status = "error" if issues else "ok"
    return _make_check(status, notify,
                       node_count=len(raw_nodes), expected=expected_nodes,
                       nodes=nodes_info, issues=issues or None, url=endpoint)


def _host_identities(entry: str) -> set[str]:
    """Every identifier a declared topology entry may legitimately match.

    The configuration file accepts an IP, a host:port, a full URL or an FQDN,
    but a cluster reports its members by IP and by node name. An FQDN therefore
    matches neither unless it is resolved first, which used to make a perfectly
    reachable node be reported as missing from the cluster.
    """
    host = _node_host(entry) if ("://" in entry or ":" in entry) else entry
    identities = {host, host.split(".")[0]}
    try:
        _name, _aliases, addresses = socket.gethostbyname_ex(host)
        identities.update(addresses)
        identities.add(_name)
        identities.add(_name.split(".")[0])
        identities.update(_aliases)
    except (socket.gaierror, UnicodeError, OSError):
        pass          # not resolvable here; the literal forms still apply
    return {i for i in identities if i}


# ─────────────────────────────────────────────────────────────────────────────
# Check 19 – Manager API reachable on every declared manager node
# ─────────────────────────────────────────────────────────────────────────────
def check_manager_node_endpoints(node_urls: list[str], user: str,
                                 password: str) -> dict:
    """
    Authenticate against the API of every declared manager node.

    Check 16 only asks the local master which nodes it believes are connected;
    this one actually talks to each manager (master and workers) so a worker
    whose API is down, unreachable through the firewall or using different
    credentials is reported explicitly.
    """
    nodes: list[dict] = []
    issues: list[str] = []

    for url in node_urls:
        host = _node_host(url)
        label = _node_label(url)
        token, err = _get_manager_token(url, user, password)
        if err:
            nodes.append({"host": host, "url": url, "reachable": False, "error": err})
            issues.append(f"{label}: manager API unreachable ({_short_error(err)})")
            continue

        entry: dict = {"host": host, "url": url, "reachable": True}
        try:
            resp = requests.get(f"{url}/cluster/local/info",
                                headers={"Authorization": f"Bearer {token}"},
                                verify=False, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                items = resp.json().get("data", {}).get("affected_items", [])
                if items:
                    entry["node_name"] = items[0].get("node")
                    entry["node_type"] = items[0].get("type")
                    entry["cluster"] = items[0].get("cluster")
            else:
                entry["error"] = f"HTTP {resp.status_code} on /cluster/local/info"
                issues.append(f"{label}: HTTP {resp.status_code} on /cluster/local/info")
        except Exception as exc:
            entry["error"] = str(exc)
            issues.append(f"{label}: {_short_error(exc)}")
        nodes.append(entry)

    clusters = {n.get("cluster") for n in nodes if n.get("cluster")}
    if len(clusters) > 1:
        issues.append("Manager nodes report different cluster names: "
                      + ", ".join(sorted(clusters)))

    masters = [n.get("host") for n in nodes if n.get("node_type") == "master"]
    if len(masters) > 1:
        issues.append("More than one manager node reports type 'master': "
                      + ", ".join(masters))

    notify = bool(issues)
    return _make_check("error" if notify else "ok", notify,
                       node_count=len(nodes),
                       reachable=sum(1 for n in nodes if n.get("reachable")),
                       nodes=nodes, issues=issues or None)


# ─────────────────────────────────────────────────────────────────────────────
# Check 20 – Indexer reachable / same cluster on every declared indexer node
# ─────────────────────────────────────────────────────────────────────────────
def check_indexer_node_endpoints(node_urls: list[str], user: str,
                                 password: str) -> dict:
    """
    Query every declared indexer node directly instead of relying on a single
    entry point. A node that is up but split from the cluster answers with a
    different cluster_name (or refuses the connection), which the cluster-wide
    _cat/nodes call made from a healthy node cannot show.
    """
    nodes: list[dict] = []
    issues: list[str] = []

    for url in node_urls:
        host = _node_host(url)
        label = _node_label(url)
        try:
            resp = requests.get(f"{url}/", auth=(user, password),
                                verify=False, timeout=REQUEST_TIMEOUT)
        except requests.exceptions.ConnectionError as exc:
            nodes.append({"host": host, "url": url, "reachable": False,
                          "error": f"Connection refused: {exc}"})
            issues.append(f"{label}: indexer unreachable (connection refused)")
            continue
        except requests.exceptions.Timeout:
            nodes.append({"host": host, "url": url, "reachable": False,
                          "error": "Request timed out"})
            issues.append(f"{label}: indexer request timed out")
            continue
        except Exception as exc:
            nodes.append({"host": host, "url": url, "reachable": False,
                          "error": str(exc)})
            issues.append(f"{label}: {_short_error(exc)}")
            continue

        if resp.status_code != 200:
            nodes.append({"host": host, "url": url, "reachable": False,
                          "http_code": resp.status_code,
                          "error": f"HTTP {resp.status_code}"})
            issues.append(f"{label}: HTTP {resp.status_code} from the indexer API")
            continue

        data = resp.json()
        entry = {
            "host": host, "url": url, "reachable": True,
            "node_name": data.get("name"),
            "cluster_name": data.get("cluster_name"),
            "version": (data.get("version") or {}).get("number"),
        }

        # Per-node view of the cluster: a node that lost quorum reports its own
        # health with a red/unknown status even when the rest of the cluster is
        # fine.
        try:
            health = requests.get(f"{url}/_cluster/health", auth=(user, password),
                                  params={"local": "true"}, verify=False,
                                  timeout=REQUEST_TIMEOUT)
            if health.status_code == 200:
                payload = health.json()
                entry["cluster_status"] = payload.get("status")
                entry["nodes_seen"] = payload.get("number_of_nodes")
                if payload.get("status") == "red":
                    issues.append(f"{label}: reports cluster status 'red'")
        except Exception:
            pass

        nodes.append(entry)

    clusters = {n.get("cluster_name") for n in nodes if n.get("cluster_name")}
    if len(clusters) > 1:
        issues.append("Indexer nodes belong to different clusters: "
                      + ", ".join(sorted(clusters)))

    versions = {n.get("version") for n in nodes if n.get("version")}
    if len(versions) > 1:
        issues.append("Indexer nodes run different versions: "
                      + ", ".join(sorted(versions)))

    seen = {n.get("nodes_seen") for n in nodes if n.get("nodes_seen") is not None}
    if len(seen) > 1:
        issues.append("Indexer nodes disagree on the cluster size ("
                      + ", ".join(str(s) for s in sorted(seen))
                      + "), which suggests a split cluster.")

    notify = bool(issues)
    return _make_check("error" if notify else "ok", notify,
                       node_count=len(nodes),
                       reachable=sum(1 for n in nodes if n.get("reachable")),
                       nodes=nodes, issues=issues or None)


# ─────────────────────────────────────────────────────────────────────────────
# Check 21 – Dashboard reachable on every declared dashboard node
# ─────────────────────────────────────────────────────────────────────────────
def check_dashboard_nodes(node_urls: list[str]) -> dict:
    nodes: list[dict] = []
    issues: list[str] = []

    for url in node_urls:
        host = _node_host(url)
        label = _node_label(url)
        result = check_dashboard(url)
        entry = {"host": host, "url": url,
                 "status": result.get("status"),
                 "http_code": result.get("http_code")}
        if result.get("status") != "ok":
            entry["error"] = result.get("details")
            issues.append(
                f"{label}: {_short_error(result.get('details', 'unreachable'))}")
        nodes.append(entry)

    notify = bool(issues)
    return _make_check("error" if notify else "ok", notify,
                       node_count=len(nodes),
                       reachable=sum(1 for n in nodes if n["status"] == "ok"),
                       nodes=nodes, issues=issues or None)


# ─────────────────────────────────────────────────────────────────────────────
# Argument parser
# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# --init-config : generate /etc/wazuh-health-checker.conf
# ─────────────────────────────────────────────────────────────────────────────
# The topology is DISCOVERED ONCE and written to the file, on purpose. Checks 16
# and 17 answer "is a node I expect missing from the cluster?", so the expected
# list has to be a declaration the user reviewed - if it were rediscovered on
# every run, a node that drops out would vanish from both sides of the
# comparison and the check could never fail.
WAZUH_INSTALL_FILES_TAR = "/root/wazuh-install-files.tar"


def _credentials_from_install_files(tar_path: str = WAZUH_INSTALL_FILES_TAR) -> dict[str, str]:
    """Read the credentials wazuh-install.sh generated, when they are still on disk.

    The installer leaves wazuh-install-files/wazuh-passwords.txt inside the tar,
    holding repeated "indexer_username/indexer_password" and
    "api_username/api_password" pairs. Returns {} if anything is unavailable.
    """
    if not os.path.isfile(tar_path):
        return {}
    try:
        import tarfile
        with tarfile.open(tar_path) as tar:
            member = next((m for m in tar.getmembers()
                           if m.name.endswith("wazuh-passwords.txt")), None)
            if member is None:
                return {}
            handle = tar.extractfile(member)
            if handle is None:
                return {}
            text = handle.read().decode("utf-8", "replace")
    except Exception as exc:
        print(f"WARNING: Could not read {tar_path}: {exc}", file=sys.stderr)
        return {}

    pairs: list[tuple[str, str, str]] = []
    kind = user = None
    for line in text.splitlines():
        m = re.match(r"\s*(indexer|api)_username:\s*'([^']*)'", line)
        if m:
            kind, user = m.group(1), m.group(2)
            continue
        m = re.match(r"\s*(indexer|api)_password:\s*'([^']*)'", line)
        if m and user is not None and m.group(1) == kind:
            pairs.append((kind, user, m.group(2)))
            kind = user = None

    found: dict[str, str] = {}
    for wanted, keys in (("admin", ("INDEXER_USER", "INDEXER_PASS")),):
        for kind, user, password in pairs:
            if kind == "indexer" and user == wanted:
                found[keys[0]], found[keys[1]] = user, password
                break
    # wazuh-wui is the API user the dashboard uses; 'wazuh' is the fallback.
    for wanted in ("wazuh-wui", "wazuh"):
        for kind, user, password in pairs:
            if kind == "api" and user == wanted:
                found.setdefault("MANAGER_USER", user)
                found.setdefault("MANAGER_PASS", password)
                break
        if "MANAGER_USER" in found:
            break
    return found


def _discover_manager_nodes(url: str, user: str,
                            password: str) -> tuple[list[str], str | None, bool]:
    """Manager cluster members, via the same GET /cluster/nodes check 16 uses.

    Returns (nodes, error, cluster_enabled). A standalone manager is NOT an
    error: GET /cluster/nodes answers 400 (error 3013, "Cluster is not
    running") whenever clustering is disabled, so GET /cluster/status is asked
    first and a single-node install reports cluster_enabled=False with no error.
    """
    token, err = _get_manager_token(url, user, password)
    if err:
        return [], err, False

    headers = {"Authorization": f"Bearer {token}"}
    try:
        status = requests.get(f"{url}/cluster/status", headers=headers,
                              verify=False, timeout=REQUEST_TIMEOUT)
        if status.status_code == 200:
            enabled = status.json().get("data", {}).get("enabled", "no")
            if str(enabled).lower() not in ("yes", "true"):
                return [], None, False
    except Exception:
        pass  # fall through and let /cluster/nodes report the real problem

    endpoint = f"{url}/cluster/nodes"
    try:
        resp = requests.get(endpoint, headers=headers,
                            verify=False, timeout=REQUEST_TIMEOUT)
    except Exception as exc:
        return [], str(exc), True
    if resp.status_code != 200:
        payload = {}
        try:
            payload = resp.json()
        except ValueError:
            pass
        # 3013 = cluster disabled; treat it as standalone rather than an error.
        if payload.get("error") == 3013:
            return [], None, False
        detail = payload.get("detail") or f"HTTP {resp.status_code}"
        return [], f"{detail} ({endpoint})", True
    items = resp.json().get("data", {}).get("affected_items", [])
    return [n.get("ip") for n in items if n.get("ip")], None, True


def _discover_indexer_nodes(url: str, user: str, password: str) -> tuple[list[str], str | None]:
    """Indexer cluster members, via the same _cat/nodes check 17 uses."""
    endpoint = f"{url}/_cat/nodes?format=json&h=ip,name"
    try:
        resp = requests.get(endpoint, auth=(user, password),
                            verify=False, timeout=REQUEST_TIMEOUT)
    except Exception as exc:
        return [], str(exc)
    if resp.status_code != 200:
        return [], f"HTTP {resp.status_code} from {endpoint}"
    return [n.get("ip") for n in resp.json() if n.get("ip")], None


def _prompt(label: str, current: str = "", secret: bool = False) -> str:
    shown = f" [{current}]" if current and not secret else ""
    if secret:
        import getpass
        value = getpass.getpass(f"{label}: ")
    else:
        value = input(f"{label}{shown}: ").strip()
    return value or current


CONFIG_TEMPLATE = """\
# ─────────────────────────────────────────────────────────────────────────────
# Wazuh health checker – single configuration file
# ─────────────────────────────────────────────────────────────────────────────
# Read by monitoring.py and sourced by wrapper.sh, which exports every value so
# the notifier scripts see them too. Keep this file root-owned and chmod 600.
#
# Any value can be overridden at run time by an environment variable of the same
# name, or by the matching monitoring.py command-line flag.

# ── Credentials ──────────────────────────────────────────────────────────────
MANAGER_USER={MANAGER_USER}
MANAGER_PASS={MANAGER_PASS}
INDEXER_USER={INDEXER_USER}
INDEXER_PASS={INDEXER_PASS}

# ── Cluster topology ─────────────────────────────────────────────────────────
# Comma-separated. Each entry may be an IP, host:port, or a full URL.
# Leave every list empty for an all-in-one deployment.
# Include the local manager master in MANAGER_NODES: checks 16 and 17 verify
# that each declared node is still present in the cluster.
MANAGER_NODES={MANAGER_NODES}
INDEXER_NODES={INDEXER_NODES}
DASHBOARD_NODES={DASHBOARD_NODES}

# ── Paths and thresholds ─────────────────────────────────────────────────────
LOG_FILE={LOG_FILE}
#DISK_PATH=/
#DISK_THRESHOLD=75
#SHARD_THRESHOLD=80
#RETENTION_ISM_DAYS=90
#RETENTION_ALERTS_DAYS=365
#ALERTS_TREND_DAYS=7
#ALERTS_DROP_THRESHOLD=20
#PORTS=1514,1515
#DEPLOY_MODE=bare-metal
#NODE_ROLE=all
#K8S_NAMESPACE=wazuh

# ── Notifications (used by slack_notifier.py / email_notifier.py) ────────────
SLACK_WEBHOOK_URL={SLACK_WEBHOOK_URL}
SMTP_SERVER={SMTP_SERVER}
SMTP_PORT={SMTP_PORT}
SMTP_USER={SMTP_USER}
SMTP_PASS={SMTP_PASS}
EMAIL_TO={EMAIL_TO}
"""


def init_config(config_file: str, manager_url: str, indexer_url: str,
                assume_yes: bool = False) -> int:
    """Interactively build the single config file, discovering the topology."""
    print(f"\n  Wazuh health checker – configuration setup")
    print(f"  Target file: {config_file}\n")

    if os.path.exists(config_file) and not assume_yes:
        if _prompt(f"  '{config_file}' already exists. Overwrite? (y/N)", "N").lower() != "y":
            print("  Aborted; nothing was written.")
            return 1

    values = dict(_config_values)
    # Environment variables outrank the file. On a step-by-step installation
    # there is no /root/wazuh-install-files.tar, so the environment is the only
    # non-interactive source of credentials - which is what --yes relies on.
    for key in (*_REQUIRED_SECRETS, "MANAGER_NODES", "INDEXER_NODES",
                "DASHBOARD_NODES", "LOG_FILE", "SLACK_WEBHOOK_URL",
                "SMTP_SERVER", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "EMAIL_TO"):
        env_value = os.environ.get(key)
        if env_value:
            values[key] = env_value

    discovered = _credentials_from_install_files()
    if discovered:
        print(f"  [+] Credentials found in {WAZUH_INSTALL_FILES_TAR}")
        for key, value in discovered.items():
            values.setdefault(key, value)
    else:
        print(f"  [ ] {WAZUH_INSTALL_FILES_TAR} not readable – credentials will be asked for")

    if not assume_yes:
        print()
        values["MANAGER_USER"] = _prompt("  Manager API user", values.get("MANAGER_USER", "wazuh-wui"))
        if not values.get("MANAGER_PASS"):
            values["MANAGER_PASS"] = _prompt("  Manager API password", secret=True)
        values["INDEXER_USER"] = _prompt("  Indexer user", values.get("INDEXER_USER", "admin"))
        if not values.get("INDEXER_PASS"):
            values["INDEXER_PASS"] = _prompt("  Indexer password", secret=True)

    for key in _REQUIRED_SECRETS:
        if not values.get(key):
            print(f"\n  ERROR: {key} is still empty; cannot discover the topology.",
                  file=sys.stderr)
            return 1

    print("\n  Discovering cluster topology…")
    managers, mgr_err, mgr_clustered = _discover_manager_nodes(
        manager_url, values["MANAGER_USER"], values["MANAGER_PASS"])
    if mgr_err:
        print(f"  [!] Manager nodes: {mgr_err}")
        print(f"      Leaving MANAGER_NODES empty – fill it in by hand if this is a cluster.")
    elif not mgr_clustered:
        print(f"  [+] Manager nodes:  standalone (clustering disabled)")
    else:
        print(f"  [+] Manager nodes:  {', '.join(managers) or '(none reported)'}")
    indexers, idx_err = _discover_indexer_nodes(
        indexer_url, values["INDEXER_USER"], values["INDEXER_PASS"])
    if idx_err:
        print(f"  [!] Indexer nodes: {idx_err}")
        print(f"      Leaving INDEXER_NODES empty – fill it in by hand if this is a cluster.")
    else:
        print(f"  [+] Indexer nodes:  {', '.join(indexers) or '(single node)'}")

    # A single node behind the localhost defaults needs no explicit topology.
    if len(managers) < 2:
        managers = []
    if len(indexers) < 2:
        indexers = []

    rendered = CONFIG_TEMPLATE.format(
        MANAGER_USER=values.get("MANAGER_USER", ""),
        MANAGER_PASS=values.get("MANAGER_PASS", ""),
        INDEXER_USER=values.get("INDEXER_USER", ""),
        INDEXER_PASS=values.get("INDEXER_PASS", ""),
        MANAGER_NODES=",".join(managers),
        INDEXER_NODES=",".join(indexers),
        DASHBOARD_NODES=values.get("DASHBOARD_NODES", ""),
        LOG_FILE=values.get("LOG_FILE", DEFAULT_LOG_FILE),
        SLACK_WEBHOOK_URL=values.get("SLACK_WEBHOOK_URL", ""),
        SMTP_SERVER=values.get("SMTP_SERVER", ""),
        SMTP_PORT=values.get("SMTP_PORT", "587"),
        SMTP_USER=values.get("SMTP_USER", ""),
        SMTP_PASS=values.get("SMTP_PASS", ""),
        EMAIL_TO=values.get("EMAIL_TO", ""),
    )

    directory = os.path.dirname(config_file) or "."
    try:
        os.makedirs(directory, exist_ok=True)
        fd = os.open(config_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(rendered)
        os.chmod(config_file, 0o600)
    except OSError as exc:
        print(f"\n  ERROR: Cannot write {config_file}: {exc}", file=sys.stderr)
        return 1

    print(f"\n  [\u2713] Wrote {config_file} (chmod 600)")
    print(f"      Review it, then add SLACK_WEBHOOK_URL / SMTP_* for notifications.")
    print(f"      Nothing else needs editing – wrapper.sh sources this file.\n")
    return 0


def parse_args() -> argparse.Namespace:
    # --config-file / --secrets-file are resolved first: their contents supply
    # the defaults for every other option, so the precedence ends up being
    # CLI flag > environment variable > config file > built-in default.
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config-file",
                     default=os.environ.get("HEALTH_CHECKER_CONF", DEFAULT_CONFIG_FILE),
                     help=f"Single configuration file (default: {DEFAULT_CONFIG_FILE})")
    pre.add_argument("--secrets-file", default=DEFAULT_SECRETS_FILE,
                     help="Legacy credentials file, still read when present")
    known, _ = pre.parse_known_args()
    load_config(known.config_file, known.secrets_file)

    parser = argparse.ArgumentParser(
        parents=[pre],
        description="Wazuh environment health checker – supports bare-metal, "
                    "Docker, and Kubernetes deployments."
    )
    parser.add_argument("--init-config", action="store_true",
                        help="Discover the cluster topology and write the "
                             "configuration file, then exit.")
    parser.add_argument("--yes", action="store_true",
                        help="Non-interactive --init-config (no prompts).")
    parser.add_argument("--deploy-mode",
                        choices=["bare-metal", "docker", "kubernetes"],
                        default=cfg("DEPLOY_MODE", "bare-metal"))
    parser.add_argument("--k8s-namespace", default=cfg("K8S_NAMESPACE", K8S_DEFAULT_NAMESPACE))
    parser.add_argument("--node-role",
                        choices=["all", "manager", "indexer", "dashboard"],
                        default=cfg("NODE_ROLE", "all"))
    # These default to None so that a topology declared through --*-nodes (or
    # through the DEFAULT_*_NODES lists) fully replaces the localhost defaults
    # instead of being probed alongside them.
    parser.add_argument("--manager-url",   default=cfg("MANAGER_URL"),
                        help=f"Manager API URL (default: {DEFAULT_MANAGER_URL})")
    parser.add_argument("--indexer-url",   default=cfg("INDEXER_URL"),
                        help=f"Indexer URL (default: {DEFAULT_INDEXER_URL})")
    parser.add_argument("--dashboard-url", default=cfg("DASHBOARD_URL"),
                        help=f"Dashboard URL (default: {DEFAULT_DASHBOARD_URL})")
    parser.add_argument("--log-file", default=cfg("LOG_FILE", DEFAULT_LOG_FILE))
    parser.add_argument("--disk-path",      default=cfg("DISK_PATH", DEFAULT_DISK_PATH))
    parser.add_argument("--disk-threshold", type=int,
                        default=cfg_int("DISK_THRESHOLD", DEFAULT_DISK_THRESHOLD))
    parser.add_argument("--shard-threshold", type=int,
                        default=cfg_int("SHARD_THRESHOLD", DEFAULT_SHARD_THRESHOLD))
    parser.add_argument("--manager-host", default=cfg("MANAGER_HOST"),
                        help="Host for the TCP port checks. Defaults to every "
                             "manager node declared in the topology, or "
                             "'localhost' for an all-in-one deployment.")
    parser.add_argument("--ports", default=cfg("PORTS", "1514,1515"))
    parser.add_argument("--retention-ism-days", type=int,
                        default=cfg_int("RETENTION_ISM_DAYS", 90))
    parser.add_argument("--retention-alerts-days", type=int,
                        default=cfg_int("RETENTION_ALERTS_DAYS", 365))
    parser.add_argument("--alerts-trend-days", type=int,
                        default=cfg_int("ALERTS_TREND_DAYS", 7),
                        help="Window in days for alert trend comparison")
    parser.add_argument("--alerts-drop-threshold", type=float,
                        default=cfg_float("ALERTS_DROP_THRESHOLD", 20.0),
                        help="Warn when alert drop percentage is >= this value")
    parser.add_argument("--manager-nodes", default=cfg("MANAGER_NODES"),
                        help="Comma-separated manager cluster nodes (IP, host:port "
                             f"or URL). Port defaults to {MANAGER_API_PORT}.")
    parser.add_argument("--indexer-nodes", default=cfg("INDEXER_NODES"),
                        help="Comma-separated indexer cluster nodes (IP, host:port "
                             f"or URL). Port defaults to {INDEXER_PORT}.")
    parser.add_argument("--dashboard-nodes", default=cfg("DASHBOARD_NODES"),
                        help="Comma-separated dashboard nodes (IP, host:port "
                             f"or URL). Port defaults to {DASHBOARD_PORT}.")
    return parser.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    args = parse_args()

    if args.init_config:
        sys.exit(init_config(
            args.config_file,
            (args.manager_url or DEFAULT_MANAGER_URL).rstrip("/"),
            (args.indexer_url or DEFAULT_INDEXER_URL).rstrip("/"),
            assume_yes=args.yes,
        ))

    secrets = _load_secrets(args.config_file, args.secrets_file)
    mgr_user = secrets["MANAGER_USER"]
    mgr_pass = secrets["MANAGER_PASS"]
    idx_user = secrets["INDEXER_USER"]
    idx_pass = secrets["INDEXER_PASS"]

    mode = args.deploy_mode
    role = args.node_role

    # ── Resolve the cluster topology ──────────────────────────────────────
    # The script lives on the manager master; everything else is reached over
    # the network using the declared node addresses. When no node is declared
    # the localhost defaults are used, which is the all-in-one case.
    manager_node_urls = _parse_node_list(
        args.manager_nodes, DEFAULT_MANAGER_NODES, MANAGER_API_PORT)
    indexer_node_urls = _parse_node_list(
        args.indexer_nodes, DEFAULT_INDEXER_NODES, INDEXER_PORT)
    dashboard_node_urls = _parse_node_list(
        args.dashboard_nodes, DEFAULT_DASHBOARD_NODES, DASHBOARD_PORT)

    # The manager API is always queried locally: this node is the master.
    manager_url = (args.manager_url or DEFAULT_MANAGER_URL).rstrip("/")

    indexer_urls = _resolve_endpoints(
        args.indexer_url, indexer_node_urls, DEFAULT_INDEXER_URL)
    dashboard_urls = _resolve_endpoints(
        args.dashboard_url, dashboard_node_urls, DEFAULT_DASHBOARD_URL)

    print(f"[*] Starting Wazuh health checks (deploy-mode={mode}, node-role={role})…")

    # Cluster-wide indexer checks (shards, ISM, retention, …) only need one
    # reachable entry point; pick the first node that answers so a single dead
    # indexer does not blank out every indexer check.
    if len(indexer_urls) > 1:
        indexer_url, unreachable_indexers = _first_reachable(
            indexer_urls, _probe_indexer(idx_user, idx_pass))
        if unreachable_indexers:
            print(f"    [!] Indexer entry point(s) not answering: "
                  f"{', '.join(unreachable_indexers)}")
    else:
        indexer_url, unreachable_indexers = indexer_urls[0], []

    dashboard_url = dashboard_urls[0]

    # Agents connect to every manager node, so probe 1514/1515 on all of them.
    if args.manager_host:
        candidate_hosts = [h.strip() for h in args.manager_host.split(",") if h.strip()]
    elif manager_node_urls:
        candidate_hosts = [_node_host(u) for u in manager_node_urls]
    else:
        candidate_hosts = ["localhost"]
    port_hosts = list(dict.fromkeys(candidate_hosts))

    topology = {
        "manager_url":     manager_url,
        "manager_nodes":   manager_node_urls,
        "indexer_url":     indexer_url,
        "indexer_nodes":   indexer_node_urls or indexer_urls,
        "dashboard_nodes": dashboard_node_urls or dashboard_urls,
        "port_hosts":      port_hosts,
    }

    print(f"    Manager   : {manager_url}"
          + (f"  (+{len(manager_node_urls)} declared node(s))" if manager_node_urls else ""))
    print(f"    Indexer   : {indexer_url}"
          + (f"  (of {len(indexer_urls)} node(s))" if len(indexer_urls) > 1 else ""))
    print(f"    Dashboard : {', '.join(dashboard_urls)}")

    checks: dict[str, dict] = {}

    if mode != "bare-metal" and should_run("container_health", role):
        print("    [0] Container/Pod health…")
        if mode == "docker":
            checks["container_health"] = check_container_health_docker()
        elif mode == "kubernetes":
            checks["container_health"] = check_container_health_k8s(args.k8s_namespace)

    if should_run("manager_api", role):
        print("    [1] Manager API…")
        checks["manager_api"] = check_manager_api(manager_url, mgr_user, mgr_pass)
    else:
        checks["manager_api"] = _make_skip(role)

    if should_run("indexer_api", role):
        print("    [2] Indexer API…")
        checks["indexer_api"] = check_indexer_api(indexer_url, idx_user, idx_pass)
    else:
        checks["indexer_api"] = _make_skip(role)

    if should_run("dashboard", role):
        print("    [3] Dashboard…")
        checks["dashboard"] = check_dashboard(dashboard_url)
    else:
        checks["dashboard"] = _make_skip(role)

    if should_run("disk_space", role):
        print("    [4] Disk space…")
        checks["disk_space"] = check_disk_space(args.disk_path, args.disk_threshold)
    else:
        checks["disk_space"] = _make_skip(role)

    if should_run("indexer_disk_space", role):
        print("    [4b] Indexer disk space (API)…")
        checks["indexer_disk_space"] = check_indexer_disk_space(
            indexer_url, idx_user, idx_pass, args.disk_threshold)
    else:
        checks["indexer_disk_space"] = _make_skip(role)

    if should_run("shards_per_node", role):
        print("    [5-6] Shards…")
        checks["shards_per_node"], checks["active_shards"] = check_shards(
            indexer_url, idx_user, idx_pass, args.shard_threshold)
    else:
        checks["shards_per_node"] = _make_skip(role)
        checks["active_shards"] = _make_skip(role)

    if should_run("jvm_options", role):
        print("    [7] JVM options (API)…")
        checks["jvm_options"] = check_jvm_api(indexer_url, idx_user, idx_pass)
    else:
        checks["jvm_options"] = _make_skip(role)

    if should_run("unassigned_shards", role):
        print("    [8] Unassigned shards…")
        checks["unassigned_shards"] = check_unassigned_shards(
            indexer_url, idx_user, idx_pass)
    else:
        checks["unassigned_shards"] = _make_skip(role)

    if should_run("ports", role):
        print("    [9] Ports…")
        ports_to_check = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
        checks["ports"] = check_ports(port_hosts, ports_to_check)
    else:
        checks["ports"] = _make_skip(role)

    if should_run("agents", role):
        print("    [10] Agent summary…")
        checks["agents"] = check_agents(manager_url, mgr_user, mgr_pass)
    else:
        checks["agents"] = _make_skip(role)

    if should_run("ilm_policies", role):
        print("    [11] ISM policies…")
        checks["ilm_policies"] = check_ilm_policies(indexer_url, idx_user, idx_pass)
    else:
        checks["ilm_policies"] = _make_skip(role)

    if should_run("cron_rotation", role):
        print("    [12] Cron rotation…")
        checks["cron_rotation"] = check_cron_rotation(
            deploy_mode=mode, namespace=args.k8s_namespace)
    else:
        checks["cron_rotation"] = _make_skip(role)

    if should_run("retention_feasibility", role):
        print("    [13] Retention feasibility…")
        checks["retention_feasibility"] = check_retention_feasibility(
            indexer_url, idx_user, idx_pass,
            args.disk_path, args.retention_ism_days, args.retention_alerts_days)
    else:
        checks["retention_feasibility"] = _make_skip(role)

    if should_run("filebeat_service", role):
        print("    [14] Filebeat service…")
        checks["filebeat_service"] = check_filebeat_service(
            deploy_mode=mode, namespace=args.k8s_namespace)
    else:
        checks["filebeat_service"] = _make_skip(role)

    if should_run("filebeat_output", role):
        print("    [15] Filebeat output…")
        checks["filebeat_output"] = check_filebeat_output(
            deploy_mode=mode, namespace=args.k8s_namespace)
    else:
        checks["filebeat_output"] = _make_skip(role)

    # ── Multi-node checks (16, 17, 19, 20, 21) ───────────────────────────
    # They only run when the corresponding topology list is populated, so an
    # all-in-one deployment keeps the exact same output as before.
    manager_node_hosts = [_node_host(u) for u in manager_node_urls]
    if manager_node_hosts and should_run("manager_cluster_nodes", role):
        print("    [16] Manager cluster nodes…")
        checks["manager_cluster_nodes"] = check_manager_cluster_nodes(
            manager_node_hosts, manager_url, mgr_user, mgr_pass)

    indexer_node_hosts = [_node_host(u) for u in indexer_node_urls]
    if indexer_node_hosts and should_run("indexer_nodes", role):
        print("    [17] Indexer cluster nodes…")
        checks["indexer_nodes"] = check_indexer_nodes(
            indexer_node_hosts, idx_user, idx_pass, indexer_url)

    if should_run("alert_volume_trend", role):
        print("    [18] Alert volume trend…")
        checks["alert_volume_trend"] = check_alert_volume_trend(
            indexer_url,
            idx_user,
            idx_pass,
            args.alerts_trend_days,
            args.alerts_drop_threshold,
        )
    else:
        checks["alert_volume_trend"] = _make_skip(role)

    if manager_node_urls and should_run("manager_node_endpoints", role):
        print("    [19] Manager API per node…")
        checks["manager_node_endpoints"] = check_manager_node_endpoints(
            manager_node_urls, mgr_user, mgr_pass)

    if indexer_node_urls and should_run("indexer_node_endpoints", role):
        print("    [20] Indexer reachability per node…")
        checks["indexer_node_endpoints"] = check_indexer_node_endpoints(
            indexer_node_urls, idx_user, idx_pass)

    if len(dashboard_urls) > 1 and should_run("dashboard_nodes", role):
        print("    [21] Dashboard per node…")
        checks["dashboard_nodes"] = check_dashboard_nodes(dashboard_urls)

    global_notify = any(
        c.get("notify", False) for c in checks.values()
        if c.get("status") != "skipped"
    )

    entry = {
        "timestamp":   datetime.now(tz=timezone.utc).astimezone().isoformat(),
        "deploy_mode": mode,
        "node_role":   role,
        "topology":    topology,
        "checks":      checks,
        "notify":      global_notify,
    }

    log_dir = os.path.dirname(args.log_file)
    if log_dir and not os.path.isdir(log_dir):
        try:
            os.makedirs(log_dir, exist_ok=True)
        except PermissionError:
            print(f"ERROR: Cannot create log directory {log_dir}.", file=sys.stderr)
            sys.exit(1)

    try:
        with open(args.log_file, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        print(f"\n[✓] Results appended to {args.log_file}")
    except PermissionError:
        print(f"ERROR: Cannot write to {args.log_file}.", file=sys.stderr)
        sys.exit(1)

    # ── Print summary ────────────────────────────────────────────────────
    print("\n── Health Check Summary ─────────────────────────────────────────")
    print(f"   Deploy mode: {mode} | Node role: {role}")
    if manager_node_urls or indexer_node_urls or len(dashboard_urls) > 1:
        print(f"   Topology: {len(manager_node_urls) or 1} manager / "
              f"{len(indexer_node_urls) or len(indexer_urls)} indexer / "
              f"{len(dashboard_urls)} dashboard node(s)")
    STATUS_ICONS = {"ok": "✓", "warning": "⚠", "error": "✗", "skipped": "–"}

    labels = {}
    if "container_health" in checks:
        labels["container_health"] = "Container / Pod Health"
    labels.update({
        "manager_api":           "Manager API",
        "indexer_api":           "Indexer API",
        "dashboard":             "Dashboard",
        "disk_space":            "Disk Space",
        "indexer_disk_space":    "Indexer Disk Space (API)",
        "shards_per_node":       "Shards / Node config",
        "active_shards":         "Active Shards",
        "jvm_options":           "JVM Options (API)",
        "unassigned_shards":     "Unassigned Shards",
        "ports":                 "Ports (1514/1515)",
        "agents":                "Agent Summary",
        "ilm_policies":          "ISM Policies",
        "cron_rotation":         "Cron Log Rotation",
        "retention_feasibility": "Retention Feasibility",
        "filebeat_service":      "Filebeat Service",
        "filebeat_output":       "Filebeat → Indexer conn.",
    })
    if "manager_cluster_nodes" in checks:
        labels["manager_cluster_nodes"] = "Manager Cluster Nodes"
    if "indexer_nodes" in checks:
        labels["indexer_nodes"] = "Indexer Nodes"
    labels["alert_volume_trend"] = "Alert Volume Trend"
    if "manager_node_endpoints" in checks:
        labels["manager_node_endpoints"] = "Manager API per Node"
    if "indexer_node_endpoints" in checks:
        labels["indexer_node_endpoints"] = "Indexer Reach. per Node"
    if "dashboard_nodes" in checks:
        labels["dashboard_nodes"] = "Dashboard per Node"

    def _reason(check: dict) -> list[str]:
        """Extract human-readable reason lines from a check result."""
        lines = []
        if check.get("details"):
            lines.append(str(check["details"]))
        for issue in check.get("issues") or []:
            if issue not in lines:
                lines.append(issue)
        if check.get("used_pct") is not None:
            lines.append(
                f"Used {check['used_pct']}% of {check.get('total_gb')} GB "
                f"(threshold: {check.get('threshold_pct')}%)")
        if check.get("count") is not None and check.get("status") != "ok":
            lines.append(f"{check['count']} unassigned shard(s) found")
        if check.get("pct_used") is not None and check.get("status") != "ok":
            lines.append(
                f"{check['active']} active shards = {check['pct_used']}% of limit "
                f"{check['limit']} (threshold: {check.get('threshold_pct')}%)")
        if check.get("http_code") and check.get("status") != "ok":
            lines.append(f"HTTP {check['http_code']} from {check.get('url', '')}")
        if check.get("reachable") is not None and check.get("node_count") is not None:
            lines.append(f"{check['reachable']}/{check['node_count']} node(s) reachable")
        if check.get("managed_indices") is not None:
            lines.append(
                f"{check.get('policy_count', 0)} ISM policy(ies), "
                f"{check.get('policies_with_retention', 0)} with a delete phase, "
                f"{check['managed_indices']} managed index(es)")
        for host, states in (check.get("hosts") or {}).items():
            for port, state in states.items():
                if state != "open":
                    lines.append(f"{host} port {port}: {state}")
        if not check.get("hosts"):
            for port, state in (check.get("ports") or {}).items():
                if state != "open":
                    lines.append(f"Port {port}: {state}")
        if check.get("total") is not None:
            lines.append(
                f"Total: {check['total']}  "
                f"Active: {check['active']} ({check['active_pct']}%)  "
                f"Disconnected: {check['disconnected']} ({check['disconnected_pct']}%)  "
                f"Pending: {check['pending']} ({check['pending_pct']}%)  "
                f"Never connected: {check['never_connected']} ({check['never_connected_pct']}%)")
        if check.get("manager_version") is not None or check.get("manager_uuid") is not None:
            lines.append(
                f"Manager version: {check.get('manager_version', 'unknown')} | "
                f"UUID: {check.get('manager_uuid', 'unknown')}")
        if check.get("current_alerts") is not None and check.get("previous_alerts") is not None:
            drop_val = check.get("drop_pct")
            drop_str = f"{drop_val}%" if drop_val is not None else "n/a"
            lines.append(
                f"Current {check.get('comparison_window_days')}d: {check['current_alerts']} | "
                f"Previous {check.get('comparison_window_days')}d: {check['previous_alerts']} | "
                f"Drop: {drop_str} (threshold: {check.get('drop_threshold_pct')}%)")
        if check.get("policies") is not None:
            for p in check["policies"]:
                if p.get("delete_min_age"):
                    retention = f"delete_after={p['delete_min_age']}"
                elif p.get("delete_conditions"):
                    retention = f"delete_on={','.join(p['delete_conditions'])}"
                elif p.get("has_delete_phase"):
                    retention = "delete phase without conditions"
                else:
                    retention = "no delete phase"
                managed = p.get("managed_indices")
                managed_txt = f", managed_indices={managed}" if managed is not None else ""
                lines.append(
                    f"{p['name']}: states={p.get('states', [])}, {retention}{managed_txt}")
        # NOTE: removed the redundant `nodes` iteration block that was
        # duplicating lines already captured by the `issues` loop above.
        for target in check.get("missing_rotation_for") or []:
            lines.append(f"Missing cron for /var/ossec/logs/{target}/")
        for a in check.get("retention_analyses") or []:
            disk_ok = a.get("disk_feasible", True)
            shrd_ok = a.get("shards_feasible", True)
            feasible = "OK" if (disk_ok and shrd_ok) else "WARN"
            proj_disk = a.get("projected_disk_gb", "?")
            tot_disk = a.get("total_disk_gb", "?")
            proj_shrd = a.get("projected_shards", "n/a")
            shrd_lim = a.get("shard_limit", "n/a")
            scope = a.get("scope", "ism")
            label = a.get("policy", a.get("scope", "?"))
            days = a.get("retention_days", "?")
            if scope == "local_logs":
                lines.append(
                    f"[{feasible}] local logs / {days}d: needs {proj_disk} GB "
                    f"(have {tot_disk} GB)")
            else:
                lines.append(
                    f"[{feasible}] {label} / {days}d: needs {proj_disk} GB "
                    f"(have {tot_disk} GB), {proj_shrd} shards (limit {shrd_lim})")
        for c in check.get("containers") or []:
            if c.get("state", "").lower() != "running":
                lines.append(f"  {c['service']}: {c['state']}")
        for p in check.get("pods") or []:
            if p.get("phase", "") != "Running":
                lines.append(f"  {p['name']}: {p['phase']}")
        return lines

    for key, label in labels.items():
        if key not in checks:
            continue
        check = checks[key]
        icon = STATUS_ICONS.get(check.get("status", "error"), "?")
        notif = " ← NOTIFICATION" if check.get("notify") else ""
        st = check.get("status", "?").upper()
        print(f"  [{icon}] {label:<28} {st}{notif}")
        if check.get("notify"):
            for reason in _reason(check):
                print(f"         └─ {reason}")
        elif key == "manager_api":
            if check.get("manager_version") is not None or check.get("manager_uuid") is not None:
                print(
                    "         └─ "
                    f"Manager version: {check.get('manager_version', 'unknown')} | "
                    f"UUID: {check.get('manager_uuid', 'unknown')}")
        elif key in ("alert_volume_trend", "ilm_policies", "manager_node_endpoints",
                     "indexer_node_endpoints", "dashboard_nodes"):
            for reason in _reason(check):
                print(f"         └─ {reason}")

    if global_notify:
        print("\n  ⚠  One or more checks require attention (notify=true in log).")
    else:
        print("\n  ✓  All checks passed.")
    print("─────────────────────────────────────────────────────────────────\n")


if __name__ == "__main__":
    main()
