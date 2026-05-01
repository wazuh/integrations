#!/var/ossec/framework/python/bin/python3
"""
Wazuh Environment Health Checker
Wazuh Inc.
Nicolás Curioni <nicolas.curioni@wazuh.com>
=====================================================
Supports bare-metal, Docker, and Kubernetes Wazuh deployments.

Checks performed:

    0. Container / Pod health                                          [docker/k8s]
    1. Manager API availability (JWT auth)                             [local]
    2. Indexer API / cluster health                                    [indexer]
    3. Dashboard accessibility                                         [dashboard]
    4. Disk space usage (alerts at >= 75% by default)                  [local]
   4b. Indexer disk space via API                                      [indexer]
    5. Shards configured per node (max_shards_per_node x node_count)   [indexer]
    6. Active shards closeness to limit (>= 80% of limit by default)   [indexer]
    7. JVM Xms/Xmx vs total system RAM (via API)                      [indexer]
    8. Unassigned shards                                               [indexer]
    9. TCP port reachability (1514 – events, 1515 – enrollment)        [manager]
   10. Agent summary (active / disconnected / pending / never_connected)[manager]
   11. ILM policies configured in the Indexer                          [indexer]
   12. Cron jobs for alert/archive log rotation in the Manager         [manager]
   13. Retention feasibility (disk + shards vs ILM retention days)     [indexer]
   14. Filebeat service status                                         [manager]
   15. Filebeat output connectivity                                    [manager]
   16. Wazuh Manager cluster nodes (via API)            [optional]     [manager]
   17. Wazuh Indexer cluster nodes (_cat/nodes)          [optional]     [indexer]
   18. Alert volume trend drop (current vs previous window)             [indexer]

Deploy modes (--deploy-mode):
    bare-metal – traditional installation (default)
    docker     – Wazuh Docker Compose deployment
    kubernetes – Wazuh Kubernetes deployment

Node roles (--node-role):
    all       – run every check (default)
    manager   – checks 1, 4, 9, 10, 12, 14, 15, 16
    indexer   – checks 1, 2, 4, 4b, 5, 6, 7, 8, 11, 13, 17, 18
    dashboard – checks 1, 3, 4

Usage:
    python3 monitoring.py [options]

Examples:
    # Bare-metal (same as original)
    python3 monitoring.py --deploy-mode bare-metal

    # Docker single-node
    python3 monitoring.py --deploy-mode docker \\
        --docker-compose-dir /path/to/wazuh-docker/single-node/

    # Kubernetes
    python3 monitoring.py --deploy-mode kubernetes \\
        --k8s-namespace wazuh
"""

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
DEFAULT_SECRETS_FILE   = "/etc/health-checker.secrets"
DEFAULT_MANAGER_NODES: list[str] = []
DEFAULT_INDEXER_NODES: list[str] = []
REQUEST_TIMEOUT = 10

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
    "indexer_nodes", "alert_volume_trend",
}
MANAGER_CHECKS = {
    "ports", "agents", "cron_rotation", "filebeat_service",
    "filebeat_output", "manager_cluster_nodes",
}
DASHBOARD_CHECKS = {"dashboard"}


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
# Secrets loader
# ─────────────────────────────────────────────────────────────────────────────
_REQUIRED_SECRETS = ("MANAGER_USER", "MANAGER_PASS", "INDEXER_USER", "INDEXER_PASS")


def _load_secrets(secrets_file: str) -> dict[str, str]:
    file_values: dict[str, str] = {}
    if os.path.isfile(secrets_file):
        try:
            with open(secrets_file) as f:
                for lineno, raw in enumerate(f, 1):
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" not in line:
                        print(f"WARNING: {secrets_file}:{lineno}: skipping invalid line",
                              file=sys.stderr)
                        continue
                    key, _, value = line.partition("=")
                    file_values[key.strip()] = value.strip().strip('"').strip("'")
        except PermissionError:
            print(f"ERROR: Cannot read {secrets_file}. Run as root.", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"INFO: Secrets file '{secrets_file}' not found – relying on environment variables.",
              file=sys.stderr)

    secrets: dict[str, str] = {}
    missing: list[str] = []
    for key in _REQUIRED_SECRETS:
        value = os.environ.get(key) or file_values.get(key)
        if not value:
            missing.append(key)
        else:
            secrets[key] = value

    if missing:
        print(
            f"ERROR: Missing credentials: {', '.join(missing)}.\n"
            f"  Provide them in '{secrets_file}' or as environment variables.",
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
def check_ports(host: str, ports: list[int], timeout: int = REQUEST_TIMEOUT) -> dict:
    results = {}
    all_ok = True
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                results[str(port)] = "open"
        except (ConnectionRefusedError, socket.timeout, OSError) as exc:
            results[str(port)] = f"closed/unreachable ({exc})"
            all_ok = False
    notify = not all_ok
    status = "ok" if all_ok else "error"
    return _make_check(status, notify, host=host, ports=results)


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
# Check 11 – ISM Policies
# ─────────────────────────────────────────────────────────────────────────────
def check_ilm_policies(indexer_url: str, user: str, password: str) -> dict:
    endpoint = f"{indexer_url}/_plugins/_ism/policies"
    try:
        resp = requests.get(endpoint, auth=(user, password),
                            verify=False, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            return _make_check("error", True, http_code=resp.status_code,
                               details=f"HTTP {resp.status_code}", url=endpoint)

        raw_policies = resp.json().get("policies", [])
        policies = []
        for item in raw_policies:
            pol = item.get("policy", {})
            name = pol.get("policy_id", item.get("_id", "unknown"))
            states = pol.get("states", [])
            state_names = [s.get("name") for s in states]
            delete_min_age = rollover_age = None
            for state in states:
                actions = state.get("actions", [])
                for action in actions:
                    if "rollover" in action:
                        rollover_age = action["rollover"].get("min_index_age")
                for transition in state.get("transitions", []):
                    if transition.get("state_name", "").lower() in ("delete", "deleted"):
                        delete_min_age = transition.get("conditions", {}).get("min_index_age")
            policies.append({
                "name": name, "states": state_names,
                "delete_min_age": delete_min_age, "rollover_age": rollover_age,
            })

        if not policies:
            return _make_check("warning", True,
                               details="No ISM policies found. Log retention may be unmanaged.",
                               policies=[])
        return _make_check("ok", False, policy_count=len(policies), policies=policies)
    except requests.exceptions.ConnectionError as exc:
        return _make_check("error", True, details=f"Connection refused: {exc}", url=endpoint)
    except requests.exceptions.Timeout:
        return _make_check("error", True, details="Request timed out", url=endpoint)
    except Exception as exc:
        return _make_check("error", True, details=str(exc), url=endpoint)


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
                for fname in os.listdir(loc):
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
def _parse_age_to_days(age_str: str) -> int | None:
    if not age_str:
        return None
    m = re.fullmatch(r"(\d+)([dhwMy])", age_str.strip())
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2)
    multipliers = {"d": 1, "h": 1, "w": 7, "M": 30, "y": 365}
    return n * multipliers[unit]


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

    retention_analyses: list[dict] = []
    no_ism_policies = False
    try:
        ism_resp = requests.get(f"{indexer_url}/_plugins/_ism/policies",
                                auth=(user, password), verify=False,
                                timeout=REQUEST_TIMEOUT)
        if ism_resp.status_code == 200:
            for item in ism_resp.json().get("policies", []):
                pol = item.get("policy", {})
                policy_name = pol.get("policy_id", "unknown")
                delete_age_str = None
                for state in pol.get("states", []):
                    for transition in state.get("transitions", []):
                        if transition.get("state_name", "").lower() in ("delete", "deleted"):
                            delete_age_str = transition.get("conditions", {}).get("min_index_age")
                retention_days = _parse_age_to_days(delete_age_str)
                if retention_days is None:
                    continue
                _eval_retention(policy_name, retention_days, "ism",
                                avg_daily_size_gb, avg_shards_per_day,
                                total_disk_gb, shard_limit,
                                retention_analyses, issues)
    except Exception:
        pass

    if not retention_analyses:
        no_ism_policies = True
        issues.append(f"No ISM policies found. Projecting with default {default_ism_days}d.")
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
    for expected in expected_nodes:
        if expected not in found_ids:
            issues.append(f"{expected}: not found in cluster response")

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

    issues: list[str] = []
    for ip in expected_nodes:
        if ip not in found_ips:
            issues.append(f"{ip}: not found in indexer node list")

    notify = bool(issues)
    status = "error" if issues else "ok"
    return _make_check(status, notify,
                       node_count=len(raw_nodes), expected=expected_nodes,
                       nodes=nodes_info, issues=issues or None, url=endpoint)


# ─────────────────────────────────────────────────────────────────────────────
# Argument parser
# ─────────────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Wazuh environment health checker – supports bare-metal, "
                    "Docker, and Kubernetes deployments."
    )
    parser.add_argument("--deploy-mode",
                        choices=["bare-metal", "docker", "kubernetes"],
                        default="bare-metal")
    parser.add_argument("--k8s-namespace", default=K8S_DEFAULT_NAMESPACE)
    parser.add_argument("--node-role",
                        choices=["all", "manager", "indexer", "dashboard"],
                        default="all")
    parser.add_argument("--manager-url",   default=DEFAULT_MANAGER_URL)
    parser.add_argument("--indexer-url",   default=DEFAULT_INDEXER_URL)
    parser.add_argument("--dashboard-url", default=DEFAULT_DASHBOARD_URL)
    parser.add_argument("--secrets-file", default=DEFAULT_SECRETS_FILE)
    parser.add_argument("--log-file", default=DEFAULT_LOG_FILE)
    parser.add_argument("--disk-path",      default=DEFAULT_DISK_PATH)
    parser.add_argument("--disk-threshold", type=int, default=DEFAULT_DISK_THRESHOLD)
    parser.add_argument("--shard-threshold", type=int, default=DEFAULT_SHARD_THRESHOLD)
    parser.add_argument("--manager-host", default="localhost")
    parser.add_argument("--ports", default="1514,1515")
    parser.add_argument("--retention-ism-days", type=int, default=90)
    parser.add_argument("--retention-alerts-days", type=int, default=365)
    parser.add_argument("--alerts-trend-days", type=int, default=7,
                        help="Window in days for alert trend comparison")
    parser.add_argument("--alerts-drop-threshold", type=float, default=20.0,
                        help="Warn when alert drop percentage is >= this value")
    parser.add_argument("--manager-nodes", default="",
                        help="Comma-separated manager cluster node IPs/names")
    parser.add_argument("--indexer-nodes", default="",
                        help="Comma-separated indexer cluster node IPs")
    return parser.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    args = parse_args()
    secrets = _load_secrets(args.secrets_file)
    mgr_user = secrets["MANAGER_USER"]
    mgr_pass = secrets["MANAGER_PASS"]
    idx_user = secrets["INDEXER_USER"]
    idx_pass = secrets["INDEXER_PASS"]

    mode = args.deploy_mode
    role = args.node_role

    print(f"[*] Starting Wazuh health checks (deploy-mode={mode}, node-role={role})…")

    checks: dict[str, dict] = {}

    if mode != "bare-metal" and should_run("container_health", role):
        print("    [0] Container/Pod health…")
        if mode == "docker":
            checks["container_health"] = check_container_health_docker()
        elif mode == "kubernetes":
            checks["container_health"] = check_container_health_k8s(args.k8s_namespace)

    if should_run("manager_api", role):
        print("    [1] Manager API…")
        checks["manager_api"] = check_manager_api(args.manager_url, mgr_user, mgr_pass)
    else:
        checks["manager_api"] = _make_skip(role)

    if should_run("indexer_api", role):
        print("    [2] Indexer API…")
        checks["indexer_api"] = check_indexer_api(args.indexer_url, idx_user, idx_pass)
    else:
        checks["indexer_api"] = _make_skip(role)

    if should_run("dashboard", role):
        print("    [3] Dashboard…")
        checks["dashboard"] = check_dashboard(args.dashboard_url)
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
            args.indexer_url, idx_user, idx_pass, args.disk_threshold)
    else:
        checks["indexer_disk_space"] = _make_skip(role)

    if should_run("shards_per_node", role):
        print("    [5-6] Shards…")
        checks["shards_per_node"], checks["active_shards"] = check_shards(
            args.indexer_url, idx_user, idx_pass, args.shard_threshold)
    else:
        checks["shards_per_node"] = _make_skip(role)
        checks["active_shards"] = _make_skip(role)

    if should_run("jvm_options", role):
        print("    [7] JVM options (API)…")
        checks["jvm_options"] = check_jvm_api(args.indexer_url, idx_user, idx_pass)
    else:
        checks["jvm_options"] = _make_skip(role)

    if should_run("unassigned_shards", role):
        print("    [8] Unassigned shards…")
        checks["unassigned_shards"] = check_unassigned_shards(
            args.indexer_url, idx_user, idx_pass)
    else:
        checks["unassigned_shards"] = _make_skip(role)

    if should_run("ports", role):
        print("    [9] Ports…")
        ports_to_check = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
        checks["ports"] = check_ports(args.manager_host, ports_to_check)
    else:
        checks["ports"] = _make_skip(role)

    if should_run("agents", role):
        print("    [10] Agent summary…")
        checks["agents"] = check_agents(args.manager_url, mgr_user, mgr_pass)
    else:
        checks["agents"] = _make_skip(role)

    if should_run("ilm_policies", role):
        print("    [11] ISM policies…")
        checks["ilm_policies"] = check_ilm_policies(args.indexer_url, idx_user, idx_pass)
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
            args.indexer_url, idx_user, idx_pass,
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

    manager_nodes = (
        [ip.strip() for ip in args.manager_nodes.split(",") if ip.strip()]
        if args.manager_nodes.strip() else DEFAULT_MANAGER_NODES
    )
    if manager_nodes and should_run("manager_cluster_nodes", role):
        print("    [16] Manager cluster nodes…")
        checks["manager_cluster_nodes"] = check_manager_cluster_nodes(
            manager_nodes, args.manager_url, mgr_user, mgr_pass)

    indexer_nodes = (
        [ip.strip() for ip in args.indexer_nodes.split(",") if ip.strip()]
        if args.indexer_nodes.strip() else DEFAULT_INDEXER_NODES
    )
    if indexer_nodes and should_run("indexer_nodes", role):
        print("    [17] Indexer cluster nodes…")
        checks["indexer_nodes"] = check_indexer_nodes(
            indexer_nodes, idx_user, idx_pass, args.indexer_url)

    if should_run("alert_volume_trend", role):
        print("    [18] Alert volume trend…")
        checks["alert_volume_trend"] = check_alert_volume_trend(
            args.indexer_url,
            idx_user,
            idx_pass,
            args.alerts_trend_days,
            args.alerts_drop_threshold,
        )
    else:
        checks["alert_volume_trend"] = _make_skip(role)

    global_notify = any(
        c.get("notify", False) for c in checks.values()
        if c.get("status") != "skipped"
    )

    entry = {
        "timestamp":   datetime.now(tz=timezone.utc).astimezone().isoformat(),
        "deploy_mode": mode,
        "node_role":   role,
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
                delete_age = p.get("delete_min_age") or "no delete phase"
                lines.append(
                    f"{p['name']}: states={p.get('states', [])}, delete_after={delete_age}")
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
        elif key == "alert_volume_trend":
            for reason in _reason(check):
                print(f"         └─ {reason}")

    if global_notify:
        print("\n  ⚠  One or more checks require attention (notify=true in log).")
    else:
        print("\n  ✓  All checks passed.")
    print("─────────────────────────────────────────────────────────────────\n")


if __name__ == "__main__":
    main()
