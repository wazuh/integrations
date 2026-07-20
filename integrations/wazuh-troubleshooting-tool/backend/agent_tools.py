"""
agent_tools.py
Tool registry for the Wazuh Agent (agentic troubleshooting loop).

Every tool wraps an already-existing, already-tested function from
utils/*.py or use_cases/flows — nothing here re-implements diagnostic or
fix logic. This module only describes each one (name, JSON schema, and
whether it mutates the system) so an LLM tool-calling loop (agent_engine.py)
can select and invoke them safely.

Tools are split into two trust tiers:
  - READ-ONLY tools execute immediately, no approval needed.
  - MUTATING tools (restarts services, edits config, deletes data, etc.)
    always pause the agent loop for explicit user approval first.
"""

from executor import run_command
from utils.service_utils import get_service_status, restart_service_and_wait
from utils.cluster_utils import get_cluster_health, get_write_blocks, clear_write_blocks
from utils.index_utils import list_indices, check_most_recent_index, select_indices_by_age, delete_indices
from utils.pipeline_utils import (
    get_agent_status,
    check_manager_config,
    get_alerts_json_status,
    check_cluster_shards,
    check_alert_indices,
)
from utils.agent_utils import list_active_agents, restart_agent as _restart_agent, restart_all_agents as _restart_all_agents
from utils.manager_config_utils import set_log_alert_level, enable_jsonout_output
from utils.manager_log_utils import get_manager_log_errors, get_manager_disk_usage
from utils.log_handler import LogHandler
from utils.filebeat_utils import (
    run_filebeat_output_test,
    get_filebeat_log_errors,
    fix_unsupported_filebeat_version as _fix_unsupported_filebeat_version,
)
from utils.replica_utils import set_replica_count
from utils.shard_utils import get_unassigned_shards, explain_allocation
from utils.fix_engine import FixEngine
from utils.cert_utils import regenerate_and_redeploy_certs as _regenerate_and_redeploy_certs
from utils.default_route_utils import set_default_route
from utils.lgtm_utils import find_relevant_issues
from utils.public_repo_search import search_public_issues, search_public_discussions
from copilot_engine import fetch_wazuh_cloud_trial_doc

KNOWN_SERVICES = ["wazuh-indexer", "wazuh-manager", "wazuh-dashboard", "filebeat"]


# ─────────────────────────────────────────────────────────────────────────────
# Combined helpers — a few mutating fixes are naturally "edit + restart" as a
# single logical action in the existing wizards, so they stay that way here
# too (one approval, not two).
# ─────────────────────────────────────────────────────────────────────────────

def _fix_manager_log_alert_level():
    new_value = set_log_alert_level(3)
    status = restart_service_and_wait("wazuh-manager")
    return {"log_alert_level": new_value, "manager_status": status}


def _fix_manager_jsonout_output():
    enabled = enable_jsonout_output()
    status = restart_service_and_wait("wazuh-manager")
    return {"jsonout_output_enabled": enabled, "manager_status": status}


def _fix_dashboard_default_route():
    new_value = set_default_route()
    status = restart_service_and_wait("wazuh-dashboard")
    return {"default_route": new_value, "dashboard_status": status}


def _check_all_services():
    return {svc: get_service_status(svc) for svc in KNOWN_SERVICES}


def _get_cluster_health():
    parsed, raw = get_cluster_health()
    return parsed if parsed is not None else {"error": "could not reach indexer", "raw": raw}


def _search_lgtm_knowledge_base(query):
    issues = find_relevant_issues(query)
    if not issues:
        return {"matches": [], "note": "no matching resolved issue found in the internal knowledge base"}
    return {
        "matches": [
            {
                "number": i["number"],
                "title": i["title"],
                "resolution": "\n".join(i.get("comments", []) + i.get("external_community", []))[:1500],
            }
            for i in issues
        ]
    }


def _search_public_wazuh_repo(query):
    issues = search_public_issues(query)
    discussions = search_public_discussions(query)
    return {
        "issues": [
            {
                "number": i["number"],
                "title": i["title"],
                "url": i["url"],
                "discussion": "\n".join(i.get("comments", []))[:1000],
            }
            for i in issues
        ],
        "discussions": [
            {"number": d["number"], "title": d["title"], "url": d["url"], "answer": d.get("answer", "")}
            for d in discussions
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# TOOL REGISTRY
# ─────────────────────────────────────────────────────────────────────────────
# risk: "low" | "medium" | "high" — shown as a badge in the approval UI.

TOOLS = [
    # ── READ-ONLY: services & system ────────────────────────────────────
    {
        "name": "check_all_services",
        "description": "Get systemd status (active/inactive/failed) for wazuh-indexer, wazuh-manager, wazuh-dashboard and filebeat in one call.",
        "mutating": False,
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: _check_all_services(),
    },
    {
        "name": "check_service_status",
        "description": "Get the systemd status of a single named service.",
        "mutating": False,
        "parameters": {
            "type": "object",
            "properties": {"service": {"type": "string", "enum": KNOWN_SERVICES}},
            "required": ["service"],
        },
        "fn": lambda service: get_service_status(service),
    },
    {
        "name": "check_disk_usage",
        "description": "Run `df -h` on the host. Use when investigating slow/failed services or unassigned shards, since a full disk is a common silent cause.",
        "mutating": False,
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: FixEngine.check_disk(),
    },

    # ── READ-ONLY: IPs & certs ───────────────────────────────────────────
    {
        "name": "check_ip_configuration",
        "description": "Compare the indexer IP configured at install time (config.yml) against what's actually configured in the indexer and dashboard configs. Mismatches are a common cause of the dashboard failing to reach the indexer.",
        "mutating": False,
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: FixEngine.compare_ips(),
    },
    {
        "name": "check_indexer_cert_paths",
        "description": "Check whether the TLS cert/key/CA files referenced in opensearch.yml actually exist on disk.",
        "mutating": False,
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: FixEngine.check_indexer_cert_paths(),
    },
    {
        "name": "check_dashboard_cert_paths",
        "description": "Check whether the TLS cert/key/CA files referenced in opensearch_dashboards.yml actually exist on disk.",
        "mutating": False,
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: FixEngine.check_dashboard_cert_paths(),
    },
    {
        "name": "check_cert_permissions",
        "description": "Check file/directory permissions and ownership on the dashboard's certs directory.",
        "mutating": False,
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: FixEngine.check_cert_permissions(),
    },
    {
        "name": "check_jvm_heap",
        "description": "Check the wazuh-indexer JVM heap size (jvm.options) against the recommended value (50% of host RAM). Undersized heap is a common cause of indexer crashes/slowness.",
        "mutating": False,
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: FixEngine.check_jvm_heap(),
    },

    # ── READ-ONLY: manager / agents / pipeline ───────────────────────────
    {
        "name": "check_manager_config",
        "description": "Check ossec.conf's log_alert_level and jsonout_output settings — misconfiguration here silently drops alerts before they're ever written to alerts.json.",
        "mutating": False,
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: check_manager_config(),
    },
    {
        "name": "get_manager_log_errors",
        "description": "Tail the manager's ossec.log filtered to error/warn lines.",
        "mutating": False,
        "parameters": {"type": "object", "properties": {"lines": {"type": "integer", "description": "how many recent lines to scan, default 200"}}},
        "fn": lambda lines=200: get_manager_log_errors(lines),
    },
    {
        "name": "get_manager_disk_usage",
        "description": "Disk usage for /var/ossec (the manager's data directory).",
        "mutating": False,
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: get_manager_disk_usage(),
    },
    {
        "name": "get_agent_status",
        "description": "Run agent_control -l, optionally filtered to one agent by name or ID, to check if it's Active.",
        "mutating": False,
        "parameters": {"type": "object", "properties": {"identifier": {"type": "string", "description": "agent name or ID to look up; omit to just check whether ANY agent is active"}}},
        "fn": lambda identifier=None: get_agent_status(identifier),
    },
    {
        "name": "list_active_agents",
        "description": "List every currently-active endpoint agent (id, name), excluding the manager's own local agent 000.",
        "mutating": False,
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: list_active_agents(),
    },
    {
        "name": "get_alerts_json_status",
        "description": "Check whether the manager is actively writing new alerts to alerts.json (the file Filebeat reads). Staleness here means the pipeline is stalled at the manager, before Filebeat/indexer are even involved.",
        "mutating": False,
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: get_alerts_json_status(),
    },

    # ── READ-ONLY: filebeat ──────────────────────────────────────────────
    {
        "name": "run_filebeat_output_test",
        "description": "Run `filebeat test output` to check Filebeat's connectivity to the indexer.",
        "mutating": False,
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: run_filebeat_output_test(),
    },
    {
        "name": "get_filebeat_log_errors",
        "description": "Tail Filebeat's log filtered to error/warn lines.",
        "mutating": False,
        "parameters": {"type": "object", "properties": {"lines": {"type": "integer", "description": "how many recent lines to scan, default 200"}}},
        "fn": lambda lines=200: get_filebeat_log_errors(lines),
    },

    # ── READ-ONLY: indexer / cluster / indices ───────────────────────────
    {
        "name": "get_cluster_health",
        "description": "GET /_cluster/health from the indexer (status green/yellow/red, node count, shard counts).",
        "mutating": False,
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: _get_cluster_health(),
    },
    {
        "name": "check_cluster_shards",
        "description": "Cluster health plus, if not green, the detail of *why* shards are unassigned (disk watermark, no replica node, etc).",
        "mutating": False,
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: check_cluster_shards(),
    },
    {
        "name": "get_unassigned_shards",
        "description": "List every currently-unassigned shard with its index, shard number and reason.",
        "mutating": False,
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: get_unassigned_shards(),
    },
    {
        "name": "explain_shard_allocation",
        "description": "Get OpenSearch's own explanation for why one specific shard is unassigned.",
        "mutating": False,
        "parameters": {
            "type": "object",
            "properties": {
                "index": {"type": "string"},
                "shard": {"type": "integer"},
                "primary": {"type": "boolean", "description": "true for the primary copy, false for a replica"},
            },
            "required": ["index", "shard"],
        },
        "fn": lambda index, shard, primary=False: explain_allocation(index, shard, primary),
    },
    {
        "name": "get_cluster_write_blocks",
        "description": "Check for cluster-wide read_only/create_index blocks. These silently prevent ALL writes/new indices cluster-wide even when _cluster/health looks fine.",
        "mutating": False,
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: get_write_blocks(),
    },
    {
        "name": "list_alert_indices",
        "description": "List wazuh-alerts-* indices with health/status/doc count/size.",
        "mutating": False,
        "parameters": {"type": "object", "properties": {"pattern": {"type": "string", "description": "index pattern, default 'wazuh-alerts-*'"}}},
        "fn": lambda pattern="wazuh-alerts-*": list_indices(pattern),
    },
    {
        "name": "check_most_recent_alert_index",
        "description": "Find the newest wazuh-alerts-* index by date and report how many days old it is — the key check for 'no alerts are showing today'.",
        "mutating": False,
        "parameters": {"type": "object", "properties": {"pattern": {"type": "string", "description": "index pattern, default 'wazuh-alerts-*'"}}},
        "fn": lambda pattern="wazuh-alerts-*": check_most_recent_index(pattern),
    },
    {
        "name": "check_alert_indices_today",
        "description": "Confirm wazuh-alerts-* indices exist and one matching TODAY's date is present.",
        "mutating": False,
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: check_alert_indices(),
    },
    {
        "name": "preview_indices_older_than",
        "description": "Preview which indices would be affected by an age-based cleanup, WITHOUT deleting anything. Always call this before proposing delete_old_indices, and show the exact list to the user.",
        "mutating": False,
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "index pattern, default 'wazuh-alerts-*'"},
                "older_than_days": {"type": "integer"},
            },
            "required": ["older_than_days"],
        },
        "fn": lambda older_than_days, pattern="wazuh-alerts-*": select_indices_by_age(pattern, older_than_days=older_than_days),
    },

    # ── READ-ONLY: knowledge base ────────────────────────────────────────
    {
        "name": "search_lgtm_knowledge_base",
        "description": (
            "Search internally-reviewed, previously-resolved Wazuh issues (marked LGTM by the community "
            "team) for one matching the current symptom. Call this before proposing a fix for anything "
            "that looks like it could be a known, previously-seen issue rather than guessing from scratch."
        ),
        "mutating": False,
        "parameters": {
            "type": "object",
            "properties": {"query": {"type": "string", "description": "the symptom or error message to search for"}},
            "required": ["query"],
        },
        "fn": lambda query: _search_lgtm_knowledge_base(query),
    },
    {
        "name": "search_public_wazuh_issues",
        "description": "Live-search the public wazuh/wazuh GitHub repo (issues + discussions) for similar reported problems and how they were resolved.",
        "mutating": False,
        "parameters": {
            "type": "object",
            "properties": {"query": {"type": "string", "description": "the symptom or error message to search for"}},
            "required": ["query"],
        },
        "fn": lambda query: _search_public_wazuh_repo(query),
    },
    {
        "name": "fetch_wazuh_cloud_trial_docs",
        "description": "Fetch the official Wazuh Cloud trial sign-up documentation. Use when a user asks about Wazuh Cloud trial credentials, sign-up, or login.",
        "mutating": False,
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: {"content": fetch_wazuh_cloud_trial_doc()},
    },

    # ── READ-ONLY: logs ───────────────────────────────────────────────────
    {
        "name": "get_indexer_logs",
        "description": "Recent wazuh-indexer cluster log, filtered to error/warn.",
        "mutating": False,
        "parameters": {"type": "object", "properties": {"hours": {"type": "integer", "description": "how many hours back, default 2"}}},
        "fn": lambda hours=2: LogHandler.clean_logs(LogHandler.get_indexer_logs(hours)),
    },
    {
        "name": "get_dashboard_logs",
        "description": "Recent wazuh-dashboard journal log, filtered to error/warn.",
        "mutating": False,
        "parameters": {"type": "object", "properties": {"hours": {"type": "integer", "description": "how many hours back, default 2"}}},
        "fn": lambda hours=2: LogHandler.clean_logs(LogHandler.get_dashboard_logs(hours)),
    },
    # ── MUTATING: services ───────────────────────────────────────────────
    {
        "name": "restart_service",
        "description": "Restart a systemd service and wait for it to come back active.",
        "mutating": True,
        "risk": "medium",
        "parameters": {
            "type": "object",
            "properties": {"service": {"type": "string", "enum": KNOWN_SERVICES}},
            "required": ["service"],
        },
        "fn": lambda service: restart_service_and_wait(service),
    },

    # ── MUTATING: IP / certs ─────────────────────────────────────────────
    {
        "name": "fix_indexer_ip",
        "description": "Rewrite network.host in opensearch.yml to match the install-time control IP, then restart wazuh-indexer.",
        "mutating": True,
        "risk": "medium",
        "parameters": {"type": "object", "properties": {"control_ip": {"type": "string"}}, "required": ["control_ip"]},
        "fn": lambda control_ip: FixEngine.fix_indexer_ip(control_ip),
    },
    {
        "name": "fix_dashboard_ip",
        "description": "Rewrite the indexer host URL in opensearch_dashboards.yml to match the control IP, then restart wazuh-dashboard.",
        "mutating": True,
        "risk": "medium",
        "parameters": {"type": "object", "properties": {"control_ip": {"type": "string"}}, "required": ["control_ip"]},
        "fn": lambda control_ip: FixEngine.fix_dashboard_ip(control_ip),
    },
    {
        "name": "fix_indexer_cert_paths",
        "description": "Auto-detect the cert/key/CA files actually present in /etc/wazuh-indexer/certs and rewrite opensearch.yml to point at them, then restart wazuh-indexer.",
        "mutating": True,
        "risk": "medium",
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: FixEngine.fix_indexer_cert_paths(),
    },
    {
        "name": "fix_dashboard_cert_paths",
        "description": "Auto-detect the cert/key/CA files actually present in /etc/wazuh-dashboard/certs and rewrite opensearch_dashboards.yml to point at them, then restart wazuh-dashboard.",
        "mutating": True,
        "risk": "medium",
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: FixEngine.fix_dashboard_cert_paths(),
    },
    {
        "name": "fix_cert_permissions",
        "description": "chmod/chown the dashboard's certs directory back to the expected 500/400 wazuh-dashboard ownership.",
        "mutating": True,
        "risk": "low",
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: FixEngine.fix_cert_permissions(),
    },
    {
        "name": "regenerate_and_redeploy_certs",
        "description": (
            "Full TLS cert regeneration: runs wazuh-certs-tool.sh and redeploys fresh certs to the indexer, "
            "Filebeat and dashboard, then restarts all three services. Use only after simpler cert-path/permission "
            "fixes have already been ruled out or failed — this is the heaviest, slowest cert fix available."
        ),
        "mutating": True,
        "risk": "high",
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: _regenerate_and_redeploy_certs(),
    },

    # ── MUTATING: dashboard config ───────────────────────────────────────
    {
        "name": "fix_dashboard_default_route",
        "description": "Set uiSettings.overrides.defaultRoute to /app/wz-home in opensearch_dashboards.yml (fixes 'Application Not Found' after an upgrade), then restart wazuh-dashboard.",
        "mutating": True,
        "risk": "low",
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: _fix_dashboard_default_route(),
    },

    # ── MUTATING: indexer heap ───────────────────────────────────────────
    {
        "name": "fix_jvm_heap",
        "description": "Set -Xms/-Xmx in the indexer's jvm.options to the given size (GB), then restart wazuh-indexer.",
        "mutating": True,
        "risk": "medium",
        "parameters": {"type": "object", "properties": {"heap_gb": {"type": "integer"}}, "required": ["heap_gb"]},
        "fn": lambda heap_gb: FixEngine.fix_jvm_heap(heap_gb),
    },

    # ── MUTATING: manager config ─────────────────────────────────────────
    {
        "name": "fix_manager_log_alert_level",
        "description": "Set ossec.conf's log_alert_level to 3 (so alerts stop being silently dropped) and restart wazuh-manager.",
        "mutating": True,
        "risk": "low",
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: _fix_manager_log_alert_level(),
    },
    {
        "name": "fix_manager_jsonout_output",
        "description": "Set ossec.conf's jsonout_output to yes (required for alerts.json to be written) and restart wazuh-manager.",
        "mutating": True,
        "risk": "low",
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: _fix_manager_jsonout_output(),
    },

    # ── MUTATING: agents ──────────────────────────────────────────────────
    {
        "name": "restart_agent",
        "description": "Remotely restart one currently-Active endpoint agent by ID.",
        "mutating": True,
        "risk": "low",
        "parameters": {"type": "object", "properties": {"agent_id": {"type": "string"}}, "required": ["agent_id"]},
        "fn": lambda agent_id: _restart_agent(agent_id),
    },
    {
        "name": "restart_all_agents",
        "description": "Remotely restart EVERY currently-active endpoint agent.",
        "mutating": True,
        "risk": "medium",
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: _restart_all_agents(),
    },

    # ── MUTATING: filebeat ────────────────────────────────────────────────
    {
        "name": "fix_unsupported_filebeat_version",
        "description": "Deploy the Wazuh Filebeat module + alerts template, and reinstall Filebeat-OSS 7.10.2 if the version is still wrong. Use when classify_filebeat_failure-style symptoms point at an unsupported version.",
        "mutating": True,
        "risk": "medium",
        "parameters": {"type": "object", "properties": {}},
        "fn": lambda: _fix_unsupported_filebeat_version(),
    },

    # ── MUTATING: cluster / indices ──────────────────────────────────────
    {
        "name": "clear_cluster_write_blocks",
        "description": "Clear the given cluster.blocks.* settings that are silently preventing writes/new indices cluster-wide.",
        "mutating": True,
        "risk": "medium",
        "parameters": {
            "type": "object",
            "properties": {"block_names": {"type": "array", "items": {"type": "string"}}},
            "required": ["block_names"],
        },
        "fn": lambda block_names: clear_write_blocks(block_names),
    },
    {
        "name": "set_index_replica_count",
        "description": "Update number_of_replicas on an index/pattern. Applies immediately to existing indices, no reindex needed.",
        "mutating": True,
        "risk": "low",
        "parameters": {
            "type": "object",
            "properties": {"index_pattern": {"type": "string"}, "replicas": {"type": "integer"}},
            "required": ["index_pattern", "replicas"],
        },
        "fn": lambda index_pattern, replicas: set_replica_count(index_pattern, replicas),
    },
    {
        "name": "delete_old_indices",
        "description": (
            "PERMANENTLY delete the given indices. IRREVERSIBLE — there is no undo. Always call "
            "preview_indices_older_than first and pass exactly the index names it returned; never guess names."
        ),
        "mutating": True,
        "risk": "high",
        "parameters": {
            "type": "object",
            "properties": {"index_names": {"type": "array", "items": {"type": "string"}}},
            "required": ["index_names"],
        },
        "fn": lambda index_names: delete_indices(index_names),
    },

    # ── MUTATING: ad-hoc escape hatch ─────────────────────────────────────
    {
        "name": "run_shell_command",
        "description": (
            "Run an arbitrary shell command for ad-hoc investigation when no other tool fits "
            "(e.g. 'grep', 'cat', 'journalctl', 'ps aux'). Prefer a specific tool above whenever one "
            "applies. This always requires approval — even for a command that only reads state — "
            "because it cannot be verified as safe the way the named tools above can."
        ),
        "mutating": True,
        "risk": "medium",
        "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
        "fn": lambda command: run_command(command),
    },
]

TOOLS_BY_NAME = {t["name"]: t for t in TOOLS}


# qwen3:1.7b runs CPU-only on modest hardware — passing it all 48 tool
# schemas makes the prompt so long it can take minutes just to start
# answering. This is the reduced set it gets instead: the most common
# read-only diagnostics, the most common single-step fixes, and all three
# knowledge-base tools (the whole point of that feature). Claude has no
# such constraint and keeps the full TOOLS list via to_anthropic_schema().
OLLAMA_TOOL_NAMES = {
    # read-only diagnostics
    "check_all_services", "check_service_status", "check_disk_usage",
    "check_manager_config", "get_manager_log_errors", "get_manager_disk_usage",
    "get_agent_status", "list_active_agents", "get_alerts_json_status",
    "run_filebeat_output_test", "get_filebeat_log_errors",
    "get_cluster_health", "check_cluster_shards", "get_unassigned_shards",
    "check_most_recent_alert_index", "check_alert_indices_today",
    "get_indexer_logs", "get_dashboard_logs",
    # knowledge base — always available regardless of brain
    "search_lgtm_knowledge_base", "search_public_wazuh_issues", "fetch_wazuh_cloud_trial_docs",
    # the handful of most common single-step fixes
    "restart_service", "fix_manager_log_alert_level", "fix_manager_jsonout_output", "restart_agent",
}


def to_openai_schema():
    """Ollama's /api/chat 'tools' param — the reduced OLLAMA_TOOL_NAMES subset only."""
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["parameters"],
            },
        }
        for t in TOOLS if t["name"] in OLLAMA_TOOL_NAMES
    ]


def to_anthropic_schema():
    """Claude's 'tools' param — the full TOOLS list, no reduction needed."""
    return [
        {
            "name": t["name"],
            "description": t["description"],
            "input_schema": t["parameters"],
        }
        for t in TOOLS
    ]


def list_tools_metadata():
    """For the frontend's tool-transparency panel — no fn/lambdas."""
    return [
        {
            "name": t["name"],
            "description": t["description"],
            "mutating": t["mutating"],
            "risk": t.get("risk", "read-only"),
            "ollama_available": t["name"] in OLLAMA_TOOL_NAMES,
        }
        for t in TOOLS
    ]
