"""
copilot_engine.py
Wazuh Copilot — AI-powered Wazuh expert assistant.
Sends conversations to a local Ollama instance with a deep Wazuh system prompt.
Optionally enriches context with live environment data from the Wazuh API / Indexer.
"""

import json
import requests
import urllib3

urllib3.disable_warnings()

# ─────────────────────────────────────────────────────────────────────────────
# SYSTEM PROMPT — the brain of the copilot
# ─────────────────────────────────────────────────────────────────────────────

WAZUH_SYSTEM_PROMPT = """You are WazuhCopilot, a world-class Wazuh SIEM expert assistant.
Provide direct, precise, and technical answers.
Always generate complete, ready-to-use XML rules/decoders or YAML configs.
For explanations, keep them brief and structured. Use current Wazuh v4.x syntax."""


# ─────────────────────────────────────────────────────────────────────────────
# ENVIRONMENT CONTEXT COLLECTOR
# ─────────────────────────────────────────────────────────────────────────────

def _safe_run(cmd: str) -> str:
    """Run a shell command, return output or empty string on failure."""
    import subprocess
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5)
        return out.decode(errors="replace").strip()
    except Exception:
        return ""


def collect_environment_context(
    wazuh_api_url: str,
    api_username: str,
    api_password: str,
    indexer_url: str,
    indexer_username: str,
    indexer_password: str,
) -> dict:
    """
    Collect live environment data to give the AI context about the user's
    actual Wazuh deployment. All failures are silently ignored.
    """
    ctx = {}

    # ── Service status ────────────────────────────────────────────────────
    ctx["manager_status"]   = _safe_run("systemctl is-active wazuh-manager")
    ctx["indexer_status"]   = _safe_run("systemctl is-active wazuh-indexer")
    ctx["dashboard_status"] = _safe_run("systemctl is-active wazuh-dashboard")
    ctx["filebeat_status"]  = _safe_run("systemctl is-active filebeat")

    # ── System resources ─────────────────────────────────────────────────
    ctx["disk"]   = _safe_run("df -h / /var/ossec /var/lib/wazuh-indexer 2>/dev/null | head -5")
    ctx["memory"] = _safe_run("free -h")

    # ── Wazuh API ─────────────────────────────────────────────────────────
    try:
        token_res = requests.post(
            f"{wazuh_api_url}/security/user/authenticate?raw=true",
            auth=(api_username, api_password),
            verify=False,
            timeout=5,
        )
        token = token_res.text.strip() if token_res.status_code == 200 else None

        if token:
            headers = {"Authorization": f"Bearer {token}"}

            # Manager info
            info = requests.get(f"{wazuh_api_url}/", headers=headers, verify=False, timeout=5)
            if info.status_code == 200:
                d = info.json().get("data", {})
                ctx["manager_version"] = d.get("api_version", "unknown")
                ctx["wazuh_version"]   = d.get("api_version", "unknown")

            # Agent summary
            agents_res = requests.get(
                f"{wazuh_api_url}/agents?limit=500",
                headers=headers,
                verify=False,
                timeout=5,
            )
            if agents_res.status_code == 200:
                agents = agents_res.json().get("data", {}).get("affected_items", [])
                ctx["agents_total"]        = len(agents)
                ctx["agents_active"]       = sum(1 for a in agents if a.get("status") == "active")
                ctx["agents_disconnected"] = sum(1 for a in agents if a.get("status") == "disconnected")

            # Cluster
            cluster_res = requests.get(
                f"{wazuh_api_url}/cluster/status",
                headers=headers,
                verify=False,
                timeout=5,
            )
            if cluster_res.status_code == 200:
                cdata = cluster_res.json().get("data", {})
                ctx["cluster_enabled"] = cdata.get("enabled", "unknown")
                ctx["cluster_running"] = cdata.get("running", "unknown")

    except Exception:
        pass

    # ── Indexer cluster health ─────────────────────────────────────────────
    try:
        health = requests.get(
            f"{indexer_url}/_cluster/health",
            auth=(indexer_username, indexer_password),
            verify=False,
            timeout=5,
        )
        if health.status_code == 200:
            h = health.json()
            ctx["indexer_cluster_status"]     = h.get("status", "unknown")
            ctx["indexer_nodes"]              = h.get("number_of_nodes", 0)
            ctx["indexer_active_shards"]      = h.get("active_shards", 0)
            ctx["indexer_unassigned_shards"]  = h.get("unassigned_shards", 0)
    except Exception:
        pass

    # ── Recent ossec.log errors ────────────────────────────────────────────
    ctx["recent_manager_errors"] = _safe_run(
        "tail -n 30 /var/ossec/logs/ossec.log 2>/dev/null | grep -i -E 'error|warn' | tail -10"
    )

    return ctx


def format_environment_context(ctx: dict) -> str:
    """Concise environment summary for CPU-friendly inference."""
    if not ctx:
        return ""

    parts = []
    # Services
    svcs = []
    for key, name in [("manager_status", "manager"), ("indexer_status", "indexer"), ("dashboard_status", "dashboard"), ("filebeat_status", "filebeat")]:
        val = ctx.get(key)
        if val:
            svcs.append(f"{name}:{val}")
    if svcs:
        parts.append("Services: " + ", ".join(svcs))

    # Version
    if ctx.get("wazuh_version"):
        parts.append(f"Version: {ctx['wazuh_version']}")

    # Agents
    if ctx.get("agents_total") is not None:
        parts.append(f"Agents: {ctx['agents_total']} total ({ctx.get('agents_active', 0)} active)")

    # Indexer status
    if ctx.get("indexer_cluster_status"):
        parts.append(f"Indexer: {ctx['indexer_cluster_status'].upper()}")

    if not parts:
        return ""

    return "=== Environment: " + " | ".join(parts) + " ==="


# ─────────────────────────────────────────────────────────────────────────────
# MAIN COPILOT FUNCTION
# ─────────────────────────────────────────────────────────────────────────────

def fetch_wazuh_cloud_trial_doc() -> str:
    """Fetch the official Wazuh Cloud trial documentation and extract the main content."""
    try:
        url = "https://documentation.wazuh.com/current/cloud-service/getting-started/sign-up-trial.html"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            html = r.text
            start_idx = html.find('<section id="sign-up-for-a-trial">')
            if start_idx != -1:
                chunk = html[start_idx:start_idx + 15000]
                import re
                clean_text = re.sub(r'<[^>]+>', ' ', chunk)
                clean_text = re.sub(r'\s+', ' ', clean_text).strip()
                return clean_text[:6000]
    except Exception as e:
        print(f"Error fetching documentation: {e}")
    return ""

# Session-based cache for environment context strings to enable Ollama KV cache reuse
SESSION_ENV_CACHE = {}

def run_copilot(
    messages: list,
    ollama_url: str,
    ollama_model: str,
    include_env: bool,
    wazuh_api_url: str,
    api_username: str,
    api_password: str,
    indexer_url: str,
    indexer_username: str,
    indexer_password: str,
    stream: bool = False,
    session_id: str = None,
    system_prompt: str = None,
) -> str:
    # Check if this query is about Wazuh Cloud trial or credentials
    last_user_msg = ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            last_user_msg = msg.get("content", "").lower()
            break

    doc_context = ""
    if "cloud" in last_user_msg and any(x in last_user_msg for x in ["trial", "trail", "credential", "password", "username", "login"]):
        doc_context = fetch_wazuh_cloud_trial_doc()

    # Build the system message list
    base_prompt = system_prompt if system_prompt is not None else WAZUH_SYSTEM_PROMPT
    if doc_context:
        system_content = (
            base_prompt + 
            f"\n\n=== Official Wazuh Cloud Service Documentation ===\n{doc_context}\n=================================================\n\n"
            "Instructions: Greet the user as @4Ø4S0υł. Use the above official documentation to answer their question. "
            "Explain that Wazuh Cloud trial credentials (username/password) are sent in a welcome email once provisioned, "
            "or can be retrieved in the Environments console. Provide links if relevant."
        )
    else:
        system_content = base_prompt

    if include_env:
        try:
            env_str = None
            if session_id and session_id in SESSION_ENV_CACHE:
                env_str = SESSION_ENV_CACHE[session_id]

            if not env_str:
                env_ctx = collect_environment_context(
                    wazuh_api_url, api_username, api_password,
                    indexer_url, indexer_username, indexer_password,
                )
                env_str = format_environment_context(env_ctx)
                if session_id and env_str:
                    SESSION_ENV_CACHE[session_id] = env_str

            if env_str:
                system_content += "\n\n" + env_str
        except Exception:
            pass

    ollama_messages = [{"role": "system", "content": system_content}] + messages

    payload = {
        "model":    ollama_model,
        "messages": ollama_messages,
        "stream":   False,
        "think":    False,
        "options": {
            "temperature": 0.3,   # more factual for technical answers
            "num_predict": 4096,
        },
    }

    resp = requests.post(
        f"{ollama_url}/api/chat",
        json=payload,
        timeout=300,
    )

    if resp.status_code != 200:
        raise RuntimeError(
            f"Ollama returned HTTP {resp.status_code}: {resp.text[:300]}"
        )

    data = resp.json()
    return data.get("message", {}).get("content", "").strip()


def list_ollama_models(ollama_url: str) -> list:
    """Return list of available Ollama model names."""
    try:
        resp = requests.get(f"{ollama_url}/api/tags", timeout=10)
        if resp.status_code == 200:
            return [m["name"] for m in resp.json().get("models", [])]
    except Exception:
        pass
    return []


def check_ollama_health(ollama_url: str) -> dict:
    """Quick health check — is Ollama reachable and is the model available?"""
    try:
        resp = requests.get(f"{ollama_url}/api/tags", timeout=5)
        if resp.status_code == 200:
            models = [m["name"] for m in resp.json().get("models", [])]
            return {"ok": True, "models": models}
    except Exception as e:
        return {"ok": False, "error": str(e), "models": []}
    return {"ok": False, "models": []}
