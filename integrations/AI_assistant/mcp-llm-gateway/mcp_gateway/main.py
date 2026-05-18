import time
import json
import uuid
import re
import traceback
import asyncio
import os
from datetime import datetime, timezone
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from typing import Optional, Any, Dict, List, Tuple

from .config import (
    GATEWAY_API_KEY, VERBOSE, DEBUG_ACTION_OUTPUT,
    ALERTS_INDEX,
    LLM_PROVIDER, GEMINI_MODEL, OPENAI_MODEL, BEDROCK_MODEL_ID,
    MCP_SSE_URL, OPENSEARCH_DASHBOARD_URL, OPENSEARCH_DASHBOARD_BASEPATH,
    OPENSEARCH_DASHBOARD_SPACE, OPENSEARCH_DASHBOARD_VERIFY_TLS,
    OPENSEARCH_DASHBOARD_CA_FILE, OPENSEARCH_DASHBOARD_USER, OPENSEARCH_DASHBOARD_PASS,
    WAZUH_INDEXER_URL, WAZUH_INDEXER_VERIFY_TLS,
    WAZUH_INDEXER_CA_FILE, AUTO_CREATE_INDEX_PATTERN, PUBLIC_GATEWAY_URL
)
from .models import PredictBody, PendingAction, WizardState
from .state import PENDING, PENDING_LOCK, WIZARDS, WIZARDS_LOCK, _cleanup_pending, _cleanup_wizards

from .llm import _build_llm, _ensure_agent_executor, _load_mcp_tools
from .wazuh_api import (
    _stg_api, _prod_api, _get_agents, _find_agent, _agent_status,
    wazuh_restart_agent, wazuh_delete_agents_bulk, wazuh_list_groups, wazuh_assign_agent_to_group, wazuh_remove_agent_from_group
)
from .opensearch_api import (
    osd_request, osd_find_index_pattern_id_by_title, osd_create_index_pattern,
    indexer_request, _indexer_configured
)
from .dashboard_plan import (
    llm_generate_dashboard_plan, discover_available_index_patterns,
    validate_plan_fields, guess_time_field_for_index, build_vis_payload,
    build_dashboard_payload, build_multi_dashboard_payload, 
    llm_generate_full_dashboard_plan, osd_create_visualization, osd_create_dashboard,
    _last_json_block
)
from .formatters import (
    _parse_timeframe_to_seconds, _parse_wazuh_iso, _fmt_age,
    format_disconnected_candidates, format_restart_agent_result,
    format_delete_agents_result, format_assign_group_result, format_remove_group_result, _api_reason
)
from .dql_builder import try_build_discover_filter_link
from .inventory_qa import answer_inventory_query
from .report_generator import generate_pdf_report, send_report_email

def _extract_prompt(body: PredictBody) -> str:
    if isinstance(body.parameters, dict):
        for key in ("prompt", "question", "input", "text"):
            if body.parameters.get(key):
                return str(body.parameters[key])
        msgs = body.parameters.get("messages")
        if isinstance(msgs, list):
            for m in reversed(msgs):
                if isinstance(m, dict) and m.get("role") == "user":
                    return m.get("content") or ""
    return ""

def _resolve_agent_identifier(identifier: str, agents: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    identifier = str(identifier).strip()
    for a in agents:
        if str(a.get("id")) == identifier:
            return a
    for a in agents:
        if str(a.get("name", "")).lower() == identifier.lower():
            return a
    return None

def _session_id(request: Request, x_session_id: Optional[str]) -> str:
    if x_session_id and x_session_id.strip():
        return x_session_id.strip()[:128]
    ip = request.client.host if request.client else "unknown"
    return f"ip:{ip}"

def _parse_agent_ids(raw_ids: str) -> List[str]:
    if not raw_ids:
        return []
    s = re.sub(r"[,\n\r\t]+", " ", raw_ids)
    s = re.sub(r"\band\b", " ", s, flags=re.I)
    tokens = re.findall(r"\b[0-9]{3,}\b", s)
    out, seen = [], set()
    for t in tokens:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out

app = FastAPI(title="OpenSearch MCP → LLM Gateway (v3.7.0)", version="3.7.0")
app.state.recent_emails = []

_GREETING = re.compile(r"^\s*(hi|hello|hey|yo|hai|hola)\b[!. ]*$", re.I)
_HELP = re.compile(r"^\s*(help|commands|command\s+list|examples|usage|menu|what\s+can\s+you\s+do)\b", re.I)
_CONFIRM = re.compile(r"^\s*(confirm|yes|y|ok|okay|proceed|go\s+ahead|do\s+it)\s*\.?\s*$", re.I)
_DENY = re.compile(r"^\s*(no|n|cancel|stop|abort|nevermind|never\s+mind)\s*\.?\s*$", re.I)
_CREATE_CUSTOM_DASHBOARD = re.compile(r"^\s*(?:create|make|build)\s+(?:a\s+)?custom\s+dashboard\b", re.I)
_WIZARD_RESET = re.compile(r"^\s*(?:reset|cancel)\s+dashboard\s+wizard\b", re.I)
_RESTART_AGENT = re.compile(
    r"""(?ix)
    ^\s*
    (?:please\s+)?(?:can\s+you\s+)?(?:kindly\s+)?
    (?:restart|reboot)\s+
    (?:the\s+)?(?:wazuh\s+)?(?:agent)\s*
    (?:id\s*)?
    (?P<id>\d{1,6})
    \s*$
    """
)
_REMOVE_AGENT = re.compile(r"\b(?:remove|delete)\b.*\bagent\b(?:\s*id)?\s*(?P<id>\d{3,})\b", re.I)
_REMOVE_ALL_DISCONNECTED = re.compile(r"\b(?:remove|delete)\b.*\b(?:all\s+)?discon(?:nec)?ted\b.*\bagents?\b", re.I)
_REMOVE_DISCONNECTED_OLDER_THAN = re.compile(
    r"\b(?:remove|delete)\b.*\bdiscon(?:nec)?ted\b.*\bagents?\b.*"
    r"\b(?:older[_\s-]?than|older\s+than|for|since)\b\s*(?P<tf>[0-9smhdwSMHDW]+(?:\s*[0-9smhdwSMHDW]+)*)",
    re.I
)
_SHOW_GROUPS = re.compile(r"\b(?:show|list|display)\b.*\b(agent\s+)?groups?\b", re.I)
_ADD_AGENTS_TO_GROUP = re.compile(
    r"\b(?:add|assign|move|put)\b.*\bagents?\b\s*(?P<ids>[\d,\sand]+)\b.*"
    r"\b(?:to|into|in)\b.*\b(?:group|agent\s+group)\b\s*(?P<group>[A-Za-z0-9._-]+)\b",
    re.I
)

_CREATE_DASHBOARD_PIE = re.compile(
    r"\b(?:create|make|build)\b.*\b(?:custom\s+)?dashboard\b.*\bpie\b(?:\s+chart)?"
    r"(?:\s+using\s+(?P<index>[A-Za-z0-9*._-]+)\s+index\s+pattern)?"
    r"(?:\s+for\s+showing)?"
    r".*?\btop\s+(?P<n>\d{1,3})\b\s+(?P<phrase>.+?)(?:\s+triggered\b|$)",
    re.I
)

def help_message() -> str:
    return (
        "Here are example commands you can use (you can phrase them naturally too):\n\n"
        "Agent actions:\n"
        "- restart agent `agent-id`\n"
        "- remove agent `agent-id`\n"
        "- remove all disconnected agents\n"
        "- remove disconnected agents older than `time-period`   (12h, 30m, 2w, 7d12h)\n"
        "- show agent groups\n"
        "- add agents `agent-id1`, `agent-id2` to group `agent-group`\n\n"
        "Dashboards:\n"
        "- create dashboard with a pie chart top 10 rule id triggered\n"
        "- create custom dashboard    (wizard: index pattern → viz type → requirement)\n\n"
        "Tip: After I show a plan, type CONFIRM to execute, or NO to cancel."
    )



async def _detect_wazuh_intent_llm(user_prompt: str) -> Optional[Dict[str, Any]]:
    llm = _build_llm()
    prompt = f"""You are a Wazuh intention detection AI.
Analyze the user's input and determine if they are requesting a specific action.
Valid actions:
- "restart_agent" (needs agent_id string)
- "remove_agent" (needs agent_id string)
- "remove_all_disconnected"
- "remove_disconnected_older_than" (needs timeframe_str string like '30m', '12h')
- "assign_group" (extract agent_ids array if present, extract group_id string if present)
- "remove_group" (extract agent_ids array if present, extract group_id string if present)
- "show_groups"
- "create_custom_dashboard" (triggers when the user asks to create a dashboard. If specified, extract 'index_pattern_title' string, inferring 'wazuh-alerts-*' for "vulnerability alerts", 'wazuh-states-vulnerabilities-*' for "vulnerabilities only", etc. Also extract a 'topic' string if they describe what it should cover. If neither is specified, just return {{"action": "create_custom_dashboard"}}).
- "reset_dashboard_wizard"
- "create_dashboard_pie" (needs 'index_pattern_title' string, default 'wazuh-alerts-*' unless user specified or inferred like above. Needs 'field' string like 'agent.name', 'top_n' integer default 5)
- "generate_full_dashboard" (triggers when user asks for a full dashboard about a specific topic. Needs 'topic' string describing the requirement and 'index_pattern_title' inferred as above, default 'wazuh-alerts-*')
- "generate_email_report" (triggers when user asks to send or email a pdf report. Needs 'topic' string describing the requirement and 'index_pattern_title' inferred as above, default 'wazuh-alerts-*')
- "mcp_query" (if the user is asking a question about logs, alerts, vulnerabilities, or asking to search/analyze data using OpenSearch)
- "unknown" (if they are just chatting, asking a general non-security question, or lack required parameters for a specific action)

If the user mentions an arbitrary example ID instead of a real ID, try your best to extract it (e.g. if they say "three digits").
If the intent is clear but exact parameters are confusing, output the best guess.

Return EXACTLY a JSON object with "action" and any required parameters.
Example: {{"action": "generate_full_dashboard", "topic": "brute force attacks", "index_pattern_title": "wazuh-alerts-*"}}

User Input: {user_prompt}
JSON:"""
    try:
        msg = await asyncio.to_thread(llm.invoke, prompt)
        raw = getattr(msg, "content", "") or ""
        return json.loads(_last_json_block(raw))
    except Exception:
        return None

def _viz_choice_list() -> str:
    return "1) pie  2) bar  3) line  4) metric  5) table\n(Or type 'auto' to let me generate a full dashboard automatically)"

def _normalize_viz_choice(x: str) -> Optional[str]:
    s = (x or "").strip().lower()
    if s in ("1", "pie"):
        return "pie"
    if s in ("2", "bar", "barchart", "bar chart"):
        return "bar"
    if s in ("3", "line", "linechart", "line chart", "timeseries", "time series"):
        return "line"
    if s in ("4", "metric"):
        return "metric"
    if s in ("5", "table", "data table", "datatable"):
        return "table"
    if s in ("auto", "full", "yes", "y", "automatically"):
        return "auto"
    return None

def _slugify(s: str) -> str:
    s = (s or "").lower().strip()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s[:60] or "obj"

@app.get("/health", summary="Health check for Gateway, LLM, MCP, Dashboards, Indexer")
async def health():
    status = {"gateway": "ok", "llm": "unknown", "mcp": "unknown", "osd": "unknown", "indexer": "unknown"}
    details: Dict[str, Any] = {
        "provider": LLM_PROVIDER,
        "model": (GEMINI_MODEL if LLM_PROVIDER == "gemini" else OPENAI_MODEL if LLM_PROVIDER == "openai" else BEDROCK_MODEL_ID),
        "staging_configured": bool(_stg_api()),
        "prod_configured": bool(_prod_api()),
        "mcp_configured": bool(MCP_SSE_URL),
        "indexer_configured": bool(_indexer_configured()),
        "indexer_url": WAZUH_INDEXER_URL,
        "indexer_verify": WAZUH_INDEXER_VERIFY_TLS,
        "indexer_ca_file": WAZUH_INDEXER_CA_FILE,
        "osd_url": OPENSEARCH_DASHBOARD_URL,
        "osd_basepath": OPENSEARCH_DASHBOARD_BASEPATH,
        "osd_space": OPENSEARCH_DASHBOARD_SPACE,
        "osd_verify": OPENSEARCH_DASHBOARD_VERIFY_TLS,
        "osd_ca_file": OPENSEARCH_DASHBOARD_CA_FILE,
        "verbose": VERBOSE,
        "debug_action_output": DEBUG_ACTION_OUTPUT,
    }
    try:
        llm = _build_llm()
        _ = (await asyncio.to_thread(llm.invoke, "health")).content
        status["llm"] = "ok"
    except Exception as e:
        status["llm"] = "error"
        details["llm_error"] = str(e)
    try:
        if not MCP_SSE_URL:
            status["mcp"] = "not_configured"
        else:
            tools = await asyncio.wait_for(_load_mcp_tools(), timeout=8)
            status["mcp"] = "ok"
            details["mcp_tools_count"] = len(tools)
    except asyncio.TimeoutError:
        status["mcp"] = "timeout"
    except Exception as e:
        status["mcp"] = "error"
        details["mcp_error"] = str(e)
    try:
        if not (OPENSEARCH_DASHBOARD_URL and OPENSEARCH_DASHBOARD_USER and OPENSEARCH_DASHBOARD_PASS):
            status["osd"] = "not_configured"
        else:
            sc, txt = await osd_request("GET", "/api/status")
            status["osd"] = "ok" if sc == 200 else f"error_http_{sc}"
            if sc != 200:
                details["osd_error"] = txt[:500]
    except Exception as e:
        status["osd"] = "error"
        details["osd_error"] = str(e)
    try:
        if not _indexer_configured():
            status["indexer"] = "not_configured"
        else:
            sc, txt = await indexer_request("GET", "/")
            status["indexer"] = "ok" if sc == 200 else f"error_http_{sc}"
            if sc != 200:
                details["indexer_error"] = txt[:500]
    except Exception as e:
        status["indexer"] = "error"
        details["indexer_error"] = str(e)
    summary = "ok" if status["llm"] == "ok" else "degraded"
    return {"summary": summary, "status": status, "details": details}

@app.get("/download/report/{report_id}", summary="Download a generated PDF report")
async def download_report(report_id: str):
    # Ensure the report string contains expected characters to avoid path traversal
    if not re.match(r"^[a-zA-Z0-9_-]+\.pdf$", report_id):
        raise HTTPException(status_code=400, detail="Invalid report format.")
    
    file_path = f"/tmp/{report_id}"
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Report not found or expired.")
        
    return FileResponse(
        path=file_path, 
        media_type="application/pdf", 
        filename=report_id,
        headers={"Content-Disposition": f"attachment; filename={report_id}"}
    )

@app.post("/analyze", summary="Main analysis endpoint")
async def analyze(
    request: Request,
    body: PredictBody,
    x_api_key: Optional[str] = Header(default=None),
    x_session_id: Optional[str] = Header(default=None),
):
    if GATEWAY_API_KEY and x_api_key != GATEWAY_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    _cleanup_pending()
    _cleanup_wizards()

    sid = _session_id(request, x_session_id)
    user_prompt = _extract_prompt(body).strip()

    if not user_prompt:
        return {"output": {"message": "No input provided."}}

    if _GREETING.match(user_prompt):
        return {"output": {"message": (
            "Hello! I am your Wazuh AI Analyst. How can I assist you with your security analysis today?"
        )}}

    if _HELP.search(user_prompt):
        return {"output": {"message": help_message()}}

    discover_link = await try_build_discover_filter_link(user_prompt)
    if discover_link:
        return {"output": {"message": discover_link}}

    inventory_answer = await answer_inventory_query(user_prompt)
    if inventory_answer:
        return {"output": {"message": inventory_answer}}

    if _WIZARD_RESET.match(user_prompt):
        async with WIZARDS_LOCK:
            WIZARDS.pop(sid, None)
        return {"output": {"message": "Dashboard wizard reset."}}

    if _DENY.match(user_prompt):
        async with PENDING_LOCK:
            PENDING.pop(sid, None)
        async with WIZARDS_LOCK:
            WIZARDS.pop(sid, None)
        return {"output": {"message": "Cancelled. No changes made."}}

    if _CONFIRM.match(user_prompt):
        async with PENDING_LOCK:
            pending = PENDING.get(sid)

        if not pending:
            return {"output": {"message": "No pending action."}}

        if pending.kind in ("create_dashboard_any", "create_dashboard_pie"):
            plan = pending.payload
            try:
                ok_vis, vis_resp = await osd_create_visualization(plan["vis_id"], plan["vis_payload"])
                if not ok_vis:
                    async with PENDING_LOCK:
                        PENDING.pop(sid, None)
                    return {"output": {"message": f"Failed to create visualization.\n{vis_resp}"}}

                ok_dash, dash_resp = await osd_create_dashboard(plan["dash_id"], plan["dash_payload"])
                async with PENDING_LOCK:
                    PENDING.pop(sid, None)

                if not ok_dash:
                    return {"output": {"message": f"Visualization created ({plan['vis_id']}) but failed to create dashboard.\n{dash_resp}"}}

                return {"output": {"message": (
                    "Dashboard created successfully.\n"
                    f"- dashboard_id: {plan['dash_id']}\n"
                    f"- visualization_id: {plan['vis_id']}\n"
                    f"- index_pattern: {plan.get('index_pattern_title','')}\n"
                    f"- viz_type: {plan.get('viz_type','')}\n"
                )}}
            except Exception as e:
                async with PENDING_LOCK:
                    PENDING.pop(sid, None)
                return {"output": {"message": f"Dashboard creation failed: {e}"}}

        if pending.kind == "generate_full_dashboard":
            payload = pending.payload
            try:
                created_vis = []
                # 1. Create all visualizations
                for v in payload["visualizations"]:
                    ok_vis, vis_resp = await osd_create_visualization(v["vis_id"], v["vis_payload"])
                    if ok_vis:
                        created_vis.append(v)
                    else:
                        pass
                
                if not created_vis:
                    async with PENDING_LOCK:
                        PENDING.pop(sid, None)
                    return {"output": {"message": "Failed to create any visualizations for the dashboard."}}
                
                # 2. Rebuild the master dashboard payload with only the successful text ones
                valid_vis_ids = [v["vis_id"] for v in created_vis]
                final_dash_payload = build_multi_dashboard_payload(payload["dash_title"], valid_vis_ids)

                ok_dash, dash_resp = await osd_create_dashboard(payload["dash_id"], final_dash_payload)
                async with PENDING_LOCK:
                    PENDING.pop(sid, None)

                if not ok_dash:
                    return {"output": {"message": f"Failed to create the master dashboard.\n{dash_resp}"}}

                msg = f"Multi-visualization Dashboard created successfully!\n- Dashboard ID: `{payload['dash_id']}`\n\nGenerated Panels:\n"
                for v in created_vis:
                    msg += f"- `{v['vis_id']}` (Type: {v['viz_type']})\n"
                
                return {"output": {"message": msg}}
            except Exception as e:
                async with PENDING_LOCK:
                    PENDING.pop(sid, None)
                return {"output": {"message": f"Full Dashboard creation failed: {e}\n{traceback.format_exc()}"}}

        if pending.kind == "send_pdf_report":
            topic = pending.payload["topic"]
            recipient = pending.payload["email"]
            pdf_path = pending.payload["pdf_path"]
            title = pending.payload["title"]
            summary = pending.payload["summary"]
            
            try:
                # We skip re-generating it since it's already generated for the preview.
                sent = await send_report_email(pdf_path, recipient, title, summary)
                async with PENDING_LOCK:
                    PENDING.pop(sid, None)
                    
                if sent:
                    # Update email history
                    if recipient in app.state.recent_emails:
                        app.state.recent_emails.remove(recipient)
                    app.state.recent_emails.insert(0, recipient)
                    app.state.recent_emails = app.state.recent_emails[:5]
                    
                    return {"output": {"message": f"Success! PDF report for '{topic}' has been emailed to {recipient}."}}
                else:
                    return {"output": {"message": f"Failed to send email to {recipient}. Please verify standard SMTP environment variables in the Gateway."}}
            except Exception as e:
                async with PENDING_LOCK:
                    PENDING.pop(sid, None)
                return {"output": {"message": f"Failed to send PDF report email: {e}"}}

        prod = _prod_api()
        if not prod:
            async with PENDING_LOCK:
                PENDING.pop(sid, None)
            return {"output": {"message": "Action failed: PROD Wazuh API not configured."}}

        if pending.kind == "restart_agent":
            agent_id = pending.payload["agent_id"]
            agents = await _get_agents(prod)
            a = _find_agent(agents, agent_id)
            if not a:
                async with PENDING_LOCK:
                    PENDING.pop(sid, None)
                return {"output": {"message": f"Agent with id {agent_id} is not present."}}

            st = _agent_status(a)
            if st == "disconnected":
                async with PENDING_LOCK:
                    PENDING.pop(sid, None)
                return {"output": {"message": f"Agent {agent_id} is disconnected. Restart not possible."}}
            if st != "active":
                async with PENDING_LOCK:
                    PENDING.pop(sid, None)
                return {"output": {"message": f"Agent {agent_id} status is '{st}'. Restart not allowed."}}

            resp = await wazuh_restart_agent(prod, agent_id)
            async with PENDING_LOCK:
                PENDING.pop(sid, None)

            msg = format_restart_agent_result(agent_id, resp)
            if VERBOSE and DEBUG_ACTION_OUTPUT:
                msg += "\n\n(debug) api_response=" + json.dumps(resp, ensure_ascii=False)
            return {"output": {"message": msg}}

        if pending.kind == "remove_agent":
            agent_id = pending.payload["agent_id"]
            older_than = str(pending.payload.get("older_than", "0s"))
            status = str(pending.payload.get("status", "all"))

            agents = await _get_agents(prod)
            if not _find_agent(agents, agent_id):
                async with PENDING_LOCK:
                    PENDING.pop(sid, None)
                return {"output": {"message": f"Agent with id {agent_id} is not present."}}

            resp = await wazuh_delete_agents_bulk(prod, agents_list=agent_id, status=status, older_than=older_than)
            async with PENDING_LOCK:
                PENDING.pop(sid, None)

            msg = format_delete_agents_result(f"Remove agent {agent_id}", resp)
            if VERBOSE and DEBUG_ACTION_OUTPUT:
                msg += "\n\n(debug) api_response=" + json.dumps(resp, ensure_ascii=False)
            return {"output": {"message": msg}}

        if pending.kind == "remove_all_disconnected":
            older_than = str(pending.payload.get("older_than", "0s"))
            include_never = bool(pending.payload.get("include_never_connected", False))
            status = "never_connected,disconnected" if include_never else "disconnected"

            resp = await wazuh_delete_agents_bulk(prod, agents_list="all", status=status, older_than=older_than)
            async with PENDING_LOCK:
                PENDING.pop(sid, None)

            msg = format_delete_agents_result("Remove all disconnected agents", resp)
            if VERBOSE and DEBUG_ACTION_OUTPUT:
                msg += "\n\n(debug) api_response=" + json.dumps(resp, ensure_ascii=False)
            return {"output": {"message": msg}}

        if pending.kind == "remove_disconnected_older_than":
            agent_ids = pending.payload.get("agent_ids") or []
            tf_str = pending.payload.get("timeframe_str", "")
            if not agent_ids:
                async with PENDING_LOCK:
                    PENDING.pop(sid, None)
                return {"output": {"message": "No candidates to remove. No changes made."}}

            agents_list = ",".join(agent_ids)
            resp = await wazuh_delete_agents_bulk(prod, agents_list=agents_list, status="disconnected", older_than="0s")
            async with PENDING_LOCK:
                PENDING.pop(sid, None)

            msg = format_delete_agents_result(f"Remove disconnected agents older than {tf_str}", resp)
            if VERBOSE and DEBUG_ACTION_OUTPUT:
                msg += "\n\n(debug) api_response=" + json.dumps(resp, ensure_ascii=False)
            return {"output": {"message": msg}}

        if pending.kind == "assign_group":
            group_id = pending.payload["group_id"]
            agent_ids = pending.payload["agent_ids"]

            agents = await _get_agents(prod)
            missing = [aid for aid in agent_ids if not _find_agent(agents, aid)]
            if missing:
                async with PENDING_LOCK:
                    PENDING.pop(sid, None)
                return {"output": {"message": f"These agent id(s) are not present: {', '.join(missing)}"}}

            results = []
            for aid in agent_ids:
                r = await wazuh_assign_agent_to_group(prod, aid, group_id)
                results.append((aid, r))

            async with PENDING_LOCK:
                PENDING.pop(sid, None)

            msg = format_assign_group_result(group_id, results)
            if VERBOSE and DEBUG_ACTION_OUTPUT:
                msg += "\n\n(debug) results=" + json.dumps({aid: resp for aid, resp in results}, ensure_ascii=False)
            return {"output": {"message": msg}}

        if pending.kind == "remove_group":
            group_id = pending.payload["group_id"]
            agent_ids = pending.payload["agent_ids"]

            agents = await _get_agents(prod)
            missing = [aid for aid in agent_ids if not _find_agent(agents, aid)]
            if missing:
                async with PENDING_LOCK:
                    PENDING.pop(sid, None)
                return {"output": {"message": f"These agent id(s) are not present: {', '.join(missing)}"}}

            results = []
            for aid in agent_ids:
                r = await wazuh_remove_agent_from_group(prod, aid, group_id)
                results.append((aid, r))

            async with PENDING_LOCK:
                PENDING.pop(sid, None)

            msg = format_remove_group_result(group_id, results)
            if VERBOSE and DEBUG_ACTION_OUTPUT:
                msg += "\n\n(debug) results=" + json.dumps({aid: resp for aid, resp in results}, ensure_ascii=False)
            return {"output": {"message": msg}}

        async with PENDING_LOCK:
            PENDING.pop(sid, None)
        return {"output": {"message": "Failed: Unknown pending action."}}

    async with WIZARDS_LOCK:
        wiz = WIZARDS.get(sid)

    if wiz:
        try:
            step = wiz.step

            if step == "restart_choose_agent":
                choice = user_prompt.strip()
                prod = _prod_api()
                agents = await _get_agents(prod)
                agent_obj = _resolve_agent_identifier(choice, agents)
                
                if not agent_obj:
                    return {"output": {"message": f"Could not find an agent matching '{choice}'. Please provide an exact ID (e.g., 005) or exact Agent Name."}}
                
                aid = str(agent_obj["id"]).zfill(3)
                
                st = _agent_status(agent_obj)
                if st == "disconnected":
                    async with WIZARDS_LOCK:
                        WIZARDS.pop(sid, None)
                    return {"output": {"message": f"Agent {aid} is disconnected. Restart not possible."}}
                if st != "active":
                    async with WIZARDS_LOCK:
                        WIZARDS.pop(sid, None)
                    return {"output": {"message": f"Agent {aid} status is '{st}'. Restart not allowed."}}

                async with WIZARDS_LOCK:
                    WIZARDS.pop(sid, None)
                async with PENDING_LOCK:
                    PENDING[sid] = PendingAction("restart_agent", {"agent_id": aid}, time.time())
                
                confirm_msg = (
                    f"Restarting a Wazuh agent is an operational action and needs explicit confirmation.\n\n"
                    f"Do you want to proceed with restarting agent {aid} ({agent_obj.get('name', 'Unknown')})?\n"
                    f"Type **CONFIRM** to proceed or **NO** to cancel."
                )
                return {"output": {"message": confirm_msg}}

            if step == "assign_group_choose_agent":
                choice = user_prompt.strip()
                prod = _prod_api()
                agents = await _get_agents(prod)
                agent_obj = _resolve_agent_identifier(choice, agents)
                
                if not agent_obj:
                    return {"output": {"message": f"Could not find an agent matching '{choice}'. Please provide an exact ID (e.g., 005) or exact Agent Name."}}
                
                aid = str(agent_obj["id"]).zfill(3)
                group_id = wiz.data.get("group_id")
                
                if group_id:
                    async with WIZARDS_LOCK:
                        WIZARDS.pop(sid, None)
                    async with PENDING_LOCK:
                        PENDING[sid] = PendingAction("assign_group", {"group_id": group_id, "agent_ids": [aid]}, time.time())
                    return {"output": {"message": f"Do I need to assign agent {aid} ({agent_obj.get('name')}) to group '{group_id}'? If yes type CONFIRM, or NO to cancel."}}
                    
                current_groups = agent_obj.get("group", [])
                
                gresp = await wazuh_list_groups(prod)
                if not isinstance(gresp, dict) or gresp.get("error") != 0:
                    async with WIZARDS_LOCK:
                        WIZARDS.pop(sid, None)
                    return {"output": {"message": "Failed to list available groups from Wazuh API."}}
                
                items = (gresp.get("data") or {}).get("affected_items") or []
                all_groups = [str(it["name"]) for it in items if isinstance(it, dict) and it.get("name")]
                
                available_groups = [g for g in all_groups if g not in current_groups]
                
                if not available_groups:
                    async with WIZARDS_LOCK:
                        WIZARDS.pop(sid, None)
                    return {"output": {"message": f"Agent {aid} is already assigned to all available groups ({', '.join(current_groups)})."}}
                elif len(available_groups) == 1:
                    group_id = available_groups[0]
                    async with WIZARDS_LOCK:
                        WIZARDS.pop(sid, None)
                    async with PENDING_LOCK:
                        PENDING[sid] = PendingAction("assign_group", {"group_id": group_id, "agent_ids": [aid]}, time.time())
                    return {"output": {"message": f"Agent {aid} is not in group '{group_id}'.\nDo I need to assign agent {aid} to group '{group_id}'? If yes type CONFIRM, or NO to cancel."}}
                else:
                    async with WIZARDS_LOCK:
                        WIZARDS[sid] = WizardState("assign_group_choose_group", time.time(), {"agent_ids": [aid], "available_groups": available_groups})
                    return {"output": {"message": f"Agent {aid} ({agent_obj.get('name')}) can be added to the following groups: {', '.join(available_groups)}.\nWhich group should I assign it to?"}}

            if step == "assign_group_choose_group":
                choice = user_prompt.strip()
                agent_ids = wiz.data.get("agent_ids", [])
                available_groups = wiz.data.get("available_groups", [])
                
                picked = None
                for g in available_groups:
                    if choice.lower() == g.lower():
                        picked = g
                        break
                
                if not picked:
                    return {"output": {"message": f"Invalid group. Please choose one of: {', '.join(available_groups)}" }}
                    
                async with WIZARDS_LOCK:
                    WIZARDS.pop(sid, None)
                async with PENDING_LOCK:
                    PENDING[sid] = PendingAction("assign_group", {"group_id": picked, "agent_ids": agent_ids}, time.time())
                
                return {"output": {"message": f"Do I need to assign agent(s) {', '.join(agent_ids)} to group '{picked}'? If yes type CONFIRM, or NO to cancel."}}

            if step == "remove_group_choose_agent":
                choice = user_prompt.strip()
                prod = _prod_api()
                agents = await _get_agents(prod)
                agent_obj = _resolve_agent_identifier(choice, agents)
                
                if not agent_obj:
                    return {"output": {"message": f"Could not find an agent matching '{choice}'. Please provide an exact ID (e.g., 005) or exact Agent Name."}}
                
                aid = str(agent_obj["id"]).zfill(3)
                group_id = wiz.data.get("group_id")
                
                if group_id:
                    async with WIZARDS_LOCK:
                        WIZARDS.pop(sid, None)
                    async with PENDING_LOCK:
                        PENDING[sid] = PendingAction("remove_group", {"group_id": group_id, "agent_ids": [aid]}, time.time())
                    return {"output": {"message": f"Do I need to remove agent {aid} ({agent_obj.get('name')}) from group '{group_id}'? If yes type CONFIRM, or NO to cancel."}}
                    
                groups = agent_obj.get("group", [])
                if not groups:
                    async with WIZARDS_LOCK:
                        WIZARDS.pop(sid, None)
                    return {"output": {"message": f"Agent {aid} ({agent_obj.get('name')}) has no group assignments."}}
                elif len(groups) == 1:
                    group_id = groups[0]
                    async with WIZARDS_LOCK:
                        WIZARDS.pop(sid, None)
                    async with PENDING_LOCK:
                        PENDING[sid] = PendingAction("remove_group", {"group_id": group_id, "agent_ids": [aid]}, time.time())
                    return {"output": {"message": f"Agent {aid} is only assigned to group '{group_id}'.\nDo I need to remove agent {aid} from group '{group_id}'? If yes type CONFIRM, or NO to cancel."}}
                else:
                    async with WIZARDS_LOCK:
                        WIZARDS[sid] = WizardState("remove_group_choose_group", time.time(), {"agent_ids": [aid], "available_groups": groups})
                    return {"output": {"message": f"Agent {aid} ({agent_obj.get('name')}) is assigned to multiple groups: {', '.join(groups)}.\nWhich group should I remove it from?"}}

            if step == "remove_group_choose_group":
                choice = user_prompt.strip()
                agent_ids = wiz.data.get("agent_ids", [])
                available_groups = wiz.data.get("available_groups", [])
                
                picked = None
                for g in available_groups:
                    if choice.lower() == g.lower():
                        picked = g
                        break
                
                if not picked:
                    return {"output": {"message": f"Invalid group. Please choose one of: {', '.join(available_groups)}" }}
                    
                async with WIZARDS_LOCK:
                    WIZARDS.pop(sid, None)
                async with PENDING_LOCK:
                    PENDING[sid] = PendingAction("remove_group", {"group_id": picked, "agent_ids": agent_ids}, time.time())
                
                return {"output": {"message": f"Do I need to remove agent(s) {', '.join(agent_ids)} from group '{picked}'? If yes type CONFIRM, or NO to cancel."}}

            if step == "describe_full_dashboard":
                user_req = user_prompt.strip()
                options: List[str] = wiz.data.get("index_options") or []
                
                # Fast mini-LLM call to extract topic and index preference from the user's response
                llm = _build_llm()
                prompt = (
                    f"Given the user's request for a dashboard: '{user_req}'\n"
                    f"And these available index patterns: {options}\n"
                    "Extract the 'topic' they want (e.g. 'sshd brute force', 'vulnerabilities') and the 'index_pattern_title' they chose.\n"
                    "If they just said a number like '1' and a topic, resolve the number to the corresponding index pattern from the list (1-indexed).\n"
                    "If they explicitly mentioned an index pattern name, use that.\n"
                    "If they didn't specify an index, infer it if possible (e.g. 'wazuh-alerts-*', 'wazuh-states-vulnerabilities-*'), otherwise default to 'wazuh-alerts-*'.\n"
                    "Return EXACTLY a JSON object with 'topic' and 'index_pattern_title'.\n"
                    "JSON:"
                )
                try:
                    msg = await asyncio.to_thread(llm.invoke, prompt)
                    raw = getattr(msg, "content", "") or ""
                    parsed = json.loads(_last_json_block(raw))
                    topic = parsed.get("topic", user_req).strip()
                    index_title = parsed.get("index_pattern_title", ALERTS_INDEX).strip()
                except Exception:
                    topic = user_req
                    index_title = ALERTS_INDEX

                # Build the full dashboard
                dash_title = f"{topic.title()} Dashboard"
                dash_id = f"dash-{_slugify(topic)}-{uuid.uuid4().hex[:8]}"

                idx_id = await osd_find_index_pattern_id_by_title(index_title)
                time_field = await guess_time_field_for_index(index_title)
                if not idx_id:
                    if AUTO_CREATE_INDEX_PATTERN:
                        ok, created = await osd_create_index_pattern(index_title, time_field)
                        if ok and created:
                            idx_id = created
                        else:
                            return {"output": {"message": f"Index pattern '{index_title}' not found and auto-create failed: {created}"}}
                    else:
                        return {"output": {"message": f"Index pattern '{index_title}' not found in Dashboards. Create it in UI first."}}

                try:
                    raw_plans = await llm_generate_full_dashboard_plan(index_title, topic)
                except Exception as e:
                    return {"output": {"message": f"Failed to generate dashboard plans: {e}"}}

                valid_visualizations = []
                for plan in raw_plans:
                    ok_fields, vmsg = await validate_plan_fields(index_title, plan)
                    if not ok_fields:
                        continue

                    v_type = plan.get("viz_type", "pie")
                    v_title = str(plan.get("viz_title", f"{v_type.title()} - {index_title}"))
                    v_id = f"viz-{_slugify(v_title)}-{uuid.uuid4().hex[:8]}"

                    try:
                        vis_payload = build_vis_payload(
                            vis_type=v_type,
                            title=f"{dash_title} - {v_title}",
                            index_pattern_id=idx_id,
                            time_field=time_field or "@timestamp",
                            query=plan.get("query", ""),
                            time_from=plan.get("time_from", "now-7d"),
                            time_to=plan.get("time_to", "now"),
                            field=plan.get("field"),
                            table_fields=plan.get("table_fields"),
                            top_n=plan.get("top_n", 5),
                            split_field=plan.get("split_field"),
                            split_top_n=plan.get("split_top_n", 5),
                            interval=plan.get("interval", "auto"),
                        )
                        valid_visualizations.append({
                            "vis_id": v_id,
                            "viz_type": v_type,
                            "vis_title": v_title,
                            "vis_payload": vis_payload,
                            "plan": plan
                        })
                    except Exception:
                        pass

                if not valid_visualizations:
                    return {"output": {"message": "Failed to generate any valid visualizations for this custom dashboard (likely field validation errors). Please try describing the requirement differently."}}

                async with WIZARDS_LOCK:
                    WIZARDS.pop(sid, None)
                async with PENDING_LOCK:
                    PENDING[sid] = PendingAction(
                        "generate_full_dashboard",
                        {
                            "dash_id": dash_id,
                            "dash_title": dash_title,
                            "visualizations": valid_visualizations,
                        },
                        time.time()
                    )

                msg = f"I generated a comprehensive auto-dashboard design for '{topic}' using index '{index_title}'.\n\nIt will contain {len(valid_visualizations)} visualizations:\n"
                for v in valid_visualizations:
                    msg += f"- {v['vis_title']} (Type: {v['viz_type']})\n"
                msg += "\nDo I need to proceed and create this dashboard? Type CONFIRM/yes to proceed, or NO to cancel."
                return {"output": {"message": msg}}

                dash_title = str(plan.get("dash_title") or f"Custom Dashboard - {index_title}")
                vis_title = str(plan.get("vis_title") or f"{viz_type.title()} - {index_title}")

                top_n = int(plan.get("top_n") or 5)
                field = plan.get("field")
                split_field = plan.get("split_field")
                split_top_n = int(plan.get("split_top_n") or top_n)
                query = str(plan.get("query") or "")
                time_from = str(plan.get("time_from") or "now-24h")
                time_to = str(plan.get("time_to") or "now")
                interval = str(plan.get("interval") or "auto")

                vis_id = f"viz-{_slugify(vis_title)}-{uuid.uuid4().hex[:8]}"
                dash_id = f"dash-{_slugify(dash_title)}-{uuid.uuid4().hex[:8]}"

                try:
                    vis_payload = build_vis_payload(
                        vis_type=viz_type,
                        title=vis_title,
                        index_pattern_id=idx_id,
                        time_field=time_field or "@timestamp",
                        query=query,
                        time_from=time_from,
                        time_to=time_to,
                        field=field,
                        top_n=top_n,
                        split_field=split_field if viz_type == "line" else None,
                        split_top_n=split_top_n,
                        interval=interval,
                    )
                    dash_payload = build_dashboard_payload(dash_title, vis_id)
                except Exception as e:
                    return {"output": {"message": f"Failed to build payloads: {e}"}}

                async with PENDING_LOCK:
                    PENDING[sid] = PendingAction(
                        "create_dashboard_any",
                        {
                            "index_pattern_title": index_title,
                            "index_pattern_id": idx_id,
                            "time_field": time_field,
                            "viz_type": viz_type,
                            "vis_id": vis_id,
                            "dash_id": dash_id,
                            "vis_payload": vis_payload,
                            "dash_payload": dash_payload,
                            "plan": plan,
                            "validation": vmsg,
                        },
                        time.time(),
                    )
                async with WIZARDS_LOCK:
                    WIZARDS.pop(sid, None)

                plan_text = json.dumps(plan, ensure_ascii=False, indent=2)
                return {"output": {"message": (
                    f"Plan ready.\n\n"
                    f"index-pattern: {index_title}\n"
                    f"viz_type: {viz_type}\n"
                    f"validation: {vmsg}\n\n"
                    f"Plan JSON:\n{plan_text}\n\n"
                    "Type CONFIRM/yes to create it, or NO to cancel."
                )}}

            if step == "fix_field":
                new_field = user_prompt.strip()
                plan = wiz.data.get("plan") or {}
                index_title = wiz.data.get("index_pattern_title") or ALERTS_INDEX
                viz_type = wiz.data.get("viz_type") or "pie"

                if viz_type == "line":
                    plan["split_field"] = new_field
                else:
                    plan["field"] = new_field

                ok_fields, vmsg = await validate_plan_fields(index_title, plan)
                if not ok_fields:
                    async with WIZARDS_LOCK:
                        WIZARDS[sid] = WizardState(
                            step="fix_field",
                            created_at=time.time(),
                            data={**wiz.data, "plan": plan, "validation_msg": vmsg},
                        )
                    return {"output": {"message": f"Still failing: {vmsg}\nReply with another field name."}}

                idx_id = await osd_find_index_pattern_id_by_title(index_title)
                time_field = await guess_time_field_for_index(index_title)
                if not idx_id:
                    if AUTO_CREATE_INDEX_PATTERN:
                        ok, created = await osd_create_index_pattern(index_title, time_field)
                        if ok and created:
                            idx_id = created
                        else:
                            return {"output": {"message": f"Index pattern '{index_title}' not found and auto-create failed: {created}"}}
                    else:
                        return {"output": {"message": f"Index pattern '{index_title}' not found in Dashboards. Create it in UI first."}}

                dash_title = str(plan.get("dash_title") or f"Custom Dashboard - {index_title}")
                vis_title = str(plan.get("vis_title") or f"{viz_type.title()} - {index_title}")
                top_n = int(plan.get("top_n") or 5)
                field = plan.get("field")
                split_field = plan.get("split_field")
                split_top_n = int(plan.get("split_top_n") or top_n)
                query = str(plan.get("query") or "")
                time_from = str(plan.get("time_from") or "now-24h")
                time_to = str(plan.get("time_to") or "now")
                interval = str(plan.get("interval") or "auto")

                vis_id = f"viz-{_slugify(vis_title)}-{uuid.uuid4().hex[:8]}"
                dash_id = f"dash-{_slugify(dash_title)}-{uuid.uuid4().hex[:8]}"

                try:
                    vis_payload = build_vis_payload(
                        vis_type=viz_type,
                        title=vis_title,
                        index_pattern_id=idx_id,
                        time_field=time_field or "@timestamp",
                        query=query,
                        time_from=time_from,
                        time_to=time_to,
                        field=field,
                        top_n=top_n,
                        split_field=split_field if viz_type == "line" else None,
                        split_top_n=split_top_n,
                        interval=interval,
                    )
                    dash_payload = build_dashboard_payload(dash_title, vis_id)
                except Exception as e:
                    return {"output": {"message": f"Failed to build payloads: {e}"}}

                async with PENDING_LOCK:
                    PENDING[sid] = PendingAction(
                        "create_dashboard_any",
                        {
                            "index_pattern_title": index_title,
                            "index_pattern_id": idx_id,
                            "time_field": time_field,
                            "viz_type": viz_type,
                            "vis_id": vis_id,
                            "dash_id": dash_id,
                            "vis_payload": vis_payload,
                            "dash_payload": dash_payload,
                            "plan": plan,
                            "validation": vmsg,
                        },
                        time.time(),
                    )

                async with WIZARDS_LOCK:
                    WIZARDS.pop(sid, None)

                plan_text = json.dumps(plan, ensure_ascii=False, indent=2)
                return {"output": {"message": (
                    f"Plan updated.\n\n"
                    f"index-pattern: {index_title}\n"
                    f"viz_type: {viz_type}\n"
                    f"validation: {vmsg}\n\n"
                    f"Plan JSON:\n{plan_text}\n\n"
                    "Type CONFIRM/yes to create it, or NO to cancel."
                )}}

            if step == "ask_email_for_report":
                email_input = user_prompt.strip()
                
                # Check if user selected from history list (e.g. "1")
                if email_input.isdigit() and 1 <= int(email_input) <= len(app.state.recent_emails):
                    email = app.state.recent_emails[int(email_input) - 1]
                else:
                    email = email_input
                    
                topic = wiz.data.get("topic")
                pdf_path = wiz.data.get("pdf_path")
                title = wiz.data.get("title")
                summary = wiz.data.get("summary")
                
                async with WIZARDS_LOCK:
                    WIZARDS.pop(sid, None)
                async with PENDING_LOCK:
                    PENDING[sid] = PendingAction(
                        "send_pdf_report",
                        {
                            "topic": topic,
                            "email": email,
                            "pdf_path": pdf_path,
                            "title": title,
                            "summary": summary
                        },
                        time.time()
                    )
                return {"output": {"message": f"Got it. Do you want me to send the generated PDF report for '{topic}' to {email}? Type CONFIRM/yes to proceed or NO to cancel."}}

            async with WIZARDS_LOCK:
                WIZARDS.pop(sid, None)
            return {"output": {"message": "Wizard state corrupted; reset. Try: create custom dashboard"}}

        except Exception as e:
            tb = traceback.format_exc()
            async with WIZARDS_LOCK:
                WIZARDS.pop(sid, None)
            return {"output": {"message": f"Wizard error: {e}\n\nTRACEBACK:\n{tb}"}}

    intent = await _detect_wazuh_intent_llm(user_prompt)
    if intent and intent.get("action") and intent["action"] not in ("unknown", "mcp_query"):
        action = intent["action"]
        
        if action == "reset_dashboard_wizard":
            async with WIZARDS_LOCK:
                WIZARDS.pop(sid, None)
            return {"output": {"message": "Dashboard wizard reset."}}

        if action == "create_custom_dashboard":
            try:
                provided_index = intent.get("index_pattern_title", "").strip()
                topic = intent.get("topic", "").strip()
                
                patterns = await discover_available_index_patterns()
                if not patterns:
                    return {"output": {"message": "No index patterns found. Configure Indexer (WAZUH_INDEXER_*) or check permissions."}}

                # Fast Path: User provided enough context in initial prompt
                if provided_index and topic:
                    matched_idx = next((p for p in patterns if p == provided_index), None)
                    if not matched_idx:
                        matched_idx = next((p for p in patterns if p.startswith(provided_index) or provided_index.startswith(p.strip("-*"))), None)
                    
                    if matched_idx:
                        # Emulate the generate_full_dashboard logic directly here
                        dash_title = f"{topic.title()} Dashboard"
                        dash_id = f"dash-{_slugify(topic)}-{uuid.uuid4().hex[:8]}"

                        idx_id = await osd_find_index_pattern_id_by_title(matched_idx)
                        time_field = await guess_time_field_for_index(matched_idx)
                        if not idx_id:
                            if AUTO_CREATE_INDEX_PATTERN:
                                ok, created = await osd_create_index_pattern(matched_idx, time_field)
                                if ok and created:
                                    idx_id = created
                                else:
                                    return {"output": {"message": f"Index pattern '{matched_idx}' not found and auto-create failed: {created}"}}
                            else:
                                return {"output": {"message": f"Index pattern '{matched_idx}' not found in Dashboards. Create it in UI first."}}

                        try:
                            raw_plans = await llm_generate_full_dashboard_plan(matched_idx, topic)
                        except Exception as e:
                            return {"output": {"message": f"Failed to generate dashboard plans: {e}"}}

                        valid_visualizations = []
                        for plan in raw_plans:
                            ok_fields, vmsg = await validate_plan_fields(matched_idx, plan)
                            if not ok_fields:
                                continue

                            v_type = plan.get("viz_type", "pie")
                            v_title = str(plan.get("viz_title", f"{v_type.title()} - {matched_idx}"))
                            v_id = f"viz-{_slugify(v_title)}-{uuid.uuid4().hex[:8]}"

                            try:
                                vis_payload = build_vis_payload(
                                    vis_type=v_type,
                                    title=f"{dash_title} - {v_title}",
                                    index_pattern_id=idx_id,
                                    time_field=time_field or "@timestamp",
                                    query=plan.get("query", ""),
                                    time_from=plan.get("time_from", "now-7d"),
                                    time_to=plan.get("time_to", "now"),
                                    field=plan.get("field"),
                                    table_fields=plan.get("table_fields"),
                                    top_n=plan.get("top_n", 5),
                                    split_field=plan.get("split_field"),
                                    split_top_n=plan.get("split_top_n", 5),
                                    interval=plan.get("interval", "auto"),
                                )
                                valid_visualizations.append({
                                    "vis_id": v_id,
                                    "viz_type": v_type,
                                    "vis_title": v_title,
                                    "vis_payload": vis_payload,
                                    "plan": plan
                                })
                            except Exception:
                                pass

                        if not valid_visualizations:
                            return {"output": {"message": "Failed to generate any valid visualizations for this custom dashboard (likely field validation errors). Please try describing the requirement differently."}}

                        async with PENDING_LOCK:
                            PENDING[sid] = PendingAction(
                                "generate_full_dashboard",
                                {
                                    "dash_id": dash_id,
                                    "dash_title": dash_title,
                                    "visualizations": valid_visualizations,
                                },
                                time.time()
                            )

                        msg = f"I generated a comprehensive auto-dashboard design for '{topic}' using index '{matched_idx}'.\n\nIt will contain {len(valid_visualizations)} visualizations:\n"
                        for v in valid_visualizations:
                            msg += f"- {v['vis_title']} (Type: {v['viz_type']})\n"
                        msg += "\nDo I need to proceed and create this dashboard? Type CONFIRM/yes to proceed, or NO to cancel."
                        return {"output": {"message": msg}}

                # Guided Path: Ask for both use case and index pattern together
                lines = ["Available index patterns:"]
                for i, p in enumerate(patterns, start=1):
                    lines.append(f"{i}) {p}")

                async with WIZARDS_LOCK:
                    WIZARDS[sid] = WizardState(
                        step="describe_full_dashboard",
                        created_at=time.time(),
                        data={"index_options": patterns},
                    )
                return {"output": {"message": "Please let me know what kind of dashboard are required, or say about your usecase AND let me know which index pattern I need to use.\n\n" + "\n".join(lines)}}
            except Exception as e:
                return {"output": {"message": f"Failed to start wizard: {e}"}}

        if action == "show_groups":
            prod = _prod_api()
            if not prod:
                return {"output": {"message": "PROD Wazuh API not configured."}}
            gresp = await wazuh_list_groups(prod)
            if not isinstance(gresp, dict) or gresp.get("error") != 0:
                reason = _api_reason(gresp)
                msg = "Failed to list groups."
                if reason:
                    msg += f" Reason: {reason}"
                return {"output": {"message": msg}}
            items = (gresp.get("data") or {}).get("affected_items") or []
            groups = []
            for it in items:
                if isinstance(it, dict) and it.get("name"):
                    groups.append(str(it["name"]))
                elif isinstance(it, str):
                    groups.append(it)
            groups = sorted(set(groups))
            return {"output": {"message": "Agent groups:\n- " + "\n- ".join(groups)}}

        if action == "assign_group":
            agent_ids = intent.get("agent_ids", [])
            group_id = str(intent.get("group_id", "")).strip()

            prod = _prod_api()
            if not prod:
                return {"output": {"message": "PROD Wazuh API not configured."}}

            if not agent_ids:
                async with WIZARDS_LOCK:
                    WIZARDS[sid] = WizardState("assign_group_choose_agent", time.time(), {"group_id": group_id})
                return {"output": {"message": "Which agent should I assign? Please provide the exact agent ID or Name."}}

            agent_ids = [str(a).zfill(3) for a in agent_ids]
            agents = await _get_agents(prod)
            missing = [aid for aid in agent_ids if not _find_agent(agents, aid)]
            if missing:
                return {"output": {"message": f"These agent id(s) are not present: {', '.join(missing)}"}}

            if len(agent_ids) == 1 and not group_id:
                aid = agent_ids[0]
                agent_obj = _find_agent(agents, aid)
                current_groups = agent_obj.get("group", [])
                
                gresp = await wazuh_list_groups(prod)
                if not isinstance(gresp, dict) or gresp.get("error") != 0:
                    return {"output": {"message": "Failed to list available groups from Wazuh API."}}
                
                items = (gresp.get("data") or {}).get("affected_items") or []
                all_groups = []
                for it in items:
                    if isinstance(it, dict) and it.get("name"):
                        all_groups.append(str(it["name"]))
                
                available_groups = [g for g in all_groups if g not in current_groups]
                
                if not available_groups:
                    return {"output": {"message": f"Agent {aid} is already assigned to all available groups ({', '.join(current_groups)})."}}
                elif len(available_groups) == 1:
                    group_id = available_groups[0]
                    async with PENDING_LOCK:
                        PENDING[sid] = PendingAction("assign_group", {"group_id": group_id, "agent_ids": agent_ids}, time.time())
                    return {"output": {"message": f"Agent {aid} is not in group '{group_id}'.\nDo I need to assign agent(s) {aid} to group '{group_id}'? If yes type CONFIRM, or NO to cancel."}}
                else:
                    async with WIZARDS_LOCK:
                        WIZARDS[sid] = WizardState("assign_group_choose_group", time.time(), {"agent_ids": agent_ids, "available_groups": available_groups})
                    return {"output": {"message": f"Agent {aid} can be added to the following groups: {', '.join(available_groups)}.\nWhich group should I assign it to?"}}

            if not group_id:
                return {"output": {"message": "Please specify which group you want to assign these agents to."}}

            async with PENDING_LOCK:
                PENDING[sid] = PendingAction("assign_group", {"group_id": group_id, "agent_ids": agent_ids}, time.time())
            return {"output": {"message": f"Do I need to assign agent(s) {', '.join(agent_ids)} to group '{group_id}'? If yes type CONFIRM, or NO to cancel."}}

        if action == "remove_group":
            agent_ids = intent.get("agent_ids", [])
            group_id = str(intent.get("group_id", "")).strip()
            
            prod = _prod_api()
            if not prod:
                return {"output": {"message": "PROD Wazuh API not configured."}}

            if not agent_ids:
                async with WIZARDS_LOCK:
                    WIZARDS[sid] = WizardState("remove_group_choose_agent", time.time(), {"group_id": group_id})
                return {"output": {"message": "Which agent should I remove? Please provide the exact agent ID or Name."}}

            agent_ids = [str(a).zfill(3) for a in agent_ids]
            agents = await _get_agents(prod)
            missing = [aid for aid in agent_ids if not _find_agent(agents, aid)]
            if missing:
                return {"output": {"message": f"These agent id(s) are not present: {', '.join(missing)}"}}

            if len(agent_ids) == 1 and not group_id:
                aid = agent_ids[0]
                agent_obj = _find_agent(agents, aid)
                groups = agent_obj.get("group", [])
                
                if not groups:
                    return {"output": {"message": f"Agent {aid} has no group assignments."}}
                elif len(groups) == 1:
                    group_id = groups[0]
                    async with PENDING_LOCK:
                        PENDING[sid] = PendingAction("remove_group", {"group_id": group_id, "agent_ids": agent_ids}, time.time())
                    return {"output": {"message": f"Agent {aid} is only assigned to group '{group_id}'.\nDo I need to remove agent {aid} from group '{group_id}'? If yes type CONFIRM, or NO to cancel."}}
                else:
                    async with WIZARDS_LOCK:
                        WIZARDS[sid] = WizardState("remove_group_choose_group", time.time(), {"agent_ids": agent_ids, "available_groups": groups})
                    return {"output": {"message": f"Agent {aid} is assigned to multiple groups: {', '.join(groups)}.\nWhich group should I remove it from?"}}

            if not group_id:
                return {"output": {"message": "Please specify which group you want to remove these agents from."}}

            async with PENDING_LOCK:
                PENDING[sid] = PendingAction("remove_group", {"group_id": group_id, "agent_ids": agent_ids}, time.time())
            return {"output": {"message": f"Do I need to remove agent(s) {', '.join(agent_ids)} from group '{group_id}'? If yes type CONFIRM, or NO to cancel."}}

        if action == "remove_disconnected_older_than" and intent.get("timeframe_str"):
            tf_str = str(intent.get("timeframe_str")).strip()
            seconds = _parse_timeframe_to_seconds(tf_str)
            if seconds <= 0:
                return {"output": {"message": "Invalid timeframe. Use: 30m, 12h, 7d, 2w, or combos like 7d12h."}}

            prod = _prod_api()
            if not prod:
                return {"output": {"message": "PROD Wazuh API not configured."}}

            agents = await _get_agents(prod)
            now = datetime.now(timezone.utc)

            candidates: List[Dict[str, Any]] = []
            for a in agents:
                if _agent_status(a) != "disconnected":
                    continue
                dt = _parse_wazuh_iso(a.get("disconnection_time"))
                if not dt:
                    continue

                age_sec = int((now - dt).total_seconds())
                if age_sec >= seconds:
                    candidates.append({
                        "id": str(a.get("id")),
                        "name": str(a.get("name", "")),
                        "disconnection_time": str(a.get("disconnection_time")),
                        "age_sec": age_sec,
                        "age_human": _fmt_age(age_sec),
                    })

            candidates = [c for c in candidates if c["id"]]
            candidates.sort(key=lambda x: x["age_sec"], reverse=True)

            if not candidates:
                return {"output": {"message": f"No disconnected agents older_than {tf_str}. No changes made."}}

            agent_ids = [c["id"] for c in candidates]

            async with PENDING_LOCK:
                PENDING[sid] = PendingAction(
                    "remove_disconnected_older_than",
                    {"agent_ids": agent_ids, "timeframe_str": tf_str},
                    time.time()
                )

            msg = format_disconnected_candidates(candidates, tf_str)
            msg += "\n\nDo I need to remove these agents? If yes type CONFIRM, or NO to cancel."
            return {"output": {"message": msg}}

        if action == "remove_agent" and intent.get("agent_id"):
            agent_id = str(intent["agent_id"]).zfill(3)
            prod = _prod_api()
            if not prod:
                return {"output": {"message": "PROD Wazuh API not configured."}}

            agents = await _get_agents(prod)
            if not _find_agent(agents, agent_id):
                return {"output": {"message": f"Agent with id {agent_id} is not present."}}

            async with PENDING_LOCK:
                PENDING[sid] = PendingAction("remove_agent", {"agent_id": agent_id, "older_than": "0s", "status": "all"}, time.time())
            return {"output": {"message": f"Do I need to remove the agent {agent_id}? If yes type CONFIRM, or NO to cancel."}}

        if action == "remove_all_disconnected":
            prod = _prod_api()
            if not prod:
                return {"output": {"message": "PROD Wazuh API not configured."}}

            agents = await _get_agents(prod)
            disconnected = [a for a in agents if _agent_status(a) == "disconnected"]
            ids = sorted({str(a.get("id")) for a in disconnected if a.get("id")})
            if not ids:
                return {"output": {"message": "No disconnected agents found. No changes made."}}

            async with PENDING_LOCK:
                PENDING[sid] = PendingAction("remove_all_disconnected", {"older_than": "0s", "include_never_connected": False}, time.time())
            return {"output": {"message": f"Do I need to remove ALL disconnected agents? Found {len(ids)} disconnected: {', '.join(ids)}. If yes type CONFIRM, or NO to cancel."}}

        if action == "restart_agent":
            agent_id = intent.get("agent_id")
            if not agent_id:
                async with WIZARDS_LOCK:
                    WIZARDS[sid] = WizardState("restart_choose_agent", time.time(), {})
                return {"output": {"message": "Which agent do you want to restart? Please provide the exact agent ID or Name."}}

            agent_id = str(agent_id).zfill(3)
            prod = _prod_api()
            if not prod:
                return {"output": {"message": "Restart failed: PROD Wazuh API not configured."}}

            agents = await _get_agents(prod)
            agent = _find_agent(agents, agent_id)
            if not agent:
                return {"output": {"message": f"Agent with id {agent_id} is not present."}}

            st = _agent_status(agent)
            if st == "disconnected":
                return {"output": {"message": f"Agent {agent_id} is disconnected. Restart not possible."}}
            if st != "active":
                return {"output": {"message": f"Agent {agent_id} status is '{st}'. Restart not allowed."}}

            async with PENDING_LOCK:
                PENDING[sid] = PendingAction("restart_agent", {"agent_id": agent_id}, time.time())
            
            confirm_msg = (
                f"Restarting a Wazuh agent is an operational action and needs explicit confirmation.\n\n"
                f"Do you want to proceed with restarting agent {agent_id} ({agent.get('name', 'Unknown')})?\n"
                f"Type **CONFIRM** to proceed or **NO** to cancel."
            )
            return {"output": {"message": confirm_msg}}

        if action == "create_dashboard_pie":
            idx_title = intent.get("index_pattern_title") or ALERTS_INDEX
            top_n = max(1, min(int(intent.get("top_n", 5)), 100))
            field = str(intent.get("field", "agent.name")).strip()

            idx_id = await osd_find_index_pattern_id_by_title(idx_title)
            time_field = await guess_time_field_for_index(idx_title)
            if not idx_id:
                if AUTO_CREATE_INDEX_PATTERN:
                    ok, created = await osd_create_index_pattern(idx_title, time_field)
                    if ok and created:
                        idx_id = created
                    else:
                        return {"output": {"message": f"Index pattern '{idx_title}' not found and auto-create failed: {created}"}}
                else:
                    return {"output": {"message": f"Index pattern '{idx_title}' not found in Dashboards. Create it in UI first."}}

            ok_fields, vmsg = await validate_plan_fields(idx_title, {"field": field})
            if not ok_fields:
                return {"output": {"message": f"Field validation failed: {vmsg}"}}

            vis_title = f"Top {top_n} {field} Triggered (Pie)"
            dash_title = f"Wazuh - Top {top_n} {field} Triggered"
            vis_id = f"pie-{_slugify(field)}-top{top_n}-{uuid.uuid4().hex[:8]}"
            dash_id = f"dash-{_slugify(field)}-top{top_n}-{uuid.uuid4().hex[:8]}"

            vis_payload = build_vis_payload(
                vis_type="pie",
                title=vis_title,
                index_pattern_id=idx_id,
                time_field=time_field or "@timestamp",
                query="",
                time_from="now-24h",
                time_to="now",
                field=field,
                top_n=top_n,
            )
            dash_payload = build_dashboard_payload(dash_title, vis_id)

            async with PENDING_LOCK:
                PENDING[sid] = PendingAction(
                    "create_dashboard_pie",
                    {
                        "index_pattern_title": idx_title,
                        "viz_type": "pie",
                        "vis_id": vis_id,
                        "dash_id": dash_id,
                        "vis_payload": vis_payload,
                        "dash_payload": dash_payload,
                    },
                    time.time()
                )

            return {"output": {"message": (
                f"Plan: Create Dashboard '{dash_title}' with 1 visualization.\n\n"
                f"pie: {vis_title}\n\n"
                f"index-pattern: {idx_title}\n"
                f"field: {field}\n"
                f"validation: {vmsg}\n"
                "Do I need to proceed and create it? Type CONFIRM/yes to proceed."
            )}}

        if action == "generate_full_dashboard":
            idx_title = intent.get("index_pattern_title") or ALERTS_INDEX
            
            topic = str(intent.get("topic") or user_prompt).strip()
            dash_title = f"{topic.title()} Dashboard"
            dash_id = f"dash-{_slugify(topic)}-{uuid.uuid4().hex[:8]}"
            
            idx_id = await osd_find_index_pattern_id_by_title(idx_title)
            time_field = await guess_time_field_for_index(idx_title)
            if not idx_id:
                if AUTO_CREATE_INDEX_PATTERN:
                    ok, created = await osd_create_index_pattern(idx_title, time_field)
                    if ok and created:
                        idx_id = created
                    else:
                        return {"output": {"message": f"Index pattern '{idx_title}' not found and auto-create failed: {created}"}}
                else:
                    return {"output": {"message": f"Index pattern '{idx_title}' not found in Dashboards. Create it in UI first."}}

            try:
                # 1. Ask LLM to generate list of visualization configs
                raw_plans = await llm_generate_full_dashboard_plan(idx_title, topic)
            except Exception as e:
                return {"output": {"message": f"Failed to generate dashboard plans: {e}"}}
            
            valid_visualizations = []
            
            # 2. Build standard vis payloads for each
            for plan in raw_plans:
                ok_fields, vmsg = await validate_plan_fields(idx_title, plan)
                if not ok_fields:
                    continue
                    
                viz_type = plan.get("viz_type", "pie")
                vis_title = str(plan.get("viz_title", f"{viz_type.title()} - {idx_title}"))
                vis_id = f"viz-{_slugify(vis_title)}-{uuid.uuid4().hex[:8]}"

                try:
                    vis_payload = build_vis_payload(
                        vis_type=viz_type,
                        title=f"{dash_title} - {vis_title}",
                        index_pattern_id=idx_id,
                        time_field=time_field or "@timestamp",
                        query=plan.get("query", ""),
                        time_from=plan.get("time_from", "now-7d"),
                        time_to=plan.get("time_to", "now"),
                        field=plan.get("field"),
                        table_fields=plan.get("table_fields"),
                        top_n=plan.get("top_n", 5),
                        split_field=plan.get("split_field"),
                        split_top_n=plan.get("split_top_n", 5),
                        interval=plan.get("interval", "auto"),
                    )
                    valid_visualizations.append({
                        "vis_id": vis_id,
                        "viz_type": viz_type,
                        "vis_title": vis_title,
                        "vis_payload": vis_payload,
                        "plan": plan
                    })
                except Exception:
                    pass
                    
            if not valid_visualizations:
                return {"output": {"message": "Failed to generate any valid visualizations for this custom dashboard (likely field validation errors). Please try describing the requirement differently."}}
            
            async with PENDING_LOCK:
                PENDING[sid] = PendingAction(
                    "generate_full_dashboard",
                    {
                        "dash_id": dash_id,
                        "dash_title": dash_title,
                        "visualizations": valid_visualizations,
                        "index_pattern_title": idx_title,
                        "topic": topic
                    },
                    time.time()
                )

            msg = f"I generated a comprehensive dashboard design for '{topic}'.\n\nIt will contain {len(valid_visualizations)} visualizations:\n"
            for v in valid_visualizations:
                msg += f"- {v['vis_title']} (Type: {v['viz_type']})\n"
                
            msg += "\nDo I need to proceed and create this dashboard? Type CONFIRM/yes to proceed, or NO to cancel."
            return {"output": {"message": msg}}

        if action == "generate_email_report":
            topic = str(intent.get("topic") or user_prompt).strip()
            idx_title = intent.get("index_pattern_title") or ALERTS_INDEX
            
            # 1. Generate the report immediately so they can preview it
            report_filename = f"report_{_slugify(topic)}_{uuid.uuid4().hex[:8]}.pdf"
            pdf_path = f"/tmp/{report_filename}"
            
            try:
                rep_data = await generate_pdf_report(topic, idx_title, pdf_path)
            except Exception as e:
                return {"output": {"message": f"Failed to generate PDF report preview: {e}"}}

            # 2. Provide the link and ask for email
            if PUBLIC_GATEWAY_URL:
                download_url = f"{PUBLIC_GATEWAY_URL.rstrip('/')}/download/report/{report_filename}"
            else:
                import urllib.parse
                parsed_url = urllib.parse.urlparse(str(request.base_url))
                # If the request comes through localhost, replace it with the likely external IP to make the link clickable
                domain = "192.168.0.199:9912" if parsed_url.hostname in ("127.0.0.1", "localhost") else parsed_url.netloc
                download_url = f"http://{domain}/download/report/{report_filename}"
            
            async with WIZARDS_LOCK:
                WIZARDS[sid] = WizardState(
                    step="ask_email_for_report",
                    created_at=time.time(),
                    data={
                        "topic": topic, 
                        "pdf_path": pdf_path,
                        "title": rep_data.get("title"),
                        "summary": rep_data.get("summary")
                    },
                )
            
            msg = f"I have generated the PDF report for '{topic}'.\n\nPreview Summary: {rep_data.get('summary')}\n\nTo view the full PDF, copy and paste this link into a new browser tab to download:\n{download_url}\n\nWho do you want me to send this report to? Please provide their email address."
            if app.state.recent_emails:
                msg += "\n\nRecent choices:\n"
                for i, em in enumerate(app.state.recent_emails, start=1):
                    msg += f"{i}) {em}\n"
                msg += "\n(Reply with a number or a new email address)"

            return {"output": {"message": msg}}



    try:
        executor = await _ensure_agent_executor()
        result = await executor.ainvoke({"input": user_prompt})
        raw_output = result.get("output")
        final_text = (
            "".join([r.get("text", "") for r in raw_output]) if isinstance(raw_output, list)
            else str(raw_output) if raw_output else "No output returned."
        )
        return {"output": {"message": final_text}}
    except Exception as e:
        tb = traceback.format_exc()
        return {"output": {"message": f"(AGENT error) {e}\n\nTRACEBACK:\n{tb}"}}
