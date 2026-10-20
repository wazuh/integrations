"""
agent_engine.py
The agent loop: plan -> call tool -> observe -> repeat, with a hard
propose-then-confirm gate in front of every mutating tool.

Read-only tools chain automatically — the agent can run several checks in a
row on its own. The moment it wants to call a tool marked "mutating" in
agent_tools.py, the loop stops and hands control back to the caller (the
/agent/approve endpoint) with the exact tool + arguments it wants to run.
Nothing mutating ever executes without that round-trip.

Sessions are kept in-memory only (module-level dict), same lifetime
convention as copilot_engine.py's SESSION_ENV_CACHE - fine for a single
backend process; conversations don't need to survive a restart.
"""

import json
import uuid

import agent_brain
from agent_tools import TOOLS, TOOLS_BY_NAME, to_openai_schema, to_anthropic_schema, list_tools_metadata
from utils import session_store
from utils.lgtm_utils import find_relevant_issues, format_lgtm_context
from utils.wazuh_docs import format_doc_context
from copilot_engine import collect_environment_context, format_environment_context
from config import (
    WAZUH_API_URL, API_USERNAME, API_PASSWORD,
    INDEXER_URL, INDEXER_USERNAME, INDEXER_PASSWORD,
)

MAX_ITERATIONS = 8

TOOLS_OPENAI = to_openai_schema()
TOOLS_ANTHROPIC = to_anthropic_schema()

# ─────────────────────────────────────────────────────────────────────────────
# OLLAMA RAG PATH — qwen3:1.7b is CPU-only and too slow to drive the agentic
# tool-calling loop (even a trimmed schema took 180s+ with no result on this
# hardware). Instead of asking it to decide when to call tools, we fetch
# everything relevant directly in Python (fast, no LLM involved) and hand it
# one single prompt for one single answer - no multi-turn loop, no tool
# schema overhead. This trades away Ollama's ability to execute fixes itself;
# Claude keeps the full tool-calling loop since it's fast enough for it.
#
# find_relevant_issues() searches the unified local SQLite+embeddings store
# (lgtm.db) covering wazuh/community issues, wazuh/community discussions, AND
# public wazuh/wazuh issues together - all pre-synced, so this is a fast local
# lookup with no live GitHub calls at chat time (unlike Claude's tool-calling
# path, which can still call search_public_wazuh_issues live for freshness).
# ─────────────────────────────────────────────────────────────────────────────

RAG_SYSTEM_PROMPT = """You are the Wazuh Troubleshooting Assistant. Answer using the live \
system data and known-issue context provided below when it's relevant to the question. \
Be direct and specific. If the provided context doesn't cover the question, answer from \
general Wazuh expertise instead of saying you don't know. Keep answers focused and short.

Never invent a specific documentation URL, deep link, or exact file path unless it appears \
verbatim in the context provided below - a plausible-looking but wrong URL is worse than no \
URL at all. If you want to point someone to documentation and don't have a verified link, \
say "check the official Wazuh documentation at documentation.wazuh.com" instead of \
fabricating a specific page path. Likewise, flag install/package commands as something to \
verify against the official docs for their exact OS/version rather than presenting them as \
guaranteed-correct - package names, repo setup steps, and syntax vary and you may not have \
the current, exact sequence memorized correctly."""


def _build_rag_context(user_text):
    parts = []

    lgtm_context = format_lgtm_context(find_relevant_issues(user_text))
    if lgtm_context:
        parts.append(lgtm_context)

    try:
        doc_context = format_doc_context(user_text)
        if doc_context:
            parts.append(doc_context)
    except Exception:
        pass  # verified-doc fetch is best-effort - never block an answer on it

    try:
        env_ctx = collect_environment_context(
            WAZUH_API_URL, API_USERNAME, API_PASSWORD,
            INDEXER_URL, INDEXER_USERNAME, INDEXER_PASSWORD,
        )
        env_str = format_environment_context(env_ctx)
        if env_str:
            parts.append(env_str)
    except Exception:
        pass  # live env snapshot is best-effort - never block an answer on it

    return "\n\n".join(parts)


def _run_ollama_rag(session, user_text, model):
    system_prompt = RAG_SYSTEM_PROMPT
    context = _build_rag_context(user_text)
    if context:
        system_prompt += "\n\n" + context

    # Only the last few turns go to Ollama, not the whole growing history -
    # this is RAG-grounded (context is rebuilt fresh every message from the
    # knowledge base + live env), not memory-dependent, and qwen3:1.7b's
    # prompt-processing time on this CPU scales with input length. Sending
    # the full history would make every later message in a conversation
    # progressively slower for no real benefit.
    recent_turns = session["turns"][-6:]

    step = agent_brain.step(recent_turns, system_prompt, [], [], brain="ollama", model=model)
    session["turns"].append({"role": "assistant", "text": step["text"]})
    return {"status": "final", "message": step["text"], "trace": []}

SYSTEM_PROMPT = """You are the Wazuh Troubleshooting Agent, an autonomous diagnostic assistant for a \
live Wazuh SIEM deployment (manager, indexer, dashboard, filebeat, endpoint agents).

You have tools to inspect and fix the deployment directly instead of just describing what to do. Use them.

Rules:
1. Investigate before acting. Call read-only tools to confirm a root cause before proposing a fix - \
don't jump straight to a fix from the symptom alone if a tool can confirm it first. For symptoms that could \
be a known issue, check search_lgtm_knowledge_base and search_public_wazuh_issues early - a previously-seen \
resolution is worth more than reasoning from scratch.
2. Call tools one at a time when a later step depends on an earlier result; only call several at once \
when they are genuinely independent checks.
3. Every tool that changes system state (restarts a service, edits a config file, deletes data, installs \
a package, etc.) automatically pauses for the user's explicit approval before it actually runs - you don't \
need to ask permission in words, just call the tool once you've decided it's the right next step. The user \
sees exactly what you're about to run, with its arguments, before it executes.
4. Never call a mutating tool speculatively "just to see what happens" - only once your diagnosis actually \
points to it as the fix.
5. Some actions are irreversible (deleting indices) or heavy (full certificate regeneration) - prefer the \
smallest fix that addresses the confirmed root cause, and say why you picked it.
6. When you're done, give a short plain-language summary: what was wrong, what you checked, what you fixed \
(or recommend if you stopped short of fixing it), and whether the issue looks resolved.
7. When you're not calling a tool, you're either asking the user one concise clarifying question or giving \
your final answer - keep both short and to the point.
"""

SESSIONS = {}


def _new_session():
    return {
        "turns": [],
        "pending_batch": None,
        "pending_batch_index": 0,
        "pending_action": None,
        "brain": "ollama",
        "model": None,
        "iterations": 0,
    }


def _get_session(session_id):
    if session_id not in SESSIONS:
        SESSIONS[session_id] = _new_session()
        persisted = session_store.load_session(session_id)
        if persisted:
            SESSIONS[session_id]["turns"] = persisted
    return SESSIONS[session_id]


def _to_text(result):
    if isinstance(result, str):
        return result[:8000]
    try:
        return json.dumps(result, default=str)[:8000]
    except Exception:
        return str(result)[:8000]


def _append_tool_result(session, tc, result):
    session["turns"].append({
        "role": "tool",
        "tool_call_id": tc["id"],
        "name": tc["name"],
        "content": _to_text(result),
    })


def _execute_tool(tool, tc):
    try:
        return tool["fn"](**(tc["arguments"] or {}))
    except TypeError as e:
        return {"error": f"invalid arguments for {tc['name']}: {e}"}
    except Exception as e:
        return {"error": str(e)}


def _process_batch(session, trace):
    """Run session['pending_batch'] from session['pending_batch_index'] onward.
    Returns (tool_call, tool) if it had to pause on a mutating call, else None
    once the whole batch has executed."""
    batch = session["pending_batch"]
    idx = session["pending_batch_index"]

    while idx < len(batch):
        tc = batch[idx]
        tool = TOOLS_BY_NAME.get(tc["name"])

        if tool is None:
            error = {"error": f"unknown tool '{tc['name']}'"}
            _append_tool_result(session, tc, error)
            trace.append({"type": "tool_result", "tool": tc["name"], "error": True, "result": error})
            idx += 1
            continue

        if tool["mutating"]:
            session["pending_batch_index"] = idx
            return tc, tool

        result = _execute_tool(tool, tc)
        trace.append({"type": "tool_call", "tool": tc["name"], "arguments": tc["arguments"], "mutating": False})
        trace.append({"type": "tool_result", "tool": tc["name"], "result": result})
        _append_tool_result(session, tc, result)
        idx += 1

    session["pending_batch"] = None
    session["pending_batch_index"] = 0
    return None


def _pending_action_payload(tc, tool):
    return {
        "tool_call_id": tc["id"],
        "tool": tc["name"],
        "arguments": tc["arguments"],
        "description": tool["description"],
        "risk": tool.get("risk", "medium"),
    }


def _run_loop(session):
    trace = []

    while session["iterations"] < MAX_ITERATIONS:
        if session["pending_batch"]:
            paused = _process_batch(session, trace)
            if paused:
                tc, tool = paused
                session["pending_action"] = _pending_action_payload(tc, tool)
                return {"status": "awaiting_approval", "pending_action": session["pending_action"], "trace": trace}

        session["iterations"] += 1

        step = agent_brain.step(
            session["turns"], SYSTEM_PROMPT, TOOLS_OPENAI, TOOLS_ANTHROPIC,
            brain=session["brain"], model=session.get("model"),
        )

        if not step["tool_calls"]:
            session["turns"].append({"role": "assistant", "text": step["text"]})
            return {"status": "final", "message": step["text"], "trace": trace}

        session["turns"].append({"role": "assistant", "text": step["text"], "tool_calls": step["tool_calls"]})
        session["pending_batch"] = step["tool_calls"]
        session["pending_batch_index"] = 0

    return {
        "status": "final",
        "message": "Stopped after too many investigation steps in a row — ask me to continue, or narrow the question.",
        "trace": trace,
    }


def handle_message(session_id, user_text, brain="ollama", model=None):
    session = _get_session(session_id)

    if session.get("pending_action"):
        return {
            "status": "error",
            "message": "There's an action awaiting your approval — approve or reject it before sending a new message.",
            "pending_action": session["pending_action"],
        }

    session["brain"] = brain if brain in ("ollama", "claude") else "ollama"
    session["model"] = model
    session["iterations"] = 0
    session["turns"].append({"role": "user", "text": user_text})

    if session["brain"] == "ollama":
        result = _run_ollama_rag(session, user_text, model)
    else:
        result = _run_loop(session)
    result["session_id"] = session_id
    session_store.save_session(session_id, session["turns"], brain=session.get("brain"))
    return result


def handle_approve(session_id, approve, edited_arguments=None):
    session = SESSIONS.get(session_id)
    if not session or not session.get("pending_action"):
        return {"status": "error", "message": "No pending action for this session."}

    trace = []
    tc = session["pending_batch"][session["pending_batch_index"]]
    tool = TOOLS_BY_NAME[tc["name"]]

    if approve:
        args = edited_arguments if edited_arguments is not None else tc["arguments"]
        exec_tc = {"id": tc["id"], "name": tc["name"], "arguments": args}
        result = _execute_tool(tool, exec_tc)
        trace.append({"type": "tool_call", "tool": tc["name"], "arguments": args, "mutating": True})
        trace.append({"type": "tool_result", "tool": tc["name"], "result": result})
        _append_tool_result(session, tc, result)
    else:
        declined = {"error": "User declined this action. Choose a different approach, ask a clarifying question, or stop here."}
        _append_tool_result(session, tc, declined)
        trace.append({"type": "tool_result", "tool": tc["name"], "result": "declined by user"})

    session["pending_batch_index"] += 1
    session["pending_action"] = None
    session["iterations"] = 0

    result = _run_loop(session)
    result["trace"] = trace + result["trace"]
    result["session_id"] = session_id
    session_store.save_session(session_id, session["turns"], brain=session.get("brain"))
    return result


def reset_session(session_id):
    SESSIONS.pop(session_id, None)
    return {"status": "reset"}


def get_tools_metadata():
    return list_tools_metadata()


def list_session_history():
    return session_store.list_sessions()


def resume_session(chat_id):
    """Load a persisted chat back into memory so sending a new message
    continues it, and return its turns for the frontend to replay."""
    turns = session_store.load_session(chat_id)
    if turns is None:
        return None
    session = _new_session()
    session["turns"] = turns
    SESSIONS[chat_id] = session
    return turns


def delete_session_history(chat_id):
    session_store.delete_session(chat_id)
    SESSIONS.pop(chat_id, None)


def rename_session_history(chat_id, new_title):
    return session_store.rename_session(chat_id, new_title)


def get_brains():
    return agent_brain.available_brains()
