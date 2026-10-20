"""
agent_brain.py
Dual-brain tool-calling abstraction for the Wazuh Agent.

Two interchangeable "brains" can drive the same agent loop:
  - "ollama": local, offline, uses Ollama's OpenAI-style /api/chat tools param.
  - "claude": the Anthropic API (Claude), used the same way Claude Agent SDK
    tool-use loops work — generally far more reliable at multi-step tool use
    than a small local model, at the cost of needing an API key + egress.

agent_engine.py talks to this module only through step(), and passes/receives
a brain-neutral conversation shape so it never needs to know which brain is
active:

    turns: list of
      {"role": "user", "text": str}
      {"role": "assistant", "text": str, "tool_calls": [{"id","name","arguments"}]}
      {"role": "tool", "tool_call_id": str, "name": str, "content": str}

    step() returns: {"text": str, "tool_calls": [{"id","name","arguments"}]}
"""

import json
import requests

from config import OLLAMA_URL, OLLAMA_MODEL, ANTHROPIC_API_KEY, ANTHROPIC_MODEL
from copilot_engine import check_ollama_health, list_ollama_models

try:
    import anthropic
except ImportError:
    anthropic = None

_anthropic_client = None


def available_brains():
    """What the frontend should offer as brain choices, and whether each is actually usable."""
    health = check_ollama_health(OLLAMA_URL)
    return {
        "ollama": {
            "available": health.get("ok", False),
            "model": OLLAMA_MODEL,
            "models": health.get("models") or list_ollama_models(OLLAMA_URL),
        },
        "claude": {
            "available": bool(ANTHROPIC_API_KEY) and anthropic is not None,
            "model": ANTHROPIC_MODEL,
            "reason": "" if ANTHROPIC_API_KEY else "no anthropic.api_key configured",
        },
    }


def _get_anthropic_client():
    global _anthropic_client
    if _anthropic_client is None:
        _anthropic_client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    return _anthropic_client


def step(turns, system_prompt, tools_openai, tools_anthropic, brain="ollama", model=None):
    if brain == "claude":
        if not ANTHROPIC_API_KEY or anthropic is None:
            raise RuntimeError("Claude brain is not configured (missing anthropic.api_key or the anthropic package).")
        return _step_claude(turns, system_prompt, tools_anthropic, model)
    return _step_ollama(turns, system_prompt, tools_openai, model)


# ─────────────────────────────────────────────────────────────────────────────
# OLLAMA
# ─────────────────────────────────────────────────────────────────────────────

def _step_ollama(turns, system_prompt, tools, model):
    model = model or OLLAMA_MODEL
    messages = [{"role": "system", "content": system_prompt}]

    for t in turns:
        if t["role"] == "user":
            messages.append({"role": "user", "content": t["text"]})
        elif t["role"] == "assistant":
            msg = {"role": "assistant", "content": t.get("text") or ""}
            if t.get("tool_calls"):
                msg["tool_calls"] = [
                    {"function": {"name": tc["name"], "arguments": tc["arguments"]}}
                    for tc in t["tool_calls"]
                ]
            messages.append(msg)
        elif t["role"] == "tool":
            messages.append({"role": "tool", "name": t["name"], "content": t["content"]})

    payload = {
        "model": model,
        "messages": messages,
        "tools": tools,
        "stream": False,
        "think": False,
        # qwen3:1.7b generates at ~7 tokens/sec on this CPU (no GPU) - 2048 would
        # let it ramble for minutes. Capped to keep answers focused and the wait tolerable.
        "options": {"temperature": 0.2, "num_predict": 300},
    }

    resp = requests.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=300)
    if resp.status_code != 200:
        raise RuntimeError(f"Ollama returned HTTP {resp.status_code}: {resp.text[:300]}")

    message = resp.json().get("message", {})
    raw_calls = message.get("tool_calls") or []

    tool_calls = []
    for i, tc in enumerate(raw_calls):
        fn = tc.get("function", {})
        args = fn.get("arguments", {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except (ValueError, TypeError):
                args = {}
        tool_calls.append({"id": f"call_{i}", "name": fn.get("name", ""), "arguments": args or {}})

    return {"text": (message.get("content") or "").strip(), "tool_calls": tool_calls}


# ─────────────────────────────────────────────────────────────────────────────
# CLAUDE
# ─────────────────────────────────────────────────────────────────────────────

def _step_claude(turns, system_prompt, tools, model):
    model = model or ANTHROPIC_MODEL
    client = _get_anthropic_client()

    messages = []
    i = 0
    while i < len(turns):
        t = turns[i]
        if t["role"] == "user":
            messages.append({"role": "user", "content": t["text"]})
            i += 1
        elif t["role"] == "assistant":
            content = []
            if t.get("text"):
                content.append({"type": "text", "text": t["text"]})
            for tc in t.get("tool_calls", []):
                content.append({"type": "tool_use", "id": tc["id"], "name": tc["name"], "input": tc["arguments"]})
            messages.append({"role": "assistant", "content": content})
            i += 1
        elif t["role"] == "tool":
            group = []
            while i < len(turns) and turns[i]["role"] == "tool":
                group.append({
                    "type": "tool_result",
                    "tool_use_id": turns[i]["tool_call_id"],
                    "content": turns[i]["content"],
                })
                i += 1
            messages.append({"role": "user", "content": group})
        else:
            i += 1

    resp = client.messages.create(
        model=model,
        max_tokens=2048,
        system=system_prompt,
        messages=messages,
        tools=tools,
    )

    text_parts = []
    tool_calls = []
    for block in resp.content:
        if block.type == "text":
            text_parts.append(block.text)
        elif block.type == "tool_use":
            tool_calls.append({"id": block.id, "name": block.name, "arguments": block.input or {}})

    return {"text": "\n".join(text_parts).strip(), "tool_calls": tool_calls}
