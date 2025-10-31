#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MCP-LLM Gateway (FastAPI + LangChain)
-------------------------------------
Version 1.1


This service bridges OpenSearch MCP tools with an LLM backend (OpenAI or Bedrock).
It provides a REST API that receives analysis requests, executes MCP tools,
and returns summarized responses based on Wazuh alert and vulnerability data.


Main features:
- Loads the SOC Analyst system prompt from an external file.
- Sanitizes prompt formatting for consistent model interpretation.
- Replaces placeholders from environment variables automatically.
- Supports OpenAI (GPT) and AWS Bedrock (Claude) providers.
- Connects to the MCP Server via SSE and dynamically discovers tools.
- Handles authentication, parsing, and structured response delivery.
"""


import os
import re
import sys
import json
import asyncio
from typing import Optional, Any


import uvicorn
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict


# LangChain core modules
from langchain.tools.base import BaseTool
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain.prompts import (
    ChatPromptTemplate,
    MessagesPlaceholder,
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
)


# LLM clients
from langchain_openai import ChatOpenAI
try:
    from langchain_aws import ChatBedrock
except ImportError:
    ChatBedrock = None


# MCP adapter client
from langchain_mcp_adapters.client import MultiServerMCPClient




# ============================================================================
# Environment Configuration
# ============================================================================
# All parameters can be defined in /etc/mcp-llm-gateway/mcp-llm-gateway.env
# The default values below allow local testing.
# ----------------------------------------------------------------------------
GATEWAY_API_KEY = os.getenv("GATEWAY_API_KEY", "secret")
PORT = int(os.getenv("PORT", "9912"))
VERBOSE = os.getenv("VERBOSE", "false").lower() == "true"


MCP_SSE_URL = os.getenv("MCP_SSE_URL")


LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openai").lower()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")


AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet-20240229-v1:0")


ALERTS_INDEX = os.getenv("ALERTS_INDEX", "wazuh-alerts-*")
VULN_INDEX = os.getenv("VULN_INDEX", "wazuh-states-vulnerabilities-*")
DEFAULT_TIME_WINDOW = os.getenv("DEFAULT_TIME_WINDOW", "now-30m")




# ============================================================================
# Load and Sanitize System Prompt
# ============================================================================
def load_system_prompt() -> str:
    """
    Load and sanitize the SOC system prompt from an external file.


    - Normalizes line endings and removes BOM or excess whitespace.
    - Replaces placeholders {ALERTS_INDEX}, {VULN_INDEX}, and {DEFAULT_TIME_WINDOW}
      with their environment values defined in /etc/mcp-llm-gateway/mcp-llm-gateway.env.
    - Returns a clean, consistent string usable by LangChain.
    """
    path = "/etc/mcp-llm-gateway/mcp-llm-gateway.prompt"
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            content = f.read()


        # Normalize and sanitize text
        txt = content.strip().replace("\r\n", "\n").replace("\r", "\n")
        txt = re.sub(r"\n{3,}", "\n\n", txt)
        txt = txt.replace("\ufeff", "")


        # Replace placeholders with environment values
        replacements = {
            "{ALERTS_INDEX}": ALERTS_INDEX,
            "{VULN_INDEX}": VULN_INDEX,
            "{DEFAULT_TIME_WINDOW}": DEFAULT_TIME_WINDOW,
        }
        for old, new in replacements.items():
            txt = txt.replace(old, new)


        # Append reminder section
        txt += (
            f"\n\nRemember:\n"
            f"- Use {ALERTS_INDEX} for alerts.\n"
            f"- Use {VULN_INDEX} for vulnerabilities.\n"
            f"- Default time range: {DEFAULT_TIME_WINDOW}.\n"
        )


        if VERBOSE:
            print(f"[gateway] Loaded and sanitized system prompt ({len(txt)} chars)", file=sys.stderr)


        return txt


    except Exception as e:
        print(f"[gateway] ERROR: Could not load system prompt: {e}", file=sys.stderr)
        return "You are a Senior SOC Analyst."




SYSTEM_PROMPT = load_system_prompt()




# ============================================================================
# FastAPI Models and Initialization
# ============================================================================
class PredictBody(BaseModel):
    """Defines the structure of the POST body received from OpenSearch ML Commons."""
    model_config = ConfigDict(extra="allow")
    parameters: Optional[Any] = None
    payload: Optional[Any] = None




# Create FastAPI app
app = FastAPI(title="OpenSearch MCP → LLM Gateway", version="1.1")


# Global state
AGENT_EXECUTOR: Optional[AgentExecutor] = None
INIT_LOCK = asyncio.Lock()


_GREETING = re.compile(r"^\s*(hi|hello|hey|hola|buenas)\b", re.IGNORECASE)




# ============================================================================
# Helper Functions
# ============================================================================
def _extract_prompt(body: PredictBody) -> str:
    """Extracts the natural language query from the request body."""
    if isinstance(body.parameters, dict):
        if VERBOSE:
            print(f"[gateway] DEBUG: parameters received -> {body.parameters}", file=sys.stderr)
        for key in ("prompt", "question", "input", "text"):
            if body.parameters.get(key):
                return str(body.parameters[key])
        msgs = body.parameters.get("messages")
        if isinstance(msgs, list):
            for m in reversed(msgs):
                if isinstance(m, dict) and m.get("role") == "user":
                    return m.get("content")
    return "Summarize Wazuh alerts from the last 30 minutes with key findings and recommendations."




async def _load_mcp_tools() -> list[BaseTool]:
    """Connects to the MCP SSE endpoint and retrieves all available tools."""
    if not MCP_SSE_URL:
        raise RuntimeError("MCP_SSE_URL environment variable is required.")
    headers = {"Content-Type": "application/json", "Accept-Encoding": "identity"}
    client = MultiServerMCPClient({
        "opensearch": {"url": MCP_SSE_URL, "transport": "sse", "headers": headers}
    })
    tools = await client.get_tools()
    if VERBOSE:
        print(f"[gateway] Discovered {len(tools)} MCP tools", file=sys.stderr)
    return tools




def _build_llm():
    """Initializes the LLM client."""
    if LLM_PROVIDER == "openai":
        if not OPENAI_API_KEY:
            raise RuntimeError("OPENAI_API_KEY required for OpenAI provider.")
        return ChatOpenAI(model=OPENAI_MODEL, temperature=0)


    elif LLM_PROVIDER == "claude_bedrock":
        if not ChatBedrock:
            raise RuntimeError("langchain-aws not installed.")
        return ChatBedrock(
            model_id=BEDROCK_MODEL_ID,
            region_name=AWS_REGION,
            model_kwargs={"temperature": 0},
        )


    raise RuntimeError(f"Unsupported LLM_PROVIDER: {LLM_PROVIDER}")




def _build_prompt() -> ChatPromptTemplate:
    """Builds the LangChain conversation prompt."""
    return ChatPromptTemplate.from_messages([
        SystemMessagePromptTemplate.from_template(SYSTEM_PROMPT),
        HumanMessagePromptTemplate.from_template("{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ])




async def _ensure_agent_executor() -> AgentExecutor:
    """Creates and caches the LangChain AgentExecutor instance."""
    global AGENT_EXECUTOR
    if AGENT_EXECUTOR is None:
        async with INIT_LOCK:
            if AGENT_EXECUTOR is None:
                tools = await _load_mcp_tools()
                llm = _build_llm()
                prompt = _build_prompt()
                agent = create_tool_calling_agent(llm, tools, prompt)
                AGENT_EXECUTOR = AgentExecutor(
                    agent=agent,
                    tools=tools,
                    verbose=VERBOSE,
                    handle_parsing_errors=True,
                )
    return AGENT_EXECUTOR




# ============================================================================
# FastAPI Endpoints
# ============================================================================
@app.get("/health", summary="Real-time health check for Gateway, LLM, and MCP")
async def health():
    """Performs live operational validation for Gateway, LLM, and MCP."""
    status = {"gateway": "ok", "llm": "unknown", "mcp": "unknown"}
    details = {}


    # LLM check
    try:
        if LLM_PROVIDER == "openai":
            llm = ChatOpenAI(model=OPENAI_MODEL, temperature=0)
            _ = llm.invoke("Health check").content
        elif LLM_PROVIDER == "claude_bedrock" and ChatBedrock:
            llm = ChatBedrock(model_id=BEDROCK_MODEL_ID, region_name=AWS_REGION)
            _ = llm.invoke("Health check").content
        else:
            raise RuntimeError(f"Unsupported LLM provider: {LLM_PROVIDER}")
        status["llm"] = "ok"
    except Exception as e:
        status["llm"] = "error"
        details["llm_error"] = str(e)


    # MCP check
    try:
        if not MCP_SSE_URL:
            raise RuntimeError("MCP_SSE_URL not defined in environment")
        client = MultiServerMCPClient({
            "opensearch": {"url": MCP_SSE_URL, "transport": "sse", "headers": {"Accept-Encoding": "identity"}}
        })
        tools = await asyncio.wait_for(client.get_tools(), timeout=5)
        status["mcp"] = "ok"
        details["mcp_tools_count"] = len(tools)
    except asyncio.TimeoutError:
        status["mcp"] = "timeout"
        details["mcp_error"] = "Connection to MCP timed out (5s)"
    except Exception as e:
        status["mcp"] = "error"
        details["mcp_error"] = str(e)


    # Summary
    if status["llm"] == "ok" and status["mcp"] == "ok":
        summary = "All components operational."
    elif status["llm"] == "ok" and status["mcp"] != "ok":
        summary = "LLM operational; MCP not reachable."
    elif status["llm"] != "ok" and status["mcp"] == "ok":
        summary = "MCP operational; LLM not reachable."
    else:
        summary = "Both LLM and MCP unavailable."


    return {
        "summary": summary,
        "status": status,
        "details": details,
        "provider": LLM_PROVIDER,
        "model": OPENAI_MODEL if LLM_PROVIDER == "openai" else BEDROCK_MODEL_ID,
        "mcp_url": MCP_SSE_URL,
    }




@app.post("/analyze", summary="Main analysis endpoint")
async def predict(body: PredictBody, x_api_key: Optional[str] = Header(default=None)):
    """Handles main analysis requests from OpenSearch."""
    if GATEWAY_API_KEY and x_api_key != GATEWAY_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")


    user_prompt = _extract_prompt(body)
    if _GREETING.match(user_prompt):
        return {
            "output": {"message": (
                "Hello! I can help with cybersecurity questions and analyze alerts and vulnerabilities from your Wazuh environment.\n"
                "Examples of queries:\n"
                "- Analyze the most important alerts in my environment\n"
                "- Analyze the alerts from the last X minutes\n"
                "- Analyze brute force attack alerts\n"
                "- Please analyze the alert with the rule ID X\n"
                "- Which endpoints are affected by this CVE-XXXX-XXXXX\n"
                "- List critical CVEs"
            )}
        }


    try:
        executor = await _ensure_agent_executor()
        result = await executor.ainvoke({"input": user_prompt})
        raw_output = result.get("output")
        final_text = (
            "".join([r.get("text", "") for r in raw_output]) if isinstance(raw_output, list)
            else str(raw_output) if raw_output else "No output returned."
        )


        if VERBOSE:
            print(f"[gateway] DEBUG: Final output length={len(final_text)}", file=sys.stderr)
        return {"output": {"message": final_text}}


    except Exception as e:
        print(f"[gateway] ERROR: {e}", file=sys.stderr)
        return {"output": {"message": f"(AGENT error) {e}"}}




# ============================================================================
# Entry Point
# ============================================================================
if __name__ == "__main__":
    uvicorn.run("mcp_llm_gateway:app", host="0.0.0.0", port=PORT, reload=False)      
