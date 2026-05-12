import asyncio
import traceback
import sys
from typing import Optional

from langchain_openai import ChatOpenAI

try:
    from langchain_aws import ChatBedrock
except ImportError:
    ChatBedrock = None

try:
    from langchain_google_genai import ChatGoogleGenerativeAI
except ImportError:
    ChatGoogleGenerativeAI = None

try:
    from langchain.agents import create_tool_calling_agent
except ImportError:
    from langchain.agents.tool_calling_agent.base import create_tool_calling_agent

try:
    from langchain.agents import AgentExecutor
except ImportError:
    from langchain.agents.agent import AgentExecutor

from langchain.prompts import (
    ChatPromptTemplate,
    MessagesPlaceholder,
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
)

from langchain_mcp_adapters.client import MultiServerMCPClient

from .config import (
    LLM_PROVIDER, OPENAI_API_KEY, OPENAI_MODEL, BEDROCK_MODEL_ID, AWS_REGION,
    GEMINI_API_KEY, GEMINI_MODEL, MCP_SSE_URL, VERBOSE
)
from .prompts import SOC_PROMPT

AGENT_EXECUTOR: Optional[AgentExecutor] = None
INIT_LOCK = asyncio.Lock()

def _build_llm():
    if LLM_PROVIDER == "openai":
        if not OPENAI_API_KEY:
            raise RuntimeError("OPENAI_API_KEY required for LLM_PROVIDER=openai.")
        return ChatOpenAI(model=OPENAI_MODEL, temperature=0)

    if LLM_PROVIDER == "claude_bedrock":
        if not ChatBedrock:
            raise RuntimeError("langchain-aws not installed but LLM_PROVIDER=claude_bedrock.")
        return ChatBedrock(
            model_id=BEDROCK_MODEL_ID,
            region_name=AWS_REGION,
            model_kwargs={"temperature": 0},
        )

    if LLM_PROVIDER == "gemini":
        if not ChatGoogleGenerativeAI:
            raise RuntimeError("langchain-google-genai not installed but LLM_PROVIDER=gemini.")
        if not GEMINI_API_KEY:
            raise RuntimeError("GEMINI_API_KEY required for LLM_PROVIDER=gemini.")
        return ChatGoogleGenerativeAI(
            model=GEMINI_MODEL,
            google_api_key=GEMINI_API_KEY,
            temperature=0,
        )

    raise RuntimeError(f"Unsupported LLM_PROVIDER: {LLM_PROVIDER}")

async def _load_mcp_tools():
    if not MCP_SSE_URL:
        raise RuntimeError("MCP_SSE_URL is required to use MCP tools.")

    headers = {"Content-Type": "application/json", "Accept-Encoding": "identity"}

    try:
        client = MultiServerMCPClient({
            "opensearch": {"url": MCP_SSE_URL, "transport": "sse", "headers": headers}
        })
        tools = await client.get_tools()
        if VERBOSE:
            print(f"[gateway] Discovered {len(tools)} MCP tools", file=sys.stderr)
        return tools
    except Exception as e:
        tb = traceback.format_exc()
        raise RuntimeError(f"Failed to load MCP tools from MCP_SSE_URL='{MCP_SSE_URL}': {e}\n{tb}")

def _build_prompt(system_prompt: str) -> ChatPromptTemplate:
    return ChatPromptTemplate.from_messages([
        SystemMessagePromptTemplate.from_template(system_prompt),
        HumanMessagePromptTemplate.from_template("{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ])

async def _ensure_agent_executor() -> AgentExecutor:
    global AGENT_EXECUTOR
    if AGENT_EXECUTOR is None:
        async with INIT_LOCK:
            if AGENT_EXECUTOR is None:
                tools = await _load_mcp_tools()
                llm = _build_llm()
                
                from .opensearch_api import get_all_fields_for_index
                from .opensearch_api import get_all_fields_for_index
                from .config import ALERTS_INDEX, VULN_INDEX
                try:
                    fields = await get_all_fields_for_index(ALERTS_INDEX)
                    fields_info = "\n\nAvailable fields in " + ALERTS_INDEX + ":\n" + ", ".join(fields) + "\n\n"
                    
                    vuln_fields = await get_all_fields_for_index(VULN_INDEX)
                    if vuln_fields:
                        fields_info += "Available fields in " + VULN_INDEX + ":\n" + ", ".join(vuln_fields) + "\n\n"
                        
                    actual_prompt = SOC_PROMPT + fields_info
                except Exception:
                    actual_prompt = SOC_PROMPT

                prompt = _build_prompt(actual_prompt)
                agent = create_tool_calling_agent(llm, tools, prompt)
                AGENT_EXECUTOR = AgentExecutor(
                    agent=agent,
                    tools=tools,
                    verbose=VERBOSE,
                    handle_parsing_errors=True,
                )
    return AGENT_EXECUTOR
