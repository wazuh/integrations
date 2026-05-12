import re
import sys
from .config import (
    VERBOSE, ALERTS_INDEX, VULN_INDEX, DEFAULT_TIME_WINDOW, 
    SOC_PROMPT_PATH, DQL_PROMPT_PATH, INVENTORY_PROMPT_PATH
)

PROMPT_VAR_ALLOWLIST = {"input", "agent_scratchpad"}
_BRACE_TOKEN_RE = re.compile(r"\{([A-Za-z0-9_]+)\}")

def _load_text(path: str, fallback: str) -> str:
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            return f.read().strip().replace("\r\n", "\n").replace("\r", "\n").replace("\ufeff", "")
    except Exception as e:
        if VERBOSE:
            print(f"[gateway] WARN: could not load {path}: {e}", file=sys.stderr)
        return fallback

def _replace_known_placeholders(txt: str) -> str:
    txt = txt.replace("{ALERTS_INDEX}", ALERTS_INDEX)
    txt = txt.replace("{VULN_INDEX}", VULN_INDEX)
    txt = txt.replace("{DEFAULT_TIME_WINDOW}", DEFAULT_TIME_WINDOW)
    return txt

def escape_all_braces_except_allowlist(txt: str) -> str:
    def repl(m: re.Match) -> str:
        token = m.group(1)
        if token in PROMPT_VAR_ALLOWLIST:
            return "{" + token + "}"
        return "{{" + token + "}}"
    return _BRACE_TOKEN_RE.sub(repl, txt)

def load_soc_prompt() -> str:
    txt = _load_text(SOC_PROMPT_PATH, "You are a Senior SOC Analyst.")
    txt = _replace_known_placeholders(txt)
    return escape_all_braces_except_allowlist(txt)

def load_dql_prompt() -> str:
    base = _load_text(
        DQL_PROMPT_PATH,
        (
            "You convert plain English into strict JSON for OpenSearch Discover links.\n"
            "Return only JSON object with: index_pattern, time_from, time_to, kql."
        ),
    )
    base = _replace_known_placeholders(base)
    base = escape_all_braces_except_allowlist(base)
    return base

def load_inventory_prompt() -> str:
    base = _load_text(
        INVENTORY_PROMPT_PATH,
        (
            "You are a Wazuh inventory analyst. Use only provided inventory records to answer. "
            "If endpoint names are requested, list endpoint names clearly as bullets."
        ),
    )
    base = _replace_known_placeholders(base)
    base = escape_all_braces_except_allowlist(base)
    return base

SOC_PROMPT = load_soc_prompt()

DQL_PROMPT = load_dql_prompt()
INVENTORY_PROMPT = load_inventory_prompt()
