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

ALERT_PROMPT = """You are an AI assistant that defines OpenSearch Alerting Monitors dynamically based on a user's verbal request.
The user wants to get notified when certain logs arrive in OpenSearch.
Your job is to generate ONLY a valid JSON structure that will be injected into an OpenSearch Monitory configuration.

Available index patterns:
{INDEX_PATTERNS}

**SAMPLE DOCUMENT SCHEMA CONTEXT:**
To help you determine the correct field names (e.g., whether to use `data.dstuser` instead of `user`), here is an array of sample documents retrieved from OpenSearch that matches the user's topic:
```json
{SAMPLE_DOCUMENT}
```
**MASTER SCHEMA FIELDS:**
If the sample document above is empty or does not explicitly contain the field you need, you MUST pick the correct field exclusively from this master list of all verifiable schema fields:
{AVAILABLE_FIELDS}

CRITICAL RULES FOR FIELD NAMES:
1. Always map the user's requirement to an existing field shown in either the SAMPLE DOCUMENT or the MASTER SCHEMA FIELDS list.
2. If the user asks for a username and `data.dstuser` exists but `user.name` doesn't, use `data.dstuser`.
3. NEVER make up or hallucinate field names. If you query a field that does not exist, the monitor will crash.

CRITICAL RULES FOR OUTPUT:
1. ONLY output valid JSON. No markdown formatting, no explanations.
2. The JSON must contain these exact keys: `name`, `trigger_name`, `query_body`, and optionally `message_template`.
3. The `query_body` MUST be a valid OpenSearch Search API query object. IT IS CRITICAL that you include a `range` filter on the `timestamp` field to only match documents in the last `{INTERVAL_STR}` (e.g., `"gte": "now-{INTERVAL_STR}", "lte": "now"`). If you do not include this, the monitor will search the entire index every time it runs!
4. The `message_template` MUST be highly informative and iterate through the matched alerts using mustache templates to show details. Instead of a generic message, you MUST use `{{#ctx.results.0.hits.hits}}` to loop over the hits and print their `_source.rule.id`, `_source.rule.description`, `_source.rule.groups`, `_source.agent.name`, and any other relevant fields, then close the loop with `{{/ctx.results.0.hits.hits}}`.
5. The `query_body` must request `size: 100` (or another appropriate number > 0) so that the hits are returned and can be used in the message template. Do not use `size: 0`.
6. VERY IMPORTANT: When matching free-text topics (e.g. "authentication failed" or "sudo"), DO NOT restrict your search to a single narrow field like `data.audit.command` or `rule.description`. Instead, use `query_string` and explicitly provide an array of broad fields in the `fields` parameter (e.g. `{"query_string": {"fields": ["rule.description", "full_log", "rule.groups", "data.*"], "query": "*authentication failed*"}}`). ALWAYS prioritize searching Wazuh-native fields.

Example Request: "Alert me when rule 5710 is triggered more than 5 times"
Example Output:
```json
{
  "name": "Alert: SSH Authentication Failed (Rule 5710)",
  "trigger_name": "SSH Failure Trigger",
  "query_body": {
    "size": 100,
    "query": {
      "bool": {
        "must": [
          { "term": { "rule.id": "5710" } }
        ],
        "filter": [
          { "range": { "timestamp": { "gte": "now-{INTERVAL_STR}", "lte": "now" } } }
        ]
      }
    }
  },
  "message_template": "Monitor {{ctx.monitor.name}} triggered! Found rule matches in the last {{ctx.periodStart}} to {{ctx.periodEnd}}.\n\nAlert Details:\n{{#ctx.results.0.hits.hits}}\n- Rule ID: {{_source.rule.id}}\n- Description: {{_source.rule.description}}\n- Groups: {{_source.rule.groups}}\n- Agent: {{_source.agent.name}}\n{{/ctx.results.0.hits.hits}}"
}
```

Now, generate the JSON for the following requirement:
User Request: "{USER_REQUEST}"
Selected Index Pattern: "{SELECTED_INDEX}"
"""

