import json
import asyncio
import uuid
import copy
from typing import Dict, Any, Tuple

from .llm import _build_llm
from .prompts import ALERT_PROMPT
from .opensearch_api import indexer_field_caps, indexer_request

def _last_json_block(text: str) -> str:
    """Extracts the last JSON block from a markdown-formatted string."""
    parts = text.split("```")
    for i in range(len(parts) - 1, -1, -1):
        if parts[i].strip().startswith("json\n") or parts[i].strip().startswith("{"):
            block = parts[i].strip()
            if block.startswith("json\n"):
                block = block[5:].strip()
            return block
    return text.strip()

async def _extract_search_keywords_llm(topic: str) -> str:
    """Uses a lightweight prompt to extract query string keywords from the topic 
    so we can fetch relevant sample data from OpenSearch."""
    llm = _build_llm()
    prompt = f"""
    You are an intent parser. The user wants to create an OpenSearch monitor based on this topic:
    "{topic}"
    
    Extract the exact values that could be found in a log message (like rule IDs, IP addresses, usernames, filenames, etc).
    Return ONLY a single line of space-separated keywords that can be used in an OpenSearch `query_string` search.
    Do NOT include explanatory text or markdown.
    """
    try:
        msg = await asyncio.to_thread(llm.invoke, prompt)
        res = getattr(msg, "content", "") or ""
        return res.strip()
    except Exception:
        return ""

async def _auto_select_index_pattern(topic: str) -> str:
    """Uses LLM to select the most appropriate index from all available indices based on the user topic."""
    from .opensearch_api import indexer_cat_indices
    try:
        all_indices = await indexer_cat_indices("wazuh-*")
        indices_list_str = "\n".join([f"- {idx}" for idx in all_indices])
    except Exception:
        indices_list_str = "- wazuh-alerts-*\n- wazuh-archives-*\n- wazuh-states-vulnerabilities-*\n- wazuh-states-syscollector-*\n- wazuh-states-inventory-*"
        
    llm = _build_llm()
    prompt = f"""
    You are an OpenSearch indexing router. The user wants to create an OpenSearch monitor.
    User Requirement: "{topic}"
    
    Here are the physical indices currently in the system:
    {indices_list_str}
    
    CRITICAL INSTRUCTIONS:
    1. Select EXACTLY ONE most appropriate wildcard index pattern for this requirement based on these official mappings:
       - `wazuh-alerts-*`: Real-time alerts generated when events match a security detection rule (e.g., auth failures, malware, file changes). ALWAYS select this if the user requirement contains the word "alert" or "alerts", even if they use words like "monitor" or "active". DO NOT use for hardware/memory unless the user explicitly mentions a WAZUH RULE.
       - `wazuh-archives-*`: ALL events sent to the server.
       - `wazuh-monitoring-*`: Status of Wazuh agents (Active, Disconnected, Pending). DO NOT use this for performance/hardware/memory.
       - `wazuh-statistics-*`: Performance metrics of the Wazuh server (events received, processed and dropped).
       - `wazuh-states-vulnerabilities-*`: Detected vulnerabilities on endpoints.
       - `wazuh-states-inventory-hardware-*`: Hardware components (CPU, RAM, Memory configs).
       - `wazuh-states-inventory-hotfixes-*`: Windows KBs/updates and patches.
       - `wazuh-states-inventory-interfaces-*`: Network interfaces (up/down status, packet transfers).
       - `wazuh-states-inventory-networks-*`: IPv4 and IPv6 addresses associated with network interfaces.
       - `wazuh-states-inventory-packages-*`: Installed software packages/programs.
       - `wazuh-states-inventory-ports-*`: Open network ports on an endpoint.
       - `wazuh-states-inventory-processes-*`: Running system processes on an endpoint.
       - `wazuh-states-inventory-protocols-*`: Network routing configuration details and protocols.
       - `wazuh-states-inventory-system-*`: OS name, hostname, and architecture.
       - `wazuh-states-inventory-browser-extensions-*`: Information about browser extensions.
       - `wazuh-states-inventory-services-*`: Information about active/inactive system services.
       - `wazuh-states-inventory-groups-*`: User groups on endpoints.
       - `wazuh-states-inventory-users-*`: User accounts on endpoints.
    2. Convert the specific index name your recognize from the physical list to a wildcard pattern. For example:
       - `wazuh-alerts-4.x-2026.04.07` -> `wazuh-alerts-*`
       - `wazuh-states-inventory-hardware-wazuh-server` -> `wazuh-states-inventory-hardware-*`
       NEVER return a date or specific cluster name suffix. Always end with `*`.
    3. DISAMBIGUATION: If the requirement is extremely ambiguous (e.g., "users" could mean auth log alerts or static user inventory), or if you cannot determine the index, you MUST respond EXACTLY with `ASK_USER: <your short clarifying question>`.
    
    If you are confident, return ONLY the exact wildcard index pattern (e.g. wazuh-alerts-*). Do not include any explanations. If you are unsure, return `ASK_USER: ...`.
    """
    try:
        msg = await asyncio.to_thread(llm.invoke, prompt)
        res = getattr(msg, "content", "") or ""
        val = res.strip()
        if val.startswith("ASK_USER:"):
            return val
        if "wazuh-" in val:
            if not val.endswith("*"):
                val += "*"
            return val
    except Exception:
        pass
    return "wazuh-alerts-*"

async def llm_generate_alert_monitor(index_pattern: str, topic: str, dest_id: str, force_create: bool = False) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Given a topic (user intent) and a selected index pattern, ask the LLM
    to generate the OS Monitor query and conditions. Returns a fully formed Monitor payload.
    """
    
    if not index_pattern or index_pattern.lower() == "auto":
        index_pattern = await _auto_select_index_pattern(topic)
        if index_pattern.startswith("ASK_USER:"):
            return False, index_pattern.replace("ASK_USER:", "").strip(), {}

    # 1. Try to find a sample document to feed to the LLM for schema context
    keywords = await _extract_search_keywords_llm(topic)
    sample_doc_str = "{}"
    
    if keywords:
        q = {
            "size": 5,
            "query": {
                "query_string": {
                    "query": keywords,
                    "default_operator": "OR",
                    "lenient": True
                }
            }
        }
        sc, txt = await indexer_request("POST", f"/{index_pattern}/_search", json_body=q)
        if 200 <= sc < 300:
            try:
                j = json.loads(txt)
                hits = j.get("hits", {}).get("hits", [])
                samples = []
                for h in hits:
                    samples.append(h.get("_source", {}))
                if samples:
                    sample_doc_str = json.dumps(samples, indent=2)
            except Exception:
                pass

    # 2. Get the master list of all available fields and their types to prevent hallucination
    from .opensearch_api import get_all_fields_for_index
    try:
        available_fields = await get_all_fields_for_index(index_pattern)
        fields_str = "Available fields (fallback):\n" + "\n".join([f"- {f}" for f in available_fields[:200]])
    except Exception:
        available_fields = []
        fields_str = "Could not fetch fields."

    interval = 1
    unit = "MINUTES"
    interval_str = "1m"
    if "wazuh-states-" in index_pattern:
        interval = 1
        unit = "HOURS"
        interval_str = "1h"

    llm = _build_llm()
    prompt = ALERT_PROMPT.replace("{USER_REQUEST}", topic).replace("{SELECTED_INDEX}", index_pattern)
    prompt = prompt.replace("{INDEX_PATTERNS}", index_pattern)
    prompt = prompt.replace("{SAMPLE_DOCUMENT}", sample_doc_str)
    prompt = prompt.replace("{AVAILABLE_FIELDS}", fields_str)
    prompt = prompt.replace("{INTERVAL_STR}", interval_str)

    def _get_fields_from_query(q):
        fields = set()
        if isinstance(q, dict):
            for k, v in q.items():
                if k in ["term", "match", "match_phrase", "range", "wildcard", "exists", "terms"]:
                    if isinstance(v, dict):
                        if k == "exists":
                            f = v.get("field")
                            if f: fields.add(f)
                        else:
                            for fk in v.keys():
                                if not fk.startswith("boost"):
                                    fields.add(fk)
                else:
                    fields.update(_get_fields_from_query(v))
        elif isinstance(q, list):
            for item in q:
                fields.update(_get_fields_from_query(item))
        return fields

    try:
        max_retries = 3
        parsed = {}
        for attempt in range(max_retries):
            msg = await asyncio.to_thread(llm.invoke, prompt)
            raw = getattr(msg, "content", "") or ""
            text_block = _last_json_block(raw)
            
            try:
                parsed = json.loads(text_block)
            except Exception:
                pass # Probably invalid JSON, let it fall through or fail
                
            query_body = parsed.get("query_body", {})
            if not query_body:
                break
                
            def _remove_empty_fields(q):
                if isinstance(q, dict):
                    if "query_string" in q and isinstance(q["query_string"], dict):
                        if "fields" in q["query_string"] and q["query_string"]["fields"] == []:
                            del q["query_string"]["fields"]
                    for k, v in q.items():
                        _remove_empty_fields(v)
                elif isinstance(q, list):
                    for item in q:
                        _remove_empty_fields(item)
                        
            used_fields = _get_fields_from_query(query_body.get("query", {}))
            invalid_fields = [f for f in used_fields if f not in available_fields and f not in ["@timestamp", "timestamp"]]
            
            if not invalid_fields:
                _remove_empty_fields(query_body)
                
                def _check_hits(days: int) -> int:
                    import copy
                    test_query = copy.deepcopy(query_body)
                    def _widen_time_range(q):
                        if isinstance(q, dict):
                            for k, v in q.items():
                                if k == "range" and isinstance(v, dict):
                                    for field_name, range_params in v.items():
                                        if field_name in ["timestamp", "@timestamp"] and isinstance(range_params, dict):
                                            if "gte" in range_params:
                                                range_params["gte"] = f"now-{days}d"
                                else:
                                    _widen_time_range(v)
                        elif isinstance(q, list):
                            for item in q:
                                _widen_time_range(item)
                    _widen_time_range(test_query)
                    test_query["size"] = 0
                    return test_query
                    
                hits_count = 0
                for test_days in [30, 60, 90]:
                    sc, txt = await indexer_request("POST", f"/{index_pattern}/_search", json_body=_check_hits(test_days))
                    if 200 <= sc < 300:
                        try:
                            hits_count = json.loads(txt).get("hits", {}).get("total", {}).get("value", 0)
                            if hits_count > 0:
                                break
                        except Exception:
                            pass
                
                if hits_count > 0:
                    break # All fields valid and query returns data
                else:
                    if attempt < max_retries - 1:
                        prompt += "\n\nCRITICAL ERROR: Your generated query returned 0 hits when tested against 30, 60, and 90 days of history! This alert would never trigger. Please verify your exact field values, make the conditions more lenient, or use `query_string` with wildcards to fix this."
                        continue
                    else:
                        print(f"OS_SEARCH_WARNING: Query returned 0 hits, but skipping user confirmation to avoid friction.", flush=True)
                        break # Out of retries, just proceed with what we have
                
            if attempt < max_retries - 1:
                prompt += f"\n\nCRITICAL ERROR: Your last response used hallucinated fields that DO NOT EXIST in the schema: {invalid_fields}. You are strictly forbidden from querying fields outside of the AVAILABLE_FIELDS list. Retry and fix this immediately."
        
        name = parsed.get("name", f"Alert: {topic}")
        query_body = parsed.get("query_body", {})
        trigger_name = parsed.get("trigger_name", "Condition Met")
        
        if not query_body:
            query_body = {"size": 400, "query": {"match_all": {}}}
            
        # LLM generated custom message
        default_message = "Monitor {{ctx.monitor.name}} just entered alert status. Please investigate the issue.\\n- Trigger: {{ctx.trigger.name}}\\n- Severity: {{ctx.trigger.severity}}\\n- Period start: {{ctx.periodStart}}\\n- Period end: {{ctx.periodEnd}}\\n\\n{{#ctx.results.0.hits.hits}}\\n- Rule ID: {{_source.rule.id}} - {{_source.rule.description}}\\n- Agent: {{_source.agent.name}}\\n{{/ctx.results.0.hits.hits}}"
        msg_template_str = parsed.get("message_template", default_message)
        
        # Interval already computed earlier
            
        monitor_payload = {
            "name": name,
            "type": "monitor",
            "monitor_type": "query_level_monitor",
            "enabled": True,
            "schedule": {
                "period": {
                    "interval": interval,
                    "unit": unit
                }
            },
            "inputs": [{
                "search": {
                    "indices": [i.strip() for i in index_pattern.split(",") if i.strip()],
                    "query": query_body
                }
            }],
            "triggers": [{
                "query_level_trigger": {
                    "id": f"trig-{uuid.uuid4().hex[:8]}",
                    "name": trigger_name,
                    "severity": "1",
                    "condition": {
                        "script": {
                            "source": "return ctx.results[0].hits.total.value > 0",
                            "lang": "painless"
                        }
                    },
                    "actions": [{
                        "id": f"act-{uuid.uuid4().hex[:8]}",
                        "name": "Notify Destination",
                        "destination_id": dest_id,
                        "subject_template": {
                            "source": f"Alert: {name}",
                            "lang": "mustache"
                        },
                        "message_template": {
                            "source": msg_template_str,
                            "lang": "mustache"
                        },
                        "throttle_enabled": False
                    }]
                }
            }]
        }
        
        return True, "", monitor_payload
        
    except Exception as e:
        return False, f"Failed to generate valid Alert JSON via LLM: {str(e)}", {}
