import json
import uuid
import re
import asyncio
from typing import Optional, Any, Dict, List, Tuple
from .llm import _build_llm
from .opensearch_api import (
    _indexer_configured,
    indexer_cat_indices,
    indexer_field_caps,
    osd_request,
    get_all_fields_for_index,
    indexer_request
)
from .alert_plan import _extract_search_keywords_llm

async def _get_sample_docs(index_pattern: str, topic: str) -> str:
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
        try:
            sc, txt = await indexer_request("POST", f"/{index_pattern}/_search", json_body=q)
            if 200 <= sc < 300:
                j = json.loads(txt)
                hits = j.get("hits", {}).get("hits", [])
                samples = []
                for h in hits:
                    samples.append(h.get("_source", {}))
                if samples:
                    sample_doc_str = json.dumps(samples, indent=2)
        except Exception:
            pass
    return sample_doc_str

def _last_json_block(text: str) -> str:
    text = (text or "").strip()
    start_idx = -1
    for i, c in enumerate(text):
        if c in ('{', '['):
            start_idx = i
            break
    end_idx = -1
    for i in range(len(text)-1, -1, -1):
        if text[i] in ('}', ']'):
            end_idx = i
            break
    if start_idx != -1 and end_idx != -1 and end_idx >= start_idx:
        return text[start_idx:end_idx+1]
    return text

def field_exists_in_field_caps(caps: Dict[str, Any], field: str) -> bool:
    f = (caps.get("fields") or {}).get(field)
    if not f:
        return False
    if len(f) > 1:
        return False
    # Ensure at least one type is aggregatable since visualizations use bucket aggregations
    for ext_type, details in f.items():
        if details.get("aggregatable") is True:
            return True
    return False

def _collect_plan_fields(plan: Dict[str, Any]) -> List[str]:
    fields = []
    for k in ("field", "split_field", "terms_field"):
        v = plan.get(k)
        if isinstance(v, str) and v.strip():
            fields.append(v.strip())
    tf = plan.get("table_fields")
    if isinstance(tf, list):
        for x in tf:
            if isinstance(x, str) and x.strip():
                fields.append(x.strip())
    out, seen = [], set()
    for f in fields:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out

async def validate_plan_fields(index: str, plan: Dict[str, Any]) -> Tuple[bool, str]:
    fields = _collect_plan_fields(plan)
    if not fields:
        return True, "No fields to validate."
    if not _indexer_configured():
        return True, "Indexer not configured; skipped field validation."

    try:
        caps = await indexer_field_caps(index, fields)
        missing = [f for f in fields if not field_exists_in_field_caps(caps, f)]
        if missing:
            return False, f"Missing in mappings: {', '.join(missing)}"
        return True, "Field validation OK."
    except Exception as e:
        return False, f"Field validation error: {e}"

def _guess_index_patterns_from_indices(indices: List[str]) -> List[str]:
    pats = set()
    for idx in indices:
        if not idx.startswith("wazuh-"):
            continue
        parts = idx.split("-")
        if len(parts) >= 2:
            base = "-".join(parts[:2])
            pats.add(base + "-*")
        if len(parts) >= 3:
            base3 = "-".join(parts[:3])
            pats.add(base3 + "-*")

    common = [
        "wazuh-alerts-*",
        "wazuh-archives-*",
        "wazuh-states-vulnerabilities-*",
        "wazuh-monitoring-*",
        "wazuh-statistics-*",
    ]
    for c in common:
        pats.add(c)

    out = sorted(pats, key=lambda x: (len(x), x))
    final = []
    for p in out:
        if any(p.startswith(s[:-1]) and s.endswith("*") for s in final):
            pass
        final.append(p)
    uniq, seen = [], set()
    for p in final:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq[:25]

async def discover_available_index_patterns() -> List[str]:
    if _indexer_configured():
        idxs = await indexer_cat_indices("wazuh-*")
        pats = _guess_index_patterns_from_indices(idxs)
        return pats
    return [
        "wazuh-alerts-*",
        "wazuh-archives-*",
        "wazuh-states-vulnerabilities-*",
        "wazuh-monitoring-*",
        "wazuh-statistics-*",
    ]

async def guess_time_field_for_index(index_pattern: str) -> Optional[str]:
    candidates = ["@timestamp", "timestamp", "event.created", "data.timestamp"]
    if not _indexer_configured():
        return "@timestamp"
    try:
        caps = await indexer_field_caps(index_pattern, candidates)
        for c in candidates:
            if field_exists_in_field_caps(caps, c):
                return c
    except Exception:
        pass
    return "@timestamp"

def build_vis_payload(
    *,
    vis_type: str,
    title: str,
    index_pattern_id: str,
    time_field: str,
    query: str,
    time_from: str,
    time_to: str,
    field: Optional[str] = None,
    top_n: int = 5,
    interval: str = "auto",
    split_field: Optional[str] = None,
    split_top_n: int = 5,
    table_fields: Optional[List[str]] = None,
) -> Dict[str, Any]:
    if not time_field:
        time_field = "@timestamp"

    search_source = {
        "query": {"language": "kuery", "query": query or ""},
        "filter": [],
        "index": index_pattern_id,
    }

    vis_type = (vis_type or "").lower().strip()

    if vis_type == "pie":
        if not field:
            raise ValueError("pie requires 'field'")
        vis_state = {
            "title": title,
            "type": "pie",
            "params": {
                "type": "pie",
                "addTooltip": True,
                "addLegend": True,
                "legendPosition": "right",
                "isDonut": False,
            },
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
                 "params": {"field": field, "size": int(top_n), "order": "desc", "orderBy": "1", "missingBucket": True, "missingBucketLabel": "Missing"}},
            ],
        }

    elif vis_type == "bar":
        if not field:
            raise ValueError("bar requires 'field'")
        vis_state = {
            "title": title,
            "type": "histogram",
            "params": {
                "type": "histogram",
                "addTooltip": True,
                "addLegend": False,
                "legendPosition": "right",
                "categoryAxes": [
                    {
                        "id": "CategoryAxis-1",
                        "type": "category",
                        "position": "bottom",
                        "show": True,
                        "style": {},
                        "scale": {"type": "linear"},
                        "labels": {
                            "show": True,
                            "truncate": 100,
                            "rotate": 45,
                            "filter": True
                        },
                        "title": {}
                    }
                ],
                "valueAxes": [
                    {
                        "id": "ValueAxis-1",
                        "name": "LeftAxis-1",
                        "type": "value",
                        "position": "left",
                        "show": True,
                        "style": {},
                        "scale": {"type": "linear", "mode": "normal"},
                        "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                        "title": {"text": "Count"}
                    }
                ],
                "grid": {
                    "categoryLines": False,
                    "valueAxis": "ValueAxis-1"
                }
            },
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
                 "params": {"field": field, "size": int(top_n), "order": "desc", "orderBy": "1", "missingBucket": True, "missingBucketLabel": "Missing"}},
            ],
        }

    elif vis_type == "line":
        vis_state = {
            "title": title,
            "type": "line",
            "params": {
                "addTooltip": True,
                "addLegend": True,
                "legendPosition": "right",
            },
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
                 "params": {"field": time_field, "interval": interval, "min_doc_count": 1}},
            ],
        }
        if split_field:
            vis_state["aggs"].append(
                {"id": "3", "enabled": True, "type": "terms", "schema": "group",
                 "params": {"field": split_field, "size": int(split_top_n), "order": "desc", "orderBy": "1"}}
            )

    elif vis_type == "metric":
        if field:
            aggs = [
                {
                    "id": "1", 
                    "enabled": True, 
                    "type": "cardinality", 
                    "schema": "metric", 
                    "params": {"field": field, "customLabel": "Unique Count"}
                }
            ]
        else:
            aggs = [{"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}]

        vis_state = {
            "title": title,
            "type": "metric",
            "params": {
                "addTooltip": True,
            },
            "aggs": aggs,
        }

    elif vis_type == "table":
        if not field and not table_fields:
            raise ValueError("table requires 'field' or 'table_fields'")
            
        fields_to_use = table_fields if table_fields else [field]
        # remove time_field and timestamp fields since they cause 'invalid field for Terms aggregation' errors
        fields_to_use = [f for f in fields_to_use if f not in (time_field, "@timestamp", "timestamp")]
        if not fields_to_use:
            fields_to_use = ["agent.name"] # fallback
            
        aggs = [{"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}]
        
        for i, f in enumerate(fields_to_use):
            aggs.append({
                "id": str(i + 2), 
                "enabled": True, 
                "type": "terms", 
                "schema": "bucket",
                "params": {"field": f, "size": int(top_n), "order": "desc", "orderBy": "1", "missingBucket": True, "missingBucketLabel": "Missing"}
            })

        vis_state = {
            "title": title,
            "type": "table",
            "params": {
                "perPage": 10,
                "showPartialRows": True,
                "showMetricsAtAllLevels": False,
                "sort": {"columnIndex": 1, "direction": "desc"},
            },
            "aggs": aggs,
        }

    elif vis_type == "map":
        if not field:
            raise ValueError("map requires 'field' (a geo_point field)")
        vis_state = {
            "title": title,
            "type": "tile_map",
            "params": {
                "colorSchema": "Yellow to Red",
                "mapType": "Scaled Circle Markers",
                "isDesaturated": True,
                "addTooltip": True,
                "heatClusterSize": 1.5,
                "legendPosition": "bottomright",
                "mapZoom": 2,
                "mapCenter": [0, 0],
                "wms": {"enabled": False, "options": {"format": "image/png", "transparent": True}}
            },
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                {"id": "2", "enabled": True, "type": "geohash_grid", "schema": "segment",
                 "params": {"field": field, "autoPrecision": True, "precision": 2, "useGeocentroid": True, "isFilteredByCollar": True}},
            ],
        }

    else:
        raise ValueError(f"Unsupported visualization type: {vis_type}")

    return {
        "attributes": {
            "title": title,
            "description": "",
            "visState": json.dumps(vis_state, separators=(",", ":")),
            "uiStateJSON": "{}",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(search_source, separators=(",", ":"))
            },
        }
    }

def build_dashboard_payload(title: str, vis_id: str) -> Dict[str, Any]:
    panel_id = str(uuid.uuid4())
    panels = [{
        "version": "2.19.0",
        "type": "visualization",
        "gridData": {"x": 0, "y": 0, "w": 24, "h": 15, "i": panel_id},
        "panelIndex": panel_id,
        "embeddableConfig": {},
        "id": vis_id,
    }]
    references = [{
        "name": f"panel_{panel_id}",
        "type": "visualization",
        "id": vis_id,
    }]
    attrs = {
        "title": title,
        "hits": 0,
        "description": "",
        "panelsJSON": json.dumps(panels, separators=(",", ":")),
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}, separators=(",", ":")),
        "timeRestore": False,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []},
                                           separators=(",", ":"))
        },
    }
    return {"attributes": attrs, "references": references}

def build_multi_dashboard_payload(title: str, visualizations: List[Dict[str, Any]]) -> Dict[str, Any]:
    panels = []
    references = []
    
    x = 0
    col_heights = [0] * 48
    
    for i, vis in enumerate(visualizations):
        panel_id = str(uuid.uuid4())
        vis_id = vis.get("vis_id", "")
        viz_type = vis.get("viz_type", "")
        plan = vis.get("plan", {})
        
        if "grid_w" in plan and "grid_h" in plan:
            w = int(plan["grid_w"])
            h = int(plan["grid_h"])
            if viz_type == "metric":
                h = min(h, 8)
            elif viz_type in ("line", "area", "map", "pie", "bar"):
                h = min(h, 15)
        else:
            if viz_type == "metric":
                w, h = 48, 8
            elif viz_type in ("line", "area"):
                w, h = 48, 14
            elif viz_type == "table":
                w, h = 48, 18
            else:
                w, h = 24, 14

        w = max(1, min(w, 48))
        h = max(1, h)

        if x + w > 48:
            x = 0
            
        y = max(col_heights[x : x+w])
            
        panels.append({
            "version": "2.19.0",
            "type": "visualization",
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": panel_id},
            "panelIndex": panel_id,
            "embeddableConfig": {},
            "id": vis_id,
        })
        references.append({
            "name": f"panel_{panel_id}",
            "type": "visualization",
            "id": vis_id,
        })
        
        for c in range(x, x+w):
            col_heights[c] = y + h
            
        x += w
        if x >= 48:
            x = 0

    attrs = {
        "title": title,
        "hits": 0,
        "description": "Auto-generated dashboard based on analysis requirement.",
        "panelsJSON": json.dumps(panels, separators=(",", ":")),
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}, separators=(",", ":")),
        "timeRestore": False,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []},
                                           separators=(",", ":"))
        },
    }
    return {"attributes": attrs, "references": references}

async def osd_create_visualization(vis_id: str, payload: Dict[str, Any]) -> Tuple[bool, str]:
    sc, txt = await osd_request("POST", f"/api/saved_objects/visualization/{vis_id}?overwrite=true", json_body=payload)
    if 200 <= sc < 300:
        return True, txt
    return False, f"status={sc} raw={txt}"

async def osd_create_dashboard(dash_id: str, payload: Dict[str, Any]) -> Tuple[bool, str]:
    sc, txt = await osd_request("POST", f"/api/saved_objects/dashboard/{dash_id}?overwrite=true", json_body=payload)
    if 200 <= sc < 300:
        return True, txt
    return False, f"status={sc} raw={txt}"

async def llm_generate_dashboard_plan(index_pattern: str, viz_type: str, requirement: str) -> Dict[str, Any]:
    llm = _build_llm()
    fields_list = await get_all_fields_for_index(index_pattern)
    fields_str = ", ".join(fields_list)
    
    sys_prompt = (
        "You are generating a JSON plan for an OpenSearch Dashboards visualization.\n"
        "Rules:\n"
        "- Output ONLY valid JSON object.\n"
        "- CRITICAL INSTRUCTION: Your entire response must consist solely of the JSON object. Do not include any explanations, tutorial steps, or markdown formatting.\n"
        "- Use KQL for 'query' if filtering is needed, else empty string.\n"
        "- time_from/time_to should be relative strings like 'now-24h' and 'now'.\n"
        "- For pie/bar/table: choose a 'field' to do a TOP-N terms aggregation.\n"
        "- For line: prefer a time series count; if requirement mentions 'top N agents' over time, use split_field=agent.name and split_top_n=N.\n"
        f"- Prefer these fields (if relevant): {fields_str}\n"
        "- If user says brute force on ssh, suggest query: \"rule.groups : sshd\" or something similar.\n"
        "- Keep titles short and clear.\n"
    )

    user = (
        f"Index pattern: {index_pattern}\n"
        f"Visualization type: {viz_type}\n"
        f"Requirement: {requirement}\n"
    )

    msg = await asyncio.to_thread(llm.invoke, sys_prompt + "\n" + user)
    raw = getattr(msg, "content", "") or ""
    plan = json.loads(_last_json_block(raw))

    plan.setdefault("query", "")
    plan.setdefault("time_from", "now-24h")
    plan.setdefault("time_to", "now")
    plan.setdefault("top_n", 5)
    plan.setdefault("interval", "auto")

    if viz_type in ("pie", "bar", "table") and not plan.get("field"):
        plan["field"] = "agent.name"
    if viz_type == "line":
        plan.setdefault("split_field", None)
        plan.setdefault("split_top_n", int(plan.get("top_n") or 5))

    return plan

async def llm_fix_dashboard_plan(index_pattern: str, plan: Dict[str, Any], validation_msg: str, requirement: str) -> Dict[str, Any]:
    llm = _build_llm()
    fields_list = await get_all_fields_for_index(index_pattern)
    fields_str = ", ".join(fields_list)
    sample_doc_str = await _get_sample_docs(index_pattern, requirement)
    
    sys_prompt = (
        "You are an expert at fixing OpenSearch Dashboards visualization JSON plans.\n"
        "The previous plan failed field validation. You must fix the fields based on the valid available fields.\n\n"
        "Rules:\n"
        "- Output ONLY valid JSON object representing the fixed plan.\n"
        "- CRITICAL INSTRUCTION: Your entire response must consist solely of the JSON object. Do not include any explanations, tutorial steps, or markdown formatting.\n"
        f"- Here is the validation error: {validation_msg}\n"
        f"- ONLY use these available fields: {fields_str}\n"
        "- If the query filter might be too strict, make the KQL query more lenient by using wildcards (e.g., `rule.groups: *auth*`).\n"
        "- Keep the rest of the plan intact if possible.\n"
    )
    
    user = (
        f"Index pattern: {index_pattern}\n"
        f"Requirement: {requirement}\n"
        f"Sample Document: {sample_doc_str}\n"
        f"Previous Plan: {json.dumps(plan)}\n"
        "Return the corrected JSON plan:"
    )
    
    msg = await asyncio.to_thread(llm.invoke, sys_prompt + "\n" + user)
    raw = getattr(msg, "content", "") or ""
    
    try:
        fixed_plan = json.loads(_last_json_block(raw))
    except Exception:
        return plan # fallback if LLM fails

    # Ensure defaults are maintained
    fixed_plan.setdefault("query", plan.get("query", ""))
    fixed_plan.setdefault("time_from", plan.get("time_from", "now-1d"))
    fixed_plan.setdefault("time_to", plan.get("time_to", "now"))
    fixed_plan.setdefault("top_n", plan.get("top_n", 5))
    fixed_plan.setdefault("interval", plan.get("interval", "auto"))
    if plan.get("viz_title"):
        fixed_plan.setdefault("viz_title", plan.get("viz_title"))
    if plan.get("viz_type"):
        fixed_plan.setdefault("viz_type", plan.get("viz_type"))

    return fixed_plan

async def llm_generate_full_dashboard_plan(index_pattern: str, requirement: str) -> List[Dict[str, Any]]:
    llm = _build_llm()
    fields_list = await get_all_fields_for_index(index_pattern)
    fields_str = ", ".join(fields_list)
    sample_doc_str = await _get_sample_docs(index_pattern, requirement)
    
    sys_prompt = (
        "You are generating a JSON array of configuration plans for a highly tailored OpenSearch Dashboard.\n"
        "The user will describe a use case (like 'brute force attack dashboard' or 'Google Cloud Alerts').\n"
        "CRITICAL: Do NOT just generate generic 'Total Count' or 'Top Source IPs' charts for every request. You MUST carefully analyze the provided 'Sample Document' and select the most unique, informative, and relevant fields for THAT specific log type. Create 5 to 8 highly specific visualizations.\n\n"
        "Rules:\n"
        "- Output ONLY a valid JSON Array of objects.\n"
        "- CRITICAL INSTRUCTION: Your entire response must consist solely of the JSON array. Do not include any explanations, tutorial steps, or markdown formatting.\n"
        "- You MUST include at least one 'table' visualization in every dashboard to show raw details, using the most relevant specific fields for the log type (e.g., 'data.gcp.resource.name' or 'syscheck.path' instead of generic 'agent.name').\n"
        "- Vary the `viz_type` (e.g. pie, bar, table, line, metric). Use 'map' ONLY if geographic data is highly relevant to the logs.\n"
        "- Be highly creative and specific. If the logs are GCP, show Top GCP Severities, Top Resources, Affected Users, etc. If it's FIM, show Top File Paths, File Actions, etc. Use the sample document to find the absolute best fields!\n"
        "- CRITICAL FIELD MATCHING: Do NOT hallucinate fields or mix fields from different platforms! If the topic is 'office365', ONLY use 'data.office365.*' fields. If 'aws', use 'data.aws.*'. ALWAYS cross-reference the exact field names with the 'Sample Document'!\n"
        "- CRITICAL RULE FOR FILTERING: If the index is generic (like 'wazuh-alerts-*'), you MUST add a KQL `query` filter to EVERY visualization to restrict the data to the requested topic. You MUST base this filter on `rule.groups` (e.g., `rule.groups: *office365*`, `rule.groups: *gcp*`, `rule.groups: *syscheck*`). WARNING: The 'Sample Document' might contain red herrings (like an 'Active Window' log showing the user's browser title). IGNORE active window logs unless specifically requested! Force the query to filter the actual log group!\n"
        "- Use highly descriptive and specific titles (e.g., 'Top GCP Resources Accessed', 'Authentication Failures Timeline', 'Most Modified File Paths').\n"
        "- `time_from`/`time_to` should be relative strings like 'now-24h' and 'now', unless specified otherwise.\n"
        "- For pie/bar: specify the top-level 'field' to aggregate on (e.g. 'agent.name', 'data.srcip', 'data.srcuser', 'rule.description').\n"
        "- For metric: omit 'field' for a total document count. To count unique values (e.g. unique IPs), specify the 'field' property.\n"
        "- For table: specify a list of string fields in 'table_fields' (e.g. ['agent.name', 'data.srcip', 'rule.description']). Do NOT include time fields like '@timestamp'.\n"
        "- For map: specify 'field' as exactly 'GeoLocation.location' (the native Wazuh geo_point field).\n"
        "- For line: specify 'split_field' if you want multiple series lines.\n"
        "- For layout: specify `grid_w` (width, 1 to 48) and `grid_h` (height). IMPORTANT to avoid empty space and overstretching:\n"
        "   * Metrics MUST be very short (grid_h: 6 to 8). You can make them wide (grid_w: 48) or place multiple metrics side-by-side.\n"
        "   * Pie/Bar charts should be medium size (grid_w: 24, grid_h: 12 to 14).\n"
        "   * Line/Area graphs should be wide but NOT tall (grid_w: 48, grid_h: 12 to 14).\n"
        "   * Maps should be (grid_w: 24, grid_h: 14) or (grid_w: 48, grid_h: 14).\n"
        "   * Tables should be wide (grid_w: 48, grid_h: 15 to 18).\n"
        "   * Try to keep elements in the same row the same height so no blank vertical spaces appear.\n"
        f"- Prefer these fields (if relevant): {fields_str}\n"
        "- Return ONLY the JSON Array.\n"
        "\n"
        "Example payload:\n"
        "[\n"
        "  {\"viz_title\": \"Timeline of Activity\", \"viz_type\": \"line\", \"query\": \"rule.groups: authentication_failed\", \"time_from\": \"now-24h\", \"time_to\": \"now\", \"grid_w\": 48, \"grid_h\": 16},\n"
        "  {\"viz_title\": \"Recent Alerts\", \"viz_type\": \"table\", \"table_fields\": [\"agent.name\", \"data.srcip\", \"rule.description\", \"data.srcuser\"], \"top_n\": 10, \"query\": \"rule.groups: authentication_failed\", \"time_from\": \"now-24h\", \"time_to\": \"now\", \"grid_w\": 48, \"grid_h\": 20}\n"
        "]"
    )

    user = (
        f"Index pattern: {index_pattern}\n"
        f"Design a full multi-visualization dashboard for this requirement:\n{requirement}\n"
        f"Sample Document: {sample_doc_str}\n"
    )

    msg = await asyncio.to_thread(llm.invoke, sys_prompt + "\n" + user)
    raw = getattr(msg, "content", "") or ""
    
    plans = json.loads(_last_json_block(raw))
    if not isinstance(plans, list):
        raise ValueError("LLM did not return a JSON array of plans.")
        
    for plan in plans:
        plan.setdefault("query", "")
        plan.setdefault("time_from", "now-24h")
        plan.setdefault("time_to", "now")
        plan.setdefault("top_n", 5)
        plan.setdefault("interval", "auto")

        viz_type = str(plan.get("viz_type", "pie")).lower()
        if viz_type in ("pie", "bar") and not plan.get("field"):
            plan["field"] = "agent.name"
        if viz_type == "table" and not plan.get("table_fields") and not plan.get("field"):
            plan["table_fields"] = ["agent.name", "rule.description"]
        if viz_type == "map":
            plan["field"] = "GeoLocation.location"
        if viz_type == "line":
            plan.setdefault("split_field", None)
            plan.setdefault("split_top_n", int(plan.get("top_n") or 5))

    has_table = any(str(p.get("viz_type")).lower() == "table" for p in plans)
    if not has_table:
        plans.append({
            "viz_title": "Recent Alerts (Details)",
            "viz_type": "table",
            "table_fields": ["agent.name", "data.srcip", "data.srcuser", "rule.description"],
            "top_n": 50,
            "query": plans[0].get("query", ""),
            "time_from": plans[0].get("time_from", "now-24h"),
            "time_to": plans[0].get("time_to", "now"),
            "interval": "auto"
        })
            
    return plans
