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
    get_all_fields_for_index
)

def _last_json_block(text: str) -> str:
    m = re.search(r"\{.*\}\s*$", text or "", re.S)
    return m.group(0) if m else (text or "").strip()

def field_exists_in_field_caps(caps: Dict[str, Any], field: str) -> bool:
    f = (caps.get("fields") or {}).get(field)
    if not f:
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
        vis_state = {
            "title": title,
            "type": "metric",
            "params": {
                "addTooltip": True,
            },
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            ],
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
                "showPartialRows": False,
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

def build_multi_dashboard_payload(title: str, vis_ids: List[str]) -> Dict[str, Any]:
    panels = []
    references = []
    
    # Simple grid layout logic (2 columns wide, 48 grid units available total)
    x, y = 0, 0
    w, h = 48, 15 # default full width
    
    if len(vis_ids) > 1:
        w = 24 # split into 2 columns if multiple charts

    for i, vis_id in enumerate(vis_ids):
        panel_id = str(uuid.uuid4())
        
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
        
        x += w
        if x >= 48:
            x = 0
            y += h

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

async def llm_generate_full_dashboard_plan(index_pattern: str, requirement: str) -> List[Dict[str, Any]]:
    llm = _build_llm()
    fields_list = await get_all_fields_for_index(index_pattern)
    fields_str = ", ".join(fields_list)
    
    sys_prompt = (
        "You are generating a JSON array of configuration plans for a comprehensive OpenSearch Dashboard.\n"
        "The user will describe a use case (like 'brute force attack dashboard'). You must generate 4 to 6 different "
        "visualizations that give a full picture of the data for this requirement.\n\n"
        "Rules:\n"
        "- Output ONLY a valid JSON Array of objects.\n"
        "- You MUST include at least one 'table' visualization in every dashboard to show raw details.\n"
        "- Vary the `viz_type` (e.g. at least one 'pie', 'bar', 'table', 'line', 'metric'). You may include at most ONE 'map' visualization.\n"
        "- The 'query' MUST contain KQL filtering if the requirement demands it (e.g. `rule.mitre.tactic: \"Brute Force\"` or `rule.groups: \"sshd\"`), but leave it as `\"\"` for general views without a specific filter.\n"
        "- Use proper titles. e.g for brute force: 'Top Source IPs', 'Timeline', 'Targeted Agents Details'.\n"
        "- `time_from`/`time_to` should be relative strings like 'now-7d' and 'now', unless specified otherwise.\n"
        "- For pie/bar: specify the top-level 'field' to aggregate on (e.g. 'agent.name', 'data.srcip', 'data.srcuser', 'rule.description').\n"
        "- For table: specify a list of string fields in 'table_fields' (e.g. ['agent.name', 'data.srcip', 'rule.description']). Do NOT include time fields like '@timestamp'.\n"
        "- For map: specify 'field' as exactly 'GeoLocation.location' (the native Wazuh geo_point field).\n"
        "- For line: specify 'split_field' if you want multiple series lines.\n"
        f"- Prefer these fields (if relevant): {fields_str}\n"
        "- Return ONLY the JSON Array.\n"
        "\n"
        "Example payload:\n"
        "[\n"
        "  {\"viz_title\": \"Timeline of Activity\", \"viz_type\": \"line\", \"query\": \"rule.groups: authentication_failed\", \"time_from\": \"now-24h\", \"time_to\": \"now\"},\n"
        "  {\"viz_title\": \"Recent Alerts\", \"viz_type\": \"table\", \"table_fields\": [\"agent.name\", \"data.srcip\", \"rule.description\", \"data.srcuser\"], \"top_n\": 10, \"query\": \"rule.groups: authentication_failed\", \"time_from\": \"now-24h\", \"time_to\": \"now\"}\n"
        "]"
    )

    user = (
        f"Index pattern: {index_pattern}\n"
        f"Design a full multi-visualization dashboard for this requirement:\n{requirement}\n"
    )

    msg = await asyncio.to_thread(llm.invoke, sys_prompt + "\n" + user)
    raw = getattr(msg, "content", "") or ""
    
    plans = json.loads(_last_json_block(raw))
    if not isinstance(plans, list):
        raise ValueError("LLM did not return a JSON array of plans.")
        
    for plan in plans:
        plan.setdefault("query", "")
        plan.setdefault("time_from", "now-7d")
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
            "time_from": plans[0].get("time_from", "now-7d"),
            "time_to": plans[0].get("time_to", "now"),
            "interval": "auto"
        })
            
    return plans
