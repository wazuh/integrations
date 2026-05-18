import httpx
import json
import time
from typing import Optional, Any, Dict, List, Tuple, Union
from .config import (
    OPENSEARCH_DASHBOARD_URL, OPENSEARCH_DASHBOARD_USER, OPENSEARCH_DASHBOARD_PASS, OPENSEARCH_DASHBOARD_VERIFY_TLS,
    OPENSEARCH_DASHBOARD_CA_FILE, OPENSEARCH_DASHBOARD_BASEPATH, OPENSEARCH_DASHBOARD_SPACE,
    WAZUH_INDEXER_URL, WAZUH_INDEXER_USER, WAZUH_INDEXER_PASS, WAZUH_INDEXER_VERIFY_TLS, WAZUH_INDEXER_CA_FILE
)

def _norm_path(p: str) -> str:
    if not p:
        return ""
    p = p.strip()
    if not p.startswith("/"):
        p = "/" + p
    return p.rstrip("/")

def _osd_api_prefix() -> str:
    basepath = _norm_path(OPENSEARCH_DASHBOARD_BASEPATH)
    space = OPENSEARCH_DASHBOARD_SPACE.strip()
    space_part = f"/s/{space}" if space else ""
    return f"{OPENSEARCH_DASHBOARD_URL}{basepath}{space_part}"

def _ensure_osd_configured() -> None:
    if not (OPENSEARCH_DASHBOARD_URL and OPENSEARCH_DASHBOARD_USER and OPENSEARCH_DASHBOARD_PASS):
        raise RuntimeError("OpenSearch Dashboards not configured (OPENSEARCH_DASHBOARD_* env vars missing).")

def _tls_verify_value(default_bool: bool, ca_file: str) -> Union[bool, str]:
    if ca_file:
        return ca_file
    return default_bool

async def osd_request(method: str, path: str, *, json_body=None, params=None) -> Tuple[int, str]:
    _ensure_osd_configured()
    if not path.startswith("/"):
        path = "/" + path
    url = _osd_api_prefix() + path
    headers = {"osd-xsrf": "true", "Content-Type": "application/json"}

    verify_val = _tls_verify_value(OPENSEARCH_DASHBOARD_VERIFY_TLS, OPENSEARCH_DASHBOARD_CA_FILE)
    async with httpx.AsyncClient(verify=verify_val, timeout=60) as client:
        r = await client.request(
            method,
            url,
            auth=(OPENSEARCH_DASHBOARD_USER, OPENSEARCH_DASHBOARD_PASS),
            headers=headers,
            params=params,
            json=json_body,
        )
        return r.status_code, r.text

async def osd_find_index_pattern_id_by_title(title: str) -> Optional[str]:
    params = {
        "type": "index-pattern",
        "per_page": "100",
        "search_fields": "title",
        "search": title,
    }
    sc, txt = await osd_request("GET", "/api/saved_objects/_find", params=params)
    if sc != 200:
        return None
    try:
        data = json.loads(txt)
        objs = data.get("saved_objects") or []
        for o in objs:
            attrs = (o.get("attributes") or {})
            if str(attrs.get("title")) == title:
                return str(o.get("id"))
    except Exception:
        return None
    return None

async def osd_create_index_pattern(title: str, time_field: Optional[str]) -> Tuple[bool, str]:
    payload = {"attributes": {"title": title}}
    if time_field:
        payload["attributes"]["timeFieldName"] = time_field
    sc, txt = await osd_request("POST", "/api/saved_objects/index-pattern?overwrite=true", json_body=payload)
    if 200 <= sc < 300:
        try:
            j = json.loads(txt)
            return True, str(j.get("id") or "")
        except Exception:
            return True, ""
    return False, f"status={sc} raw={txt}"

def _indexer_configured() -> bool:
    return bool(WAZUH_INDEXER_URL and WAZUH_INDEXER_USER and WAZUH_INDEXER_PASS)

async def indexer_request(method: str, path: str, *, json_body=None, params=None) -> Tuple[int, str]:
    if not _indexer_configured():
        raise RuntimeError("Indexer not configured (WAZUH_INDEXER_* env vars missing).")
    if not path.startswith("/"):
        path = "/" + path
    url = WAZUH_INDEXER_URL + path
    verify_val = _tls_verify_value(WAZUH_INDEXER_VERIFY_TLS, WAZUH_INDEXER_CA_FILE)
    async with httpx.AsyncClient(verify=verify_val, timeout=30) as client:
        r = await client.request(
            method,
            url,
            auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASS),
            params=params,
            json=json_body,
        )
        return r.status_code, r.text

async def indexer_cat_indices(pattern: str = "wazuh-*") -> List[str]:
    sc, txt = await indexer_request("GET", f"/_cat/indices/{pattern}", params={"format": "json"})
    if sc != 200:
        return []
    try:
        rows = json.loads(txt)
        out = []
        for r in rows:
            idx = r.get("index")
            if idx:
                out.append(str(idx))
        return out
    except Exception:
        return []

async def indexer_field_caps(index: str, fields: List[str]) -> Dict[str, Any]:
    sc, txt = await indexer_request("GET", f"/{index}/_field_caps", params={"fields": ",".join(fields)})
    if sc != 200:
        raise RuntimeError(f"field_caps failed: http={sc} body={txt[:300]}")
    return json.loads(txt)

_INDEX_FIELDS_CACHE: Dict[str, Tuple[float, List[str]]] = {}
_CACHE_TTL = 3600

async def get_all_fields_for_index(index_pattern: str) -> List[str]:
    now = time.time()
    if index_pattern in _INDEX_FIELDS_CACHE:
        ts, cached_fields = _INDEX_FIELDS_CACHE[index_pattern]
        if now - ts < _CACHE_TTL:
            return cached_fields

    try:
        sc, txt = await indexer_request("GET", f"/{index_pattern}/_field_caps?fields=*")
        if sc == 200:
            data = json.loads(txt)
            good_fields = []
            for f, details in data.get("fields", {}).items():
                is_good = False
                for k, v in details.items():
                    if v.get("searchable") and (k in ["keyword", "ip", "boolean", "long", "integer", "float", "double", "date"]):
                        is_good = True
                    if k == "text" and not details.get("keyword"):
                        is_good = True
                if is_good and not f.startswith("_"):
                    good_fields.append(f)
            good_fields.sort()
            if good_fields:
                _INDEX_FIELDS_CACHE[index_pattern] = (now, good_fields)
                return good_fields
    except Exception:
        pass

    return [
        "agent.name", "agent.id", "rule.id", "rule.level", "rule.groups",
        "rule.description", "data.srcip", "data.dstip", "@timestamp", "timestamp"
    ]
