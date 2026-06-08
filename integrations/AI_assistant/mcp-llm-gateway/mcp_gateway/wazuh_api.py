import time
import httpx
from typing import Optional, Any, Dict, List
from .config import (
    STAGING_WAZUH_API_URL, STAGING_WAZUH_API_USER, STAGING_WAZUH_API_PASS, STAGING_WAZUH_API_VERIFY_TLS,
    WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASS, WAZUH_API_VERIFY_TLS,
    AGENTS_CACHE_TTL
)
from .state import _AGENTS_CACHE, _AGENTS_CACHE_LOCK, AgentsCache

class WazuhAPI:
    def __init__(self, base: str, user: str, password: str, verify_tls: bool):
        if not (base and user and password):
            raise RuntimeError("Wazuh API base/user/password not configured.")
        self.base = base.rstrip("/")
        self.user = user
        self.password = password
        self.verify = verify_tls
        self._token: Optional[str] = None
        self._token_ts: float = 0.0

    async def _get_token(self) -> str:
        if self._token and (time.time() - self._token_ts) < 720:
            return self._token

        url = f"{self.base}/security/user/authenticate"
        async with httpx.AsyncClient(verify=self.verify, timeout=30) as client:
            r = await client.get(url, auth=(self.user, self.password))
            r.raise_for_status()
            data = r.json()
            token = (data.get("data") or {}).get("token")
            if not token:
                raise RuntimeError("Failed to obtain JWT token from Wazuh API.")
            self._token = token
            self._token_ts = time.time()
            return token

    async def request(self, method: str, path: str, *, params=None, json_body=None, content=None, headers=None) -> Dict[str, Any]:
        token = await self._get_token()
        h = {"Authorization": f"Bearer {token}"}
        if headers:
            h.update(headers)
        url = f"{self.base}{path}"
        async with httpx.AsyncClient(verify=self.verify, timeout=180) as client:
            r = await client.request(method, url, params=params, json=json_body, content=content, headers=h)
        try:
            return r.json()
        except Exception:
            return {"http_status": r.status_code, "text": r.text}

def _stg_api() -> Optional[WazuhAPI]:
    if not (STAGING_WAZUH_API_URL and STAGING_WAZUH_API_USER and STAGING_WAZUH_API_PASS):
        return None
    return WazuhAPI(STAGING_WAZUH_API_URL, STAGING_WAZUH_API_USER, STAGING_WAZUH_API_PASS, STAGING_WAZUH_API_VERIFY_TLS)

def _prod_api() -> Optional[WazuhAPI]:
    if not (WAZUH_API_URL and WAZUH_API_USER and WAZUH_API_PASS):
        return None
    return WazuhAPI(WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASS, WAZUH_API_VERIFY_TLS)


async def wazuh_list_agents(api: WazuhAPI, limit: int = 5000) -> Dict[str, Any]:
    return await api.request(
        "GET",
        "/agents",
        params={"limit": str(limit), "select": "id,name,status,group,disconnection_time,lastKeepAlive"},
        headers={"Content-Type": "application/json"},
    )

async def wazuh_restart_agent(api: WazuhAPI, agent_id: str) -> Dict[str, Any]:
    return await api.request("PUT", f"/agents/{agent_id}/restart", headers={"Content-Type": "application/json"})

async def wazuh_delete_agents_bulk(api: WazuhAPI, *, agents_list: str, status: str, older_than: str) -> Dict[str, Any]:
    return await api.request(
        "DELETE",
        "/agents",
        params={"older_than": older_than, "agents_list": agents_list, "status": status},
        headers={"Content-Type": "application/json"},
    )

async def wazuh_list_groups(api: WazuhAPI) -> Dict[str, Any]:
    return await api.request("GET", "/groups", headers={"Content-Type": "application/json"})

async def wazuh_assign_agent_to_group(api: WazuhAPI, agent_id: str, group_id: str) -> Dict[str, Any]:
    return await api.request("PUT", f"/agents/{agent_id}/group/{group_id}", headers={"Content-Type": "application/json"})

async def wazuh_remove_agent_from_group(api: WazuhAPI, agent_id: str, group_id: str) -> Dict[str, Any]:
    return await api.request("DELETE", f"/agents/{agent_id}/group/{group_id}", headers={"Content-Type": "application/json"})

def _agents_from_list(resp: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not isinstance(resp, dict) or resp.get("error") != 0:
        return []
    data = resp.get("data") or {}
    items = data.get("affected_items") or []
    return items if isinstance(items, list) else []

def _find_agent(agents: List[Dict[str, Any]], agent_id: str) -> Optional[Dict[str, Any]]:
    for a in agents:
        if str(a.get("id")) == str(agent_id):
            return a
    return None

def _agent_status(a: Dict[str, Any]) -> str:
    return str((a or {}).get("status", "unknown")).lower()

async def _get_agents(api: WazuhAPI) -> List[Dict[str, Any]]:
    if AGENTS_CACHE_TTL <= 0:
        return _agents_from_list(await wazuh_list_agents(api))

    key = api.base
    now = time.time()
    async with _AGENTS_CACHE_LOCK:
        c = _AGENTS_CACHE.get(key)
        if c and (now - c.ts) <= AGENTS_CACHE_TTL:
            return c.agents

    agents = _agents_from_list(await wazuh_list_agents(api))
    async with _AGENTS_CACHE_LOCK:
        _AGENTS_CACHE[key] = AgentsCache(ts=now, agents=agents)
    return agents
