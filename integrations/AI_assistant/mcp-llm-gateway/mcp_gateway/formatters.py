import re
from datetime import datetime, timezone
from typing import Optional, Any, Dict, List, Tuple

_TIMEFRAME_TOKEN_RE = re.compile(r"(\d+)\s*([smhdwSMHDW])")

def _parse_timeframe_to_seconds(tf: str) -> int:
    tf = (tf or "").strip()
    if not tf:
        return 0
    total = 0
    for num_s, unit in _TIMEFRAME_TOKEN_RE.findall(tf):
        n = int(num_s)
        u = unit.lower()
        if u == "s":
            total += n
        elif u == "m":
            total += n * 60
        elif u == "h":
            total += n * 3600
        elif u == "d":
            total += n * 86400
        elif u == "w":
            total += n * 7 * 86400
    return total

def _parse_wazuh_iso(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None

def _fmt_age(seconds: int) -> str:
    if seconds < 0:
        seconds = 0
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    if m:
        parts.append(f"{m}m")
    if s or not parts:
        parts.append(f"{s}s")
    return "".join(parts)

def format_disconnected_candidates(cands: List[Dict[str, Any]], tf_str: str) -> str:
    lines = [f"Disconnected agents older_than {tf_str}:"]
    for c in cands:
        lines.append(
            f"- {c['id']}  {c['name']}  disconnected_since={c['disconnection_time']}  age={c['age_human']}"
        )
    return "\n".join(lines)

def _api_reason(resp: Dict[str, Any]) -> str:
    if not isinstance(resp, dict):
        return ""
    return str(resp.get("message") or ((resp.get("data") or {}).get("message")) or "").strip()

def format_restart_agent_result(agent_id: str, api_response: Dict[str, Any]) -> str:
    if not isinstance(api_response, dict):
        return f"Agent {agent_id} restart failed (invalid API response)."
    err = api_response.get("error")
    if err == 0:
        return f"Restart command sent for agent {agent_id}."
    reason = _api_reason(api_response)
    out = f"Agent {agent_id} restart failed (API error={err})."
    if reason:
        out += f" Reason: {reason}"
    return out

def format_delete_agents_result(label: str, api_response: Dict[str, Any]) -> str:
    if not isinstance(api_response, dict):
        return f"{label}: deletion failed (invalid API response)."
    err = api_response.get("error")
    reason = _api_reason(api_response)
    if err == 0:
        data = api_response.get("data") or {}
        affected = data.get("affected_items") or []
        return f"{label}: deleted {len(affected)} agent(s): {', '.join([str(x) for x in affected])}"
    out = f"{label}: deletion failed (API error={err})."
    if reason:
        out += f" Reason: {reason}"
    return out

def format_assign_group_result(group_id: str, results: List[Tuple[str, Dict[str, Any]]]) -> str:
    ok, fail = [], []
    for aid, resp in results:
        if isinstance(resp, dict) and resp.get("error") == 0:
            ok.append(aid)
        else:
            reason = _api_reason(resp)
            err = resp.get("error") if isinstance(resp, dict) else "unknown"
            fail.append((aid, reason or f"error={err}"))
    out = [f"Group assignment to '{group_id}' completed."]
    if ok:
        out.append(f"Assigned: {', '.join(ok)}")
    if fail:
        out.append("Failed:")
        for aid, why in fail:
            out.append(f"- {aid}: {why}")
    return "\n".join(out)

def format_remove_group_result(group_id: str, results: List[Tuple[str, Dict[str, Any]]]) -> str:
    ok, fail = [], []
    for aid, resp in results:
        if isinstance(resp, dict) and resp.get("error") == 0:
            ok.append(aid)
        else:
            reason = _api_reason(resp)
            err = resp.get("error") if isinstance(resp, dict) else "unknown"
            fail.append((aid, reason or f"error={err}"))
    out = [f"Removal from group '{group_id}' completed."]
    if ok:
        out.append(f"Removed: {', '.join(ok)}")
    if fail:
        out.append("Failed:")
        for aid, why in fail:
            out.append(f"- {aid}: {why}")
    return "\n".join(out)
