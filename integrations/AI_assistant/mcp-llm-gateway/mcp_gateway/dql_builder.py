import json
import re
import asyncio
from urllib.parse import quote
from typing import Optional, Dict

from .config import (
	ALERTS_INDEX,
	OPENSEARCH_DASHBOARD_URL,
	OPENSEARCH_DASHBOARD_BASEPATH,
	OPENSEARCH_DASHBOARD_SPACE,
)
from .llm import _build_llm
from .prompts import DQL_PROMPT

_DISCOVER_AGENT_FILTER = re.compile(
	r"\bfilter\b.*\balerts?\b.*\blast\s+(?P<n>\d{1,4})\s*"
	r"(?P<u>m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days|w|week|weeks)\b"
	r".*\bagent[._\s-]*id\b\s*[:=]?\s*(?P<agents>\d{1,6}(?:\s*(?:,|\bor\b|\band\b(?=\s*\d))\s*\d{1,6})*)",
	re.I,
)


def _last_json_block(text: str) -> str:
	m = re.search(r"\{.*\}\s*$", text or "", re.S)
	return m.group(0) if m else (text or "").strip()


def _norm_path(p: str) -> str:
	if not p:
		return ""
	p = p.strip()
	if not p.startswith("/"):
		p = "/" + p
	return p.rstrip("/")


def _discover_base_url() -> str:
	basepath = _norm_path(OPENSEARCH_DASHBOARD_BASEPATH)
	space = OPENSEARCH_DASHBOARD_SPACE.strip()
	space_part = f"/s/{space}" if space else ""
	return f"{OPENSEARCH_DASHBOARD_URL}{basepath}{space_part}"


def _unit_to_short(unit: str) -> str:
	u = (unit or "").lower()
	if u in ("m", "min", "mins", "minute", "minutes"):
		return "m"
	if u in ("h", "hr", "hrs", "hour", "hours"):
		return "h"
	if u in ("d", "day", "days"):
		return "d"
	if u in ("w", "week", "weeks"):
		return "w"
	return "m"


def _build_discover_link(index_pattern: str, time_from: str, time_to: str, kql: str) -> str:
	kql_encoded = quote(kql, safe=":._-*()'\" ")
	kql_encoded = kql_encoded.replace(" ", "%20")
	base = _discover_base_url()
	return (
		f"{base}/app/data-explorer/discover"
		f"#?_a=(discover:(columns:!(_source),isDirty:!f,sort:!()),metadata:(indexPattern:'{index_pattern}',view:discover))"
		f"&_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:{time_from},to:{time_to}))"
		f"&_q=(filters:!(),query:(language:kuery,query:'{kql_encoded}'))"
	)


def _parse_agent_ids(raw_agents: str) -> list[str]:
	s = (raw_agents or "").strip()
	if not s:
		return []
	parts = re.split(r"\s*(?:,|\bor\b|\band\b)\s*", s, flags=re.I)
	out = []
	seen = set()
	for p in parts:
		v = p.strip().strip("'\"")
		if not v or v.lower() in ("or", "and"):
			continue
		if v not in seen:
			seen.add(v)
			out.append(v)
	return out


def _build_agent_or_kql(agent_ids: list[str]) -> str:
	if len(agent_ids) == 1:
		return f"agent.id: {agent_ids[0]}"
	return " or ".join([f"(agent.id: {aid})" for aid in agent_ids])

def _prefer_llm_first(user_prompt: str) -> bool:
	s = (user_prompt or "").lower()
	if any(op in s for op in (">=", "<=", " > ", " < ")):
		return True
	complex_markers = (
		"rule level",
		"rule.id",
		"rule id",
		"rule groups",
		"rule group",
		"not ",
		" except ",
	)
	return any(m in s for m in complex_markers)


def _from_regex(user_prompt: str) -> Optional[Dict[str, str]]:
	m = _DISCOVER_AGENT_FILTER.search(user_prompt or "")
	if not m:
		return None

	n = int(m.group("n") or 30)
	n = n if n > 0 else 30
	unit = _unit_to_short(m.group("u") or "m")
	time_from = f"now-{n}{unit}"

	agent_ids = _parse_agent_ids(m.group("agents") or "")
	if not agent_ids:
		return None

	return {
		"index_pattern": ALERTS_INDEX or "wazuh-alerts-*",
		"time_from": time_from,
		"time_to": "now",
		"kql": _build_agent_or_kql(agent_ids),
	}


async def _from_llm(user_prompt: str) -> Optional[Dict[str, str]]:
	llm = _build_llm()
	prompt = (
		DQL_PROMPT
		+ "\n\nUser request:\n"
		+ user_prompt.strip()
		+ "\n\nReturn JSON only."
	)
	msg = await asyncio.to_thread(llm.invoke, prompt)
	raw = getattr(msg, "content", "") or ""
	data = json.loads(_last_json_block(raw))

	index_pattern = str(data.get("index_pattern") or ALERTS_INDEX or "wazuh-alerts-*").strip()
	time_from = str(data.get("time_from") or "now-30m").strip()
	time_to = str(data.get("time_to") or "now").strip()
	kql = str(data.get("kql") or "").strip()

	if not kql:
		return None
	if not index_pattern:
		index_pattern = "wazuh-alerts-*"

	return {
		"index_pattern": index_pattern,
		"time_from": time_from,
		"time_to": time_to,
		"kql": kql,
	}


async def try_build_discover_filter_link(user_prompt: str) -> Optional[str]:
	s = (user_prompt or "").strip()
	if not s:
		return None
	if "filter" not in s.lower() or "alert" not in s.lower():
		return None

	spec = None
	if _prefer_llm_first(s):
		try:
			spec = await _from_llm(s)
		except Exception:
			spec = None
		if not spec:
			spec = _from_regex(s)
	else:
		spec = _from_regex(s)
		if not spec:
			try:
				spec = await _from_llm(s)
			except Exception:
				spec = None


	if not spec:
		return None

	if not OPENSEARCH_DASHBOARD_URL:
		return (
			"Discover filter parsed, but OPENSEARCH_DASHBOARD_URL is missing.\n"
			f"KQL: {spec['kql']}\n"
			f"Time: {spec['time_from']} to {spec['time_to']}\n"
			f"Index pattern: {spec['index_pattern']}"
		)

	url = _build_discover_link(
		spec["index_pattern"],
		spec["time_from"],
		spec["time_to"],
		spec["kql"],
	)
	return f"Here is your Discover link:\n{url}"


