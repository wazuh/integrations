import json
import re
import asyncio
import sys
from typing import Optional, Dict, Any, List

from .config import INVENTORY_INDEX, VERBOSE
from .opensearch_api import indexer_request, _indexer_configured
from .llm import _build_llm
from .prompts import INVENTORY_PROMPT

_INV_DOMAIN_WORDS = {
	"system", "operating", "os", "hardware", "software", "package", "packages", "vendor", "vendors",
	"process", "processes", "network", "interface", "interfaces", "traffic", "identity", "user", "users",
	"group", "groups", "installed", "endpoint", "endpoints", "host", "hosts", "agent",
}

_INV_ACTION_WORDS = {
	"analyze", "review", "monitor", "inspect", "view", "show", "list", "find", "which", "where", "what", "name",
	"check", "verify", "confirm",
}

_ALERT_QUERY_HINTS = {
	"alert", "alerts", "event", "events", "rule", "rules", "severity", "level", "fired", "triggered", "last alert",
}

_STRONG_INV_DOMAIN_WORDS = {
	"system", "operating", "os", "hardware", "software", "package", "packages", "vendor", "vendors",
	"process", "processes", "network", "interface", "interfaces", "traffic", "identity", "user", "users",
	"installed",
}

_STOPWORDS = {
	"the", "a", "an", "and", "or", "to", "for", "with", "from", "all", "last", "this", "that", "is", "are", "of", "in",
	"on", "by", "where", "what", "which", "name", "alerts", "alert", "endpoint", "endpoints",
}

_SEARCH_FIELDS = [
	"agent.name^4",
	"agent.id^2",
	"host.hostname^4",
	"host.name^3",
	"host.os.name^2",
	"host.os.version",
	"software.name^5",
	"software.vendor^2",
	"package.name^5",
	"package.vendor^2",
	"packages.name^5",
	"packages.vendor^2",
	"process.name^4",
	"process.command_line",
	"processes.name^4",
	"network.interface.name^2",
	"network.protocol",
	"user.name^2",
	"users.name^2",

]

_PRODUCT_PHRASE_FIELDS = [
	"package.name^10",
	"packages.name^10",
	"software.name^8",
	"process.name^4",
]

_OS_FIELDS = [
	"host.os.name^8",
	"host.os.version^8",
	"host.os.platform^4",
	"host.os.kernel.release^6",
]

_SOFTWARE_WILDCARD_FIELDS = [
	"software.name",
	"software.name.keyword",
	"package.name",
	"package.name.keyword",
	"packages.name",
	"packages.name.keyword",
	"software.vendor",
	"software.vendor.keyword",
	"package.vendor",
	"package.vendor.keyword",
	"packages.vendor",
	"packages.vendor.keyword",
]

_SOFTWARE_QUERY_STOPWORDS = {
	"which", "what", "where", "name", "agent", "endpoint", "endpoints", "host", "hosts",
	"how", "many", "agents",
	"has", "have", "had", "installed", "install", "is", "are", "the", "a", "an", "of", "in",
	"software", "package", "packages", "app", "application", "browser extensions",
}

_NOISY_SOFTWARE_NAME_PATTERNS = [
	r"\bietoedge\b",
	r"\bie_to_edge\b",
	r"\bbho\b",
	r"\bextension\b",
	r"\bedge\s+relevant\s+text\s+changes\b",
]

_SOFTWARE_SCOPE_KEYWORDS = {"software", "package", "packages", "app", "application", "browser extensions",}

_OS_PLATFORM_TERMS = {
	"windows", "linux", "ubuntu", "debian", "centos", "rhel", "redhat", "mac", "macos",
}

_AGENT_GROUP_CMD_PATTERNS = [
	r"\b(?:show|list|display)\b.*\bagent\s+groups?\b",
	r"\b(?:add|assign|move|put)\b.*\bagents?\b.*\b(?:to|into|in)\b.*\bgroup\b",
	r"\b(?:remove|delete)\b.*\bagents?\b.*\b(?:from)\b.*\bgroup\b",
]


def _dbg(message: str) -> None:
	if VERBOSE:
		print(f"[inventory_qa] {message}", file=sys.stderr)


def _extract_terms(user_prompt: str) -> List[str]:
	words = re.findall(r"[A-Za-z0-9_.-]+", (user_prompt or "").lower())
	out: List[str] = []
	seen = set()
	for w in words:
		if len(w) < 2:
			continue
		if w in _STOPWORDS:
			continue
		if w in _INV_DOMAIN_WORDS:
			continue
		if w in _INV_ACTION_WORDS:
			continue
		if w in {"has", "have", "installed", "install", "version"}:
			continue
		if w not in seen:
			seen.add(w)
			out.append(w)
	return out[:6]


def _extract_product_phrase(user_prompt: str) -> Optional[str]:
	s = (user_prompt or "").strip()
	if not s:
		return None

	patterns = [
		r"\bhas\s+(.+?)\s+installed\b",
		r"\bwhere\s+(.+?)\s+is\s+installed\b",
		r"\bwith\s+(.+?)\s+installed\b",
	]
	for p in patterns:
		m = re.search(p, s, flags=re.I)
		if not m:
			continue
		candidate = m.group(1).strip(" .,:;\"'")
		candidate = re.sub(r"^(the|a|an)\s+", "", candidate, flags=re.I)
		if candidate and len(candidate) >= 2:
			return candidate

	return None


def _extract_agent_ids(user_prompt: str) -> List[str]:
	ids = re.findall(r"\b\d{3,6}\b", user_prompt or "")
	out: List[str] = []
	seen = set()
	for i in ids:
		if i not in seen:
			seen.add(i)
			out.append(i)
	return out


def _expand_agent_id_variants(agent_ids: List[str]) -> List[str]:
	out: List[str] = []
	seen = set()
	for raw in agent_ids:
		s = str(raw).strip()
		if not s or not s.isdigit():
			continue
		variants = [s]
		try:
			num = int(s)
		except Exception:
			num = None
		if num is not None:
			variants.append(str(num))
			variants.append(f"{num:03d}")
		for v in variants:
			if v not in seen:
				seen.add(v)
				out.append(v)
	return out[:12]


async def _llm_search_spec(user_prompt: str) -> Optional[Dict[str, Any]]:
	llm = _build_llm()
	prompt = (
		"You create an OpenSearch inventory retrieval spec in JSON only.\n"
		"Return exactly this schema: {\"agent_ids\": [\"001\"], \"phrases\": [\"windows 11\", \"os version\"], \"terms\": [\"os\", \"version\"]}.\n"
		"Rules: include agent IDs if present; include short phrases for target attributes/software names; keep terms concise; no extra keys.\n\n"
		f"User question:\n{user_prompt.strip()}\n"
	)
	msg = await asyncio.to_thread(llm.invoke, prompt)
	raw = getattr(msg, "content", "") or ""
	m = re.search(r"\{.*\}\s*$", raw, re.S)
	if not m:
		return None
	data = json.loads(m.group(0))
	if not isinstance(data, dict):
		return None
	return data


async def _llm_validate_spec(user_prompt: str, draft_spec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
	llm = _build_llm()
	prompt = (
		"You validate and normalize an inventory retrieval JSON spec. Return JSON only with keys: "
		"agent_ids (array of strings), phrases (array of strings), terms (array of strings). "
		"Remove unsafe/irrelevant values and keep concise values.\n\n"
		f"User question:\n{user_prompt.strip()}\n\n"
		f"Draft spec:\n{json.dumps(draft_spec, ensure_ascii=False)}\n"
	)
	msg = await asyncio.to_thread(llm.invoke, prompt)
	raw = getattr(msg, "content", "") or ""
	m = re.search(r"\{.*\}\s*$", raw, re.S)
	if not m:
		return None
	data = json.loads(m.group(0))
	if not isinstance(data, dict):
		return None
	return data


def _sanitize_spec(spec: Optional[Dict[str, Any]], user_prompt: str, fallback_terms: List[str], product_phrase: Optional[str]) -> Dict[str, List[str]]:
	if not isinstance(spec, dict):
		spec = {}

	raw_agent_ids = spec.get("agent_ids") if isinstance(spec.get("agent_ids"), list) else []
	raw_phrases = spec.get("phrases") if isinstance(spec.get("phrases"), list) else []
	raw_terms = spec.get("terms") if isinstance(spec.get("terms"), list) else []

	agent_ids: List[str] = []
	seen_agent = set()
	for value in raw_agent_ids:
		s = str(value).strip()
		if not re.fullmatch(r"\d{1,6}", s):
			continue
		if s not in seen_agent:
			seen_agent.add(s)
			agent_ids.append(s)

	if not agent_ids:
		agent_ids = _extract_agent_ids(user_prompt)

	phrases: List[str] = []
	seen_phrase = set()
	for value in raw_phrases:
		s = str(value).strip()
		if len(s) < 2 or len(s) > 80:
			continue
		if s not in seen_phrase:
			seen_phrase.add(s)
			phrases.append(s)

	if product_phrase and product_phrase not in seen_phrase:
		phrases.append(product_phrase)

	terms: List[str] = []
	seen_term = set()
	for value in raw_terms:
		s = str(value).strip()
		if not re.fullmatch(r"[A-Za-z0-9_.-]{2,40}", s):
			continue
		if s.lower() in _STOPWORDS:
			continue
		if s not in seen_term:
			seen_term.add(s)
			terms.append(s)

	if not terms:
		terms = [t for t in fallback_terms if re.fullmatch(r"[A-Za-z0-9_.-]{2,40}", t)]

	return {
		"agent_ids": agent_ids[:5],
		"phrases": phrases[:6],
		"terms": terms[:8],
	}


def _build_query_from_spec(spec: Dict[str, Any], fallback_terms: List[str], product_phrase: Optional[str], user_prompt: str) -> Dict[str, Any]:
	agent_ids = [str(x) for x in (spec.get("agent_ids") or []) if str(x).strip()] if isinstance(spec, dict) else []
	phrases = [str(x).strip() for x in (spec.get("phrases") or []) if str(x).strip()] if isinstance(spec, dict) else []
	terms = [str(x).strip() for x in (spec.get("terms") or []) if str(x).strip()] if isinstance(spec, dict) else []

	if not agent_ids:
		agent_ids = _extract_agent_ids(user_prompt)
	agent_ids = _expand_agent_id_variants(agent_ids)
	if not terms:
		terms = fallback_terms
	if product_phrase and product_phrase not in phrases:
		phrases.append(product_phrase)

	filters: List[Dict[str, Any]] = []
	if agent_ids:
		filters.append({
			"bool": {
				"should": [
					{"terms": {"agent.id": agent_ids}},
					{"terms": {"agent.id.keyword": agent_ids}},
				],
				"minimum_should_match": 1,
			}
		})

	should: List[Dict[str, Any]] = []
	for p in phrases[:4]:
		should.append({
			"multi_match": {
				"query": p,
				"fields": _PRODUCT_PHRASE_FIELDS + _OS_FIELDS,
				"type": "phrase",
			}
		})

	if terms:
		should.append({
			"simple_query_string": {
				"query": " ".join(terms[:8]),
				"fields": _SEARCH_FIELDS + _OS_FIELDS,
				"default_operator": "or",
			}
		})

	bool_q: Dict[str, Any] = {"filter": filters}
	if should:
		bool_q["should"] = should
		if not filters:
			bool_q["minimum_should_match"] = 1

	return {"bool": bool_q}


def _build_relaxed_software_query(user_prompt: str, terms: List[str], product_phrase: Optional[str]) -> Dict[str, Any]:
	agent_ids = _expand_agent_id_variants(_extract_agent_ids(user_prompt))
	filters: List[Dict[str, Any]] = []
	if agent_ids:
		filters.append({
			"bool": {
				"should": [
					{"terms": {"agent.id": agent_ids}},
					{"terms": {"agent.id.keyword": agent_ids}},
				],
				"minimum_should_match": 1,
			}
		})

	candidates: List[str] = []
	seen = set()
	if product_phrase:
		p = product_phrase.strip()
		if p:
			candidates.append(p)
			seen.add(p.lower())
	for t in terms:
		ts = (t or "").strip()
		if not ts:
			continue
		key = ts.lower()
		if key in seen:
			continue
		seen.add(key)
		candidates.append(ts)

	should: List[Dict[str, Any]] = []
	for c in candidates[:8]:
		for field in _SOFTWARE_WILDCARD_FIELDS:
			should.append(
				{
					"wildcard": {
						field: {
							"value": f"*{c}*",
							"case_insensitive": True,
						}
					}
				}
			)

	bool_q: Dict[str, Any] = {"filter": filters, "should": should}
	if should:
		bool_q["minimum_should_match"] = 1
	return {"bool": bool_q}


def _is_software_install_question(user_prompt: str) -> bool:
	s = (user_prompt or "").lower()
	if not s:
		return False
	if "install" not in s:
		return False
	if re.search(r"\bhas\s+.+\s+installed\b", s):
		return True
	if re.search(r"\bis\s+.+\s+installed\b", s):
		return True
	return any(k in s for k in _SOFTWARE_SCOPE_KEYWORDS)


def _has_explicit_software_scope(user_prompt: str) -> bool:
	s = (user_prompt or "").lower()
	return any(k in s for k in _SOFTWARE_SCOPE_KEYWORDS)


def _is_os_inventory_count_question(user_prompt: str) -> bool:
	s = (user_prompt or "").lower()
	if "how many" not in s:
		return False
	if not any(w in s for w in ("agent", "agents", "endpoint", "endpoints", "host", "hosts")):
		return False
	if any(h in s for h in _ALERT_QUERY_HINTS):
		return False
	return any(t in s for t in _OS_PLATFORM_TERMS) or " os " in f" {s} " or "operating system" in s


def _extract_os_platform_filter(user_prompt: str) -> Optional[str]:
	s = (user_prompt or "").lower()
	for term in _OS_PLATFORM_TERMS:
		if term in s:
			return term
	return None


def _build_software_name_priority_query(user_prompt: str, terms: List[str], product_phrase: Optional[str]) -> Dict[str, Any]:
	agent_ids = _expand_agent_id_variants(_extract_agent_ids(user_prompt))
	filters: List[Dict[str, Any]] = []
	if agent_ids:
		filters.append({
			"bool": {
				"should": [
					{"terms": {"agent.id": agent_ids}},
					{"terms": {"agent.id.keyword": agent_ids}},
				],
				"minimum_should_match": 1,
			}
		})

	fields = [
		"software.name^12",
		"software.name.keyword^16",
		"package.name^12",
		"package.name.keyword^16",
		"packages.name^12",
		"packages.name.keyword^16",
	]

	should: List[Dict[str, Any]] = []
	if product_phrase:
		should.append(
			{
				"multi_match": {
					"query": product_phrase,
					"fields": fields,
					"type": "phrase",
				}
			}
		)

	for token in terms[:6]:
		for field in ["software.name", "package.name", "packages.name"]:
			should.append(
				{
					"wildcard": {
						field: {
							"value": f"*{token}*",
							"case_insensitive": True,
						}
					}
				}
			)

	bool_q: Dict[str, Any] = {"filter": filters, "should": should}
	if should:
		bool_q["minimum_should_match"] = 1
	return {"bool": bool_q}


def _tokenize_text(value: str) -> List[str]:
	return [t.lower() for t in re.findall(r"[A-Za-z0-9]+", value or "") if t]


def _target_software_tokens(user_prompt: str, product_phrase: Optional[str], terms: List[str]) -> List[str]:
	raw = product_phrase or user_prompt or ""
	tokens = _tokenize_text(raw)
	out: List[str] = []
	seen = set()
	for token in tokens:
		if len(token) < 2:
			continue
		if token in _SOFTWARE_QUERY_STOPWORDS:
			continue
		if token not in seen:
			seen.add(token)
			out.append(token)
	if not out:
		for term in terms:
			t = (term or "").strip().lower()
			if len(t) < 2 or t in _SOFTWARE_QUERY_STOPWORDS:
				continue
			if t not in seen:
				seen.add(t)
				out.append(t)
	return out[:4]


def _collect_names_from_inventory(src: Dict[str, Any], key: str) -> List[str]:
	obj = src.get(key)
	if obj is None:
		return []
	if isinstance(obj, dict):
		name = obj.get("name")
		return [str(name)] if isinstance(name, str) and name.strip() else []
	if isinstance(obj, list):
		out: List[str] = []
		for item in obj:
			if isinstance(item, dict):
				name = item.get("name")
				if isinstance(name, str) and name.strip():
					out.append(name)
			elif isinstance(item, str) and item.strip():
				out.append(item)
		return out
	if isinstance(obj, str) and obj.strip():
		return [obj]
	return []


def _extract_software_names(src: Dict[str, Any]) -> List[str]:
	names: List[str] = []
	for key in ("software", "package", "packages"):
		names.extend(_collect_names_from_inventory(src, key))

	seen = set()
	out: List[str] = []
	for name in names:
		n = str(name).strip()
		if not n:
			continue
		k = n.lower()
		if k in seen:
			continue
		seen.add(k)
		out.append(n)
	return out


def _is_noisy_software_name(name: str) -> bool:
	low = (name or "").lower()
	return any(re.search(p, low) for p in _NOISY_SOFTWARE_NAME_PATTERNS)


def _filter_hits_for_software_question(hits: List[Dict[str, Any]], user_prompt: str, product_phrase: Optional[str], terms: List[str]) -> List[Dict[str, Any]]:
	tokens = _target_software_tokens(user_prompt, product_phrase, terms)
	if not tokens:
		return hits

	filtered: List[Dict[str, Any]] = []
	for h in hits:
		src = h.get("_source") if isinstance(h, dict) else None
		if not isinstance(src, dict):
			continue

		names = _extract_software_names(src)
		if not names:
			continue

		name_tokens_list = [_tokenize_text(n) for n in names]
		matched_names: List[str] = []
		for idx, name_tokens in enumerate(name_tokens_list):
			if all(tok in name_tokens for tok in tokens):
				matched_names.append(names[idx])

		if not matched_names:
			continue

		if all(_is_noisy_software_name(n) for n in matched_names):
			continue

		filtered.append(h)

	return filtered


def _looks_like_inventory_query(user_prompt: str) -> bool:
	s = (user_prompt or "").lower()
	if not s:
		return False
	for p in _AGENT_GROUP_CMD_PATTERNS:
		if re.search(p, s, flags=re.I):
			return False
	if _is_os_inventory_count_question(user_prompt):
		return True
	if any(h in s for h in _ALERT_QUERY_HINTS):
		return False
	has_domain = any(w in s for w in _INV_DOMAIN_WORDS)
	has_strong_domain = any(w in s for w in _STRONG_INV_DOMAIN_WORDS)
	has_action = any(w in s for w in _INV_ACTION_WORDS)
	has_install_intent = ("install" in s or "installed" in s) and has_strong_domain
	if has_install_intent and has_domain:
		return True
	return has_domain and has_strong_domain and has_action


def _endpoint_name(src: Dict[str, Any]) -> str:
	agent = src.get("agent") if isinstance(src.get("agent"), dict) else {}
	host = src.get("host") if isinstance(src.get("host"), dict) else {}
	candidate = (
		str(host.get("hostname") or "").strip()
		or str(host.get("name") or "").strip()
		or str(agent.get("name") or "").strip()
		or str(agent.get("id") or "").strip()
		or "unknown-endpoint"
	)
	return candidate


def _trim_source(src: Dict[str, Any]) -> Dict[str, Any]:
	keep_keys = {
		"agent", "host", "hardware", "software", "package", "packages",
		"process", "processes", "network", "user", "users", "group", "groups", "GeoLocation",
	}
	out: Dict[str, Any] = {}
	for k in keep_keys:
		if k in src:
			out[k] = src[k]
	return out if out else src


def _is_os_question(user_prompt: str) -> bool:
	s = (user_prompt or "").lower()
	return (
		" os " in f" {s} "
		or "operating system" in s
		or "os version" in s
		or any(t in s for t in _OS_PLATFORM_TERMS)
	)


def _has_os_fields(src: Dict[str, Any]) -> bool:
	host = src.get("host") if isinstance(src.get("host"), dict) else {}
	os_obj = host.get("os") if isinstance(host.get("os"), dict) else {}
	if not isinstance(os_obj, dict):
		return False
	kernel = os_obj.get("kernel") if isinstance(os_obj.get("kernel"), dict) else {}
	return bool(
		os_obj.get("name")
		or os_obj.get("version")
		or os_obj.get("platform")
		or kernel.get("release")
	)


async def answer_inventory_query(user_prompt: str) -> Optional[str]:
	if not _looks_like_inventory_query(user_prompt):
		_dbg("skip: prompt not detected as inventory query")
		return None

	if _is_software_install_question(user_prompt) and not _has_explicit_software_scope(user_prompt):
		return (
			"Please rephrase your query by specifying the inventory scope keyword: package, app, or application.\n"
			"Example: Can you check if Agent 001 has Microsoft Teams package installed?"
		)

	_dbg(f"start: prompt={user_prompt!r}")

	if not _indexer_configured():
		_dbg("indexer not configured")
		return "Inventory query failed: Indexer is not configured (WAZUH_INDEXER_* env vars missing)."

	terms = _extract_terms(user_prompt)
	product_phrase = _extract_product_phrase(user_prompt)
	_dbg(f"extracted terms={terms} product_phrase={product_phrase!r}")
	query: Dict[str, Any]
	try:
		draft_spec = await _llm_search_spec(user_prompt)
	except Exception:
		draft_spec = None
		_dbg("llm search spec failed; using heuristic query builder")

	validated_spec: Optional[Dict[str, Any]] = None
	if draft_spec:
		_dbg(f"llm draft spec={json.dumps(draft_spec, ensure_ascii=False)}")
		try:
			validated_spec = await _llm_validate_spec(user_prompt, draft_spec)
		except Exception:
			validated_spec = None
			_dbg("llm spec validation failed; using code sanitizer on draft spec")

	safe_spec = _sanitize_spec(validated_spec or draft_spec, user_prompt, terms, product_phrase)
	_dbg(f"safe spec={json.dumps(safe_spec, ensure_ascii=False)}")

	if safe_spec.get("agent_ids") or safe_spec.get("phrases") or safe_spec.get("terms"):
		query = _build_query_from_spec(safe_spec, terms, product_phrase, user_prompt)
	elif terms or product_phrase:
		query = _build_query_from_spec({}, terms, product_phrase, user_prompt)
	else:
		agent_ids = _extract_agent_ids(user_prompt)
		if agent_ids:
			agent_ids = _expand_agent_id_variants(agent_ids)
			query = {
				"bool": {
					"filter": [
						{
							"bool": {
								"should": [
									{"terms": {"agent.id": agent_ids}},
									{"terms": {"agent.id.keyword": agent_ids}},
								],
								"minimum_should_match": 1,
							}
						}
					]
				}
			}
		else:
			query = {"match_all": {}}

	_dbg(f"primary query={json.dumps(query, ensure_ascii=False)[:1200]}")

	body = {
		"size": 80,
		"sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
		"query": query,
	}

	search_index = INVENTORY_INDEX
	if _is_os_question(user_prompt):
		search_index = "wazuh-states-inventory-system-*"

	sc, txt = await indexer_request("POST", f"/{search_index}/_search", json_body=body)
	_dbg(f"primary search status={sc}")
	if sc != 200:
		_dbg(f"primary search error body={txt[:400]}")
		if search_index != INVENTORY_INDEX:
			_dbg("retry primary search on default inventory index pattern")
			sc, txt = await indexer_request("POST", f"/{INVENTORY_INDEX}/_search", json_body=body)
			_dbg(f"retry primary search status={sc}")
		if sc != 200:
			return f"Inventory query failed: index search returned http {sc}. Body: {txt[:400]}"

	try:
		data = json.loads(txt)
	except Exception:
		return f"Inventory query failed: invalid JSON response from indexer. Body: {txt[:400]}"

	hits = (((data.get("hits") or {}).get("hits")) if isinstance(data, dict) else None) or []
	_dbg(f"primary hits={len(hits)}")
	if not hits:
		if terms or product_phrase:
			_dbg("fallback: trying relaxed case-insensitive software wildcard search")
			relaxed_body = {
				"size": 80,
				"sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
				"query": _build_relaxed_software_query(user_prompt, terms, product_phrase),
			}
			sc_relaxed, txt_relaxed = await indexer_request("POST", f"/{INVENTORY_INDEX}/_search", json_body=relaxed_body)
			_dbg(f"relaxed search status={sc_relaxed}")
			if sc_relaxed == 200:
				try:
					data_relaxed = json.loads(txt_relaxed)
					hits = (((data_relaxed.get("hits") or {}).get("hits")) if isinstance(data_relaxed, dict) else None) or []
					_dbg(f"relaxed hits={len(hits)}")
				except Exception:
					_dbg("relaxed JSON parse failed")
					pass
		agent_ids = _extract_agent_ids(user_prompt)
		if agent_ids:
			agent_ids = _expand_agent_id_variants(agent_ids)
			_dbg(f"fallback by agent.id={agent_ids}")
			fallback_body = {
				"size": 80,
				"sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
				"query": {
					"bool": {
						"filter": [
							{
								"bool": {
									"should": [
										{"terms": {"agent.id": agent_ids}},
										{"terms": {"agent.id.keyword": agent_ids}},
									],
									"minimum_should_match": 1,
								}
							}
						]
					}
				},
			}
			fallback_index = "wazuh-states-inventory-system-*" if _is_os_question(user_prompt) else INVENTORY_INDEX
			sc2, txt2 = await indexer_request("POST", f"/{fallback_index}/_search", json_body=fallback_body)
			_dbg(f"fallback search status={sc2}")
			if sc2 != 200 and fallback_index != INVENTORY_INDEX:
				_dbg("retry fallback search on default inventory index pattern")
				sc2, txt2 = await indexer_request("POST", f"/{INVENTORY_INDEX}/_search", json_body=fallback_body)
				_dbg(f"retry fallback search status={sc2}")
			if sc2 == 200:
				try:
					data2 = json.loads(txt2)
					hits = (((data2.get("hits") or {}).get("hits")) if isinstance(data2, dict) else None) or []
					_dbg(f"fallback hits={len(hits)}")
				except Exception:
					_dbg("fallback JSON parse failed")
					pass

	if not hits and _is_software_install_question(user_prompt) and (product_phrase or terms):
		_dbg("software-question: trying name-priority query after no-hit fallback")
		software_body = {
			"size": 120,
			"sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
			"query": _build_software_name_priority_query(user_prompt, terms, product_phrase),
		}
		sc_sw, txt_sw = await indexer_request("POST", f"/{INVENTORY_INDEX}/_search", json_body=software_body)
		_dbg(f"software-question: name-priority search status={sc_sw}")
		if sc_sw == 200:
			try:
				data_sw = json.loads(txt_sw)
				sw_hits = (((data_sw.get("hits") or {}).get("hits")) if isinstance(data_sw, dict) else None) or []
				_dbg(f"software-question: name-priority hits={len(sw_hits)}")
				if sw_hits:
					hits = sw_hits
			except Exception:
				_dbg("software-question: name-priority JSON parse failed")
				pass
	if not hits:
		_dbg("no hits after primary + fallback")
		return "No inventory records matched that query in wazuh-states-inventory-*."

	if _is_software_install_question(user_prompt) and (product_phrase or terms):
		_dbg("software-question: trying name-priority query")
		software_body = {
			"size": 120,
			"sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
			"query": _build_software_name_priority_query(user_prompt, terms, product_phrase),
		}
		sc_sw, txt_sw = await indexer_request("POST", f"/{INVENTORY_INDEX}/_search", json_body=software_body)
		_dbg(f"software-question: name-priority search status={sc_sw}")
		if sc_sw == 200:
			try:
				data_sw = json.loads(txt_sw)
				sw_hits = (((data_sw.get("hits") or {}).get("hits")) if isinstance(data_sw, dict) else None) or []
				_dbg(f"software-question: name-priority hits={len(sw_hits)}")
				if sw_hits:
					hits = sw_hits
			except Exception:
				_dbg("software-question: name-priority JSON parse failed")
				pass

	if _is_software_install_question(user_prompt):
		strict_hits = _filter_hits_for_software_question(hits, user_prompt, product_phrase, terms)
		_dbg(f"software-question: strict name hits={len(strict_hits)} of total_hits={len(hits)}")
		if strict_hits:
			hits = strict_hits
		else:
			_dbg("software-question: no strict software-name matches")
			return "No inventory records matched that query in wazuh-states-inventory-*."

	if _is_os_question(user_prompt):
		os_hits = []
		for h in hits:
			src = h.get("_source") if isinstance(h, dict) else None
			if isinstance(src, dict) and _has_os_fields(src):
				os_hits.append(h)
		_dbg(f"os-question: os_hits={len(os_hits)} of total_hits={len(hits)}")
		if os_hits:
			hits = os_hits

	if _is_os_inventory_count_question(user_prompt):
		platform_filter = _extract_os_platform_filter(user_prompt)
		count_endpoints = set()
		for h in hits:
			src = h.get("_source") if isinstance(h, dict) else None
			if not isinstance(src, dict):
				continue
			host = src.get("host") if isinstance(src.get("host"), dict) else {}
			os_obj = host.get("os") if isinstance(host.get("os"), dict) else {}
			name_val = str(os_obj.get("name") or "").lower()
			platform_val = str(os_obj.get("platform") or "").lower()
			full_val = str(os_obj.get("full") or "").lower()
			if platform_filter and platform_filter not in f"{name_val} {platform_val} {full_val}":
				continue
			count_endpoints.add(_endpoint_name(src))

		label = platform_filter.title() if platform_filter else "Matching"
		return f"You have {len(count_endpoints)} {label} agents/endpoints in inventory."

	sample = []
	seen_endpoints = set()
	for h in hits[:40]:
		src = h.get("_source") if isinstance(h, dict) else None
		if not isinstance(src, dict):
			continue
		ep = _endpoint_name(src)
		seen_endpoints.add(ep)
		sample.append({
			"endpoint": ep,
			"inventory": _trim_source(src),
		})

	_dbg(f"sample_size={len(sample)} unique_endpoints={len(seen_endpoints)}")
	if sample:
		_dbg(f"sample_first_endpoint={sample[0].get('endpoint')} sample_first_keys={list((sample[0].get('inventory') or {}).keys())}")

	llm = _build_llm()
	llm_prompt = (
		INVENTORY_PROMPT
		+ "\n\n"
		f"User question:\n{user_prompt.strip()}\n\n"
		f"Matched endpoints count: {len(seen_endpoints)}\n"
		f"Matched records sample (JSON):\n{json.dumps(sample, ensure_ascii=False)[:18000]}\n"
	)

	try:
		msg = await asyncio.to_thread(llm.invoke, llm_prompt)
		out = getattr(msg, "content", "") or ""
		out = str(out).strip()
		_dbg(f"llm_output_len={len(out)}")
		if out:
			return out
	except Exception:
		_dbg("llm invoke failed; using endpoint fallback")
		pass

	eps = sorted(seen_endpoints)
	return "Matched endpoints:\n- " + "\n- ".join(eps[:50])


