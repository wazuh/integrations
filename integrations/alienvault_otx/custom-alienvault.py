#!/var/ossec/framework/python/bin/python3
"""
Wazuh integration: AlienVault OTX threat intelligence enrichment.

Invocation (Wazuh manager):
    custom-alienvault.py <alert_path> <api_key> <hook_url> [debug]

Where:
    alert_path  Path to the alert JSON written by Wazuh.
    api_key     OTX API key (X-OTX-API-KEY header value).
    hook_url    OTX base URL, typically https://otx.alienvault.com
    debug       Optional literal "debug" to enable DEBUG-level logging.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import sys
from socket import socket, AF_UNIX, SOCK_DGRAM
from typing import Any, Dict, Iterable, List, Optional

try:
    import requests
except ImportError:
    sys.stderr.write(
        "Wazuh AlienVault OTX integration requires the 'requests' package. "
        "Install it in the Wazuh Python runtime, for example: "
        "/var/ossec/framework/python/bin/pip3 install requests\n"
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PWD = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = f"{PWD}/logs/integrations.log"
SOCKET_ADDR = f"{PWD}/queue/sockets/queue"

OTX_TIMEOUT_SECONDS = 15
USER_AGENT = "Wazuh-AlienVault-OTX-Integration/2.0"

# Confidence tiers based on OTX pulse_info.count
HIGH_CONFIDENCE_PULSES = 5
MEDIUM_CONFIDENCE_PULSES = 2

# Cap details so the enriched alert payload stays compact
MAX_PULSE_DETAIL_ITEMS = 5

# Cap on how many indicators of each type are queried for a single alert.
# Wazuh alerts can contain several IPs from the same flow (e.g. CloudTrail
# alerts that record source plus NAT plus original IPs).  Querying every
# one would burn through the OTX rate limit.  When more than this many
# distinct candidates are extracted for an IOC type, we cap at the first
# MAX_QUERIES_PER_TYPE and log a warning naming the dropped values so the
# analyst can still see what wasn't checked.
MAX_QUERIES_PER_TYPE = 3

SHA256_HEX_PATTERN = re.compile(r"^[A-Fa-f0-9]{64}$")
SHA256_IN_HASHES_STRING = re.compile(r"SHA256=([A-Fa-f0-9]{64})")

# OTX validation sources that signal a known-good / false-positive indicator.
# When any of these appear in the response's `validation[]` array, the
# indicator is treated as clean regardless of pulse_count.  Popular domains
# (gmail.com, google.com, microsoft.com, etc.) accumulate community pulses
# because attackers abuse them as mail platforms or redirect hosts -- the
# validation list is OTX's own signal that these are not malicious
# infrastructure.
OTX_WHITELIST_VALIDATION_SOURCES: frozenset = frozenset({
    "whitelist",       # OTX explicit whitelist
    "false_positive",  # OTX accepted false-positive report
    "majestic",        # Majestic Million (top sites by referring subnets)
    "alexa",           # Alexa Top Sites
    "akamai",          # Akamai Popular Domains
})

# Sender domains excluded from domain-IOC lookups.
# When a sender address such as attacker@gmail.com appears in an alert, the
# domain part (gmail.com) is not a useful IOC -- it is shared infrastructure
# abused by attackers, not malicious infrastructure itself.  Querying OTX for
# these domains produces false positives because they accumulate community
# pulses as phishing lure platforms while being genuinely benign services.
# Non-webmail sender domains (e.g. attacker@suspicious-domain.ru) are still
# extracted and queried normally.
MAIL_INFRASTRUCTURE_DOMAINS: frozenset = frozenset({
    "gmail.com", "googlemail.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "yahoo.co.uk", "yahoo.fr", "yahoo.de",
    "icloud.com", "me.com", "mac.com",
    "protonmail.com", "proton.me",
    "aol.com",
})


SUPPORTED_FIELD_PATHS: Dict[str, List[str]] = {
    "src_ip": [
        "srcip",
        "data.srcip",
        "data.nat_source_ip",
        "data.source_address",
        "data.aws.ClientIP",          # Also used by Cloudflare module
        "data.aws.source_ip_address",
        "data.aws.sourceIPAddress",
        "data.win.eventdata.ipAddress",
        "data.office365.ClientIPAddress",
        "data.office365.ClientIP",
        "data.office365.SenderIp",
        "data.gcp.jsonPayload.sourceIP",
        "data.azure.properties.ipAddress",
        "data.suricata.src_ip",
        "data.zeek.id_orig_h",
    ],
    "dst_ip": [
        "dstip",
        "data.dstip",
        "data.nat_destination_ip",
        "data.destination_address",
        "data.Remote_IP",             # DNS module
        "data.aws.OriginIP",          # Cloudflare module
        "data.aws.destinationIPAddress",
        "data.win.eventdata.destinationIp",
        "data.suricata.dest_ip",
        "data.zeek.id_resp_h",
    ],
    "domain": [
        "domain",
        "data.domain",
        "data.fqdn",
        "data.hostname",
        "data.win.eventdata.queryName",
        "data.win.eventdata.destinationHostname",
        "data.dns.query",
        "data.suricata.dns.rrname",
    ],
    "file_hash": [
        "syscheck.sha256_after",
        "data.osquery.columns.sha256",
        "data.virustotal.source.sha256",
        "data.event.SHA256String",    # CrowdStrike DetectionSummaryEvent
    ],
}


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("custom-alienvault")


def setup_logging(debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logger.setLevel(level)
    if not logger.handlers:
        handler = logging.FileHandler(LOG_FILE)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] custom-alienvault: %(message)s"
        ))
        logger.addHandler(handler)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_nested(obj: Any, dotted_path: str) -> Any:
    """Walk a dotted path through nested dicts. Returns None if any segment is missing."""
    cur = obj
    for part in dotted_path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur


def first_match(alert: Dict[str, Any], paths: Iterable[str]) -> Optional[Any]:
    """Return the first non-empty value found at any of the given dotted paths."""
    for path in paths:
        val = get_nested(alert, path)
        if val not in (None, "", [], {}):
            return val
    return None


def is_public_ip(value: Any) -> bool:
    if not value:
        return False
    try:
        return ipaddress.ip_address(str(value)).is_global
    except ValueError:
        return False


def is_valid_domain(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    v = value.strip()
    if not v or len(v) < 4 or " " in v or "\t" in v or "." not in v:
        return False
    try:
        ipaddress.ip_address(v)
        return False
    except ValueError:
        return True


def clean_domain(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    v = str(value).strip().lower()
    for scheme in ("http://", "https://", "ftp://"):
        if v.startswith(scheme):
            v = v[len(scheme):]
            break
    for sep in ("/", "?", "#"):
        if sep in v:
            v = v.split(sep, 1)[0]
    if ":" in v and not v.startswith("["):
        v = v.split(":", 1)[0]
    return v or None


# ---------------------------------------------------------------------------
# Indicator extraction
# ---------------------------------------------------------------------------

def iter_msgraph_evidence(alert: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    evidence = get_nested(alert, "data.ms-graph.evidence")
    if isinstance(evidence, list):
        for item in evidence:
            if isinstance(item, dict):
                yield item
    elif isinstance(evidence, dict):
        yield evidence


def _all_path_matches(alert: Dict[str, Any], paths: Iterable[str]) -> List[str]:
    """Walk every dotted path and return all non-empty *scalar* values found.

    Unlike first_match(), this collects every hit so the caller can dedupe and
    cap.  List-valued matches are flattened one level deep so configurations
    like ``data.Remote_IP: [ip1, ip2]`` work transparently.
    """
    out: List[str] = []
    for path in paths:
        val = get_nested(alert, path)
        if val in (None, "", [], {}):
            continue
        if isinstance(val, list):
            for item in val:
                if item not in (None, "", [], {}) and not isinstance(item, (dict, list)):
                    out.append(str(item))
        elif not isinstance(val, dict):
            out.append(str(val))
    return out


def _dedupe_preserving_order(items: Iterable[str]) -> List[str]:
    """Order-preserving uniqueness for IOC value lists."""
    seen: set = set()
    out: List[str] = []
    for v in items:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _classify_crowdstrike_ioc(alert: Dict[str, Any]) -> Dict[str, List[str]]:
    """Route data.event.IOCValue into the right bucket based on IOCType.

    CrowdStrike's IOCValue is a discriminated union -- its semantic type is
    carried in the sibling IOCType field.  Without dispatching on IOCType, a
    domain IOC would land in src_ip and never resolve.

    Recognised IOCType values (case-insensitive):
        hash_sha256, sha256      -> file_hash
        domain                   -> domain
        ipv4, ipv6               -> dst_ip   (Falcon IOCs are typically
                                              the externally-observed peer)
    Other types (hash_md5, hash_sha1, registry, ...) are skipped because
    OTX cannot resolve them.
    """
    out: Dict[str, List[str]] = {"src_ip": [], "dst_ip": [], "domain": [], "file_hash": []}
    ioc_type = (get_nested(alert, "data.event.IOCType") or "").strip().lower()
    ioc_value = get_nested(alert, "data.event.IOCValue")
    if not ioc_type or not ioc_value:
        return out
    ioc_value = str(ioc_value).strip()
    if ioc_type in ("hash_sha256", "sha256"):
        out["file_hash"].append(ioc_value)
    elif ioc_type == "domain":
        out["domain"].append(ioc_value)
    elif ioc_type in ("ipv4", "ipv6"):
        out["dst_ip"].append(ioc_value)
    else:
        logger.debug(f"Skipping CrowdStrike IOCType '{ioc_type}' (not OTX-resolvable)")
    return out


def _crowdstrike_quarantine_hashes(alert: Dict[str, Any]) -> List[str]:
    """Walk data.event.QuarantineFiles[] for SHA-256 hashes.

    CrowdStrike emits this as an array of file-object dicts, each carrying
    its own SHA256HashData.  A plain dotted path can't reach into list
    indices, so we walk it explicitly.
    """
    qf = get_nested(alert, "data.event.QuarantineFiles")
    if not isinstance(qf, list):
        return []
    out: List[str] = []
    for entry in qf:
        if isinstance(entry, dict):
            sha = entry.get("SHA256HashData") or entry.get("sha256HashData")
            if isinstance(sha, str) and SHA256_HEX_PATTERN.match(sha):
                out.append(sha)
    return out


def collect_src_ips(alert: Dict[str, Any]) -> List[str]:
    """All distinct candidate source IPs, filtered to public addresses."""
    candidates: List[str] = list(_all_path_matches(alert, SUPPORTED_FIELD_PATHS["src_ip"]))
    for ev in iter_msgraph_evidence(alert):
        for key in ("ipAddress", "senderIp"):
            v = ev.get(key)
            if v:
                candidates.append(str(v))
    candidates += _classify_crowdstrike_ioc(alert)["src_ip"]

    public: List[str] = []
    for ip in _dedupe_preserving_order(candidates):
        if is_public_ip(ip):
            public.append(ip)
        else:
            logger.debug(f"Skipping non-public src_ip candidate: {ip}")
    return public


def extract_src_ip(alert: Dict[str, Any]) -> Optional[str]:
    """Back-compat shim: first public source IP, or None."""
    ips = collect_src_ips(alert)
    return ips[0] if ips else None


def collect_dst_ips(alert: Dict[str, Any]) -> List[str]:
    """All distinct candidate destination IPs, filtered to public addresses."""
    candidates: List[str] = list(_all_path_matches(alert, SUPPORTED_FIELD_PATHS["dst_ip"]))
    candidates += _classify_crowdstrike_ioc(alert)["dst_ip"]

    public: List[str] = []
    for ip in _dedupe_preserving_order(candidates):
        if is_public_ip(ip):
            public.append(ip)
        else:
            logger.debug(f"Skipping non-public dst_ip candidate: {ip}")
    return public


def extract_dst_ip(alert: Dict[str, Any]) -> Optional[str]:
    """Back-compat shim: first public destination IP, or None."""
    ips = collect_dst_ips(alert)
    return ips[0] if ips else None


def collect_domains(alert: Dict[str, Any]) -> List[str]:
    """All distinct domain candidates, cleaned and validated.

    Order of precedence (preserved through dedup):
      1. SUPPORTED_FIELD_PATHS["domain"] entries
      2. MS Graph evidence url / urls
      3. CrowdStrike IOCValue when IOCType==domain
      4. Sender domain (only when nothing else surfaced -- see
         extract_sender_domain() for the mail-provider exclusion list)

    MS Graph sender fields (p1Sender / p2Sender) are NOT used as primary
    sources; gmail.com, outlook.com etc. would otherwise generate false
    positives because they show up in OTX pulses as phishing lure hosts.
    """
    raw: List[str] = list(_all_path_matches(alert, SUPPORTED_FIELD_PATHS["domain"]))

    # MS Graph URL fields
    for ev in iter_msgraph_evidence(alert):
        for url_key in ("url", "urls"):
            value = ev.get(url_key)
            if isinstance(value, str) and value:
                raw.append(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and item:
                        raw.append(item)
                    elif isinstance(item, dict) and item.get("url"):
                        raw.append(item["url"])

    raw += _classify_crowdstrike_ioc(alert)["domain"]

    # Clean + validate
    cleaned: List[str] = []
    for v in raw:
        c = clean_domain(v)
        if c and is_valid_domain(c):
            cleaned.append(c)
        else:
            logger.debug(f"Skipping invalid/IP-like domain candidate: {v!r}")

    cleaned = _dedupe_preserving_order(cleaned)

    # Sender-domain fallback only when no structural domain found
    if not cleaned:
        sender = extract_sender_domain(alert)
        if sender and is_valid_domain(sender):
            cleaned.append(sender)
            logger.debug(f"Using sender domain as domain IOC: {sender}")

    return cleaned


def extract_domain(alert: Dict[str, Any]) -> Optional[str]:
    """Back-compat shim: first domain candidate, or None."""
    doms = collect_domains(alert)
    return doms[0] if doms else None


def extract_sender_domain(alert: Dict[str, Any]) -> Optional[str]:
    """Return the sender domain from email evidence, unless it is a
    high-volume mail provider (see MAIL_INFRASTRUCTURE_DOMAINS).

    OTX has no per-address email endpoint -- /api/v1/indicators/email/
    returns 404.  The closest useful signal is the sender domain.  Querying
    generic webmail providers (gmail.com, outlook.com, etc.) is not useful
    because they appear in OTX pulses as abused platforms, not as malicious
    infrastructure.  A non-webmail sender domain such as suspicious-domain.ru
    is still a valid IOC and is returned normally.

    p1Sender (SMTP MAIL FROM / envelope sender) is preferred over p2Sender
    (RFC5322 header From) because it is harder to spoof and more often the
    actual attacker-controlled address in phishing alerts.
    """
    # MS Graph evidence: p1Sender first (envelope), then p2Sender/sender
    for ev in iter_msgraph_evidence(alert):
        for key in ("p1Sender", "p2Sender", "sender"):
            sender = ev.get(key)
            if not isinstance(sender, dict):
                continue
            # domainName is authoritative when present
            domain = sender.get("domainName")
            if not domain:
                addr = sender.get("emailAddress")
                if addr and "@" in addr:
                    domain = addr.split("@", 1)[1]
            if domain:
                domain = domain.strip().lower()
                if domain in MAIL_INFRASTRUCTURE_DOMAINS:
                    logger.debug(
                        f"Skipping sender domain '{domain}' "
                        "(high-volume mail provider -- not a useful domain IOC)"
                    )
                    return None
                return domain

    # Plain O365 / generic fields
    for path in (
        "data.office365.SenderAddress",
        "data.office365.From",
        "data.win.eventdata.senderAddress",
    ):
        val = get_nested(alert, path)
        if val and isinstance(val, str) and "@" in val:
            domain = val.strip().lower().split("@", 1)[1]
            if domain in MAIL_INFRASTRUCTURE_DOMAINS:
                logger.debug(
                    f"Skipping sender domain '{domain}' "
                    "(high-volume mail provider -- not a useful domain IOC)"
                )
                return None
            return domain

    return None


def collect_file_hashes(alert: Dict[str, Any]) -> List[str]:
    """All distinct SHA-256 hashes found across structured and freeform fields."""
    out: List[str] = []

    # Sysmon-style "MD5=...,SHA256=...,IMPHASH=..." string
    eventdata = get_nested(alert, "data.win.eventdata") or {}
    hashes_str = eventdata.get("hashes") or eventdata.get("Hashes") or ""
    if hashes_str:
        for match in SHA256_IN_HASHES_STRING.finditer(hashes_str):
            out.append(match.group(1))

    # Registered single-value paths
    for val in _all_path_matches(alert, SUPPORTED_FIELD_PATHS["file_hash"]):
        if SHA256_HEX_PATTERN.match(val):
            out.append(val)

    # MS Graph fileEvidence
    for ev in iter_msgraph_evidence(alert):
        details = ev.get("fileDetails")
        if isinstance(details, dict):
            for key in ("sha256", "sha256Ac"):
                sha = details.get(key)
                if isinstance(sha, str) and SHA256_HEX_PATTERN.match(sha):
                    out.append(sha)

    # CrowdStrike QuarantineFiles[] (array of file objects)
    out.extend(_crowdstrike_quarantine_hashes(alert))

    # CrowdStrike IOCValue when IOCType is a SHA-256 form
    for sha in _classify_crowdstrike_ioc(alert)["file_hash"]:
        if SHA256_HEX_PATTERN.match(sha):
            out.append(sha)

    return _dedupe_preserving_order(out)


def extract_sha256_hash(alert: Dict[str, Any]) -> Optional[str]:
    """Back-compat shim: first SHA-256 found, or None."""
    hashes = collect_file_hashes(alert)
    return hashes[0] if hashes else None


def extract_file_path(alert: Dict[str, Any]) -> Optional[str]:
    return (
        get_nested(alert, "data.win.eventdata.Image")
        or get_nested(alert, "data.win.eventdata.image")
        or get_nested(alert, "syscheck.path")
    )


def extract_windows_event_fields(alert: Dict[str, Any]) -> Dict[str, Any]:
    eventdata = get_nested(alert, "data.win.eventdata") or {}
    keys = ("image", "parentImage", "parentProcessId", "processId", "currentDirectory")
    return {k: eventdata[k] for k in keys if eventdata.get(k) is not None}


# ---------------------------------------------------------------------------
# OTX queries
# ---------------------------------------------------------------------------

def _otx_request(url: str, api_key: str) -> Optional[Dict[str, Any]]:
    headers = {"X-OTX-API-KEY": api_key, "User-Agent": USER_AGENT}
    try:
        resp = requests.get(url, headers=headers, timeout=OTX_TIMEOUT_SECONDS)
    except requests.exceptions.RequestException as e:
        logger.warning(f"OTX request failed for {url}: {e}")
        return None

    if resp.status_code == 401:
        logger.error("OTX returned 401 Unauthorized -- check the api_key configuration.")
        return None
    if resp.status_code == 429:
        logger.warning("OTX rate limit hit (HTTP 429). Skipping this lookup.")
        return None
    if resp.status_code == 404:
        logger.debug(f"OTX 404 for {url} (indicator not present in OTX).")
        return None
    if not resp.ok:
        logger.warning(f"OTX returned HTTP {resp.status_code} for {url}.")
        return None

    try:
        return resp.json()
    except ValueError:
        logger.warning(f"OTX returned non-JSON response for {url}.")
        return None


def query_otx(
    indicator_type: str, value: str, api_key: str, hook_url: str
) -> Optional[Dict[str, Any]]:
    base = hook_url.rstrip("/")
    if indicator_type in ("src_ip", "dst_ip"):
        url = f"{base}/api/v1/indicators/IPv4/{value}/general"
    elif indicator_type == "domain":
        url = f"{base}/api/v1/indicators/domain/{value}/general"
    elif indicator_type == "file_hash":
        url = f"{base}/api/v1/indicators/file/{value}/general"
    else:
        return None

    data = _otx_request(url, api_key)
    if data and "pulse_info" in data:
        return data
    return None


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

def _otx_is_whitelisted(otx_data: Dict[str, Any]) -> bool:
    """Return True if OTX's own validation list marks this indicator clean.

    Popular domains accumulate community pulses because attackers abuse them
    as mail senders, redirect targets, or hosting platforms.  OTX records
    this explicitly in the ``validation`` array using sources such as
    ``whitelist``, ``false_positive``, ``majestic``, and ``alexa``.  When
    any of those sources appear, pulse_count is noise -- the domain is not
    malicious infrastructure.
    """
    validation = otx_data.get("validation")
    if not isinstance(validation, list):
        return False
    for entry in validation:
        if isinstance(entry, dict):
            source = (entry.get("source") or "").lower()
            if source in OTX_WHITELIST_VALIDATION_SOURCES:
                return True
    return False


def evaluate_verdict(otx_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not otx_data:
        return {
            "malicious": False,
            "verdict": "unknown",
            "confidence": "unknown",
            "reason": "no_otx_response_or_query_failed",
        }

    # Check OTX's own whitelist / false-positive markers before pulse_count.
    # A domain like gmail.com may have many pulses (attackers use it as a
    # phishing lure platform) but OTX explicitly marks it as a known false
    # positive.  The whitelist check overrides the pulse count in that case.
    if _otx_is_whitelisted(otx_data):
        pulse_count = int((otx_data.get("pulse_info") or {}).get("count", 0) or 0)
        logger.debug(
            f"Indicator '{otx_data.get('indicator', '?')}' has OTX whitelist "
            f"validation entry (pulse_count={pulse_count}); marking clean."
        )
        return {
            "malicious": False,
            "verdict": "clean",
            "confidence": "high",
            "pulse_count": pulse_count,
            "reason": "otx_whitelist_validation",
        }

    pulse_info = otx_data.get("pulse_info") or {}
    pulse_count = int(pulse_info.get("count", 0) or 0)
    pulses = pulse_info.get("pulses") or []

    pulse_names: List[str] = []
    adversaries: List[str] = []
    malware_families: List[str] = []

    for p in pulses:
        if len(pulse_names) < MAX_PULSE_DETAIL_ITEMS and p.get("name"):
            pulse_names.append(p["name"])
        adv = p.get("adversary")
        if adv and adv not in adversaries and len(adversaries) < MAX_PULSE_DETAIL_ITEMS:
            adversaries.append(adv)
        for fam in (p.get("malware_families") or []):
            name = fam.get("display_name") if isinstance(fam, dict) else fam
            if name and name not in malware_families and len(malware_families) < MAX_PULSE_DETAIL_ITEMS:
                malware_families.append(name)

    if pulse_count <= 0:
        return {
            "malicious": False,
            "verdict": "clean",
            "confidence": "high",
            "pulse_count": 0,
            "reason": "no_otx_pulses",
        }

    if pulse_count >= HIGH_CONFIDENCE_PULSES:
        confidence = "high"
    elif pulse_count >= MEDIUM_CONFIDENCE_PULSES:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "malicious": True,
        "verdict": "malicious",
        "confidence": confidence,
        "pulse_count": pulse_count,
        "pulse_names": pulse_names,
        "adversaries": adversaries,
        "malware_families": malware_families,
    }


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def _cap_with_warning(values: List[str], ioc_type: str) -> List[str]:
    """Return at most MAX_QUERIES_PER_TYPE values; log dropped ones."""
    if len(values) <= MAX_QUERIES_PER_TYPE:
        return values
    kept = values[:MAX_QUERIES_PER_TYPE]
    dropped = values[MAX_QUERIES_PER_TYPE:]
    logger.warning(
        f"Capped {ioc_type} at {MAX_QUERIES_PER_TYPE} of {len(values)} candidates; "
        f"dropped: {dropped}"
    )
    return kept


def collect_indicators(alert: Dict[str, Any]) -> Dict[str, List[str]]:
    """Per-type list of indicator candidates to query, capped and deduped.

    Sender-domain fallback is handled inside collect_domains() so the cap
    applies uniformly.
    """
    return {
        "src_ip":    _cap_with_warning(collect_src_ips(alert),    "src_ip"),
        "dst_ip":    _cap_with_warning(collect_dst_ips(alert),    "dst_ip"),
        "domain":    _cap_with_warning(collect_domains(alert),    "domain"),
        "file_hash": _cap_with_warning(collect_file_hashes(alert), "file_hash"),
    }


def _verdict_rank(block: Dict[str, Any]) -> tuple:
    """Sort key for picking the "worst" verdict block.

    Higher tuple sorts higher.  The ranking is:
      1. malicious > clean > unknown
      2. within the same verdict tier, higher pulse_count wins

    So an indicator with 8 pulses beats one with 3, and any malicious result
    beats any clean or unknown result regardless of pulse counts elsewhere.
    """
    verdict_score = {"malicious": 2, "clean": 1}.get(block.get("verdict", ""), 0)
    pulse_count = int(block.get("pulse_count") or 0)
    return (verdict_score, pulse_count)


def _query_and_select_worst(
    ioc_type: str, values: List[str], api_key: str, hook_url: str
) -> Optional[Dict[str, Any]]:
    """Query OTX for every value, return the worst-verdict block (or None)."""
    if not values:
        return None
    blocks: List[Dict[str, Any]] = []
    for value in values:
        otx_data = query_otx(ioc_type, value, api_key, hook_url)
        verdict = evaluate_verdict(otx_data)
        block = {
            "value": value,
            "malicious": verdict["malicious"],
            "verdict": verdict["verdict"],
            "confidence": verdict["confidence"],
            "pulse_count": verdict.get("pulse_count"),
            "pulse_names": verdict.get("pulse_names"),
            "adversaries": verdict.get("adversaries"),
            "malware_families": verdict.get("malware_families"),
            "reason": verdict.get("reason"),
        }
        blocks.append({k: v for k, v in block.items() if v not in (None, [], {})})

    if len(blocks) > 1:
        logger.debug(
            f"{ioc_type}: queried {len(blocks)} candidates "
            f"({[b['value'] for b in blocks]}), selecting worst verdict"
        )
    worst = max(blocks, key=_verdict_rank)
    return worst


def enrich_alert(
    alert: Dict[str, Any], api_key: str, hook_url: str
) -> Dict[str, Any]:
    indicators = collect_indicators(alert)

    if not any(indicators.values()):
        logger.info("No queryable indicators found in alert.")
        win_fields = extract_windows_event_fields(alert)
        return win_fields if win_fields else alert

    enriched_indicators: Dict[str, Dict[str, Any]] = {}
    for ioc_type, values in indicators.items():
        worst = _query_and_select_worst(ioc_type, values, api_key, hook_url)
        if worst is not None:
            enriched_indicators[ioc_type] = worst

    any_malicious = any(v.get("malicious") for v in enriched_indicators.values())
    all_clean = (
        bool(enriched_indicators)
        and all(v.get("verdict") == "clean" for v in enriched_indicators.values())
    )
    overall = "malicious" if any_malicious else ("clean" if all_clean else "partial_unknown")

    enriched: Dict[str, Any] = {
        "integration": "alienvault_otx",
        "original_rule": get_nested(alert, "rule.id"),
        "input_alert": alert.get("id"),
        "overall_malicious": any_malicious,
        "overall_verdict": overall,
        "indicators": enriched_indicators,
    }

    # Preserve the original alert's full_log so analysts can pivot back to
    # the source event from a single enriched record.
    full_log = alert.get("full_log")
    if full_log:
        enriched["original_full_log"] = full_log

    win_fields = extract_windows_event_fields(alert)
    if win_fields:
        enriched["windows_event_data"] = win_fields
    else:
        file_path = extract_file_path(alert)
        if file_path:
            enriched["file_path"] = file_path

    return {k: v for k, v in enriched.items() if v not in (None, [], {})}


def escape_agent_string(value: str) -> str:
    return value.replace("|", "||").replace(":", "|:")


def send_event(msg: Dict[str, Any], agent: Optional[Dict[str, Any]] = None) -> None:
    if not agent or agent.get("id") == "000":
        line = f"1:alienvault_otx:{json.dumps(msg)}"
    else:
        agent_str = f"[{agent['id']}] ({agent.get('name', '?')}) {agent.get('ip', 'any')}"
        agent_str = escape_agent_string(agent_str)
        line = f"1:{agent_str}->alienvault_otx:{json.dumps(msg)}"

    logger.debug(f"Sending event to queue ({len(line)} bytes)")
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(line.encode())
        sock.close()
    except OSError as e:
        logger.error(f"Failed to send event to Wazuh queue socket: {e}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: List[str]) -> int:
    if len(argv) < 4:
        sys.stderr.write(
            f"Usage: {argv[0]} <alert_path> <api_key> <hook_url> [debug]\n"
        )
        return 1

    alert_path, api_key, hook_url = argv[1], argv[2], argv[3]
    debug = len(argv) > 4 and argv[4] == "debug"
    setup_logging(debug=debug)

    logger.info(f"Starting; alert={alert_path} hook_url={hook_url}")

    try:
        with open(alert_path) as f:
            alert = json.load(f)
    except (OSError, ValueError) as e:
        logger.error(f"Failed to read or parse alert file {alert_path}: {e}")
        return 1

    if isinstance(alert.get("_source"), dict) and "data" not in alert:
        logger.debug("Unwrapping Elasticsearch _source envelope.")
        alert = alert["_source"]

    enriched = enrich_alert(alert, api_key, hook_url)
    send_event(enriched, alert.get("agent"))
    logger.info("Done.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as e:
        logging.getLogger("custom-alienvault").exception(f"Unhandled exception: {e}")
        sys.exit(1)