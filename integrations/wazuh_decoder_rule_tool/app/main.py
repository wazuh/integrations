from __future__ import annotations

import html
import json
import os
import re
import shlex
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

import httpx

_SBERT_MODEL = None
_SBERT_AVAILABLE = False
try:  # Optional dependency for better ML suggestions
    from sentence_transformers import SentenceTransformer, util as st_util  # type: ignore

    _SBERT_AVAILABLE = True
except Exception:  # noqa: BLE001
    _SBERT_AVAILABLE = False

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from app.decoder_ml import DecoderSimilarityModel, load_patterns_from_repo, refresh_wazuh_repo

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
DEFAULT_WAZUH_LOGTEST = "/var/ossec/bin/wazuh-logtest"
DEFAULT_DECODERS_DIR = "/var/ossec/etc/decoders"
DEFAULT_RULES_DIR = "/var/ossec/etc/rules"
DEFAULT_WAZUH_SSH_HOST = "192.168.56.10"
DEFAULT_WAZUH_SSH_PORT = "22"
DEFAULT_WAZUH_SSH_USER = "vagrant"
DEFAULT_WAZUH_SSH_PASSWORD = "vagrant"
WAZUH_LOGTEST = os.getenv("WAZUH_LOGTEST_PATH", DEFAULT_WAZUH_LOGTEST)
WAZUH_DECODERS_DIR = os.getenv("WAZUH_DECODERS_DIR", DEFAULT_DECODERS_DIR)
WAZUH_RULES_DIR = os.getenv("WAZUH_RULES_DIR", DEFAULT_RULES_DIR)
WAZUH_SSH_HOST = os.getenv("WAZUH_SSH_HOST", DEFAULT_WAZUH_SSH_HOST)
WAZUH_SSH_PORT = os.getenv("WAZUH_SSH_PORT", DEFAULT_WAZUH_SSH_PORT)
WAZUH_SSH_USER = os.getenv("WAZUH_SSH_USER", DEFAULT_WAZUH_SSH_USER)
WAZUH_SSH_KEY = os.getenv("WAZUH_SSH_KEY", "")
WAZUH_SSH_PASSWORD = os.getenv("WAZUH_SSH_PASSWORD", DEFAULT_WAZUH_SSH_PASSWORD)
WAZUH_REMOTE_ENABLED = bool(WAZUH_SSH_HOST and WAZUH_SSH_USER)
WAZUH_REPO_URL = os.getenv("WAZUH_REPO_URL", "https://github.com/wazuh/wazuh.git")
WAZUH_REPO_CACHE_DIR = Path(os.getenv("WAZUH_REPO_CACHE_DIR", str(BASE_DIR.parent / "data" / "wazuh_repo")))
WAZUH_REPO_DECODER_SUBPATH = os.getenv("WAZUH_REPO_DECODER_SUBPATH", "ruleset/decoders")
ML_MODEL_DIR = Path(os.getenv("ML_MODEL_DIR", str(BASE_DIR.parent / "data" / "models" / "decoder-sbert")))
LOCAL_OUTPUT_DIR = BASE_DIR.parent / "generated"
FEEDBACK_DATASET_PATH = BASE_DIR.parent / "data" / "datasets" / "feedback.jsonl"
REJECTED_FEEDBACK_PATH = BASE_DIR.parent / "data" / "datasets" / "feedback_rejections.jsonl"

# ── OpenRouter / LLM config ──
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_BASE_URL = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
AI_DEFAULT_MODEL = os.getenv("AI_DEFAULT_MODEL", "anthropic/claude-sonnet-4-5")

_ML_MODEL: Optional[DecoderSimilarityModel] = None
_ML_MODEL_ERROR: str = ""
_ML_PATTERN_COUNT = 0

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Pre-load ML patterns on startup to avoid "red" status in dashboard
    print("INFO:     Pre-loading ML model and patterns...")
    ensure_ml_model(force_refresh=False)
    print(f"INFO:     ML patterns loaded: {_ML_PATTERN_COUNT}")
    yield

app = FastAPI(title="Wazuh Decoder Rule Creator", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


class LogSample(BaseModel):
    raw_log: str = Field(..., min_length=1)
    expected_decoder: Optional[str] = None
    expected_rule_id: Optional[int] = None
    expected_fields: Dict[str, str] = Field(default_factory=dict)


class AnalyzeRequest(BaseModel):
    logs: List[LogSample] = Field(..., min_length=1)
    app_name: str = Field(default="customapp")
    rule_requirement: Optional[str] = None
    extract_fields: List[str] = Field(default_factory=list)
    split_decoders: bool = Field(default=False)


class CandidateRequest(BaseModel):
    app_name: str = Field(default="customapp")
    logs: List[LogSample] = Field(..., min_length=1)
    level: int = Field(default=5, ge=0, le=16)
    rule_id: int = Field(default=100500, ge=100000)
    rule_requirement: Optional[str] = None
    extract_fields: List[str] = Field(default_factory=list)
    split_decoders: bool = Field(default=False)


class TestRequest(BaseModel):
    candidate: CandidateRequest
    install_mode: str = Field(default="stdin")


class MLRefreshRequest(BaseModel):
    force: bool = Field(default=False)


class FeedbackDecoderInput(BaseModel):
    name: Optional[str] = None
    parent: Optional[str] = None
    prematch: Optional[str] = None
    regex: Optional[str] = None
    order: List[str] = Field(default_factory=list)
    source_file: Optional[str] = None


class FeedbackRequest(BaseModel):
    approved: bool
    app_name: str = Field(default="customapp")
    log: str = Field(..., min_length=1)
    extract_fields: List[str] = Field(default_factory=list)
    decoder: Optional[FeedbackDecoderInput] = None
    notes: Optional[str] = None


def sanitize_name(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9_-]", "-", value.strip().lower())
    return value or "customapp"


def escape_xml(text: str) -> str:
    return html.escape(text, quote=False)


def first_non_empty(logs: List[str]) -> str:
    for line in logs:
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def infer_log_type(logs: List[str]) -> str:
    stripped = [line.strip() for line in logs if line.strip()]
    if stripped and all(line.startswith("{") and line.endswith("}") for line in stripped[: min(3, len(stripped))]):
        return "json"
    if any("=" in line for line in stripped):
        return "keyvalue"
    if any(re.match(r"^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}", line) for line in stripped):
        return "syslog"
    return "generic"


def infer_program_name(logs: List[str], fallback: str) -> str:
    syslog_prog = re.compile(r"^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+([\w.-]+)(?:\[\d+\])?:")
    for line in logs:
        m = syslog_prog.match(line)
        if m:
            return m.group(1)
    return sanitize_name(fallback)


def extract_program_from_log(logs: List[str]) -> Optional[str]:
    syslog_prog = re.compile(r"^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+([\w.-]+)(?:\[\d+\])?:")
    bracket_prog = re.compile(r"^\[[^\]]+\]\s+([\w.-]+)\s+-")
    java_prog = re.compile(r"^\d{2,4}[/-]\d{2}[/-]\d{2}\s+\d{2}:\d{2}:\d{2}\s+[A-Z]+\s+([\w.$-]+):")
    for line in logs:
        m1 = syslog_prog.match(line)
        if m1:
            return m1.group(1)
        m2 = bracket_prog.match(line.strip())
        if m2:
            return m2.group(1)
        m3 = java_prog.match(line.strip())
        if m3:
            return m3.group(1)
    return None


def choose_prematch(logs: List[str], program_name: str, predecoded_program: Optional[str] = None) -> str:
    first_log = first_non_empty(logs)

    if predecoded_program:
        return predecoded_program
    # CEF log: starts with CEF:<version>|  → generic prematch
    if re.match(r'^CEF:\d+\|', first_log):
        return r"^CEF\p\d+\p"
    if first_log.startswith('['):
        return r"\p\d+-\d+-\S+:\d+:\d+,\d+\p"
    if any("failed login" in line.lower() for line in logs):
        return "failed login"
    if any("User '" in line for line in logs):
        return "User '"
    if program_name:
        return program_name
    return first_log[:20]


def prematch_from_current_logs(logs: List[str], *candidates: Optional[str]) -> Optional[str]:
    source_logs = [line for line in logs if line]
    for candidate in candidates:
        value = (candidate or "").strip()
        if not value:
            continue
        if value.startswith(r'\p') or value.startswith('^'):
            return value
        if any(value in line for line in source_logs):
            return value
    return None


def prematch_osregex_from_current_logs(logs: List[str], *candidates: Optional[str]) -> Optional[str]:
    matched = prematch_from_current_logs(logs, *candidates)
    if not matched:
        return None
    if matched.startswith(r'\p') or matched.startswith('^'):
        return matched

    first_log = first_non_empty(logs)
    idx = first_log.find(matched)
    if idx >= 0:
        prefix = first_log[:idx + len(matched)]
        generalized_prefix = generalize_regex_literal(prefix)
        if generalized_prefix:
            return f"^{generalized_prefix}"

    prematch = normalize_regex_literal(matched)
    prematch = re.sub(r"\d+", r"\\d+", prematch)
    return prematch


def normalize_regex_literal(text: str) -> str:
    return "".join(escape_osregex_literal_char(char) for char in text)


def escape_osregex_literal_char(char: str) -> str:
    if char in {"$", "(", ")", "\\", "|", "<"}:
        return f"\\{char}"
    if char == "\t":
        return r"\t"
    return char


def generalize_osregex_token(token: str) -> str:
    # 1. Check for punctuation-wrapped tokens like <TAG>
    punc_set = r'()\*+,\-.:;<=>?\[\]!"\'#$%&|{}'
    punc_char = f'[{punc_set}]'
    
    if re.fullmatch(rf'{punc_char}[A-Z0-9_@-]+{punc_char}', token):
        return r"\p\S+\p"
        
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", token):
        return r"\d+.\d+.\d+.\d+"
    if re.fullmatch(r"\d+", token):
        return r"\d+"
    if re.fullmatch(r"[0-9a-fA-F]{6,}", token):
        return r"\w+"

    parts: List[str] = []
    index = 0
    while index < len(token):
        char = token[index]
        if char in "()*+,-.:;<=>?[]!\"'#$%&|{}":
            parts.append(r"\p")
            index += 1
            continue
        if char.isdigit():
            while index < len(token) and token[index].isdigit():
                index += 1
            parts.append(r"\d+")
            continue
        parts.append(escape_osregex_literal_char(char))
        index += 1
    return "".join(parts)


def generalize_regex_literal(text: str) -> str:
    """
    Escapes text for use in regex, but applies some common-sense generalizations
    to avoid over-specification. Uses \\p for punctuation boundaries.
    """
    if not text:
        return ""
    
    # 1. Handle ###SOMETHING### patterns
    text = re.sub(r'###[A-Z0-9_-]+###', r'###\\S+###', text)
    
    # 2. Handle [PID] or similar bracketed numbers
    text = re.sub(r'\[\d+\]', r'[\\d+]', text)
    
    # 3. Handle <TAGS> or [TAGS] with \p\S+\p
    punc_set = r'()\*+,\-.:;<=>?\[\]!"\'#$%&|{}'
    text = re.sub(rf'[{punc_set}][A-Z0-9_@-]+[{punc_set}]', r'\\p\\S+\\p', text)
    
    # Escape the rest
    final = re.escape(text)
    
    # Convert back our generalized markers (after re.escape)
    final = final.replace(r'\#\#\#\\\\S\+\#\#\#', r'###\S+###')
    final = final.replace(r'\[\\d\+\]', r'[\d+]')
    final = final.replace(r'\\p\\S\+\\p', r'\p\S+\p')
    
    # Generalize spaces and punctuation
    final = final.replace(r'\\s\+', r'\s+')
    final = final.replace(r'\ ', r'\s+')
    
    # Optionally convert remaining punctuation to \p if they are in the set
    for char in "()*+,-.:;<=>?[]!\"'#$%&|{}":
        escaped_char = re.escape(char)
        final = final.replace(escaped_char, r"\p")
    
    # Collapse multiple \p
    final = re.sub(r'(\\p)+', r'\\p', final)
    
    return final


def build_generalized_osregex(log_line: str) -> str:
    predecoded = parse_phase1_predecode(log_line)
    target_text = (predecoded.get("body") or log_line or "").strip()
    if not target_text:
        return r".*"

    return generalize_regex_literal(target_text) or r".*"


TIMESTAMP_CAPTURE_SHAPES: List[Tuple[re.Pattern, str]] = [
    (
        re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$"),
        r"(\d+-\d+-\d+T\d+:\d+:\d+(?:\.\d+)?(?:Z|[+-]\d+:?\d+)?)",
    ),
    (
        re.compile(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:[.,]\d+)?$"),
        r"(\d+-\d+-\d+\s+\d+:\d+:\d+(?:[.,]\d+)?)",
    ),
    (
        re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}$"),
        r"(\S+\s+\d+\s+\d+:\d+:\d+)",
    ),
    (
        re.compile(r"^\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?$"),
        r"(\d+/\S+/\d+:\d+:\d+:\d+(?:\s+[+-]\d+)?)",
    ),
    (
        re.compile(r"^\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+$"),
        r"(\d+-\d+\s+\d+:\d+:\d+\.\d+)",
    ),
    (
        re.compile(r"^\d{8}-\d{2}:\d{2}:\d{2}:\d+$"),
        r"(\d+-\d+:\d+:\d+:\d+)",
    ),
]

_TIMESTAMP_FIELDS = {"logtime", "timestamp", "time"}
_IP_FIELDS = {"srcip", "dstip", "ip", "ipaddress", "ipaddr", "clientip", "serverip"}
_HOSTNAME_FIELDS = {"logsource", "hostname", "host", "source", "node"}
_LEVEL_FIELDS = {"loglevel", "level", "severity", "status"}


def field_capture_pattern(field_name: str, value: str) -> str:
    canonical = canonicalize_field_name(field_name)

    if canonical in _TIMESTAMP_FIELDS:
        for shape_re, capture in TIMESTAMP_CAPTURE_SHAPES:
            if shape_re.fullmatch(value):
                return capture

    if canonical in _IP_FIELDS and re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
        return r"(\d+.\d+.\d+.\d+)"

    if canonical in _HOSTNAME_FIELDS and " " not in value:
        return r"(\S+)"

    if canonical in _LEVEL_FIELDS and " " not in value:
        return r"(\S+)"

    if " " in value or "\t" in value:
        return r"(.+)"
    return r"(\S+)"


def build_dynamic_regex_from_fields(log_line: str, fields: Dict[str, str]) -> tuple[Optional[str], List[str]]:
    predecoded = parse_phase1_predecode(log_line)
    target_text = (predecoded.get("body") or log_line or "").strip()
    if not target_text:
        return None, []

    excluded = {"program"}
    matches: List[Tuple[int, int, str]] = []
    for key, value in fields.items():
        # Skip internal metadata keys and any non-string values (e.g. _cef_field_map)
        if key in excluded or key.startswith("_") or not value or not isinstance(value, str):
            continue
        found = re.search(re.escape(value), target_text)
        if not found:
            continue
        matches.append((found.start(), found.end(), key))

    if not matches:
        return None, []

    # Prioritize non-message fields and then earlier matches
    matches.sort(key=lambda x: (0 if x[2] == "message" else 1, -x[0]), reverse=True)
    
    non_overlapping: List[Tuple[int, int, str]] = []
    # We use a set of used ranges to avoid overlaps
    used_indices = set()

    for start, end, key in matches:
        # Check if this match overlaps with any already selected match
        overlap = False
        for s, e, _ in non_overlapping:
            if not (end <= s or start >= e):
                overlap = True
                break
        
        if not overlap:
            non_overlapping.append((start, end, key))
            for i in range(start, end):
                used_indices.add(i)

    # Sort again by start position for regex building
    non_overlapping.sort(key=lambda item: item[0])
    
    if not non_overlapping:
        return None, []

    parts: List[str] = []
    order: List[str] = []
    last = 0
    for start, end, key in non_overlapping:
        literal = target_text[last:start]
        if literal:
            parts.append(generalize_regex_literal(literal))
        field_value = target_text[start:end]
        parts.append(field_capture_pattern(key, field_value))
        order.append(key)
        last = end

    tail = target_text[last:]
    if tail:
        parts.append(generalize_regex_literal(tail))

    regex = "".join(parts).strip()
    return (regex or None), order


def build_split_regexes_from_fields(logs: List[str], fields: Dict[str, str]) -> List[Tuple[str, List[str]]]:
    """
    Generates one child decoder per field.
    For CEF key=value extension logs uses .+cef_key=(capture) patterns.
    Only emits decoders for fields present in `fields` as plain strings
    (i.e. user-requested fields actually found in the log).
    """
    target_texts = []
    is_cef = False
    for log_line in logs:
        if re.match(r'^CEF:\d+\|', log_line.strip()):
            is_cef = True
        predecoded = parse_phase1_predecode(log_line)
        body = (predecoded.get("body") or log_line or "").strip()
        if body:
            target_texts.append(body)
            
    target_text = "\n".join(target_texts)
    if not target_text:
        return []

    # ── CEF key=value extension handling ──────────────────────────────────
    if is_cef:
        cef_field_map: Dict[str, str] = fields.get("_cef_field_map", {})  # type: ignore[assignment]
        results: List[Tuple[str, List[str]]] = []
        for key, value in fields.items():
            if key.startswith("_") or not value or not isinstance(value, str):
                continue
                
            # Find the actual CEF extension key for this user-requested field
            cef_key = None
            canonical_name = canonicalize_field_name(key)
            aliases = FIELD_ALIASES.get(canonical_name, (canonical_name,))
            for alias in aliases:
                canonical_alias = canonicalize_field_name(alias)
                for wazuh_field, ck in cef_field_map.items():
                    if canonicalize_field_name(wazuh_field) == canonical_alias:
                        cef_key = ck
                        break
                if cef_key:
                    break
                    
            if not cef_key:
                continue

            if cef_key == "msg":
                # msg values may contain spaces — greedy capture
                results.append((rf"\.+{re.escape(cef_key)}=(\.+)", [key]))
            elif cef_key in ("spt", "dpt", "end", "start", "cnt", "in", "out"):
                results.append((rf"\.+{re.escape(cef_key)}=(\d+)", [key]))
            elif re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', value):
                results.append((rf"\.+{re.escape(cef_key)}=(\d+\.\d+\.\d+\.\d+)", [key]))
            else:
                results.append((rf"\.+{re.escape(cef_key)}=(\S+)", [key]))
        if results:
            return results

    # ── Generic key=value / free-form split ───────────────────────────────
    results = []
    for key, value in fields.items():
        if key in ("message", "_cef_field_map") or key.startswith("_") or not value or not isinstance(value, str):
            continue
            
        # 1. Try to find if this field has a KV context stored from extractors
        kv_str = fields.get(f"_kv_{key}")
        if kv_str:
            sep_match = re.search(rf"({re.escape(key)}\s*[=:]+\s*){re.escape(value)}", target_text)
            if sep_match:
                prefix = sep_match.group(1)
                results.append((f"\\.+{re.escape(prefix)}(\\S+)", [key]))
                continue
                
        # 2. Try a robust regex to dynamically find "key=value" or "key: value"
        # without hardcoding prefix length
        match = re.search(r'\b(\w+\s*[=:]\s*[\'"]?)' + re.escape(value) + r'(?:[\'"]?)(?:\b|$)', target_text)
        if match:
            prefix = match.group(1).strip()
            results.append((f"\\.+{re.escape(prefix)}(\\S+)", [key]))
            continue

        # 3. Fallback for completely free-form fields without key=
        found = re.search(re.escape(value), target_text)
        if found:
            start = found.start()
            
            # Determine appropriate capture group pattern
            capture_group = r"(\S+)"
            if re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', value):
                capture_group = r"(\d+\.\d+\.\d+\.\d+)"
            elif value.isdigit():
                capture_group = r"(\d+)"
                
            prefix_candidate = target_text[:start]
            last_space = prefix_candidate.rstrip().rfind(' ')
            if last_space != -1:
                prefix_text = prefix_candidate[last_space+1:]
            else:
                prefix_text = prefix_candidate
                
            # Fallback if prefix_text is somehow completely empty or too short
            if len(prefix_text.strip()) < 2:
                prefix_text = target_text[max(0, start - 4):start]
                
            if re.search(r'\d+[.:]\d+', prefix_text):
                prefix_escaped = re.escape(prefix_text)
                prefix_escaped = re.sub(r'\d+', r'\\d+', prefix_escaped)
            else:
                prefix_escaped = re.escape(prefix_text)

            results.append((f"\\.+{prefix_escaped}{capture_group}", [key]))
            
    return results


FIELD_ALIASES: Dict[str, Tuple[str, ...]] = {
    "logtime": ("logtime", "timestamp", "time"),
    "timestamp": ("timestamp", "logtime", "time"),
    "logsource": ("logsource", "hostname", "host", "source"),
    "hostname": ("hostname", "logsource", "host"),
    "host": ("host", "hostname", "logsource"),
    "loglevel": ("loglevel", "level", "status", "severity"),
    "level": ("level", "loglevel", "status", "severity"),
    "severity": ("severity", "loglevel", "level", "status"),
    "status": ("status", "loglevel", "level", "severity"),
    "logger": ("logger", "program", "program_name", "component"),
    "thread": ("thread", "thread_id"),
    "wtoken": ("wtoken",),
    "token": ("token",),
    "alldrawn": ("allDrawn", "alldrawn"),
    "startingdisplayed": ("startingDisplayed", "startingdisplayed"),
    "message": ("message", "msg"),
    # CEF extension field aliases (user-facing → internal Wazuh field names)
    "sourceip": ("srcip", "sourceip", "src"),
    "srcip": ("srcip", "sourceip", "src"),
    "destinationip": ("dstip", "destinationip", "dst"),
    "dstip": ("dstip", "destinationip", "dst"),
    "sourceport": ("sourceport", "srcport", "spt"),
    "srcport": ("sourceport", "srcport", "spt"),
    "destinationport": ("destinationport", "dstport", "dpt"),
    "dstport": ("destinationport", "dstport", "dpt"),
    "dvchost": ("dvchost",),
}


def canonicalize_field_name(field_name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]+", "", field_name.strip()).lower()


def select_requested_fields(
    available_fields: Dict[str, str],
    requested_fields: List[str],
) -> tuple[Dict[str, str], List[str]]:
    selected: Dict[str, str] = {}
    missing: List[str] = []
    canonical_available = {canonicalize_field_name(name): name for name in available_fields}
    available_keys = list(canonical_available.keys())
    for raw_name in requested_fields:
        field_name = raw_name.strip()
        if not field_name:
            continue
        canonical_name = canonicalize_field_name(field_name)
        alias_candidates = FIELD_ALIASES.get(canonical_name, (canonical_name,))
        matched_key: Optional[str] = None
        for candidate in alias_candidates:
            source_key = canonical_available.get(canonicalize_field_name(candidate))
            if source_key and available_fields.get(source_key):
                matched_key = source_key
                break
        if not matched_key:
            for available_key in available_keys:
                if canonical_name in available_key or available_key in canonical_name:
                    source_key = canonical_available.get(available_key)
                    if source_key and available_fields.get(source_key):
                        matched_key = source_key
                        break
        if matched_key:
            selected[field_name] = available_fields[matched_key]
            continue
        missing.append(field_name)
    return selected, missing


def fields_excluding_noise(fields: Dict[str, str]) -> Dict[str, str]:
    # Exclude noisy/internal keys from field selection
    excluded = {"program", "message"}
    internal_prefixes = ("_kv_", "_cef_")
    return {
        key: value
        for key, value in fields.items()
        if key not in excluded
        and not any(key.startswith(p) for p in internal_prefixes)
        and value
        and not isinstance(value, dict)
    }


def merge_field_names(*field_lists: List[str]) -> List[str]:
    ordered: List[str] = []
    seen = set()
    for field_list in field_lists:
        for field_name in field_list:
            cleaned = field_name.strip()
            if not cleaned or cleaned in seen:
                continue
            ordered.append(cleaned)
            seen.add(cleaned)
    return ordered


def infer_fields_from_all_logs(logs: List[str]) -> Dict[str, str]:
    if not logs:
        return {}
    extracted_sets = [extract_relevant_fields(line) for line in logs if line.strip()]
    if not extracted_sets:
        return {}

    union_fields: Dict[str, str] = {}
    for fields in extracted_sets:
        for key, value in fields.items():
            if key not in union_fields and value and not key.startswith("_") and isinstance(value, str):
                union_fields[key] = value
                
            # Also preserve internal keys like _cef_field_map and _kv_ prefixes
            # so the split decoder can use them later
            if key.startswith("_") and key not in union_fields and value:
                union_fields[key] = value

    return union_fields


TIMESTAMP_SYNTH_PATTERNS: List[re.Pattern] = [
    re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"),
    re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b"),
    re.compile(r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b"),
    re.compile(r"\b\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?\b"),
    re.compile(r"\b\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\b"),
    re.compile(r"\b\d{8}-\d{2}:\d{2}:\d{2}:\d+\b"),
]

LEVEL_SYNTH_PATTERN = re.compile(
    r"\b(?:EMERGENCY|EMERG|ALERT|CRITICAL|CRIT|ERROR|ERR|WARNING|WARN|NOTICE|INFORMATIONAL|INFO|DEBUG|TRACE|FATAL|SEVERE|FINE|FINER|FINEST)\b",
    re.IGNORECASE,
)

SYNTHESIZER_TARGETS: Dict[str, str] = {
    "logtime": "logtime",
    "timestamp": "logtime",
    "time": "logtime",
    "logsource": "logsource",
    "hostname": "logsource",
    "host": "logsource",
    "source": "logsource",
    "loglevel": "loglevel",
    "level": "loglevel",
    "severity": "loglevel",
    "status": "loglevel",
    "message": "message",
}


def synth_extract_timestamp(log_line: str) -> Optional[str]:
    for pattern in TIMESTAMP_SYNTH_PATTERNS:
        m = pattern.search(log_line)
        if m:
            return m.group(0)
    return None


def synth_extract_hostname(log_line: str, timestamp: Optional[str]) -> Optional[str]:
    if not timestamp:
        return None
    idx = log_line.find(timestamp)
    if idx < 0:
        return None
    tail = log_line[idx + len(timestamp):]
    tail_stripped = tail.lstrip()
    m = re.match(r"([A-Za-z0-9_.-]+)", tail_stripped)
    if not m:
        return None
    token = m.group(1)
    if token.endswith(":"):
        return None
    if LEVEL_SYNTH_PATTERN.fullmatch(token):
        return None
    return token


def synth_extract_level(log_line: str) -> Optional[str]:
    m = LEVEL_SYNTH_PATTERN.search(log_line)
    return m.group(0) if m else None


def synth_extract_message(
    log_line: str,
    timestamp: Optional[str],
    host: Optional[str],
    level: Optional[str],
) -> Optional[str]:
    cursor = 0
    for anchor in (timestamp, host, level):
        if not anchor:
            continue
        idx = log_line.find(anchor, cursor)
        if idx >= 0:
            cursor = idx + len(anchor)
    if cursor <= 0:
        return None
    tail = log_line[cursor:].lstrip(" \t:-")
    return tail.strip() or None


def synthesize_requested_fields(
    log_line: str,
    requested_fields: List[str],
    existing_fields: Dict[str, str],
) -> Dict[str, str]:
    if not log_line or not requested_fields:
        return {}

    existing_canonical = {canonicalize_field_name(k) for k in existing_fields}
    targets: List[str] = []
    for raw_name in requested_fields:
        canonical = canonicalize_field_name(raw_name)
        mapped = SYNTHESIZER_TARGETS.get(canonical)
        if mapped and mapped not in targets and mapped not in existing_canonical:
            targets.append(mapped)

    if not targets:
        return {}

    synthesized: Dict[str, str] = {}

    timestamp: Optional[str] = None
    if "logtime" in targets:
        timestamp = synth_extract_timestamp(log_line)
        if timestamp:
            synthesized["logtime"] = timestamp

    host: Optional[str] = None
    if "logsource" in targets:
        host = synth_extract_hostname(log_line, timestamp or synth_extract_timestamp(log_line))
        if host:
            synthesized["logsource"] = host

    level: Optional[str] = None
    if "loglevel" in targets:
        level = synth_extract_level(log_line)
        if level:
            synthesized["loglevel"] = level

    if "message" in targets:
        message = synth_extract_message(
            log_line,
            timestamp or synth_extract_timestamp(log_line),
            host or synth_extract_hostname(log_line, timestamp or synth_extract_timestamp(log_line)),
            level or synth_extract_level(log_line),
        )
        if message:
            synthesized["message"] = message

    return synthesized


def choose_log_driven_fields(
    logs: List[str],
    requested_fields: List[str],
    ml_order: Optional[List[str]] = None,
) -> tuple[Dict[str, str], List[str], List[str]]:
    common_fields = infer_fields_from_all_logs(logs)
    auto_fields = safe_auto_fields(first_non_empty(logs))
    if not common_fields:
        common_fields = auto_fields

    if requested_fields:
        first_log = first_non_empty(logs)
        synthesized = synthesize_requested_fields(first_log, requested_fields, common_fields)
        for key, value in synthesized.items():
            if value and key not in common_fields:
                common_fields[key] = value

    selected_requested, missing_requested = select_requested_fields(common_fields, requested_fields)
    ml_selected, _ = select_requested_fields(common_fields, ml_order or [])
    fallback_fields = fields_excluding_noise(common_fields)

    requested_canonical = {canonicalize_field_name(name) for name in (requested_fields or [])}
    if requested_canonical:
        field_order = merge_field_names(
            list(selected_requested.keys()),
            list(ml_selected.keys()),
        )
    else:
        field_order = merge_field_names(
            list(selected_requested.keys()),
            list(ml_selected.keys()),
            list(fallback_fields.keys()),
        )
    # Use the actual values from selected_requested which already handled mapping/aliases
    chosen_fields = {}
    for name in field_order:
        if name in selected_requested:
            chosen_fields[name] = selected_requested[name]
        elif name in ml_selected:
            chosen_fields[name] = ml_selected[name]
        elif name in fallback_fields:
            chosen_fields[name] = fallback_fields[name]
            
    return chosen_fields, field_order, missing_requested


def build_log_based_regex(
    logs: List[str],
    requested_fields: List[str],
    ml_order: Optional[List[str]] = None,
    split_decoders: bool = False,
) -> tuple[List[Tuple[str, List[str]]], List[str], List[str]]:
    first_log = first_non_empty(logs)
    auto_fields = extract_relevant_fields(first_log)
    is_cef = re.match(r'^CEF:\d+\|', first_log.strip()) is not None

    # Always use split-decoder mode for all log types (CEF, Syslog, etc)
    # as requested, because child decoders are far more reliable than a single regex.
    split_decoders = True

    chosen_fields, field_order, missing_fields = choose_log_driven_fields(logs, requested_fields, ml_order=ml_order)

    # For CEF logs inject the _cef_field_map so the split builder can use it
    if is_cef and "_cef_field_map" in auto_fields:
        chosen_fields["_cef_field_map"] = auto_fields["_cef_field_map"]  # type: ignore[assignment]

    # Generate one child decoder per field (split mode)
    if split_decoders:
        split_results = build_split_regexes_from_fields(logs, chosen_fields)
        if split_results:
            return split_results, field_order, missing_fields

    # If split mode somehow yielded no results, fallback to legacy detectors
    if not is_cef:
        bracketed_requested_fields = requested_fields or []
        bracketed_regex, bracketed_order = infer_bracketed_log_regex(first_log, bracketed_requested_fields, auto_fields)
        if bracketed_regex and bracketed_order:
            return [(bracketed_regex, bracketed_order)], field_order, missing_fields

        java_dash_regex, java_dash_order = infer_java_dash_log_regex(first_log, bracketed_requested_fields, auto_fields)
        if java_dash_regex and java_dash_order:
            return [(java_dash_regex, java_dash_order)], field_order, missing_fields

    dynamic_regex, dynamic_order = build_dynamic_regex_from_fields(first_log, chosen_fields)
    if dynamic_regex and dynamic_order:
        return [(dynamic_regex, dynamic_order)], field_order, missing_fields

    # Fallback to generalized whole-line match if dynamic fails
    generalized = build_generalized_osregex(first_log)
    return [(f"({generalized})", ["message"])], field_order, missing_fields


def validate_osregex(regex: str) -> List[str]:
    errors: List[str] = []
    unsupported_checks = [
        (r"\\d\{", r"osregex does not support counted quantifiers like \d{2}; repeat the token explicitly."),
        (r"\(\?:", r"osregex does not support non-capturing groups (?:...)."),
        (r"\[\^", r"osregex does not support bracket character classes like [^...]."),
        (r"\[[A-Za-z0-9]-[A-Za-z0-9]", r"osregex does not support bracket ranges like [A-Z]."),
    ]
    for pattern, message in unsupported_checks:
        if re.search(pattern, regex):
            errors.append(message)
    if r"\." in regex:
        errors.append(r"osregex treats \. as any character; use a literal . when you mean a dot.")
    return errors


def infer_android_windowmanager_regex(
    log_line: str,
    requested_fields: List[str],
    available_fields: Dict[str, str],
) -> tuple[Optional[str], List[str]]:
    android_log = re.match(
        r"^(?P<logtime>\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)"
        r" +(?P<pid>\d+)"
        r" +(?P<tid>\d+)"
        r" +(?P<level>\S)"
        r" +(?P<logger>[\w.$-]+):"
        r" +(?P<body>.*)$",
        log_line.strip(),
    )
    if not android_log or android_log.group("logger") != "WindowManager":
        return None, []

    requested = {canonicalize_field_name(name) for name in requested_fields}
    supported = {"logtime", "wtoken", "token", "alldrawn", "startingdisplayed"}
    if not requested.intersection(supported):
        return None, []

    order: List[str] = []
    parts = [
        r"(\d+-\d+ \d+:\d+:\d+.\d+)",
        r"  \d+",
        r"  \d+",
        r" \S",
        r" WindowManager:",
        r" \S+",
        r" \S+",
    ]
    if "logtime" in requested and available_fields.get("logtime"):
        order.append("logtime")

    if "wtoken" in requested and available_fields.get("wtoken"):
        parts.append(r" wtoken = (\.+)")
        order.append("wtoken")
    else:
        parts.append(r" wtoken = \S+")

    if "token" in requested and available_fields.get("token"):
        parts.append(r" token=(\.+)")
        order.append("token")
    else:
        parts.append(r" token=\S+")

    parts.append(r", allDrawn= ")
    if "alldrawn" in requested and available_fields.get("allDrawn"):
        parts.append(r"(\S+)")
        order.append("allDrawn")
    else:
        parts.append(r"\S+")

    if "startingdisplayed" in requested and available_fields.get("startingDisplayed"):
        parts.append(r", startingDisplayed =  (\S+)")
        order.append("startingDisplayed")

    regex = "".join(parts)
    return (regex or None), order


def infer_java_dash_log_regex(
    log_line: str,
    requested_fields: List[str],
    available_fields: Dict[str, str],
) -> tuple[Optional[str], List[str]]:
    java_dash_log = re.match(
        r"^(?P<logtime>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d+)\s+-\s+(?P<loglevel>\w+)\s+\[(?P<thread>[^\]]+)\]\s+-\s+(?P<message>.*)$",
        log_line.strip(),
    )
    if not java_dash_log:
        return None, []

    selected = {canonicalize_field_name(name) for name in requested_fields}
    if not selected:
        selected = {"logtime", "loglevel", "message"}

    parts: List[str] = []
    order: List[str] = []

    if "logtime" in selected and available_fields.get("logtime"):
        parts.append(r"(\d+-\d+-\d+\s+\d+:\d+:\d+,\d+)")
        order.append("logtime")
    else:
        parts.append(r"\d+-\d+-\d+\s+\d+:\d+:\d+,\d+")

    parts.append(r"\s+-\s+")

    if ("loglevel" in selected or "level" in selected or "status" in selected) and available_fields.get("loglevel"):
        parts.append(r"(\w+)")
        order.append("loglevel")
    else:
        parts.append(r"\w+")

    parts.append(r"\s+\[")

    if "thread" in selected and available_fields.get("thread"):
        parts.append(r"([\w:$@.-]+)")
        order.append("thread")
    else:
        parts.append(r"[\w:$@.-]+")

    parts.append(r"\]\s+-\s+")

    if "message" in selected and available_fields.get("message"):
        parts.append(r"(\.+)")
        order.append("message")
    else:
        parts.append(r"\.+")

    regex = "".join(parts)
    return (regex or None), order


def infer_bracketed_log_regex(
    log_line: str,
    requested_fields: List[str],
    available_fields: Dict[str, str],
) -> tuple[Optional[str], List[str]]:
    bracketed_log = re.match(
        r"^\[(?P<logtime>\d{2,4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d+)\]"
        r"\s+(?P<loglevel>\S+)\s+-\s+\[(?P<thread>[^\]]+)\]\s+(?P<message>.*)$",
        log_line.strip(),
    )
    if not bracketed_log:
        return None, []

    selected = {canonicalize_field_name(name) for name in requested_fields}
    if not selected:
        selected = {"logtime", "loglevel", "message"}

    parts: List[str] = ["["]
    order: List[str] = []

    if "logtime" in selected and available_fields.get("logtime"):
        parts.append(r"(\d+-\d+-\d+\s+\d+:\d+:\d+,\d+)")
        order.append("logtime")
    else:
        parts.append(generalize_osregex_token(available_fields.get("logtime", bracketed_log.group("logtime"))))

    parts.append(r"]\s+")

    if ("loglevel" in selected or "level" in selected or "status" in selected) and available_fields.get("loglevel"):
        parts.append(r"(\S+)")
        order.append("loglevel")
    else:
        parts.append(generalize_osregex_token(available_fields.get("loglevel", bracketed_log.group("loglevel"))))

    parts.append(r"\s+-\s+[")

    if "thread" in selected and available_fields.get("thread"):
        parts.append(r"(\S+)")
        order.append("thread")
    else:
        parts.append(generalize_osregex_token(available_fields.get("thread", bracketed_log.group("thread"))))

    parts.append(r"]\s+")

    bracketed_message = bracketed_log.group("message").strip()
    logger_value = available_fields.get("logger")
    message_value = available_fields.get("message", bracketed_message)

    if logger_value and bracketed_message.startswith(f"{logger_value}:"):
        if "logger" in selected:
            parts.append(r"(\S+):\s+")
            order.append("logger")
        else:
            parts.append(generalize_regex_literal(f"{logger_value}: "))

    if "message" in selected and available_fields.get("message"):
        parts.append(r"(.+)")
        order.append("message")
    else:
        parts.append(generalize_regex_literal(message_value))

    regex = "".join(parts)
    return (regex or None), order


def infer_multi_bracketed_log_regex(
    log_line: str,
    requested_fields: List[str],
    available_fields: Dict[str, str],
) -> tuple[Optional[str], List[str]]:
    multi_bracketed_log = re.match(
        r"^\[(?P<logtime>[^\]]+)\]\s*\[(?P<loglevel>[^\]]+)\]\s*\[(?P<logger>[^\]]+)\]\s*\[(?P<node>[^\]]+)\]\s+(?P<message>.+)$",
        log_line.strip(),
    )
    if not multi_bracketed_log:
        return None, []

    selected = {canonicalize_field_name(name) for name in requested_fields}
    if not selected:
        selected = {"logtime", "loglevel", "message"}

    parts: List[str] = [r"\p"]
    order: List[str] = []

    if "logtime" in selected and available_fields.get("logtime"):
        logtime_val = available_fields["logtime"]
        logtime_pattern = r"\d+-\d+-\S+:\d+:\d+,\d+"
        parts.append("(" + logtime_pattern + ")")
        order.append("logtime")
    else:
        parts.append(r"\d+-\d+-\S+:\d+:\d+,\d+")

    parts.append(r"\p\p")

    if ("loglevel" in selected or "level" in selected or "status" in selected) and available_fields.get("loglevel"):
        parts.append(r"(\S+) \p\p")
        order.append("loglevel")
    else:
        parts.append(r"\S+ \p\p")

    if "logger" in selected and available_fields.get("logger"):
        parts.append(r"(\S+)\p\s\p")
        order.append("logger")
    else:
        parts.append(r"\S+\p\s\p")

    if "node" in selected and available_fields.get("node"):
        parts.append(r"(\S+)\p\s")
        order.append("node")
    else:
        parts.append(r"\S+\p\s")

    if "message" in selected and available_fields.get("message"):
        parts.append(r"(\.+)")
        order.append("message")
    else:
        parts.append(r"\.+")

    regex = "".join(parts)
    return (regex or None), order


def infer_regex_and_order(logs: List[str], requested_fields: Optional[List[str]] = None) -> tuple[str, List[str], List[str], List[str]]:
    return build_log_based_regex(logs, requested_fields or [])


def score_ml_decoder_template(
    ml_suggestion: Dict[str, Any],
    available_fields: Dict[str, str],
    requested_fields: List[str],
) -> float:
    score = float(ml_suggestion.get("score") or 0)
    ml_order = [str(item) for item in (ml_suggestion.get("order") or []) if str(item).strip()]
    if not ml_order:
        return score

    selected_ml_fields, _ = select_requested_fields(available_fields, ml_order)
    if not selected_ml_fields:
        return 0.0

    requested_selected, missing_requested = select_requested_fields(available_fields, requested_fields)
    requested_count = len(requested_fields)
    matched_requested_count = len(requested_selected)
    if requested_count:
        score += matched_requested_count / requested_count
        if missing_requested:
            score -= len(missing_requested) / requested_count

    score += len(selected_ml_fields) / max(1, len(ml_order))
    return score


def select_ml_decoder_template(
    logs: List[str],
    requested_fields: List[str],
    ml_suggestions: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if not ml_suggestions:
        return None

    available_fields = infer_fields_from_all_logs(logs) or extract_relevant_fields(first_non_empty(logs))
    ranked = sorted(
        ml_suggestions,
        key=lambda suggestion: score_ml_decoder_template(suggestion, available_fields, requested_fields),
        reverse=True,
    )
    selected = ranked[0]
    if score_ml_decoder_template(selected, available_fields, requested_fields) <= 0:
        return None
    return selected


def parse_phase1_predecode(log_line: str) -> Dict[str, str]:
    data: Dict[str, str] = {}
    # Handles common syslog style: Dec 25 20:45:02 host program[pid]: message
    syslog_re = re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<program>[\w.-]+)(?:\[\d+\])?:\s*(?P<body>.*)$"
    )
    m = syslog_re.match(log_line.strip())
    if not m:
        return data
    data["timestamp"] = m.group("timestamp")
    data["hostname"] = m.group("hostname")
    data["program_name"] = m.group("program")
    data["body"] = m.group("body")
    return data


def derive_unique_token(after_predecoded: str) -> str:
    if not after_predecoded:
        return ""
    tokens = re.findall(r"[A-Za-z][A-Za-z0-9_.:/-]{2,}", after_predecoded)
    ignored = {"info", "warn", "warning", "error", "debug", "failed", "success", "login", "user", "from"}
    for token in tokens:
        if token.lower() in ignored:
            continue
        if re.fullmatch(r"\d+(?:\.\d+)*", token):
            continue
        return token
    return tokens[0] if tokens else ""


# ── CEF (Common Event Format) support ────────────────────────────────────────
# Maps CEF extension key names → Wazuh decoder field names.
# Extend this table to support more CEF fields.
CEF_FIELD_MAP: Dict[str, str] = {
    "src":     "srcip",
    "dst":     "dstip",
    "spt":     "sourceport",
    "dpt":     "destinationport",
    "dvchost": "dvchost",
    "dvc":     "dvchost",
    "msg":     "message",
    "act":     "action",
    "outcome": "action",
    "suser":   "srcuser",
    "duser":   "dstuser",
    "shost":   "srchost",
    "dhost":   "dsthost",
    "proto":   "protocol",
    "app":     "protocol",
    "cat":     "category",
    "severity":"severity",
    "end":     "end_time",
    "start":   "start_time",
    "cn1":     "id",
    "fname":   "filename",
    "filePath":"filepath",
    "fileHash":"filehash",
    "url":     "url",
    "request": "url",
    "cs1":     "cs1",
    "cs2":     "cs2",
}


def safe_auto_fields(log_line: str) -> Dict[str, str]:
    """Return extracted fields safe for JSON serialisation.

    Strips internal metadata entries (keys starting with '_') and any values
    that are not plain strings (e.g. the _cef_field_map nested dict).
    """
    raw = extract_relevant_fields(log_line)
    return {
        k: v
        for k, v in raw.items()
        if not k.startswith("_") and isinstance(v, str)
    }


def extract_cef_fields(log_line: str) -> Optional[Dict[str, str]]:
    """
    Parses a CEF log line and returns extracted fields mapped to Wazuh names.
    Returns None if the log is not CEF format.

    CEF format: CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension
    """
    cef_match = re.match(
        r'^CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$',
        log_line.strip(),
    )
    if not cef_match:
        return None

    fields: Dict[str, str] = {}
    fields["cef_version"]    = cef_match.group(1)
    fields["vendor"]         = cef_match.group(2)
    fields["product"]        = cef_match.group(3)
    fields["device_version"] = cef_match.group(4)
    fields["signature_id"]   = cef_match.group(5)
    fields["event_name"]     = cef_match.group(6)
    fields["severity"]       = cef_match.group(7)
    extension                = cef_match.group(8)

    # Parse extension: key=value pairs (values may be quoted or space-delimited)
    # CEF spec: keys are alphanumeric, values end at the next known key or EOS
    # Simple greedy parse: split on <key>= boundaries
    ext_tokens = re.findall(r'([\w]+)=((?:(?!\s+\w+=).)+)', extension)
    cef_field_map_used: Dict[str, str] = {}  # wazuh_field → cef_key
    for cef_key, raw_value in ext_tokens:
        value = raw_value.strip()
        wazuh_field = CEF_FIELD_MAP.get(cef_key, cef_key)  # fall back to raw key
        fields.setdefault(wazuh_field, value)
        # Also store original CEF key name for regex building
        fields.setdefault(f"_kv_{wazuh_field}", f"{cef_key}={value}")
        cef_field_map_used[wazuh_field] = cef_key

    # Store the reverse map so split decoder builder knows which CEF key to use
    fields["_cef_field_map"] = cef_field_map_used  # type: ignore[assignment]
    return fields


def extract_relevant_fields(log_line: str) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    text = (log_line or "").strip()
    if not text:
        return fields

    # JSON logs
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            for key, value in parsed.items():
                if isinstance(value, (str, int, float, bool)):
                    fields[str(key)] = str(value)
            if fields:
                return fields
    except Exception:
        pass

    # CEF logs — detect and parse before generic key=value
    cef_fields = extract_cef_fields(text)
    if cef_fields is not None:
        fields.update(cef_fields)
        # Still run IP fallback below, but skip generic kv scan
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        if ip_match:
            fields.setdefault("srcip", ip_match.group(0))
        return fields

    # key=value, key==value, key:value, key::value pairs
    kv_pattern = r"(\b[\w\.-]+)\s*([=:]+)\s*('(?:[^']|\\')*'|\"(?:[^\"]|\\\")*\"|[^\s,;]+)"
    for key, sep, val in re.findall(kv_pattern, text):
        cleaned = val.strip("'\"")
        if cleaned:
            # Store the separator context if we want to use it for regex building
            fields.setdefault(key, cleaned)
            # We can also store the full "key=value" string to help regex generation
            fields.setdefault(f"_kv_{key}", f"{key}{sep}{cleaned}")

    # Common semantic patterns
    user_action = re.search(r"User '([^']+)' (failed login|successful login|login failed|login success|logged in)", text, flags=re.IGNORECASE)
    if user_action:
        fields.setdefault("user", user_action.group(1))
        fields.setdefault("action", user_action.group(2).lower())

    unquoted_user_action = re.search(
        r"\bUser\s+([A-Za-z0-9_.@:-]+)\s+(failed login|successful login|login failed|login success|logged in)\b",
        text,
        flags=re.IGNORECASE,
    )
    if unquoted_user_action:
        fields.setdefault("user", unquoted_user_action.group(1))
        fields.setdefault("action", unquoted_user_action.group(2).lower())

    java_log = re.match(
        r"^(?P<timestamp>\d{2,4}[/-]\d{2}[/-]\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<status>INFO|WARN|ERROR|DEBUG)\s+(?P<logger>[\w.$-]+):\s*(?P<message>.*)$",
        text,
        flags=re.IGNORECASE,
    )
    if java_log:
        fields.setdefault("timestamp", java_log.group("timestamp"))
        fields.setdefault("status", java_log.group("status"))
        fields.setdefault("logger", java_log.group("logger"))
        if java_log.group("message"):
            fields.setdefault("message", java_log.group("message"))

    # Java-style log with dash separator: YYYY-MM-DD HH:MM:SS,mmm - LEVEL [thread] - message
    java_dash_log = re.match(
        r"^(?P<logtime>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d+)\s+-\s+(?P<loglevel>\w+)\s+\[(?P<thread>[^\]]+)\]\s+-\s+(?P<message>.*)$",
        text,
    )
    if java_dash_log:
        fields.setdefault("logtime", java_dash_log.group("logtime"))
        fields.setdefault("loglevel", java_dash_log.group("loglevel"))
        fields.setdefault("thread", java_dash_log.group("thread"))
        fields.setdefault("message", java_dash_log.group("message"))

    # Multi-bracketed logs like [timestamp][level][logger][node] message
    multi_bracketed_log = re.match(
        r"^\[(?P<logtime>[^\]]+)\]\s*\[(?P<loglevel>[^\]]+)\]\s*\[(?P<logger>[^\]]+)\]\s*\[(?P<node>[^\]]+)\]\s+(?P<message>.+)$",
        text,
    )
    if multi_bracketed_log:
        fields.setdefault("logtime", multi_bracketed_log.group("logtime"))
        fields.setdefault("loglevel", multi_bracketed_log.group("loglevel"))
        fields.setdefault("logger", multi_bracketed_log.group("logger"))
        fields.setdefault("node", multi_bracketed_log.group("node"))
        fields.setdefault("message", multi_bracketed_log.group("message"))

    bracketed_log = re.match(
        r"^\[(?P<logtime>\d{2,4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d+)\]"
        r"\s+(?P<loglevel>\S+)\s+-\s+\[(?P<thread>[^\]]+)\]\s+(?P<message>.*)$",
        text,
    )
    if bracketed_log:
        fields.setdefault("logtime", bracketed_log.group("logtime"))
        fields.setdefault("loglevel", bracketed_log.group("loglevel"))
        fields.setdefault("thread", bracketed_log.group("thread"))
        bracketed_message = bracketed_log.group("message").strip()
        logger_and_message = re.match(r"^(?P<logger>[^:]+):\s+(?P<body>.*)$", bracketed_message)
        if logger_and_message:
            fields.setdefault("logger", logger_and_message.group("logger").strip())
            fields.setdefault("message", logger_and_message.group("body").strip())
        elif bracketed_message:
            fields.setdefault("message", bracketed_message)

    pipe_metric_log = re.match(
        r"^(?P<logtime>\d{8}-\d{2}:\d{2}:\d{2}:\d+)\|(?P<logger>[^|]+)\|(?P<thread_id>[^|]+)\|\s*(?P<metric>[A-Za-z_][\w]*)\s*=\s*(?P<metric_value>.+)$",
        text,
    )
    if pipe_metric_log:
        fields.setdefault("logtime", pipe_metric_log.group("logtime"))
        fields.setdefault("logger", pipe_metric_log.group("logger").strip())
        fields.setdefault("thread_id", pipe_metric_log.group("thread_id").strip())
        metric_name = pipe_metric_log.group("metric").strip()
        metric_value = pipe_metric_log.group("metric_value").strip()
        if metric_name:
            fields.setdefault(metric_name, metric_value)
            fields.setdefault("metric_name", metric_name)
        if metric_value:
            fields.setdefault("metric_value", metric_value)
            fields.setdefault("message", metric_value)

    android_log = re.match(
        r"^(?P<logtime>\d{2}-\d{2} +\d{2}:\d{2}:\d{2}\.\d+)"
        r" +(?P<pid>\d+)"
        r" +(?P<tid>\d+)"
        r" +(?P<level>[A-Z])"
        r" +(?P<logger>[\w.$-]+):"
        r" +(?P<body>.*)$",
        text,
    )
    if android_log:
        fields.setdefault("logtime", android_log.group("logtime"))
        fields.setdefault("pid", android_log.group("pid"))
        fields.setdefault("tid", android_log.group("tid"))
        fields.setdefault("level", android_log.group("level"))
        fields.setdefault("logger", android_log.group("logger"))

        body = android_log.group("body").strip()
        if body:
            fields.setdefault("message", body)

        wtoken_match = re.search(r"\bwtoken += +([^\s]+)", body)
        if wtoken_match:
            fields.setdefault("wtoken", wtoken_match.group(1))

        token_match = re.search(r"\btoken=([^\s]+)", body)
        if token_match:
            fields.setdefault("token", token_match.group(1))

        all_drawn_match = re.search(r"\ballDrawn= +([^\s,]+)", body)
        if all_drawn_match:
            fields.setdefault("allDrawn", all_drawn_match.group(1))

        starting_displayed_match = re.search(r"\bstartingDisplayed += +([^\s,]+)", body)
        if starting_displayed_match:
            fields.setdefault("startingDisplayed", starting_displayed_match.group(1))

    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    if ip_match:
        fields.setdefault("srcip", ip_match.group(0))

    program = extract_program_from_log([text])
    if program:
        fields.setdefault("program", program)

    if not fields:
        fields["message"] = text
    return fields


def parse_logtest_output(stdout: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "decoder_name": None,
        "rule_id": None,
        "rule_level": None,
        "rule_description": None,
        "program_name": None,
        "predecoded_timestamp": None,
        "predecoded_hostname": None,
        "phase1_completed": "Phase 1" in stdout,
        "phase2_completed": "Phase 2" in stdout,
        "phase3_completed": "Phase 3" in stdout,
        "no_decoder_match": False,
        "no_rule_match": False,
    }

    def match_one(pattern: str) -> Optional[str]:
        m = re.search(pattern, stdout, flags=re.IGNORECASE | re.MULTILINE)
        return m.group(1) if m else None

    result["predecoded_timestamp"] = match_one(r"^\s*timestamp:\s*'([^']*)'")
    result["predecoded_hostname"] = match_one(r"^\s*hostname:\s*'([^']*)'")
    result["program_name"] = match_one(r"^\s*program_name:\s*'([^']*)'")
    result["decoder_name"] = match_one(r"^\s*name:\s*'([^']*)'")
    rule_id = match_one(r"^\s*id:\s*'([^']*)'")
    rule_level = match_one(r"^\s*level:\s*'([^']*)'")
    rule_description = match_one(r"^\s*description:\s*'([^']*)'")

    if rule_id and rule_id.isdigit():
        result["rule_id"] = int(rule_id)
    if rule_level and rule_level.isdigit():
        result["rule_level"] = int(rule_level)
    result["rule_description"] = rule_description

    lower = stdout.lower()
    result["no_decoder_match"] = ("no decoder matched" in lower) or ("name:" not in lower and result["phase2_completed"])
    result["no_rule_match"] = ("no rule matched" in lower) or ("id:" not in lower and result["phase3_completed"])
    return result


def combined_logtest_output(run: Dict[str, Any]) -> str:
    text = "\n".join(part for part in [run.get("stdout", ""), run.get("stderr", "")] if part)
    text = re.sub(
        r"\*\*Phase 1: Completed pre-decoding\.\n\tfull event: 'vagrant'\n\n\*\*Phase 2: Completed decoding\.\n\tNo decoder matched\.\n\n",
        "",
        text,
        flags=re.MULTILINE,
    )
    return text


def run_logtest_for_samples(samples: List[LogSample]) -> Dict[str, Any]:
    details = []
    builtin_decoder_seen = False
    builtin_rule_seen = False
    parsed_entries = []
    for sample in samples:
        run = run_wazuh_logtest(sample.raw_log)
        parsed = parse_logtest_output(combined_logtest_output(run)) if run["available"] else {}
        parsed_entries.append(parsed)
        details.append({"raw_log": sample.raw_log, "logtest": run, "parsed": parsed})
        if parsed.get("decoder_name"):
            builtin_decoder_seen = True
        if parsed.get("rule_id"):
            builtin_rule_seen = True
    return {
        "details": details,
        "parsed_entries": parsed_entries,
        "builtin_decoder_seen": builtin_decoder_seen,
        "builtin_rule_seen": builtin_rule_seen,
        "available": all(item["logtest"]["available"] for item in details) if details else False,
    }


def infer_rule_from_natural_language(requirement: str, default_level: int) -> Tuple[int, str]:
    if not requirement:
        return default_level, ""
    req = requirement.strip()
    level = default_level
    explicit_level = re.search(r"\blevel\s*(\d{1,2})\b", req, flags=re.IGNORECASE)
    if explicit_level:
        level = max(0, min(16, int(explicit_level.group(1))))
    else:
        lowered = req.lower()
        if any(word in lowered for word in ["critical", "severe", "urgent"]):
            level = max(level, 12)
        elif any(word in lowered for word in ["high", "important"]):
            level = max(level, 10)
        elif any(word in lowered for word in ["low", "informational", "info"]):
            level = min(level, 4)
    return level, req


def ensure_ml_model(force_refresh: bool = False) -> Optional[DecoderSimilarityModel]:
    global _ML_MODEL, _ML_MODEL_ERROR, _ML_PATTERN_COUNT

    if force_refresh:
        refreshed = refresh_wazuh_repo(
            repo_url=WAZUH_REPO_URL,
            cache_dir=WAZUH_REPO_CACHE_DIR,
            sparse_subpath=WAZUH_REPO_DECODER_SUBPATH,
            force=False,
        )
        if refreshed.get("ok") != "true":
            _ML_MODEL_ERROR = refreshed.get("message", "failed to refresh wazuh repo")
            return None

    if _ML_MODEL is not None and not force_refresh:
        return _ML_MODEL

    patterns = load_patterns_from_repo(WAZUH_REPO_CACHE_DIR, WAZUH_REPO_DECODER_SUBPATH)
    if not patterns:
        _ML_MODEL = None
        _ML_PATTERN_COUNT = 0
        _ML_MODEL_ERROR = f"no decoder xml files found in {WAZUH_REPO_CACHE_DIR / WAZUH_REPO_DECODER_SUBPATH}"
        return None

    _ML_MODEL = DecoderSimilarityModel(patterns)
    _ML_PATTERN_COUNT = len(patterns)
    _ML_MODEL_ERROR = ""
    return _ML_MODEL


def load_sbert_model() -> Optional[Any]:
    global _SBERT_MODEL
    if not _SBERT_AVAILABLE:
        return None
    if _SBERT_MODEL is not None:
        return _SBERT_MODEL
    if ML_MODEL_DIR.exists():
        try:
            _SBERT_MODEL = SentenceTransformer(str(ML_MODEL_DIR))
        except Exception:
            _SBERT_MODEL = None
    return _SBERT_MODEL


def append_jsonl_record(path: Path, record: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")


def retrain_similarity_model() -> Dict[str, Any]:
    global _ML_MODEL, _SBERT_MODEL, _ML_MODEL_ERROR

    build_proc = subprocess.run(
        [sys.executable, str(BASE_DIR.parent / "scripts" / "build_dataset.py")],
        text=True,
        capture_output=True,
        cwd=str(BASE_DIR.parent),
    )
    if build_proc.returncode != 0:
        return {
            "ok": False,
            "step": "build_dataset",
            "stdout": build_proc.stdout,
            "stderr": build_proc.stderr,
        }

    train_proc = subprocess.run(
        [sys.executable, str(BASE_DIR.parent / "scripts" / "train_similarity.py")],
        text=True,
        capture_output=True,
        cwd=str(BASE_DIR.parent),
    )
    if train_proc.returncode != 0:
        return {
            "ok": False,
            "step": "train_similarity",
            "stdout": train_proc.stdout,
            "stderr": train_proc.stderr,
        }

    _ML_MODEL = None
    _SBERT_MODEL = None
    _ML_MODEL_ERROR = ""
    ensure_ml_model(force_refresh=False)
    return {
        "ok": True,
        "build_stdout": build_proc.stdout,
        "build_stderr": build_proc.stderr,
        "train_stdout": train_proc.stdout,
        "train_stderr": train_proc.stderr,
    }


def save_feedback_example(request: FeedbackRequest) -> Dict[str, Any]:
    app_name = sanitize_name(request.app_name)
    timestamp = datetime.utcnow().isoformat() + "Z"

    if not request.approved:
        rejection_record = {
            "timestamp": timestamp,
            "approved": False,
            "app_name": app_name,
            "log": request.log.strip(),
            "extract_fields": request.extract_fields,
            "notes": request.notes or "",
        }
        append_jsonl_record(REJECTED_FEEDBACK_PATH, rejection_record)
        return {"saved": True, "trained": False, "path": str(REJECTED_FEEDBACK_PATH)}

    decoder = request.decoder
    if not decoder or not decoder.regex or not decoder.order:
        return {"saved": False, "trained": False, "error": "approved feedback requires decoder regex and order"}

    parent_name = decoder.parent or app_name
    decoder_name = decoder.name or f"{app_name}-event"
    source_file = decoder.source_file or f"feedback/{app_name}.json"
    target_parts = [
        decoder_name,
        parent_name,
        decoder.prematch or "",
        decoder.regex,
        " ".join(decoder.order),
        source_file,
    ]
    feedback_record = {
        "timestamp": timestamp,
        "approved": True,
        "log": request.log.strip(),
        "extract_fields": request.extract_fields,
        "notes": request.notes or "",
        "decoder": {
            "name": decoder_name,
            "parent": parent_name,
            "prematch": decoder.prematch or "",
            "regex": decoder.regex,
            "order": decoder.order,
            "source_file": source_file,
        },
        "target_text": " ".join(part for part in target_parts if part).lower(),
    }
    append_jsonl_record(FEEDBACK_DATASET_PATH, feedback_record)
    retrain = retrain_similarity_model()
    return {
        "saved": True,
        "trained": bool(retrain.get("ok")),
        "path": str(FEEDBACK_DATASET_PATH),
        "retrain": retrain,
    }


def ml_suggestions_for_logs(
    logs: List[str],
    extracted_program_name: Optional[str],
    unique_after_predecoded: str,
    top_k: int = 5,
) -> List[Dict[str, Any]]:
    model = ensure_ml_model(force_refresh=False)
    if not model:
        return []
    query_parts = [
        first_non_empty(logs),
        extracted_program_name or "",
        unique_after_predecoded or "",
    ]
    query = " ".join(part for part in query_parts if part).strip()
    if not query:
        return []

    sbert = load_sbert_model()
    suggestions: List[Dict[str, Any]] = []

    if sbert:
        pattern_texts = [p.feature_text for p in model.patterns]
        q_vec = sbert.encode(query, convert_to_tensor=True)
        p_vecs = sbert.encode(pattern_texts, convert_to_tensor=True)
        scores = st_util.cos_sim(q_vec, p_vecs)[0]
        top_indices = scores.topk(min(top_k, len(pattern_texts))).indices.tolist()
        for idx in top_indices:
            p = model.patterns[idx]
            suggestions.append(
                {
                    "name": p.name,
                    "parent": p.parent,
                    "program_name": p.program_name,
                    "prematch": p.prematch,
                    "regex": p.regex,
                    "order": p.order,
                    "source_file": p.source_file,
                    "score": float(scores[idx]),
                }
            )
        return suggestions

    for pattern, score in model.suggest(query=query, top_k=top_k):
        suggestions.append(
            {
                "name": pattern.name,
                "parent": pattern.parent,
                "program_name": pattern.program_name,
                "prematch": pattern.prematch,
                "regex": pattern.regex,
                "order": pattern.order,
                "source_file": pattern.source_file,
                "score": round(score, 4),
            }
        )
    return suggestions


def analyze_logs_impl(request: AnalyzeRequest) -> Dict[str, Any]:
    raw_logs = [sample.raw_log for sample in request.logs]
    app_name = sanitize_name(request.app_name)
    log_type = infer_log_type(raw_logs)
    program_name = infer_program_name(raw_logs, app_name)
    extracted_program = extract_program_from_log(raw_logs)
    logtest_scan = run_logtest_for_samples(request.logs)
    parsed_entries = logtest_scan["parsed_entries"]
    first_parsed = parsed_entries[0] if parsed_entries else {}
    predecoded_program = first_parsed.get("program_name")
    prematch_seed = predecoded_program or extracted_program or ""
    prematch = choose_prematch(raw_logs, app_name, predecoded_program=predecoded_program)
    predecoded = parse_phase1_predecode(first_non_empty(raw_logs))
    token_source = predecoded.get("body") or first_non_empty(raw_logs)
    unique_after_predecoded = derive_unique_token(token_source)
    logtest_available = logtest_scan["available"]
    first_logtest = logtest_scan["details"][0]["logtest"] if logtest_scan["details"] else {}
    ml_suggestions = ml_suggestions_for_logs(
        logs=raw_logs,
        extracted_program_name=extracted_program,
        unique_after_predecoded=unique_after_predecoded,
        top_k=5,
    )
    ml_selected = select_ml_decoder_template(raw_logs, request.extract_fields, ml_suggestions)
    # 4. Generate Regex & Order (New: returns list of pairs)
    regex_order_pairs, likely_fields, missing_extract_fields = build_log_based_regex(
        raw_logs,
        request.extract_fields,
        ml_order=(ml_selected or {}).get("order"),
        split_decoders=request.split_decoders,
    )
    
    # For compatibility with single-regex logic in analysis results
    first_regex = regex_order_pairs[0][0] if regex_order_pairs else ""
    first_order = regex_order_pairs[0][1] if regex_order_pairs else []
    regex_validation_errors = validate_osregex(first_regex)

    return {
        "app_name": app_name,
        "log_type": log_type,
        "program_name": program_name,
        "extracted_program_name": extracted_program,
        "predecoded_program_name": predecoded_program,
        "prematch": prematch,
        "unique_after_predecoded": unique_after_predecoded,
        "token_source": token_source,
        "auto_fields": safe_auto_fields(first_non_empty(raw_logs)),
        "requested_extract_fields": request.extract_fields,
        "missing_extract_fields": missing_extract_fields,
        "regex": first_regex,
        "regex_order_pairs": regex_order_pairs,
        "regex_display": first_regex,
        "regex_validation_errors": regex_validation_errors,
        "order": first_order,
        "ml_suggestions": ml_suggestions,
        "ml_selected_template": ml_selected,
        "likely_fields": likely_fields,
        "checked_with_wazuh_logtest": True,
        "wazuh_logtest_summary": {
            "available": logtest_available,
            "builtin_decoder_seen": logtest_scan["builtin_decoder_seen"],
            "builtin_rule_seen": logtest_scan["builtin_rule_seen"],
            "predecoded_program_name": first_parsed.get("program_name"),
            "decoder_name": first_parsed.get("decoder_name"),
            "rule_id": first_parsed.get("rule_id"),
            "stderr": first_logtest.get("stderr", ""),
        },
        "logtest_scan": logtest_scan,
        "needs_custom_decoder": not logtest_scan["builtin_decoder_seen"],
        "needs_custom_rule": bool(request.rule_requirement and request.rule_requirement.strip()),
        "notes": [
            "Analyze always checks the sample directly with wazuh-logtest first.",
            "Generated regex is not automatically syntax-checked by wazuh-logtest unless you test/install the generated decoder.",
            "If wazuh-logtest reports a decoder/rule, this app reuses built-ins by default.",
            "Custom rule generation is enabled when rule_requirement is provided.",
            "ML suggestions are learned from Wazuh decoder XML patterns and only influence decoder generation when their field order fits the current logs.",
        ],
    }


def build_decoder_xml(
    app_name: str,
    parent_decoder: str,
    child_decoder_name: str,
    parent_program_name: Optional[str],
    parent_prematch: Optional[str],
    child_prematch: str,
    include_child_prematch: bool,
    regex_order_pairs: List[Tuple[str, List[str]]],
) -> str:
    parent_match = ""
    if parent_program_name:
        parent_match = f"  <program_name>{escape_xml(parent_program_name)}</program_name>"
    elif parent_prematch:
        parent_match = f"  <prematch>{escape_xml(parent_prematch)}</prematch>"

    xml_parts = [
        f"<decoder name=\"{escape_xml(parent_decoder)}\">",
        parent_match,
        "</decoder>"
    ]

    for regex, order in regex_order_pairs:
        child_lines = [
            f"<decoder name=\"{escape_xml(child_decoder_name)}\">",
            f"  <parent>{escape_xml(parent_decoder)}</parent>",
        ]
        if include_child_prematch and child_prematch:
            child_lines.append(f"  <prematch>{escape_xml(child_prematch)}</prematch>")
        
        child_lines.extend(
            [
                f"  <regex>{escape_xml(regex)}</regex>",
                f"  <order>{escape_xml(','.join(order))}</order>",
                "</decoder>",
            ]
        )
        xml_parts.append("\n".join(child_lines))

    return "\n\n".join(xml_parts)


def build_rule_xml(
    app_name: str,
    rule_id: int,
    level: int,
    description: str,
    decoded_as: Optional[str] = None,
    if_sid: Optional[int] = None,
) -> str:
    lines = [
        f"<group name=\"custom,{escape_xml(app_name)},\">",
        f"  <rule id=\"{rule_id}\" level=\"{level}\">",
    ]
    if if_sid is not None:
        lines.append(f"    <if_sid>{if_sid}</if_sid>")
    elif decoded_as:
        lines.append(f"    <decoded_as>{escape_xml(decoded_as)}</decoded_as>")
    lines.append(f"    <description>{escape_xml(description)}</description>")
    lines.append("  </rule>")
    lines.append("</group>")
    return "\n".join(lines)


def regex_candidate_variants(regex: str) -> List[str]:
    variants: List[str] = []
    for item in [
        regex,
        regex.replace(r"\s+", " "),
        regex.replace(r"\S+", r"(\S+)"),
        regex.replace(r"(.*)", r"(.+)"),
    ]:
        cleaned = item.strip()
        if cleaned and cleaned not in variants:
            variants.append(cleaned)
    return variants


def render_candidate_decoder_xml(candidate: Dict[str, Any], regex_order_pairs: List[Tuple[str, List[str]]]) -> Optional[str]:
    analysis = candidate.get("analysis", {})
    if not regex_order_pairs:
        return None

    parent_program_name = candidate.get("parent_program_name")
    if parent_program_name is None and "parent_program_name" not in candidate:
        parent_program_name = analysis.get("predecoded_program_name") or analysis.get("program_name")

    parent_prematch = candidate.get("parent_prematch")
    if parent_prematch is None and "parent_prematch" not in candidate:
        parent_prematch = analysis.get("prematch")

    return build_decoder_xml(
        app_name=candidate.get("app_name", "custom"),
        parent_decoder=analysis.get("app_name", "custom"),
        child_decoder_name=candidate.get("decoder_name", f"{candidate.get('app_name', 'custom')}-event"),
        parent_program_name=parent_program_name,
        parent_prematch=parent_prematch,
        child_prematch=analysis.get("prematch", ""),
        include_child_prematch=False,
        regex_order_pairs=regex_order_pairs,
    )


def build_candidate(request: CandidateRequest) -> Dict[str, Any]:
    analysis = analyze_logs_impl(
        AnalyzeRequest(
            logs=request.logs,
            app_name=request.app_name,
            rule_requirement=request.rule_requirement,
            extract_fields=request.extract_fields,
            split_decoders=request.split_decoders,
        )
    )
    app_name = analysis["app_name"]
    first_parsed = analysis["logtest_scan"]["parsed_entries"][0] if analysis["logtest_scan"]["parsed_entries"] else {}
    existing_decoder = first_parsed.get("decoder_name")
    existing_rule_id = first_parsed.get("rule_id")
    predecoded_program = first_parsed.get("program_name")
    needs_custom_decoder = analysis["needs_custom_decoder"]
    needs_custom_rule = analysis["needs_custom_rule"]

    parent_decoder = app_name
    child_decoder_name = f"{app_name}-event"
    prematch = analysis["prematch"]
    unique_after_predecoded = analysis["unique_after_predecoded"]
    regex = analysis["regex"]
    order = analysis["order"]
    ml_selected: Optional[Dict[str, Any]] = analysis.get("ml_selected_template")

    regex_order_pairs = analysis.get("regex_order_pairs", [])
    if not regex_order_pairs:
        # Fallback if somehow missing
        regex_order_pairs = [(regex, order)]

    # Use <program_name> only when Phase 1 pre-decoding explicitly produced program_name.
    # If there are multiple parsed entries with DIFFERENT program names, build a regex.
    parsed_entries = analysis.get("logtest_scan", {}).get("parsed_entries", [])
    programs = []
    for entry in parsed_entries:
        p = entry.get("program_name")
        if p and p not in programs:
            programs.append(p)
            
    if programs:
        if len(programs) > 1:
            parent_program_name = "^" + "$|^".join(programs) + "$"
        else:
            parent_program_name = programs[0]
    else:
        parent_program_name = predecoded_program

    parent_prematch = None
    if not parent_program_name:
        token_source = analysis.get("token_source")
        logs_to_use = [token_source] if token_source else [sample.raw_log for sample in request.logs]
        parent_prematch = prematch_osregex_from_current_logs(
            logs_to_use,
            analysis.get("extracted_program_name"),
            unique_after_predecoded,
            prematch,
        )

    child_prematch = (
        unique_after_predecoded
        or prematch
        or analysis.get("extracted_program_name")
        or analysis.get("program_name")
        or app_name
    )
    # The parent decoder already scopes matching; keep child decoders regex-only.
    decoder_xml = None
    if needs_custom_decoder:
        decoder_xml = render_candidate_decoder_xml(
            {
                "app_name": app_name,
                "decoder_name": child_decoder_name,
                "analysis": analysis,
                "parent_program_name": parent_program_name,
                "parent_prematch": parent_prematch,
            },
            regex_order_pairs
        )

    effective_level = request.level
    custom_rule_description = f"{app_name} event detected"
    if request.rule_requirement:
        effective_level, custom_rule_description = infer_rule_from_natural_language(request.rule_requirement, request.level)

    rule_xml = None
    if needs_custom_rule:
        if_sid = existing_rule_id if existing_rule_id else None
        decoded_as = None if if_sid else (existing_decoder or parent_decoder)
        rule_xml = build_rule_xml(
            app_name=app_name,
            rule_id=request.rule_id,
            level=effective_level,
            description=custom_rule_description,
            decoded_as=decoded_as,
            if_sid=if_sid,
        )

    candidate = {
        "analysis": analysis,
        "ml_selected_template": ml_selected,
        "existing_decoder": existing_decoder,
        "existing_rule_id": existing_rule_id,
        "decoder_name": child_decoder_name if needs_custom_decoder else (existing_decoder or child_decoder_name),
        "decoder_xml": decoder_xml,
        "rule_xml": rule_xml,
        "rule_id": request.rule_id,
        "level": effective_level,
        "parent_program_name": parent_program_name,
        "parent_prematch": parent_prematch,
        "decision": {
            "needs_custom_decoder": needs_custom_decoder,
            "needs_custom_rule": needs_custom_rule,
            "regex_validation_errors": analysis.get("regex_validation_errors", []),
            "decoder_skip_reason": (
                f"Skipped generation: existing decoder '{existing_decoder}' already matches this log."
                if not needs_custom_decoder and existing_decoder
                else None
            ),
            "rule_skip_reason": (
                f"Skipped generation: existing rule '{existing_rule_id}' already matches this log."
                if not needs_custom_rule and existing_rule_id
                else None
            ),
            "reasoning": (
                "wazuh-logtest is unavailable; defaulting to custom decoder generation."
                if not analysis["logtest_scan"]["available"]
                else (
                    "No built-in decoder matched in wazuh-logtest output; generated decoder fields come from the user logs, with ML used to rank compatible field orders."
                    if needs_custom_decoder
                    else "A built-in decoder already matched; skipping custom decoder."
                )
            ),
        },
    }
    validation = validate_generated_candidate(candidate, request.logs)
    candidate["generation_validation"] = validation
    if validation.get("working_regex"):
        candidate["decoder_xml"] = render_candidate_decoder_xml(candidate, [(validation["working_regex"], validation.get("working_order") or order)])
        candidate["analysis"]["regex"] = validation["working_regex"]
        candidate["analysis"]["regex_display"] = validation["working_regex"]
        candidate["analysis"]["order"] = validation.get("working_order") or order
    return candidate


def find_wazuh_logtest() -> Optional[str]:
    if WAZUH_REMOTE_ENABLED:
        return WAZUH_LOGTEST
    return WAZUH_LOGTEST if Path(WAZUH_LOGTEST).exists() else None


def ssh_base_cmd() -> List[str]:
    cmd: List[str] = []
    if WAZUH_SSH_PASSWORD:
        cmd.extend(["sshpass", "-p", WAZUH_SSH_PASSWORD])

    cmd.extend(
        [
            "ssh",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-p",
            WAZUH_SSH_PORT,
        ]
    )
    if not WAZUH_SSH_PASSWORD:
        cmd.extend(["-o", "BatchMode=yes"])
    if WAZUH_SSH_KEY:
        cmd.extend(["-i", WAZUH_SSH_KEY])
    cmd.append(f"{WAZUH_SSH_USER}@{WAZUH_SSH_HOST}")
    return cmd


def build_remote_sudo_command(command: str) -> str:
    if WAZUH_SSH_PASSWORD:
        return f"sudo -S -p '' {command}"
    return f"sudo {command}"


def build_remote_stdin(payload: Optional[str] = None, requires_sudo: bool = False) -> Optional[str]:
    parts: List[str] = []
    if requires_sudo and WAZUH_SSH_PASSWORD:
        parts.append(WAZUH_SSH_PASSWORD)
    if payload:
        parts.append(payload.rstrip("\n"))
    if not parts:
        return None
    return "\n".join(parts) + "\n"


def run_ssh_command(remote_cmd: str, input_data: Optional[str] = None, timeout: int = 20) -> Dict[str, Any]:
    cmd = ssh_base_cmd() + [remote_cmd]
    proc = subprocess.run(
        cmd,
        input=input_data,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    connection_error = proc.returncode == 255 and (
        "could not resolve hostname" in (proc.stderr or "").lower()
        or "connection refused" in (proc.stderr or "").lower()
        or "permission denied" in (proc.stderr or "").lower()
        or "operation timed out" in (proc.stderr or "").lower()
        or "no route to host" in (proc.stderr or "").lower()
    )
    return {
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "connection_error": connection_error,
    }


def run_wazuh_logtest(log_line: str, expected: Optional[str] = None) -> Dict[str, Any]:
    if WAZUH_REMOTE_ENABLED:
        args = [WAZUH_LOGTEST]
        if expected:
            args.extend(["-U", expected])
        remote_cmd = build_remote_sudo_command(" ".join(shlex.quote(part) for part in args))
        proc = run_ssh_command(remote_cmd, input_data=build_remote_stdin(log_line, requires_sudo=True), timeout=20)
        if proc["connection_error"]:
            return {
                "available": False,
                "ok": False,
                "returncode": proc["returncode"],
                "stdout": proc["stdout"],
                "stderr": proc["stderr"],
            }
        return {
            "available": True,
            "ok": proc["returncode"] == 0,
            "returncode": proc["returncode"],
            "stdout": proc["stdout"],
            "stderr": proc["stderr"],
        }

    binary = find_wazuh_logtest()
    if not binary:
        return {
            "available": False,
            "ok": False,
            "returncode": None,
            "stdout": "",
            "stderr": f"wazuh-logtest not found at {WAZUH_LOGTEST}",
        }

    cmd = [binary]
    if expected:
        cmd.extend(["-U", expected])

    proc = subprocess.run(
        cmd,
        input=log_line + "\n",
        text=True,
        capture_output=True,
        timeout=10,
    )
    return {
        "available": True,
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def write_candidate_files(candidate: Dict[str, Any]) -> Dict[str, Any]:
    writes = []
    errors = []
    app_name = candidate["analysis"]["app_name"]
    stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")

    def write_remote_xml(target_dir: str, prefix: str, content: Optional[str]):
        if not content:
            return
        filename = f"local_{sanitize_name(app_name)}_{prefix}_{stamp}.xml"
        remote_path = f"{target_dir.rstrip('/')}/{filename}"
        remote_cmd = build_remote_sudo_command(f"tee {shlex.quote(remote_path)} >/dev/null")
        proc = run_ssh_command(remote_cmd, input_data=build_remote_stdin(content, requires_sudo=True), timeout=20)
        if proc["returncode"] == 0:
            writes.append(f"ssh://{WAZUH_SSH_USER}@{WAZUH_SSH_HOST}:{remote_path}")
            return
        errors.append(f"failed to write remote {remote_path}: rc={proc['returncode']} stderr={proc['stderr'].strip()}")

    def write_xml(target_dir: str, fallback_subdir: str, prefix: str, content: Optional[str]):
        if not content:
            return
        filename = f"local_{sanitize_name(app_name)}_{prefix}_{stamp}.xml"
        path = Path(target_dir) / filename
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content + "\n", encoding="utf-8")
            writes.append(str(path))
            return
        except Exception as exc:  # noqa: BLE001
            errors.append(f"failed to write {path}: {exc}")

        fallback = LOCAL_OUTPUT_DIR / fallback_subdir / filename
        try:
            fallback.parent.mkdir(parents=True, exist_ok=True)
            fallback.write_text(content + "\n", encoding="utf-8")
            writes.append(str(fallback))
            errors.append(f"wrote fallback file instead: {fallback}")
        except Exception as fallback_exc:  # noqa: BLE001
            errors.append(f"failed to write fallback {fallback}: {fallback_exc}")

    if WAZUH_REMOTE_ENABLED:
        write_remote_xml(WAZUH_DECODERS_DIR, "decoder", candidate.get("decoder_xml"))
        write_remote_xml(WAZUH_RULES_DIR, "rule", candidate.get("rule_xml"))
    else:
        write_xml(WAZUH_DECODERS_DIR, "decoders", "decoder", candidate.get("decoder_xml"))
        write_xml(WAZUH_RULES_DIR, "rules", "rule", candidate.get("rule_xml"))
    return {"written_files": writes, "errors": errors}


def install_temp_content(target_dir: str, filename: str, content: str) -> Tuple[bool, str]:
    target_path = f"{target_dir.rstrip('/')}/{filename}"
    if WAZUH_REMOTE_ENABLED:
        remote_cmd = build_remote_sudo_command(f"tee {shlex.quote(target_path)} >/dev/null")
        proc = run_ssh_command(remote_cmd, input_data=build_remote_stdin(content, requires_sudo=True), timeout=20)
        return proc["returncode"] == 0, proc.get("stderr", "")

    path = Path(target_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content + "\n", encoding="utf-8")
        return True, ""
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def remove_temp_content(target_dir: str, filename: str) -> None:
    target_path = f"{target_dir.rstrip('/')}/{filename}"
    if WAZUH_REMOTE_ENABLED:
        remote_cmd = build_remote_sudo_command(f"rm -f {shlex.quote(target_path)}")
        run_ssh_command(remote_cmd, input_data=build_remote_stdin(requires_sudo=True), timeout=20)
        return

    path = Path(target_path)
    try:
        path.unlink(missing_ok=True)
    except Exception:
        pass


def validate_generated_candidate(candidate: Dict[str, Any], logs: List[LogSample]) -> Dict[str, Any]:
    if not candidate.get("decision", {}).get("needs_custom_decoder"):
        return {"attempted": False, "validated": False, "reason": "custom decoder not needed"}
    if not find_wazuh_logtest():
        return {"attempted": False, "validated": False, "reason": "wazuh-logtest unavailable"}

    app_name = candidate["analysis"]["app_name"]
    regex_order_pairs = candidate["analysis"].get("regex_order_pairs", [])
    decoder_xml = render_candidate_decoder_xml(candidate, regex_order_pairs)
    if not decoder_xml:
        return {"attempted": True, "validated": False, "reason": "could not render decoder xml"}

    stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    decoder_filename = f"local_{sanitize_name(app_name)}_validate_decoder_{stamp}.xml"
    rule_filename = f"local_{sanitize_name(app_name)}_validate_rule_{stamp}.xml"
    
    ok, err = install_temp_content(WAZUH_DECODERS_DIR, decoder_filename, decoder_xml)
    if not ok:
        return {"attempted": True, "validated": False, "reason": f"decoder install failed: {err}"}

    rule_installed = False
    if candidate.get("rule_xml"):
        rule_ok, rule_err = install_temp_content(WAZUH_RULES_DIR, rule_filename, candidate["rule_xml"])
        if not rule_ok:
            remove_temp_content(WAZUH_DECODERS_DIR, decoder_filename)
            return {"attempted": True, "validated": False, "reason": f"rule install failed: {rule_err}"}
        rule_installed = True

    try:
        matched = False
        outputs = []
        for sample in logs:
            output = run_wazuh_logtest(sample.raw_log)
            parsed = parse_logtest_output(combined_logtest_output(output)) if output["available"] else {}
            outputs.append({"parsed": parsed, "stdout": output.get("stdout", ""), "stderr": output.get("stderr", "")})
            if parsed.get("decoder_name") == candidate.get("decoder_name", f"{app_name}-event"):
                matched = True
        
        return {
            "attempted": True,
            "validated": matched,
            "outputs": outputs,
            "reason": "validation complete" if matched else "decoder did not match in logtest"
        }
    finally:
        remove_temp_content(WAZUH_DECODERS_DIR, decoder_filename)
        if rule_installed:
            remove_temp_content(WAZUH_RULES_DIR, rule_filename)


def evaluate_test_result(sample: LogSample, logtest_output: Dict[str, Any], candidate: Dict[str, Any]) -> Dict[str, Any]:
    score = 0
    reasons: List[str] = []
    expected = sample.expected_decoder or candidate["decoder_name"]
    stdout = logtest_output.get("stdout", "")
    auto_fields = extract_relevant_fields(sample.raw_log)

    if not logtest_output["available"]:
        return {
            "score": 0,
            "reasons": ["wazuh-logtest is unavailable in this environment."],
            "pass": False,
        }

    if expected and expected in stdout:
        score += 40
        reasons.append(f"Decoder {expected} appeared in logtest output.")
    else:
        reasons.append(f"Decoder {expected} did not appear in logtest output.")

    if sample.expected_rule_id and str(sample.expected_rule_id) in stdout:
        score += 20
        reasons.append(f"Rule {sample.expected_rule_id} appeared in logtest output.")
    elif sample.expected_rule_id:
        reasons.append(f"Rule {sample.expected_rule_id} did not appear in logtest output.")

    if sample.expected_fields:
        per_field = max(1, 40 // len(sample.expected_fields))
        for key, value in sample.expected_fields.items():
            if value in stdout:
                score += per_field
            else:
                reasons.append(f"Expected field {key}={value} not found in output.")
    else:
        # When no expectations provided, ensure the auto-extracted fields are echoed back for visibility.
        for key, value in auto_fields.items():
            if value in stdout:
                score += 2
            else:
                reasons.append(f"Field {key}={value} not observed in logtest output.")

    return {
        "score": min(score, 100),
        "reasons": reasons,
        "pass": score >= 60 and logtest_output["available"],
        "auto_fields": safe_auto_fields(sample.raw_log),
    }


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/analyze")
def analyze(request: AnalyzeRequest):
    return JSONResponse(analyze_logs_impl(request))


@app.post("/api/generate")
def generate(request: CandidateRequest):
    return JSONResponse(build_candidate(request))


@app.post("/api/test")
def test_candidate(request: TestRequest):
    candidate = build_candidate(request.candidate)
    expected_tuple = f"{candidate['rule_id']}:{candidate['level']}:{candidate['decoder_name']}" if candidate.get("rule_xml") else None
    file_install = None
    if request.install_mode == "write_files":
        file_install = write_candidate_files(candidate)

    results = []
    for sample in request.candidate.logs:
        output = run_wazuh_logtest(sample.raw_log, expected=expected_tuple)
        results.append(
            {
                "raw_log": sample.raw_log,
                "logtest": output,
                "evaluation": evaluate_test_result(sample, output, candidate),
                "auto_fields": safe_auto_fields(sample.raw_log),
                "parsed": parse_logtest_output(combined_logtest_output(output)) if output["available"] else {},
            }
        )
    return JSONResponse({"candidate": candidate, "results": results, "file_install": file_install})


@app.get("/api/ml/status")
def ml_status():
    model = ensure_ml_model(force_refresh=False)
    return {
        "model_loaded": bool(model),
        "pattern_count": _ML_PATTERN_COUNT,
        "repo_cache_dir": str(WAZUH_REPO_CACHE_DIR),
        "repo_decoder_subpath": WAZUH_REPO_DECODER_SUBPATH,
        "repo_url": WAZUH_REPO_URL,
        "error": _ML_MODEL_ERROR,
    }


@app.post("/api/ml/refresh")
def ml_refresh(request: MLRefreshRequest):
    global _ML_MODEL
    refreshed = refresh_wazuh_repo(
        repo_url=WAZUH_REPO_URL,
        cache_dir=WAZUH_REPO_CACHE_DIR,
        sparse_subpath=WAZUH_REPO_DECODER_SUBPATH,
        force=request.force,
    )
    _ML_MODEL = None
    model = ensure_ml_model(force_refresh=False)
    return {
        "refresh": refreshed,
        "model_loaded": bool(model),
        "pattern_count": _ML_PATTERN_COUNT,
        "error": _ML_MODEL_ERROR,
    }


@app.post("/api/feedback")
def feedback(request: FeedbackRequest):
    return JSONResponse(save_feedback_example(request))


@app.get("/health")
def health():
    return {
        "ok": True,
        "wazuh_remote_enabled": WAZUH_REMOTE_ENABLED,
        "wazuh_ssh_host": WAZUH_SSH_HOST,
        "wazuh_ssh_port": WAZUH_SSH_PORT,
        "wazuh_ssh_user": WAZUH_SSH_USER,
        "wazuh_logtest_path": WAZUH_LOGTEST,
        "wazuh_logtest_exists": bool(find_wazuh_logtest()),
        "wazuh_decoders_dir": WAZUH_DECODERS_DIR,
        "wazuh_rules_dir": WAZUH_RULES_DIR,
        "ml_model_loaded": bool(_ML_MODEL),
        "ml_pattern_count": _ML_PATTERN_COUNT,
        "ml_model_error": _ML_MODEL_ERROR,
        "wazuh_repo_cache_dir": str(WAZUH_REPO_CACHE_DIR),
    }


# ─────────────────────────────────────────────
# AI / LLM generation
# ─────────────────────────────────────────────

class AIGenerateRequest(BaseModel):
    app_name: str = Field(default="customapp")
    logs: List[LogSample] = Field(..., min_length=1)
    rule_id: int = Field(default=100500, ge=100000)
    level: int = Field(default=5, ge=0, le=16)
    rule_requirement: Optional[str] = None
    extract_fields: List[str] = Field(default_factory=list)
    model: str = Field(default="anthropic/claude-sonnet-4-5")
    temperature: float = Field(default=0.2, ge=0.0, le=1.0)
    extra_context: str = Field(default="")


def _build_ai_prompt(request: AIGenerateRequest, analysis: Dict[str, Any]) -> str:
    logs_block = "\n".join(s.raw_log for s in request.logs[:5])
    fields_hint = ", ".join(request.extract_fields) if request.extract_fields else "auto-detect"
    rule_req = request.rule_requirement or "generic event detection"
    regex = analysis.get("regex") or ""
    order = ", ".join(analysis.get("order") or [])
    prematch = analysis.get("prematch") or ""
    program = analysis.get("predecoded_program_name") or analysis.get("program_name") or request.app_name

    # Few-shot examples from ML suggestions
    few_shot = ""
    suggestions = analysis.get("ml_suggestions") or []
    if suggestions:
        examples = []
        for s in suggestions[:3]:
            examples.append(
                f"  name={s.get('name','?')} parent={s.get('parent','?')} "
                f"prematch={s.get('prematch','?')} regex={s.get('regex','?')} "
                f"order={','.join(s.get('order') or [])}"
            )
        few_shot = "Similar existing Wazuh decoders (for reference):\n" + "\n".join(examples) + "\n\n"

    return f"""You are a Wazuh SIEM expert. Generate a complete, valid Wazuh decoder and rule XML for the log samples below.

Log samples:
{logs_block}

App name: {request.app_name}
Program name (from logtest): {program}
Fields to extract: {fields_hint}
Rule requirement: {rule_req}
Rule ID: {request.rule_id}
Rule level: {request.level}
{f'Extra context: {request.extra_context}' if request.extra_context else ''}

Heuristic analysis hints (you may refine these):
  prematch: {prematch}
  regex: {regex}
  order: {order}

{few_shot}Instructions:
1. Output a parent decoder and a child decoder that captures the fields.
2. Use valid Wazuh osregex syntax (no PCRE, no (?:...) groups, no [^...] classes).
3. Use \\d+ for digits, \\S+ for non-whitespace, .+ for anything.
4. Output a rule XML group that references the decoder.
5. Wrap the decoder XML in a ```xml ... ``` block and the rule XML in a separate ```xml ... ``` block.
6. After each block, briefly explain your reasoning.

Generate the XML now:"""


async def _stream_openrouter(prompt: str, model: str, temperature: float) -> AsyncIterator[bytes]:
    if not OPENROUTER_API_KEY:
        yield b"ERROR: OPENROUTER_API_KEY is not set. Add it to your environment and restart the app."
        return

    payload = {
        "model": model,
        "temperature": temperature,
        "stream": True,
        "messages": [{"role": "user", "content": prompt}],
    }
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost:8000",
        "X-Title": "Wazuh Decoder Studio",
    }
    url = f"{OPENROUTER_BASE_URL}/chat/completions"

    async with httpx.AsyncClient(timeout=120) as client:
        async with client.stream("POST", url, json=payload, headers=headers) as response:
            if response.status_code != 200:
                body = await response.aread()
                yield f"ERROR {response.status_code}: {body.decode()}".encode()
                return
            async for line in response.aiter_lines():
                if not line.startswith("data: "):
                    continue
                data = line[6:]
                if data.strip() == "[DONE]":
                    break
                try:
                    chunk = json.loads(data)
                    token = chunk["choices"][0]["delta"].get("content", "")
                    if token:
                        yield token.encode()
                except Exception:
                    continue


@app.post("/api/ai/generate")
async def ai_generate(request: AIGenerateRequest):
    """Stream AI-generated decoder + rule XML from OpenRouter."""
    # Run heuristic analysis first to provide context to the LLM
    analysis = analyze_logs_impl(
        AnalyzeRequest(
            logs=request.logs,
            app_name=request.app_name,
            rule_requirement=request.rule_requirement,
            extract_fields=request.extract_fields,
        )
    )
    prompt = _build_ai_prompt(request, analysis)
    return StreamingResponse(
        _stream_openrouter(prompt, request.model, request.temperature),
        media_type="text/plain",
    )
