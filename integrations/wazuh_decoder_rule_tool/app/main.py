from __future__ import annotations

import asyncio
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
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from app.decoder_ml import (
    DecoderSimilarityModel,
    RulePattern,
    RuleSimilarityModel,
    load_patterns_from_repo,
    load_rule_patterns_from_repo,
    refresh_wazuh_repo,
)
from app.decoder_ml_enhanced import ensure_ml_model_enhanced
try:
    from app import rag_engine as _rag
    _RAG_AVAILABLE = True
except Exception:
    _rag = None  # type: ignore
    _RAG_AVAILABLE = False


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
WAZUH_REPO_BRANCH = os.getenv("WAZUH_REPO_BRANCH", "v4.14.5")
ML_MODEL_DIR = Path(os.getenv("ML_MODEL_DIR", str(BASE_DIR.parent / "data" / "models" / "decoder-sbert")))
LOCAL_OUTPUT_DIR = BASE_DIR.parent / "generated"
FEEDBACK_DATASET_PATH = BASE_DIR.parent / "data" / "datasets" / "feedback.jsonl"
REJECTED_FEEDBACK_PATH = BASE_DIR.parent / "data" / "datasets" / "feedback_rejections.jsonl"

# ── AI / LLM config ──
# Priority: Ollama (local) > DashScope > OpenRouter
# Ollama / local OpenAI-compatible endpoint (no rate limits)
# Default to localhost Ollama so it works without any env var when Ollama is running locally.
# Accepts both http://localhost:11434 and http://localhost:11434/v1 — the /v1 suffix is
# normalized in the URL construction below to prevent double-/v1 404 errors.
_OLLAMA_RAW_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
# Normalise: strip trailing /v1 so we always build the full path ourselves
OLLAMA_BASE_URL = _OLLAMA_RAW_URL.rstrip("/")
if OLLAMA_BASE_URL.endswith("/v1"):
    OLLAMA_BASE_URL = OLLAMA_BASE_URL[:-3].rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "wazuh-decoder")

# OpenRouter
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_BASE_URL = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
AI_DEFAULT_MODEL = os.getenv("AI_DEFAULT_MODEL", "meta-llama/llama-3.3-70b-instruct:free")

# DashScope International (Singapore) for Qwen 3.6 Plus
DASHSCOPE_API_KEY = os.getenv("DASHSCOPE_API_KEY", "")
DASHSCOPE_BASE_URL = os.getenv("DASHSCOPE_BASE_URL", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1")

_ML_MODEL: Optional[DecoderSimilarityModel] = None
_ML_MODEL_ERROR: str = ""
_ML_PATTERN_COUNT = 0

# Rule ML model (trained from wazuh-ruleset)
_RULE_ML_MODEL: Optional[RuleSimilarityModel] = None
_RULE_PATTERN_COUNT = 0
WAZUH_RULESET_REPO_DIR = Path(os.getenv("WAZUH_RULESET_REPO_DIR", str(BASE_DIR.parent / "data" / "wazuh_ruleset_repo")))

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Pre-load ML patterns on startup to avoid "red" status in dashboard
    print("INFO:     Pre-loading ML model and patterns...")
    ensure_ml_model_enhanced(force_refresh=False, use_ensemble=True)
    print(f"INFO:     ML patterns loaded: {_ML_PATTERN_COUNT}")
    # Pre-load rule patterns from wazuh-ruleset repo
    _load_rule_ml_model()
    # Build RAG vector store in background (non-blocking)
    if _RAG_AVAILABLE:
        import threading
        def _build_rag():
            print("INFO:     Building RAG vector store (background)...")
            result = _rag.build_store(force=False)
            print(f"INFO:     RAG store ready: {result}")
        threading.Thread(target=_build_rag, daemon=True).start()
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
    field_hints: Dict[str, str] = Field(default_factory=dict)
    split_decoders: bool = Field(default=False)


class CandidateRequest(BaseModel):
    app_name: str = Field(default="customapp")
    logs: List[LogSample] = Field(..., min_length=1)
    level: int = Field(default=5, ge=0, le=16)
    rule_id: int = Field(default=100500, ge=100000)
    rule_requirement: Optional[str] = None
    rule_description: Optional[str] = Field(default=None, description="Explicit rule description (overrides auto-detected from rule_requirement)")
    extract_fields: List[str] = Field(default_factory=list)
    field_hints: Dict[str, str] = Field(default_factory=dict)
    split_decoders: bool = Field(default=False)
    log_source_name: Optional[str] = Field(default=None)
    parent_rule_id: Optional[int] = Field(default=None, description="Existing parent rule ID to extend (creates child rule only)")
    child_field_conditions: List[Dict[str, str]] = Field(default_factory=list, description="Field name/value pairs for <field> tags in child rule")
    child_match_conditions: List[str] = Field(default_factory=list, description="Match strings for <match> tags in child rule")
    child_static_conditions: List[Dict[str, str]] = Field(default_factory=list, description="Static field tag name/value pairs for direct XML tags (e.g. <srcip>, <action>, <id>) in child rule")


class TestRequest(BaseModel):
    candidate: CandidateRequest
    install_mode: str = Field(default="stdin")


class InstallRequest(BaseModel):
    decoder_xml: Optional[str] = None
    rule_xml: Optional[str] = None
    app_name: str = Field(default="customapp")
    log_source_name: Optional[str] = None


class UninstallRequest(BaseModel):
    file_paths: List[str] = Field(...)


class LogtestRawRequest(BaseModel):
    logs: List[str] = Field(..., min_length=1)
    expected: Optional[str] = None


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
    field_hints: Dict[str, str] = Field(default_factory=dict)
    decoder: Optional[FeedbackDecoderInput] = None
    notes: Optional[str] = None


def sanitize_name(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9_-]", "-", value.strip().lower())
    return value or "customapp"


def escape_xml(text: str) -> str:
    # Only escape & and < which are required for XML text content.
    # Do NOT escape > — html.escape would turn -> into -&gt;,
    # which breaks Wazuh regex patterns that use -> (arrow notation).
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    return text


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
    if any(re.search(r"failed\s+login", line, re.IGNORECASE) for line in logs):
        return r"failed\s+login"
    if any(re.search(r"User\s+'", line) for line in logs):
        return r"User\s+'"
    if program_name:
        return program_name
    return first_log[:20]


def prematch_from_current_logs(logs: List[str], *candidates: Optional[str]) -> Optional[str]:
    source_logs = [line for line in logs if line]
    for candidate in candidates:
        value = (candidate or "").strip()
        if not value:
            continue
        if value.startswith(r'\p') or value.startswith('^') or re.search(r'\\[spd]', value):
            return value
        if any(re.search(value, line, re.IGNORECASE) for line in source_logs):
            return value
    return None


def generalize_prefix_literal(prefix: str) -> str:
    # Check for bracketed timestamp at start
    # [2026-05-19 05:52:24 +0200] or [2026/05/19 05:52:24 +0200]
    m1 = re.match(r'^(\[\d{4}([-/])\d{2}\2\d{2}\s+\d{2}:\d{2}:\d{2}\s+[-+]\d{4}\])(.*)$', prefix)
    if m1:
        sep = re.escape(m1.group(2))
        ts_part = rf'\d+{sep}\d+{sep}\d+ \d+\p\d+\p\d+ \S+]'
        rest = m1.group(3)
        return ts_part + generalize_regex_literal(rest)

    # [2026-05-19 05:52:24]
    m2 = re.match(r'^(\[\d{4}([-/])\d{2}\2\d{2}\s+\d{2}:\d{2}:\d{2}\])(.*)$', prefix)
    if m2:
        sep = re.escape(m2.group(2))
        ts_part = rf'\d+{sep}\d+{sep}\d+ \d+\p\d+\p\d+]'
        rest = m2.group(3)
        return ts_part + generalize_regex_literal(rest)

    # [2026-05-19T05:52:24.123Z]
    m3 = re.match(r'^(\[\d{4}([-/])\d{2}\2\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\])(.*)$', prefix)
    if m3:
        sep = re.escape(m3.group(2))
        ts_part = rf'\d+{sep}\d+{sep}\d+T\d+\p\d+\p\d+\S+]'
        rest = m3.group(3)
        return ts_part + generalize_regex_literal(rest)

    # 2026-05-19 05:52:24 +0200
    m4 = re.match(r'^(\d{4}([-/])\d{2}\2\d{2}\s+\d{2}:\d{2}:\d{2}\s+[-+]\d{4})(.*)$', prefix)
    if m4:
        sep = re.escape(m4.group(2))
        ts_part = rf'\d+{sep}\d+{sep}\d+ \d+\p\d+\p\d+ \S+'
        rest = m4.group(3)
        return ts_part + generalize_regex_literal(rest)

    # 2026-05-19 05:52:24
    m5 = re.match(r'^(\d{4}([-/])\d{2}\2\d{2}\s+\d{2}:\d{2}:\d{2})(.*)$', prefix)
    if m5:
        sep = re.escape(m5.group(2))
        ts_part = rf'\d+{sep}\d+{sep}\d+ \d+\p\d+\p\d+'
        rest = m5.group(3)
        return ts_part + generalize_regex_literal(rest)

    # Dec 25 20:45:02
    m6 = re.match(r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})(.*)$', prefix)
    if m6:
        ts_part = r'\S+ \d+ \d+\p\d+\p\d+'
        rest = m6.group(2)
        return ts_part + generalize_regex_literal(rest)

    return generalize_regex_literal(prefix)


def prematch_osregex_from_current_logs(logs: List[str], *candidates: Optional[str]) -> Optional[str]:
    matched = prematch_from_current_logs(logs, *candidates)
    if not matched:
        return None
    if matched.startswith(r'\p') or matched.startswith('^') or re.search(r'\\[spd]', matched):
        return matched if matched.startswith('^') else f'^{matched}'

    first_log = first_non_empty(logs)
    idx = first_log.find(matched)
    if idx >= 0:
        end_idx = idx + len(matched)
        punc_set = "()*+,-.:;<=>?[]!\"'#$%&|{}"
        while end_idx < len(first_log) and first_log[end_idx] in punc_set:
            end_idx += 1
        prefix = first_log[:end_idx]
        generalized_prefix = generalize_prefix_literal(prefix)
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


def generalize_prefix_text(prefix_text: str, fields: Dict[str, str], current_key: str) -> str:
    # 1. Replace other fields' exact values with placeholders
    placeholders = {}
    for other_key, other_val in fields.items():
        if other_key == current_key or other_key.startswith("_") or not other_val or not isinstance(other_val, str):
            continue
        # Only replace if the value is reasonably long or distinct (e.g. not a single char/digit)
        if len(other_val) >= 2:
            placeholder = f"__FIELD_PLACEHOLDER_{other_key}__"
            if other_val in prefix_text:
                prefix_text = prefix_text.replace(other_val, placeholder)
                # Determine appropriate pattern
                if other_key in ("srcip", "dstip") or re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', other_val):
                    pat = r"\d+.\d+.\d+.\d+"
                elif other_val.isdigit():
                    pat = r"\d+"
                else:
                    pat = r"\S+"
                placeholders[placeholder] = pat

    # 2. Escape special characters (must match build_split_regexes_from_fields osregex_escape)
    def osregex_escape(text: str) -> str:
        # Wazuh OS_REGEX special chars: $ ( ) \ | <
        # [ ] { } are literal (NOT character classes/quantifiers)
        return re.sub(r'([$()\\|<])', r'\\\1', text)
    
    prefix_escaped = osregex_escape(prefix_text)

    # 3. Replace standard dynamic patterns (like IP, MAC, numbers) that are not fields
    # MAC Address (e.g., 00:11:22:33:44:55 or 00-11-22-33-44-55)
    prefix_escaped = re.sub(r'\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b', r'\\S+', prefix_escaped)
    prefix_escaped = re.sub(r'\b[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5}\b', r'\\S+', prefix_escaped)
    
    # IP Address
    prefix_escaped = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', r'\\d+.\\d+.\\d+.\\d+', prefix_escaped)
    
    # Any other digits (like PIDs or ports or duration numbers)
    prefix_escaped = re.sub(r'\b\d+\b', r'\\d+', prefix_escaped)

    # 4. Restore the field placeholders with their generic patterns
    for placeholder, pat in placeholders.items():
        prefix_escaped = prefix_escaped.replace(placeholder, pat)
        
    return prefix_escaped


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
                results.append((rf"\.+{re.escape(cef_key)}=(\d+.\d+.\d+.\d+)", [key]))
            else:
                results.append((rf"\.+{re.escape(cef_key)}=(\S+)", [key]))
        if results:
            unique_results = []
            seen_regexes = set()
            for r, k in results:
                if r not in seen_regexes:
                    unique_results.append((r, k))
                    seen_regexes.add(r)
            return unique_results

    # ── Generic key=value / free-form split ───────────────────────────────
    results = []
    
    def osregex_escape(text: str) -> str:
        # Wazuh OS_REGEX special chars: $ ( ) \ | <
        # [ ] { } are literal (NOT character classes/quantifiers)
        return re.sub(r'([$()\\|<])', r'\\\1', text)

    for key, value in fields.items():
        if key in ("_cef_field_map",) or key.startswith("_") or not value or not isinstance(value, str):
            continue
        value = value.strip()
            

        # 2. Try a robust regex to dynamically find "key=value" or "key: value"
        # without hardcoding prefix length
        match = re.search(r'\b(\w+\s*[=:]\s*)([\'"]?)(' + re.escape(value) + r')([\'"]?)', target_text)
        if match:
            quote_open = match.group(2)
            quote_close = match.group(4)
            
            # Use only the matched key and separator to avoid arbitrary preceding words
            prefix_text = match.group(1)
            
            # Check if it starts exactly at the beginning of the text
            is_start = (match.start(1) == 0)
            prefix_re = "" if is_start else r"\.+"
            
            # If there is a space right before our key= match, inject it for cleaner regex
            if not is_start and match.start(1) > 0 and target_text[match.start(1) - 1] == ' ':
                prefix_re += " "
            
            prefix_escaped = prefix_text
            if quote_open:
                prefix_escaped += osregex_escape(quote_open)
            
            # Determine appropriate capture group pattern
            if key == "message" or " " in value or "\t" in value:
                capture_group = r"(\.+)"
            else:
                capture_group = r"(\S+)"
                if re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', value):
                    capture_group = r"(\d+.\d+.\d+.\d+)"
                elif value.isdigit():
                    capture_group = r"(\d+)"
            
            results.append((f"{prefix_re}{prefix_escaped}{capture_group}{osregex_escape(quote_close)}", [key]))
            continue

        # 2.5 Handle hyphenated action/status fields (e.g., deny-smb -> capture deny)
        if key in ("action", "status", "severity") and "-" in value:
            found = re.search(re.escape(value), target_text)
            if found:
                prefix_part = value.split("-")[0]
                start = found.start()
                prefix_candidate = target_text[:start]
                m_prefix = re.search(r'([A-Za-z0-9_.:-]+[\s]*[^A-Za-z0-9\s]*\s*)$', prefix_candidate)
                if m_prefix:
                    prefix_text = m_prefix.group(1)
                else:
                    last_space = prefix_candidate.rstrip().rfind(' ')
                    prefix_text = prefix_candidate[last_space+1:] if last_space != -1 else target_text[max(0, start - 4):start]
                prefix_escaped = generalize_prefix_text(prefix_text, fields, key)
                results.append((f"\\.+{prefix_escaped}({re.escape(prefix_part)})-\\S+", [key]))
                continue

        # 3. Fallback for completely free-form fields without key=
        found = re.search(re.escape(value), target_text)
        if found:
            start = found.start()
            
            # Determine appropriate capture group pattern
            if key == "message" or " " in value or "\t" in value:
                capture_group = r"(\.+)"
            else:
                capture_group = r"(\S+)"
                if re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', value):
                    capture_group = r"(\d+.\d+.\d+.\d+)"
                elif value.isdigit():
                    capture_group = r"(\d+)"
                
            prefix_candidate = target_text[:start]
            # Try to grab the last two preceding words/tokens and any attached punctuation for high specificity
            m_prefix = re.search(r'([A-Za-z0-9_.:-]+[\s]*[^A-Za-z0-9\s]*\s*[A-Za-z0-9_.:-]+[\s]*[^A-Za-z0-9\s]*\s*)$', prefix_candidate)
            if not m_prefix:
                # Fall back to a single word/token if there aren't two
                m_prefix = re.search(r'([A-Za-z0-9_.:-]+[\s]*[^A-Za-z0-9\s]*\s*)$', prefix_candidate)
            if m_prefix:
                prefix_text = m_prefix.group(1)
            else:
                last_space = prefix_candidate.rstrip().rfind(' ')
                if last_space != -1:
                    prefix_text = prefix_candidate[last_space+1:]
                else:
                    prefix_text = prefix_candidate
                
                if len(prefix_text.strip()) < 2:
                    prefix_text = target_text[max(0, start - 4):start]
                
            prefix_escaped = generalize_prefix_text(prefix_text, fields, key)

            is_start = (len(prefix_candidate) == len(prefix_text))
            prefix_re = "" if is_start else r"\.+"

            value_end = start + len(value)
            suffix_char = target_text[value_end:value_end+1] if value_end < len(target_text) else ""
            if suffix_char in ("'", '"', "]", ")", "}", ",", ";"):
                capture_suffix = osregex_escape(suffix_char)
            else:
                capture_suffix = ""

            results.append((f"{prefix_re}{prefix_escaped}{capture_group}{capture_suffix}", [key]))
    unique_results = []
    seen_regexes = set()
    for regex, keys in results:
        if regex not in seen_regexes:
            unique_results.append((regex, keys))
            seen_regexes.add(regex)
            
    return unique_results


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
    "sourceip": ("srcip", "sourceip", "src", "source"),
    "srcip": ("srcip", "sourceip", "src", "source"),
    "destinationip": ("dstip", "destinationip", "dst", "destination"),
    "dstip": ("dstip", "destinationip", "dst", "destination"),
    "sourceport": ("sourceport", "srcport", "spt"),
    "srcport": ("sourceport", "srcport", "spt", "port"),
    "destinationport": ("destinationport", "dstport", "dpt"),
    "dstport": ("destinationport", "dstport", "dpt", "port"),
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
    field_hints: Optional[Dict[str, str]] = None,
) -> tuple[Dict[str, str], List[str], List[str]]:
    common_fields = infer_fields_from_all_logs(logs)
    auto_fields = safe_auto_fields(first_non_empty(logs))
    if not common_fields:
        common_fields = auto_fields

    if field_hints:
        for key, val in field_hints.items():
            if val:
                common_fields[key] = val

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
    field_hints: Optional[Dict[str, str]] = None,
) -> tuple[List[Tuple[str, List[str]]], List[str], List[str]]:
    first_log = first_non_empty(logs)
    auto_fields = extract_relevant_fields(first_log)
    is_cef = re.match(r'^CEF:\d+\|', first_log.strip()) is not None

    # Always use split-decoder mode for all log types (CEF, Syslog, etc)
    # as requested, because child decoders are far more reliable than a single regex.
    split_decoders = True

    if field_hints:
        requested_fields = list(requested_fields)
        for hint_key in field_hints.keys():
            if hint_key not in requested_fields:
                requested_fields.append(hint_key)

    chosen_fields, field_order, missing_fields = choose_log_driven_fields(
        logs, requested_fields, ml_order=ml_order, field_hints=field_hints
    )

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


def clean_rule_description(text: str) -> str:
    cleaned = text.strip()
    # Extract explicit "use description as X" / "use the description as X" / "description should be X"
    desc_match = re.search(
        r'(?:use\s+(?:the\s+)?description\s+(?:as|to\s+be)\s+|'
        r'description\s+(?:should\s+)?be\s+|'
        r'description\s+is\s+)[\'\"]?(.+?)[\'\"]?\s*\.?\s*$',
        cleaned, flags=re.IGNORECASE,
    )
    if desc_match:
        return desc_match.group(1).strip().strip('"').strip("'").rstrip('.').strip()

    prefixes = [
        r'^i\s+wanna\s+create\s+parent\s+rule\s+for\s+this\s+and\s+also\s+need\s+to\s+create\s+child\s+rule\s+based\s+on\s+the\s+parent\s+rule\s+that\s+need\s+to\s+be\s+',
        r'^i\s+(?:want|need)\s+to\s+(?:create|make|have)\s+(?:a\s+)?(?:parent\s+)?rule\s+(?:for|to)\s+',
        r'^(?:create|make|have)\s+(?:a\s+)?(?:parent\s+)?rule\s+(?:for|to)\s+',
        r'^create\s+alert\s+using\s+\d+\s+parent\s+rule\s+by\s+matching\s+',
        r'^(?:please\s+)',
    ]
    for p in prefixes:
        cleaned = re.sub(p, '', cleaned, flags=re.IGNORECASE)
    # After prefix stripping, check again for "use (the) description as X" pattern
    if not desc_match:
        desc_match = re.search(
            r'use\s+(?:the\s+)?description\s+(?:as|to\s+be)\s+[\'\"]?(.+?)[\'\"]?\s*\.?\s*$',
            cleaned, flags=re.IGNORECASE,
        )
        if desc_match:
            return desc_match.group(1).strip().strip('"').strip("'").rstrip('.').strip()
    cleaned = re.sub(r'\s+(?:please|thanks|thank\s+you)$', '', cleaned, flags=re.IGNORECASE)
    return cleaned.strip()


def derive_child_rule_conditions(
    logs: List[str],
    rule_requirement: str,
    extract_fields: Optional[List[str]] = None,
    field_hints: Optional[Dict[str, str]] = None,
    parsed_logtest_fields: Optional[Dict[str, str]] = None,
    clean_description: Optional[str] = None,
) -> Tuple[List[Dict[str, str]], List[str], List[Dict[str, str]]]:
    """
    Derive <field>, <match>, and static conditions from all available context.
    Returns (field_conditions, match_conditions, static_conditions).

    Uses multiple signals to auto-detect conditions:
    1. extract_fields — known field names the decoder extracts
    2. field_hints — user-provided expected field values
    3. parsed_logtest_fields — actual decoded fields from wazuh-logtest
    4. extract_relevant_fields — heuristic extraction from raw logs
    5. rule_requirement — natural language description of what to match
    """
    field_conditions: List[Dict[str, str]] = []
    match_conditions: List[str] = []
    static_conditions: List[Dict[str, str]] = []

    # ── Step 1: Collect field values from all available sources ──
    all_field_values: Dict[str, str] = {}
    cleaned_req = rule_requirement.strip().lower()

    # 1a. field_hints provide direct expected values — highest priority.
    # Track which fields were explicitly set so auto-detection doesn't override them.
    hinted_fields: set = set()
    if field_hints:
        for fname, fval in field_hints.items():
            if fname and fval:
                hinted_fields.add(fname)
                if fname in STATIC_FIELD_TAGS:
                    cond = {"name": fname, "value": fval}
                    if cond not in static_conditions:
                        static_conditions.append(cond)
                else:
                    cond = {"name": fname, "value": fval}
                    if cond not in field_conditions:
                        field_conditions.append(cond)

    # Meta fields from logtest that should not become rule conditions automatically
    _META_FIELDS = frozenset({"program_name", "program", "hostname", "decoder_name"})
    meta_in_req = any(mf in cleaned_req for mf in _META_FIELDS) or any(mf.replace("_", "") in cleaned_req for mf in _META_FIELDS)

    # 1b. logtest decoded fields — real decoded values from wazuh-logtest.
    #     Skip meta fields (program_name, hostname, decoder_name) unless
    #     the user explicitly mentioned them in the requirement.
    if parsed_logtest_fields:
        for fname, fval in parsed_logtest_fields.items():
            if fname and fval and not fname.startswith("_"):
                if fname in hinted_fields:
                    continue
                if fname in _META_FIELDS and not meta_in_req:
                    continue
                all_field_values[fname] = fval

    # 1c. extract_relevant_fields — heuristic extraction from raw logs
    for log in logs:
        fields = extract_relevant_fields(log)
        for k, v in fields.items():
            if not k.startswith("_") and isinstance(v, str) and v:
                if k not in all_field_values and k not in hinted_fields:
                    if k in _META_FIELDS and not meta_in_req:
                        continue
                    all_field_values[k] = v

    # ── Step 2: Parse the requirement for explicit field-value patterns ──

    # Patterns: "field X (is|=|equals|matches) Y", "X field (is|=) Y"
    explicit_patterns = re.findall(
        r'(?:field\s+)?(\w{2,})\s+(?:is|are|=|equals?|matches?|contains?)\s+'  # field name
        r"'([^']*)'",  # value in single quotes
        cleaned_req, flags=re.IGNORECASE,
    )
    explicit_patterns += re.findall(
        r'(?:field\s+)?(\w{2,})\s+(?:is|are|=|equals?|matches?|contains?)\s+'  # field name
        r'"([^"]*)"',  # value in double quotes
        cleaned_req, flags=re.IGNORECASE,
    )
    explicit_patterns += re.findall(
        r'(?:field\s+)?(\w{2,})\s+(?:is|are|=|equals?|matches?|contains?)\s+'  # field name
        r'(\w{2,})',  # value as bare word
        cleaned_req, flags=re.IGNORECASE,
    )

    for fname, fval in explicit_patterns:
        fname = fname.strip()
        fval = fval.strip()
        if fname and fval and fname not in hinted_fields:
            cond = {"name": fname, "value": fval}
            if fname in STATIC_FIELD_TAGS:
                if cond not in static_conditions:
                    static_conditions.append(cond)
            else:
                if cond not in field_conditions:
                    field_conditions.append(cond)

    # ── Step 3: Tokenize requirement into keywords ──
    _STOP = frozenset({
        'the','a','an','for','and','or','but','in','on','at','to','of','is','was',
        'are','were','be','been','being','have','has','had','do','does','did','will',
        'would','could','should','may','might','shall','can','need','dare','ought',
        'used','this','that','these','those','with','from','by','as','into','through',
        'during','before','after','above','below','between','out','off','over','under',
        'again','further','then','once','here','there','when','where','why','how',
        'all','each','every','both','few','more','most','other','some','such','no',
        'nor','not','only','own','same','so','than','too','very','just','because',
        'i','me','my','we','our','you','your','he','him','his','she','her','it','its',
        'they','them','their','detect','create','based','wanna','want','use','also','need',
        'parent','rule','child','level','alert','message','field','value','matches',
        'equals','contain','contains','else','when','where','which','who','whom',
    })
    req_words = [w for w in re.findall(r'\b[a-zA-Z0-9]{3,}\b', cleaned_req) if w not in _STOP]

    if not req_words:
        return field_conditions, match_conditions, static_conditions

    # ── Step 4: Score fields against requirement keywords ──
    # Build a list of (field_name, field_value, score) for candidate conditions
    candidate_conditions: List[Tuple[str, str, int]] = []
    matched_words: set = set()

    # 4a. Check if any requirement keyword IS a field name from extract_fields
    extract_field_set = set(f.lower() for f in (extract_fields or [])) | set(all_field_values.keys()) | set(fname for fname, _ in explicit_patterns)

    for kw in req_words:
        if kw in extract_field_set:
            # This keyword is a known field name — find its value in log data
            field_value = all_field_values.get(kw, "") or all_field_values.get(kw.upper(), "") or all_field_values.get(kw.lower(), "")
            # Also check if it matches in logtest fields
            if parsed_logtest_fields:
                for pf, pv in parsed_logtest_fields.items():
                    if pf.lower() == kw and pv:
                        field_value = pv
                        break
            if field_value:
                candidate_conditions.append((kw, field_value, 3))
                matched_words.add(kw)

    # 4b. Match keywords against field values
    for kw in sorted(req_words, key=len, reverse=True):
        if kw in matched_words:
            continue
        for field_name, field_value in all_field_values.items():
            fv_lower = field_value.lower()
            # Check if keyword is a significant part of the field value
            # or vice versa — but require at least 2-char overlap for short values
            if kw in fv_lower or (len(kw) >= 3 and fv_lower in kw):
                score = 2 if kw in fv_lower else 1
                candidate_conditions.append((field_name, field_value, score))
                matched_words.add(kw)
                break

    # 4c. From extract_fields, add conditions for fields with meaningful values
    #      that haven't already been covered.
    if extract_fields:
        already_covered = {c[0] for c in candidate_conditions}
        for ef in extract_fields:
            ef_lower = ef.lower()
            if ef_lower in already_covered or ef_lower in hinted_fields:
                continue
            fv = all_field_values.get(ef) or all_field_values.get(ef_lower)
            if not fv:
                continue
            # Only add if the value is short/meaningful (not a specific IP, long path, etc.)
            is_meaningful = (
                fv.lower() in cleaned_req
                or (len(fv) <= 25 and not re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', fv) and not re.search(r'[\\/]', fv))
            )
            if is_meaningful:
                candidate_conditions.append((ef, fv, 1))

    # ── Step 5: Classify candidates into static vs field conditions ──
    # Skip fields already set explicitly via field_hints
    for fname, fval, score in candidate_conditions:
        if fname in hinted_fields:
            continue
        cond = {"name": fname, "value": fval}
        if fname in STATIC_FIELD_TAGS:
            if cond not in static_conditions:
                static_conditions.append(cond)
        else:
            if cond not in field_conditions:
                field_conditions.append(cond)

    # ── Step 6: Remaining unmatched keywords → match conditions ──
    # Skip words that appear in the cleaned description (they're descriptive, not matching)
    desc_words = set(clean_description.lower().split()) if clean_description else set()
    body_text = " ".join(logs)
    for kw in sorted(req_words, key=len, reverse=True):
        if kw in matched_words:
            continue
        if kw in desc_words:
            continue
        if re.search(rf'\b{re.escape(kw)}\b', body_text, flags=re.IGNORECASE):
            match_conditions.append(kw)
            matched_words.add(kw)

    return field_conditions, match_conditions, static_conditions


def derive_child_regex_from_logs(logs: List[str], rule_requirement: str) -> Optional[str]:
    bodies = []
    for log in logs:
        predecoded = parse_phase1_predecode(log)
        body = (predecoded.get("body") or log).strip()
        if body:
            bodies.append(body)
    if not bodies:
        return derive_regex_from_predecoded_body(logs)
    body = bodies[0]

    _STOP = frozenset({'the','a','an','is','was','are','were','be','been','being',
        'have','has','had','do','does','did','will','would','could','should','may',
        'might','shall','can','need','dare','ought','used','to','of','in','for','on',
        'with','at','by','from','as','into','through','during','before','after','above',
        'below','between','out','off','over','under','again','further','then','once',
        'here','there','when','where','why','how','all','each','every','both','few',
        'more','most','other','some','such','no','nor','not','only','own','same','so',
        'than','too','very','just','because','but','and','or','if','while','that',
        'this','these','those','i','me','my','myself','we','our','ours','ourselves',
        'you','your','yours','yourself','yourselves','he','him','his','himself','she',
        'her','hers','herself','it','its','itself','they','them','their','theirs',
        'themselves','what','which','who','whom','am','is','are','was','were','be',
        'been','being','have','has','had','having','do','does','did','doing','will',
        'would','should','can','could','shall','may','might','must','let','need',
        'dare','ought','used','detected','detect','create','based','wanna','want',
        'also','need','this','that','and','for','the','parent','rule','child'})

    req_words = {w for w in re.findall(r'\b[a-zA-Z]{3,}\b', rule_requirement.lower()) if w not in _STOP}
    if not req_words:
        return derive_regex_from_predecoded_body(logs)

    def stem(w: str) -> str:
        w = w.rstrip('s')
        for suf in ('ure', 'ing', 'ed'):
            if w.endswith(suf):
                return w[:-len(suf)]
        return w

    body_lower = body.lower()
    matches = []
    for rw in req_words:
        rs = stem(rw)
        for bw in re.findall(r'\b[a-zA-Z]+\b', body):
            if stem(bw.lower()) == rs or bw.lower() == rw:
                idx = body_lower.find(bw.lower())
                if idx != -1:
                    matches.append((idx, idx + len(bw)))
                    break
        else:
            idx = body_lower.find(rw)
            if idx != -1:
                matches.append((idx, idx + len(rw)))

    if not matches:
        return derive_regex_from_predecoded_body(logs)

    matches.sort()
    seg_start = matches[0][0]
    seg_end = max(e for _, e in matches)
    seg = body[seg_start:seg_end]

    tokens = re.split(r"(\s+|'[^']*'|\"[^\"]*\"|\b\d+\.\d+\.\d+\.\d+\b|\b\d+\b)", seg)
    parts = []
    for token in tokens:
        if not token:
            continue
        if re.fullmatch(r"\s+", token):
            parts.append(r"\s")
        elif re.fullmatch(r"'[^']*'", token):
            parts.append(r"'\S+'")
        elif re.fullmatch(r'"[^"]*"', token):
            parts.append(r'"\S+"')
        elif re.fullmatch(r"\d+\.\d+\.\d+\.\d+", token):
            parts.append(r"\d+\.\d+\.\d+\.\d+")
        elif re.fullmatch(r"\d+", token):
            parts.append(r"\d+")
        else:
            parts.append(re.sub(r'([$()\\|<])', r'\\\1', token))

    return r"\.+" + "".join(parts) + r"\.+"


def derive_regex_from_predecoded_body(logs: List[str]) -> Optional[str]:
    bodies = []
    for log in logs:
        predecoded = parse_phase1_predecode(log)
        body = (predecoded.get("body") or log).strip()
        if body:
            bodies.append(body)
    if not bodies:
        return None

    def body_to_regex(body: str) -> str:
        tokens = re.split(r"(\s+|'[^']*'|\"[^\"]*\"|\b\d+\.\d+\.\d+\.\d+\b)", body)
        parts = []
        found_variable = False
        for token in tokens:
            if not token:
                continue
            if re.fullmatch(r"\s+", token):
                parts.append(r"\s")
            elif re.fullmatch(r"'[^']*'", token):
                parts.append(r"'\S+'")
                found_variable = True
            elif re.fullmatch(r'"[^"]*"', token):
                parts.append(r'"\S+"')
                found_variable = True
            elif re.fullmatch(r"\d+\.\d+\.\d+\.\d+", token):
                parts.append(r"\d+\.\d+\.\d+\.\d+")
                found_variable = True
            elif re.fullmatch(r"\d+", token):
                parts.append(r"\d+")
                found_variable = True
            else:
                escaped = re.sub(r'([$()\\|<])', r'\\\1', token)
                parts.append(escaped)
        return "".join(parts)

    regexes = [body_to_regex(b) for b in bodies]

    if len(regexes) == 1:
        full = regexes[0]
        var_patterns = [r"'\S+'", r'"\S+"', r"\d+\.\d+\.\d+\.\d+"]
        for vp in var_patterns:
            idx = full.find(vp)
            if idx >= 0:
                return full[:idx + len(vp)]
        idx = full.find(r"\d+")
        if idx >= 0:
            return full[:idx + len(r"\d+")]
        return full

    min_len = min(len(r) for r in regexes)
    common = ""
    for i in range(min_len):
        if all(r[i] == regexes[0][i] for r in regexes):
            common += regexes[0][i]
        else:
            break

    if len(common) >= 4:
        if common.endswith(r"\s"):
            common = common[:-2]
        return common

    return regexes[0]


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

    # Palo Alto CSV logs — detect by timestamp + THREAT/TRAFFIC/CONFIG pattern
    pa_match = re.match(r'^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}),(\d+),(\w+),', text)
    if pa_match:
        parts = text.split(",")
        if len(parts) >= 25:
            fields["logtime"] = parts[0]
            fields["serial"] = parts[1]
            fields["logtype"] = parts[2]
            fields["srcip"] = parts[6]
            fields["dstip"] = parts[7]
            action_raw = parts[10] if len(parts) > 10 else ""
            if "-" in action_raw:
                fields["action"] = action_raw.split("-")[0]
            else:
                fields["action"] = action_raw
            # Message is typically in quotes later in the log
            for p in parts:
                p_stripped = p.strip()
                if p_stripped.startswith('"') and p_stripped.endswith('"') and len(p_stripped) > 4:
                    fields["message"] = p_stripped.strip('"')
                    break
            return fields

    # Extract `=` separated pairs first (stronger indicator)
    kv_pattern_eq = r"(\b[\w\.-]+)\s*([=]+)\s*('(?:[^']|\\')*'|\"(?:[^\"]|\\\")*\"|[^\s,;]+)"
    for key, sep, val in re.findall(kv_pattern_eq, text):
        cleaned = val.strip("'\"")
        if cleaned:
            fields.setdefault(key, cleaned)
            fields.setdefault(f"_kv_{key}", f"{key}{sep}{cleaned}")

    # Extract `:` separated pairs, but restrict value to not contain `=` (avoids capturing "program: key=val" as a single pair)
    kv_pattern_colon = r"(\b[\w\.-]+)\s*(:+)\s*('(?:[^']|\\')*'|\"(?:[^\"]|\\\")*\"|[^\s,;=]+)"
    for key, sep, val in re.findall(kv_pattern_colon, text):
        cleaned = val.strip("'\"")
        if cleaned:
            fields.setdefault(key, cleaned)
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
        "decoded_fields": {},
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

    # Extract phase-2 decoded fields (everything after "name:" that looks like field: 'value')
    if result["phase2_completed"]:
        # Find the "name:" line and collect subsequent field:value lines
        phase2_match = re.search(
            r"\*\*Phase 2: Completed decoding\.\s*\n(\s+name:\s*'[^']*'\s*\n(?:\s+\w+:\s*'[^']*'\s*\n)*)",
            stdout, re.MULTILINE
        )
        if phase2_match:
            field_lines = re.findall(
                r"\s+(\w+):\s*'([^']*)'",
                phase2_match.group(1)
            )
            for fname, fval in field_lines:
                if fname != "name":
                    result["decoded_fields"][fname] = fval

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


def infer_rule_from_natural_language(requirement: str, default_level: int) -> int:
    if not requirement:
        return default_level
    req = requirement.strip()
    level = default_level
    explicit_level = re.search(r"\blevel\s*(\d{1,2})\b", req, flags=re.IGNORECASE)
    if explicit_level:
        level = max(0, min(16, int(explicit_level.group(1))))
    else:
        lowered = req.lower()
        if any(word in lowered for word in ["critical", "severe", "urgent"]):
            level = max(level, 12)
        elif any(word in lowered for word in ["high", "important", "fail"]):
            level = max(level, 10)
        elif any(word in lowered for word in ["low", "informational", "info"]):
            level = min(level, 4)
    return level


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

    # Reload model with newly trained SBERT
    ensure_ml_model_enhanced(force_refresh=False, use_ensemble=True)
    return {
        "ok": True,
        "build_stdout": build_proc.stdout,
        "build_stderr": build_proc.stderr,
        "train_stdout": train_proc.stdout,
        "train_stderr": train_proc.stderr,
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
    ensure_ml_model_enhanced(force_refresh=False, use_ensemble=True)
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
    model = ensure_ml_model_enhanced(force_refresh=False, use_ensemble=True)
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


def _load_rule_ml_model() -> None:
    global _RULE_ML_MODEL, _RULE_PATTERN_COUNT
    rules_dir = WAZUH_RULESET_REPO_DIR / "rules"
    if not rules_dir.exists():
        return
    patterns = load_rule_patterns_from_repo(WAZUH_RULESET_REPO_DIR, "rules")
    if patterns:
        _RULE_ML_MODEL = RuleSimilarityModel(patterns)
        _RULE_PATTERN_COUNT = len(patterns)


def rule_suggestions_for_requirement(rule_requirement: str, top_k: int = 5) -> List[Dict[str, Any]]:
    """Get ML-based rule suggestions from the wazuh-ruleset for a given natural language requirement."""
    if _RULE_ML_MODEL is None:
        _load_rule_ml_model()
    if _RULE_ML_MODEL is None:
        return []
    suggestions: List[Dict[str, Any]] = []
    for pattern, score in _RULE_ML_MODEL.suggest(query=rule_requirement, top_k=top_k):
        suggestions.append({
            "rule_id": pattern.rule_id,
            "level": pattern.level,
            "decoded_as": pattern.decoded_as,
            "if_sid": pattern.if_sid,
            "regex": pattern.regex,
            "field_conditions": pattern.field_conditions,
            "static_conditions": pattern.static_conditions,
            "match_conditions": pattern.match_conditions,
            "description": pattern.description,
            "group": pattern.group,
            "source_file": pattern.source_file,
            "score": round(score, 4),
        })
    return suggestions


PREDECODED_SYSLOG_FIELDS = frozenset({
    "timestamp", "hostname", "program_name",
})

def validate_individual_fields(
    extract_fields: List[str],
    logtest_decoded_fields: Dict[str, str],
    log_body: str,
    field_hints: Optional[Dict[str, str]] = None,
    auto_fields: Optional[Dict[str, str]] = None,
) -> Dict[str, Dict[str, str]]:
    """
    For each requested field not yet decoded by the built-in decoder,
    explain why it can or cannot be extracted.
    Returns dict: field_name -> {"status": "...", "reason": "..."}
    """
    results: Dict[str, Dict[str, str]] = {}
    for field in extract_fields:
        if field in logtest_decoded_fields:
            results[field] = {"status": "decoded", "reason": "already decoded by built-in decoder"}
            continue
        field_lower = field.lower()
        if field_lower in PREDECODED_SYSLOG_FIELDS:
            results[field] = {
                "status": "skipped",
                "reason": f"'{field}' is extracted during syslog pre-decoding "
                          f"and cannot be re-decoded by a child decoder",
            }
            continue
        # Check if a known value for this field exists in the body
        hint_val = (field_hints or {}).get(field, "").lower()
        if hint_val and hint_val in log_body.lower():
            results[field] = {"status": "pending", "reason": "value found in body, will be extracted by custom decoder"}
            continue
        auto_val = (auto_fields or {}).get(field, "").lower()
        if auto_val and auto_val in log_body.lower():
            results[field] = {"status": "pending", "reason": "value detected in body, will be extracted by custom decoder"}
            continue
        results[field] = {
            "status": "warning",
            "reason": f"field '{field}' or its value not found in the message body — "
                      f"verify the field name or provide a field_hint",
        }
    return results


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

    # Collect fields already decoded by the built-in decoder so we skip them
    logtest_decoded_fields: Dict[str, str] = {}
    for entry in parsed_entries:
        for fname, fval in entry.get("decoded_fields", {}).items():
            if fname not in logtest_decoded_fields:
                logtest_decoded_fields[fname] = fval

    # Do not filter explicitly requested fields, even if logtest already decoded them.
    # If the user explicitly typed them in, or if auto-detect found them, we should generate them.
    effective_extract_fields = list(request.extract_fields)
    skipped_decoded_fields = []

    ml_suggestions = ml_suggestions_for_logs(
        logs=raw_logs,
        extracted_program_name=extracted_program,
        unique_after_predecoded=unique_after_predecoded,
        top_k=5,
    )
    ml_selected = select_ml_decoder_template(raw_logs, effective_extract_fields, ml_suggestions)
    # 4. Generate Regex & Order (New: returns list of pairs)
    regex_order_pairs, likely_fields, missing_extract_fields = build_log_based_regex(
        raw_logs,
        effective_extract_fields,
        ml_order=(ml_selected or {}).get("order"),
        split_decoders=request.split_decoders,
        field_hints=getattr(request, 'field_hints', None),
    )
    
    # Per-field validation: explain which fields will/won't be decoded and why
    field_validation = validate_individual_fields(
        request.extract_fields, logtest_decoded_fields, token_source,
        field_hints=getattr(request, 'field_hints', None),
        auto_fields=safe_auto_fields(first_non_empty(raw_logs)),
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
        "effective_extract_fields": effective_extract_fields,
        "skipped_decoded_fields": skipped_decoded_fields,
        "logtest_decoded_fields": logtest_decoded_fields,
        "field_validation": field_validation,
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
        "needs_custom_decoder": not logtest_scan["builtin_decoder_seen"] or bool(request.extract_fields),
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
    parent_lines = [f"<decoder name=\"{escape_xml(parent_decoder)}\">"]
    if parent_program_name:
        parent_lines.append(f"  <program_name>{escape_xml(parent_program_name)}</program_name>")
    elif parent_prematch:
        parent_lines.append(f"  <prematch>{escape_xml(parent_prematch)}</prematch>")
    parent_lines.append("</decoder>")

    xml_parts = ["\n".join(parent_lines)]
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


def derive_log_source_name(logs: List[str], parent_decoder: str, user_provided: Optional[str] = None) -> str:
    if user_provided and user_provided.strip():
        return user_provided.strip()
    if parent_decoder and parent_decoder not in ("customapp", "custom"):
        return parent_decoder
    program = extract_program_from_log(logs)
    if program:
        return program
    predecoded = parse_phase1_predecode(first_non_empty(logs))
    if predecoded.get("program_name"):
        return predecoded["program_name"]
    return parent_decoder or "custom"


# Wazuh static field tags that are direct children of <rule> (no <field name="..."> wrapper)
# Reference: https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html
STATIC_FIELD_TAGS: frozenset = frozenset({
    "srcip", "dstip", "srcport", "dstport", "protocol", "action", "id",
    "url", "data", "extra_data", "status", "system_name", "user",
    "hostname", "program_name",
})


def _render_field_tags(field_conditions: Optional[List[Dict[str, str]]]) -> List[str]:
    if not field_conditions:
        return []
    return [f"    <field name=\"{escape_xml(fc['name'])}\">{escape_xml(fc.get('value', ''))}</field>" for fc in field_conditions if fc.get("name") and fc.get("value")]


def _render_static_tags(static_conditions: Optional[List[Dict[str, str]]]) -> List[str]:
    if not static_conditions:
        return []
    lines: List[str] = []
    for sc in static_conditions:
        tag = sc.get("name", "").strip()
        value = sc.get("value", "").strip()
        if tag and value and tag in STATIC_FIELD_TAGS:
            lines.append(f"    <{escape_xml(tag)}>{escape_xml(value)}</{escape_xml(tag)}>")
    return lines


def _render_match_tags(match_conditions: Optional[List[str]]) -> List[str]:
    if not match_conditions:
        return []
    return [f"    <match>{escape_xml(mc)}</match>" for mc in match_conditions]


def build_rule_xml(
    app_name: str,
    rule_id: int,
    level: int,
    log_source_name: str,
    decoded_as: Optional[str] = None,
    if_sid: Optional[int] = None,
    regex: Optional[str] = None,
    child_rule: Optional[Dict[str, Any]] = None,
    field_conditions: Optional[List[Dict[str, str]]] = None,
    match_conditions: Optional[List[str]] = None,
    static_conditions: Optional[List[Dict[str, str]]] = None,
    child_only: bool = False,
    description: Optional[str] = None,
) -> str:
    lines = [
        f"<group name=\"custom,{escape_xml(app_name)}\">",
    ]
    if child_only:
        # Emit only a single child rule extending an existing parent.
        # Use <match> / <field> / static tags instead of <regex> for clarity.
        desc = child_rule.get("description", f"{escape_xml(log_source_name)} messages grouped") if child_rule else f"{escape_xml(log_source_name)} messages grouped"
        child_fields = child_rule.get("field_conditions") if child_rule else field_conditions
        child_statics = child_rule.get("static_conditions") if child_rule else static_conditions
        child_matches = child_rule.get("match_conditions") if child_rule else match_conditions
        child_lvl = child_rule.get("level", level) if child_rule else level
        lines.append(f"  <rule id=\"{rule_id}\" level=\"{child_lvl}\">")
        if if_sid is not None:
            lines.append(f"    <if_sid>{if_sid}</if_sid>")
        lines.extend(_render_field_tags(child_fields))
        lines.extend(_render_static_tags(child_statics))
        lines.extend(_render_match_tags(child_matches))
        lines.append(f"    <description>{escape_xml(desc)}</description>")
        lines.append("  </rule>")
    else:
        parent_desc = description if description else f"{escape_xml(log_source_name)} messages grouped"
        lines.append(f"  <rule id=\"{rule_id}\" level=\"{level}\">")
        if if_sid is not None:
            lines.append(f"    <if_sid>{if_sid}</if_sid>")
        if decoded_as:
            lines.append(f"    <decoded_as>{escape_xml(decoded_as)}</decoded_as>")
        if regex:
            lines.append(f"    <regex>{escape_xml(regex)}</regex>")
        lines.extend(_render_field_tags(field_conditions))
        lines.extend(_render_static_tags(static_conditions))
        lines.extend(_render_match_tags(match_conditions))
        lines.append(f"    <description>{parent_desc}</description>")
        lines.append("  </rule>")
        if child_rule:
            child_id = child_rule.get("id", rule_id + 1)
            child_lvl = child_rule.get("level", level)
            child_desc = child_rule.get("description", parent_desc)
            child_re = child_rule.get("regex")
            child_fields = child_rule.get("field_conditions")
            child_statics = child_rule.get("static_conditions")
            child_matches = child_rule.get("match_conditions")
            lines.append(f"  <rule id=\"{child_id}\" level=\"{child_lvl}\">")
            lines.append(f"    <if_sid>{rule_id}</if_sid>")
            if child_re:
                lines.append(f"    <regex>{escape_xml(child_re)}</regex>")
            lines.extend(_render_field_tags(child_fields))
            lines.extend(_render_static_tags(child_statics))
            lines.extend(_render_match_tags(child_matches))
            lines.append(f"    <description>{escape_xml(child_desc)}</description>")
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
            field_hints=getattr(request, 'field_hints', {}),
        )
    )
    if not analysis.get("wazuh_logtest_summary", {}).get("available", False):
        stderr = analysis.get("wazuh_logtest_summary", {}).get("stderr", "")
        raise RuntimeError(f"wazuh-logtest is not accessible. Generation requires a working wazuh-logtest instance. Details: {stderr}")
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

    log_source_name = derive_log_source_name(
        logs=[s.raw_log for s in request.logs],
        parent_decoder=parent_decoder,
        user_provided=getattr(request, 'log_source_name', None),
    )

    # ── Check for user-specified parent_rule_id ──
    user_parent_id: Optional[int] = getattr(request, 'parent_rule_id', None)

    rule_xml = None
    if needs_custom_rule:
        builtin_rule_id = existing_rule_id
        decoded_as = existing_decoder or parent_decoder

        child_rule = None
        # Only build a child rule when explicitly requested via parent_rule_id
        # or when user provides child conditions.
        user_field_conditions: List[Dict[str, str]] = getattr(request, 'child_field_conditions', [])
        user_match_conditions: List[str] = getattr(request, 'child_match_conditions', [])
        user_static_conditions: List[Dict[str, str]] = getattr(request, 'child_static_conditions', [])
        has_explicit_child_conditions = bool(user_field_conditions or user_match_conditions or user_static_conditions)

        if user_parent_id is not None or has_explicit_child_conditions:
            child_level = infer_rule_from_natural_language(request.rule_requirement or "", request.level)
            child_desc = (
                request.rule_description
                if request.rule_description
                else clean_rule_description(request.rule_requirement or "")
            )

            if not has_explicit_child_conditions:
                # Auto-detect conditions from logs + requirement
                parsed_logtest_fields: Dict[str, str] = {}
                for entry in analysis.get("logtest_scan", {}).get("parsed_entries", []):
                    for field_key in ("decoder_name", "program_name", "predecoded_hostname"):
                        val = entry.get(field_key)
                        if val and field_key not in parsed_logtest_fields:
                            parsed_logtest_fields[field_key.replace("predecoded_", "").replace("decoder_", "")] = val
                auto_fields, auto_matches, auto_statics = derive_child_rule_conditions(
                    logs=[s.raw_log for s in request.logs],
                    rule_requirement=request.rule_requirement or "",
                    extract_fields=request.extract_fields,
                    field_hints=getattr(request, 'field_hints', {}),
                    parsed_logtest_fields=parsed_logtest_fields or None,
                    clean_description=child_desc,
                )
            else:
                auto_fields, auto_matches, auto_statics = (
                    user_field_conditions, user_match_conditions, user_static_conditions
                )

            child_rule = {
                "id": request.rule_id + 1,
                "level": child_level,
                "description": child_desc,
                "field_conditions": auto_fields,
                "match_conditions": auto_matches,
                "static_conditions": auto_statics,
            }

        # Parent description is always "{log_source_name} messages grouped".
        # rule_description is for the child rule, NOT the parent.
        parent_rule_desc: Optional[str] = None
        if not child_rule and request.rule_requirement:
            parent_rule_desc = clean_rule_description(request.rule_requirement)

        # ── Case 1: User specified an existing parent rule ID ──
        # Emit a single child-only rule extending the user's parent, no wrapper parent rule
        if user_parent_id is not None:
            rule_xml = build_rule_xml(
                app_name=app_name,
                rule_id=request.rule_id,
                level=effective_level,
                log_source_name=log_source_name,
                if_sid=user_parent_id,
                child_rule=child_rule,
                child_only=True,
            )
        elif builtin_rule_id == 2501:
            regex_pattern = derive_regex_from_predecoded_body([s.raw_log for s in request.logs])
            rule_xml = build_rule_xml(
                app_name=app_name,
                rule_id=request.rule_id,
                level=effective_level,
                log_source_name=log_source_name,
                if_sid=builtin_rule_id,
                regex=regex_pattern,
                child_rule=child_rule,
                description=parent_rule_desc,
            )
        elif builtin_rule_id is not None:
            analysis["rule_warning"] = (
                f"Log already matches built-in rule {builtin_rule_id}. "
                f"Verify with wazuh-logtest whether you need a custom rule or can extend the existing one."
            )
            rule_xml = build_rule_xml(
                app_name=app_name,
                rule_id=request.rule_id,
                level=effective_level,
                log_source_name=log_source_name,
                decoded_as=decoded_as,
                child_rule=child_rule,
                description=parent_rule_desc,
            )
        else:
            rule_xml = build_rule_xml(
                app_name=app_name,
                rule_id=request.rule_id,
                level=effective_level,
                log_source_name=log_source_name,
                decoded_as=decoded_as,
                child_rule=child_rule,
                description=parent_rule_desc,
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
        "log_source_name": log_source_name,
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
    try:
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
    except subprocess.TimeoutExpired:
        return {
            "returncode": None,
            "stdout": "",
            "stderr": "wazuh-logtest is not accessible: SSH command timed out",
            "connection_error": True,
        }
    except Exception as e:
        return {
            "returncode": None,
            "stdout": "",
            "stderr": f"wazuh-logtest is not accessible: SSH command failed — {e}",
            "connection_error": True,
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

    try:
        proc = subprocess.run(
            cmd,
            input=log_line + "\n",
            text=True,
            capture_output=True,
            timeout=10,
        )
    except FileNotFoundError:
        return {
            "available": False,
            "ok": False,
            "returncode": None,
            "stdout": "",
            "stderr": f"wazuh-logtest is not accessible: binary not found at {binary}",
        }
    except subprocess.TimeoutExpired:
        return {
            "available": False,
            "ok": False,
            "returncode": None,
            "stdout": "",
            "stderr": "wazuh-logtest is not accessible: the binary timed out (unresponsive)",
        }
    except Exception as e:
        return {
            "available": False,
            "ok": False,
            "returncode": None,
            "stdout": "",
            "stderr": f"wazuh-logtest is not accessible: {e}",
        }
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
    try:
        return JSONResponse(analyze_logs_impl(request))
    except Exception as e:
        return JSONResponse({"message": str(e)}, status_code=503)


@app.post("/api/generate")
def generate(request: CandidateRequest):
    try:
        return JSONResponse(build_candidate(request))
    except Exception as e:
        return JSONResponse({"message": str(e)}, status_code=503)


@app.post("/api/test")
def test_candidate(request: TestRequest):
    try:
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
    except Exception as e:
        return JSONResponse({"message": str(e)}, status_code=503)


@app.post("/api/install")
def install_decoder(request: InstallRequest):
    try:
        stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        app_name = sanitize_name(request.app_name) or "customapp"
        writes = []
        errors = []

        def write_one(target_dir, prefix, content):
            if not content:
                return
            filename = f"local_{app_name}_{prefix}_{stamp}.xml"
            remote_path = f"{target_dir.rstrip('/')}/{filename}"
            local_path = str(Path(target_dir) / filename)
            if WAZUH_REMOTE_ENABLED:
                remote_cmd = build_remote_sudo_command(f"tee {shlex.quote(remote_path)} >/dev/null")
                proc = run_ssh_command(remote_cmd, input_data=build_remote_stdin(content, requires_sudo=True), timeout=20)
                if proc["returncode"] == 0:
                    writes.append(f"ssh://{WAZUH_SSH_USER}@{WAZUH_SSH_HOST}:{remote_path}")
                    return
                errors.append(f"failed to write remote {remote_path}: rc={proc['returncode']} stderr={proc['stderr'].strip()}")
            else:
                try:
                    Path(target_dir).mkdir(parents=True, exist_ok=True)
                    Path(local_path).write_text(content + "\n", encoding="utf-8")
                    writes.append(local_path)
                except Exception as exc:
                    fallback = LOCAL_OUTPUT_DIR / prefix / filename
                    fallback.parent.mkdir(parents=True, exist_ok=True)
                    fallback.write_text(content + "\n", encoding="utf-8")
                    writes.append(str(fallback))
                    errors.append(f"wrote fallback: {fallback}")

        rule_content = request.rule_xml
        if rule_content and not rule_content.strip().startswith("<group"):
            rule_content = f'<group name="custom_{app_name}">\n{rule_content.strip()}\n</group>'

        write_one(WAZUH_DECODERS_DIR, "decoder", request.decoder_xml)
        write_one(WAZUH_RULES_DIR, "rule", rule_content)
        return JSONResponse({"success": len(errors) == 0, "written_files": writes, "errors": errors, "stamp": stamp})
    except Exception as e:
        return JSONResponse({"message": str(e)}, status_code=503)


@app.post("/api/uninstall")
def uninstall_decoder(request: UninstallRequest):
    try:
        removed = []
        errors = []
        for path in request.file_paths:
            if "ssh://" in path:
                remote_path = path.split(":", 2)[-1]
                remote_cmd = build_remote_sudo_command(f"rm -f {shlex.quote(remote_path)}")
                proc = run_ssh_command(remote_cmd, input_data=build_remote_stdin(requires_sudo=True), timeout=15)
                if proc["returncode"] == 0:
                    removed.append(path)
                else:
                    errors.append(f"failed to remove {path}: rc={proc['returncode']}")
            else:
                try:
                    Path(path).unlink(missing_ok=True)
                    removed.append(path)
                except Exception as exc:
                    errors.append(f"failed to remove {path}: {exc}")
        return JSONResponse({"removed_files": removed, "errors": errors})
    except Exception as e:
        return JSONResponse({"message": str(e)}, status_code=503)


@app.post("/api/logtest/raw")
def logtest_raw(request: LogtestRawRequest):
    try:
        results = []
        for raw_log in request.logs:
            output = run_wazuh_logtest(raw_log, expected=request.expected)
            parsed = {}
            if output["available"]:
                combined = output.get("stdout", "") + "\n" + output.get("stderr", "")
                parsed = parse_logtest_output(combined)
            results.append({
                "raw_log": raw_log,
                "stdout": output.get("stdout", ""),
                "stderr": output.get("stderr", ""),
                "available": output["available"],
                "ok": output.get("ok", False),
                "parsed": parsed,
            })
        return JSONResponse({"results": results})
    except Exception as e:
        return JSONResponse({"message": str(e)}, status_code=503)


@app.get("/api/ml/status")
def ml_status():
    model = ensure_ml_model_enhanced(force_refresh=False, use_ensemble=True)
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
        branch=WAZUH_REPO_BRANCH,
    )
    _ML_MODEL = None
    model = ensure_ml_model_enhanced(force_refresh=False, use_ensemble=True)
    # Also rebuild RAG store so it picks up new decoders
    rag_result = {}
    if _RAG_AVAILABLE and _rag is not None:
        try:
            rag_result = _rag.build_store(force=True)
        except Exception as e:
            rag_result = {"status": "error", "message": str(e)}
    return {
        "refresh": refreshed,
        "model_loaded": bool(model),
        "pattern_count": _ML_PATTERN_COUNT,
        "error": _ML_MODEL_ERROR,
        "rag": rag_result,
    }


@app.get("/api/rag/status")
def rag_status():
    """Return the current status of the RAG vector store."""
    if not _RAG_AVAILABLE or _rag is None:
        return {"available": False, "reason": "chromadb not installed or rag_engine failed to load"}
    return {"available": True, **_rag.get_status()}


@app.post("/api/feedback")
def feedback(request: FeedbackRequest):
    return JSONResponse(save_feedback_example(request))


@app.get("/health")
def health():
    binary = find_wazuh_logtest()
    if WAZUH_REMOTE_ENABLED and binary:
        try:
            cmd = ssh_base_cmd() + [f"sudo {WAZUH_LOGTEST} -q </dev/null 2>/dev/null; echo EXITCODE=$?"]
            proc = subprocess.run(cmd, text=True, capture_output=True, timeout=5)
            logtest_accessible = proc.returncode == 0 and proc.stdout is not None
        except Exception:
            logtest_accessible = False
    elif binary:
        logtest_accessible = os.access(binary, os.X_OK)
    else:
        logtest_accessible = False
    return {
        "ok": True,
        "wazuh_remote_enabled": WAZUH_REMOTE_ENABLED,
        "wazuh_ssh_host": WAZUH_SSH_HOST,
        "wazuh_ssh_port": WAZUH_SSH_PORT,
        "wazuh_ssh_user": WAZUH_SSH_USER,
        "wazuh_logtest_path": WAZUH_LOGTEST,
        "wazuh_logtest_exists": bool(binary),
        "wazuh_logtest_accessible": logtest_accessible,
        "wazuh_decoders_dir": WAZUH_DECODERS_DIR,
        "wazuh_rules_dir": WAZUH_RULES_DIR,
        "ml_model_loaded": bool(_ML_MODEL),
        "ml_pattern_count": _ML_PATTERN_COUNT,
        "ml_model_error": _ML_MODEL_ERROR,
        "wazuh_repo_cache_dir": str(WAZUH_REPO_CACHE_DIR),
        "ai_provider": "ollama" if OLLAMA_BASE_URL else ("dashscope" if DASHSCOPE_API_KEY else ("openrouter" if OPENROUTER_API_KEY else "none")),
        "ai_model": OLLAMA_MODEL if OLLAMA_BASE_URL else AI_DEFAULT_MODEL,
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
    field_hints: Dict[str, str] = Field(default_factory=dict)
    split_decoders: bool = Field(default=False)
    temperature: float = Field(default=0.05, ge=0.0, le=1.0)
    extra_context: str = Field(default="")
    log_source_name: Optional[str] = Field(default=None)
    generation_mode: str = Field(
        default="auto",
        description="What to generate: 'decoder_only', 'rule_only', 'both', or 'auto'. "
                    "'auto' generates decoder when no rule_requirement, both when rule_requirement is set."
    )
    validate_with_logtest: bool = Field(
        default=True,
        description="If True, auto-validate the generated decoder by installing temporarily "
                    "and running wazuh-logtest to ensure 100% accuracy."
    )


_OLLAMA_SYSTEM_PROMPT = """You are a Wazuh SIEM expert. You produce ONLY valid Wazuh decoder and rule XML.
No explanations, no commentary — just XML wrapped in ```xml blocks.

## ⚠️ OS_Regex is NOT PCRE — CRITICAL DIFFERENCES
Wazuh OS_Regex is fundamentally different from PCRE regex:
- '.' is a LITERAL dot character (never a wildcard!)
- '\\.' means ANY character (opposite of PCRE!)
- Quantifiers (+, *) ONLY work on backslash-escaped sequences like \\d+, \\w+, \\.+
  They do NOT work on bare characters like .+ a+ 0+
- '(.+)' is INVALID — write '(\\S+)' for non-space tokens or '(\\.+)' for any-char
- '.*' is INVALID — use '\\.+' instead
- No alternation with | inside parentheses — use separate decoder entries

## CORRECT vs WRONG patterns
  CORRECT: (\\S+)                          WRONG: (.+)
  CORRECT: (\\d+.\\d+.\\d+.\\d+)          WRONG: (\\d+\\.\\d+\\.\\d+\\.\\d+)
  CORRECT: \\.+ (any-char one-or-more)     WRONG: .+
  CORRECT: \\.+ (any-char zero-or-more)     WRONG: .*
  CORRECT: '\\S+'                          WRONG: '.+'

## Valid OS_Regex character classes
  \\d = digits      \\w = word chars     \\s = space (only ASCII 32)
  \\. = ANY char     \\S = non-space      \\W = non-word
  \\D = non-digit    \\p = punctuation    \\t = tab

## Valid quantifiers (apply ONLY to ^ sequences)
  \\d+ \\w+ \\s+ \\.+ \\S+ \\W+ \\D+ \\p+

## Decoder XML Examples
<!-- Example 1: When program_name is pre-decoded -->
<decoder name="myapp">
  <program_name>^myapp</program_name>
</decoder>
<decoder name="myapp-event">
  <parent>myapp</parent>
  <regex>User '(\\S+)' failed login from '(\\d+.\\d+.\\d+.\\d+)'</regex>
  <order>user, srcip</order>
</decoder>

<!-- Example 2: When program_name is NOT pre-decoded -->
<decoder name="myapp">
  <prematch>\\S+ \\S+ myapp\\[\\d+\\]: </prematch>
</decoder>
<decoder name="myapp-event">
  <parent>myapp</parent>
  <regex>User '(\\S+)' failed login from '(\\d+.\\d+.\\d+.\\d+)'</regex>
  <order>user, srcip</order>
</decoder>

## Rule XML Example
<rule id="100001" level="5">
  <if_sid>5710</if_sid>
  <decoded_as>myapp</decoded_as>
  <field name="user">admin</field>
  <description>User login failed</description>
</rule>

Output ONLY XML wrapped in ```xml``` blocks. Do NOT repeat or echo any part of the prompt."""


def _build_ai_prompt(request: AIGenerateRequest, analysis: Dict[str, Any]) -> str:
    logs_block = "\n".join(s.raw_log for s in request.logs[:5])
    effective_fields = analysis.get("effective_extract_fields") or request.extract_fields
    skipped_fields = analysis.get("skipped_decoded_fields") or []
    has_rule_req = bool(request.rule_requirement and request.rule_requirement.strip())
    rule_req = request.rule_requirement or ""
    predecoded_program = analysis.get("predecoded_program_name") or ""
    extracted_program = analysis.get("extracted_program_name") or ""
    program = predecoded_program or extracted_program or request.app_name
    log_source = request.log_source_name or program or request.app_name

    gen_mode = getattr(request, 'generation_mode', 'auto')
    if gen_mode == "auto":
        gen_mode = "both" if has_rule_req else "decoder_only"

    config_lines = [
        f"- App name: {request.app_name}",
        f"- Log source: {log_source}",
        f"- Program name: {program}",
    ]
    if effective_fields:
        config_lines.append(f"- ONLY extract these fields: {', '.join(effective_fields)}")
        if getattr(request, 'split_decoders', False):
            config_lines.append("- (Split the output into separate child decoders for each field)")
        config_lines.append("- Do NOT add any extra fields beyond this list")
    else:
        config_lines.append("- Fields: auto-detect from log content")
        if getattr(request, 'split_decoders', False):
            config_lines.append("- (Split the output into separate child decoders for each field)")
    if skipped_fields:
        config_lines.append(f"- Fields ALREADY decoded by built-in (SKIP these): {', '.join(skipped_fields)}")
    if gen_mode in ("both", "rule_only") and has_rule_req:
        config_lines.append(f"- Rule requirement: {rule_req}")
        config_lines.append(f"- Rule ID: {request.rule_id}, Level: {request.level}")
    if request.extra_context:
        config_lines.append(f"- Extra context: {request.extra_context}")
    config_block = "\n".join(config_lines)

    hints_block = ""
    field_hints = getattr(request, 'field_hints', {})
    if field_hints:
        hints_lines = [f"  - '{v}' -> field '{k}'" for k, v in field_hints.items() if v]
        if hints_lines:
            hints_block = "Field value mapping hints:\n" + "\n".join(hints_lines) + "\n"

    if predecoded_program:
        parent_strategy = f"Parent decoder MUST use <program_name> (program: '{predecoded_program}')."
    else:
        token_source = analysis.get("token_source")
        logs_to_use = [token_source] if token_source else [s.raw_log for s in request.logs]
        parent_prematch = prematch_osregex_from_current_logs(
            logs_to_use,
            extracted_program,
            analysis.get("unique_after_predecoded"),
            analysis.get("prematch"),
        )
        if parent_prematch:
            parent_strategy = f"No program name pre-decoded by Wazuh. You MUST use <prematch>{parent_prematch}</prematch> for the parent decoder. Do NOT invent a different prematch."
        else:
            parent_strategy = "No program name pre-decoded by Wazuh. You MUST use <prematch> for the parent decoder instead of <program_name> based on the log's prefix."

    logtest_summary = analysis.get("wazuh_logtest_summary", {})
    logtest_decoded = analysis.get("logtest_decoded_fields", {})
    logtest_block = ""
    if logtest_summary:
        decoded_str = ""
        if logtest_decoded:
            decoded_str = "  Already decoded: " + ", ".join(f"{k}={v}" for k, v in logtest_decoded.items()) + "\n"
        logtest_block = (
            f"Logtest: decoder={logtest_summary.get('decoder_name', 'None')}, "
            f"rule={logtest_summary.get('rule_id', 'None')}, "
            f"program={logtest_summary.get('predecoded_program_name', 'None')}\n"
            f"{decoded_str}"
        )

    ml_context = ""
    suggestions = analysis.get("ml_suggestions") or []
    if suggestions[:3]:
        ml_lines = []
        for s in suggestions[:3]:
            ml_lines.append(f"  {s.get('name','?')}: regex={s.get('regex','?')} order={','.join(s.get('order') or [])}")
        ml_context = "Similar Wazuh decoders (reference):\n" + "\n".join(ml_lines) + "\n"

    # RAG: retrieve verified real decoder examples from vector store
    rag_context = ""
    if _RAG_AVAILABLE and _rag is not None:
        try:
            first_log = request.logs[0].raw_log if request.logs else ""
            rag_examples = _rag.retrieve(first_log, fields=effective_fields, top_k=3)
            rag_context = _rag.format_rag_context(rag_examples)
        except Exception as _rag_err:
            logger.warning(f"RAG retrieval failed: {_rag_err}")

    rule_ml_context = ""
    if has_rule_req and gen_mode in ("both", "rule_only"):
        rule_suggestions = rule_suggestions_for_requirement(request.rule_requirement, top_k=2)
        if rule_suggestions:
            rl = []
            for rs in rule_suggestions:
                rl.append(f"  Rule {rs.get('rule_id','?')} (level {rs.get('level','?')}): {rs.get('description','')}")
            rule_ml_context = "Similar rules:\n" + "\n".join(rl) + "\n"

    if gen_mode == "decoder_only":
        output_instruction = (
            "## OUTPUT: Generate ONLY decoder XML inside one ```xml block.\n"
            "Do NOT repeat the prompt back — output only the new XML you generate."
        )
    elif gen_mode == "rule_only":
        output_instruction = (
            "## OUTPUT: Generate ONLY rule XML inside one ```xml block.\n"
            "Do NOT repeat the prompt."
        )
    else:
        output_instruction = (
            "## OUTPUT: Decoder XML in one ```xml block, rule XML in a separate ```xml block.\n"
            "Do NOT echo the prompt or include reference material — only your own generated XML."
        )

    decoder_rules_list = [
        "- Parent: MUST use <prematch> UNLESS Wazuh explicitly predecoded a program_name. Do NOT guess program_name.",
    ]
    if getattr(request, 'split_decoders', False):
        decoder_rules_list.append("- Child: YOU MUST SPLIT CHILD DECODERS. Create a SEPARATE child decoder block for EVERY SINGLE field you extract. Each child decoder should have <parent>, a specific <regex> for just that field, and an <order> containing ONLY that single field name. All children share the same decoder name.")
    else:
        decoder_rules_list.append("- Child: <parent>, <regex>, <order> — one child decoder per set of fields; multiple children share the same decoder name")
    
    decoder_rules_list.extend([
        "- <regex> uses OS_Regex (NOT PCRE)",
        "- Only valid quantifiers: \\d+, \\w+, \\s+, \\p+, \\.+, \\S+, \\W+, \\D+",
        "- Bare char quantifiers (.+, a+, 0+) are INVALID — do NOT use them",
        "- NEVER write (.+) — use (\\S+) for non-space or (\\.+) for any-char",
        "- NEVER write .* — use \\.+ instead",
        "- Use \\S+ to match non-space tokens (most common for field values)",
        "- IP addresses: ALWAYS write (\\d+.\\d+.\\d+.\\d+) — plain dots, NO backslash before dot",
        "- Capture group count MUST match <order> field count exactly",
        "- Do NOT add <type>, <fts>, or <plugin_decoder> unless specifically needed"
    ])
    decoder_rules = "## Decoder Rules\n" + "\n".join(decoder_rules_list)

    rule_section = ""
    if gen_mode in ("rule_only", "both") and has_rule_req:
        rule_section = """## Rule Rules
- <decoded_as> points to the parent decoder name
- <match> uses sregex: plain substring match, | for OR
- Static field tags: <srcip>, <dstip>, <srcport>, <dstport>, <action>, <id>, <url>, <status>, <user>
- Use <field name="F">V</field> only for custom fields NOT in the static list
- <if_sid> for parent rule chaining"""

    return f"""## Log Samples
{logs_block}

## Configuration
{config_block}

{logtest_block}{parent_strategy}
{hints_block}{rag_context}
{ml_context}{rule_ml_context}
{decoder_rules}
{rule_section}
{output_instruction}"""





async def _stream_ai(prompt: str, model: str, temperature: float) -> AsyncIterator[bytes]:
    # Priority: Ollama (local, no rate limits) > DashScope > OpenRouter

    async def _stream_from_api(url: str, payload: dict, headers: dict, max_retries: int = 3) -> AsyncIterator[bytes]:
        for attempt in range(max_retries):
            try:
                # 60s timeout for streaming requests (models might take a while to load into memory on the first request)
                async with httpx.AsyncClient(timeout=60.0) as client:
                    async with client.stream("POST", url, json=payload, headers=headers) as response:
                        if response.status_code == 429:
                            retry_after = int(response.headers.get("Retry-After", 5))
                            backoff = retry_after * (2 ** attempt)
                            if attempt < max_retries - 1:
                                yield f"[Rate limited. Retrying in {backoff}s... (attempt {attempt + 1}/{max_retries})]\n".encode()
                                await asyncio.sleep(backoff)
                                continue
                            else:
                                yield f"ERROR 429: Rate limit exceeded after {max_retries} retries. Try again later.".encode()
                                return
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
                break  # Success, exit retry loop
            except httpx.ReadTimeout:
                if attempt < max_retries - 1:
                    yield f"[AI is taking too long to respond. Retrying... (attempt {attempt + 1}/{max_retries})]\n".encode()
                    await asyncio.sleep(2)
                    continue
                else:
                    yield f"ERROR: The AI model timed out after {max_retries} attempts. It may still be loading into memory. Please try again in a few seconds.".encode()
                    return
            except Exception as e:
                yield f"ERROR: Network or server error connecting to AI provider: {str(e)}".encode()
                return

    # 1) Ollama / local model (no rate limits) — use system+user roles
    if OLLAMA_BASE_URL:
        payload = {
            "model": OLLAMA_MODEL,
            "temperature": temperature,
            "top_k": 15,
            "repeat_penalty": 1.20,
            "num_predict": 4096,
            "stream": True,
            "messages": [
                {"role": "system", "content": _OLLAMA_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        }
        headers = {"Content-Type": "application/json"}
        # Always build as base/v1/chat/completions (OLLAMA_BASE_URL has /v1 stripped above)
        url = f"{OLLAMA_BASE_URL}/v1/chat/completions"
        async for chunk in _stream_from_api(url, payload, headers, max_retries=2):
            yield chunk
        return

    # 2) DashScope (with retry)
    if DASHSCOPE_API_KEY:
        payload = {
            "model": "qwen3.6-plus",
            "temperature": temperature,
            "stream": True,
            "messages": [{"role": "user", "content": prompt}],
        }
        headers = {
            "Authorization": f"Bearer {DASHSCOPE_API_KEY}",
            "Content-Type": "application/json",
        }
        url = f"{DASHSCOPE_BASE_URL}/chat/completions"
        async for chunk in _stream_from_api(url, payload, headers):
            yield chunk
        return

    # 3) OpenRouter (with retry)
    if OPENROUTER_API_KEY:
        payload = {
            "model": model,
            "temperature": temperature,
            "stream": True,
            "messages": [{"role": "user", "content": prompt}],
        }
        headers = {
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://localhost:8443",
            "X-Title": "Wazuh Decoder Studio",
        }
        url = f"{OPENROUTER_BASE_URL}/chat/completions"
        async for chunk in _stream_from_api(url, payload, headers):
            yield chunk
        return

    yield b"ERROR: No AI provider configured.\n\nSet one of:\n  OLLAMA_BASE_URL (recommended - local, no rate limits)\n  DASHSCOPE_API_KEY\n  OPENROUTER_API_KEY"


@app.post("/api/ai/generate")
async def ai_generate(request: AIGenerateRequest):
    """Generate decoder + rule XML with AI. Structure from AI, regex silently corrected
    from analysis data. The user sees one unified output."""
    try:
        analysis = analyze_logs_impl(
            AnalyzeRequest(
                logs=request.logs,
                app_name=request.app_name,
                rule_requirement=request.rule_requirement,
                extract_fields=request.extract_fields,
                field_hints=getattr(request, 'field_hints', {}),
                split_decoders=request.split_decoders,
            )
        )
    except Exception as e:
        return PlainTextResponse(f"ERROR: wazuh-logtest is not accessible: {e}")

    prompt = _build_ai_prompt(request, analysis)
    full_response = await _collect_ai_response(prompt, AI_DEFAULT_MODEL, request.temperature)
    decoder_xml, rule_xml = _extract_xml_from_ai_response(
        full_response, regex_order_pairs=analysis.get("regex_order_pairs")
    )
    out = ""
    if decoder_xml:
        out += f"### Decoder\n\n```xml\n{decoder_xml}\n```\n\n"
    if rule_xml:
        out += f"### Rule\n\n```xml\n{rule_xml}\n```"
    return StreamingResponse(
        _iter_text(out or full_response),
        media_type="text/plain",
    )


def _iter_text(text: str) -> AsyncIterator[bytes]:
    """Yield a single text as one chunk (for non-streaming endpoints that return StreamingResponse)."""
    yield text.encode()


async def _collect_ai_response(prompt: str, model: str, temperature: float) -> str:
    """Collect the full AI response as a string (non-streaming)."""
    chunks: List[str] = []
    async for chunk in _stream_ai(prompt, model, temperature):
        chunks.append(chunk.decode() if isinstance(chunk, bytes) else chunk)
    return "".join(chunks)


async def _stream_ai_sanitized(prompt: str, model: str, temperature: float) -> AsyncIterator[bytes]:
    """Collect the full AI response, apply OS_Regex sanitization (fix \\d+\\.\\d+ → \\d+.\\d+
    for IP addresses), then yield the cleaned text as a single streaming chunk.
    This ensures the wrong PCRE-style escaped-dot IP pattern never reaches the user."""
    chunks: List[str] = []
    async for chunk in _stream_ai(prompt, model, temperature):
        decoded = chunk.decode() if isinstance(chunk, bytes) else chunk
        chunks.append(decoded)
    full_text = "".join(chunks)
    # Apply post-processing: fix wrong \d+\.\d+ IP patterns inside XML tags
    sanitized_text = _apply_osregex_ip_fix_to_text(full_text)
    yield sanitized_text.encode()


def _fix_osregex_bare_dot_quantifier(content: str) -> str:
    """Fix bare '.' used as a wildcard quantifier in OS_Regex content.
    In PCRE, '.' means any char and '.+' means one-or-more any char.
    In OS_Regex, '.' is a LITERAL dot — to mean "any char" you must write '\\.'.
    And quantifiers only work on backslash-escaped sequences, so '.+' is doubly wrong.
    
    Fixes:
      (.+)  →  (\\S+)    (most common AI mistake — use non-space for field capture)
      .+    →  \\.+      (convert bare-dot any-char to OS_Regex any-char)
      .*    →  \\.+      (zero-or-more made one-or-more; .* is useless in OS_Regex)
    
    Does NOT touch '\\.+' which is already valid OS_Regex.
    """
    import re as _re
    # Fix (.+) → (\\S+) — the most common AI pattern
    content = _re.sub(r'\(\.\+\)', r'(\\S+)', content)
    # Fix .+ → \\.+ (but NOT \\.+ → \\.+, so check no backslash before dot)
    content = _re.sub(r'(?<!\\)\.\+', r'\\.+', content)
    # Fix .* → \\.+ (same, avoid double-escaping)
    content = _re.sub(r'(?<!\\)\.\*', r'\\.+', content)
    return content


def _fix_osregex_ip_dots(content: str) -> str:
    """Fix escaped dots in IP address regex patterns for Wazuh OS_Regex.

    In Wazuh OS_Regex, '.' is ALWAYS a literal dot. '\.' means ANY character.
    AI models write \d+\.\d+ (PCRE-style) which is WRONG for OS_Regex.
    Correct form: \d+.\d+.\d+.\d+ (plain dots, no backslash before dot).

    Uses plain string.replace() — no regex backslash confusion.
    Loops until stable to handle all dots in \d+\.\d+\.\d+\.\d+.
    Does NOT touch \. followed by + or * (those are valid any-char quantifiers).
    """
    prev = None
    while content != prev:
        prev = content
        # Replace \d+\.\d  →  \d+.\d  (IP dot between digit groups with quantifier)
        content = content.replace('\\d+\\.\\d', '\\d+.\\d')
        # Replace \d\.\d   →  \d.\d   (IP dot between bare digit groups)
        content = content.replace('\\d\\.\\d', '\\d.\\d')
        # Also fix \d*\.\d patterns
        content = content.replace('\\d*\\.\\d', '\\d*.\\d')

    # Fix common Gemini/AI mistakes where they use .+ or \S+ for IPs
    content = content.replace('(.+\\..+\\..+\\..+)', '(\\d+.\\d+.\\d+.\\d+)')
    content = content.replace('(.+..+..+..+)', '(\\d+.\\d+.\\d+.\\d+)')
    content = content.replace('(\\S+\\.\\S+\\.\\S+\\.\\S+)', '(\\d+.\\d+.\\d+.\\d+)')
    content = content.replace('(\\S+.\\S+.\\S+.\\S+)', '(\\d+.\\d+.\\d+.\\d+)')
    return content


def _apply_osregex_ip_fix_to_text(text: str) -> str:
    """Apply IP dot fix and bare dot fixes to the full raw AI response text.
    Fixes \d+\.\d+ → \d+.\d+ inside <regex>, <prematch>, and ```xml blocks.
    """
    import re as _re

    def _fix_all(content: str) -> str:
        content = _fix_osregex_ip_dots(content)
        content = _fix_osregex_bare_dot_quantifier(content)
        return content

    # Fix inside <regex>...</regex> tags
    fixed = _re.sub(
        r'(<regex[^>]*>)([\s\S]*?)(</regex>)',
        lambda m: m.group(1) + _fix_all(m.group(2)) + m.group(3),
        text,
    )
    # Fix inside <prematch>...</prematch> tags
    fixed = _re.sub(
        r'(<prematch[^>]*>)([\s\S]*?)(</prematch>)',
        lambda m: m.group(1) + _fix_all(m.group(2)) + m.group(3),
        fixed,
    )
    # Fix inside ```xml ... ``` fenced blocks (covers the raw streaming output)
    def _fix_xml_fence(m: _re.Match) -> str:
        block = m.group(1)
        block = _re.sub(
            r'(<regex[^>]*>)([\s\S]*?)(</regex>)',
            lambda bm: bm.group(1) + _fix_all(bm.group(2)) + bm.group(3),
            block,
        )
        block = _re.sub(
            r'(<prematch[^>]*>)([\s\S]*?)(</prematch>)',
            lambda bm: bm.group(1) + _fix_all(bm.group(2)) + bm.group(3),
            block,
        )
        return f'```xml{block}```'

    fixed = _re.sub(r'```xml([\s\S]*?)```', _fix_xml_fence, fixed)
    return fixed


# ── Internal field-to-regex mapping (never exposed to user) ──────────────
# These are correct Wazuh OS_Regex patterns inferred from field values.
# Used silently to fix AI-generated regex — the user sees one unified output.
_INTERNAL_FIELD_REGEX = {
    "srcip": r"(\d+\.\d+\.\d+\.\d+)",
    "dstip": r"(\d+\.\d+\.\d+\.\d+)",
    "srcport": r"(\d+)",
    "dstport": r"(\d+)",
    "protocol": r"(\S+)",
    "action": r"(\S+)",
    "status": r"(\S+)",
    "user": r"(\S+)",
    "srcuser": r"(\S+)",
    "dstuser": r"(\S+)",
    "hostname": r"(\S+)",
    "id": r"(\S+)",
    "url": r"(\S+)",
    "method": r"(\S+)",
    "uid": r"(\d+)",
    "gid": r"(\d+)",
    "pid": r"(\d+)",
    "ppid": r"(\d+)",
}


def _internal_infer_regex_order_pairs(
    fields: List[Dict[str, Any]], extracted_data: List[Dict[str, str]]
) -> List[Tuple[str, List[str]]]:
    """Internal: build (regex, [order fields]) pairs from field analysis.
    Never displayed to the user — only used to silently correct AI output."""
    if not fields:
        return _infer_from_extracted_data(extracted_data)
    pairs: List[Tuple[str, List[str]]] = []
    order_list: List[str] = []
    for f in fields:
        name = (f.get("name") or "").strip()
        if name:
            order_list.append(name)
            if name not in _INTERNAL_FIELD_REGEX:
                _INTERNAL_FIELD_REGEX[name] = r"(\S+)"
    if order_list:
        regex = " ".join(_INTERNAL_FIELD_REGEX.get(f, r"(\S+)") for f in order_list)
        pairs.append((regex, order_list))
    return pairs


def _infer_from_extracted_data(
    extracted_data: List[Dict[str, str]]
) -> List[Tuple[str, List[str]]]:
    """Internal: infer regex from extracted field data when field defs unavailable."""
    from collections import OrderedDict
    import re as _re

    field_order = OrderedDict()
    for entry in extracted_data:
        for key, value in entry.items():
            if key not in field_order:
                field_order[key] = value
    if not field_order:
        return []
    order_list = list(field_order.keys())
    regex = " ".join(_INTERNAL_FIELD_REGEX.get(f, r"(\S+)") for f in order_list)
    return [(regex, order_list)]


def _inject_correct_regex(decoder_xml: str, regex_order_pairs: List[Tuple[str, List[str]]]) -> str:
    """Silently replace <regex> content in AI output with correct patterns from analysis.
    The user sees one unified output — this is an internal correction step,
    not a separate programmatic output."""
    if not decoder_xml or not regex_order_pairs:
        return decoder_xml
    import re as _re
    field_to_regex = {}
    for regex, order_list in regex_order_pairs:
        key = frozenset(f.strip() for f in order_list)
        field_to_regex[key] = regex

    def _replace(m: _re.Match) -> str:
        rest = decoder_xml[m.end():]
        order_m = _re.search(r'<order>([^<]+)</order>', rest)
        if order_m:
            fields = frozenset(f.strip() for f in order_m.group(1).split(','))
            correct = field_to_regex.get(fields)
            if correct:
                return f'{m.group(1)}{correct}{m.group(3)}'
        content = m.group(2)
        content = _fix_osregex_bare_dot_quantifier(content)
        content = _fix_osregex_ip_dots(content)
        return f'{m.group(1)}{content}{m.group(3)}'

    return _re.sub(r'(<regex[^>]*>)([\s\S]*?)(</regex>)', _replace, decoder_xml)


def _enforce_split_decoders(decoder_xml: str, regex_order_pairs: List[Tuple[str, List[str]]]) -> str:
    """If split_decoders is True (regex_order_pairs > 1) but AI generated a single combined decoder,
    forcibly split the child decoder block into multiple blocks."""
    if not decoder_xml or not regex_order_pairs or len(regex_order_pairs) <= 1:
        return decoder_xml
        
    import re as _re
    decoder_blocks = _re.findall(r'(<decoder\b[^>]*>.*?</decoder>)', decoder_xml, _re.DOTALL)
    if not decoder_blocks:
        return decoder_xml
        
    expected_fields = set()
    for _, order_list in regex_order_pairs:
        expected_fields.update(order_list)
        
    new_blocks = []
    for block in decoder_blocks:
        order_m = _re.search(r'<order>([^<]+)</order>', block)
        if order_m:
            fields = [f.strip() for f in order_m.group(1).split(',')]
            if len(fields) > 1 and any(f in expected_fields for f in fields):
                # This is the combined child decoder! Split it.
                name_m = _re.search(r'<decoder\b[^>]*>', block)
                name_tag = name_m.group(0) if name_m else '<decoder name="custom-event">'
                
                parent_m = _re.search(r'(<parent>[^<]+</parent>)', block)
                parent_tag = parent_m.group(1) if parent_m else ''
                
                split_blocks = []
                for regex, order_list in regex_order_pairs:
                    order_str = ",".join(order_list)
                    split_blocks.append(f'{name_tag}\n  {parent_tag}\n  <regex>{regex}</regex>\n  <order>{order_str}</order>\n</decoder>')
                new_blocks.append("\n\n".join(split_blocks))
                continue
                
        new_blocks.append(block)
        
    return "\n\n".join(new_blocks)


def _extract_xml_from_ai_response(
    full_text: str,
    regex_order_pairs: Optional[List[Tuple[str, List[str]]]] = None,
) -> Tuple[str, str]:
    """Extract decoder XML and rule XML from AI response text.
    Silently corrects regex patterns using analysis data when available.
    Returns (decoder_xml, rule_xml)."""
    import re as _re
    xml_blocks = _re.findall(r'```xml\s*([\s\S]*?)```', full_text)
    decoder_xml = ""
    rule_xml = ""
    for block in xml_blocks:
        block = block.strip()
        if "<decoder" in block and not decoder_xml:
            decoder_xml = block
        elif ("<rule" in block or "<group" in block) and not rule_xml:
            rule_xml = block
    if not decoder_xml:
        m = _re.search(r'(<decoder[\s\S]*?</decoder>)', full_text)
        if m:
            decoder_xml = m.group(1).strip()
    if not rule_xml:
        m = _re.search(r'(<group[\s\S]*?</group>)', full_text)
        if m:
            rule_xml = m.group(1).strip()
            
    # Forcibly split child decoders if the user requested it but the AI failed to do so
    decoder_xml = _enforce_split_decoders(decoder_xml, regex_order_pairs)
    
    # Silently inject correct regex patterns (invisible to user)
    decoder_xml = _inject_correct_regex(decoder_xml, regex_order_pairs)
    decoder_xml = _sanitize_decoder_xml_osregex(decoder_xml)
    return decoder_xml, rule_xml


def _sanitize_decoder_xml_osregex(decoder_xml: str) -> str:
    """Fix escaped dots in IP patterns and bare dots inside decoder XML."""
    if not decoder_xml:
        return decoder_xml
    import re as _re

    def _fix_all(content: str) -> str:
        content = _fix_osregex_ip_dots(content)
        content = _fix_osregex_bare_dot_quantifier(content)
        return content

    sanitized = _re.sub(
        r'(<regex[^>]*>)([\s\S]*?)(</regex>)',
        lambda m: m.group(1) + _fix_all(m.group(2)) + m.group(3),
        decoder_xml,
    )
    sanitized = _re.sub(
        r'(<prematch[^>]*>)([\s\S]*?)(</prematch>)',
        lambda m: m.group(1) + _fix_all(m.group(2)) + m.group(3),
        sanitized,
    )
    return sanitized


def _sanitize_rule_xml_static_fields(rule_xml: str) -> str:
    """Wazuh rules do not allow <field name="static_field"> tags.
    They must be written as <static_field> tags directly. This function sanitizes them."""
    if not rule_xml:
        return rule_xml
    import re as _re
    static_fields = {
        "srcip", "dstip", "srcport", "dstport", "user", "url", "id", 
        "status", "action", "hostname", "program_name", "location", 
        "match", "extra_data", "system_name", "protocol"
    }
    sanitized = rule_xml
    for field in static_fields:
        pattern = rf'<field\s+name=["\']{field}["\']\s*>([\s\S]*?)</field>'
        replacement = rf'<{field}>\1</{field}>'
        sanitized = _re.sub(pattern, replacement, sanitized)
    return sanitized


def _validate_ai_decoder_with_logtest(
    decoder_xml: str,
    rule_xml: str,
    logs: List[LogSample],
    app_name: str,
) -> Dict[str, Any]:
    """Install decoder/rule temporarily, run wazuh-logtest, and return validation results."""
    rule_xml = _sanitize_rule_xml_static_fields(rule_xml)
    if not decoder_xml:
        return {"validated": False, "reason": "no decoder XML to validate"}
    if not find_wazuh_logtest():
        return {"validated": False, "reason": "wazuh-logtest unavailable"}

    stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    safe_name = sanitize_name(app_name)
    decoder_filename = f"local_{safe_name}_ai_validate_decoder_{stamp}.xml"
    rule_filename = f"local_{safe_name}_ai_validate_rule_{stamp}.xml"

    ok, err = install_temp_content(WAZUH_DECODERS_DIR, decoder_filename, decoder_xml)
    if not ok:
        return {"validated": False, "reason": f"decoder install failed: {err}"}

    rule_installed = False
    if rule_xml:
        wrapped_rule_xml = rule_xml.strip()
        if not wrapped_rule_xml.startswith("<group"):
            wrapped_rule_xml = f'<group name="temp_ai_validate">\n{wrapped_rule_xml}\n</group>'
        rule_ok, rule_err = install_temp_content(WAZUH_RULES_DIR, rule_filename, wrapped_rule_xml)
        if rule_ok:
            rule_installed = True

    try:
        results = []
        all_matched = True
        for sample in logs:
            output = run_wazuh_logtest(sample.raw_log)
            parsed = parse_logtest_output(combined_logtest_output(output)) if output["available"] else {}
            decoder_name = parsed.get("decoder_name", "")
            matched = bool(decoder_name and decoder_name != "unknown")
            if not matched:
                all_matched = False
            results.append({
                "raw_log": sample.raw_log[:200],
                "decoder_matched": decoder_name,
                "fields": {k: v for k, v in parsed.items() if k not in ("decoder_name", "rule_id", "rule_level")},
                "matched": matched,
            })
        return {
            "validated": all_matched,
            "results": results,
            "reason": "all logs matched decoder" if all_matched else "some logs did not match decoder",
        }
    finally:
        remove_temp_content(WAZUH_DECODERS_DIR, decoder_filename)
        if rule_installed:
            remove_temp_content(WAZUH_RULES_DIR, rule_filename)


@app.post("/api/ai/generate-validated")
async def ai_generate_validated(request: AIGenerateRequest):
    """Generate decoder/rule XML with AI, then validate with wazuh-logtest.
    Retries up to 3 times if validation fails, feeding errors back to the AI."""
    try:
        analysis = analyze_logs_impl(
            AnalyzeRequest(
                logs=request.logs,
                app_name=request.app_name,
                rule_requirement=request.rule_requirement,
                extract_fields=request.extract_fields,
                field_hints=getattr(request, 'field_hints', {}),
                split_decoders=request.split_decoders,
            )
        )
    except Exception as e:
        return JSONResponse({"error": f"wazuh-logtest is not accessible: {e}"}, status_code=503)

    app_name = analysis["app_name"]

    max_retries = 3
    best_decoder_xml = ""
    best_rule_xml = ""
    best_validation = {"validated": False, "reason": "not attempted"}
    correction_context = ""

    for attempt in range(max_retries):
        prompt = _build_ai_prompt(request, analysis)
        if correction_context:
            prompt += f"\n\n## CORRECTION (attempt {attempt + 1})\n{correction_context}"

        full_response = await _collect_ai_response(prompt, AI_DEFAULT_MODEL, request.temperature)
        decoder_xml, rule_xml = _extract_xml_from_ai_response(
            full_response, regex_order_pairs=analysis.get("regex_order_pairs")
        )
        rule_xml = _sanitize_rule_xml_static_fields(rule_xml)

        best_decoder_xml = decoder_xml or best_decoder_xml
        best_rule_xml = rule_xml or best_rule_xml

        if not request.validate_with_logtest:
            best_validation = {"validated": False, "reason": "validation disabled by user"}
            break

        validation = _validate_ai_decoder_with_logtest(
            decoder_xml, rule_xml, request.logs, app_name
        )
        best_validation = validation

        if validation.get("validated"):
            break

        # Build correction context for retry
        failed_logs = [r for r in validation.get("results", []) if not r.get("matched")]
        if failed_logs:
            correction_context = (
                f"The previous decoder XML FAILED wazuh-logtest validation.\n"
                f"Failed logs:\n"
            )
            for fl in failed_logs[:3]:
                correction_context += f"  Log: {fl['raw_log']}\n  Matched decoder: {fl.get('decoder_matched', 'none')}\n"
            correction_context += "Fix the regex patterns to match these logs. Output corrected XML only."

    return JSONResponse({
        "decoder_xml": _sanitize_decoder_xml_osregex(best_decoder_xml),
        "rule_xml": best_rule_xml,
        "validation": best_validation,
        "attempts": attempt + 1,
        "generation_mode": getattr(request, 'generation_mode', 'auto'),
    })

