from __future__ import annotations

import math
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class DecoderPattern:
    name: str
    parent: Optional[str]
    program_name: Optional[str]
    prematch: Optional[str]
    regex: Optional[str]
    order: List[str]
    source_file: str

    @property
    def feature_text(self) -> str:
        parts = [
            self.name or "",
            self.parent or "",
            self.program_name or "",
            self.prematch or "",
            self.regex or "",
            " ".join(self.order),
            self.source_file,
        ]
        return " ".join(part for part in parts if part).lower()


def _extract_tag(block: str, tag: str) -> Optional[str]:
    m = re.search(rf"<{tag}>(.*?)</{tag}>", block, flags=re.DOTALL | re.IGNORECASE)
    if not m:
        return None
    value = re.sub(r"\s+", " ", m.group(1)).strip()
    return value or None


def parse_decoder_file(xml_text: str, source_file: str) -> List[DecoderPattern]:
    blocks = re.findall(
        r"<decoder\s+name=['\"]([^'\"]+)['\"]\s*>(.*?)</decoder>",
        xml_text,
        flags=re.DOTALL | re.IGNORECASE,
    )
    patterns: List[DecoderPattern] = []
    for name, body in blocks:
        order_text = _extract_tag(body, "order") or ""
        order = [item.strip() for item in order_text.split(",") if item.strip()]
        patterns.append(
            DecoderPattern(
                name=name.strip(),
                parent=_extract_tag(body, "parent"),
                program_name=_extract_tag(body, "program_name"),
                prematch=_extract_tag(body, "prematch"),
                regex=_extract_tag(body, "regex"),
                order=order,
                source_file=source_file,
            )
        )
    return patterns


def tokenize(text: str) -> List[str]:
    return re.findall(r"[a-z0-9_.:/-]+", text.lower())


class DecoderSimilarityModel:
    def __init__(self, patterns: List[DecoderPattern]):
        self.patterns = patterns
        self.idf: Dict[str, float] = {}
        self.vectors: List[Dict[str, float]] = []
        self.norms: List[float] = []
        self._fit()

    def _fit(self) -> None:
        docs = [tokenize(p.feature_text) for p in self.patterns]
        df: Dict[str, int] = {}
        for terms in docs:
            for term in set(terms):
                df[term] = df.get(term, 0) + 1
        doc_count = max(1, len(docs))
        self.idf = {term: math.log((1 + doc_count) / (1 + freq)) + 1.0 for term, freq in df.items()}

        self.vectors = []
        self.norms = []
        for terms in docs:
            vec = self._vectorize_terms(terms)
            self.vectors.append(vec)
            self.norms.append(math.sqrt(sum(v * v for v in vec.values())) or 1.0)

    def _vectorize_terms(self, terms: List[str]) -> Dict[str, float]:
        tf: Dict[str, float] = {}
        for t in terms:
            tf[t] = tf.get(t, 0.0) + 1.0
        total = float(len(terms) or 1)
        vec: Dict[str, float] = {}
        for term, count in tf.items():
            if term not in self.idf:
                continue
            vec[term] = (count / total) * self.idf[term]
        return vec

    def suggest(self, query: str, top_k: int = 5) -> List[Tuple[DecoderPattern, float]]:
        q_vec = self._vectorize_terms(tokenize(query))
        q_norm = math.sqrt(sum(v * v for v in q_vec.values())) or 1.0
        scores: List[Tuple[DecoderPattern, float]] = []
        for idx, pattern in enumerate(self.patterns):
            dot = 0.0
            p_vec = self.vectors[idx]
            for term, q_val in q_vec.items():
                dot += q_val * p_vec.get(term, 0.0)
            score = dot / (q_norm * self.norms[idx])
            if score > 0:
                scores.append((pattern, score))
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:top_k]


def refresh_wazuh_repo(
    repo_url: str,
    cache_dir: Path,
    sparse_subpath: str,
    force: bool = False,
    branch: Optional[str] = None,
) -> Dict[str, str]:
    if cache_dir.exists() and force:
        shutil.rmtree(cache_dir, ignore_errors=True)

    if not cache_dir.exists():
        cmd = ["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse"]
        if branch:
            cmd.extend(["--branch", branch])
        cmd.extend([repo_url, str(cache_dir)])
        clone = subprocess.run(cmd, text=True, capture_output=True)
        if clone.returncode != 0:
            return {"ok": "false", "message": f"git clone failed: {clone.stderr.strip()}"}
        sparse = subprocess.run(
            ["git", "-C", str(cache_dir), "sparse-checkout", "set", sparse_subpath],
            text=True,
            capture_output=True,
        )
        if sparse.returncode != 0:
            return {"ok": "false", "message": f"sparse-checkout failed: {sparse.stderr.strip()}"}
        return {"ok": "true", "message": "cloned"}

    pull = subprocess.run(
        ["git", "-C", str(cache_dir), "pull", "--ff-only"],
        text=True,
        capture_output=True,
    )
    if pull.returncode != 0:
        return {"ok": "false", "message": f"git pull failed: {pull.stderr.strip()}"}
    return {"ok": "true", "message": "updated"}


def load_patterns_from_repo(cache_dir: Path, decoder_subpath: str) -> List[DecoderPattern]:
    decoder_dir = cache_dir / decoder_subpath
    if not decoder_dir.exists():
        return []
    patterns: List[DecoderPattern] = []
    for path in decoder_dir.rglob("*.xml"):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        patterns.extend(parse_decoder_file(text, str(path.relative_to(cache_dir))))
    return patterns


# ── Rule Pattern ML (trained from wazuh-ruleset rules) ──

# Wazuh static field tags that are direct children of <rule> (no <field name="..."> wrapper)
STATIC_FIELD_TAGS: frozenset = frozenset({
    "srcip", "dstip", "srcport", "dstport", "protocol", "action", "id",
    "url", "data", "extra_data", "status", "system_name", "user",
    "hostname", "program_name",
})


@dataclass
class RulePattern:
    rule_id: Optional[str]
    level: Optional[str]
    decoded_as: Optional[str]
    if_sid: Optional[str]
    regex: Optional[str]
    field_conditions: List[Dict[str, str]]
    static_conditions: List[Dict[str, str]]
    match_conditions: List[str]
    description: Optional[str]
    group: Optional[str]
    source_file: str

    @property
    def feature_text(self) -> str:
        parts = [
            self.description or "",
            self.decoded_as or "",
            self.regex or "",
            " ".join(fc.get("name", "") + "=" + fc.get("value", "") for fc in self.field_conditions),
            " ".join(sc.get("name", "") + "=" + sc.get("value", "") for sc in self.static_conditions),
            " ".join(self.match_conditions),
            self.group or "",
        ]
        return " ".join(part for part in parts if part).lower()


def parse_rule_file(xml_text: str, source_file: str) -> List[RulePattern]:
    """Parse rule XML file into RulePattern objects.
    Extracts <rule> blocks and their child tags: decoded_as, if_sid, regex, field, match, description, group.
    """
    group_match = re.search(r'<group\s+name=[\'"]([^\'"]+)[\'"]', xml_text, flags=re.IGNORECASE)
    group_name = group_match.group(1).strip() if group_match else None

    patterns: List[RulePattern] = []
    rule_blocks = re.findall(
        r'<rule\s+id=[\'"](\d+)[\'"]\s*(?:level=[\'"](\d+)[\'"])?\s*(.*?)</rule>',
        xml_text,
        flags=re.DOTALL | re.IGNORECASE,
    )
    for rule_id, level, body in rule_blocks:
        field_conditions: List[Dict[str, str]] = []
        for fm in re.finditer(r'<field\s+name=[\'"]([^\'"]+)[\'"][^>]*>(.*?)</field>', body, flags=re.DOTALL | re.IGNORECASE):
            field_conditions.append({"name": fm.group(1).strip(), "value": fm.group(2).strip()})
        match_conditions = re.findall(r'<match>(.*?)</match>', body, flags=re.DOTALL | re.IGNORECASE)
        match_conditions = [m.strip() for m in match_conditions if m.strip()]
        static_conditions: List[Dict[str, str]] = []
        for tag_name in STATIC_FIELD_TAGS:
            for sm in re.finditer(rf'<{re.escape(tag_name)}>(.*?)</{re.escape(tag_name)}>', body, flags=re.DOTALL | re.IGNORECASE):
                val = sm.group(1).strip()
                if val:
                    static_conditions.append({"name": tag_name, "value": val})

        patterns.append(RulePattern(
            rule_id=rule_id.strip(),
            level=level.strip() if level else None,
            decoded_as=_extract_tag(body, "decoded_as"),
            if_sid=_extract_tag(body, "if_sid"),
            regex=_extract_tag(body, "regex"),
            field_conditions=field_conditions,
            static_conditions=static_conditions,
            match_conditions=match_conditions,
            description=_extract_tag(body, "description"),
            group=group_name,
            source_file=source_file,
        ))
    return patterns


def load_rule_patterns_from_repo(cache_dir: Path, rules_subpath: str = "rules") -> List[RulePattern]:
    """Load all rule patterns from a wazuh-ruleset repo checkout."""
    rules_dir = cache_dir / rules_subpath
    if not rules_dir.exists():
        return []
    patterns: List[RulePattern] = []
    for path in rules_dir.rglob("*.xml"):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        patterns.extend(parse_rule_file(text, str(path.relative_to(cache_dir))))
    return patterns


class RuleSimilarityModel:
    """TF-IDF based similarity model for Wazuh rule patterns.
    Learns from real Wazuh rules to suggest rule templates based on user requirements.
    """

    def __init__(self, patterns: List[RulePattern]):
        self.patterns = patterns
        self.idf: Dict[str, float] = {}
        self.vectors: List[Dict[str, float]] = []
        self.norms: List[float] = []
        self._fit()

    def _fit(self) -> None:
        docs = [tokenize(p.feature_text) for p in self.patterns]
        df: Dict[str, int] = {}
        for terms in docs:
            for term in set(terms):
                df[term] = df.get(term, 0) + 1
        doc_count = max(1, len(docs))
        self.idf = {term: math.log((1 + doc_count) / (1 + freq)) + 1.0 for term, freq in df.items()}
        self.vectors = []
        self.norms = []
        for terms in docs:
            vec = self._vectorize_terms(terms)
            self.vectors.append(vec)
            self.norms.append(math.sqrt(sum(v * v for v in vec.values())) or 1.0)

    def _vectorize_terms(self, terms: List[str]) -> Dict[str, float]:
        tf: Dict[str, float] = {}
        for t in terms:
            tf[t] = tf.get(t, 0.0) + 1.0
        total = float(len(terms) or 1)
        vec: Dict[str, float] = {}
        for term, count in tf.items():
            if term not in self.idf:
                continue
            vec[term] = (count / total) * self.idf[term]
        return vec

    def suggest(self, query: str, top_k: int = 5) -> List[Tuple[RulePattern, float]]:
        q_vec = self._vectorize_terms(tokenize(query))
        q_norm = math.sqrt(sum(v * v for v in q_vec.values())) or 1.0
        scores: List[Tuple[RulePattern, float]] = []
        for idx, pattern in enumerate(self.patterns):
            dot = 0.0
            p_vec = self.vectors[idx]
            for term, q_val in q_vec.items():
                dot += q_val * p_vec.get(term, 0.0)
            score = dot / (q_norm * self.norms[idx])
            if score > 0:
                scores.append((pattern, score))
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:top_k]
