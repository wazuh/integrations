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
