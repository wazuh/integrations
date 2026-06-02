"""
Enhanced ensemble ML model for Wazuh decoder/rule similarity.

Improvements over v1:
  - Tuned weights: TF-IDF 0.3, SBERT 0.7 (semantic model is stronger for unseen formats)
  - Sigmoid-normalized confidence scores for well-calibrated probabilities
  - Log-type hinting: biases results toward JSON/Windows/syslog decoders
    based on detected log format before embedding comparison
  - Regex token overlap scoring: boosts patterns whose OS_Regex tokens
    overlap with tokens extracted from the query log
  - Minimum confidence gate raised to 0.15 (don't confuse LLM with low-confidence hits)
  - Graceful fallback to TF-IDF-only when SBERT is unavailable
"""

from __future__ import annotations

import math
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

import numpy as np

try:
    from sentence_transformers import SentenceTransformer
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    _ADVANCED_ML_AVAILABLE = True
except ImportError:
    _ADVANCED_ML_AVAILABLE = False

from app.decoder_ml import DecoderPattern


# ── Log-type detection ─────────────────────────────────────────────────────────

def _detect_log_type(log: str) -> str:
    """Return a rough log type label for boosting relevant decoders."""
    stripped = log.strip()
    if stripped.startswith("{") or stripped.startswith("[{"):
        return "json"
    if re.search(r"WinEvtLog|EventID|Sysmon|Windows", log, re.IGNORECASE):
        return "windows"
    if re.search(r"CEF:\d+\|", log):
        return "cef"
    if re.search(r"^\[UFW |kernel: \[UFW", log):
        return "ufw"
    if re.search(r"\bdhcpd\b|\bDHCPACK\b|\bDHCPDISCOVER\b", log, re.IGNORECASE):
        return "dhcp"
    if re.search(r"\bapache2?\b|\bhttpd\b|\bModSecurity\b", log, re.IGNORECASE):
        return "apache"
    if re.search(r"\bsshd\b", log):
        return "sshd"
    if re.search(r"\bsudo\b", log):
        return "sudo"
    if re.search(r'"GET |"POST |"PUT |"DELETE |HTTP/[12]', log):
        return "web"
    if re.search(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", stripped):
        return "iso8601"
    return "syslog"


_LOG_TYPE_HINTS: Dict[str, List[str]] = {
    "json": ["json"],
    "windows": ["windows", "winevtlog", "sysmon"],
    "apache": ["apache", "httpd", "modsecurity"],
    "sshd": ["sshd", "ssh"],
    "sudo": ["sudo"],
    "web": ["web-accesslog", "nginx", "apache"],
    "dhcp": ["dhcpd", "dhcp"],
    "cef": ["cef", "palo", "pan"],
    "ufw": ["ufw", "netfilter", "iptables"],
}


def _log_type_boost(pattern: DecoderPattern, log_type: str) -> float:
    """Return a small boost [0.0, 0.15] if the pattern matches the detected log type."""
    hints = _LOG_TYPE_HINTS.get(log_type, [])
    name_lower = (pattern.name or "").lower()
    src_lower = (pattern.source_file or "").lower()
    prog_lower = (pattern.program_name or "").lower()
    for hint in hints:
        if hint in name_lower or hint in src_lower or hint in prog_lower:
            return 0.12
    return 0.0


# ── Regex token overlap scoring ────────────────────────────────────────────────

_OS_REGEX_TOKENS_RE = re.compile(
    r"\\[wWdDsSp]|\\\.|\\t|\\n|"    # character classes
    r"\(\\.+?\)|"                    # capture groups
    r"[A-Za-z0-9_]{3,}",            # literal word fragments ≥3 chars
)


def _extract_regex_tokens(pattern_text: str) -> set:
    """Extract meaningful tokens from an OS_Regex or prematch string."""
    return set(_OS_REGEX_TOKENS_RE.findall(pattern_text.lower()))


def _log_literal_tokens(log: str) -> set:
    """Extract 3+-char word fragments from a raw log line."""
    return set(re.findall(r"[A-Za-z0-9_]{3,}", log.lower()))


def _regex_overlap_score(pattern: DecoderPattern, log_tokens: set) -> float:
    """Return an overlap fraction between pattern regex tokens and log literal tokens."""
    if not log_tokens:
        return 0.0
    pattern_tokens: set = set()
    for field in [pattern.prematch, pattern.regex, pattern.program_name]:
        if field:
            pattern_tokens |= _extract_regex_tokens(field)
    if not pattern_tokens:
        return 0.0
    overlap = pattern_tokens & log_tokens
    # Jaccard-like: overlap / union, capped at 0.2 contribution
    score = len(overlap) / max(len(pattern_tokens | log_tokens), 1)
    return min(score, 0.20)


# ── Confidence calibration ─────────────────────────────────────────────────────

def _sigmoid(x: float, scale: float = 8.0, shift: float = 0.4) -> float:
    """Sigmoid that maps [0,1] raw similarity to a calibrated [0,1] probability.
    Default scale/shift are tuned so that 0.4 raw → ~0.5 calibrated.
    """
    return 1.0 / (1.0 + math.exp(-scale * (x - shift)))


# ── Enhanced pattern ───────────────────────────────────────────────────────────

@dataclass
class EnhancedDecoderPattern(DecoderPattern):
    """Extended decoder pattern with weighted feature text for TF-IDF."""
    enhanced_feature_text: str = ""

    def __post_init__(self):
        name_weight = 3
        program_weight = 2
        prematch_weight = 2
        regex_weight = 3
        order_weight = 1

        parts: List[str] = []
        if self.name:
            parts.extend([self.name] * name_weight)
        if self.program_name:
            parts.extend([self.program_name] * program_weight)
        if self.prematch:
            parts.extend([self.prematch] * prematch_weight)
        if self.regex:
            regex_tokens = re.findall(r"\[\\w\+\\]|\\\\d\+|\\\\S\+|\\\\w\+", self.regex)
            parts.extend(regex_tokens * regex_weight)
            parts.append(self.regex)
        if self.order:
            parts.extend(self.order * order_weight)
        if self.source_file:
            parts.append(self.source_file)

        self.enhanced_feature_text = " ".join(parts).lower()


# ── Ensemble model ─────────────────────────────────────────────────────────────

class EnsembleDecoderSimilarityModel:
    """Ensemble of TF-IDF + SBERT for decoder suggestion.

    Score = 0.3 * tfidf + 0.7 * sbert + log_type_boost + regex_overlap
    Then sigmoid-calibrated to [0, 1].
    """

    TFIDF_WEIGHT: float = 0.3
    SBERT_WEIGHT: float = 0.7
    MIN_CONFIDENCE: float = 0.15  # gate: don't return results below this

    def __init__(self, patterns: List[DecoderPattern]):
        self.original_patterns = patterns
        self.enhanced_patterns = [
            EnhancedDecoderPattern(
                p.name, p.parent, p.program_name, p.prematch,
                p.regex, p.order, p.source_file
            )
            for p in patterns
        ]

        self.tfidf_vectorizer: Optional[Any] = None
        self.tfidf_matrix: Optional[Any] = None
        self.sbert_model: Optional[Any] = None
        self.sbert_embeddings: Optional[Any] = None

        self._fit()

    def _fit(self) -> None:
        feature_texts = [p.enhanced_feature_text for p in self.enhanced_patterns]

        if _ADVANCED_ML_AVAILABLE:
            self.tfidf_vectorizer = TfidfVectorizer(
                tokenizer=self._enhanced_tokenize,
                token_pattern=None,
                lowercase=False,
                ngram_range=(1, 2),
                max_features=8000,  # increased from 5000 for better vocabulary coverage
            )
            self.tfidf_matrix = self.tfidf_vectorizer.fit_transform(feature_texts)

        self._load_sbert_model()
        if self.sbert_model and _ADVANCED_ML_AVAILABLE:
            self.sbert_embeddings = self.sbert_model.encode(
                feature_texts,
                convert_to_numpy=True,
                normalize_embeddings=True,
                show_progress_bar=False,
            )

    def _enhanced_tokenize(self, text: str) -> List[str]:
        """Preserve OS_Regex patterns as whole tokens alongside word fragments."""
        tokens = re.findall(
            r"\[\\w\+\\]|\\\\d\+|\\\\S\+|\\\\w\+|\\\\[wWdDsSpPtTnN]|[a-z0-9_.:/|-]+",
            text.lower(),
        )
        return tokens

    def _load_sbert_model(self) -> None:
        if not _ADVANCED_ML_AVAILABLE:
            return
        try:
            # Try fine-tuned model first (final checkpoint from train_similarity.py)
            from app.main import ML_MODEL_DIR  # type: ignore
            final_path = Path(str(ML_MODEL_DIR)) / "final"
            if final_path.exists():
                self.sbert_model = SentenceTransformer(str(final_path))
                print(f"INFO: Loaded fine-tuned SBERT from {final_path}")
                return
            if Path(str(ML_MODEL_DIR)).exists():
                self.sbert_model = SentenceTransformer(str(ML_MODEL_DIR))
                print(f"INFO: Loaded SBERT from {ML_MODEL_DIR}")
                return
        except Exception:
            pass
        try:
            self.sbert_model = SentenceTransformer("all-MiniLM-L6-v2")
            print("INFO: Loaded base SBERT (all-MiniLM-L6-v2)")
        except Exception:
            self.sbert_model = None
            print("WARNING: SBERT model unavailable; using TF-IDF only")

    def suggest(
        self,
        query: str,
        top_k: int = 5,
        tfidf_weight: Optional[float] = None,
        sbert_weight: Optional[float] = None,
    ) -> List[Tuple[DecoderPattern, float]]:
        """Return top-k patterns with calibrated confidence scores."""
        if not self.enhanced_patterns:
            return []

        tw = tfidf_weight if tfidf_weight is not None else self.TFIDF_WEIGHT
        sw = sbert_weight if sbert_weight is not None else self.SBERT_WEIGHT

        log_type = _detect_log_type(query)
        log_tokens = _log_literal_tokens(query)
        enhanced_query = self._create_enhanced_query(query)

        n = len(self.enhanced_patterns)
        tfidf_scores = np.zeros(n)
        sbert_scores = np.zeros(n)

        # TF-IDF
        if _ADVANCED_ML_AVAILABLE and self.tfidf_vectorizer is not None:
            try:
                q_tokens = self._enhanced_tokenize(enhanced_query)
                q_vec = self.tfidf_vectorizer.transform([" ".join(q_tokens)])
                tfidf_scores = cosine_similarity(q_vec, self.tfidf_matrix).flatten()
            except Exception:
                pass

        # SBERT
        if _ADVANCED_ML_AVAILABLE and self.sbert_model is not None:
            try:
                q_emb = self.sbert_model.encode(
                    [enhanced_query],
                    convert_to_numpy=True,
                    normalize_embeddings=True,
                )
                sbert_scores = np.dot(q_emb, self.sbert_embeddings.T).flatten()
            except Exception:
                pass

        combined = tw * tfidf_scores + sw * sbert_scores

        # Per-pattern boosts: log-type hint + regex token overlap
        boost = np.array([
            _log_type_boost(p, log_type) + _regex_overlap_score(p, log_tokens)
            for p in self.original_patterns
        ])
        combined = combined + boost

        top_indices = np.argsort(combined)[::-1][:top_k]

        results: List[Tuple[DecoderPattern, float]] = []
        for idx in top_indices:
            raw_score = float(combined[idx])
            calibrated = _sigmoid(raw_score)
            if calibrated >= self.MIN_CONFIDENCE:
                results.append((self.original_patterns[idx], calibrated))

        return results

    def _create_enhanced_query(self, query: str) -> str:
        """Expand the query with repeated word tokens for TF-IDF weighting."""
        words = query.split()
        # Repeat non-numeric words to give them more TF weight
        emphasized = [w for w in words if re.search(r"[A-Za-z_]", w)]
        return " ".join([query] + emphasized[:20])  # cap to avoid huge vectors


def create_ensemble_model(patterns: List[DecoderPattern]) -> EnsembleDecoderSimilarityModel:
    """Factory function to create ensemble model."""
    return EnsembleDecoderSimilarityModel(patterns)


# ── Backward-compatibility wrapper ─────────────────────────────────────────────

class BackwardCompatibleModelWrapper:
    """Wraps EnsembleDecoderSimilarityModel to match the DecoderSimilarityModel API."""

    def __init__(self, ensemble_model: EnsembleDecoderSimilarityModel):
        self.ensemble_model = ensemble_model
        self.patterns = ensemble_model.original_patterns

    def suggest(self, query: str, top_k: int = 5) -> List[Tuple[DecoderPattern, float]]:
        return self.ensemble_model.suggest(query, top_k=top_k)


# ── ensure_ml_model_enhanced ───────────────────────────────────────────────────

def ensure_ml_model_enhanced(
    force_refresh: bool = False,
    use_ensemble: bool = True,
) -> Any:
    """Enhanced version of ensure_ml_model that uses the ensemble approach."""
    from app.main import (  # type: ignore
        refresh_wazuh_repo,
        load_patterns_from_repo,
        WAZUH_REPO_URL,
        WAZUH_REPO_CACHE_DIR,
        WAZUH_REPO_DECODER_SUBPATH,
        WAZUH_REPO_BRANCH,
        BASE_DIR,
    )
    import app.main as main_module  # type: ignore

    if force_refresh or main_module._ML_MODEL is None:
        print("INFO:     (Enhanced) Loading/refreshing ML model and patterns...")
        repo_result = refresh_wazuh_repo(
            WAZUH_REPO_URL,
            WAZUH_REPO_CACHE_DIR,
            WAZUH_REPO_DECODER_SUBPATH,
            force=force_refresh,
            branch=WAZUH_REPO_BRANCH,
        )
        if repo_result.get("ok") != "true":
            main_module._ML_MODEL_ERROR = repo_result.get("message", "Unknown error")
            main_module._ML_MODEL = None
            main_module._ML_PATTERN_COUNT = 0
            return main_module._ML_MODEL

        patterns = load_patterns_from_repo(
            WAZUH_REPO_CACHE_DIR,
            WAZUH_REPO_DECODER_SUBPATH,
        )

        if not patterns:
            main_module._ML_MODEL_ERROR = "No patterns loaded from Wazuh repo"
            main_module._ML_MODEL = None
            main_module._ML_PATTERN_COUNT = 0
            return main_module._ML_MODEL

        if use_ensemble and _ADVANCED_ML_AVAILABLE:
            try:
                ensemble_model = create_ensemble_model(patterns)
                main_module._ML_MODEL = BackwardCompatibleModelWrapper(ensemble_model)
                main_module._ML_MODEL_ERROR = ""
                main_module._ML_PATTERN_COUNT = len(patterns)
                model_type = "Enhanced Ensemble (TF-IDF 30% + SBERT 70%)"
                print(f"INFO:     ML patterns loaded: {main_module._ML_PATTERN_COUNT} [{model_type}]")
            except Exception as e:
                main_module._ML_MODEL_ERROR = f"Ensemble failed: {e!s}, falling back to basic"
                from app.decoder_ml import DecoderSimilarityModel
                main_module._ML_MODEL = DecoderSimilarityModel(patterns)
                main_module._ML_PATTERN_COUNT = len(patterns)
        else:
            from app.decoder_ml import DecoderSimilarityModel
            main_module._ML_MODEL = DecoderSimilarityModel(patterns)
            main_module._ML_PATTERN_COUNT = len(patterns)
            main_module._ML_MODEL_ERROR = ""

    return main_module._ML_MODEL