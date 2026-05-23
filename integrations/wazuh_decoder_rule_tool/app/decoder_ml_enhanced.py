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


@dataclass
class EnhancedDecoderPattern(DecoderPattern):
    """Extended decoder pattern with enhanced features"""
    enhanced_feature_text: str = ""
    
    def __post_init__(self):
        # Create enhanced feature text with weighted components
        super_init = super().__post_init__() if hasattr(super(), '__post_init__') else None
        
        # Weight different components for better discrimination
        name_weight = 3.0
        program_weight = 2.0
        prematch_weight = 2.5
        regex_weight = 3.0
        order_weight = 1.5
        
        parts = []
        if self.name:
            parts.extend([self.name] * int(name_weight))
        if self.program_name:
            parts.extend([self.program_name] * int(program_weight))
        if self.prematch:
            parts.extend([self.prematch] * int(prematch_weight))
        if self.regex:
            # Extract meaningful tokens from regex
            regex_tokens = re.findall(r'\[\\w\+\\]|\\\\d\+|\\\\S\+|\\\\w\+', self.regex)
            parts.extend(regex_tokens * int(regex_weight))
        if self.order:
            parts.extend(self.order * int(order_weight))
        if self.source_file:
            # Add source file context
            parts.append(self.source_file)
            
        self.enhanced_feature_text = " ".join(parts).lower()


class EnsembleDecoderSimilarityModel:
    """
    Ensemble model combining TF-IDF and SBERT for superior accuracy
    Target: 100% accuracy through complementary strengths
    """
    
    def __init__(self, patterns: List[DecoderPattern]):
        self.original_patterns = patterns
        self.enhanced_patterns = [
            EnhancedDecoderPattern(
                p.name, p.parent, p.program_name, p.prematch, 
                p.regex, p.order, p.source_file
            ) for p in patterns
        ]
        
        self.tfidf_vectorizer = None
        self.tfidf_matrix = None
        self.sbert_model = None
        self.sbert_embeddings = None
        self.pattern_norms = None
        
        self._fit()
    
    def _fit(self) -> None:
        """Fit both TF-IDF and SBERT components"""
        # Prepare enhanced feature texts
        feature_texts = [p.enhanced_feature_text for p in self.enhanced_patterns]
        
        # TF-IDF component (excellent for exact token matching)
        if _ADVANCED_ML_AVAILABLE:
            self.tfidf_vectorizer = TfidfVectorizer(
                tokenizer=self._enhanced_tokenize,
                token_pattern=None,
                lowercase=False,
                ngram_range=(1, 2),
                max_features=5000
            )
            self.tfidf_matrix = self.tfidf_vectorizer.fit_transform(feature_texts)
        
        # SBERT component (excellent for semantic similarity)
        self._load_sbert_model()
        if self.sbert_model and _ADVANCED_ML_AVAILABLE:
            self.sbert_embeddings = self.sbert_model.encode(
                feature_texts, 
                convert_to_numpy=True,
                normalize_embeddings=True
            )
    
    def _enhanced_tokenize(self, text: str) -> List[str]:
        """Enhanced tokenization preserving important patterns"""
        # Keep important regex patterns as tokens
        tokens = re.findall(r'\[\\w\+\\]|\\\\d\+|\\\\S\+|\\\\w\+|\\\\[pt]|[a-z0-9_.:/-]+', text.lower())
        return tokens
    
    def _load_sbert_model(self) -> None:
        """Load SBERT model if available"""
        if not _ADVANCED_ML_AVAILABLE:
            return
            
        try:
            # Try to load custom trained model first
            from app.main import ML_MODEL_DIR
            if ML_MODEL_DIR.exists():
                self.sbert_model = SentenceTransformer(str(ML_MODEL_DIR))
            else:
                # Fallback to general purpose model
                self.sbert_model = SentenceTransformer('all-MiniLM-L6-v2')
        except Exception:
            self.sbert_model = None
    
    def suggest(
        self, 
        query: str, 
        top_k: int = 5,
        tfidf_weight: float = 0.4,
        sbert_weight: float = 0.6
    ) -> List[Tuple[DecoderPattern, float]]:
        """
        Ensemble suggestion combining TF-IDF and SBERT
        Weights can be tuned for optimal performance
        """
        if not self.enhanced_patterns:
            return []
        
        # Prepare query
        enhanced_query = self._create_enhanced_query(query)
        query_tokens = self._enhanced_tokenize(enhanced_query)
        
        scores = []
        
        # TF-IDF scoring
        tfidf_scores = np.zeros(len(self.enhanced_patterns))
        if _ADVANCED_ML_AVAILABLE and self.tfidf_vectorizer is not None:
            try:
                query_tfidf = self.tfidf_vectorizer.transform([" ".join(query_tokens)])
                tfidf_scores = cosine_similarity(query_tfidf, self.tfidf_matrix).flatten()
            except Exception:
                tfidf_scores = np.zeros(len(self.enhanced_patterns))
        
        # SBERT scoring
        sbert_scores = np.zeros(len(self.enhanced_patterns))
        if _ADVANCED_ML_AVAILABLE and self.sbert_model is not None:
            try:
                query_embedding = self.sbert_model.encode(
                    [enhanced_query], 
                    convert_to_numpy=True,
                    normalize_embeddings=True
                )
                sbert_scores = np.dot(query_embedding, self.sbert_embeddings.T).flatten()
            except Exception:
                sbert_scores = np.zeros(len(self.enhanced_patterns))
        
        # Combine scores with weights
        combined_scores = (tfidf_weight * tfidf_scores) + (sbert_weight * sbert_scores)
        
        # Get top-k results
        top_indices = np.argsort(combined_scores)[::-1][:top_k]
        
        results = []
        for idx in top_indices:
            if combined_scores[idx] > 0.01:  # Minimum threshold
                pattern = self.original_patterns[idx]
                confidence = float(combined_scores[idx])
                results.append((pattern, confidence))
        
        return results
    
    def _create_enhanced_query(self, query: str) -> str:
        """Create enhanced query matching our feature engineering"""
        # Apply similar weighting as in feature creation
        parts = [query]
        
        # Extract potential program names, etc.
        words = query.split()
        if len(words) > 1:
            # Give extra weight to potential identifiers
            parts.extend(words)
        
        return " ".join(parts)


def create_ensemble_model(patterns: List[DecoderPattern]) -> EnsembleDecoderSimilarityModel:
    """Factory function to create ensemble model"""
    return EnsembleDecoderSimilarityModel(patterns)


# Backward compatibility wrapper
class BackwardCompatibleModelWrapper:
    """Wrapper to maintain backward compatibility with existing code"""
    
    def __init__(self, ensemble_model: EnsembleDecoderSimilarityModel):
        self.ensemble_model = ensemble_model
        self.patterns = ensemble_model.original_patterns
    
    def suggest(self, query: str, top_k: int = 5) -> List[Tuple[DecoderPattern, float]]:
        return self.ensemble_model.suggest(query, top_k=top_k)


def ensure_ml_model_enhanced(
    force_refresh: bool = False,
    use_ensemble: bool = True
) -> Any:
    """
    Enhanced version of ensure_ml_model that can use ensemble approach
    """
    from app.main import (
        _ML_MODEL, _ML_MODEL_ERROR, _ML_PATTERN_COUNT,
        refresh_wazuh_repo, load_patterns_from_repo,
        WAZUH_REPO_URL, WAZUH_REPO_CACHE_DIR, 
        WAZUH_REPO_DECODER_SUBPATH, BASE_DIR
    )
    
    global _ML_MODEL, _ML_MODEL_ERROR, _ML_PATTERN_COUNT
    
    # Refresh logic remains the same
    if force_refresh or _ML_MODEL is None:
        print("INFO:     (Enhanced) Loading/refreshing ML model and patterns...")
        repo_result = refresh_wazuh_repo(
            WAZUH_REPO_URL,
            WAZUH_REPO_CACHE_DIR,
            WAZUH_REPO_DECODER_SUBPATH,
            force=force_refresh,
        )
        if repo_result.get("ok") != "true":
            _ML_MODEL_ERROR = repo_result.get("message", "Unknown error")
            _ML_MODEL = None
            _ML_PATTERN_COUNT = 0
            return _ML_MODEL
        
        patterns = load_patterns_from_repo(
            WAZUH_REPO_CACHE_DIR, 
            WAZUH_REPO_DECODER_SUBPATH
        )
        
        if not patterns:
            _ML_MODEL_ERROR = "No patterns loaded from Wazuh repo"
            _ML_MODEL = None
            _ML_PATTERN_COUNT = 0
            return _ML_MODEL
        
        # Use ensemble model if requested and available
        if use_ensemble and _ADVANCED_ML_AVAILABLE:
            try:
                ensemble_model = create_ensemble_model(patterns)
                _ML_MODEL = BackwardCompatibleModelWrapper(ensemble_model)
                _ML_MODEL_ERROR = ""
                _ML_PATTERN_COUNT = len(patterns)
                print(f"INFO:     ML patterns loaded: {_ML_PATTERN_COUNT} (Enhanced Ensemble)")
            except Exception as e:
                _ML_MODEL_ERROR = f"Ensemble model failed: {str(e)}, falling back to basic"
                # Fall back to basic model
                from app.decoder_ml import DecoderSimilarityModel
                _ML_MODEL = DecoderSimilarityModel(patterns)
                _ML_PATTERN_COUNT = len(patterns)
        else:
            # Use original model
            from app.decoder_ml import DecoderSimilarityModel
            _ML_MODEL = DecoderSimilarityModel(patterns)
            _ML_PATTERN_COUNT = len(patterns)
            _ML_MODEL_ERROR = ""
    
    return _ML_MODEL