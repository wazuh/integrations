"""
Tests for enhanced ML model integration in Wazuh decoder rule tool.
"""
import sys
import os
from pathlib import Path

# Add app directory to path for imports
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))
sys.path.append(str(BASE_DIR / "app"))

from app.decoder_ml_enhanced import (
    EnhancedDecoderPattern,
    EnsembleDecoderSimilarityModel,
    create_ensemble_model
)
from app.decoder_ml import DecoderPattern


def test_enhanced_decoder_pattern():
    """Test EnhancedDecoderPattern creation and feature text generation."""
    pattern = DecoderPattern(
        name="test_decoder",
        parent=None,
        program_name="test_program",
        prematch="test_prematch",
        regex=r"test\s+\d+",
        order=["field1", "field2"],
        source_file="test.xml"
    )
    
    enhanced = EnhancedDecoderPattern(
        name=pattern.name,
        parent=pattern.parent,
        program_name=pattern.program_name,
        prematch=pattern.prematch,
        regex=pattern.regex,
        order=pattern.order,
        source_file=pattern.source_file
    )
    
    # Check that enhanced feature text is created
    assert hasattr(enhanced, 'enhanced_feature_text')
    assert isinstance(enhanced.enhanced_feature_text, str)
    assert len(enhanced.enhanced_feature_text) > 0
    
    # Check that it contains expected components
    assert "test_decoder" in enhanced.enhanced_feature_text
    assert "test_program" in enhanced.enhanced_feature_text
    assert "test_prematch" in enhanced.enhanced_feature_text
    assert "field1" in enhanced.enhanced_feature_text
    assert "field2" in enhanced.enhanced_feature_text


def test_ensemble_model_creation():
    """Test creation of ensemble model from decoder patterns."""
    # Create sample patterns
    patterns = [
        DecoderPattern(
            name="ssh_login",
            parent=None,
            program_name="sshd",
            prematch="sshd",
            regex=r"Accepted password for \S+ from \S+ port \d+ ssh2",
            order=["username", "srcip", "port"],
            source_file="sshd.xml"
        ),
        DecoderPattern(
            name="sudo",
            parent=None,
            program_name="sudo",
            prematch=None,
            regex=r"sudo: .*? : TTY=.*) ; PWD=.*) ; USER=.*) ; COMMAND=.*)",
            order=["username", "tty", "pwd", "user", "command"],
            source_file="sudo.xml"
        )
    ]
    
    # Create ensemble model
    ensemble_model = EnsembleDecoderSimilarityModel(patterns)
    
    # Check that components are initialized
    assert ensemble_model.original_patterns == patterns
    assert len(ensemble_model.enhanced_patterns) == len(patterns)
    # Note: TF-IDF and SBERT availability depends on installed packages
    # We just check that the model object is created successfully
    assert ensemble_model is not None


def test_ensemble_model_suggest():
    """Test suggestion functionality of ensemble model."""
    patterns = [
        DecoderPattern(
            name="ssh_login",
            parent=None,
            program_name="sshd",
            prematch="sshd",
            regex=r"Accepted password for \S+ from \S+ port \d+ ssh2",
            order=["username", "srcip", "port"],
            source_file="sshd.xml"
        ),
        DecoderPattern(
            name="sudo",
            parent=None,
            program_name="sudo",
            prematch=None,
            regex=r"sudo: .*? : TTY=.*) ; PWD=.*) ; USER=.*) ; COMMAND=.*)",
            order=["username", "tty", "pwd", "user", "command"],
            source_file="sudo.xml"
        )
    ]
    
    ensemble_model = EnsembleDecoderSimilarityModel(patterns)
    
    # Test with SSH-related query
    suggestions = ensemble_model.suggest(
        query="Accepted password for admin from 192.168.1.1 port 22 ssh2",
        top_k=2
    )
    
    # Should return suggestions
    assert isinstance(suggestions, list)
    assert len(suggestions) <= 2
    
    # Check structure of suggestions
    if suggestions:
        pattern, score = suggestions[0]
        assert isinstance(pattern, DecoderPattern)
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0


def test_create_ensemble_model():
    """Test factory function for creating ensemble model."""
    patterns = [
        DecoderPattern(
            name="test1",
            parent=None,
            program_name="prog1",
            prematch="prematch1",
            regex=r"test\d+",
            order=["field1"],
            source_file="test1.xml"
        )
    ]
    
    model = create_ensemble_model(patterns)
    assert isinstance(model, EnsembleDecoderSimilarityModel)
    assert len(model.original_patterns) == 1


def test_backward_compatibility():
    """Test that enhanced model maintains backward compatibility."""
    from app.decoder_ml_enhanced import BackwardCompatibleModelWrapper
    
    patterns = [
        DecoderPattern(
            name="test_compat",
            parent=None,
            program_name="test_prog",
            prematch="test_prematch",
            regex=r"test\s+\w+",
            order=["field1", "field2"],
            source_file="compat.xml"
        )
    ]
    
    ensemble_model = EnsembleDecoderSimilarityModel(patterns)
    wrapper = BackwardCompatibleModelWrapper(ensemble_model)
    
    # Should have same interface as original model
    assert hasattr(wrapper, 'patterns')
    assert hasattr(wrapper, 'suggest')
    assert wrapper.patterns == patterns
    
    # Test suggest method
    suggestions = wrapper.suggest("test word", top_k=1)
    assert isinstance(suggestions, list)
    if suggestions:
        assert isinstance(suggestions[0], tuple)
        assert len(suggestions[0]) == 2
        assert isinstance(suggestions[0][0], DecoderPattern)
        assert isinstance(suggestions[0][1], float)


if __name__ == "__main__":
    # Run tests
    test_enhanced_decoder_pattern()
    print("✓ EnhancedDecoderPattern test passed")
    
    test_ensemble_model_creation()
    print("✓ Ensemble model creation test passed")
    
    test_ensemble_model_suggest()
    print("✓ Ensemble model suggest test passed")
    
    test_create_ensemble_model()
    print("✓ Create ensemble model test passed")
    
    test_backward_compatibility()
    print("✓ Backward compatibility test passed")
    
    print("\nAll tests passed! 🎉")