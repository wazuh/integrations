"""
Integration tests for ML enhancements in Wazuh decoder rule tool.
"""
import sys
import os
from pathlib import Path

# Add app directory to path for imports
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))
sys.path.append(str(BASE_DIR / "app"))

from app.decoder_ml_enhanced import ensure_ml_model_enhanced


def test_ensure_ml_model_enhanced():
    """Test that our enhanced model loader works."""
    model = ensure_ml_model_enhanced(force_refresh=False, use_ensemble=True)
    assert model is not None, "Model failed to load"
    assert hasattr(model, "suggest"), "Model is missing the suggest() method"
    assert callable(getattr(model, "suggest")), "suggest attribute is not callable"
    print("✓ ensure_ml_model_enhanced executed successfully")


if __name__ == "__main__":
    try:
        test_ensure_ml_model_enhanced()
        print("Integration test passed!")
    except AssertionError as e:
        print(f"Integration test failed! {e}")
        sys.exit(1)