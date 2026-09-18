"""
Tests for ml/inference/predictor.py. Deliberately does NOT download or load
microsoft/deberta-v3-base — these tests verify the predictor's *contract*
(schema shape, honest unavailability reporting) using empty/missing model
directories, which is fast and required no network access.
"""
import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ml.inference.predictor import DebertaPredictor, PredictionResult


def test_predictor_reports_unavailable_for_missing_directory():
    predictor = DebertaPredictor(model_dir="/tmp/definitely_does_not_exist_mailscope_test")
    assert predictor.is_available is False
    result = predictor.predict("Subject", "Body text")
    assert isinstance(result, PredictionResult)
    assert result.available is False
    assert result.label == "not_available"
    assert result.probabilities == {}
    assert "No trained checkpoint" in result.reason


def test_predictor_reports_unavailable_for_empty_directory():
    with tempfile.TemporaryDirectory() as tmpdir:
        predictor = DebertaPredictor(model_dir=tmpdir)
        result = predictor.predict("Subject", "Body")
        assert result.available is False
        assert result.model_name == "not_available"


def test_predictor_never_fabricates_probabilities_when_unavailable():
    predictor = DebertaPredictor(model_dir="/tmp/also_does_not_exist_mailscope")
    result = predictor.predict(None, "Some suspicious sounding text about verifying your password")
    assert result.probabilities == {}
    assert result.label != "benign" and result.label != "suspicious"


def test_load_is_only_attempted_once_and_cached():
    predictor = DebertaPredictor(model_dir="/tmp/nonexistent_mailscope_cache_test")
    predictor.predict("a", "b")
    assert predictor._load_attempted is True
    reason_first = predictor._unavailable_reason
    predictor.predict("c", "d")
    # Second call must not re-derive a different reason (i.e. it used the cached state).
    assert predictor._unavailable_reason == reason_first
