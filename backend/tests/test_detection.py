"""
Tests for Isolation Forest anomaly detection.
"""

import pytest
import time
import numpy as np
import pandas as pd

from backend.features.extractor import (
    extract_features_windowed,
    features_to_dataframe,
    FEATURE_NAMES,
)
from backend.detection.isolation_forest import AnomalyDetector
from backend.ingestion.traffic_simulator import simulate_normal, simulate_ddos


def _generate_normal_features(n_windows=50):
    """Generate feature DataFrame from normal traffic."""
    packets = simulate_normal(packet_count=n_windows * 20)
    windows = extract_features_windowed(packets, window_size=2.0)
    return features_to_dataframe(windows)


def _generate_attack_features(n_windows=50):
    """Generate feature DataFrame from DDoS traffic."""
    packets = simulate_ddos(packet_count=n_windows * 20)
    windows = extract_features_windowed(packets, window_size=2.0)
    return features_to_dataframe(windows)


class TestAnomalyDetector:
    def test_train_on_normal_data(self):
        detector = AnomalyDetector(contamination=0.05, n_estimators=50)
        df = _generate_normal_features()
        summary = detector.train(df)

        assert detector.is_trained
        assert summary["n_samples"] == len(df)
        assert summary["n_features"] == len(FEATURE_NAMES)
        assert 0 <= summary["anomaly_ratio"] <= 1

    def test_predict_returns_correct_shape(self):
        detector = AnomalyDetector(contamination=0.05, n_estimators=50)
        df = _generate_normal_features()
        detector.train(df)

        results = detector.predict(df)
        assert len(results["labels"]) == len(df)
        assert len(results["scores"]) == len(df)
        assert set(np.unique(results["labels"])).issubset({-1, 1})

    def test_attack_traffic_scores_lower(self):
        """Attack traffic should have more negative (anomalous) scores."""
        detector = AnomalyDetector(contamination=0.05, n_estimators=100)

        normal_df = _generate_normal_features(80)
        detector.train(normal_df)

        attack_df = _generate_attack_features(80)

        normal_scores = detector.decision_function(normal_df)
        attack_scores = detector.decision_function(attack_df)

        # Attack traffic should generally score lower (more negative)
        assert np.mean(attack_scores) < np.mean(normal_scores)

    def test_contamination_update(self):
        detector = AnomalyDetector(contamination=0.05)
        detector.update_contamination(0.1)
        assert detector.contamination == 0.1

    def test_invalid_contamination_raises(self):
        detector = AnomalyDetector()
        with pytest.raises(ValueError):
            detector.update_contamination(0.0)
        with pytest.raises(ValueError):
            detector.update_contamination(0.5)

    def test_predict_untrained_raises(self):
        detector = AnomalyDetector()
        df = pd.DataFrame(np.zeros((5, len(FEATURE_NAMES))), columns=FEATURE_NAMES)
        with pytest.raises(RuntimeError):
            detector.predict(df)

    def test_save_and_load(self, tmp_path):
        detector = AnomalyDetector(contamination=0.05, n_estimators=50)
        df = _generate_normal_features(30)
        detector.train(df)

        path = detector.save(tmp_path / "test_model.joblib")
        assert path.exists()

        new_detector = AnomalyDetector()
        new_detector.load(path)
        assert new_detector.is_trained
        assert new_detector.contamination == 0.05

        # Results should be identical
        scores1 = detector.decision_function(df)
        scores2 = new_detector.decision_function(df)
        np.testing.assert_array_almost_equal(scores1, scores2)
