"""
Tests for threat scoring.
"""

import pytest
from backend.scoring.scorer import (
    normalize_anomaly_score,
    compute_feature_deviation_score,
    compute_threat_score,
)


class TestScoreNormalization:
    def test_normal_score_maps_low(self):
        """Positive raw scores (normal) should map to low threat scores."""
        score = normalize_anomaly_score(0.3)
        assert 0 <= score <= 30

    def test_anomaly_score_maps_high(self):
        """Negative raw scores (anomalous) should map to high threat scores."""
        score = normalize_anomaly_score(-0.3)
        assert 70 <= score <= 100

    def test_boundary_score(self):
        """Score at 0 should be around 50."""
        score = normalize_anomaly_score(0.0)
        assert 45 <= score <= 55

    def test_output_range(self):
        """Scores must always be in [0, 100]."""
        for raw in [-1.0, -0.5, -0.1, 0, 0.1, 0.5, 1.0]:
            score = normalize_anomaly_score(raw)
            assert 0 <= score <= 100


class TestFeatureDeviationScore:
    def test_no_baseline_returns_zero(self):
        score, devs = compute_feature_deviation_score({}, {})
        assert score == 0.0
        assert devs == []

    def test_identical_to_baseline(self):
        baseline = {
            "packet_count": {"mean": 100, "std": 10},
            "mean_packet_size": {"mean": 400, "std": 50},
        }
        features = {"packet_count": 100, "mean_packet_size": 400}
        score, devs = compute_feature_deviation_score(features, baseline)
        assert score < 10  # very low deviation

    def test_large_deviation_scores_high(self):
        baseline = {
            "packets_per_second": {"mean": 100, "std": 10},
            "bytes_per_second": {"mean": 40000, "std": 5000},
        }
        features = {
            "packets_per_second": 1000,  # 90 standard deviations
            "bytes_per_second": 400000,  # 72 standard deviations
        }
        score, devs = compute_feature_deviation_score(features, baseline)
        assert score > 80  # high deviation


class TestThreatScore:
    def test_full_scoring_pipeline(self):
        baseline = {
            "packets_per_second": {"mean": 100, "std": 10, "min": 50, "max": 150, "median": 100},
        }
        features = {"packets_per_second": 500}
        category_result = {
            "label": "Volumetric Anomaly (DDoS-like)",
            "severity_boost": 1.2,
        }
        result = compute_threat_score(-0.3, features, baseline, category_result)

        assert 0 <= result["threat_score"] <= 100
        assert result["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert 0 <= result["confidence"] <= 1
        assert "components" in result

    def test_severity_mapping(self):
        """Test that severity labels map correctly to score ranges."""
        baseline = {"x": {"mean": 0, "std": 1}}

        # Low score
        r1 = compute_threat_score(0.3, {"x": 0}, baseline, {"severity_boost": 0.5})
        assert r1["severity"] == "LOW"

        # High score
        r2 = compute_threat_score(-0.5, {"x": 100}, baseline, {"severity_boost": 1.3})
        assert r2["severity"] in ["HIGH", "CRITICAL"]
