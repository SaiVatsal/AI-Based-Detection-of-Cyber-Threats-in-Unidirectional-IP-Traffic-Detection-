"""
CampusShield AI — Threat Scorer
=================================
Converts raw anomaly scores and feature deviations into a
normalized 0-100 threat score with severity mapping.
"""

import logging
import math

import numpy as np

from backend.config import SEVERITY_THRESHOLDS, SCORE_WEIGHTS

logger = logging.getLogger(__name__)


def normalize_anomaly_score(raw_score: float) -> float:
    """
    Convert Isolation Forest's raw decision_function output
    (typically in range [-0.5, 0.5], more negative = more anomalous)
    to a 0-100 scale where higher = more threatening.

    Uses a sigmoid-like mapping centered around the decision boundary (0).
    """
    # Invert: raw score is negative for anomalies, we want positive
    inverted = -raw_score

    # Sigmoid mapping to [0, 100]
    # Tuned so that score=0 → 50, score=-0.3 → ~80, score=0.3 → ~20
    scaled = 1 / (1 + math.exp(-10 * inverted))
    return round(scaled * 100, 2)


def compute_feature_deviation_score(
    features: dict,
    baseline_stats: dict,
) -> tuple[float, list[dict]]:
    """
    Compute a deviation score based on how far each feature is
    from the baseline mean, measured in standard deviations.

    Returns:
        (deviation_score, deviations_list)
        deviation_score: 0-100 scale
        deviations_list: sorted list of per-feature deviations
    """
    if not baseline_stats:
        return 0.0, []

    deviations = []

    for feature_name, observed_value in features.items():
        if feature_name not in baseline_stats:
            continue
        if feature_name in ("window_index", "window_start", "window_end", "window_packet_count"):
            continue

        stats = baseline_stats[feature_name]
        baseline_mean = stats.get("mean", 0)
        baseline_std = stats.get("std", 0)

        if baseline_std == 0:
            # If baseline has zero variance, any deviation is significant
            if observed_value != baseline_mean and baseline_mean != 0:
                z_score = abs(observed_value - baseline_mean) / max(abs(baseline_mean), 1e-6)
                z_score = min(z_score, 10.0)  # cap at 10
            else:
                z_score = 0.0
        else:
            z_score = abs(observed_value - baseline_mean) / baseline_std

        deviation_pct = 0.0
        if baseline_mean != 0:
            deviation_pct = ((observed_value - baseline_mean) / abs(baseline_mean)) * 100

        direction = "above" if observed_value > baseline_mean else "below"

        deviations.append({
            "feature_name": feature_name,
            "observed_value": float(observed_value),
            "baseline_mean": float(baseline_mean),
            "baseline_std": float(baseline_std),
            "z_score": float(z_score),
            "deviation_pct": float(deviation_pct),
            "direction": direction,
        })

    # Sort by z-score (highest deviation first)
    deviations.sort(key=lambda d: d["z_score"], reverse=True)

    # Compute aggregate deviation score
    if deviations:
        # Use top-5 deviating features for robustness
        top_z = [d["z_score"] for d in deviations[:5]]
        mean_z = np.mean(top_z)
        # Map mean z-score to 0-100 via sigmoid
        # z=0 → 0, z=2 → ~50, z=5 → ~90
        deviation_score = (1 / (1 + math.exp(-1.0 * (mean_z - 2.5)))) * 100
    else:
        deviation_score = 0.0

    return round(deviation_score, 2), deviations


def compute_threat_score(
    raw_anomaly_score: float,
    features: dict,
    baseline_stats: dict,
    category_result: dict,
) -> dict:
    """
    Compute the final weighted threat score from three components:
    1. Anomaly score magnitude (40% weight)
    2. Feature deviation from baseline (40% weight)
    3. Category-specific booster (20% weight)

    Args:
        raw_anomaly_score: From IsolationForest.decision_function()
        features: Feature dict for this window
        baseline_stats: Baseline statistics from normal traffic
        category_result: Output from ThreatCategorizer.categorize()

    Returns:
        Dict with threat_score, severity, confidence, component breakdown
    """
    # Component 1: Anomaly score (normalized 0-100)
    anomaly_component = normalize_anomaly_score(raw_anomaly_score)

    # Component 2: Feature deviation (0-100)
    deviation_component, deviations = compute_feature_deviation_score(
        features, baseline_stats
    )

    # Component 3: Category boost (multiplier on base score)
    severity_boost = category_result.get("severity_boost", 1.0)
    # Convert boost multiplier to 0-100 scale
    # boost=1.0 → 50, boost=1.3 → 65, boost=0.7 → 35
    category_component = min(100, severity_boost * 50)

    # Weighted combination
    weights = SCORE_WEIGHTS
    raw_score = (
        anomaly_component * weights["anomaly_score"]
        + deviation_component * weights["feature_deviation"]
        + category_component * weights["category_boost"]
    )

    # Clamp to [0, 100]
    threat_score = max(0, min(100, round(raw_score, 2)))

    # Determine severity
    severity = "LOW"
    for sev_label, (low, high) in SEVERITY_THRESHOLDS.items():
        if low <= threat_score <= high:
            severity = sev_label
            break

    # Confidence: higher when multiple features deviate consistently
    if deviations:
        significant_devs = [d for d in deviations if d["z_score"] > 2.0]
        confidence = min(1.0, len(significant_devs) / 5.0)
        # Boost confidence if deviation and anomaly score agree
        if anomaly_component > 60 and deviation_component > 60:
            confidence = min(1.0, confidence + 0.2)
    else:
        confidence = 0.3  # low confidence without baseline

    return {
        "threat_score": threat_score,
        "severity": severity,
        "confidence": round(confidence, 3),
        "components": {
            "anomaly_score": round(anomaly_component, 2),
            "feature_deviation": round(deviation_component, 2),
            "category_boost": round(category_component, 2),
        },
        "weights": weights,
        "deviations": deviations,
    }
