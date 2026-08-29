"""
CampusShield AI — Isolation Forest Anomaly Detector
=====================================================
Unsupervised anomaly detection using sklearn's Isolation Forest.

DESIGN NOTE:
    This module ONLY answers "is this traffic window anomalous?"
    It never answers "what type of attack is this?" — that's the
    categorizer's job (backend.classification.categorizer).

    Separation of concerns:
        Detector → anomaly yes/no + raw score
        Categorizer → threat category label
        Scorer → normalized 0-100 threat score
        Explainer → human-readable contributing factors
"""

import logging
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest

from backend.config import (
    DEFAULT_CONTAMINATION,
    DEFAULT_N_ESTIMATORS,
    DEFAULT_RANDOM_STATE,
    MODEL_DIR,
)
from backend.features.extractor import FEATURE_NAMES

logger = logging.getLogger(__name__)

MODEL_PATH = MODEL_DIR / "isolation_forest.joblib"


class AnomalyDetector:
    """
    Wrapper around sklearn IsolationForest with:
    - Configurable contamination (sensitivity control)
    - Model persistence (save/load)
    - Score normalization
    """

    def __init__(
        self,
        contamination: float = DEFAULT_CONTAMINATION,
        n_estimators: int = DEFAULT_N_ESTIMATORS,
        random_state: int = DEFAULT_RANDOM_STATE,
    ):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model: Optional[IsolationForest] = None
        self._is_trained = False

    @property
    def is_trained(self) -> bool:
        return self._is_trained

    def train(self, features_df: pd.DataFrame) -> dict:
        """
        Fit the Isolation Forest on feature data.

        Args:
            features_df: DataFrame with FEATURE_NAMES columns.
                         Should represent 'normal' baseline traffic.

        Returns:
            Training summary dict with stats.
        """
        if features_df.empty:
            raise ValueError("Cannot train on empty feature set")

        n_samples = len(features_df)
        logger.info(
            f"Training IsolationForest: {n_samples} samples, "
            f"contamination={self.contamination}, "
            f"n_estimators={self.n_estimators}"
        )

        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=-1,  # use all cores
            max_samples="auto",
            bootstrap=False,
        )

        X = features_df[FEATURE_NAMES].values
        self.model.fit(X)
        self._is_trained = True

        # Compute training statistics
        train_scores = self.model.decision_function(X)
        train_labels = self.model.predict(X)
        n_anomalies = int(np.sum(train_labels == -1))

        summary = {
            "n_samples": n_samples,
            "n_features": len(FEATURE_NAMES),
            "n_estimators": self.n_estimators,
            "contamination": self.contamination,
            "n_anomalies_in_training": n_anomalies,
            "anomaly_ratio": n_anomalies / n_samples if n_samples > 0 else 0,
            "score_mean": float(np.mean(train_scores)),
            "score_std": float(np.std(train_scores)),
            "score_min": float(np.min(train_scores)),
            "score_max": float(np.max(train_scores)),
        }

        logger.info(
            f"Training complete: {n_anomalies}/{n_samples} anomalies "
            f"({summary['anomaly_ratio']:.2%})"
        )
        return summary

    def predict(self, features_df: pd.DataFrame) -> dict:
        """
        Run anomaly detection on new data.

        Args:
            features_df: DataFrame with FEATURE_NAMES columns.

        Returns:
            Dict with:
                labels: array of 1 (normal) or -1 (anomaly)
                scores: raw decision function scores (negative = more anomalous)
                anomaly_mask: boolean array (True = anomaly)
        """
        if not self._is_trained:
            raise RuntimeError("Model not trained — call train() first")

        X = features_df[FEATURE_NAMES].values
        labels = self.model.predict(X)
        scores = self.model.decision_function(X)

        return {
            "labels": labels,
            "scores": scores,
            "anomaly_mask": labels == -1,
        }

    def decision_function(self, features_df: pd.DataFrame) -> np.ndarray:
        """
        Raw anomaly scores. More negative = more anomalous.
        Useful for fine-grained ranking.
        """
        if not self._is_trained:
            raise RuntimeError("Model not trained")
        return self.model.decision_function(features_df[FEATURE_NAMES].values)

    def save(self, path: Optional[Path] = None) -> Path:
        """Persist trained model to disk."""
        if not self._is_trained:
            raise RuntimeError("Cannot save untrained model")

        save_path = path or MODEL_PATH
        save_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "contamination": self.contamination,
                "n_estimators": self.n_estimators,
                "random_state": self.random_state,
            },
            save_path,
        )
        logger.info(f"Saved model to {save_path}")
        return save_path

    def load(self, path: Optional[Path] = None) -> "AnomalyDetector":
        """Load a previously trained model from disk."""
        load_path = path or MODEL_PATH
        if not load_path.exists():
            raise FileNotFoundError(f"No saved model at {load_path}")

        data = joblib.load(load_path)
        self.model = data["model"]
        self.contamination = data["contamination"]
        self.n_estimators = data["n_estimators"]
        self.random_state = data["random_state"]
        self._is_trained = True

        logger.info(f"Loaded model from {load_path}")
        return self

    def update_contamination(self, new_contamination: float) -> None:
        """
        Update the contamination parameter.
        NOTE: This does NOT retrain the model — it only affects the
        threshold for new predictions via predict(). The underlying
        model's trees are unchanged.
        """
        if not 0.0 < new_contamination < 0.5:
            raise ValueError("Contamination must be between 0 and 0.5")
        self.contamination = new_contamination
        if self.model is not None:
            self.model.set_params(contamination=new_contamination)
        logger.info(f"Updated contamination to {new_contamination}")


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_detector = AnomalyDetector()


def get_detector() -> AnomalyDetector:
    """Get the module-level detector, loading from disk if available."""
    global _detector
    if not _detector.is_trained and MODEL_PATH.exists():
        _detector.load()
    return _detector
