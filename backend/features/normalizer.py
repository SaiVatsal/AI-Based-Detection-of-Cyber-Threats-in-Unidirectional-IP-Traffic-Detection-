"""
CampusShield AI — Feature Normalizer
======================================
StandardScaler wrapper with persistence for consistent
feature scaling between training and inference.
"""

import logging
from pathlib import Path
from typing import Optional
import pickle

import numpy as np
import pandas as pd

try:
    import joblib
except ImportError:
    class JoblibCompat:
        @staticmethod
        def dump(obj, filename):
            with open(filename, 'wb') as f:
                pickle.dump(obj, f)

        @staticmethod
        def load(filename):
            with open(filename, 'rb') as f:
                return pickle.load(f)

    joblib = JoblibCompat()

try:
    from sklearn.preprocessing import StandardScaler
except ImportError:
    class StandardScaler:
        def __init__(self):
            self.mean_ = None
            self.scale_ = None

        def fit(self, X):
            self.mean_ = np.mean(X, axis=0)
            self.scale_ = np.std(X, axis=0)
            self.scale_[self.scale_ == 0] = 1.0
            return self

        def transform(self, X):
            if self.mean_ is None:
                return X
            return (X - self.mean_) / self.scale_

        def fit_transform(self, X):
            return self.fit(X).transform(X)

        def inverse_transform(self, X):
            if self.mean_ is None:
                return X
            return (X * self.scale_) + self.mean_

from backend.config import MODEL_DIR
from backend.features.extractor import FEATURE_NAMES

logger = logging.getLogger(__name__)

SCALER_PATH = MODEL_DIR / "feature_scaler.joblib"


class FeatureNormalizer:
    """
    Wraps sklearn's StandardScaler with save/load and
    DataFrame-aware transform methods.
    """

    def __init__(self):
        self.scaler: Optional[StandardScaler] = None
        self._is_fitted = False

    @property
    def is_fitted(self) -> bool:
        return self._is_fitted

    def fit(self, df: pd.DataFrame) -> "FeatureNormalizer":
        """
        Fit the scaler on training data.

        Args:
            df: DataFrame with FEATURE_NAMES columns
        """
        if df.empty:
            raise ValueError("Cannot fit scaler on empty DataFrame")

        self.scaler = StandardScaler()
        self.scaler.fit(df[FEATURE_NAMES].values)
        self._is_fitted = True

        logger.info(
            f"Fitted normalizer on {len(df)} samples, "
            f"{len(FEATURE_NAMES)} features"
        )
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Transform features using the fitted scaler.
        Returns a new DataFrame with scaled values.
        """
        if not self._is_fitted:
            raise RuntimeError("Normalizer not fitted — call fit() first")

        scaled = self.scaler.transform(df[FEATURE_NAMES].values)
        return pd.DataFrame(scaled, columns=FEATURE_NAMES, index=df.index)

    def fit_transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Fit and transform in one call."""
        self.fit(df)
        return self.transform(df)

    def save(self, path: Optional[Path] = None) -> Path:
        """Persist the fitted scaler to disk."""
        if not self._is_fitted:
            raise RuntimeError("Cannot save unfitted normalizer")

        save_path = path or SCALER_PATH
        save_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.scaler, save_path)
        logger.info(f"Saved normalizer to {save_path}")
        return save_path

    def load(self, path: Optional[Path] = None) -> "FeatureNormalizer":
        """Load a previously fitted scaler from disk."""
        load_path = path or SCALER_PATH
        if not load_path.exists():
            raise FileNotFoundError(f"No saved normalizer at {load_path}")

        self.scaler = joblib.load(load_path)
        self._is_fitted = True
        logger.info(f"Loaded normalizer from {load_path}")
        return self

    def inverse_transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Convert scaled features back to original scale."""
        if not self._is_fitted:
            raise RuntimeError("Normalizer not fitted")

        original = self.scaler.inverse_transform(df[FEATURE_NAMES].values)
        return pd.DataFrame(original, columns=FEATURE_NAMES, index=df.index)


# ---------------------------------------------------------------------------
# Module-level singleton for convenience
# ---------------------------------------------------------------------------
_normalizer = FeatureNormalizer()


def get_normalizer() -> FeatureNormalizer:
    """
    Get the module-level normalizer, loading from disk if
    a saved scaler exists and the normalizer isn't fitted yet.
    """
    global _normalizer
    if not _normalizer.is_fitted and SCALER_PATH.exists():
        _normalizer.load()
    return _normalizer
