"""
Model wrapper for phishing detection.

If a trained model file exists at models/phishing_model.joblib it is loaded.
Otherwise a rule-based heuristic is used as a fallback so the API can still
serve predictions before training.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict

import numpy as np

from backend.feature_extractor import extract_features

logger = logging.getLogger(__name__)

_MODEL_PATH = Path(__file__).parent.parent / "models" / "phishing_model.joblib"

# Default classification thresholds
_DEFAULT_THRESHOLDS: Dict[str, float] = {
    "phishing": 0.6,    # confidence >= this → phishing
    "suspicious": 0.4,  # confidence >= this → suspicious (else safe)
}


class PhishingModel:
    """Load and serve the phishing detection model."""

    def __init__(self) -> None:
        self.model: Any = None
        self.is_loaded: bool = False
        self.thresholds: Dict[str, float] = dict(_DEFAULT_THRESHOLDS)
        self._try_load()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _try_load(self) -> None:
        try:
            import joblib  # type: ignore

            if _MODEL_PATH.exists():
                self.model = joblib.load(_MODEL_PATH)
                self.is_loaded = True
                logger.info("Model loaded from %s", _MODEL_PATH)
            else:
                logger.warning(
                    "Model file not found at %s — using heuristic fallback.",
                    _MODEL_PATH,
                )
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to load model: %s", exc)

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------

    def predict(self, url: str) -> Dict[str, Any]:
        """Return prediction dict for *url*."""
        features = extract_features(url)
        feature_values = list(features.values())

        if self.is_loaded:
            confidence = self._model_predict(feature_values)
        else:
            confidence = self._heuristic_predict(features)

        is_phishing = confidence >= self.thresholds["phishing"]
        if confidence >= self.thresholds["phishing"]:
            verdict = "phishing"
        elif confidence >= self.thresholds["suspicious"]:
            verdict = "suspicious"
        else:
            verdict = "safe"

        return {
            "url": url,
            "is_phishing": is_phishing,
            "confidence": round(float(confidence), 4),
            "verdict": verdict,
            "features": features,
        }

    def _model_predict(self, feature_values: list) -> float:
        """Use loaded sklearn model to get phishing probability."""
        X = np.array(feature_values).reshape(1, -1)
        if hasattr(self.model, "predict_proba"):
            prob = self.model.predict_proba(X)[0]
            # Assume class index 1 = phishing
            return float(prob[1])
        # Hard prediction fallback
        return float(self.model.predict(X)[0])

    # ------------------------------------------------------------------
    # Heuristic fallback (no model required)
    # ------------------------------------------------------------------

    @staticmethod
    def _heuristic_predict(features: Dict[str, Any]) -> float:
        """
        Simple rule-based score when no trained model is available.
        Score ∈ [0, 1].
        """
        score = 0.0

        if features["has_ip"]:
            score += 0.35
        if features["has_at"]:
            score += 0.20
        if features["is_suspicious_tld"]:
            score += 0.20
        if not features["is_https"]:
            score += 0.10
        if features["brand_in_subdomain"] and not features["brand_in_domain"]:
            score += 0.25
        # Brand name inside the domain itself + suspicious TLD = strong phishing signal
        if features["brand_in_domain"] and features["is_suspicious_tld"]:
            score += 0.30
        # Brand in domain but served over plain HTTP
        elif features["brand_in_domain"] and not features["is_https"]:
            score += 0.15
        if features["has_punycode"]:
            score += 0.20
        if features["url_length"] > 100:
            score += 0.10
        if features["hyphen_count"] > 4:
            score += 0.10
        if features["subdomain_depth"] >= 3:
            score += 0.10
        if features["domain_entropy"] > 3.5:
            score += 0.10
        if features["redirect_count"] > 0:
            score += 0.10

        return min(score, 1.0)
