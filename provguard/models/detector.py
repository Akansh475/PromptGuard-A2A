"""
Trained Machine Learning Model for Prompt Injection and Adversarial Intent Detection.
Wraps the serialized scikit-learn pipeline for low-latency inference in the MAS simulation.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional, Tuple

import joblib

logger = logging.getLogger("provguard.models.detector")

DEFAULT_MODEL_PATH = os.path.join(os.path.dirname(__file__), "artifacts", "injection_detector.joblib")


class TrainedInjectionDetector:
    """
    Inference wrapper for trained NLP Prompt Injection & Adversarial Intent Guardrail.
    Provides calibrated continuous risk probabilities P(injection | text) in [0.0, 1.0].
    """

    _instance: Optional["TrainedInjectionDetector"] = None

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.pipeline: Optional[Any] = None
        self.metadata: Dict[str, Any] = {}
        self.is_loaded = False
        self._load_model_if_exists()

    @classmethod
    def get_instance(cls, model_path: Optional[str] = None) -> "TrainedInjectionDetector":
        """Singleton accessor for efficient model caching in agent loops."""
        if cls._instance is None:
            cls._instance = TrainedInjectionDetector(model_path=model_path)
        return cls._instance

    def _load_model_if_exists(self) -> bool:
        """Loads serialized model artifact from disk if present."""
        if os.path.exists(self.model_path):
            try:
                data = joblib.load(self.model_path)
                if isinstance(data, dict) and "pipeline" in data:
                    self.pipeline = data["pipeline"]
                    self.metadata = data.get("metadata", {})
                else:
                    self.pipeline = data
                    self.metadata = {}
                self.is_loaded = True
                logger.info(f"Loaded trained injection detector from {self.model_path}")
                return True
            except Exception as e:
                logger.warning(f"Failed to load trained model from {self.model_path}: {e}")
                self.is_loaded = False
        return False

    def predict_probability(self, text: str) -> float:
        """
        Returns continuous calibrated probability that text is an adversarial injection.
        Returns 0.0 to 1.0. If model is not loaded, returns 0.0 with warning.
        """
        if not text or not text.strip():
            return 0.0

        if not self.is_loaded or self.pipeline is None:
            # Fallback or attempt lazy reload
            if not self._load_model_if_exists():
                return 0.0

        try:
            # Scikit-learn pipeline predict_proba: returns [[P(benign), P(adversarial)]]
            probs = self.pipeline.predict_proba([text])[0]
            # Class 1 is adversarial
            adv_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
            return min(1.0, max(0.0, adv_prob))
        except Exception as e:
            logger.error(f"Error during model inference: {e}")
            return 0.0

    def evaluate_payload(self, text: str, threshold: float = 0.50) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Evaluates payload text.
        Returns:
            (is_adversarial, probability, diagnostic_info)
        """
        prob = self.predict_probability(text)
        is_adv = prob >= threshold

        risk_level = "BENIGN"
        if prob >= 0.85:
            risk_level = "CRITICAL"
        elif prob >= 0.70:
            risk_level = "HIGH"
        elif prob >= 0.50:
            risk_level = "MEDIUM"
        elif prob >= 0.25:
            risk_level = "LOW"

        diagnostics = {
            "model_type": "Trained TF-IDF + LogisticRegression NLP Guardrail",
            "model_loaded": self.is_loaded,
            "adversarial_probability": round(prob, 4),
            "predicted_risk_level": risk_level,
            "threshold_used": threshold,
            "model_metadata": self.metadata,
        }
        return is_adv, prob, diagnostics
