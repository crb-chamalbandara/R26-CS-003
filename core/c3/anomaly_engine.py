"""
C3 anomaly engine.

Loads an Isolation Forest model and normalizes anomaly scores to 0-1.
"""
from __future__ import annotations

import pickle
from pathlib import Path
from typing import Optional

import numpy as np

from .feature_engine import FEATURE_ORDER  # noqa: F401 — kept for collection pipeline

# 4 pure IAT timing features — the only features that are both:
#   (a) populated in the pcap-derived training data (c3_extracted_v2.csv), and
#   (b) have real signal range matching live browser traffic.
#
# requests_per_hour EXCLUDED: training data has synthetic RPH up to 3.3 billion.
#   Even after capping at 100k, 26% of benign rows cluster at exactly 100k,
#   making the model score real browser CDN traffic (rph ~36k) as BEACON.
# payload/HTTP/browser features EXCLUDED: all-zero in pcap training data.
#   Including them would make every real browser request anomalous.
ANOMALY_FEATURE_SUBSET = [
    "iat_mean_ms",
    "iat_cv",
    "iat_bowley_skewness",
    "iat_mad_ms",
]


class C3AnomalyEngine:
    def __init__(self) -> None:
        self._model = None
        self._cal_low: Optional[float] = None
        self._cal_high: Optional[float] = None
        self._model_path = Path(__file__).resolve().parents[2] / "models" / "c3_isolation_forest.pkl"
        self.reload()

    def reload(self) -> bool:
        self._model = None
        self._cal_low = None
        self._cal_high = None
        try:
            with open(self._model_path, "rb") as f:
                payload = pickle.load(f)
            model, low, high = self._unpack_payload(payload)
            if model is None:
                raise ValueError("missing model")
            self._model = model
            self._cal_low = low
            self._cal_high = high
            print("[C3] Isolation Forest model loaded")
            return True
        except FileNotFoundError:
            print("[C3] No Isolation Forest model found - anomaly score disabled")
        except Exception as exc:
            print(f"[C3] Could not load Isolation Forest model: {exc}")
        return False

    @property
    def model_loaded(self) -> bool:
        return self._model is not None

    @property
    def model_type(self) -> str:
        return "isolation_forest" if self.model_loaded else "heuristic-only"

    def score(self, features: dict) -> tuple[Optional[float], str]:
        if not self._model:
            return None, "no isolation forest model"
        if self._cal_low is None or self._cal_high is None:
            return None, "missing calibration bounds"
        if not hasattr(self._model, "score_samples"):
            return None, "model does not support score_samples"
        try:
            n_feats = len(ANOMALY_FEATURE_SUBSET)
            values = [float(features.get(name, 0.0)) for name in ANOMALY_FEATURE_SUBSET]
            nonzero = sum(1 for v in values if v != 0.0)
            if nonzero < 1:
                return None, "insufficient feature data (all features are zero)"
            X = np.array([values], dtype=float)
            raw = float(self._model.score_samples(X)[0])
            normalized = self._normalize(raw, self._cal_low, self._cal_high)
            return normalized, f"IF raw {raw:.4f} [{nonzero}/{n_feats} features active]"
        except Exception as exc:
            return None, f"anomaly score failed: {exc}"

    @staticmethod
    def _normalize(raw: float, low: float, high: float) -> float:
        if high == low:
            return 0.0
        scaled = (raw - low) / (high - low)
        scaled = max(0.0, min(1.0, scaled))
        return round(1.0 - scaled, 6)

    @staticmethod
    def _unpack_payload(payload) -> tuple[object | None, Optional[float], Optional[float]]:
        if isinstance(payload, dict):
            model = payload.get("model") or payload.get("estimator") or payload.get("iforest")
            low = payload.get("calibration_low") or payload.get("low") or payload.get("p5")
            high = payload.get("calibration_high") or payload.get("high") or payload.get("p95")
            return model, _to_float(low), _to_float(high)
        if isinstance(payload, (list, tuple)) and len(payload) == 3:
            model, low, high = payload
            return model, _to_float(low), _to_float(high)
        return payload, None, None


def _to_float(value) -> Optional[float]:
    try:
        if value is None:
            return None
        return float(value)
    except Exception:
        return None


c3_anomaly_engine = C3AnomalyEngine()


# Browser-context features — complementary to the timing model above.
# Requires live browser session data from C3 collection mode.
# Train with: train_c3_browser.bat
BROWSER_FEATURE_SUBSET = [
    "avg_idle_time_ms",
    "user_active_ratio",
    "background_tab_ratio",
    "url_path_entropy",
]


class C3BrowserAnomalyEngine:
    def __init__(self) -> None:
        self._model = None
        self._cal_low: Optional[float] = None
        self._cal_high: Optional[float] = None
        self._model_path = Path(__file__).resolve().parents[2] / "models" / "c3_browser_context_forest.pkl"
        self.reload()

    def reload(self) -> bool:
        self._model = None
        self._cal_low = None
        self._cal_high = None
        try:
            with open(self._model_path, "rb") as f:
                payload = pickle.load(f)
            model, low, high = C3AnomalyEngine._unpack_payload(payload)
            if model is None:
                raise ValueError("missing model")
            self._model = model
            self._cal_low = low
            self._cal_high = high
            print("[C3] Browser Context model loaded")
            return True
        except FileNotFoundError:
            print("[C3] No Browser Context model — run train_c3_browser.bat to train")
        except Exception as exc:
            print(f"[C3] Could not load Browser Context model: {exc}")
        return False

    @property
    def model_loaded(self) -> bool:
        return self._model is not None

    def score(self, features: dict) -> tuple[Optional[float], str]:
        if not self._model:
            return None, "browser context model not loaded"
        if self._cal_low is None or self._cal_high is None:
            return None, "missing calibration bounds"
        try:
            values = [float(features.get(name, 0.0)) for name in BROWSER_FEATURE_SUBSET]
            X = np.array([values], dtype=float)
            raw = float(self._model.score_samples(X)[0])
            normalized = C3AnomalyEngine._normalize(raw, self._cal_low, self._cal_high)
            return normalized, f"browser-IF raw {raw:.4f}"
        except Exception as exc:
            return None, f"browser anomaly score failed: {exc}"


# ── RF Classifier engine (HTTP behavior, Model 2) ──────────────────────────────

# 10 server-log-derivable features — complement to the 4 IAT timing features
# above.  Trained on labeled human/bot sessions from web_bot_detection_dataset.
# Keep in sync with RF_FEATURE_SUBSET in scripts/train_c3_rf_model.py.
RF_FEATURE_SUBSET = [
    "iat_mean_ms", "iat_cv", "iat_bowley_skewness", "iat_mad_ms",
    "requests_per_hour", "payload_size_mean", "payload_size_std",
    "http_post_ratio", "url_path_entropy", "request_burst_count",
]


class C3RFClassifierEngine:
    """
    Supervised Random Forest classifier that fills the c3_browser_anomaly_engine
    slot.  Returns predict_proba(bot_class) as the score (0–1).

    Trained on web_bot_detection_dataset (human vs advanced/moderate bot sessions).
    Complements C3AnomalyEngine (Isolation Forest on timing features only).

    Train with: train_c3_rf.bat  (scripts/train_c3_rf_model.py)
    """

    def __init__(self) -> None:
        self._model = None
        self._feature_names: list[str] = RF_FEATURE_SUBSET
        self._threshold: float = 0.5
        self._model_path = (
            Path(__file__).resolve().parents[2] / "models" / "c3_rf_classifier.pkl"
        )
        self.reload()

    def reload(self) -> bool:
        self._model = None
        try:
            with open(self._model_path, "rb") as f:
                payload = pickle.load(f)
            if isinstance(payload, dict):
                model = payload.get("model")
                self._feature_names = payload.get("feature_names", RF_FEATURE_SUBSET)
                self._threshold = float(payload.get("threshold", 0.5))
            else:
                model = payload
            if model is None or not hasattr(model, "predict_proba"):
                raise ValueError("payload does not contain a valid classifier")
            self._model = model
            print("[C3] RF Classifier (HTTP behavior) loaded")
            return True
        except FileNotFoundError:
            print("[C3] No RF Classifier model — run train_c3_rf.bat to train")
        except Exception as exc:
            print(f"[C3] Could not load RF Classifier model: {exc}")
        return False

    @property
    def model_loaded(self) -> bool:
        return self._model is not None

    def score(self, features: dict) -> tuple[Optional[float], str]:
        if not self._model:
            return None, "RF classifier model not loaded"
        try:
            values = [float(features.get(name, 0.0)) for name in self._feature_names]
            X = np.array([values], dtype=float)
            prob = float(self._model.predict_proba(X)[0][1])
            verdict = "bot" if prob >= self._threshold else "human"
            return prob, (
                f"RF prob={prob:.4f} threshold={self._threshold:.2f} [{verdict}]"
            )
        except Exception as exc:
            return None, f"RF classifier score failed: {exc}"


c3_rf_engine = C3RFClassifierEngine()

# Expose RF engine under the same name that analyzer.py already imports.
# This replaces the browser-context Isolation Forest with the supervised RF.
c3_browser_anomaly_engine = c3_rf_engine
