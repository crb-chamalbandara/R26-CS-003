"""
C1 — static_model.py  |  The Model Loader
------------------------------------------
Purpose : Load the trained models from disk and run predictions:
            - XGBoost (supervised)   -> known-pattern malicious probability
            - Isolation Forest (unsupervised, benign-only) -> anomaly score
              for zero-day / novel-pattern extensions that don't resemble
              any known malicious sample.
Role    : Called exclusively by analyzer.py. It knows nothing about
          extensions — it just takes a 33-number vector and returns scores.
"""
from __future__ import annotations

import json
from typing import List, Tuple

import joblib   # joblib saves/loads Python objects (like trained ML models) to/from .pkl files


def load_model(model_path: str):
    """Load the trained XGBoost model (.pkl file) from disk into memory."""
    return joblib.load(model_path)


def load_feature_columns(path: str) -> List[str]:
    """Load the ordered list of 33 feature column names from the JSON file.
    This ensures features are always fed to the model in the correct order."""
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def predict_score(model, feature_vector: List[float]) -> Tuple[float, float]:
    """Run the model on one extension's feature vector.
    Returns (score_0_to_100, raw_probability_0_to_1).
    predict_proba returns [P(benign), P(malicious)] — we take index [1] for malicious probability."""
    prob  = model.predict_proba([feature_vector])[0][1]   # probability of being malicious
    score = float(prob) * 100.0                           # convert 0–1 probability to 0–100 score
    return score, float(prob)


def predict_anomaly_score(model, feature_vector: List[float]) -> float:
    """Run the Isolation Forest (trained on benign-only data) on one extension's
    feature vector and return an anomaly score 0-100 (higher = more unlike any
    benign extension seen during training — a zero-day / novel-pattern signal).

    decision_function is more NEGATIVE for anomalies, roughly in [-0.5, 0.5].
    We flip and rescale it: -0.5 -> 100 (anomalous), +0.5 -> 0 (normal). This
    is the exact mapping designed and validated in C1_ML_Analysis.ipynb."""
    raw = model.decision_function([feature_vector])[0]
    return float(max(0.0, min(100.0, (0.5 - raw) * 100.0)))
