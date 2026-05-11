"""Model loading and inference helpers for C1 static analysis."""
from __future__ import annotations

import json
from typing import List, Tuple

import joblib


def load_model(model_path: str):
    return joblib.load(model_path)


def load_feature_columns(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def predict_score(model, feature_vector: List[float]) -> Tuple[float, float]:
    prob = model.predict_proba([feature_vector])[0][1]
    score = float(prob) * 100.0
    return score, float(prob)
