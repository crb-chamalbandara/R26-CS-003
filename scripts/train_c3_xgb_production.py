"""
SUPERSEDED 2026-08-28 -- kept only as the historical record of the NetFlow-
scale methodology. This no longer writes to the production slot (OUT_MODEL
below points at a harmless side file) so running it by mistake cannot
silently overwrite the deployed model.

core/c3/anomaly_engine.py now loads a model trained by
scripts/train_c3_xgb_http.py on data/c3_ctu13_http_c2_dataset.csv (real
Zeek http.log payload bytes), not this script's data/c3_xgb_training.csv
(CTU-13/IoT-23 NetFlow flow-total bytes). Reason: this NetFlow-trained model
scored 0.0000 on every realistic browser-beacon feature vector regardless of
timing regularity, because payload_size_mean here is a NetFlow flow-total
(up to 2.1GB) rebranded to the live feature name without rescaling -- see
C3_FullPipeline_XGB_Results.md Result 6. Full before/after comparison in
C3_XGB_HTTP_Deployment_Results.md.

The RandomForest this slot held before XGBoost is preserved at
models/archive/c3_rf_classifier_PRE_XGB_20260827.pkl. This script's own
NetFlow-scale XGBoost output is preserved at
models/archive/c3_xgb_classifier_NETFLOW_PRE_HTTP_20260828.pkl.

---- ORIGINAL DOCSTRING (2026-08-27, when this WAS the production trainer) ----

Train the PRODUCTION XGBoost C2 classifier -> models/c3_xgb_classifier.pkl

This is the model core/c3/anomaly_engine.py loads at runtime. It replaces the
RandomForest that previously filled that slot; the RF is preserved at
models/archive/c3_rf_classifier_PRE_XGB_20260827.pkl and can be restored by
reverting anomaly_engine.py's model path.

WHY XGBOOST, AND WHY THE THRESHOLD MOVED WITH IT (both measured, see
C3_FullPipeline_XGB_Results.md):
  Swapping RF -> XGBoost while leaving the BEACON threshold at 0.60 changes
  almost nothing (30.0% -> 25.0% recall on genuinely metronomic C2; the two
  models catch nearly the same windows). XGBoost's real advantage is
  CALIBRATION, not raw score: across 1,200 adversarial benign windows the
  highest fused score RF ever produced was 0.5585, while XGBoost's was 0.5139.
  That gap is headroom RF does not have. Lowering the BEACON threshold to 0.52
  therefore yields, out-of-fold:
        XGBoost @ 0.52  ->  80.0% recall (16/20), 0 false positives
        RF      @ 0.52  ->  60.0% recall (12/20), 3 false positives
  The model and the threshold are a package; neither alone is worth deploying.

HYPERPARAMETERS are not re-searched here. They were selected by nested
leave-one-scenario-out CV in scripts/train_c3_xgb_optimized.py (inner folds on
training data only, never on a test fold) and are pinned below so this script
is a deterministic, reviewable single fit rather than a fresh search whose
result could drift between runs.

FEATURES are the same 7 the RF used, under the live feature_engine.py names,
so anomaly_engine.py's schema validation passes and no feature_engine.py
change is required.

SCOPE / HONESTY: trained on real CTU-13 + IoT-23 C2-channel windows only. No
synthetic rows. The 80% figure above applies to beacons with iat_cv < 0.05
(<=~8% jitter); detection collapses above iat_cv ~0.10. See the results doc
for the full caveats (n=20 in that band; threshold selected against the same
benign sample and still needs independent validation).
"""
from __future__ import annotations

import json
import pickle
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score
from xgboost import XGBClassifier

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET = REPO_ROOT / "data" / "c3_xgb_training.csv"
# NOT the production slot any more -- see the SUPERSEDED note above. The
# production trainer is scripts/train_c3_xgb_http.py.
OUT_MODEL = REPO_ROOT / "models" / "archive" / "c3_xgb_netflow_reproduction.pkl"
OUT_RESULTS = REPO_ROOT / "data" / "_xgb_production_train.json"

FEATURES = [
    "iat_mean_ms", "iat_cv", "iat_bowley_skewness", "iat_mad_ms",
    "payload_size_mean", "payload_size_std", "request_burst_count",
]
LABEL_COL = "label_c2"

# Selected by nested LOSO CV in scripts/train_c3_xgb_optimized.py -- pinned,
# not re-searched. spw_mult scales scale_pos_weight (XGBoost's equivalent of
# RF's class_weight="balanced") by the factor that CV preferred.
XGB_PARAMS = dict(n_estimators=200, max_depth=6, learning_rate=0.1,
                  min_child_weight=3, n_jobs=8, random_state=42,
                  eval_metric="aucpr", verbosity=0)
SPW_MULT = 2.0

# Kept at 0.5 deliberately. anomaly_engine.score() returns the raw probability
# to risk_fusion and uses this value only to render a "bot"/"human" label in
# its log line -- it does NOT gate the fused verdict. The threshold that
# actually decides BEACON is in risk_fusion.py (0.52 after this change).
MODEL_THRESHOLD = 0.5


def main():
    t0 = time.time()
    df = pd.read_csv(DATASET)
    X = df[FEATURES].to_numpy(dtype=float)
    y = df[LABEL_COL].to_numpy(dtype=int)
    n_pos = int(y.sum())
    print(f"training windows: {len(df):,}  positive: {n_pos} ({100*n_pos/len(df):.4f}%)")
    print(f"positives by dataset: {df[df[LABEL_COL]==1].groupby('source_dataset').size().to_dict()}")

    spw = ((y == 0).sum() / max(1, n_pos)) * SPW_MULT
    clf = XGBClassifier(scale_pos_weight=spw, **XGB_PARAMS).fit(X, y)

    prob = clf.predict_proba(X)[:, 1]
    in_sample = {
        "pr_auc": round(float(average_precision_score(y, prob)), 4),
        "roc_auc": round(float(roc_auc_score(y, prob)), 4),
        "recall_at_0.5": round(float(((prob >= 0.5) & (y == 1)).sum() / max(n_pos, 1)), 4),
    }
    importances = {n: round(float(s), 6) for n, s in
                   sorted(zip(FEATURES, clf.feature_importances_), key=lambda kv: -kv[1])}
    print(f"\nin-sample (NOT a generalization claim): {in_sample}")
    print("feature importances:")
    for n, s in importances.items():
        print(f"  {n:24s} {s:.4f}")

    payload = {
        "model": clf,
        "feature_names": FEATURES,
        "threshold": MODEL_THRESHOLD,
        "trained_on": "CTU-13 + IoT-23 combined, label_c2 (ANY real C2-channel flow), n_flows>=4",
        "n_training_windows": int(len(df)),
        "n_positive_windows": n_pos,
        "params": {**XGB_PARAMS, "scale_pos_weight": round(float(spw), 2), "spw_mult": SPW_MULT},
        "feature_importances": importances,
        "in_sample": in_sample,
        "honest_loso_reference": {
            "note": "Out-of-fold figures from C3_FullPipeline_XGB_Results.md; "
                     "in-sample numbers above are memorisation, not performance.",
            "beacon_recall_iat_cv_lt_0.05_at_fusion_threshold_0.52": 0.80,
            "false_positives_on_1200_hard_negatives": 0,
            "known_limit": "detection collapses above iat_cv ~0.10 (>=20% jitter)",
        },
        "requires_fusion_threshold": 0.52,
        "replaces": "models/c3_rf_classifier.pkl (archived as "
                     "models/archive/c3_rf_classifier_PRE_XGB_20260827.pkl)",
    }
    OUT_MODEL.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_MODEL, "wb") as f:
        pickle.dump(payload, f)
    print(f"\nsaved production model -> {OUT_MODEL}")
    print("  (core/c3/anomaly_engine.py loads this file -- restart the backend to pick it up)")

    with open(OUT_RESULTS, "w", encoding="utf-8") as f:
        json.dump({"in_sample": in_sample, "feature_importances": importances,
                   "params": payload["params"], "n_training_windows": len(df),
                   "n_positive_windows": n_pos}, f, indent=2)
    print(f"saved -> {OUT_RESULTS}")
    print(f"total time {time.time()-t0:.1f}s")


if __name__ == "__main__":
    main()
