"""
C1 — train_isolation_forest.py  |  Zero-Day Anomaly Detector (Phase 2)
-------------------------------------------------------------------------
Purpose : Train an unsupervised Isolation Forest on BENIGN-ONLY feature
          rows so it learns what "normal" looks like, then can flag any
          extension — including ones that don't resemble any known
          malicious sample — as anomalous. This is the zero-day detection
          layer promised in the proposal (RF / XGBoost / Isolation Forest)
          and designed in C1_ML_Analysis.ipynb section 12.
Role    : Run ONCE (or whenever the dataset changes) to (re)produce
          isolation_forest_model.pkl. Companion to train_model.py, which
          trains the supervised XGBoost model.

Run from project root:
    python core/c1/scripts/train_isolation_forest.py --input core/c1/data/dataset_clean_v4.csv
"""
from __future__ import annotations

import argparse
import json
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


def _if_scores_0_100(model: IsolationForest, X: np.ndarray) -> np.ndarray:
    """Convert Isolation Forest decision_function output to a 0-100 anomaly
    score. decision_function is more NEGATIVE for anomalies, roughly in
    [-0.5, 0.5], so we flip and rescale: -0.5 -> 100 (anomalous), +0.5 -> 0."""
    raw = model.decision_function(X)
    return np.clip((0.5 - raw) * 100.0, 0.0, 100.0)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train C1 Isolation Forest (zero-day detector).")
    parser.add_argument(
        "--input",
        default=os.path.join("core", "c1", "data", "dataset_clean_v4.csv"),
    )
    parser.add_argument(
        "--model-out",
        default=os.path.join("core", "c1", "models", "isolation_forest_model.pkl"),
    )
    parser.add_argument("--label-col", default="label")
    # 0.02 (not the notebook draft's 0.05) — calibrated down against the
    # production benign set (which already includes complex power-user
    # extensions like Adobe Acrobat/MetaMask/uBlock) to keep the benign
    # false-positive rate at the decision boundary (score>=50) near 2%
    # instead of 5%. See scripts/README.md for the calibration sweep.
    parser.add_argument("--contamination", type=float, default=0.02)
    parser.add_argument("--n-estimators", type=int, default=200)
    args = parser.parse_args()

    df = pd.read_csv(args.input)
    if args.label_col not in df.columns:
        raise ValueError(f"Label column '{args.label_col}' not found.")

    feature_cols = [c for c in df.columns if c not in (args.label_col, "extension_id")]
    X_all = df[feature_cols].values
    y_all = df[args.label_col].values

    df_benign = df[df[args.label_col] == 0]
    X_benign = df_benign[feature_cols].values

    print("=" * 55)
    print("COMPONENT 1 — ISOLATION FOREST TRAINING (Zero-Day Layer)")
    print("=" * 55)
    print(f"  Dataset:            {args.input}")
    print(f"  Benign rows (train): {len(X_benign)}")
    print(f"  Total rows (eval):   {len(X_all)}  ({int((y_all==1).sum())} malicious)")
    print(f"  Features:            {len(feature_cols)}")
    print(f"  contamination:       {args.contamination}")
    print(f"  n_estimators:        {args.n_estimators}")

    # ── Train on benign-only data — no malicious labels used ─────────────
    model = IsolationForest(
        n_estimators=args.n_estimators,
        contamination=args.contamination,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_benign)
    print("\n[1] Trained on benign-only data.")

    # ── Score the full dataset to evaluate zero-day coverage ─────────────
    if_scores = _if_scores_0_100(model, X_all)

    for threshold in (40, 50, 60, 70):
        if_flag = (if_scores >= threshold).astype(int)
        benign_mask = y_all == 0
        malicious_mask = y_all == 1
        benign_fp_rate = float(if_flag[benign_mask].mean())
        malicious_catch_rate = float(if_flag[malicious_mask].mean())
        print(
            f"  threshold={threshold:>3}  "
            f"benign_flagged={benign_fp_rate*100:5.1f}%   "
            f"malicious_caught={malicious_catch_rate*100:5.1f}%"
        )

    # ── Zero-day coverage: how many malicious rows does IF catch that a
    #    plain 50% threshold alone would flag, independent of XGBoost? ────
    if_pred_50 = (if_scores >= 50).astype(int)
    total_mal = int((y_all == 1).sum())
    caught_by_if = int(((if_pred_50 == 1) & (y_all == 1)).sum())
    print(f"\n[2] At threshold=50: Isolation Forest alone catches "
          f"{caught_by_if}/{total_mal} malicious rows "
          f"({caught_by_if/total_mal*100:.1f}%) using ZERO malicious labels.")

    benign_flagged_50 = int(((if_pred_50 == 1) & (y_all == 0)).sum())
    total_benign = int((y_all == 0).sum())
    print(f"    Benign false-positive rate at threshold=50: "
          f"{benign_flagged_50}/{total_benign} ({benign_flagged_50/total_benign*100:.1f}%)")

    # ── Save model + metadata ─────────────────────────────────────────────
    os.makedirs(os.path.dirname(args.model_out), exist_ok=True)
    joblib.dump(model, args.model_out)
    print(f"\nModel saved: {args.model_out}")

    meta = {
        "input": args.input,
        "label_col": args.label_col,
        "n_features": len(feature_cols),
        "feature_names": feature_cols,
        "n_benign_train": int(len(X_benign)),
        "n_total_eval": int(len(X_all)),
        "n_malicious_eval": total_mal,
        "contamination": args.contamination,
        "n_estimators": args.n_estimators,
        "malicious_caught_at_threshold_50": caught_by_if,
        "malicious_caught_pct_at_threshold_50": caught_by_if / total_mal,
        "benign_false_positive_rate_at_threshold_50": benign_flagged_50 / total_benign,
    }
    meta_path = os.path.join(os.path.dirname(args.model_out), "isolation_forest_meta.json")
    with open(meta_path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
    print(f"Metadata saved: {meta_path}")


if __name__ == "__main__":
    main()
