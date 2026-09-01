"""
C1 — train_isolation_forest_separate.py  |  Zero-Day Detector, Separate Dataset
------------------------------------------------------------------------------------
Purpose : Train Isolation Forest on isolation_forest_benign_dataset.csv — a
          dataset independently sourced and maintained from
          dataset_clean_v4.csv (which trains the supervised XGBoost model).
          This is the "separate dataset for the unsupervised model" design
          decided on explicitly, rather than deriving the benign-only
          training set by filtering the supervised dataset at runtime.

Evaluation: dataset_clean_v4.csv's malicious rows are used ONLY to measure
          catch-rate (never for training) — evaluating against a labeled
          set you didn't train on is standard practice and doesn't require
          the eval data to come from the same source as training.

Run from project root:
    python core/c1/scripts/train_isolation_forest_separate.py
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
    raw = model.decision_function(X)
    return np.clip((0.5 - raw) * 100.0, 0.0, 100.0)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train C1 Isolation Forest on its own separate dataset.")
    parser.add_argument(
        "--benign-input",
        default=os.path.join("core", "c1", "data", "isolation_forest_benign_dataset.csv"),
    )
    parser.add_argument(
        "--eval-malicious-input",
        default=os.path.join("core", "c1", "data", "dataset_clean_v4.csv"),
        help="Labeled dataset to pull malicious rows from for evaluation only (never trained on).",
    )
    parser.add_argument(
        "--model-out",
        default=os.path.join("core", "c1", "models", "isolation_forest_model.pkl"),
    )
    parser.add_argument("--contamination", type=float, default=0.02)
    parser.add_argument("--n-estimators", type=int, default=200)
    args = parser.parse_args()

    df_benign = pd.read_csv(args.benign_input)
    feature_cols = [c for c in df_benign.columns if c != "label"]
    X_benign = df_benign[feature_cols].values

    df_eval = pd.read_csv(args.eval_malicious_input)
    X_mal = df_eval[df_eval["label"] == 1][feature_cols].values

    print("=" * 60)
    print("COMPONENT 1 — ISOLATION FOREST (separate dataset)")
    print("=" * 60)
    print(f"  Training (benign-only) input : {args.benign_input}")
    print(f"  Training rows                : {len(X_benign)}")
    print(f"  Evaluation malicious rows    : {len(X_mal)}  (from {args.eval_malicious_input}, not trained on)")
    print(f"  Features                     : {len(feature_cols)}")
    print(f"  contamination                : {args.contamination}")

    model = IsolationForest(
        n_estimators=args.n_estimators,
        contamination=args.contamination,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_benign)
    print("\n[1] Trained on benign-only, independently-sourced data.")

    # ── Evaluate: benign false-positive rate (held-in, since IF has no
    #    separate holdout concept the way supervised models do — the
    #    honest test is still the labeled malicious set it never saw) ──
    benign_scores = _if_scores_0_100(model, X_benign)
    mal_scores = _if_scores_0_100(model, X_mal) if len(X_mal) else np.array([])

    print("\n[2] Threshold sweep:")
    for threshold in (40, 50, 60, 70):
        benign_fp = (benign_scores >= threshold).mean()
        mal_catch = (mal_scores >= threshold).mean() if len(mal_scores) else float("nan")
        print(f"  threshold={threshold:>3}  benign_flagged={benign_fp*100:5.2f}%   "
              f"malicious_caught={mal_catch*100:5.2f}%")

    # ── The specific check that mattered last time: known-benign complex
    #    power extensions must not get flagged ──────────────────────────
    power_csv = os.path.join(os.path.dirname(args.eval_malicious_input), "benign_power_extensions.csv")
    if os.path.exists(power_csv):
        df_power = pd.read_csv(power_csv)
        X_power = df_power[feature_cols].values
        power_scores = _if_scores_0_100(model, X_power)
        print(f"\n[3] Known complex benign extensions (Adobe, LastPass, MetaMask, etc.):")
        for ext_id, score in zip(df_power.get("extension_id", range(len(power_scores))), power_scores):
            flag = "  <-- WOULD BE FLAGGED at threshold 60" if score >= 60 else ""
            print(f"  {str(ext_id)[:35]:35s}  anomaly={score:5.1f}{flag}")
        worst = power_scores.max()
        print(f"  Worst (highest) score among known-benign power extensions: {worst:.1f}")

    os.makedirs(os.path.dirname(args.model_out), exist_ok=True)
    joblib.dump(model, args.model_out)
    print(f"\nModel saved: {args.model_out}")

    meta = {
        "benign_input": args.benign_input,
        "eval_malicious_input": args.eval_malicious_input,
        "n_features": len(feature_cols),
        "feature_names": feature_cols,
        "n_benign_train": int(len(X_benign)),
        "n_malicious_eval": int(len(X_mal)),
        "contamination": args.contamination,
        "n_estimators": args.n_estimators,
    }
    meta_path = os.path.join(os.path.dirname(args.model_out), "isolation_forest_meta.json")
    with open(meta_path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
    print(f"Metadata saved: {meta_path}")


if __name__ == "__main__":
    main()
