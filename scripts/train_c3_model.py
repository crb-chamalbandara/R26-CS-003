"""
Train C3 Isolation Forest model.

Input : data/c3_extracted_v2.csv   (label=0 benign rows used for training)
Output: models/c3_isolation_forest.pkl

Algorithm: Isolation Forest (unsupervised, benign-only training).
  The model learns what NORMAL timing looks like and flags deviations.
  Beacon rows (label=1) are used only for evaluation, not training.
"""
from __future__ import annotations

import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

# Keep in sync with ANOMALY_FEATURE_SUBSET in core/c3/anomaly_engine.py
ANOMALY_FEATURE_SUBSET = ["iat_mean_ms", "iat_cv", "iat_bowley_skewness", "iat_mad_ms"]

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR  = REPO_ROOT / "data"
MODEL_OUT = REPO_ROOT / "models" / "c3_isolation_forest.pkl"

SEP = "=" * 60


def load_data() -> pd.DataFrame:
    patterns = [
        "c3_extracted_v2.csv",
        # "c3_collection*.csv",  # enable after live collection accumulates enough rows
    ]
    paths = []
    for pattern in patterns:
        paths.extend(sorted(DATA_DIR.glob(pattern)))

    if not paths:
        sys.exit(f"No dataset files found in {DATA_DIR}")

    frames = []
    for path in paths:
        df = pd.read_csv(path)
        if "label" in df.columns:
            frames.append(df)

    if not frames:
        sys.exit("No files contained a 'label' column")

    df = pd.concat(frames, ignore_index=True)

    needed = ["label", *ANOMALY_FEATURE_SUBSET]
    missing = [c for c in needed if c not in df.columns]
    if missing:
        sys.exit(f"Dataset missing columns: {', '.join(missing)}")

    df = df[needed].dropna()
    df = df[df["iat_mean_ms"] > 0]
    return df


def train(df: pd.DataFrame) -> tuple:
    X_benign = df[df["label"].astype(int) == 0][ANOMALY_FEATURE_SUBSET].astype(float).values
    X_beacon = df[df["label"].astype(int) == 1][ANOMALY_FEATURE_SUBSET].astype(float).values

    if len(X_benign) == 0:
        sys.exit("No label=0 rows found.")

    X_train, X_test_benign = train_test_split(X_benign, test_size=0.2, random_state=42)

    n_est = 200
    contam = 0.02
    print(f"\nFitting Isolation Forest ...")
    print(f"  n_estimators : {n_est}")
    print(f"  contamination: {contam}")
    print(f"  features     : {len(ANOMALY_FEATURE_SUBSET)}  ({', '.join(ANOMALY_FEATURE_SUBSET)})")
    print(f"  training rows: {len(X_train):,}  (80% of {len(X_benign):,} benign)")

    model = IsolationForest(n_estimators=n_est, contamination=contam, random_state=42)
    model.fit(X_train)

    scores_train = model.score_samples(X_train)
    low  = float(np.percentile(scores_train, 5))
    high = float(np.percentile(scores_train, 95))


    metrics = None
    if len(X_beacon) > 0:
        X_test = np.vstack([X_test_benign, X_beacon])
        y_test = np.array([0] * len(X_test_benign) + [1] * len(X_beacon))
        s_test = model.score_samples(X_test)
        norm   = 1.0 - np.clip((s_test - low) / (high - low), 0, 1)
        y_pred = (norm >= 0.6).astype(int)

        report  = classification_report(y_test, y_pred, target_names=["BENIGN", "BEACON"], digits=4)
        rep_d   = classification_report(y_test, y_pred, target_names=["BENIGN", "BEACON"], output_dict=True)
        cm      = confusion_matrix(y_test, y_pred)
        auc     = float(roc_auc_score(y_test, norm))
        accuracy = float((y_pred == y_test).mean())
        macro_f1 = float(f1_score(y_test, y_pred, average="macro"))
        tn, fp, fn, tp = cm[0, 0], cm[0, 1], cm[1, 0], cm[1, 1]

        metrics = {
            "report": report, "rep_d": rep_d, "cm": cm,
            "auc": auc, "accuracy": accuracy, "macro_f1": macro_f1,
            "n_train": len(X_train), "n_test_benign": len(X_test_benign),
            "n_test_beacon": len(X_beacon),
            "tn": tn, "fp": fp, "fn": fn, "tp": tp,
            "cal_low": low, "cal_high": high,
        }

    return model, low, high, metrics


def print_results(metrics: dict, data_path: str) -> None:
    rep  = metrics["report"]
    auc  = metrics["auc"]
    acc  = metrics["accuracy"]
    mf1  = metrics["macro_f1"]
    tn   = metrics["tn"]
    fp   = metrics["fp"]
    fn   = metrics["fn"]
    tp   = metrics["tp"]

    print()
    print(SEP)
    print(rep)
    print(SEP)
    print()

    print("Confusion Matrix:")
    print(f"  True Neg  (TN): {tn:5d}    benign correctly classified")
    print(f"  False Pos (FP): {fp:5d}    benign wrongly flagged as beacon")
    print(f"  False Neg (FN): {fn:5d}    beacons missed")
    print(f"  True Pos  (TP): {tp:5d}    beacons correctly detected")
    print()

    fp_rate = fp / (tn + fp) * 100 if (tn + fp) > 0 else 0.0
    recall  = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0.0

    print(f"ROC-AUC  : {auc:.4f}")
    print(f"Accuracy : {acc * 100:.2f}%")
    print(f"Macro F1 : {mf1:.4f}")
    print(f"FP rate  : {fp_rate:.1f}%  (benign flagged as beacon)")
    print(f"Recall   : {recall:.1f}%  (beacons correctly detected)")
    print()

    print("Data sources:")
    print("  Benign : CIC-IDS 2017 real network traffic")
    print("           + CTU-13 binetflow Normal flows")
    print("  Beacon : CTU-13 C&C flows (Neris, Rbot, Virut, Murlo, Sogou botnets)")
    print()


def main() -> None:
    print()
    print(SEP)
    print(" C3 Isolation Forest  --  Model Training")
    print(SEP)
    print(f" Model  : Isolation Forest (unsupervised, benign-only)")
    print(f" Data   : data\\c3_extracted_v2.csv")
    print(f" Output : models\\c3_isolation_forest.pkl")
    print(SEP)

    df = load_data()
    n_benign = (df["label"] == 0).sum()
    n_beacon = (df["label"] == 1).sum()
    print(f"\nLoaded {len(df):,} rows  |  Benign: {n_benign:,}  Beacon: {n_beacon:,}")

    model, low, high, metrics = train(df)

    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    payload = {"model": model, "calibration_low": low, "calibration_high": high}
    with open(MODEL_OUT, "wb") as f:
        pickle.dump(payload, f)

    if metrics:
        print_results(metrics, str(MODEL_OUT))

    print(f"Model saved -> {MODEL_OUT}")
    print("Restart the FastAPI backend to load the trained model.")
    print()
    print(SEP)
    print(" Training complete!  Press any key to close.")
    print(SEP)


if __name__ == "__main__":
    main()
