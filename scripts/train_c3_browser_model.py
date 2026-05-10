"""
Train C3 Browser Context Isolation Forest model.

Input : data/c3_collection*.csv  (real browser session data from C3 collection mode)
Output: models/c3_browser_context_forest.pkl

Algorithm: Isolation Forest (unsupervised, benign-only training).
  Uses 4 browser-context features measured by live browser instrumentation.
  These features are NOT present in pcap data — only real browser sessions produce them.

This model is COMPLEMENTARY to c3_isolation_forest (timing-only model):
  - Timing model (c3_isolation_forest.pkl)     detects regular-interval beaconing
  - Browser context model (this file)           detects idle-fired / background-tab beaconing

To collect training data before running this script:
  1. Start WebSentinel backend
  2. POST /c3/collect/start  {"label": 0}
  3. Browse normally for 30-60 minutes (benign data)
  4. POST /c3/collect/export
  5. Run the beacon demo (test_c3_beacon.bat) with collection active at label=1
  6. POST /c3/collect/export
  7. Run this script
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

# 4 browser-context features — require live browser instrumentation.
# NOT available in pcap data (all zero in CIC-IDS / CTU-13 captures).
# Keep in sync with BROWSER_FEATURE_SUBSET in core/c3/anomaly_engine.py
BROWSER_FEATURE_SUBSET = [
    "avg_idle_time_ms",
    "user_active_ratio",
    "background_tab_ratio",
    "url_path_entropy",
]

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR  = REPO_ROOT / "data"
MODEL_OUT = REPO_ROOT / "models" / "c3_browser_context_forest.pkl"

SEP = "=" * 60


def load_data() -> pd.DataFrame:
    paths = sorted(DATA_DIR.glob("c3_collection*.csv"))

    if not paths:
        print()
        print(SEP)
        print(" No collection data found in data/")
        print()
        print(" This model requires real browser session data.")
        print(" Steps to collect:")
        print("   1. Start WebSentinel backend")
        print("   2. POST /c3/collect/start  {\"label\": 0}")
        print("   3. Browse normally for 30-60 minutes (benign session)")
        print("   4. POST /c3/collect/export")
        print("   5. Run test_c3_beacon.bat with label=1 collection")
        print("   6. POST /c3/collect/export")
        print("   7. Re-run this script")
        print()
        print(SEP)
        print(" Training complete!  Press any key to close.")
        print(SEP)
        sys.exit(0)

    frames = []
    for path in paths:
        df = pd.read_csv(path)
        needed = ["label", *BROWSER_FEATURE_SUBSET]
        missing = [c for c in needed if c not in df.columns]
        if missing:
            print(f"  [skip] {path.name}: missing columns {missing}")
            continue
        frames.append(df[needed])
        print(f"  Loaded {path.name} : {len(df):,} rows")

    if not frames:
        sys.exit("No collection files had the required browser-context columns.")

    df = pd.concat(frames, ignore_index=True)
    df = df.dropna()
    df["label"] = df["label"].astype(int)
    return df


def train(df: pd.DataFrame) -> tuple:
    X_benign = df[df["label"] == 0][BROWSER_FEATURE_SUBSET].astype(float).values
    X_beacon = df[df["label"] == 1][BROWSER_FEATURE_SUBSET].astype(float).values

    if len(X_benign) == 0:
        sys.exit("No label=0 (benign) rows found. Collect benign browsing data first.")

    X_train, X_test_benign = train_test_split(X_benign, test_size=0.2, random_state=42)

    n_est  = 200
    contam = 0.02
    print(f"\nFitting Isolation Forest (browser context) ...")
    print(f"  n_estimators : {n_est}")
    print(f"  contamination: {contam}")
    print(f"  features     : {len(BROWSER_FEATURE_SUBSET)}  ({', '.join(BROWSER_FEATURE_SUBSET)})")
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

        report   = classification_report(y_test, y_pred, target_names=["BENIGN", "BEACON"], digits=4)
        cm       = confusion_matrix(y_test, y_pred)
        auc      = float(roc_auc_score(y_test, norm))
        accuracy = float((y_pred == y_test).mean())
        macro_f1 = float(f1_score(y_test, y_pred, average="macro"))
        tn, fp, fn, tp = cm[0, 0], cm[0, 1], cm[1, 0], cm[1, 1]

        metrics = {
            "report": report, "cm": cm,
            "auc": auc, "accuracy": accuracy, "macro_f1": macro_f1,
            "n_train": len(X_train), "n_test_benign": len(X_test_benign),
            "n_test_beacon": len(X_beacon),
            "tn": tn, "fp": fp, "fn": fn, "tp": tp,
        }
    else:
        print(f"\n  [info] No beacon rows (label=1) found.")
        print(f"         Model trained on benign data only.")
        print(f"         Run test_c3_beacon.bat with label=1 collection to add beacon data.")

    return model, low, high, metrics


def print_results(metrics: dict) -> None:
    rep = metrics["report"]
    auc = metrics["auc"]
    acc = metrics["accuracy"]
    mf1 = metrics["macro_f1"]
    tn  = metrics["tn"]
    fp  = metrics["fp"]
    fn  = metrics["fn"]
    tp  = metrics["tp"]

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
    print("  Benign : Real browser sessions collected via C3 collection mode (label=0)")
    print("  Beacon : Real beacon sessions from demo run with label=1 collection")
    print()


def main() -> None:
    print()
    print(SEP)
    print(" C3 Browser Context Model  --  Training")
    print(SEP)
    print(f" Model  : Isolation Forest (browser-context features)")
    print(f" Data   : data\\c3_collection*.csv  (live browser sessions)")
    print(f" Output : models\\c3_browser_context_forest.pkl")
    print(f" Note   : Uses only real browser session data — no pcap data")
    print(SEP)

    print(f"\nSearching for collection data in {DATA_DIR} ...")
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
        print_results(metrics)

    print(f"Browser context model saved -> {MODEL_OUT}")
    print("Restart the FastAPI backend to load the new model.")
    print()
    print(SEP)
    print(" Training complete!  Press any key to close.")
    print(SEP)


if __name__ == "__main__":
    main()
