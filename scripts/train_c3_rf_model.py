"""
Train the C3 Random Forest classifier for HTTP behavior detection.

Input : data/c3_web_bot_sessions.csv   (run extract_web_bot_sessions.py first)
Output: models/c3_rf_classifier.pkl    {model, feature_names, threshold}

This model fills the c3_browser_anomaly_engine slot in analyzer.py.
It is supervised (human vs bot) and complements the unsupervised Isolation
Forest (timing-only, anomaly detection).  The two models run in parallel;
their scores are fused by c3_risk_fusion.

Features: 10 server-log-derivable C3 features (F01-F08, F13, F14).
Label   : 0 = human (benign),  1 = bot (beacon analog).
"""
from __future__ import annotations

import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split

# Keep in sync with RF_FEATURE_SUBSET in core/c3/anomaly_engine.py
RF_FEATURE_SUBSET = [
    "iat_mean_ms", "iat_cv", "iat_bowley_skewness", "iat_mad_ms",
    "requests_per_hour", "payload_size_mean", "payload_size_std",
    "http_post_ratio", "url_path_entropy", "request_burst_count",
]

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR  = REPO_ROOT / "data"
MODEL_OUT = REPO_ROOT / "models" / "c3_rf_classifier.pkl"
SEP = "=" * 60


def load_data() -> pd.DataFrame:
    path = DATA_DIR / "c3_web_bot_sessions.csv"
    if not path.exists():
        sys.exit(
            f"Dataset not found: {path}\n"
            "Run scripts/extract_web_bot_sessions.py (or extract_web_bot_data.bat) first."
        )
    df = pd.read_csv(path)
    needed = ["label", *RF_FEATURE_SUBSET]
    missing = [c for c in needed if c not in df.columns]
    if missing:
        sys.exit(f"Dataset missing columns: {', '.join(missing)}")
    df = df[needed].dropna()
    df["label"] = df["label"].astype(int)
    return df


def find_optimal_threshold(clf: RandomForestClassifier,
                           X_train: np.ndarray,
                           y_train: np.ndarray) -> float:
    """Youden's J statistic on training set to find best decision threshold."""
    proba = clf.predict_proba(X_train)[:, 1]
    best_thresh, best_j = 0.5, -1.0
    for t in np.linspace(0.05, 0.95, 91):
        preds = (proba >= t).astype(int)
        tp = ((preds == 1) & (y_train == 1)).sum()
        fp = ((preds == 1) & (y_train == 0)).sum()
        fn = ((preds == 0) & (y_train == 1)).sum()
        tn = ((preds == 0) & (y_train == 0)).sum()
        sens = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        j = sens + spec - 1.0
        if j > best_j:
            best_j, best_thresh = j, float(t)
    return best_thresh


def train(df: pd.DataFrame) -> tuple:
    X = df[RF_FEATURE_SUBSET].astype(float).values
    y = df["label"].astype(int).values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"\nFitting Random Forest classifier ...")
    print(f"  n_estimators   : 200")
    print(f"  max_depth      : 8")
    print(f"  min_samples_leaf: 3")
    print(f"  class_weight   : balanced")
    print(f"  features       : {len(RF_FEATURE_SUBSET)}  ({', '.join(RF_FEATURE_SUBSET)})")
    print(f"  training rows  : {len(X_train):,}  (80% of {len(X):,})")

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=8,
        min_samples_leaf=3,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(clf, X_train, y_train, cv=cv, scoring="f1_macro")
    print(f"\n  5-fold CV macro-F1: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    threshold = find_optimal_threshold(clf, X_train, y_train)
    print(f"  Optimal threshold  (Youden's J on train set): {threshold:.2f}")

    y_pred = clf.predict(X_test)
    proba  = clf.predict_proba(X_test)[:, 1]

    report = classification_report(y_test, y_pred, target_names=["HUMAN", "BOT"], digits=4)
    cm     = confusion_matrix(y_test, y_pred)
    auc    = float(roc_auc_score(y_test, proba))
    acc    = float((y_pred == y_test).mean())
    mf1    = float(f1_score(y_test, y_pred, average="macro"))
    tn, fp, fn, tp = cm[0, 0], cm[0, 1], cm[1, 0], cm[1, 1]

    metrics = {
        "report": report, "cm": cm,
        "auc": auc, "accuracy": acc, "macro_f1": mf1,
        "n_train": len(X_train), "n_test": len(X_test),
        "tn": tn, "fp": fp, "fn": fn, "tp": tp,
    }
    return clf, threshold, metrics


def print_results(metrics: dict, clf: RandomForestClassifier) -> None:
    tn, fp, fn, tp = metrics["tn"], metrics["fp"], metrics["fn"], metrics["tp"]
    fp_rate = fp / (tn + fp) * 100 if (tn + fp) > 0 else 0.0
    recall  = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0.0

    print()
    print(SEP)
    print(metrics["report"])
    print(SEP)
    print()
    print("Confusion Matrix:")
    print(f"  True Neg  (TN): {tn:5d}    humans correctly classified")
    print(f"  False Pos (FP): {fp:5d}    humans wrongly flagged as bot")
    print(f"  False Neg (FN): {fn:5d}    bots missed")
    print(f"  True Pos  (TP): {tp:5d}    bots correctly detected")
    print()
    print(f"ROC-AUC  : {metrics['auc']:.4f}")
    print(f"Accuracy : {metrics['accuracy'] * 100:.2f}%")
    print(f"Macro F1 : {metrics['macro_f1']:.4f}")
    print(f"FP rate  : {fp_rate:.1f}%  (humans flagged as bot)")
    print(f"Recall   : {recall:.1f}%  (bots correctly detected)")
    print()
    print("Feature importances (descending):")
    importances = clf.feature_importances_
    for feat, imp in sorted(zip(RF_FEATURE_SUBSET, importances), key=lambda x: -x[1]):
        bar = "=" * int(imp * 40)
        print(f"  {feat:<26} {imp:.4f}  {bar}")
    print()
    print("Data source:")
    print("  Human : web_bot_detection_dataset Phase 1 & 2 human sessions")
    print("  Bot   : web_bot_detection_dataset Phase 1 & 2 advanced/moderate bot sessions")
    print()


def main() -> None:
    print()
    print(SEP)
    print("  C3 Random Forest — HTTP Behavior Classifier  (Model 2)")
    print(SEP)
    print(f"  Model  : RandomForestClassifier (supervised, labeled sessions)")
    print(f"  Data   : data/c3_web_bot_sessions.csv")
    print(f"  Output : models/c3_rf_classifier.pkl")
    print(f"  Slot   : c3_browser_anomaly_engine in analyzer.py")
    print(SEP)

    df = load_data()
    n_human = (df["label"] == 0).sum()
    n_bot   = (df["label"] == 1).sum()
    print(f"\nLoaded {len(df):,} sessions  |  Human: {n_human:,}  Bot: {n_bot:,}")

    if n_human == 0 or n_bot == 0:
        sys.exit(
            "Need both label=0 (human) and label=1 (bot) sessions.\n"
            "Run extract_web_bot_sessions.py first."
        )

    clf, threshold, metrics = train(df)
    print_results(metrics, clf)

    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "model":         clf,
        "feature_names": RF_FEATURE_SUBSET,
        "threshold":     threshold,
    }
    with open(MODEL_OUT, "wb") as f:
        pickle.dump(payload, f)

    print(f"RF model saved  -> {MODEL_OUT}")
    print("Restart the WebSentinel backend to activate the new model.")
    print()
    print(SEP)
    print("  Training complete!  Press any key to close.")
    print(SEP)


if __name__ == "__main__":
    main()
