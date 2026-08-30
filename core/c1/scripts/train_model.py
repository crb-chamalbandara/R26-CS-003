"""
C1 — train_model.py  |  Original Training Script
--------------------------------------------------
Purpose : Train the XGBoost classifier on a cleaned dataset CSV, evaluate
          it with 5-fold cross-validation and a holdout test set, then save
          the trained model and metadata.
Role    : Run ONCE (or whenever you want to retrain from a specific CSV).
          For the full automated pipeline that also builds the dataset from
          new CRX files, use retrain_with_new_data.py instead.

Run from project root:
    python core/c1/scripts/train_model.py --input core/c1/data/dataset_clean_v4.csv
"""
from __future__ import annotations

import argparse
import json
import os

import joblib           # for saving the trained model to disk as a .pkl file
import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,   # full precision/recall/F1 breakdown per class
    confusion_matrix,        # TN/FP/FN/TP counts
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedKFold, train_test_split
from xgboost import XGBClassifier


def _build_model(scale_weight: float) -> XGBClassifier:
    """Create an XGBoost classifier with fixed hyperparameters.
    scale_pos_weight corrects class imbalance by making malicious misclassifications
    more costly than benign ones (weight = n_benign / n_malicious)."""
    return XGBClassifier(
        n_estimators=300,         # 300 decision trees in the ensemble
        max_depth=4,              # shallow trees prevent overfitting on small datasets
        learning_rate=0.05,       # small step size — each tree contributes a little
        subsample=0.8,            # each tree trains on 80% of rows (random sampling)
        colsample_bytree=0.8,     # each tree uses 80% of features (reduces correlation between trees)
        min_child_weight=2,       # a leaf must have at least 2 samples — prevents tiny overfit splits
        scale_pos_weight=scale_weight,  # upweights malicious class to correct imbalance
        random_state=42,          # fixed seed for reproducibility
        eval_metric="logloss",    # log loss is appropriate for binary probability output
        verbosity=0,              # suppress verbose XGBoost training output
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Train C1 XGBoost model.")
    parser.add_argument(
        "--input",
        default=os.path.join("core", "c1", "data", "dataset_clean_v4.csv"),   # v4 = final dataset with 322 malicious
    )
    parser.add_argument(
        "--model-out",
        default=os.path.join("core", "c1", "models", "extension_detector_model.pkl"),
    )
    parser.add_argument("--label-col", default="label")
    args = parser.parse_args()

    df = pd.read_csv(args.input)
    if args.label_col not in df.columns:
        raise ValueError(f"Label column '{args.label_col}' not found.")

    X = df.drop(columns=[args.label_col])   # feature matrix — all columns except label
    y = df[args.label_col]                  # target vector — 0=benign, 1=malicious

    benign_count    = int((y == 0).sum())
    malicious_count = int((y == 1).sum())
    scale_weight    = benign_count / max(malicious_count, 1)   # e.g., 937/322 = 2.91

    print("=" * 55)
    print("COMPONENT 1 — ML MODEL TRAINING")
    print("=" * 55)
    print(f"  Dataset:   {args.input}")
    print(f"  Samples:   {len(X)} total  ({malicious_count} malicious, {benign_count} benign)")
    print(f"  Features:  {X.shape[1]}")
    print(f"  scale_pos_weight: {scale_weight:.1f}")

    # ── Stratified 5-fold cross-validation ──────────────────────
    # With only 22 malicious samples a single 80/20 split is too noisy.
    # 5-fold CV gives 5 independent estimates and a proper mean ± std.
    print("\n[1] Stratified 5-fold cross-validation...")
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_precision, cv_recall, cv_f1 = [], [], []

    for fold, (tr_idx, te_idx) in enumerate(skf.split(X, y), 1):
        Xtr, Xte = X.iloc[tr_idx], X.iloc[te_idx]
        ytr, yte = y.iloc[tr_idx], y.iloc[te_idx]
        sw = int((ytr == 0).sum()) / max(int((ytr == 1).sum()), 1)
        m = _build_model(sw)
        m.fit(Xtr, ytr)
        yp = m.predict(Xte)
        cv_precision.append(precision_score(yte, yp, zero_division=0))
        cv_recall.append(recall_score(yte, yp, zero_division=0))
        cv_f1.append(f1_score(yte, yp, zero_division=0))
        mal_in_test = int((yte == 1).sum())
        print(f"  Fold {fold}: P={cv_precision[-1]:.3f}  R={cv_recall[-1]:.3f}  "
              f"F1={cv_f1[-1]:.3f}  (malicious in test={mal_in_test})")

    print(f"\n  CV mean  — Precision: {np.mean(cv_precision):.3f}  "
          f"Recall: {np.mean(cv_recall):.3f}  F1: {np.mean(cv_f1):.3f}")
    print(f"  CV std   — Precision: {np.std(cv_precision):.3f}  "
          f"Recall: {np.std(cv_recall):.3f}  F1: {np.std(cv_f1):.3f}")

    # ── Final model trained on 80%, evaluated on held-out 20% ───
    print("\n[2] Training final model (80/20 hold-out)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    sw_final = int((y_train == 0).sum()) / max(int((y_train == 1).sum()), 1)
    model = _build_model(sw_final)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    precision = precision_score(y_test, y_pred, zero_division=0)
    recall    = recall_score(y_test, y_pred, zero_division=0)
    f1        = f1_score(y_test, y_pred, zero_division=0)

    print("\n" + "=" * 55)
    print("HOLD-OUT TEST RESULTS")
    print("=" * 55)
    print(f"  Precision : {precision:.3f}  ({precision*100:.1f}%)")
    print(f"  Recall    : {recall:.3f}  ({recall*100:.1f}%)")
    print(f"  F1-Score  : {f1:.3f}  ({f1*100:.1f}%)")
    print()
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))

    cm = confusion_matrix(y_test, y_pred)
    print("Confusion matrix:")
    print(f"  True negatives  (benign  -> benign)    : {cm[0][0]}")
    print(f"  False positives (benign  -> malicious) : {cm[0][1]}")
    print(f"  False negatives (malicious -> benign)  : {cm[1][0]}")
    print(f"  True positives  (malicious -> malicious): {cm[1][1]}")

    # ── Final production model: retrain on 100% of the data ───────
    # The 80/20 split above exists purely to produce an honest, unseen-data
    # holdout metric. The model actually saved and shipped is trained on
    # every available row — matching retrain_with_new_data.py's behaviour.
    # (A model saved straight from the 80% split was mistakenly shipped
    # once before; it's measurably weaker than the full-data fit and should
    # never be what ends up in models/extension_detector_model.pkl.)
    print("\n[2b] Retraining final model on 100% of the data for production...")
    final_model = _build_model(scale_weight)
    final_model.fit(X, y)

    # ── Feature importance (from the final, full-data model) ──────
    importances = pd.Series(final_model.feature_importances_, index=X.columns).sort_values(ascending=False)
    print("\n[3] Top 10 most important features:")
    for feat, imp in importances.head(10).items():
        print(f"  {feat:<30} {imp:.4f}")

    # ── Save artefacts ───────────────────────────────────────────
    os.makedirs(os.path.dirname(args.model_out), exist_ok=True)
    joblib.dump(final_model, args.model_out)
    print(f"\nModel saved: {args.model_out}  (trained on full {len(X)}-row dataset)")

    imp_path = os.path.join(os.path.dirname(args.model_out), "feature_importance.csv")
    importances.to_csv(imp_path, header=["importance"])

    meta = {
        "input": args.input,
        "label_col": args.label_col,
        "n_features": int(X.shape[1]),
        "feature_names": list(X.columns),
        "n_malicious": malicious_count,
        "n_benign": benign_count,
        "scale_pos_weight": float(scale_weight),
        "cv_folds": 5,
        "cv_precision_mean": float(np.mean(cv_precision)),
        "cv_precision_std":  float(np.std(cv_precision)),
        "cv_recall_mean":    float(np.mean(cv_recall)),
        "cv_recall_std":     float(np.std(cv_recall)),
        "cv_f1_mean":        float(np.mean(cv_f1)),
        "cv_f1_std":         float(np.std(cv_f1)),
        "holdout_precision": float(precision),
        "holdout_recall":    float(recall),
        "holdout_f1":        float(f1),
    }
    meta_path = os.path.join(os.path.dirname(args.model_out), "training_meta.json")
    with open(meta_path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
    print(f"Metadata saved: {meta_path}")


if __name__ == "__main__":
    main()
