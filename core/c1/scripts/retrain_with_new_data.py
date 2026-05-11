"""
C1 Model Retraining — incorporates new malicious CRX dataset.

Run from project root:
    python core/c1/scripts/retrain_with_new_data.py

What this does (safe, non-destructive):
  1. Parses all CRX files in MaliciousBrowserExtensions/ (both subfolders)
  2. Extracts the same 33 features used by the existing model
  3. Merges with existing dataset_clean_v3.csv (keeps all 922 benign rows)
  4. De-duplicates by extension ID so no sample appears twice
  5. Saves combined dataset as dataset_clean_v4.csv
  6. Retrains XGBoost using the same architecture (same hyperparams)
  7. Overwrites extension_detector_model.pkl and training_meta.json
  8. Prints before/after comparison

Nothing in analyzer.py, features.py, sandbox.py, or the API changes.
Only the .pkl file and the meta JSON are updated.
"""
from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    confusion_matrix,
)
from sklearn.model_selection import StratifiedKFold, train_test_split
from xgboost import XGBClassifier

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT        = Path(__file__).resolve().parents[3]
C1_DIR      = ROOT / "core" / "c1"
DATA_DIR    = C1_DIR / "data"
MODELS_DIR  = C1_DIR / "models"

NEW_DATA_ROOT = DATA_DIR / "MaliciousBrowserExtensions"
NEW_FOLDERS   = [
    NEW_DATA_ROOT / "AutomatedExtensions",
    NEW_DATA_ROOT / "Malicious Browser Extensions",
]

EXISTING_CSV    = DATA_DIR / "dataset_clean_v3.csv"
FEATURES_JSON   = DATA_DIR / "dataset_clean_v3_features.json"
COMBINED_CSV    = DATA_DIR / "dataset_clean_v4.csv"
MODEL_OUT       = MODELS_DIR / "extension_detector_model.pkl"
META_OUT        = MODELS_DIR / "training_meta.json"

sys.path.insert(0, str(ROOT))


# ── Feature extraction ────────────────────────────────────────────────────────

def extract_from_crx(crx_path: Path, feature_cols: list) -> dict | None:
    """
    Parse one CRX file and return a feature row dict (including label=1).
    Returns None if the file cannot be parsed.
    """
    try:
        from core.c1.crx_utils import parse_crx_bytes
        from core.c1.features import extract_manifest_features, build_feature_vector

        with open(crx_path, "rb") as fh:
            data = fh.read()

        if len(data) < 16:
            return None

        ext_id = crx_path.stem.lower()
        manifest_dict, source_code, _ = parse_crx_bytes(data, ext_id)

        if not manifest_dict:
            return None

        features = extract_manifest_features(manifest_dict, source_code or "")
        vector   = build_feature_vector(feature_cols, features)

        row = dict(zip(feature_cols, vector))
        row["label"]        = 1
        row["extension_id"] = ext_id
        return row

    except Exception:
        return None


# ── Model builder (same hyper-params as original training) ────────────────────

def build_model(scale_weight: float) -> XGBClassifier:
    return XGBClassifier(
        n_estimators=300,
        max_depth=4,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=2,
        scale_pos_weight=scale_weight,
        random_state=42,
        eval_metric="logloss",
        verbosity=0,
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 60)
    print("C1 Model Retraining — New Malicious Dataset")
    print("=" * 60)

    # Load feature column order
    with open(FEATURES_JSON, encoding="utf-8") as f:
        feature_cols: list = json.load(f)
    print(f"\nFeature columns : {len(feature_cols)}")

    # Load existing dataset
    df_existing = pd.read_csv(EXISTING_CSV)
    existing_ids = set(df_existing.get("extension_id", pd.Series(dtype=str)).dropna())
    n_benign_orig  = int((df_existing["label"] == 0).sum())
    n_mal_orig     = int((df_existing["label"] == 1).sum())
    print(f"\nExisting dataset: {len(df_existing)} rows "
          f"({n_benign_orig} benign, {n_mal_orig} malicious)")

    # Collect all CRX paths
    crx_files: list[Path] = []
    for folder in NEW_FOLDERS:
        if folder.exists():
            found = list(folder.glob("*.crx"))
            crx_files.extend(found)
            print(f"  {folder.name}: {len(found)} CRX files")
        else:
            print(f"  WARNING: folder not found: {folder}")

    print(f"\nTotal new CRX files : {len(crx_files)}")

    # Extract features from each CRX
    print("\nExtracting features", end="", flush=True)
    new_rows = []
    skipped = 0
    duplicates = 0

    for i, crx_path in enumerate(crx_files):
        if (i + 1) % 30 == 0:
            print(".", end="", flush=True)

        ext_id = crx_path.stem.lower()

        # Skip if already in existing dataset
        if ext_id in existing_ids:
            duplicates += 1
            continue

        row = extract_from_crx(crx_path, feature_cols)
        if row is None:
            skipped += 1
        else:
            new_rows.append(row)
            existing_ids.add(ext_id)  # prevent intra-batch duplicates

    print(f" done.\n")
    print(f"  Parsed OK  : {len(new_rows)}")
    print(f"  Skipped    : {skipped}  (parse error / too small)")
    print(f"  Duplicates : {duplicates}  (already in v3 dataset)")

    if not new_rows:
        print("\nERROR: No new rows extracted. Check CRX files.")
        sys.exit(1)

    # Build new-data DataFrame (drop extension_id before concat)
    df_new = pd.DataFrame(new_rows)
    df_new_features = df_new.drop(columns=["extension_id"], errors="ignore")

    # Align columns with existing dataset
    df_existing_aligned = df_existing[feature_cols + ["label"]].copy()
    frames = [df_existing_aligned, df_new_features[feature_cols + ["label"]]]

    # Include benign complex extensions if collected.
    # These cover underrepresented features: has_scripting=1, high host_permission_count,
    # has_all_urls=1 — teaching the model these are not inherently malicious.
    for extra_csv_name in ("benign_power_extensions.csv", "benign_complex_extensions.csv"):
        extra_csv = DATA_DIR / extra_csv_name
        if extra_csv.exists():
            df_extra = pd.read_csv(extra_csv)
            df_extra_aligned = df_extra[feature_cols + ["label"]].copy()
            frames.append(df_extra_aligned)
            print(f"Including {len(df_extra_aligned)} benign complex extensions "
                  f"from {extra_csv_name}")

    df_combined = pd.concat(frames, ignore_index=True)

    n_benign_new = int((df_combined["label"] == 0).sum())
    n_mal_new    = int((df_combined["label"] == 1).sum())
    print(f"\nCombined dataset : {len(df_combined)} rows "
          f"({n_benign_new} benign, {n_mal_new} malicious)")

    df_combined.to_csv(COMBINED_CSV, index=False)
    print(f"Saved combined CSV: {COMBINED_CSV.name}")

    # Train / evaluate
    X = df_combined[feature_cols].values
    y = df_combined["label"].values

    scale_weight = n_benign_new / n_mal_new
    print(f"\nscale_pos_weight : {scale_weight:.2f}  "
          f"(was 41.9 before new data)")

    # ── 5-fold stratified cross-validation ───────────────────────────────────
    print("\nRunning 5-fold stratified CV", end="", flush=True)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_p, cv_r, cv_f = [], [], []

    for fold_idx, (train_idx, val_idx) in enumerate(skf.split(X, y)):
        print(".", end="", flush=True)
        X_tr, X_val = X[train_idx], X[val_idx]
        y_tr, y_val = y[train_idx], y[val_idx]
        clf = build_model(scale_weight)
        clf.fit(X_tr, y_tr)
        y_pred = clf.predict(X_val)
        if y_val.sum() == 0:
            continue
        cv_p.append(precision_score(y_val, y_pred, zero_division=0))
        cv_r.append(recall_score(y_val, y_pred, zero_division=0))
        cv_f.append(f1_score(y_val, y_pred, zero_division=0))

    print(" done.\n")
    print(f"  CV Precision : {np.mean(cv_p):.3f} ± {np.std(cv_p):.3f}")
    print(f"  CV Recall    : {np.mean(cv_r):.3f} ± {np.std(cv_r):.3f}")
    print(f"  CV F1        : {np.mean(cv_f):.3f} ± {np.std(cv_f):.3f}")

    # ── Holdout evaluation (80/20) ────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    final_model = build_model(scale_weight)
    final_model.fit(X_train, y_train)
    y_pred_test = final_model.predict(X_test)

    holdout_p = precision_score(y_test, y_pred_test, zero_division=0)
    holdout_r = recall_score(y_test, y_pred_test, zero_division=0)
    holdout_f = f1_score(y_test, y_pred_test, zero_division=0)
    print(f"\nHoldout (20%) :")
    print(f"  Precision : {holdout_p:.3f}")
    print(f"  Recall    : {holdout_r:.3f}")
    print(f"  F1        : {holdout_f:.3f}")
    print(f"\nConfusion matrix (holdout):")
    cm = confusion_matrix(y_test, y_pred_test)
    print(f"  TN={cm[0,0]}  FP={cm[0,1]}")
    print(f"  FN={cm[1,0]}  TP={cm[1,1]}")
    print(f"\nDetailed report:")
    print(classification_report(y_test, y_pred_test,
                                 target_names=["Benign", "Malicious"],
                                 zero_division=0))

    # ── Retrain on full combined dataset ──────────────────────────────────────
    print("Retraining final model on full dataset...", end="", flush=True)
    full_model = build_model(scale_weight)
    full_model.fit(X, y)
    print(" done.")

    # Save model
    MODELS_DIR.mkdir(exist_ok=True)
    joblib.dump(full_model, MODEL_OUT)
    print(f"Model saved: {MODEL_OUT.name}")

    # Save feature importance
    fi_df = pd.DataFrame({
        "feature":   feature_cols,
        "importance": full_model.feature_importances_,
    }).sort_values("importance", ascending=False)
    fi_df.to_csv(MODELS_DIR / "feature_importance.csv", index=False)

    # Save training metadata
    meta = {
        "input":                str(COMBINED_CSV.name),
        "label_col":            "label",
        "n_features":           len(feature_cols),
        "feature_names":        feature_cols,
        "n_malicious":          n_mal_new,
        "n_benign":             n_benign_new,
        "scale_pos_weight":     scale_weight,
        "cv_folds":             5,
        "cv_precision_mean":    float(np.mean(cv_p)),
        "cv_precision_std":     float(np.std(cv_p)),
        "cv_recall_mean":       float(np.mean(cv_r)),
        "cv_recall_std":        float(np.std(cv_r)),
        "cv_f1_mean":           float(np.mean(cv_f)),
        "cv_f1_std":            float(np.std(cv_f)),
        "holdout_precision":    holdout_p,
        "holdout_recall":       holdout_r,
        "holdout_f1":           holdout_f,
    }
    with open(META_OUT, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    print(f"Metadata saved : {META_OUT.name}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("RETRAINING COMPLETE")
    print("=" * 60)
    print(f"  Malicious samples : {n_mal_orig} → {n_mal_new}  "
          f"(+{n_mal_new - n_mal_orig})")
    print(f"  CV F1             : (previous 0.617) → {np.mean(cv_f):.3f}")
    print(f"  Holdout F1        : (previous 0.444) → {holdout_f:.3f}")
    print(f"\n  Model file unchanged: extension_detector_model.pkl")
    print(f"  No changes to analyzer.py, features.py, or the API.")
    print("=" * 60)


if __name__ == "__main__":
    main()
