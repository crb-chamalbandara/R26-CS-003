"""
scripts/prepare_dataset.py
──────────────────────────
Extracts URLs + labels from the Mendeley phishing dataset zip,
builds URL features, trains a Random Forest + XGBoost ensemble,
and saves models/url_classifier.pkl.

Usage:
    python scripts/prepare_dataset.py

Expected dataset layout:
    Dataset/n96ncsr5g4-1.zip
        n96ncsr5g4-1/index.sql          ← URL labels (result=1 phishing)
        n96ncsr5g4-1/dataset/dataset_part_N.zip   ← HTML snapshots (not needed for URL model)
"""
import re
import sys
import os
import zipfile
import pickle
import io
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────
REPO_ROOT   = Path(__file__).resolve().parent.parent
DATASET_ZIP = REPO_ROOT / "Dataset" / "n96ncsr5g4-1.zip"
MODEL_OUT   = REPO_ROOT / "models" / "url_classifier.pkl"
CSV_OUT     = REPO_ROOT / "data"   / "urls_labeled.csv"

# ── Imports ───────────────────────────────────────────────────
try:
    import pandas as pd
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, f1_score
    from sklearn.pipeline import Pipeline
except ImportError as e:
    sys.exit(f"Missing dependency: {e}\nRun: pip install scikit-learn pandas numpy xgboost")

from core.c2.layer2_url import extract_features


# ══════════════════════════════════════════════════════════════
#  Step 1 — Parse index.sql from the outer zip
# ══════════════════════════════════════════════════════════════
def parse_index_sql(sql_text: str) -> list[dict]:
    """Extract (url, label) pairs from the MySQL INSERT statements."""
    records = []
    pattern = re.compile(
        r"\(\s*(\d+)\s*,\s*'([^']+)'\s*,\s*'[^']*'\s*,\s*([01])\s*,",
        re.DOTALL
    )
    for m in pattern.finditer(sql_text):
        url   = m.group(2).strip()
        label = int(m.group(3))
        if url.startswith("http"):
            records.append({"url": url, "label": label})
    return records


# ══════════════════════════════════════════════════════════════
#  Step 2 — Feature extraction
# ══════════════════════════════════════════════════════════════
FEATURE_COLS = [
    "url_len", "dots_in_host", "subdomain_depth", "has_ip",
    "is_free_tld", "is_http", "has_free_host", "has_phish_kw",
    "is_short_svc", "brand_in_host", "hyphen_count",
    "query_len", "special_in_path",
]


def build_feature_df(records: list[dict]) -> pd.DataFrame:
    rows = []
    for rec in records:
        feats = extract_features(rec["url"])
        if not feats:
            continue
        row = {k: feats.get(k, 0) for k in FEATURE_COLS}
        row["label"] = rec["label"]
        rows.append(row)
    return pd.DataFrame(rows)


# ══════════════════════════════════════════════════════════════
#  Step 3 — Train
# ══════════════════════════════════════════════════════════════
def train(df: pd.DataFrame):
    X = df[FEATURE_COLS]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"Training on {len(X_train):,} samples, testing on {len(X_test):,}")
    print(f"Class balance — phishing: {y_train.sum()} / legit: {(y_train==0).sum()}")

    # Try XGBoost first, fall back to GBM
    try:
        from xgboost import XGBClassifier
        model = XGBClassifier(
            n_estimators=300, max_depth=6, learning_rate=0.1,
            subsample=0.8, colsample_bytree=0.8,
            use_label_encoder=False, eval_metric="logloss",
            random_state=42
        )
        model_name = "XGBoost"
    except ImportError:
        model = RandomForestClassifier(n_estimators=300, max_depth=10, random_state=42, n_jobs=-1)
        model_name = "RandomForest"

    print(f"Fitting {model_name}…")
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    f1 = f1_score(y_test, y_pred)
    print(f"\n{model_name} F1 on test set: {f1:.4f}")
    print(classification_report(y_test, y_pred, target_names=["Legit", "Phishing"]))

    return model


# ══════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════
def main():
    if not DATASET_ZIP.exists():
        sys.exit(f"Dataset not found at {DATASET_ZIP}")

    print(f"Opening {DATASET_ZIP} …")
    with zipfile.ZipFile(DATASET_ZIP) as outer:
        sql_bytes = outer.read("n96ncsr5g4-1/index.sql")

    sql_text = sql_bytes.decode("utf-8", errors="replace")
    records  = parse_index_sql(sql_text)
    print(f"Parsed {len(records):,} URL records from index.sql")
    phish_n  = sum(1 for r in records if r["label"] == 1)
    legit_n  = len(records) - phish_n
    print(f"  Phishing: {phish_n:,}  |  Legitimate: {legit_n:,}")

    print("Extracting features…")
    df = build_feature_df(records)
    print(f"Feature matrix: {df.shape}")

    # Save CSV for reference
    CSV_OUT.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(CSV_OUT, index=False)
    print(f"Saved feature CSV → {CSV_OUT}")

    model = train(df)

    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(MODEL_OUT, "wb") as f:
        pickle.dump(model, f)
    print(f"\nModel saved → {MODEL_OUT}")
    print("Re-start the FastAPI backend to load the trained model.")


if __name__ == "__main__":
    main()
