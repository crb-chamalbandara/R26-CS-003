"""
C1 — prepare_data.py  |  Dataset Cleaner
------------------------------------------
Purpose : Take a raw feature CSV (e.g., master_dataset.csv or manifest_dataset.csv)
          and clean it for ML training:
            - Normalize label column to 0 (benign) / 1 (malicious)
            - Drop any non-numeric columns
            - Replace NaN and infinite values with 0
            - Clip extreme values to safe float32 range
          Also saves a _features.json listing the final column names.
Role    : Run ONCE during dataset preparation.  Produces dataset_clean.csv (v1).
          Later versions (v3, v4) were built with the same logic via retrain_with_new_data.py.

Run from project root:
    python core/c1/scripts/prepare_data.py
"""
from __future__ import annotations

import argparse
import json
import os
from typing import List

import numpy  as np
import pandas as pd


def _normalize_label(value: str) -> int | None:
    """Convert various label formats to binary integer: 1 = malicious, 0 = benign, None = unknown."""
    if value is None:
        return None
    raw = str(value).strip().lower()
    if raw in {"1", "malicious", "malware", "bad"}:
        return 1    # malicious extension
    if raw in {"0", "benign", "safe", "good"}:
        return 0    # safe extension
    return None     # unrecognised label — will be dropped


def _coerce_numeric(df: pd.DataFrame, label_col: str) -> pd.DataFrame:
    """Force all feature columns to numeric type. Non-convertible values become NaN."""
    feature_cols: List[str] = [c for c in df.columns if c != label_col]
    for col in feature_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")  # errors='coerce' turns bad values into NaN
    return df


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare C1 dataset for training.")
    parser.add_argument(
        "--input",
        default=os.path.join("core", "c1", "data", "master_dataset.csv"),
        help="Input CSV path",
    )
    parser.add_argument(
        "--output",
        default=os.path.join("core", "c1", "data", "dataset_clean.csv"),
        help="Output cleaned CSV path",
    )
    parser.add_argument("--label-col", default="label", help="Label column name")
    args = parser.parse_args()

    df = pd.read_csv(args.input)
    if args.label_col not in df.columns:
        raise ValueError(f"Label column '{args.label_col}' not found.")

    # Step 1: Normalize label values to 0/1 integers, drop rows with unknown labels
    df[args.label_col] = df[args.label_col].apply(_normalize_label)
    df = df.dropna(subset=[args.label_col]).copy()           # drop rows with unrecognised labels
    df[args.label_col] = df[args.label_col].astype(int)

    # Step 2: Coerce all feature columns to numeric (non-convertible → NaN)
    df = _coerce_numeric(df, args.label_col)

    # Step 3: Drop any text/object columns — XGBoost only works with numeric data
    non_numeric = df.drop(columns=[args.label_col]).select_dtypes(exclude=["number"]).columns
    if len(non_numeric) > 0:
        df = df.drop(columns=list(non_numeric))

    # Step 4: Replace NaN and infinite values with 0 — prevents training failures
    df = df.replace([float("inf"), float("-inf")], pd.NA)
    df = df.fillna(0)

    # Step 5: Clip extreme feature values to safe float32 range
    feature_cols = [c for c in df.columns if c != args.label_col]
    max_val      = float(np.finfo("float32").max / 2)   # half of max float32 to avoid overflow
    df[feature_cols] = df[feature_cols].clip(lower=-max_val, upper=max_val)
    df[feature_cols] = df[feature_cols].astype("float32")   # use float32 to save memory

    # Step 6: Reorder columns — features first, label last (standard ML convention)
    label_col    = args.label_col
    feature_cols = [c for c in df.columns if c != label_col]
    df           = df[feature_cols + [label_col]]

    # Save cleaned dataset
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    df.to_csv(args.output, index=False)

    # Also save the feature column names as JSON — required by analyzer.py at runtime
    feature_path = os.path.splitext(args.output)[0] + "_features.json"
    with open(feature_path, "w", encoding="utf-8") as handle:
        json.dump(feature_cols, handle, indent=2)

    counts = df[label_col].value_counts().to_dict()
    print(f"Saved cleaned dataset to: {args.output}")
    print(f"Features saved to: {feature_path}")
    print(f"Label counts: {counts}")


if __name__ == "__main__":
    main()
