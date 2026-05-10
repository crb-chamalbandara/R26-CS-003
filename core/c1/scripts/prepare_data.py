"""Prepare a cleaned dataset for C1 static ML training."""
from __future__ import annotations

import argparse
import json
import os
from typing import List

import numpy as np
import pandas as pd


def _normalize_label(value: str) -> int | None:
    if value is None:
        return None
    raw = str(value).strip().lower()
    if raw in {"1", "malicious", "malware", "bad"}:
        return 1
    if raw in {"0", "benign", "safe", "good"}:
        return 0
    return None


def _coerce_numeric(df: pd.DataFrame, label_col: str) -> pd.DataFrame:
    feature_cols: List[str] = [c for c in df.columns if c != label_col]
    for col in feature_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")
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
    parser.add_argument(
        "--label-col",
        default="label",
        help="Label column name",
    )
    args = parser.parse_args()

    df = pd.read_csv(args.input)
    if args.label_col not in df.columns:
        raise ValueError(f"Label column '{args.label_col}' not found.")

    df[args.label_col] = df[args.label_col].apply(_normalize_label)
    df = df.dropna(subset=[args.label_col]).copy()
    df[args.label_col] = df[args.label_col].astype(int)

    df = _coerce_numeric(df, args.label_col)

    non_numeric = df.drop(columns=[args.label_col]).select_dtypes(exclude=["number"]).columns
    if len(non_numeric) > 0:
        df = df.drop(columns=list(non_numeric))

    df = df.replace([float("inf"), float("-inf")], pd.NA)
    df = df.fillna(0)

    feature_cols = [c for c in df.columns if c != args.label_col]
    max_val = float(np.finfo("float32").max / 2)
    df[feature_cols] = df[feature_cols].clip(lower=-max_val, upper=max_val)
    df[feature_cols] = df[feature_cols].astype("float32")

    label_col = args.label_col
    feature_cols = [c for c in df.columns if c != label_col]
    df = df[feature_cols + [label_col]]

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    df.to_csv(args.output, index=False)

    feature_path = os.path.splitext(args.output)[0] + "_features.json"
    with open(feature_path, "w", encoding="utf-8") as handle:
        json.dump(feature_cols, handle, indent=2)

    counts = df[label_col].value_counts().to_dict()
    print(f"Saved cleaned dataset to: {args.output}")
    print(f"Features saved to: {feature_path}")
    print(f"Label counts: {counts}")


if __name__ == "__main__":
    main()
