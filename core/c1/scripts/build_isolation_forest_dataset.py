"""
C1 — build_isolation_forest_dataset.py  |  Separate Unsupervised Dataset Builder
------------------------------------------------------------------------------------
Purpose : Build a genuinely independent, benign-only dataset for the
          Isolation Forest zero-day detector — separate from
          dataset_clean_v4.csv (which trains the supervised XGBoost model).

Source  : mandatoryprogrammer/chrome-extension-manifests-dataset — 103,773
          real manifest.json files scraped from the live Chrome Web Store.
          No JS source is available in this dataset, so only the 22
          manifest/permission features are populated; the 11 code-pattern
          features are 0 for every row here (this only affects training —
          at inference time, real extensions still get real code features).

Cleaning: excludes the 120 IDs independently confirmed to be on our own
          malicious blocklist (see manifest_dataset_contaminated_ids.csv).
          Residual, unknown contamination is expected to be small and is
          exactly what Isolation Forest's `contamination` parameter exists
          to tolerate — see scripts/README.md for the reasoning.

Run from project root:
    python core/c1/scripts/build_isolation_forest_dataset.py
"""
from __future__ import annotations

import csv
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

C1_DIR   = ROOT / "core" / "c1"
DATA_DIR = C1_DIR / "data"

MANIFESTS_DIR   = DATA_DIR / "chrome-extension-manifests-dataset" / "manifests"
CONTAMINATED_CSV = DATA_DIR / "manifest_dataset_contaminated_ids.csv"
FEATURES_JSON   = DATA_DIR / "dataset_clean_v3_features.json"
OUT_CSV         = DATA_DIR / "isolation_forest_benign_dataset.csv"


def main() -> None:
    from core.c1.features import extract_manifest_features, build_feature_vector

    with open(FEATURES_JSON, encoding="utf-8") as f:
        feat_cols: list = json.load(f)

    with open(CONTAMINATED_CSV, encoding="utf-8") as f:
        excluded_ids = {row["extension_id"].strip().lower() for row in csv.DictReader(f)}
    print(f"Excluding {len(excluded_ids)} known-malicious IDs from the manifest dataset.")

    with os.scandir(MANIFESTS_DIR) as it:
        entries = [e for e in it if e.name.endswith(".json")]
    print(f"Found {len(entries)} manifest files total.")

    rows = []
    skipped_excluded = 0
    skipped_unreadable = 0

    for i, entry in enumerate(entries, 1):
        ext_id = entry.name[:-5].lower()
        if ext_id in excluded_ids:
            skipped_excluded += 1
            continue
        try:
            with open(entry.path, encoding="utf-8", errors="ignore") as f:
                manifest = json.load(f)
        except Exception:
            skipped_unreadable += 1
            continue
        if not isinstance(manifest, dict):
            skipped_unreadable += 1
            continue

        features = extract_manifest_features(manifest, "")   # no JS source available
        vector = build_feature_vector(feat_cols, features)
        row = dict(zip(feat_cols, vector))
        row["label"] = 0     # every row here is treated as benign (see script docstring)
        rows.append(row)

        if i % 20000 == 0:
            print(f"  {i}/{len(entries)} processed...")

    print(f"\nParsed OK        : {len(rows)}")
    print(f"Excluded (known-bad): {skipped_excluded}")
    print(f"Skipped (unreadable): {skipped_unreadable}")

    import pandas as pd
    df = pd.DataFrame(rows)[feat_cols + ["label"]]
    df.to_csv(OUT_CSV, index=False)
    print(f"\nSaved: {OUT_CSV}  ({len(df)} rows, {len(feat_cols)} features)")


if __name__ == "__main__":
    main()
