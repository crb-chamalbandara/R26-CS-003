"""
C1 — add_malcryptoext_data.py  |  MalCryptoExt Malicious Extension Importer
------------------------------------------------------------------------------
Purpose : Parse the .crx files downloaded from Trusted-System-Lab/MalCryptoExt
          (SIGMETRICS 2023 — "Characterizing Cryptocurrency-themed Malicious
          Browser Extensions"), extract the same 33 features used everywhere
          else in C1, label them malicious (1), and append them to
          dataset_clean_v4.csv.
Role    : Run ONCE to fold this new source in. Only .crx files are used —
          .xpi (Firefox) and .zip-wrapped files in the same download are
          skipped, since the Chrome CRX parser and this project's feature
          extractor are both built and validated against Chrome's manifest
          format specifically.

Run from project root:
    python core/c1/scripts/add_malcryptoext_data.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

C1_DIR   = ROOT / "core" / "c1"
DATA_DIR = C1_DIR / "data"

SOURCE_DIR    = DATA_DIR / "MalCryptoExt_malicious_extensions"
FEATURES_JSON = DATA_DIR / "dataset_clean_v3_features.json"
DATASET_CSV   = DATA_DIR / "dataset_clean_v4.csv"


def main() -> None:
    import json
    import pandas as pd

    from core.c1.crx_utils import parse_crx_file
    from core.c1.features import extract_manifest_features, build_feature_vector

    with open(FEATURES_JSON, encoding="utf-8") as f:
        feature_cols: list = json.load(f)

    crx_files = sorted(SOURCE_DIR.glob("*/*.crx"))
    print(f"Found {len(crx_files)} .crx files under {SOURCE_DIR.relative_to(ROOT)}\n")

    rows = []
    skipped = []
    for path in crx_files:
        category = path.parent.name
        try:
            manifest, source, ext_id = parse_crx_file(str(path))
            if not manifest:
                skipped.append((path.name, "empty/unreadable manifest"))
                continue
            features = extract_manifest_features(manifest, source or "")
            vector = build_feature_vector(feature_cols, features)
            row = dict(zip(feature_cols, vector))
            row["label"] = 1
            row["source_file"] = f"MalCryptoExt/{category}/{path.name}"
            rows.append(row)
        except Exception as exc:
            skipped.append((path.name, str(exc)[:80]))

    print(f"Parsed OK : {len(rows)}")
    print(f"Skipped   : {len(skipped)}")
    if skipped:
        for name, reason in skipped[:15]:
            print(f"  - {name}: {reason}")
        if len(skipped) > 15:
            print(f"  ... and {len(skipped) - 15} more")

    if not rows:
        print("\nNo rows parsed — nothing to merge.")
        return

    df_new = pd.DataFrame(rows)

    df_existing = pd.read_csv(DATASET_CSV)
    before_total = len(df_existing)
    before_mal   = int((df_existing["label"] == 1).sum())
    before_ben   = int((df_existing["label"] == 0).sum())

    df_combined = pd.concat(
        [df_existing, df_new[feature_cols + ["label"]]], ignore_index=True
    )
    df_combined.to_csv(DATASET_CSV, index=False)

    after_total = len(df_combined)
    after_mal   = int((df_combined["label"] == 1).sum())
    after_ben   = int((df_combined["label"] == 0).sum())

    print(f"\n{DATASET_CSV.name}: {before_total} -> {after_total} rows")
    print(f"  Malicious: {before_mal} -> {after_mal}  (+{after_mal - before_mal})")
    print(f"  Benign:    {before_ben} -> {after_ben}  (unchanged)")

    # Keep an audit trail of exactly which files contributed rows and from
    # which category, separate from the training CSV itself.
    audit_path = DATA_DIR / "malcryptoext_import_log.csv"
    pd.DataFrame(rows)[["source_file", "label"]].to_csv(audit_path, index=False)
    print(f"\nAudit log saved: {audit_path.name}")


if __name__ == "__main__":
    main()
