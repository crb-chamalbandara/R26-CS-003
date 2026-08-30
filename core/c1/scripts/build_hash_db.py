"""
C1 — build_hash_db.py  |  Blocklist Builder
--------------------------------------------
Purpose : Read a CSV of extension IDs with labels and extract all IDs
          labelled 'malicious' into malicious_ids.json.
Role    : Run ONCE during dataset preparation. The output JSON is used
          by analyzer.py as the first check before ML — any extension
          whose ID is in this list is instantly flagged MALICIOUS.

Run from project root:
    python core/c1/scripts/build_hash_db.py
"""
from __future__ import annotations

import argparse
import csv
import json
import os


def _normalize_header(name: str) -> str:
    """Clean a CSV column header — strip whitespace, BOM characters, and quotes."""
    return name.lower().strip().lstrip("﻿").strip('"').strip("'")


def main() -> None:
    # Accept command-line arguments so the input/output paths can be customised
    parser = argparse.ArgumentParser(description="Build malicious_ids.json for C1.")
    parser.add_argument(
        "--input",
        default=os.path.join("core", "c1", "data", "final_extention_id_lookup.csv"),
        help="CSV with extension_id and label columns",
    )
    parser.add_argument(
        "--output",
        default=os.path.join("core", "c1", "data", "malicious_ids.json"),
        help="Output JSON path",
    )
    parser.add_argument(
        "--include-mixed",
        action="store_true",
        help="Include mixed labels in the malicious ID list",
    )
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("CSV has no headers.")

        # Normalise all column headers so we can find them case-insensitively
        headers   = { _normalize_header(h): h for h in reader.fieldnames }
        id_key    = headers.get("extension_id")     # column that holds the 32-char extension ID
        label_key = headers.get("label")            # column that holds the malicious/benign label
        if not id_key or not label_key:
            raise ValueError("CSV must include extension_id and label columns.")

        malicious_ids = set()
        for row in reader:
            ext_id = str(row.get(id_key,    "")).strip().lower()
            label  = str(row.get(label_key, "")).strip().lower()
            if not ext_id:
                continue    # skip rows with no ID
            # Keep only confirmed malicious IDs (optionally include 'mixed' label too)
            if label == "malicious" or (args.include_mixed and label == "mixed"):
                malicious_ids.add(ext_id)

    # Write sorted list to JSON — sorted for reproducibility and easy visual inspection
    output = {"malicious_extension_ids": sorted(malicious_ids)}
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2)

    print(f"Saved {len(malicious_ids)} IDs to {args.output}")


if __name__ == "__main__":
    main()
