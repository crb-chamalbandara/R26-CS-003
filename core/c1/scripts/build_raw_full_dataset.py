"""
Convert dataset_clean_v4.csv (numeric) into a human-readable raw version
for viva demonstration.

Same 1,259 rows, same 33 features + label, but:
  - Binary permission flags  0.0/1.0  →  NO / YES
  - Count features           7.0      →  7  (kept as integer)
  - Entropy                  4.23     →  4.23  (2 decimal places)
  - Label                    0 / 1    →  BENIGN / MALICIOUS

Run from project root:
    python core/c1/scripts/build_raw_full_dataset.py
"""
import os, sys
import pandas as pd
import numpy as np
from pathlib import Path

ROOT     = Path(__file__).resolve().parents[3]
DATA_DIR = ROOT / "core" / "c1" / "data"
IN_CSV   = DATA_DIR / "dataset_clean_v4.csv"
OUT_CSV  = DATA_DIR / "dataset_raw_v4.csv"

# ── Feature groups ────────────────────────────────────────────────────────────
# These 22 columns are binary flags (0 = NO, 1 = YES)
BINARY_COLS = [
    "has_webRequest",
    "has_all_urls",
    "has_cookies",
    "has_clipboardRead",
    "has_nativeMessaging",
    "has_tabs",
    "has_history",
    "has_downloads",
    "has_storage",
    "has_background_script",
    "has_content_scripts",
    "has_webRequestBlocking",
    "has_scripting",
    "has_management",
    "has_webNavigation",
    "has_contextMenus",
    "has_proxy",
    "has_declarativeNetRequest",
    "web_accessible_resources",
    "keydown_listener",   # 0 = no keyboard listener, 1 = has keyboard listener
]

# These 11 columns are raw counts (already natural numbers — keep as int)
COUNT_COLS = [
    "host_permission_count",
    "total_permission_count",
    "eval_count",
    "atob_count",
    "function_ctor_count",
    "xhr_fetch_count",
    "websocket_count",
    "exec_script_count",
    "cookie_in_code",
    "long_string_count",
    "hex_escape_count",
    "external_url_count",
]

# Shannon entropy — continuous float, keep rounded to 2 dp
ENTROPY_COL = "content_script_entropy"


def main():
    print(f"Reading: {IN_CSV.name}")
    df = pd.read_csv(IN_CSV)
    print(f"Shape  : {df.shape}  ({df.shape[0]} rows × {df.shape[1]} columns)")
    print(f"Label  : {df['label'].value_counts().to_dict()}")

    raw = df.copy()

    # ── 1. Convert binary flags  0/1 → NO/YES ───────────────────────────────
    for col in BINARY_COLS:
        if col in raw.columns:
            raw[col] = raw[col].apply(lambda v: "YES" if float(v) >= 1.0 else "NO")

    # ── 2. Count columns — keep as clean integers ────────────────────────────
    for col in COUNT_COLS:
        if col in raw.columns:
            raw[col] = raw[col].apply(lambda v: int(round(float(v))))

    # ── 3. Entropy — round to 2 decimal places ───────────────────────────────
    if ENTROPY_COL in raw.columns:
        raw[ENTROPY_COL] = raw[ENTROPY_COL].apply(lambda v: round(float(v), 2))

    # ── 4. Label  0/1  →  BENIGN / MALICIOUS ────────────────────────────────
    raw["label"] = raw["label"].apply(lambda v: "MALICIOUS" if int(v) == 1 else "BENIGN")

    # ── 5. Save ───────────────────────────────────────────────────────────────
    raw.to_csv(OUT_CSV, index=False)

    print(f"\nSaved : {OUT_CSV}")
    print(f"Rows  : {len(raw)}  "
          f"(BENIGN: {(raw.label=='BENIGN').sum()}, "
          f"MALICIOUS: {(raw.label=='MALICIOUS').sum()})")
    print(f"Cols  : {len(raw.columns) - 1} features + 1 label = {len(raw.columns)} total")

    # ── Preview ───────────────────────────────────────────────────────────────
    print("\n─── Sample MALICIOUS rows (5) ──────────────────────────────────────────")
    mal_cols = ["has_webRequest","has_all_urls","has_cookies","has_nativeMessaging",
                "eval_count","atob_count","xhr_fetch_count","keydown_listener",
                "cookie_in_code","host_permission_count","label"]
    print(raw[raw.label=="MALICIOUS"][mal_cols].head(5).to_string(index=True))

    print("\n─── Sample BENIGN rows (5) ─────────────────────────────────────────────")
    print(raw[raw.label=="BENIGN"][mal_cols].head(5).to_string(index=True))

    print("\n─── Value types after conversion ───────────────────────────────────────")
    for col in BINARY_COLS[:3]:
        if col in raw.columns:
            print(f"  {col:30s}: {sorted(raw[col].unique())}  (binary → YES/NO)")
    for col in COUNT_COLS[:3]:
        if col in raw.columns:
            print(f"  {col:30s}: range {raw[col].min()}–{raw[col].max()}  (count)")
    print(f"  {ENTROPY_COL:30s}: range {raw[ENTROPY_COL].min()}–{raw[ENTROPY_COL].max()}  (entropy float)")
    print(f"  {'label':30s}: {sorted(raw['label'].unique())}  (class)")

    print("\nDone.")


if __name__ == "__main__":
    main()
