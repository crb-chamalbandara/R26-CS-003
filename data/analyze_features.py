"""Feature analysis script for C3 component."""
import pandas as pd
import numpy as np
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FEATURE_ORDER = [
    "iat_mean_ms", "iat_cv", "iat_bowley_skewness", "iat_mad_ms",
    "requests_per_hour", "payload_size_mean", "payload_size_std", "http_post_ratio",
    "avg_idle_time_ms", "user_active_ratio", "background_tab_ratio",
    "extension_origin_ratio", "url_path_entropy", "request_burst_count",
]

TIMING_USED  = {"iat_mean_ms","iat_cv","iat_bowley_skewness","iat_mad_ms"}
BROWSER_USED = {"avg_idle_time_ms","user_active_ratio","background_tab_ratio","url_path_entropy"}
HEURISTIC_ONLY = {"requests_per_hour","payload_size_mean","payload_size_std",
                  "http_post_ratio","extension_origin_ratio","request_burst_count"}

GROUPS = {
    "iat_mean_ms":"IAT","iat_cv":"IAT","iat_bowley_skewness":"IAT","iat_mad_ms":"IAT",
    "requests_per_hour":"Volume","payload_size_mean":"Volume",
    "payload_size_std":"Volume","http_post_ratio":"Volume",
    "avg_idle_time_ms":"Browser","user_active_ratio":"Browser",
    "background_tab_ratio":"Browser","extension_origin_ratio":"Browser",
    "url_path_entropy":"Browser","request_burst_count":"Browser",
}

SEP = "=" * 72

# ── Section 1: Feature usage map ──────────────────────────────────────────────
print()
print(SEP)
print("  SECTION 1 -- Feature Usage Map  (14 total features)")
print(SEP)

pcap_cols = set(pd.read_csv(ROOT / "data" / "c3_extracted_v2.csv", nrows=1).columns)

print()
header = f"  {'#':<4} {'Feature':<26} {'Group':<8} {'TimingIF':<10} {'BrowserIF':<10} {'Heuristic':<10} {'PcapCSV'}"
print(header)
print(f"  {'-'*4} {'-'*26} {'-'*8} {'-'*10} {'-'*10} {'-'*10} {'-'*8}")

for i, feat in enumerate(FEATURE_ORDER, 1):
    t  = "YES" if feat in TIMING_USED  else "-"
    b  = "YES" if feat in BROWSER_USED else "-"
    h  = "YES(rules)" if feat in HEURISTIC_ONLY or feat in TIMING_USED or feat in BROWSER_USED else "-"
    pc = "YES" if feat in pcap_cols else "MISSING"
    flag = " <-- NOT used by any ML" if feat in HEURISTIC_ONLY else ""
    print(f"  F{i:02d}  {feat:<26} {GROUPS[feat]:<8} {t:<10} {b:<10} {h:<10} {pc}{flag}")

print()
print("  SUMMARY:")
print(f"    Timing model   uses: 4 features  -- F01 F02 F03 F04")
print(f"    Browser model  uses: 4 features  -- F09 F10 F11 F13")
print(f"    Used by ML (any):    8 of 14 features")
print(f"    NOT used by any ML:  6 features  -- F05 F06 F07 F08 F12 F14")
print(f"    (These 6 are only used in deterministic heuristic rules)")

# ── Section 2: Pcap dataset (c3_extracted_v2.csv) ─────────────────────────────
print()
print(SEP)
print("  SECTION 2 -- Pcap Dataset  (data/c3_extracted_v2.csv)")
print(SEP)

df = pd.read_csv(ROOT / "data" / "c3_extracted_v2.csv")
n_benign = (df["label"] == 0).sum()
n_beacon = (df["label"] == 1).sum()

print(f"\n  Rows: {len(df):,}  |  Benign: {n_benign:,}  |  Beacon: {n_beacon:,}")
print(f"  Columns ({len(df.columns)}): {list(df.columns)}")
print(f"  Null values: {df.isnull().sum().sum()}")
print()

available = [f for f in FEATURE_ORDER if f in df.columns]
missing_from_pcap = [f for f in FEATURE_ORDER if f not in df.columns]

print(f"  Features PRESENT in pcap CSV ({len(available)}):")
for feat in available:
    b_vals = df[df["label"]==0][feat]
    bc_vals = df[df["label"]==1][feat]
    print(f"    {feat:<26}  benign: mean={b_vals.mean():>12.2f}  beacon: mean={bc_vals.mean():>12.2f}")

print()
print(f"  Features MISSING from pcap CSV ({len(missing_from_pcap)}):")
for feat in missing_from_pcap:
    used_by = []
    if feat in BROWSER_USED:  used_by.append("Browser IF")
    if feat in HEURISTIC_ONLY: used_by.append("Heuristic")
    print(f"    {feat:<26}  -- used by: {', '.join(used_by) if used_by else 'nothing'}")

# ── Section 3: Collection dataset ─────────────────────────────────────────────
print()
print(SEP)
print("  SECTION 3 -- Browser Collection Datasets  (data/c3_collection*.csv)")
print(SEP)

col_paths = sorted((ROOT / "data").glob("c3_collection*.csv"))
col_frames = []
for p in col_paths:
    df_c = pd.read_csv(p)
    if len(df_c) > 0 and "label" in df_c.columns:
        col_frames.append(df_c)
        print(f"\n  File: {p.name}  ({len(df_c)} rows)")
        if "label" in df_c.columns:
            vc = df_c["label"].value_counts().sort_index()
            print(f"  Labels: {dict(vc)}")

if not col_frames:
    print("\n  No collection data found.")
else:
    df_col = pd.concat(col_frames, ignore_index=True)
    df_col = df_col[df_col["label"].notna()].copy()
    df_col["label"] = df_col["label"].astype(int)
    n_b = (df_col["label"]==0).sum()
    n_bc = (df_col["label"]==1).sum()
    print(f"\n  Combined: {len(df_col)} rows  |  Benign: {n_b}  |  Beacon: {n_bc}")

    browser_feats = [f for f in FEATURE_ORDER if f in df_col.columns]
    print()
    print(f"  {'Feature':<26} {'Type':<8} {'Benign mean':>12} {'Beacon mean':>12} {'Separation'}")
    print(f"  {'-'*26} {'-'*8} {'-'*12} {'-'*12} {'-'*15}")

    for feat in browser_feats:
        if feat == "label":
            continue
        b_mean  = df_col[df_col["label"]==0][feat].mean() if n_b > 0 else float("nan")
        bc_mean = df_col[df_col["label"]==1][feat].mean() if n_bc > 0 else float("nan")

        if feat in TIMING_USED:  ftype = "TimingIF"
        elif feat in BROWSER_USED: ftype = "BrowserIF"
        elif feat in HEURISTIC_ONLY: ftype = "Heuristic"
        else: ftype = "-"

        if not (pd.isna(b_mean) or pd.isna(bc_mean)):
            diff = abs(bc_mean - b_mean)
            sep = "HIGH" if diff > 0.5 * max(abs(b_mean), abs(bc_mean), 0.001) else "low"
        else:
            sep = "n/a"

        print(f"  {feat:<26} {ftype:<8} {b_mean:>12.4f} {bc_mean:>12.4f} {sep}")

    # Show which browser features have useful signal
    print()
    print("  Browser context feature signal quality:")
    for feat in BROWSER_USED:
        if feat in df_col.columns:
            b = df_col[df_col["label"]==0][feat]
            bc = df_col[df_col["label"]==1][feat]
            print(f"    {feat:<26}: benign={b.mean():.4f} (std={b.std():.4f})  beacon={bc.mean():.4f} (std={bc.std():.4f})")

print()
print(SEP)
print("  Analysis complete.")
print(SEP)
print()
