"""
Rebuild data/c3_extracted_v2.csv from real network datasets.

Sources:
  BENIGN  — CIC-IDS 2017 CSVs (existing 9,000 rows, kept as-is)
            + CTU-13 binetflow Normal flows (~500 extra rows for diversity)
  BEACON  — CTU-13 binetflow C&C-labeled flows (all 13 scenarios)

Output columns (6 only — no dead weight):
  label, request_count, iat_mean_ms, iat_cv, iat_bowley_skewness, iat_mad_ms

Design decisions:
  - requests_per_hour EXCLUDED: benign RPH spans 80 to 3.3B (extreme CIC-IDS skew)
    vs beacon RPH 24-344. Capping introduces arbitrary choices. IAT features
    carry the same signal more cleanly.
  - payload_size_mean/std EXCLUDED: CTU-13 beacon rows have no payload tracking
    (always 0.0). Including it creates false signal — model learns "payload=0
    means beacon" which is a data collection artifact, not real.
  - Browser context columns (avg_idle_time_ms etc.) EXCLUDED: all-zero in
    both CIC-IDS and CTU-13 — no training signal.
"""
from __future__ import annotations

import csv
import sys
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

BINETFLOW_BASE = Path("D:/DATA set/CTU-13-Dataset/CTU-13-Dataset")
CURRENT_CSV    = Path("data/c3_extracted_v2.csv")
OUTPUT_CSV     = Path("data/c3_extracted_v2.csv")

OUTPUT_COLS = ["label", "request_count", "iat_mean_ms", "iat_cv", "iat_bowley_skewness", "iat_mad_ms"]

SCENARIOS = [
    ("1",  "capture20110810.binetflow"),   # Neris
    ("2",  "capture20110811.binetflow"),   # Neris
    ("3",  "capture20110812.binetflow"),   # Rbot
    ("4",  "capture20110815.binetflow"),   # Rbot
    ("5",  "capture20110815-2.binetflow"), # Virut
    ("6",  "capture20110816.binetflow"),   # Menti
    ("7",  "capture20110816-2.binetflow"), # Sogou
    ("8",  "capture20110816-3.binetflow"), # Murlo
    ("9",  "capture20110817.binetflow"),   # Neris
    ("10", "capture20110818.binetflow"),   # Rbot
    ("11", "capture20110818-2.binetflow"), # Rbot
    ("12", "capture20110819.binetflow"),   # NsisAy
    ("13", "capture20110815-3.binetflow"), # Virut
]

MIN_FLOWS_PER_GROUP = 5     # lowered from 8 — still reliable at 5+ flows
WINDOW_MINUTES      = 20    # 20-min sliding window for IAT grouping
CTU_BENIGN_PER_SC   = 50    # benign rows to extract per CTU-13 scenario


# ── statistical helpers ──────────────────────────────────────────────────────

def bowley_skewness(iats: np.ndarray) -> float:
    if len(iats) < 4:
        return 0.0
    q1, q2, q3 = np.percentile(iats, [25, 50, 75])
    denom = q3 - q1
    if denom == 0:
        return 0.0
    return float((q1 + q3 - 2 * q2) / denom)


def compute_iat_features(iats_ms: list[float]) -> dict | None:
    arr = np.array(iats_ms, dtype=float)
    arr = arr[arr > 0]
    if len(arr) < 3:
        return None
    mean = float(np.mean(arr))
    std  = float(np.std(arr))
    cv   = std / mean if mean > 0 else 0.0
    mad  = float(np.median(np.abs(arr - np.median(arr))))
    skew = bowley_skewness(arr)
    return {
        "iat_mean_ms":         round(mean, 4),
        "iat_cv":              round(cv,   6),
        "iat_bowley_skewness": round(skew, 6),
        "iat_mad_ms":          round(mad,  4),
        "request_count":       len(arr) + 1,
    }


# ── binetflow parser ──────────────────────────────────────────────────────────

def parse_binetflow(path: Path):
    """Yield (start_dt, src, dst, dport, label) for every parseable flow."""
    with open(path, "r", errors="replace") as fh:
        reader = csv.reader(fh)
        header = None
        for row in reader:
            if header is None:
                header = [h.strip().lower() for h in row]
                try:
                    idx_time  = header.index("starttime")
                    idx_src   = header.index("srcaddr")
                    idx_dst   = header.index("dstaddr")
                    idx_dport = header.index("dport")
                    idx_label = header.index("label")
                except ValueError as e:
                    print(f"    [skip] {path.name}: missing column {e}")
                    return
                continue
            if len(row) <= max(idx_time, idx_src, idx_dst, idx_dport, idx_label):
                continue
            try:
                dt  = datetime.strptime(row[idx_time].strip(), "%Y/%m/%d %H:%M:%S.%f")
                src = row[idx_src].strip()
                dst = row[idx_dst].strip()
                dp  = row[idx_dport].strip()
                lbl = row[idx_label].strip()
            except (ValueError, IndexError):
                continue
            yield dt, src, dst, dp, lbl


# ── beacon extraction ─────────────────────────────────────────────────────────

def extract_beacon_rows(scenario: str, filename: str) -> list[dict]:
    path = BINETFLOW_BASE / scenario / filename
    if not path.exists():
        print(f"    [skip] {path} not found")
        return []

    cc_flows: dict[tuple, list] = {}
    total_read = total_cc = 0
    for dt, src, dst, dport, lbl in parse_binetflow(path):
        total_read += 1
        if "Botnet" in lbl and ("CC" in lbl or "C&C" in lbl.upper()):
            key = (src, dst)
            cc_flows.setdefault(key, []).append(dt)
            total_cc += 1

    print(f"    Scenario {scenario:>2}: {total_read:,} flows, {total_cc} CC flows, "
          f"{len(cc_flows)} (src,dst) pairs")

    rows: list[dict] = []
    window_sec = WINDOW_MINUTES * 60

    for (src, dst), timestamps in cc_flows.items():
        timestamps.sort()
        if len(timestamps) < MIN_FLOWS_PER_GROUP:
            continue

        i = 0
        while i < len(timestamps):
            window: list[datetime] = []
            for j in range(i, len(timestamps)):
                if (timestamps[j] - timestamps[i]).total_seconds() <= window_sec:
                    window.append(timestamps[j])
                else:
                    break
            if len(window) >= MIN_FLOWS_PER_GROUP:
                iats_ms = [
                    (window[k + 1] - window[k]).total_seconds() * 1000
                    for k in range(len(window) - 1)
                ]
                feats = compute_iat_features(iats_ms)
                if feats is not None:
                    rows.append({
                        "label":              1,
                        "request_count":      feats["request_count"],
                        "iat_mean_ms":        feats["iat_mean_ms"],
                        "iat_cv":             feats["iat_cv"],
                        "iat_bowley_skewness": feats["iat_bowley_skewness"],
                        "iat_mad_ms":         feats["iat_mad_ms"],
                    })
            # Advance by half the window (50% overlap) for maximum coverage
            step = max(1, len(window) // 2)
            i += step

    return rows


# ── benign extraction from CTU-13 normal flows ───────────────────────────────

def extract_benign_rows(scenario: str, filename: str, max_rows: int) -> list[dict]:
    path = BINETFLOW_BASE / scenario / filename
    if not path.exists():
        return []

    normal_flows: dict[tuple, list] = {}
    for dt, src, dst, dport, lbl in parse_binetflow(path):
        if "Normal" in lbl and "Botnet" not in lbl:
            key = (src, dst, dport)
            normal_flows.setdefault(key, []).append(dt)
            if sum(len(v) for v in normal_flows.values()) > max_rows * 20:
                break

    rows: list[dict] = []
    for (src, dst, dport), timestamps in list(normal_flows.items()):
        if len(rows) >= max_rows:
            break
        timestamps.sort()
        if len(timestamps) < MIN_FLOWS_PER_GROUP:
            continue
        iats_ms = [
            (timestamps[k + 1] - timestamps[k]).total_seconds() * 1000
            for k in range(len(timestamps) - 1)
        ]
        feats = compute_iat_features(iats_ms)
        if feats is None:
            continue
        rows.append({
            "label":               0,
            "request_count":       feats["request_count"],
            "iat_mean_ms":         feats["iat_mean_ms"],
            "iat_cv":              feats["iat_cv"],
            "iat_bowley_skewness": feats["iat_bowley_skewness"],
            "iat_mad_ms":          feats["iat_mad_ms"],
        })
    return rows


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 60)
    print("  C3 Dataset Rebuilder")
    print("  Sources: CTU-13 (beacon) + CIC-IDS 2017 (benign)")
    print("=" * 60)

    # 1. Load CIC-IDS benign rows — keep the 4 IAT columns only
    print("\n[1/4] Loading CIC-IDS benign rows ...")
    df_old = pd.read_csv(CURRENT_CSV)
    benign_old = df_old[df_old["label"] == 0][
        ["label", "request_count", "iat_mean_ms", "iat_cv", "iat_bowley_skewness", "iat_mad_ms"]
    ].copy()
    # Drop rows with degenerate IAT (iat_mean_ms <= 0)
    benign_old = benign_old[benign_old["iat_mean_ms"] > 0].reset_index(drop=True)
    print(f"    Kept {len(benign_old):,} CIC-IDS benign rows")

    # 2. Extract CTU-13 beacon rows
    print(f"\n[2/4] Extracting CTU-13 C&C beacon rows (MIN_FLOWS={MIN_FLOWS_PER_GROUP}) ...")
    all_beacon: list[dict] = []
    for scenario, filename in SCENARIOS:
        rows = extract_beacon_rows(scenario, filename)
        all_beacon.extend(rows)
        print(f"      => {len(rows)} beacon rows")

    df_beacon = pd.DataFrame(all_beacon, columns=OUTPUT_COLS)
    # Remove degenerate rows
    df_beacon = df_beacon[df_beacon["iat_mean_ms"] > 0].reset_index(drop=True)
    print(f"\n    Total beacon rows: {len(df_beacon)}")
    if len(df_beacon) > 0:
        print(f"    iat_cv: min={df_beacon['iat_cv'].min():.4f}  "
              f"mean={df_beacon['iat_cv'].mean():.4f}  "
              f"max={df_beacon['iat_cv'].max():.4f}")
        print(f"    iat_cv == 0: {(df_beacon['iat_cv'] == 0).sum()} rows")

    if len(df_beacon) < 50:
        print("    [WARNING] Very few beacon rows — check CTU-13 paths.")

    # 3. Extract CTU-13 normal (benign) flows for diversity
    print(f"\n[3/4] Extracting CTU-13 normal benign rows ({CTU_BENIGN_PER_SC}/scenario) ...")
    all_ctu_benign: list[dict] = []
    for scenario, filename in SCENARIOS:
        rows = extract_benign_rows(scenario, filename, CTU_BENIGN_PER_SC)
        all_ctu_benign.extend(rows)
    df_ctu_benign = pd.DataFrame(all_ctu_benign, columns=OUTPUT_COLS)
    df_ctu_benign = df_ctu_benign[df_ctu_benign["iat_mean_ms"] > 0].reset_index(drop=True)
    print(f"    CTU-13 benign rows: {len(df_ctu_benign)}")

    # 4. Assemble and save
    print("\n[4/4] Assembling final dataset ...")
    frames = [benign_old, df_ctu_benign, df_beacon]
    df_final = pd.concat(frames, ignore_index=True)
    df_final = df_final.dropna().reset_index(drop=True)
    # Shuffle
    df_final = df_final.sample(frac=1, random_state=42).reset_index(drop=True)

    df_final.to_csv(OUTPUT_CSV, index=False)

    n_benign = (df_final["label"] == 0).sum()
    n_beacon = (df_final["label"] == 1).sum()
    print(f"\n  Saved {len(df_final):,} rows => {OUTPUT_CSV}")
    print(f"  Benign : {n_benign:,}  ({n_benign/len(df_final)*100:.1f}%)")
    print(f"  Beacon : {n_beacon:,}  ({n_beacon/len(df_final)*100:.1f}%)")
    print(f"  Columns: {OUTPUT_COLS}")
    print()
    if n_beacon > 0:
        cv = df_final[df_final["label"] == 1]["iat_cv"]
        print("  Beacon iat_cv distribution:")
        print(f"    zero   : {(cv == 0).sum()}")
        print(f"    0-0.1  : {((cv > 0) & (cv <= 0.1)).sum()}")
        print(f"    0.1-0.5: {((cv > 0.1) & (cv <= 0.5)).sum()}")
        print(f"    0.5-1.0: {((cv > 0.5) & (cv <= 1.0)).sum()}")
        print(f"    > 1.0  : {(cv > 1.0).sum()}")
    print()
    print("  Done. Run train_c3.bat to retrain the model.")
    print("=" * 60)


if __name__ == "__main__":
    main()
