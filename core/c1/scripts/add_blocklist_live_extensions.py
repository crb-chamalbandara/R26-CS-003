"""
C1 — add_blocklist_live_extensions.py  |  Live Blocklist Extension Importer
------------------------------------------------------------------------------
Purpose : Take the extension IDs from the finalized blocklist
          (malext_sentry + chrome_mal_ids) that are confirmed still live and
          downloadable from the Chrome Web Store (see
          scripts/README.md / blocklist_5cat_download_check.csv), fetch each
          one's full CRX, extract the complete 33-feature vector, label them
          malicious (1), and append to dataset_clean_v4.csv.

Role    : Consumes the audit CSV produced by the download-feasibility check
          (ext_id, reason, ok, has_signal) rather than re-deriving it, so the
          same vetting decision (only rows with real static signal) carries
          through to the actual training data.

Run from project root:
    python core/c1/scripts/add_blocklist_live_extensions.py
"""
from __future__ import annotations

import asyncio
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

C1_DIR   = ROOT / "core" / "c1"
DATA_DIR = C1_DIR / "data"

CHECK_CSV     = DATA_DIR / "blocklist_5cat_download_check.csv"
FEATURES_JSON = DATA_DIR / "dataset_clean_v3_features.json"
DATASET_CSV   = DATA_DIR / "dataset_clean_v4.csv"
AUDIT_OUT     = DATA_DIR / "blocklist_live_import_log.csv"


async def fetch_one(row, feat_cols, sem):
    from core.c1.crx_utils import fetch_crx_from_store, parse_crx_bytes
    from core.c1.features import extract_manifest_features, build_feature_vector

    ext_id = row["ext_id"].strip().lower()
    async with sem:
        last_exc = None
        for attempt in range(2):
            try:
                data = await fetch_crx_from_store(ext_id, timeout=10.0)
                manifest, source, _ = parse_crx_bytes(data, ext_id)
                features = extract_manifest_features(manifest, source or "")
                vector = build_feature_vector(feat_cols, features)
                result = dict(zip(feat_cols, vector))
                result["label"] = 1
                result["ext_id"] = ext_id
                result["reason"] = row["reason"]
                return result
            except Exception as exc:
                last_exc = exc
                if attempt < 1:
                    await asyncio.sleep(1.0)
        print(f"  FAILED {ext_id}: {last_exc}", flush=True)
        return None


async def main() -> None:
    with open(FEATURES_JSON, encoding="utf-8") as f:
        feat_cols: list = json.load(f)

    with open(CHECK_CSV, encoding="utf-8") as f:
        candidates = [r for r in csv.DictReader(f) if r["ok"] == "True" and r["has_signal"] == "True"]

    print(f"Re-fetching full feature vectors for {len(candidates)} confirmed-live, has-signal extensions...", flush=True)

    sem = asyncio.Semaphore(15)
    tasks = [fetch_one(row, feat_cols, sem) for row in candidates]

    import time
    start = time.time()
    results = []
    done = 0
    for coro in asyncio.as_completed(tasks):
        r = await coro
        done += 1
        if r is not None:
            results.append(r)
        if done % 25 == 0 or done == len(candidates):
            elapsed = time.time() - start
            rate = done / elapsed
            eta = (len(candidates) - done) / rate if rate > 0 else 0
            print(f"  {done}/{len(candidates)} processed ({len(results)} succeeded)  "
                  f"elapsed={elapsed:.0f}s  eta={eta:.0f}s", flush=True)
            # Checkpoint partial results so progress is never fully lost
            if results:
                import pandas as pd
                pd.DataFrame(results)[["ext_id", "reason", "label"]].to_csv(AUDIT_OUT, index=False)

    print(f"\nSucceeded: {len(results)} / {len(candidates)}", flush=True)

    if not results:
        print("Nothing to merge.")
        return

    import pandas as pd

    df_new = pd.DataFrame(results)
    df_existing = pd.read_csv(DATASET_CSV)
    before_total = len(df_existing)
    before_mal   = int((df_existing["label"] == 1).sum())
    before_ben   = int((df_existing["label"] == 0).sum())

    df_combined = pd.concat(
        [df_existing, df_new[feat_cols + ["label"]]], ignore_index=True
    )
    df_combined.to_csv(DATASET_CSV, index=False)

    after_mal = int((df_combined["label"] == 1).sum())
    after_ben = int((df_combined["label"] == 0).sum())

    print(f"\n{DATASET_CSV.name}: {before_total} -> {len(df_combined)} rows")
    print(f"  Malicious: {before_mal} -> {after_mal}  (+{after_mal - before_mal})")
    print(f"  Benign:    {before_ben} -> {after_ben}  (unchanged)")

    df_new[["ext_id", "reason", "label"]].to_csv(AUDIT_OUT, index=False)
    print(f"\nAudit log saved: {AUDIT_OUT.name}")


if __name__ == "__main__":
    asyncio.run(main())
