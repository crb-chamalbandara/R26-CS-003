"""
C1 — collect_modern_benign_mv3.py  |  Modern Benign MV3 Collector
------------------------------------------------------------------------------------
Why this exists
---------------
The supervised benign corpus (GoogleChromeExtension/benign) is a ~2019-era crawl:
832 of its 922 extensions are Manifest V2. The malicious corpus, by contrast,
contains plenty of modern MV3 samples. That asymmetry turns every *MV3-only*
permission into an accidental proxy for "malicious":

    has_scripting              benign 3.5%  vs malicious 21.4%
    has_declarativeNetRequest  benign 1.1%  vs malicious  9.3%

Neither permission is inherently dangerous — they are simply the MV3 replacements
for MV2 APIs. But because almost no benign training row could possibly have them,
XGBoost learned "scripting ⇒ malicious". That is what made Google Input Tools
(a Google-published, 3M-user extension) score 89.5% malicious: removing
has_scripting alone drops it to 4.2%.

The fix is to give the benign class a realistic population of modern MV3
extensions, so these permissions stop correlating with the label.

Source of IDs
-------------
chrome-extension-manifests-dataset/manifests/ — 103,773 real Chrome Web Store
extension IDs. Their *stored* manifests are old (MV2-era), but the extensions
themselves are live and most have since migrated to MV3, so downloading the
CRX today yields a current, genuinely benign MV3 sample.

Safety
------
  * Excludes the 120 IDs confirmed against our malicious blocklist, and
    cross-checks every ID against the full 6,656-entry finalized blocklist.
  * Writes to its OWN csv — never touches dataset_clean_v4.csv or any model.
  * Checkpoints every CHECKPOINT_EVERY rows, so an interrupted run keeps its work
    (a lesson from a previous run that lost 89 completed lookups).
  * Aborts automatically if the recent failure rate spikes, which is how Google's
    update server signals rate-limiting. Re-running resumes where it left off.

Run from project root:
    python core/c1/scripts/collect_modern_benign_mv3.py --target 500
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

C1_DIR = ROOT / "core" / "c1"
DATA_DIR = C1_DIR / "data"

MANIFESTS_DIR = DATA_DIR / "chrome-extension-manifests-dataset" / "manifests"
CONTAMINATED_CSV = DATA_DIR / "manifest_dataset_contaminated_ids.csv"
BLOCKLIST_CSV = DATA_DIR / "malext_sentry and chrome_mal_ids Finalized Blocklist IDs.csv"
FEATURES_JSON = DATA_DIR / "dataset_clean_v3_features.json"
OUT_CSV = DATA_DIR / "benign_modern_mv3_extensions.csv"

CHECKPOINT_EVERY = 25
# If this many of the last WINDOW attempts fail, assume rate-limiting and stop.
FAIL_WINDOW = 40
FAIL_ABORT_RATE = 0.85


def _load_excluded() -> set[str]:
    excluded: set[str] = set()
    if CONTAMINATED_CSV.exists():
        with open(CONTAMINATED_CSV, encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                excluded.add(row["extension_id"].strip().lower())
    # Full finalized blocklist — cp1252 is an Excel export artifact, not a typo.
    if BLOCKLIST_CSV.exists():
        with open(BLOCKLIST_CSV, encoding="cp1252", errors="ignore") as fh:
            for row in csv.DictReader(fh):
                for key in ("extension_id", "Extension ID", "id", "ID"):
                    if key in row and row[key]:
                        excluded.add(str(row[key]).strip().lower())
                        break
    return excluded


async def _fetch_one(ext_id: str, sem: asyncio.Semaphore, feat_cols: list) -> dict | None:
    from core.c1.crx_utils import fetch_crx_from_store, parse_crx_bytes
    from core.c1.features import extract_manifest_features, build_feature_vector

    async with sem:
        try:
            data = await asyncio.wait_for(fetch_crx_from_store(ext_id, timeout=20.0), timeout=25)
            manifest, source, _ = parse_crx_bytes(data, ext_id)
            if not isinstance(manifest, dict):
                return None
            features = extract_manifest_features(manifest, source or "")
            row = dict(zip(feat_cols, build_feature_vector(feat_cols, features)))
            row["label"] = 0
            row["extension_id"] = ext_id
            row["manifest_version"] = int(manifest.get("manifest_version", 0) or 0)
            return row
        except Exception:
            return None


def _save(rows: list, feat_cols: list) -> None:
    if not rows:
        return
    import pandas as pd

    cols = feat_cols + ["label", "extension_id", "manifest_version"]
    pd.DataFrame(rows)[cols].to_csv(OUT_CSV, index=False)


async def main_async(target: int, concurrency: int, seed: int) -> None:
    feat_cols: list = json.load(open(FEATURES_JSON, encoding="utf-8"))

    excluded = _load_excluded()
    print(f"Excluding {len(excluded)} known-bad extension IDs.", flush=True)

    # Resume support — keep anything a previous run already collected.
    existing_rows: list = []
    done_ids: set[str] = set()
    if OUT_CSV.exists():
        import pandas as pd

        df_prev = pd.read_csv(OUT_CSV)
        existing_rows = df_prev.to_dict("records")
        done_ids = {str(r["extension_id"]).lower() for r in existing_rows}
        print(f"Resuming — {len(existing_rows)} rows already collected.", flush=True)

    with os.scandir(MANIFESTS_DIR) as it:
        all_ids = [e.name[:-5].lower() for e in it if e.name.endswith(".json")]
    candidates = [i for i in all_ids if i not in excluded and i not in done_ids]
    random.Random(seed).shuffle(candidates)
    print(f"{len(candidates)} candidate IDs available.", flush=True)

    rows = list(existing_rows)
    sem = asyncio.Semaphore(concurrency)
    recent: list[bool] = []
    attempted = 0
    idx = 0
    batch = concurrency * 3

    while len([r for r in rows if r.get("manifest_version") == 3]) < target and idx < len(candidates):
        chunk = candidates[idx: idx + batch]
        idx += batch
        results = await asyncio.gather(*[_fetch_one(c, sem, feat_cols) for c in chunk])
        for res in results:
            attempted += 1
            recent.append(res is not None)
            if res is not None:
                rows.append(res)
        recent = recent[-FAIL_WINDOW:]

        n_mv3 = len([r for r in rows if r.get("manifest_version") == 3])
        pct = min(100.0, n_mv3 / target * 100)
        print(f"  attempted={attempted:5d}  collected={len(rows):5d}  MV3={n_mv3:5d}/{target}  ({pct:5.1f}%)", flush=True)

        if len(rows) % CHECKPOINT_EVERY < batch:
            _save(rows, feat_cols)

        if len(recent) >= FAIL_WINDOW and (1 - sum(recent) / len(recent)) >= FAIL_ABORT_RATE:
            print("\nABORT: failure rate spiked — Google is rate-limiting. "
                  "Progress saved; re-run later to resume.", flush=True)
            break

    _save(rows, feat_cols)
    n_mv3 = len([r for r in rows if r.get("manifest_version") == 3])
    n_mv2 = len([r for r in rows if r.get("manifest_version") == 2])
    print(f"\nSaved {len(rows)} benign rows to {OUT_CSV}", flush=True)
    print(f"  Manifest V3 : {n_mv3}", flush=True)
    print(f"  Manifest V2 : {n_mv2}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="Collect modern benign MV3 extensions for C1 training.")
    ap.add_argument("--target", type=int, default=500, help="Target number of MV3 benign samples.")
    ap.add_argument("--concurrency", type=int, default=6)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    asyncio.run(main_async(args.target, args.concurrency, args.seed))


if __name__ == "__main__":
    main()
