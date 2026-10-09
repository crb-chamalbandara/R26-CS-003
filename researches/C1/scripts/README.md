# C1 Phase 1 ML Scripts

## Build manifest/code dataset from CRX

```bash
python core/c1/scripts/build_manifest_dataset.py \
  --benign-dir core/c1/data/GoogleChromeExtension/benign/benign \
  --malware-dir core/c1/data/GoogleChromeExtension/malware/malware \
  --output core/c1/data/manifest_dataset.csv
```

## Prepare the dataset

```bash
python core/c1/scripts/prepare_data.py \
  --input core/c1/data/manifest_dataset.csv \
  --output core/c1/data/dataset_clean.csv \
  --label-col label
```

## Train the model

```bash
python core/c1/scripts/train_model.py \
  --input core/c1/data/dataset_clean.csv \
  --model-out core/c1/models/extension_detector_model.pkl \
  --label-col label
```

## Train the zero-day anomaly detector (Isolation Forest) — separate dataset

**Current / correct approach**, as of 2026-08-28. Isolation Forest is a one-class
novelty detector: it needs no malicious labels, only a large, mostly-benign pool
to learn what "normal" looks like. It is deliberately trained on its **own
dataset**, independent from `dataset_clean_v4.csv` (the supervised XGBoost
dataset) — see `core/c1/ARCHITECTURE.md`'s "Isolation Forest dataset" section for
the full reasoning.

```bash
# One-time: build the separate benign-only dataset from a large real-world
# manifest collection (currently mandatoryprogrammer/chrome-extension-manifests-dataset,
# cloned into core/c1/data/chrome-extension-manifests-dataset/). Cross-matches
# against our own blocklist and excludes any known-bad IDs found.
python core/c1/scripts/build_isolation_forest_dataset.py

# Train + evaluate. Evaluation borrows dataset_clean_v4.csv's malicious rows
# ONLY to measure catch-rate — they are never trained on.
python core/c1/scripts/train_isolation_forest_separate.py
```

`contamination` defaults to 0.02. The anomaly-flag threshold lives in
`analyzer.py` (`ISO_FOREST_ANOMALY_THRESHOLD`, currently 60) — re-run
`train_isolation_forest_separate.py`'s "[3] Known complex benign extensions"
check after any retrain to confirm real extensions like Adobe Acrobat, LastPass,
1Password etc. still stay under whatever threshold is set before shipping.

**Legacy approach** (`train_isolation_forest.py`, filters `dataset_clean_v4.csv`
down to its own benign rows) is kept for reference/fallback only — it couples the
two models' training data together, which is exactly what the separate-dataset
design above avoids. Prefer `train_isolation_forest_separate.py` going forward.

## Expand the XGBoost benign training set (false-positive reduction)

```bash
python core/c1/scripts/collect_benign_power_extensions.py
python core/c1/scripts/retrain_with_new_data.py
```

`collect_benign_power_extensions.py` downloads real CRX files for well-known,
verified-safe extensions with complex permission profiles and adds them to the
benign training set — this is what stopped the model flagging Adobe Acrobat as
89% malicious. Add more IDs to `KNOWN_BENIGN_POWER` as new false-positive cases
turn up. It retries transient network failures and merges with whatever was
already downloaded on a prior run, so a partial failure never destroys previously
collected data. This only affects the XGBoost dataset — Isolation Forest's
separate dataset is unaffected and does not need re-syncing.

## Complete missing evidence in the finalized blocklist

```bash
python -m core.c1.scripts.backfill_blocklist_evidence --limit 50
python -m core.c1.scripts.backfill_blocklist_evidence --all --concurrency 8
python -m core.c1.scripts.backfill_blocklist_evidence --limit 10 --sandbox
python -m core.c1.scripts.backfill_blocklist_evidence --ids abc...,def... --dry-run
```

`malext_sentry and chrome_mal_ids Finalized Blocklist IDs.csv` merges an
evidenced source with an ID-only dump, so ~3,000 of its 6,656 rows carry
placeholder text (`Not Found`, `Not yet confirmed`, `Not Confirmed`, `N/A`) in
at least one evidence column. This script downloads each of those extensions,
runs the same stack a live intercept runs (33 features -> XGBoost -> rule
boosters -> Isolation Forest, plus the dynamic sandbox with `--sandbox`),
derives the threat class from what they observed, and writes the completed row
back to the CSV. Every changed cell is appended to
`data/blocklist_enrichment_log.csv` with its old value, new value, confidence
and method.

Run it with `--dry-run` first if you want to see what it would write without
touching the sheet.

**Most undocumented IDs are undocumented because the store already removed the
extension** — the CRX simply cannot be downloaded any more. Those rows come back
`unavailable` and are left exactly as they were; a row with an honest gap is
better than one filled with a guess. Where `data/chrome-extension-manifests-dataset`
still holds the archived manifest, the script falls back to it and derives from
declared capability alone (the XGBoost probability is excluded in that mode,
since 11 of the 33 features are code counts that would all read zero without the
JavaScript).

The same work happens automatically, with the sandbox, whenever someone tries to
install an under-reported extension in the live browser session — see
`ARCHITECTURE.md` §1a.
