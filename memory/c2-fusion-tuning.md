---
name: c2-fusion-tuning
description: Why C2 fusion weights must NOT be tuned on batch-captured vectors
metadata:
  type: project
---

C2 fusion tuning (`scripts/tune_fusion.py`) trains on six-layer vectors captured by
`scripts/capture_fusion_vectors.py`. **Batch capture renders saved HTML headless, which
mis-represents the runtime (L6) and visual (L3) layers**: `set_content` gives an
`about:blank` origin so L6's off-origin-exfil check fires on legit pages too (L6 ≈ 0.77
legit vs 0.71 phish — inverted), and L3 pHash on saved-page screenshots is noise.

Consequence: a fusion model learned from batch vectors zeroes out L6/L3 (observed:
weights L1=0.42 L2=0.45 L4=0.12 L3=0.02 L5=0 **L6=0**, meta-AUC 0.967). Applying that would
make production IGNORE the runtime layer — regressing live BitB detection, which is exactly
what L6 is for (L6 IS discriminative on real live navigation; see test_layer6_runtime).

**Rule:** never `tune_fusion.py --apply` on batch-captured data. Production stays on the
weighted-sum fusion with the default 6-layer weights (L6=0.15) + retuned L1/L2 models.
Proper fusion tuning needs vectors logged from LIVE navigation of real URLs (run the app and
record per-page layer scores), not batch-rendered snapshots. tune_fusion is dry-run by
default for this reason. See [[c2-component-owner]].
