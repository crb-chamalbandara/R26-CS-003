# C2 — Evaluation & Tuning

All numbers below are from this session's runs; raw outputs are in [`artifacts/`](artifacts/).

## 1. Benchmark harness

[`scripts/evaluate_c2.py`](../../scripts/evaluate_c2.py) scores the detection layers over the
labelled **Mendeley** corpus (≈80k HTML snapshots with `index.sql` labels, phishing=1/legit=0) and
reports per-layer ROC/AUC, the fused score, and the confusion matrix / precision / recall / F1.
It runs in **static mode** (DOM/URL layers L1/L2/L4); L3/L5/L6 need a live browser and are scored 0
here. Run sample: **600 pages (300 phishing / 300 legit)**.

### Per-layer (AUC / AP) — [`artifacts/metrics.json`](artifacts/metrics.json), [`artifacts/roc.png`](artifacts/roc.png)

| Layer | AUC | AP |
|-------|-----|----|
| L1 (BitB DOM + ML) | **0.9577** | 0.9595 |
| L2 (URL classifier) | **0.9075** | 0.9219 |
| L4 (form destination) | 0.5161 | 0.5303 |
| **Fused** | **0.9693** | — |

### Fused operating points — [`artifacts/confusion.png`](artifacts/confusion.png)

| Threshold | Precision | Recall | F1 | Confusion `[[TN,FP],[FN,TP]]` |
|-----------|-----------|--------|----|-------------------------------|
| SUSPICIOUS ≥ 30 | 0.976 | 0.673 | 0.797 | `[[295,5],[98,202]]` |
| PHISHING ≥ 60 | 0.000 | 0.000 | 0.000 | `[[300,0],[300,0]]` |

**Under-flagging finding.** In static mode *nothing* reaches the PHISHING cutoff of 60 — the
fused score cannot get there from L1/L2/L4 alone (L3/L5/L6 = 0). This quantified the original
hand-set weighting/threshold problem and motivated the configurable + tuned fusion.

## 2. Per-model tuning — [`artifacts/tuning.json`](artifacts/tuning.json)

[`scripts/tune_models.py`](../../scripts/tune_models.py) runs `RandomizedSearchCV` over XGBoost
hyperparameters (stratified 3-fold, F1-scored) for L1 and L2, picks the best F1 decision threshold
from the PR curve, and saves the retuned models (old ones backed up to `*.pkl.bak`). Retraining in
the current environment also cleared the sklearn/xgboost version-mismatch warnings.

| Model | CV F1 | Test AUC | F1@0.5 | Best thr | F1@best |
|-------|-------|----------|--------|----------|---------|
| L1 BitB | 0.8933 | **0.9637** | 0.905 | 0.433 | 0.907 |
| L2 URL | 0.7749 | **0.9022** | 0.784 | 0.489 | 0.785 |

Best params (e.g. L1: `max_depth=7, n_estimators=489, lr≈0.105`) are recorded in the artifact.

## 3. Fusion tuning — [`artifacts/tuning_fusion.json`](artifacts/tuning_fusion.json)

The 6-layer fusion needs per-page vectors *including* L3/L6, which only exist with a live render.
[`scripts/capture_fusion_vectors.py`](../../scripts/capture_fusion_vectors.py) renders a labelled
sample **headless** (hang-proof: per-page timeout + dialog dismissal + page rebuild) and writes
6-layer vectors to [`artifacts/fusion_vectors.csv`](artifacts/fusion_vectors.csv) (**604 vectors**,
306 phishing / 298 legit). [`scripts/tune_fusion.py`](../../scripts/tune_fusion.py) then trains a
logistic meta-classifier, derives weighted-sum weights from its coefficients, and grid-searches the
verdict thresholds.

| Metric | Value |
|--------|-------|
| Baseline weighted-sum AUC | 0.8468 |
| Learned meta-classifier AUC | **0.9672** |
| Derived weights | L1≈0.42, L2≈0.45, L4≈0.12, L3≈0.02, **L5=0, L6=0** |
| Tuned thresholds | SUSPICIOUS≥1, PHISHING≥46 (F1 0.936) |

### Key methodological finding (and why fusion is NOT auto-applied)

The learned fusion **zeroes out L6 and L3**. The reason is the *capture method*, not the layers:
batch-rendering **saved** HTML can't reproduce runtime behaviour (the `set_content` origin is
`about:blank`, external `script.js`/assets don't load), so L6's signal is noise/inverted in the
capture, and L3's pHash on saved screenshots is unreliable. Applying these weights would make
production **ignore the runtime layer** — exactly the opposite of what's wanted, since L6 *is*
discriminative on real live navigation.

**Decision:** `tune_fusion.py` is **dry-run by default** (`--apply` required) and was **not
applied**. Production stays on the configurable weighted-sum (L6 fairly weighted at 0.15) plus the
retuned L1/L2 models. Proper fusion tuning needs vectors logged from **live navigation of real
URLs**, which is left as future work.

## 4. Limitations & future work

- **L3 visual** is weak — a single 64-bit pHash per brand (18 brands), threshold 0.80; prone to
  noise. A learned visual model (logo embeddings / fake-window-chrome detection) would be stronger.
- **Fusion tuning** should be redone on a live-navigation vector log, then `--apply`-ed.
- **Background tabs:** Chromium throttles non-focused tabs, so a background tab's L3 *screenshot*
  may be stale/blank (DOM/URL/runtime/reputation remain accurate).
- **CPU parallelism** is GIL-bound; a process pool could give true multi-core scaling under heavy
  multi-tab load.

### Found while building realistic tests (session 2)

- **The hand-tuned L1 heuristics were tuned to our own synthetic pages, not real attacker kits.**
  The real mrd0x BitB templates scored only 0.35 (CSS-class styling, `url-bar`/`title-bar` ids, no
  forms). Fixed additively with the R6 (fake window chrome + lock motif) / R7 (draggable fake
  window) rules → kits score 0.95. Lesson: heuristics should be validated against public attack
  tooling corpora, not only against self-authored fixtures.
- **The retuned L1 ML model is brittle out-of-distribution.** In-distribution it is fine (legit
  mean 0.119 on `html_features.csv`), but an all-zero feature vector scores 0.64 and a realistic
  benign login page scores ML 1.00, while the real kits score 0.06. In production this is masked by
  the verified-domain gate and L1's 0.15 weight, but per-layer scores shown in the UI can mislead.
  Proper fix = retrain with realistic *legit* login pages (and real BitB kit HTML) in the corpus.
  Mitigation for now: the fusion floor keys off the deterministic heuristic sub-score, not the ML
  overlay.
- **Weight caps hide decisive signals.** With L1 = 0.15, even a perfect BitB DOM detection
  contributed ≤ 15 points — below SUSPICIOUS. The decisive-signal floor (heuristic ≥ 0.9 → PHISHING,
  ≥ 0.7 → SUSPICIOUS) fixes this without re-weighting the general case.
