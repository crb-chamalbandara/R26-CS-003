# C2 — Session Changelog

Chronological record of the work, the files touched, and how each was verified. New files marked
**(new)**.

## 1. Verified-domain trust gate
- **(new)** [`scripts/fetch_verified_domains.py`](../../scripts/fetch_verified_domains.py) — builds the Tranco allowlist (curated offline fallback).
- **(new)** [`data/verified_domains.txt`](../../data/verified_domains.txt) — 50,000 verified domains.
- **(new)** [`core/c2/verified_domains.py`](../../core/c2/verified_domains.py) — eTLD+1 match + shared-host exclusion + `is_verified()`.
- [`core/main.py`](../../core/main.py) — trust gate in `analyze()` (skip L1/L2/L4, run L5; `VERIFIED` verdict).
- [`requirements.txt`](../../requirements.txt) — added `tldextract`.
- **(new)** [`test/C2/test_verified_domains.py`](../../test/C2/test_verified_domains.py) + a `c2_verified` live-runner case.
- ✅ unit 8/8; `google.com → VERIFIED`, free-host phish not trusted.

## 2. Threshold interstitial (warn / block / continue)
- [`core/playwright_session.py`](../../core/playwright_session.py) — `inject_interstitial()` + overlay JS.
- [`core/main.py`](../../core/main.py) — settings (`warn_threshold`/`block_threshold`/`interstitial_enabled`), wired into the nav handler.
- [`frontend/dashboard.html`](../../frontend/dashboard.html) — threshold/interstitial settings UI; VERIFIED verdict styling.
- ✅ settings round-trip persisted; overlay JS passes `node --check`.

## 3. L6 — Runtime Behavioral Layer
- **(new)** [`core/c2/layer6_runtime.py`](../../core/c2/layer6_runtime.py) — `check_runtime()` scoring.
- [`core/playwright_session.py`](../../core/playwright_session.py) — runtime collection + `get_runtime_signals()`.
- [`core/main.py`](../../core/main.py) — `AnalyzeReq.runtime`, L6 in layer jobs/weights, `l6` setting, nav-handler wiring.
- [`frontend/dashboard.html`](../../frontend/dashboard.html) — L6 toggle, active-probe + verdict-threshold controls.
- **(new)** [`test/C2/test_layer6_runtime.py`](../../test/C2/test_layer6_runtime.py).
- ✅ unit 6/6; BitB+L6 page scores higher (59.9 vs 52.5).

## 4. Cloudflare fix (L6 made non-invasive)
- [`core/playwright_session.py`](../../core/playwright_session.py) — removed the in-page hook from the live session; collect off-origin POSTs via `context.on("request")` and listeners via CDP `DOMDebugger.getEventListeners`. In-page hook kept for offline batch capture only.
- ✅ CDP collection validated headless; `cineru.lk` (Cloudflare) loads again.

## 5. Evaluation harness
- **(new)** [`scripts/evaluate_c2.py`](../../scripts/evaluate_c2.py) — per-layer ROC/AUC + fused confusion matrix + plots.
- Artifacts: [`artifacts/metrics.json`](artifacts/metrics.json), [`artifacts/roc.png`](artifacts/roc.png), [`artifacts/confusion.png`](artifacts/confusion.png).
- ✅ L1 0.958 / L2 0.908 / fused 0.969; under-flagging finding documented.

## 6. Per-model tuning
- **(new)** [`scripts/tune_models.py`](../../scripts/tune_models.py) — RandomizedSearchCV for L1/L2; retuned `models/bitb_classifier.pkl`, `models/url_classifier.pkl` (backed up to `*.pkl.bak`).
- Artifact: [`artifacts/tuning.json`](artifacts/tuning.json). ✅ L1 AUC 0.964, L2 AUC 0.902.

## 7. Configurable + learned fusion
- [`core/main.py`](../../core/main.py) — `weights`/`verdict_*`/`phishtank_enabled` in settings; `_fuse_score` with optional `c2_fusion.pkl` + weighted-sum fallback.
- **(new)** [`scripts/capture_fusion_vectors.py`](../../scripts/capture_fusion_vectors.py) (headless, hang-proof), [`scripts/tune_fusion.py`](../../scripts/tune_fusion.py) (dry-run by default).
- Artifacts: [`artifacts/fusion_vectors.csv`](artifacts/fusion_vectors.csv), [`artifacts/tuning_fusion.json`](artifacts/tuning_fusion.json).
- ⚠️ Not applied — batch capture under-represents L6/L3 (see [02-evaluation-and-tuning.md](02-evaluation-and-tuning.md)).

## 8. Multi-tab correctness
- [`core/playwright_session.py`](../../core/playwright_session.py) — per-page extraction (page threading), per-tab dedup (`_last_url_by_page`), per-tab close cleanup.
- [`core/main.py`](../../core/main.py) — nav handler passes `page` to all extraction + interstitial calls.
- ✅ each tab analyzed independently; regression suites pass.

## 9. Per-tab Live Analysis UI
- [`core/playwright_session.py`](../../core/playwright_session.py) — `tab_id()` + close callbacks.
- [`core/main.py`](../../core/main.py) — tag analysis with `tab_id`/`title`; broadcast `tab_closed`.
- [`frontend/dashboard.html`](../../frontend/dashboard.html) — `liveTabs` map → one card per tab; `tab_closed` removal.
- ✅ dashboard JS passes `node --check`.

## 10. Ghost-card fix (closed tab still visible)
- [`frontend/dashboard.html`](../../frontend/dashboard.html) — `closedTabs` guard so a late analysis can't re-create a closed tab's card.
- [`core/main.py`](../../core/main.py) — skip broadcast when `page.is_closed()`.

## 11. Performance — round 1
- [`core/main.py`](../../core/main.py) — `asyncio.gather` over layers; nav-handler short-circuit + conditional screenshot.
- [`core/c2/layer{1,2,3}_*.py`](../../core/c2/) — sync core + `asyncio.to_thread`.
- [`core/c2/layer5_reputation.py`](../../core/c2/layer5_reputation.py) — concurrent GSB+PhishTank, TTL cache, shared client, PhishTank gate.
- ✅ full `analyze()` ~44 ms concurrent; gated/cached L5 ~0.07 ms; verdicts unchanged.

## 12. Performance — round 2
- [`core/c2/layer{1,2,3}_*.py`](../../core/c2/) — per-layer content-hash memoization; pre-compiled L1 regexes.
- [`core/c2/layer5_reputation.py`](../../core/c2/layer5_reputation.py) + [`core/main.py`](../../core/main.py) — `aclose()` on shutdown; concurrent `_broadcast`.
- ✅ L1 42 ms → 0.094 ms on cache hit; verdicts unchanged; all suites pass.

---

### Test status (end of session)
`test_verified_domains` **8/8** · `test_layer6_runtime` **6/6** · c2 live-runner **5/5** · backend
compiles · dashboard JS passes `node --check`.

### Files new/changed
**New:** `core/c2/layer6_runtime.py`, `core/c2/verified_domains.py`, `data/verified_domains.txt`,
`scripts/{fetch_verified_domains,evaluate_c2,tune_models,capture_fusion_vectors,tune_fusion}.py`,
`test/C2/{test_verified_domains,test_layer6_runtime}.py`, `models/*.pkl.bak` (backups).
**Changed:** `core/main.py`, `core/playwright_session.py`, `frontend/dashboard.html`,
`core/c2/layer{1,2,3,5}_*.py`, `requirements.txt`, retuned `models/{bitb_classifier,url_classifier}.pkl`.

> Note: this work is on the **C2** branch and not yet committed at the time of writing.
