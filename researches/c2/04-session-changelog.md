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

## 13. Realistic C2 test cases for the dashboard Test panel (session 2)

**Finding that drove this.** The Test-panel C2 browser cases were broken
(`pw_session.is_running()` called on a `@property` → TypeError) and used toy HTML. Probing with the
**real mrd0x BitB kits** showed the detector under-firing badly: L1 = 0.35, trained ML = 0.06 — kits
style via CSS classes, use `url-bar`/`title-bar` ids (regex expected `address-bar`), have no forms
(L4 = 0). Fused: **5.25/100 → SAFE** on a clean compromised-domain URL; even L1 = 1.0 alone could
never reach SUSPICIOUS = 30 (weight 0.15). Also found the retuned L1 ML model is
out-of-distribution-happy: an all-zero feature vector scores 0.64 and a realistic benign login page
scores ML 1.00 (masked in production by the verified gate + low L1 weight).

- [`core/main.py`](../../core/main.py) — fixed `is_running()` → property on both broken cases;
  `_TEST_PAGES` now loads `test/C2/pages/*.html` at startup; `_fuse_score` gained a
  **decisive-signal floor** keyed on L1's *heuristic* sub-score (not the ML overlay, which FPs
  out-of-distribution): heuristic ≥ 0.9 → PHISHING floor, ≥ 0.7 → SUSPICIOUS floor; 7 new
  `_ALL_TEST_CASES` entries.
- [`core/c2/layer1_bitb.py`](../../core/c2/layer1_bitb.py) — **R6** fake browser window chrome
  (+0.35: `url-bar`/`title-bar`/fake-address id/class **and** an SSL/padlock motif) and **R7**
  simulated draggable window (+0.25, only with R6); R5 fake-address-bar scoped to id/class
  attributes (narrative text like "check the address bar" no longer fires it); result dicts carry a
  `heuristic` sub-score. Real kits: 0.35 → **0.95**.
- **(new)** [`test/C2/build_pages.py`](../../test/C2/build_pages.py) — builds self-contained pages
  from the real mrd0x templates (placeholders filled, CSS/JS inlined).
- **(new)** [`test/C2/pages/`](../../test/C2/pages/) — `bitb_kit_windows.html`,
  `bitb_kit_macos.html`, `keylogger_harvest.html`, `benign_login.html`, `benign_oauth.html`.
- [`frontend/dashboard.html`](../../frontend/dashboard.html) — "Run Tests" button in the C2 panel
  header (jumps to the Tests panel, runs C2 only).
- [`test/C2/test_bitb_detection.py`](../../test/C2/test_bitb_detection.py) — port 8001 → 8765
  (`WS_API` env override).
- New Test-panel cases: `c2_kit_windows`, `c2_kit_macos` (live render → L1 ≥ 0.75, PHISHING),
  `c2_scenario_oauth` (lookalike domain → PHISHING), `c2_scenario_freehost` (off-domain harvest →
  L4 ≥ 0.5, SUSPICIOUS 49.5 — L5 reputation would add up to 20 pts with a GSB key),
  `c2_scenario_compromised` (clean URL kit → PHISHING via floor; SAFE before),
  `c2_runtime_keylogger` (live CDP listener collection + probe-tripped off-origin exfil observed at
  the network layer → L6 = 1.00, block overlay shown & dismissed), `c2_benign_login` (fixed nav +
  modal + same-origin form → SAFE 18.7, L4 = 0).
- ✅ live Test-panel run **C2 14/14**, C1 4/4, C3 4/4; offline regressions: `test_c2_layers`
  28/28, `test_layer6_runtime` 6/6, `test_verified_domains` 8/8; dashboard JS `node --check` OK.
- ⚠️ Legacy note: `test_bitb_anomaly_levels.py`'s graded 50/75/100 expectations are stale — all
  four anomaly pages now score ~1.00 (current rule weights + R6 + retuned ML). Not wired into the
  Test panel; left as a manual API demo.

## 14. Step Mode — demo pacing for the Test panel (session 2, cont.)

**Why.** The Test panel ran all 14 C2 cases back-to-back at full speed — browser cases finished
in ~2 s, so an audience couldn't see the fake BitB window, the keylogger probe, or the block
overlay. Step Mode pauses each case at demo-meaningful points with narration and waits for a
"Next step" click.

- [`core/main.py`](../../core/main.py) — `_STEP_CTX` + `_step(msg)` helper (no-op in normal
  mode): pushes a `step` event to the SSE stream, then blocks on an `asyncio.Event` gate.
  `POST /dev/test_step` releases the gate. `run_tests_stream_endpoint` gains `?step=1`: each
  case runs as an `asyncio.Task` while the generator pumps the per-case narration queue;
  `finally` cancels the task and clears the ctx (covers Stop / client disconnect mid-pause).
  38 `_step()` narration points across **all 14 C2 cases** (quick URL/form/trust-gate checks get
  intro+result steps; browser cases narrate navigation, analysis, and the block interstitial).
  The two legacy browser cases also gained `_ensure_browser_running()` — they previously skipped
  navigation silently when the browser wasn't up yet. C1/C3/C4 run straight through.
- [`frontend/dashboard.html`](../../frontend/dashboard.html) — "Step Mode" toggle + "Next step ▶"
  button in the Tests panel controls; `step` SSE events render as narration on the running row
  (accent color) and enable Next; hidden again on result/done/stop.
- ✅ live step run **C2 14/14 with 38 pauses**; normal run unchanged (C2 14/14, C1 4/4, C3 4/4);
  mid-pause disconnect leaves the backend healthy; dashboard JS passes `node --check`.

---

`test_verified_domains` **8/8** · `test_layer6_runtime` **6/6** · `test_c2_layers` **28/28** ·
Test-panel live run: **C2 14/14**, C1 4/4, C3 4/4 · backend compiles · dashboard JS passes
`node --check`.

### Files new/changed
**New:** `core/c2/layer6_runtime.py`, `core/c2/verified_domains.py`, `data/verified_domains.txt`,
`scripts/{fetch_verified_domains,evaluate_c2,tune_models,capture_fusion_vectors,tune_fusion}.py`,
`test/C2/{test_verified_domains,test_layer6_runtime}.py`, `models/*.pkl.bak` (backups).
**Session 2 new:** `test/C2/build_pages.py`, `test/C2/pages/*.html` (real mrd0x kits + realistic
attack/benign fixtures).
**Changed:** `core/main.py`, `core/playwright_session.py`, `frontend/dashboard.html`,
`core/c2/layer{1,2,3,5}_*.py`, `test/C2/test_bitb_detection.py`, `requirements.txt`, retuned
`models/{bitb_classifier,url_classifier}.pkl`.

> Note: this work is on the **C2** branch and not yet committed at the time of writing.
