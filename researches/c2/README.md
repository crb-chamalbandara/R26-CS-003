# Component 2 (C2) — BitB Phishing Detector · Session Documentation

This folder documents the work done on **C2**, the Browser-in-the-Browser (BitB) phishing
detector of WebSentinel (R26-CS-003). C2 inspects every page the user navigates to (via a shared
Playwright Chromium session) and fuses several detection layers into a real-time verdict
(`SAFE` / `SUSPICIOUS` / `PHISHING`, plus `VERIFIED` for known-good sites).

This session took C2 from a 5-layer detector to a **6-layer** detector, added a verified-domain
trust gate, an in-browser warning/blocking system, full evaluation + tuning tooling, multi-tab
support with a per-tab live UI, and a two-round performance optimization.

## Contributions this session

1. **Verified-domain trust gate** — eliminates false positives on known-good sites (e.g.
   `google.com`) using a Tranco top-domain allowlist.
2. **L6 — Runtime Behavioral Layer** — a new detection layer for keylogger / clipboard /
   drag-block / off-origin credential-exfil behaviour, collected **non-invasively** (so it does
   not break anti-bot sites like Cloudflare).
3. **Threshold interstitial** — an in-browser warning banner / blocking page with a
   "Continue anyway" escape, driven by configurable risk thresholds.
4. **Configurable + learned fusion** — layer weights and verdict thresholds moved into settings;
   optional learned meta-classifier with a safe weighted-sum fallback.
5. **Evaluation & tuning toolchain** — an offline benchmark harness, per-model hyperparameter
   tuning, and a fusion-tuning pipeline, with measured results.
6. **Multi-tab correctness + per-tab Live Analysis UI** — each browser tab is analyzed and shown
   independently.
7. **Performance optimization (2 rounds)** — concurrency, off-loop CPU work, network caching, and
   repeat-visit memoization, with no change to verdicts.

## Documents

| Doc | Contents |
|-----|----------|
| [01-features-and-design.md](01-features-and-design.md) | What was built and why (design rationale per feature) |
| [02-evaluation-and-tuning.md](02-evaluation-and-tuning.md) | Benchmark methodology, results, model + fusion tuning, limitations |
| [03-performance-optimization.md](03-performance-optimization.md) | The two optimization rounds with before/after benchmarks |
| [04-session-changelog.md](04-session-changelog.md) | Chronological log: change → files → verification |

## Evidence / artifacts

`artifacts/` holds the evaluation outputs referenced by the docs (copied here because
`notebooks/` is git-ignored):

- `metrics.json`, `roc.png`, `confusion.png` — benchmark of the detection layers + fusion
- `tuning.json` — L1/L2 model hyperparameter-tuning results
- `tuning_fusion.json`, `fusion_vectors.csv` — fusion-tuning results + the captured 6-layer dataset

## Code map (component lives in [`core/c2/`](../../core/c2/))

| File | Role |
|------|------|
| [layer1_bitb.py](../../core/c2/layer1_bitb.py) | L1 — DOM heuristics + trained BitB ML model |
| [layer2_url.py](../../core/c2/layer2_url.py) | L2 — URL classifier (13 features) |
| [layer3_visual.py](../../core/c2/layer3_visual.py) | L3 — pHash brand-impersonation |
| [layer4_form.py](../../core/c2/layer4_form.py) | L4 — form destination / exfil |
| [layer5_reputation.py](../../core/c2/layer5_reputation.py) | L5 — Google Safe Browsing + PhishTank |
| [layer6_runtime.py](../../core/c2/layer6_runtime.py) | **L6 — runtime behavioral (new)** |
| [verified_domains.py](../../core/c2/verified_domains.py) | **verified-domain trust gate (new)** |

Shared infra: [`core/main.py`](../../core/main.py) (`/analyze`, fusion, nav handler),
[`core/playwright_session.py`](../../core/playwright_session.py) (session, L6 collection,
interstitial). Tooling in [`scripts/`](../../scripts/), tests in [`test/C2/`](../../test/C2/).
