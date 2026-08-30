# Component 2 — BitB Detect: Browser-in-the-Browser Phishing Detector

> **Status:** ✅ Active — primary component

## Research Question
Can a multi-layer detection pipeline combining DOM analysis, URL classification, visual
similarity, form inspection, and reputation lookups reliably identify Browser-in-the-Browser
phishing attacks in real time before the user submits credentials?

---

## Architecture Overview

```
Page navigation (via Playwright)
        │
        ├──► Layer 1: BitB Detection     (DOM heuristics — fixed iframes, z-index, drag-block)
        ├──► Layer 2: URL Classifier     (ML/heuristic — 13 URL features, XGBoost model)
        ├──► Layer 3: Visual Similarity  (pHash screenshot vs brand logo reference hashes)
        ├──► Layer 4: Form Destination   (off-domain form POST + password field)
        └──► Layer 5: Reputation Check   (Google Safe Browsing + PhishTank)
                │
                ▼
        Weighted risk score (0–100)
        Verdict: SAFE / SUSPICIOUS / PHISHING
```

Layer weights: L1=0.15 · L2=0.30 · L3=0.20 · L4=0.15 · L5=0.20

---

## Tech Stack
| Layer | Technology |
|-------|-----------|
| L1 BitB | Regex DOM heuristics (Python) |
| L2 URL | XGBoost / RandomForest + 13-feature extractor |
| L3 Visual | Pillow + imagehash (pHash Hamming distance) |
| L4 Form | Regex DOM parsing + urlparse |
| L5 Reputation | httpx async → Google Safe Browsing API v4 + PhishTank |

---

## File Map

| File | Role |
|------|------|
| `layer1_bitb.py` | DOM heuristic BitB scanner |
| `layer2_url.py` | URL feature extractor + ML/heuristic classifier |
| `layer3_visual.py` | pHash visual brand impersonation detector |
| `layer4_form.py` | Form destination + data exfiltration analyser |
| `layer5_reputation.py` | External reputation APIs (GSB + PhishTank) |
| `layer6_runtime.py` | Runtime behaviour probe scoring (keylogger / clipboard / exfil) |
| `verified_domains.py` | Verified-domain allow-list gate |
| `alert_store.py` | SQLite persistence for the individual alert log |
| `reporter.py` | HTML report, CSV and SIEM export rendering |
| `__init__.py` | Package marker |

Supporting files (project root level):
- `data/logo_hashes.json` — brand pHash reference dictionary
- `models/url_classifier.pkl` — trained XGBoost model (generate via `scripts/prepare_dataset.py`)
- `models/bitb_classifier.pkl` — trained L1 HTML classifier
- `scripts/prepare_dataset.py` — Mendeley dataset trainer

> **L1 needs an HTML parser.** `_extract_html_features()` returns an all-zero vector
> when `beautifulsoup4`/`lxml` are missing, and the model scores that constant
> vector at ≈0.64 — so *every* page inherited an L1 floor of 0.64 regardless of
> content. Both are pinned in `requirements.txt`; do not drop them.

---

## Integration Interface
`core/main.py` imports and calls:

```python
from c2.layer1_bitb       import check_bitb       # (url, dom) → {score, detail, heuristic, evidence}
from c2.layer2_url        import check_url        # (url) → {score, detail, evidence}
from c2.layer3_visual     import check_visual     # (url, screenshot_b64) → {score, detail, evidence}
from c2.layer4_form       import check_form       # (url, dom) → {score, detail, evidence}
from c2.layer5_reputation import check_reputation # (url, gsb_key, phishtank) → {score, detail, evidence}
from c2.layer6_runtime    import check_runtime    # (url, runtime) → {score, detail, evidence}
```

### The `evidence` contract
Every layer returns an `evidence` dict beside `score`/`detail`. It is **additive** —
`score`, `detail` and L1's `heuristic` keep their original meaning, because
`_fuse_score()` and the live alert cards read them.

| Key | Meaning |
|-----|---------|
| `features` | the layer's raw feature vector (L1: 16 DOM features, L2: 13 URL features) |
| `flags` | which named signals actually tripped |
| `ml_prob` | the model's probability, where a model ran |
| *(other)* | layer-specific measurements — L4's `off_domain_hosts`, L3's `best_brand`/`best_similarity`, L5's per-feed verdicts, L6's probe counters |

Two rules when extending a layer:

1. **Build evidence inside the memoized value.** L1/L2/L3 cache on `(url, dom-digest)`.
   Attaching evidence after the cache lookup silently leaves every cache hit without it.
2. **Keep it JSON-serialisable.** It round-trips through a JSON column in `alert_store`.

`_fuse_score()` in `core/main.py` accepts an optional `breakdown` dict and records how the
risk was reached — `method` (`meta_classifier` | `weighted_sum`), `weights_applied`,
`pre_floor_risk`, `l1_heuristic`, `floor_applied`, `thresholds`, `final_risk`. That is what
answers "why was this 60?" long after the analysis ran.

---

## Alert log, reports and exports

`analyze()` writes every result through `alert_store.c2_alert_store` to
`~/.websentinel/c2_alerts.db` (mirroring `core/c3/alert_store.py`). The in-memory `alerts`
list stays as the hot cache the live pane reads; the store is what survives a restart.

Evidence is **stripped from the live `/analyze` and `/alerts` payloads** — `/alerts`
returns up to 50 records and the evidence would dominate the response. The dashboard's
detail modal fetches it per alert from `/alerts/{id}`.

Page HTML and screenshots are deliberately **not** stored: the feature vectors are the
evidence, and keeping the raw DOM of a credential-harvesting page on disk is a liability.

| Endpoint | Returns |
|----------|---------|
| `GET /alerts` | in-memory recent alerts (no evidence) |
| `GET /alerts/history?limit=&verdict=&since=` | persisted log, filterable |
| `GET /alerts/stats` | counts by verdict + DB path |
| `GET /alerts/{id}` | one alert with full evidence + fusion breakdown |
| `GET /alerts/{id}/report.html` | standalone styled report |
| `GET /alerts/{id}/report.json` | full structured record |
| `GET /alerts/export.csv` | one row per alert, a column per layer score |
| `GET /alerts/export.json` | full alert log |
| `GET /alerts/export.siem` | Splunk/QRadar/ELK envelope |

> **Route order matters.** Every literal `/alerts/...` path must be registered *before*
> `/alerts/{alert_id}`, or FastAPI matches `history` and `export.csv` as an id.

The SIEM envelope reuses C4's field names (`export_type`, `export_version`, `generated_at`,
`total_events`, `events`) so one ingest pipeline handles both components.

---

## Implementation Status
- ✅ Layer 1 — BitB DOM heuristics (fixed iframes, z-index, drag-block, fake address bar)
- ✅ Layer 2 — URL classifier (heuristic fallback + XGBoost when model trained)
- ✅ Layer 3 — Visual pHash (returns 0 until `data/logo_hashes.json` populated)
- ✅ Layer 4 — Form destination analyser
- ✅ Layer 5 — GSB + PhishTank reputation lookup
- ✅ Layer 6 — runtime behaviour probe (keylogger / clipboard / off-origin exfil)
- ✅ Per-layer `evidence` on every layer + fusion breakdown
- ✅ Individual alert log persisted to SQLite (survives restart)
- ✅ Alert detail modal, History tab, and HTML / JSON / CSV / SIEM export
- 🔲 Populate `data/logo_hashes.json` with brand reference hashes
- 🔲 Train URL classifier (`scripts/prepare_dataset.py` requires Mendeley dataset ZIP)
- 🔲 Improve L1: add ML-based BitB classifier trained on BitB kit corpus
- ✅ L1 ignores HTML and CSS/JS block comments when scoring
- ✅ L1 ML overlay bounded to a +0.15 adjustment instead of overriding the rules
- 🔲 Retrain the L1 model on a BitB corpus (see "L1 scoring" below) — it is currently
  trained on generic phishing data and contributes little
- 🔲 Retention: nothing calls `alert_store.purge_older_than()` on a schedule yet

---

## L1 scoring — two things to know before touching it

**Comments never score.** Every rule is a substring search over the DOM, so
`_score_bitb()` strips `<!-- -->` and `/* */` first. Without that a page that merely
*mentions* `ondragstart` or `<iframe style="position:fixed">` in a comment was charged for
it — the graded fixtures document which rules they avoid, and those very comments tripped
the rules they said were absent. A commented-out overlay renders nothing.

**The ML overlay is a bounded adjustment, not the score.**
`final = min(1.0, heuristic + _ML_MAX_BOOST * ml_prob)` with `_ML_MAX_BOOST = 0.15` — the
headroom the graded fixtures already documented ("Heuristic 0.50; ML may boost up to ~0.65").

It was `max(heuristic, ml_prob)`, which let the model set L1 on its own. That model is
trained on the Mendeley **generic phishing** corpus (`scripts/prepare_html_dataset.py`),
not a BitB corpus, and the two disagree about the defining signal — in that training data
`has_fixed_iframe` is *twice as common in the benign class* (0.099 vs 0.047), because real
sites embed ads and videos while generic phishing pages are plain login forms. What it
actually learned is closer to "small page + password field + brand name":

| fixture | truth | heuristic | ml_prob |
|---------|-------|-----------|---------|
| `pages/benign_login.html` | benign | 0.35 | **0.995** ← false positive |
| `pages/bitb_kit_windows.html` | BitB | 0.95 | **0.062** ← false negative |
| `bitb_samples/*` (CSS inlined) | BitB | 0.70 | 0.075–0.428 |

Under `max()` those wrong answers won outright. Capping keeps whatever signal the model
has without letting it overrule the rules that actually encode BitB — and because the
boost is *additive*, real kits score slightly higher than before (0.711–0.764 vs 0.700),
where `max()` discarded the model's contribution whenever the heuristic was larger.

Retraining is the real fix, and it needs a BitB corpus rather than a phishing one. Until
then the deterministic rules carry L1. `test/C2/test_c2_layers.py::TestLayer1ScoringHygiene`
pins both behaviours.

---

## AI Session Starter
> Paste this into a new AI chat to get instant context:
>
> "I'm working on Component 2 of WebSentinel — a Browser-in-the-Browser Phishing Detector.
> Project root: `WebSentinel/`. Shared infra in `core/`. My component is in `c2/` with five
> detection layers: `layer1_bitb.py` (DOM heuristics), `layer2_url.py` (URL ML/heuristic),
> `layer3_visual.py` (pHash brand impersonation), `layer4_form.py` (form exfil),
> `layer5_reputation.py` (GSB + PhishTank), `layer6_runtime.py` (runtime probe). Each
> returns `{score: float, detail: str, evidence: dict}` — evidence is additive and must be
> built inside the memoized value. Alerts persist via `alert_store.py` to
> `~/.websentinel/c2_alerts.db` and export through `reporter.py` as HTML/CSV/SIEM.
> Weights: L1=0.15, L2=0.25, L3=0.15, L4=0.10, L5=0.20, L6=0.15.
> I need help with: [YOUR TASK]"
