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
| `__init__.py` | Package marker |

Supporting files (project root level):
- `data/logo_hashes.json` — brand pHash reference dictionary
- `models/url_classifier.pkl` — trained XGBoost model (generate via `scripts/prepare_dataset.py`)
- `scripts/prepare_dataset.py` — Mendeley dataset trainer

---

## Integration Interface
`core/main.py` imports and calls:

```python
from c2.layer1_bitb       import check_bitb       # (url, dom) → {score, detail}
from c2.layer2_url        import check_url        # (url) → {score, detail}
from c2.layer3_visual     import check_visual     # (url, screenshot_b64) → {score, detail}
from c2.layer4_form       import check_form       # (url, dom) → {score, detail}
from c2.layer5_reputation import check_reputation # (url, gsb_key) → {score, detail}
```

---

## Implementation Status
- ✅ Layer 1 — BitB DOM heuristics (fixed iframes, z-index, drag-block, fake address bar)
- ✅ Layer 2 — URL classifier (heuristic fallback + XGBoost when model trained)
- ✅ Layer 3 — Visual pHash (returns 0 until `data/logo_hashes.json` populated)
- ✅ Layer 4 — Form destination analyser
- ✅ Layer 5 — GSB + PhishTank reputation lookup
- 🔲 Populate `data/logo_hashes.json` with brand reference hashes
- 🔲 Train URL classifier (`scripts/prepare_dataset.py` requires Mendeley dataset ZIP)
- 🔲 Improve L1: add ML-based BitB classifier trained on BitB kit corpus

---

## AI Session Starter
> Paste this into a new AI chat to get instant context:
>
> "I'm working on Component 2 of WebSentinel — a Browser-in-the-Browser Phishing Detector.
> Project root: `WebSentinel/`. Shared infra in `core/`. My component is in `c2/` with five
> detection layers: `layer1_bitb.py` (DOM heuristics), `layer2_url.py` (URL ML/heuristic),
> `layer3_visual.py` (pHash brand impersonation), `layer4_form.py` (form exfil),
> `layer5_reputation.py` (GSB + PhishTank). Each returns `{score: float, detail: str}`.
> Weights: L1=0.15, L2=0.30, L3=0.20, L4=0.15, L5=0.20. I need help with: [YOUR TASK]"
