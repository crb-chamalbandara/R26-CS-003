# Component 1 — Ext Scan: Malicious Browser Extension Analyzer

> **Status:** 🔲 Not yet implemented — contributor welcome

## Research Question
Can a combination of ML-based static analysis and sandboxed dynamic execution accurately
detect malicious browser extensions before they cause harm?

---

## Architecture Overview

```
Extension Upload
      │
      ▼
┌─────────────┐     manifest.json + JS source
│ Static      │──────────────────────────────►  ML classifier
│ Analysis    │     permissions, API patterns     (score_static)
└─────────────┘
      │
      │  (if score_static > threshold)
      ▼
┌─────────────┐     Puppeteer headless Chromium
│ Sandbox     │──────────────────────────────►  Behaviour logger
│ Execution   │     network, DOM, cookie access   (score_dynamic)
└─────────────┘
      │
      ▼
  Fused verdict (weighted average)
```

---

## Tech Stack
| Layer | Recommended Technology |
|-------|----------------------|
| Static ML | scikit-learn / XGBoost on manifest + JS AST features |
| Sandboxing | Puppeteer (Node.js) or Playwright chromium with extension loaded |
| Network capture | Playwright route interception / mitmproxy |
| DOM monitoring | MutationObserver injected via CDP |

---

## File Map

| File | Role |
|------|------|
| `analyzer.py` | **Entry point** — `analyze_extension()` and `sandbox_extension()` stubs |
| `static_model.py` | **(create)** Feature extraction from manifest + JS; ML classifier |
| `sandbox.py` | **(create)** Puppeteer/Playwright sandbox runner |
| `features.py` | **(create)** Shared feature extraction utilities |
| `models/` | **(create)** Trained `.pkl` model files |

---

## Integration Interface
`core/main.py` will call (once implemented):

```python
from c1.analyzer import analyze_extension

# Inside /analyze or a dedicated /extension/analyze endpoint:
result = await analyze_extension(manifest_json, source_code)
# Returns: {"score": float, "verdict": str, "detail": str, "flags": list[str]}
```

---

## Implementation TODO
- [ ] Define feature set from manifest.json (permissions, content_scripts, background)
- [ ] Build JS AST feature extractor (esprima / acorn via subprocess)
- [ ] Collect labelled extension dataset (CRXcavator, malicious extension reports)
- [ ] Train and serialize ML model → `c1/models/ext_classifier.pkl`
- [ ] Implement `sandbox_extension()` using Playwright with `--load-extension`
- [ ] Wire `network_requests`, `dom_mutations`, `cookie_access` listeners
- [ ] Add `/extension/analyze` endpoint in `core/main.py`
- [ ] Add C1 panel to frontend dashboard

---

## AI Session Starter
> Paste this into a new AI chat to get instant context:
>
> "I'm building Component 1 of WebSentinel — a Malicious Browser Extension Analyzer.
> The project root is `WebSentinel/`. Shared infrastructure is in `core/` (FastAPI +
> Playwright). My component code lives in `c1/`. The entry-point stubs are in
> `c1/analyzer.py` with two functions: `analyze_extension(manifest, source_code)` for
> static ML analysis, and `sandbox_extension(extension_path)` for dynamic Puppeteer
> sandbox analysis. Both must return `{score: float, detail: str}`. I need help with:
> [YOUR TASK]"
