# Component 1 (C1) - Malicious Browser Extension Analyzer

> Status: Planned, not yet implemented

## Purpose
Detect malicious browser extensions before they cause harm by combining static analysis
(manifest + code patterns + ML + hash match) with optional dynamic sandbox behavior analysis.

This component is based on the project proposal and the C1 guides.

---

## Problem Context and Gap
- Malicious extensions can pass store checks, then steal credentials or inject scripts at runtime.
- Existing extension analyzers focus on static checks only and miss conditionally triggered behavior.
- No single tool combines ML-based static classification with live sandboxed behavior monitoring.

---

## Novelty (C1)
This component fuses ML-based static code classification with live runtime sandbox observation
in a single automated pipeline for browser extensions. It catches obfuscated or delayed
malicious behavior that static-only tools like CRXcavator or Tarnish miss.

---

## Research Question
Can a combination of ML-based static analysis and sandboxed dynamic execution accurately
detect malicious browser extensions before they cause harm?

---

## Architecture Overview

```
Extension Input (CRX or unpacked)
      |
      v
Static Analysis Module
  - Hash check (known malicious)
  - Manifest permission features
  - Source code pattern features
  - ML classifier (score_static 0-100)
      |
      | if score_static > 50
      v
Dynamic Sandbox Module (Docker + Puppeteer)
  - Load extension in headless Chromium
  - Capture API calls, DOM access, cookies, network
  - Behavior rules -> score_dynamic 0-100
      |
      v
Verdict Engine
  - Fuse static + dynamic scores
  - Output verdict + evidence list
```

---

## Implementation Modules (WBS)
1) Static Analysis Module
2) Dynamic Analysis Module (Sandbox)
3) Verdict Engine (score fusion + reporting)

---

## Tech Stack (from proposal)
| Layer | Technology |
|------|------------|
| Static ML | Python + scikit-learn / XGBoost |
| Sandbox | Puppeteer (Node.js) + Headless Chromium |
| Isolation | Docker Desktop |
| Baselines | Tarnish, CRXcavator |

---

## Inputs and Outputs

### Inputs
- CRX file (preferred) or unpacked extension directory
- Optional: manifest.json + concatenated JS source for testing

### Output (contract)
```json
{
  "score": 0,
  "verdict": "SAFE|SUSPICIOUS|MALICIOUS",
  "detail": "short summary",
  "flags": ["evidence_1", "evidence_2"],
  "static": {
    "score": 0,
    "hash_match": false,
    "ml_score": 0
  },
  "dynamic": {
    "score": 0,
    "executed": false,
    "signals": []
  }
}
```

---

## Data Sources

### Malicious
- chrome-mal-ids (extension ID blocklist)
- palant/malicious-extensions-list (curated IDs + behavior descriptions)
- chrome-stats malware removals (confirmed by Google, 7000+ IDs)
- refade/GoogleChromeExtension dataset (1,012 CRX, 1,098 features)

### Benign
- Top Chrome Web Store extensions (500-1000), collected via CRXcavator

---

## Static Analysis Module

### 1) Hash Check
- Compute SHA-256 of the CRX
- Compare with malicious hash database
- If match, set score_static to 100 and verdict MALICIOUS

### 2) Manifest Feature Extraction
Minimum features from manifest.json:
- Permission binary flags (webRequest, cookies, tabs, nativeMessaging)
- host_permissions count and all_urls presence
- background/service_worker existence
- content_scripts presence and count
- web_accessible_resources presence

Additional static features:
- Content script entropy (simple obfuscation signal)
- API call frequency for high-risk APIs

### 3) Source Code Pattern Features
Lightweight patterns (regex or AST):
- eval / Function / setTimeout with string
- WebSocket / fetch / XMLHttpRequest usage
- chrome.cookies / chrome.webRequest usage
- Input listeners (keylogging risk)

### 4) ML Classifier
- Primary: XGBoost
- Compare: Random Forest and Isolation Forest
- Handle class imbalance via scale_pos_weight

Optional imbalance strategy:
- Repeat sampling of malicious vs benign subsets (balanced batches)

### Static Score
```
score_static = 100 if hash_match else round(ml_score * 100)
```

---

## Dynamic Sandbox Module

Triggered only if score_static > 50 (configurable).

Sandbox behavior signals:
- Network requests to suspicious domains or IPs
- DOM mutations and scraping of form/password fields
- Cookie and storage access
- eval or obfuscated payloads at runtime
- Cross-origin fetch attempts
- Chrome API misuse vs declared permissions

Dynamic score is a weighted sum of signals.

---

## Verdict Engine

### Score Fusion
```
score_final = (0.7 * score_static) + (0.3 * score_dynamic)
```

### Verdict Rules
- MALICIOUS if score_final >= 70
- SUSPICIOUS if score_final >= 40
- SAFE otherwise

### Evidence Output
- Human-readable report string
- Evidence flags aligned to behavior signals

---

## File Map (C1)
| File | Role |
|------|------|
| analyzer.py | Orchestrates static + dynamic analysis |
| features.py | Manifest + code feature extraction |
| static_model.py | ML loading + inference |
| sandbox.py | Puppeteer sandbox runner |
| models/ | Trained model artifacts |
| scripts/ | Dataset prep and training scripts |
| data/ | Local datasets and CSVs (gitignored) |

---

## Integration Points

### Backend Endpoint
- POST /extension/analyze (to add in core/main.py)
  - payload: {"extension_path": "..."} or {"manifest": "...", "source": "..."}
  - response: C1 output contract

### Dashboard Output
- Include C1 verdict, score, and flags in the central dashboard
- Share Extension ID + score with Component 4 for attribution

---

## Development Phases (from plan)

### Phase 1: Data Collection (Now)
- Download malicious datasets
- Collect benign extension manifests
- Build unified CSV (label 0/1)
- Gather CRX samples for sandbox testing

### Phase 2: Static Analysis (Weeks 3-5)
- Build hash detection
- Manifest parser + feature vector
- Add content script entropy + API call frequency features
- Train XGBoost and compare baselines
- Output static_score (0-100)

### Phase 3: Dynamic Sandbox (Weeks 6-9)
- Docker + headless Chrome + Puppeteer
- Log API calls, DOM access, network traffic
- Track cookie access and cross-origin fetches
- Validate against known malicious samples

### Phase 4: Verdict Engine + Dashboard (Weeks 10-12)
- Merge static + dynamic scores
- Provide evidence list and reasoning
- Full evaluation vs baselines

---

## Development Start (Post-Training)

After model training, begin development by wiring the model into the static pipeline:

1) Define runtime inputs
  - Decide how the analyzer receives data (manifest.json + JS source initially; CRX later).
  - Confirm output contract (score, verdict, evidence flags).

2) Build the feature extractor
  - Implement features.py to convert manifest + code into model features.
  - Load dataset_clean_features.json to keep feature order consistent.

3) Load and run the trained model
  - Implement static_model.py to load extension_detector_model.pkl.
  - Return ml_score (0-100).

4) Add hash check
  - Load malicious_ids.txt (and other blocklists).
  - Short-circuit to MALICIOUS on match.

5) Implement analyze_extension()
  - Orchestrate: hash -> features -> model -> score -> verdict.

6) Wire the backend endpoint
  - Add /extension/analyze and return the full C1 output contract.

---

## Evaluation Metrics
- Precision, Recall, F1-score
- Compare static-only vs dynamic-only vs fused
- False positive rate on benign set
- Verdict time (end-to-end latency)

---

## AI Session Starter
"I am working on WebSentinel Component 1 (C1) - Malicious Browser Extension Analyzer.
The architecture and steps are in core/c1/ARCHITECTURE.md. I need help implementing
static feature extraction, ML training, and Puppeteer sandbox checks."
- Precision, recall, F1
- Compare: static-only vs dynamic-only vs fused
- False positives on benign set

---

## AI Session Starter
"I am working on WebSentinel Component 1 (C1) - Malicious Browser Extension Analyzer.
I need help implementing static analysis, ML training, and sandbox behavior checks.
The C1 architecture is in core/c1/ARCHITECTURE.md and the entry point stubs are in
core/c1/analyzer.py."
