# C3 — C2 Beacon Detector: Issue Analysis & Implementation Plan

**Component**: C3 — Browser Execution Aware C2 Beacon Detector  
**Dataset**: `data/c3_extracted_v2.csv`  
**Model**: `models/c3_isolation_forest.pkl` (Isolation Forest)  
**Status**: False-positive rate is critically high — most normal traffic is incorrectly scored as BEACON  

---

## Table of Contents

1. [Root Cause Summary](#root-cause-summary)
2. [Detailed Issue Analysis](#detailed-issue-analysis)
   - [CRITICAL Issues](#critical-issues)
   - [HIGH Issues](#high-issues)
   - [MEDIUM Issues](#medium-issues)
   - [LOW / UI Issues](#low--ui-issues)
3. [Implementation Plan](#implementation-plan)
   - [Phase 1 — Model Fix (Critical)](#phase-1--model-fix-critical)
   - [Phase 2 — Heuristic Fix (High)](#phase-2--heuristic-fix-high)
   - [Phase 3 — Analyzer + Engine Fixes (Medium)](#phase-3--analyzer--engine-fixes-medium)
   - [Phase 4 — UI Fixes (Low-Medium)](#phase-4--ui-fixes-low-medium)
4. [Files to Change — Quick Reference](#files-to-change--quick-reference)
5. [Testing Checklist](#testing-checklist)

---

## Root Cause Summary

The primary reason most traffic is incorrectly detected as BEACON is a **mismatch between training data and real inference data**. Specifically:

| Dimension | Training Data (c3_extracted_v2.csv) | Real Browser Traffic |
|---|---|---|
| F09 avg_idle_time_ms | **Always 0** (15,000/15,000 rows) | Non-zero (ms since last user action) |
| F10 user_active_ratio | **Always 0** | 0.0 – 1.0 |
| F11 background_tab_ratio | **Always 0** | Non-zero for background tabs |
| F12 extension_origin_ratio | **Always 0** | Non-zero with extensions |
| F13 url_path_entropy | **Always 0** | 1.0 – 5.0 bits |
| F14 request_burst_count | **Always 0** | Non-zero (page loads cause bursts) |

The Isolation Forest was trained with these 6 features permanently zeroed. It learns "zero is normal." When real traffic arrives with non-zero values in these 6 dimensions, **every sample falls outside the learned normal distribution** and receives an anomaly score of 1.0 (maximum). This propagates through the fusion engine (60% weight on anomaly) and produces widespread BEACON verdicts.

Additionally, the `requests_per_hour` feature (F05) in the training data contains synthetic extreme values up to **3.3 billion req/hour**, making calibration bounds unrealistic for real traffic (which peaks at ~50,000 req/hour).

---

## Detailed Issue Analysis

---

### CRITICAL Issues

---

#### ISSUE-C1: Six features are ALL-ZERO in the training dataset

**File affected**: `data/c3_extracted_v2.csv`, `scripts/train_c3_model.py`, `core/c3/anomaly_engine.py`

**Evidence** (verified by data inspection):
```
avg_idle_time_ms:      mean=0.0, std=0.0, min=0.0, max=0.0  (all 15,000 rows)
user_active_ratio:     mean=0.0, std=0.0, min=0.0, max=0.0
background_tab_ratio:  mean=0.0, std=0.0, min=0.0, max=0.0
extension_origin_ratio:mean=0.0, std=0.0, min=0.0, max=0.0
url_path_entropy:      mean=0.0, std=0.0, min=0.0, max=0.0
request_burst_count:   mean=0.0, std=0.0, min=0.0, max=0.0
```

**Why it happens**: The `c3_extracted_v2.csv` dataset was extracted from network-capture traces (likely CTU-13 or similar pcap-derived sources). These are raw packet captures — they do NOT contain browser execution context. Features F09–F14 require a live instrumented browser to compute. No pcap-derived dataset can provide them.

**Impact**: The Isolation Forest model sees ALL training samples at (F09=0, F10=0, F11=0, F12=0, F13=0, F14=0). It learns that zero is the normal operating point for all 6 dimensions. At inference time, real browser requests have non-zero values. The model's `score_samples()` returns a raw score well below the 5th-percentile calibration bound. After normalization:
```python
scaled = (raw - low) / (high - low)  # raw < low → scaled < 0 → clamped to 0
normalized = 1.0 - 0.0 = 1.0         # MAXIMUM anomaly score for ALL real traffic
```
With a 0.60 fusion weight on anomaly, the fusion score immediately reaches `0.60 × 1.0 = 0.60`, which is exactly the BEACON threshold. Any small heuristic contribution pushes it over.

**Fix**: Train the Isolation Forest using ONLY the 8 network-level features that are present in the training data (F01–F08). The browser-context features F09–F12 are exclusively handled by the heuristic scorer, which was specifically designed for them. This is architecturally correct: the Isolation Forest learns normal network timing/payload patterns; the heuristic learns normal browser context patterns.

---

#### ISSUE-C2: Label=1 (beacon) timing features are ALL ZEROS

**File affected**: `data/c3_extracted_v2.csv`

**Evidence**:
```
Label=1 (beacon, 6000 rows):
  iat_cv:                nonzero=0, zeros=6000  ← ALL ZERO
  iat_bowley_skewness:   nonzero=0, zeros=6000  ← ALL ZERO
  iat_mad_ms:            nonzero=0, zeros=6000  ← ALL ZERO
  iat_mean_ms:           mean=15660ms, median=266ms (some real values present)
```

**Why it happens**: The timing statistics (CV, skewness, MAD) require at least 3+ time-ordered events per host. The beacon samples in the dataset appear to have been extracted as single-flow records, not rolling windows. Without a window of events, timing variation cannot be computed.

**Impact**: The Isolation Forest is trained only on label=0 rows (ISSUE-C1 does not affect this directly). But if future supervised training is attempted, beacon samples would be indistinguishable from "no timing data" benign samples. The dataset is unreliable as a supervised training set.

**Fix**: Flag this dataset as network-features-only. When using it for Isolation Forest (unsupervised, benign-only), it is acceptable after applying the fix from ISSUE-C1. For any future supervised model, self-collected browser data (Phase 3 workflow) must be used.

---

#### ISSUE-C3: `requests_per_hour` (F05) contains synthetic extreme values

**File affected**: `data/c3_extracted_v2.csv`, calibration in `models/c3_isolation_forest.pkl`

**Evidence**:
```
Label=0 (benign, 9000 rows):
  requests_per_hour: mean=5,757,332, median=4,782, max=3,342,857,142
```

The median is realistic (4,782 req/hour ≈ 1.3 req/second). The mean is inflated by extreme outliers. Max of 3.3 BILLION req/hour is physically impossible from a browser.

**Why it happens**: The training data was generated synthetically or extracted from network traces where session duration was extremely short (e.g., 1 ms window producing 1 request → 3,600 req/hour × 1M = astronomically high). Division by a very small duration produces huge values.

**Impact**: The Isolation Forest's feature space for F05 spans 0 to 3.3B. When real traffic comes in with 100–50,000 req/hour, the model sees this as "very low" compared to training, which slightly reduces the anomaly score in dimension 5. But more critically, the calibration bounds (5th–95th percentile) include these inflated values, making the normalized score meaningless.

**Fix**: Clip `requests_per_hour` to a maximum of 100,000 before training and at inference time. This corresponds to roughly 28 requests per second — already fast enough to cover aggressive page loads. All values above this threshold are real anomalies in any case.

---

### HIGH Issues

---

#### ISSUE-H1: Heuristic `user_active_ratio` threshold fires on normal traffic

**File affected**: `core/c3/analyzer.py` → `_heuristic_score()`

**Code**:
```python
if float(features.get("user_active_ratio", 1.0)) < 0.10:
    score += 0.25
    flags.append("fires while user idle")
```

**Why it's wrong**: `user_active_ratio` is the fraction of requests in the rolling window where `user_was_active=True`. `user_was_active` is True only when the user performed a click/keydown/scroll within the last 5 seconds AND the tab is foreground.

Normal browsing scenario:
1. User opens a news article and reads for 3 minutes without clicking.
2. The page sends 20 background requests (ads, analytics, CDN heartbeats).
3. None of these fire within 5 seconds of a user action.
4. `user_active_ratio = 0/20 = 0.0` → **+0.25 heuristic** → false positive.

This fires for virtually every analytics domain, ad network, CDN resource, and any page that auto-refreshes. Combined with anomaly score, it pushes scores into SUSPICIOUS/BEACON territory.

**Additional bug**: The heuristic uses `.get("user_active_ratio", 1.0)` (default=1.0). But `feature_engine.py` computes it as `0.0` when `n=0`. So if features are empty, the heuristic defaults to "active" (1.0 = no trigger). This is safe but inconsistent with normal logic.

**Fix**:
1. Raise threshold from `< 0.10` to `< 0.05` (less than 5% active — tighter).
2. Guard with `background_tab_ratio < 0.5`: if traffic is already mostly background, the user_active signal is redundant and double-penalizes legitimate background tab traffic.
3. Combined condition: `user_active_ratio < 0.05 AND background_tab_ratio < 0.50`

---

#### ISSUE-H2: Heuristic `url_path_entropy` fires on legitimate analytics

**File affected**: `core/c3/analyzer.py` → `_heuristic_score()`

**Code**:
```python
if float(features.get("url_path_entropy", 1.0)) < 0.50:
    score += 0.10
    flags.append("same endpoint")
```

**Why it's wrong**: Low URL path entropy means many requests go to the same endpoint. This is indeed a beacon signal — but it also describes:
- Google Analytics: always hits `/collect` or `/g/collect`
- Facebook Pixel: always hits `/tr`
- CDN static assets from the same directory: `/assets/main.js`
- Any site using a polling API (weather widgets, chat, notifications)

The 0.50 threshold is extremely low. Even URLs with 2-3 characters of path variation produce entropy > 0.50. This heuristic alone is not strong enough to be meaningful but still adds 0.10 × fusion_weight to the score.

**Fix**: Remove as a standalone heuristic trigger. Replace with a compound rule: `url_path_entropy < 0.50 AND iat_cv < 0.10 AND iat_mean_ms > 0`. This way only hosts with BOTH same-endpoint requests AND regular timing get flagged — the intersection is very beacon-specific.

---

#### ISSUE-H3: Anomaly score normalization extrapolates to 1.0 for all real traffic

**File affected**: `core/c3/anomaly_engine.py` → `_normalize()`

**Code**:
```python
@staticmethod
def _normalize(raw: float, low: float, high: float) -> float:
    if high == low:
        return 0.0
    scaled = (raw - low) / (high - low)
    scaled = max(0.0, min(1.0, scaled))  # clamps below-range to 0.0
    return round(1.0 - scaled, 6)       # inverts: 0.0 → 1.0 (max anomaly)
```

- `low` = 5th percentile of `score_samples` on training data
- `high` = 95th percentile of `score_samples` on training data
- Isolation Forest: lower raw score = more anomalous

When a real sample falls BELOW `low` (below 5th percentile, i.e., more anomalous than 95% of the training set):
- `(raw - low) / (high - low)` is negative → clamped to 0.0
- `1.0 - 0.0 = 1.0` → **maximum anomaly score**

Because training data has zeroed F09–F14, every real browser request with non-zero values falls below the 5th percentile in those dimensions. This is the direct mechanistic cause of the 1.0 anomaly scores observed.

After ISSUE-C1 fix (training on F01–F08 only), this normalization will be correct for those 8 features. But we should also add a score-clamp for edge cases: if the normalized score would be ≥ 0.95 AND more than 5 features have zero values, return a reduced score to avoid extreme false positives.

**Fix**: Addressed by ISSUE-C1 fix (retrain on F01–F08). Additionally add a guard: if fewer than 6 of the 8 training features have non-zero values, return `None` (no anomaly score available) rather than potentially misleading 1.0.

---

### MEDIUM Issues

---

#### ISSUE-M1: No exclusion list for known-safe hosts

**File affected**: `core/c3/analyzer.py` → `_analyze_once()`

**Problem**: Common analytics, advertising, and CDN domains generate high volumes of regular, low-payload requests that superficially resemble beacons. Without exclusions, the detector produces persistent false positives for these well-known legitimate services.

Examples of domains that will trigger:
- `analytics.google.com` — Google Analytics collection endpoint, regular intervals
- `www.google-analytics.com` — same
- `googletagmanager.com` — GTM heartbeat/tag firing
- `pixel.facebook.com` — FB tracking pixel
- `pixel.twitter.com`, `t.co` — Twitter tracking
- `cdn.jsdelivr.net`, `cdnjs.cloudflare.com` — CDN assets, repeated paths
- `fonts.googleapis.com` — repeated font requests
- `doubleclick.net`, `googlesyndication.com` — ad serving

**Fix**: Add a `SAFE_HOST_SUFFIXES` tuple in `analyzer.py`. Before running analysis on a host, check if the host matches any safe suffix pattern. If matched, skip BEACON verdict (allow SUSPICIOUS max or skip entirely).

---

#### ISSUE-M2: Minimum event count for BEACON verdict is too low

**File affected**: `core/c3/analyzer.py` → `_analyze_once()`

**Code**:
```python
allow_beacon = len(events) >= 5
```

5 requests is insufficient to establish a statistically meaningful beacon pattern:
- IAT CV requires variance over multiple intervals (needs ≥ 10 to be meaningful)
- Background tab ratio with 5 samples has ±40% uncertainty
- False positive window: a page opening 5 background resources in quick succession

**Fix**: Raise to `allow_beacon = len(events) >= 10`. This requires the host to have sent at least 10 captured requests before a BEACON verdict is allowed. Keep `len(events) >= 3` as the minimum for SUSPICIOUS scoring.

---

#### ISSUE-M3: `background_tab_ratio` asymmetry in heuristic

**File affected**: `core/c3/analyzer.py` → `_heuristic_score()`

**Code**:
```python
if float(features.get("background_tab_ratio", 0.0)) > 0.80:
    score += 0.20
    flags.append("background traffic")
```

This is the most reliable of the browser-context heuristics and the threshold (0.80) is appropriate. However, it fires equally for a browser extension's background service worker doing legitimate work and a real beacon. 

Extension origins are already caught by `extension_origin_ratio > 0`, but the overlap means a non-extension background worker scores both `+0.20` (background) AND potentially `+0.25` (user idle). This double-counting adds 0.45 to the heuristic for what might be a service worker doing legitimate push notification polling.

**Fix**: If `extension_origin_ratio > 0`, the `background_tab_ratio` heuristic should not additionally fire (it's the same signal). Add exclusivity: if extension_origin already triggered, skip background_tab check.

---

#### ISSUE-M4: `requests_captured` counter never resets on session restart

**File affected**: `core/c3/interceptor.py`

**Code**:
```python
self._requests_captured = 0  # set in __init__, never reset in stop()
```

When `stop()` is called and then `start()` is called again, `_requests_captured` continues from where it left off. The UI shows a continuously growing number that doesn't reflect the current session.

**Fix**: Reset `_requests_captured = 0` in `stop()`.

---

#### ISSUE-M5: `ingestC3Status` triggers full API refresh on every WebSocket update

**File affected**: `frontend/dashboard.html` → `ingestC3Status()`

**Code**:
```javascript
function ingestC3Status(s) {
  c3Status = s || {};
  refreshC3();  // ← calls 4 separate fetch() calls
}
```

The `c3_status` WebSocket event is broadcast every 10 seconds. Every broadcast triggers 4 separate API calls:
- `GET /c3/status`
- `GET /c3/hosts`
- `GET /c3/alerts`
- `GET /c3/requests?limit=80`

This is 24 HTTP requests per minute just from status updates, increasing proportionally with browsing activity.

**Fix**: `ingestC3Status()` should only update the stats bar from the WebSocket payload (which already contains `requests_captured`, `hosts_monitored`, `alerts_count`, `blocked_count`). Only call the full `refreshC3()` on page load and when the user navigates to the C3 panel. Separate `renderC3Stats()` to use the WS payload directly.

---

### LOW / UI Issues

---

#### ISSUE-L1: C3 alert cards hardcoded to red (danger) border

**File affected**: `frontend/dashboard.html` → CSS `.c3-card` and `makeC3AlertCard()`

**Code (CSS)**:
```css
.c3-card {
  border-left: 3px solid var(--danger);  /* always red */
  ...
}
```

SUSPICIOUS alerts (score 0.3–0.6) should use amber (`var(--warn)`), BEACON alerts (≥0.6) should use red (`var(--danger)`). Currently all C3 alert cards are red regardless of verdict.

**Fix**: Remove `border-left` from `.c3-card` base style. In `makeC3AlertCard()`, set inline border-left based on verdict:
```javascript
const borderColor = vc === 'beacon' ? 'var(--danger)' 
                  : vc === 'suspicious' ? 'var(--warn)' 
                  : 'var(--safe)';
card.style.borderLeftColor = borderColor;
```

---

#### ISSUE-L2: Feature bar scale for `avg_idle_time_ms` is wrong

**File affected**: `frontend/dashboard.html` → `c3FeatureRisk()`

**Code**:
```javascript
if (name === 'avg_idle_time_ms') return Math.min(100, Math.round(value / 300));
```

Scale: `value / 300`. For:
- 5-minute idle (300,000ms): `300,000 / 300 = 1,000` → capped at 100 → **full red bar**
- 30-second idle (30,000ms): `30,000 / 300 = 100` → capped at 100 → **full red bar**
- 5-second idle (5,000ms): `5,000 / 300 = 16` → 16% bar (barely visible)

This means ANY request where the user hasn't clicked in the last 30 seconds shows a full red bar in the UI — which is completely normal behavior. This creates visual alarm for normal traffic.

The correct scale should reflect that a beacon fires after VERY long idle periods (minutes to hours):
- 5 min idle (300,000ms): ~15% risk
- 30 min idle (1,800,000ms): ~75% risk  
- 2 hours idle (7,200,000ms): 100% risk

**Fix**:
```javascript
if (name === 'avg_idle_time_ms') return Math.min(100, Math.round(value / 72000));
```
This sets 2-hour idle = 100%, 30-min idle = 25%, 5-min idle = ~4%.

---

#### ISSUE-L3: `url_path_entropy` feature risk scale shows wrong risk direction

**File affected**: `frontend/dashboard.html` → `c3FeatureRisk()`

**Code**:
```javascript
if (name === 'url_path_entropy') return value <= 0.5 ? 100 : value <= 1.5 ? 65 : value <= 3 ? 30 : 15;
```

This shows MAXIMUM risk for entropy ≤ 0.5 (same endpoint pattern). But since the training dataset has `url_path_entropy = 0` for ALL rows, the live feature value will never actually be 0 for real traffic (real URLs have paths with entropy ≥ 1.5). So the 100% case at `value <= 0.5` will visually show 65% for normal browsing (entropy 0.5–1.5), which overstates risk.

Real entropy values for common domains:
- CDN (same file path repeated): 1.0–1.5
- Analytics (same collect endpoint): 0.5–1.0
- Normal browsing (varied pages): 2.0–4.0
- Encoded exfil data in URL: 4.5–6.0

**Fix**:
```javascript
if (name === 'url_path_entropy') return value <= 0.5 ? 90 : value <= 1.0 ? 50 : value <= 2.0 ? 25 : value <= 4.0 ? 40 : 75;
```
Note: Very HIGH entropy (>4.0) is also suspicious (base64-encoded data in URLs). The risk curve should be U-shaped: low entropy (same endpoint) = medium-high risk, medium entropy (normal varied URLs) = low risk, very high entropy (encoded data) = high risk.

---

#### ISSUE-L4: C3 live monitor request table missing column headers in some states

**File affected**: `frontend/dashboard.html` → `#c3-pane-monitor` table

The `c3-request-rows` tbody renders 7 columns (host, method, size, tab context, user state, score, time). The corresponding `<thead>` row should define all 7 headers. If the thead is present but not visible due to CSS when the table is empty, the toggle between empty-state and table-state may look inconsistent.

**Fix**: Ensure thead is always visible when table has entries. Verify that column count in thead matches tbody. Ensure empty state (`c3-empty-requests`) uses `display:flex` for the empty message and `display:none` otherwise (current code does this correctly).

---

## Implementation Plan

The fixes are ordered by impact. Phase 1 addresses the root cause (critical false positives). Phases 2–4 progressively reduce residual false positives and improve UI accuracy.

---

### Phase 1 — Model Fix (Critical)

**Goal**: Stop the Isolation Forest from giving maximum anomaly score to all real traffic.

---

#### P1-T1: Update `anomaly_engine.py` to use only F01–F08

**File**: `core/c3/anomaly_engine.py`

Add a module-level constant for the subset of features the model was trained on:
```python
ANOMALY_FEATURE_SUBSET = [
    "iat_mean_ms",
    "iat_cv",
    "iat_bowley_skewness",
    "iat_mad_ms",
    "requests_per_hour",
    "payload_size_mean",
    "payload_size_std",
    "http_post_ratio",
]
```

Update `score()` to use `ANOMALY_FEATURE_SUBSET` instead of `FEATURE_ORDER`:
```python
def score(self, features: dict) -> tuple[Optional[float], str]:
    if not self._model:
        return None, "no isolation forest model"
    if self._cal_low is None or self._cal_high is None:
        return None, "missing calibration bounds"
    # Guard: require at least some non-zero features
    values = [float(features.get(name, 0.0)) for name in ANOMALY_FEATURE_SUBSET]
    nonzero = sum(1 for v in values if v != 0.0)
    if nonzero < 2:
        return None, "insufficient feature variance (fewer than 2 non-zero features)"
    X = np.array([values], dtype=float)
    raw = float(self._model.score_samples(X)[0])
    normalized = self._normalize(raw, self._cal_low, self._cal_high)
    return normalized, f"IF raw {raw:.4f} [{nonzero}/8 features active]"
```

**Why not remove F09–F14 from FEATURE_ORDER entirely?**: `FEATURE_ORDER` is shared with the feature engine and collection CSV schema. Only the anomaly engine changes which subset it uses. The heuristic scorer and collection pipeline continue to use all 14.

---

#### P1-T2: Update `train_c3_model.py` to use F01–F08 and cap requests_per_hour

**File**: `scripts/train_c3_model.py`

Changes:
1. Import `ANOMALY_FEATURE_SUBSET` from anomaly_engine (or redefine locally)
2. Cap `requests_per_hour` at 100,000 before training
3. Train only on the 8-feature subset
4. Save calibration bounds computed from the 8-feature scores

```python
from core.c3.anomaly_engine import ANOMALY_FEATURE_SUBSET

def preprocess(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    # Cap synthetic extremes in requests_per_hour
    df["requests_per_hour"] = df["requests_per_hour"].clip(upper=100_000)
    return df

def train(df: pd.DataFrame):
    df = preprocess(df)
    X = df[ANOMALY_FEATURE_SUBSET].astype(float)
    model = IsolationForest(
        n_estimators=200,
        contamination=0.02,
        random_state=42,
    )
    model.fit(X)
    scores = model.score_samples(X)
    low = float(np.percentile(scores, 5))
    high = float(np.percentile(scores, 95))
    print(f"Trained on {len(X)} rows using {len(ANOMALY_FEATURE_SUBSET)} features")
    print(f"Calibration: low={low:.4f}, high={high:.4f}")
    return model, low, high
```

---

#### P1-T3: Also cap `requests_per_hour` at inference time in `feature_engine.py`

**File**: `core/c3/feature_engine.py`

Add a cap in `compute_features()`:
```python
"requests_per_hour": round(min(n / (duration_s / 3600.0), 100_000.0), 4),
```

This ensures inference-time feature values are in the same range the model was trained on.

---

#### P1-T4: Retrain and save the model

After code changes above, run:
```bash
python scripts/train_c3_model.py
```

Expected output:
```
Loaded: c3_extracted_v2.csv (15000 rows)
Trained on 9000 rows using 8 features
Calibration: low=X.XXXX, high=Y.YYYY
Saved model -> models/c3_isolation_forest.pkl
Restart the FastAPI backend to load the trained model.
```

---

### Phase 2 — Heuristic Fix (High)

**Goal**: Reduce false positive rate from heuristic scoring without losing true positive coverage.

---

#### P2-T1: Fix `user_active_ratio` heuristic — raise threshold + add guard

**File**: `core/c3/analyzer.py` → `_heuristic_score()`

Current:
```python
if float(features.get("user_active_ratio", 1.0)) < 0.10:
    score += 0.25
    flags.append("fires while user idle")
```

Replacement:
```python
uar = float(features.get("user_active_ratio", 1.0))
bg = float(features.get("background_tab_ratio", 0.0))
# Only fire if predominantly foreground traffic that fires without user interaction.
# Exclude if mostly background traffic (already scored by background_tab_ratio heuristic).
if uar < 0.05 and bg < 0.50:
    score += 0.25
    flags.append("foreground requests firing while user idle")
```

**Rationale**: `uar < 0.05` (< 5% active) is a stricter threshold. `bg < 0.50` prevents double-penalizing background tab traffic.

---

#### P2-T2: Remove standalone `url_path_entropy` heuristic; replace with compound rule

**File**: `core/c3/analyzer.py` → `_heuristic_score()`

Current:
```python
if float(features.get("url_path_entropy", 1.0)) < 0.50:
    score += 0.10
    flags.append("same endpoint")
```

Replacement:
```python
path_ent = float(features.get("url_path_entropy", 1.0))
iat_cv = float(features.get("iat_cv", 1.0))
iat_mean = float(features.get("iat_mean_ms", 0.0))
# Only score same-endpoint if COMBINED with regular timing — strong beacon indicator
if path_ent < 0.50 and iat_cv < 0.10 and iat_mean > 0:
    score += 0.10
    flags.append("same endpoint with regular timing")
```

**Rationale**: Same-endpoint alone describes analytics/CDN. Same-endpoint WITH regular timing (iat_cv < 0.10) is a much tighter beacon signal.

---

#### P2-T3: Fix `background_tab_ratio` double-counting with `extension_origin_ratio`

**File**: `core/c3/analyzer.py` → `_heuristic_score()`

Add a guard to avoid double-scoring extension background traffic:

```python
ext = float(features.get("extension_origin_ratio", 0.0))
bg = float(features.get("background_tab_ratio", 0.0))
# Score background tab traffic only if it is NOT already captured by extension_origin
if bg > 0.80 and ext == 0.0:
    score += 0.20
    flags.append("background traffic (non-extension)")
elif bg > 0.80:
    score += 0.08  # reduced weight if extension already explains background
    flags.append("background traffic (extension)")
```

---

#### P2-T4: Verify updated heuristic score range

After these changes, the maximum achievable heuristic score from normal traffic should drop from `~0.80` (all 4 triggers firing) to `< 0.30` (only the regular timing trigger should realistically fire for analytics). Verify manually against test cases.

---

### Phase 3 — Analyzer + Engine Fixes (Medium)

---

#### P3-T1: Add known-safe host exclusion list

**File**: `core/c3/analyzer.py`

Add at module level:
```python
_SAFE_HOST_SUFFIXES: tuple[str, ...] = (
    "google-analytics.com",
    "analytics.google.com",
    "googletagmanager.com",
    "googletagservices.com",
    "googlesyndication.com",
    "doubleclick.net",
    "pixel.facebook.com",
    "facebook.net",
    "pixel.twitter.com",
    "analytics.twitter.com",
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "use.fontawesome.com",
    "ajax.googleapis.com",
    "static.cloudflareinsights.com",
)

def _is_safe_host(host: str) -> bool:
    h = host.lower()
    return any(h == s or h.endswith("." + s) for s in _SAFE_HOST_SUFFIXES)
```

In `_analyze_once()`, add early skip:
```python
for host, events in snapshots.items():
    if len(events) < 3:
        continue
    if _is_safe_host(host):
        # Still track these hosts (for collection mode) but cap verdict at SAFE
        continue  # or score as SAFE without analysis
```

Note: Make this configurable or at least log when a host is skipped so it's visible during debugging.

---

#### P3-T2: Raise minimum event count for BEACON verdict

**File**: `core/c3/analyzer.py` → `_analyze_once()`

Change:
```python
allow_beacon = len(events) >= 5
```
To:
```python
allow_beacon = len(events) >= 10
```

This means a host needs 10+ captured requests before a BEACON verdict is allowed. It still allows SUSPICIOUS after 3 events. This significantly reduces false positives from hosts that trigger early in a browsing session.

---

#### P3-T3: Reset `requests_captured` counter on session stop

**File**: `core/c3/interceptor.py` → `stop()`

Add reset in `stop()`:
```python
async def stop(self) -> None:
    self._running = False
    self._requests_captured = 0   # ← add this line
    for session in list(self._sessions.values()):
        ...
```

---

#### P3-T4: Add anomaly score guard for insufficient feature data

**File**: `core/c3/anomaly_engine.py` → `score()`

Already described in P1-T1. When fewer than 2 of the 8 training features are non-zero, return `None` rather than producing a potentially misleading score. This prevents the model from scoring hosts where timing data hasn't accumulated yet.

---

### Phase 4 — UI Fixes (Low-Medium)

These changes are ONLY in `frontend/dashboard.html`. They do not touch any backend or other component.

---

#### P4-T1: Fix C3 alert card border color to reflect actual verdict

**File**: `frontend/dashboard.html`

CSS change — remove `border-left` from `.c3-card` base style:
```css
/* Before */
.c3-card {
    border-left: 3px solid var(--danger);   /* remove this */
    ...
}

/* After */
.c3-card {
    border-left: 3px solid var(--b2);  /* neutral default */
    ...
}
```

JS change in `makeC3AlertCard()`:
```javascript
function makeC3AlertCard(a) {
  const score = Math.round(Number(a.score || 0) * 100);
  const vc = String(a.verdict || 'BEACON').toLowerCase();
  const borderColor = vc === 'beacon' ? 'var(--danger)'
                    : vc === 'suspicious' ? 'var(--warn)'
                    : 'var(--safe)';
  const card = document.createElement('div');
  card.className = 'c3-card';
  card.style.borderLeftColor = borderColor;
  // rest of innerHTML ...
```

---

#### P4-T2: Fix `avg_idle_time_ms` feature bar scale

**File**: `frontend/dashboard.html` → `c3FeatureRisk()`

Change:
```javascript
// Before
if (name === 'avg_idle_time_ms') return Math.min(100, Math.round(value / 300));

// After: 2-hour idle = 100%, 30-min idle = ~25%, 5-min idle = ~4%
if (name === 'avg_idle_time_ms') return Math.min(100, Math.round(value / 72000));
```

---

#### P4-T3: Fix `url_path_entropy` feature bar U-shaped risk curve

**File**: `frontend/dashboard.html` → `c3FeatureRisk()`

Change:
```javascript
// Before
if (name === 'url_path_entropy') return value <= 0.5 ? 100 : value <= 1.5 ? 65 : value <= 3 ? 30 : 15;

// After: U-shaped — low entropy (same endpoint) and very high entropy (encoded data) are both risky
if (name === 'url_path_entropy') {
  if (value <= 0.5) return 85;       // same endpoint = beacon-like
  if (value <= 1.5) return 45;       // CDN/analytics range
  if (value <= 3.0) return 15;       // normal browsing (lowest risk)
  if (value <= 4.5) return 30;       // elevated (varied but structured)
  return 70;                          // very high entropy = possible encoded exfil
}
```

---

#### P4-T4: Optimize `ingestC3Status` to not trigger full refresh on every WS update

**File**: `frontend/dashboard.html` → `ingestC3Status()`

Change:
```javascript
// Before
function ingestC3Status(s) {
  c3Status = s || {};
  refreshC3();  // 4 API calls every 10 seconds
}

// After: update stats in-place from WS payload, no extra API calls
function ingestC3Status(s) {
  if (!s) return;
  c3Status = { ...c3Status, ...s };  // merge (WS payload has most status fields)
  renderC3Stats();                    // only re-render the stats bar
  renderC3Collection();               // update collection status
}
```

Only call the full `refreshC3()` on page load (initial data fetch) and when the user explicitly switches to the C3 panel.

---

#### P4-T5: Verify C3 request table column headers match tbody

**File**: `frontend/dashboard.html`

The request table tbody renders 7 columns:
1. Host
2. Method
3. Size
4. Tab Context (Background / Active tab)
5. User State (Active / Idle)
6. Score (pill)
7. Time

Ensure the `<thead>` for `#c3-pane-monitor` table contains exactly these 7 column headers in order. If currently missing or mismatched, add:
```html
<thead>
  <tr>
    <th>Host</th>
    <th>Method</th>
    <th>Size</th>
    <th>Tab</th>
    <th>User</th>
    <th>Score</th>
    <th>Time</th>
  </tr>
</thead>
```

---

## Files to Change — Quick Reference

| File | Changes | Phase |
|---|---|---|
| `core/c3/anomaly_engine.py` | Add `ANOMALY_FEATURE_SUBSET` (F01–F08), update `score()` to use subset, add non-zero guard | P1 |
| `scripts/train_c3_model.py` | Import/use `ANOMALY_FEATURE_SUBSET`, cap `requests_per_hour` at 100K, train on 8 features only | P1 |
| `core/c3/feature_engine.py` | Cap `requests_per_hour` at 100K in `compute_features()` | P1 |
| `core/c3/analyzer.py` | Fix `user_active_ratio` heuristic (threshold + guard), fix `url_path_entropy` (compound rule), fix bg/ext double-counting, raise BEACON event minimum to 10, add `_is_safe_host()` exclusion | P2, P3 |
| `core/c3/interceptor.py` | Reset `_requests_captured = 0` in `stop()` | P3 |
| `frontend/dashboard.html` | Fix alert card border colors, fix idle_time bar scale, fix entropy bar scale, optimize `ingestC3Status`, verify table headers | P4 |

**Files NOT to change**: `core/c1/`, `core/c2/`, `core/c4/`, `core/playwright_session.py` — only C3 is modified.

---

## Testing Checklist

### After Phase 1 (Model Retrain)

- [ ] Run `python scripts/train_c3_model.py` — no errors, model saved
- [ ] Restart backend — logs show `[C3] Isolation Forest model loaded`
- [ ] Start Playwright session and browse to 3–5 normal websites (Reddit, Wikipedia, YouTube)
- [ ] After 60 seconds: check `/c3/hosts` — anomaly scores should be `< 0.5` for well-known domains
- [ ] Open the C3 test beacon page at 10-second interval
- [ ] After 60 seconds: check that the test beacon page's target host (`127.0.0.1`) scores ≥ 0.6
- [ ] Verify no normal browsing hosts appear in `/c3/alerts`

### After Phase 2 (Heuristic Fix)

- [ ] Browse for 5 minutes without clicking (read-only, let page idle)
- [ ] Verify analytics/CDN domains have heuristic_score < 0.30
- [ ] Verify test beacon page still scores heuristic_score ≥ 0.30 (background + regular timing)

### After Phase 3 (Analyzer Fixes)

- [ ] Verify `analytics.google.com` is skipped in analysis output (safe host exclusion)
- [ ] Verify hosts with < 10 events never show BEACON verdict
- [ ] After stopping and restarting session, verify request counter resets to 0

### After Phase 4 (UI Fixes)

- [ ] Open C3 → Alerts tab: SUSPICIOUS alert cards should show amber border, BEACON should show red
- [ ] Open C3 → Alerts tab: feature bar for `avg_idle_time_ms` at 30 min idle ≈ 25% (not full red)
- [ ] Open C3 → Alerts tab: `url_path_entropy` at value 2.5 shows low risk (normal browsing range)
- [ ] Open browser DevTools → Network → observe only 4 API calls on initial load, not every 10 seconds
- [ ] C3 request table headers match 7 data columns

### Regression Check (Other Components)

- [ ] C2 panel still works (BitB detection, URL analysis, visual similarity)
- [ ] C1 panel still works (extension analyzer)
- [ ] Navigation bar URL input still works
- [ ] WebSocket `analysis` events still populate C2 panel

---

## Appendix: Dataset Quality Notes

The `c3_extracted_v2.csv` dataset is suitable ONLY for training the network-timing features (F01–F08) of the Isolation Forest after applying the Phase 1 changes. It is NOT suitable for:
- Evaluating browser-context features (F09–F12) — these are always 0
- Supervised classification — beacon timing features are also 0 for label=1
- Calibrating path entropy or burst count features — these are always 0

For a fully correct model incorporating all 14 features, the Phase 3 self-collection workflow (described in `ARCHITECTURE.md`) must be used:
1. Browse normally for 30–60 minutes with collection mode label=0
2. Run test beacon page for 10–20 minutes with collection mode label=1
3. Merge self-collected data with `c3_extracted_v2.csv`
4. Retrain Isolation Forest on merged label=0 rows

Until self-collected data is available, the Phase 1 fix (8-feature model) is the correct production configuration. The heuristic scorer provides F09–F12 coverage without requiring training data.
