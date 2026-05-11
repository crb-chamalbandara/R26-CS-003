# Component 3 — C2 Beacon: Browser Execution Aware C2 Beacon Detector

> **Status:** 🔧 Architecture Revised — Isolation Forest + Threat Intelligence Fusion

## Research Question

Can browser-execution-aware anomaly detection combined with real-time threat intelligence identify stealthy browser-based C2 beaconing behaviour, even when the traffic uses trusted platforms such as Discord, GitHub, Google Docs, or Cloudflare?

---

## Architecture Overview

```
Playwright Persistent Chromium Session (core/playwright_session.py)
      │
      │  context.expose_function() + context.add_init_script()
      │  ──► User interaction tracking (click, keydown, scroll, touchstart)
      │  ──► page.evaluate() on restored tabs (covers persistent context restores)
      │
      │  CDP Network.enable (one CDP session per page/tab)
      │  ──► Captures every outbound request (fire-and-forget, zero perf impact)
      │
      ├── Request: URL, method, headers, payload size, timestamp
      ├── Context: user-active flag, background-tab flag, extension-origin flag
      └── Timing: inter-request intervals per host
              │
              ▼
        Per-host rolling window (max 50 events, in-memory deque)
              │
              ▼
        14-feature ML vector (computed every 10 seconds)
              │
              ▼
      Three-signal detection pipeline
        1. Isolation Forest anomaly score   → trained on benign browsing baseline
        2. Threat intelligence reputation   → AbuseIPDB, OTX, VirusTotal, URLhaus, Feodo
        3. Heuristic rule-based scorer      → always available, works from day one
              │
              ▼
      Hybrid risk fusion engine
        final = 0.60×anomaly + 0.25×reputation + 0.15×heuristic
        with override rules for high-confidence signals
        adaptive weights when any signal is unavailable
              │
              ▼
    Verdict: SAFE (<0.3) | SUSPICIOUS (0.3–0.6) | BEACON (≥0.6)
              │
              ▼
    BEACON ≥ 0.8 → block host via targeted Playwright route (per-host pattern only)
    Alert → SQLite + WebSocket broadcast → Dashboard
    Collection mode → auto-flush to data/c3_collection_in_progress.csv
```

---

## Core Architectural Change

### Previous Design

Primary detection relied on supervised XGBoost classification trained on both normal and malicious labelled data. Required balanced datasets of beacon traffic for training. Detection was limited to patterns seen during training.

### New Design

Primary detection uses Isolation Forest anomaly detection trained exclusively on benign browsing data. Malicious traffic is no longer needed for model training — only for threshold validation. Detection is supplemented by real-time threat intelligence reputation checks and deterministic heuristic rules, combined through a weighted fusion engine.

### Why Isolation Forest Is Correct for C3

Isolation Forest eliminates the labelled-data problem. Supervised classification requires balanced datasets of both normal and malicious traffic. Real C2 beacon samples are scarce, vary enormously across threat actors, and a classifier trained on Cobalt Strike patterns would miss a novel C2 framework with different timing. Isolation Forest learns what normal browsing looks like and flags any behaviour that deviates from that baseline — including patterns never seen before.

Browser context features are naturally suited to anomaly detection. Normal browsing has very distinctive patterns: user is active (F10 near 1.0), foreground tab (F11 near 0.0), varied timing (F02 around 0.5–1.5), diverse URL paths (F13 high). Beacon traffic is a clear outlier in this feature space — regular timing, idle user, background tab, same endpoint. Isolation Forest isolates these outliers in few tree splits.

Isolation Forest (Liu et al., 2008) is an established anomaly detection method in network security research. The novel contribution is applying it with browser-internal features (F09–F12) that traditional network IDS cannot access.

---

## Tech Stack

| Layer | Technology | Reason |
|-------|-----------|--------|
| Network interception | CDP `Network.enable` | Fire-and-forget events — zero browser performance impact. Browser does NOT pause for Python handler. |
| User interaction tracking | Playwright `context.expose_function()` + `context.add_init_script()` + `page.evaluate()` | DOM-level intentional-action detection (click, keydown, scroll, touchstart). `page.evaluate()` covers already-loaded restored tabs on persistent context startup. |
| Request blocking | Playwright `context.route()` per blocked host only | Targeted blocking — no global route handler, no performance overhead on unblocked traffic. `context.unroute(pattern)` without handler removes all routes for that pattern. |
| Anomaly detection (primary) | Isolation Forest (scikit-learn) | Unsupervised anomaly detection trained on benign browsing baseline. Detects novel threats without labelled malware data. |
| Threat intelligence | AbuseIPDB + AlienVault OTX + VirusTotal + URLhaus + Feodo Tracker | Real-time IP/domain reputation validation using async API queries and local feed matching. Catches known malicious infrastructure. Smart-query strategy: only queries TI for hosts that already show anomalous or suspicious behaviour — avoids wasting rate-limited API calls on obviously clean hosts. |
| Risk fusion | Custom weighted scoring engine | Combines three detection signals with adaptive weights and override rules for high-confidence scenarios. |
| Heuristic fallback | Rule-based scorer | Works without any trained model or API keys from day one. Deterministic beacon pattern rules. |
| Alert storage | SQLite at `~/.websentinel/c3_alerts.db` | Zero-config, in-process, survives restarts. Directory guaranteed to exist — created by `playwright_session.py` at session start. |
| Rolling windows | In-memory `collections.deque(maxlen=50)` | Per-host, fast, no external dependency. |
| TI cache | In-memory dict with TTL expiry | Avoids repeated API calls, respects rate limits. Clean hosts cached 1 hour, suspicious hosts cached 15 minutes, malicious hosts cached 24 hours. |
| TI local feeds | Feodo Tracker CSV/JSON downloaded on startup | Known botnet C2 IP list checked locally — zero latency, no API key, no rate limit. Feed refreshed every 6 hours. |
| Collection persistence | Auto-flush to `data/c3_collection_in_progress.csv` | Feature vectors written to disk as collected — survives server crashes during training sessions. |

---

## The 14 ML Features

| # | Name | What It Measures | Beacon Signal |
|---|------|-----------------|---------------|
| F01 | IAT Mean | Average time between requests to this host (ms) | Beacons have consistent intervals |
| F02 | IAT CV | Coefficient of variation of inter-arrival times | Beacons ≈ 0 (perfectly regular), normal ≈ 0.5–1.5 |
| F03 | IAT Bowley Skewness | Statistical skewness of timing distribution | Timing distribution asymmetry |
| F04 | IAT MAD | Median Absolute Deviation of inter-arrival times | Robust regularity measure (literature-standard) |
| F05 | Requests / Hour | Number of requests per hour to this host | Volume normalisation |
| F06 | Payload Size Mean | Average response payload in bytes | C2 check-ins are typically tiny (<1KB) |
| F07 | Payload Size Std | Variability of response payload sizes | Beacons have very consistent sizes |
| F08 | HTTP Method Ratio | Fraction of POST requests | Beacons alternate GET (check-in) and POST (exfil) |
| F09 | Avg Idle Time | Mean user idle time when requests fire (ms) | **Research novelty** — beacons fire during idle. Measured from click/keydown/scroll/touchstart only (mousemove excluded — too noisy). |
| F10 | User Active Ratio | Fraction of requests while user was actively interacting | **Research novelty** — normal ≈ 1, beacons ≈ 0. Intentional-action events only. |
| F11 | BG Tab Ratio | Fraction of requests from non-active tabs or worker contexts | Beacons fire from background. Worker-originated requests forced to background. |
| F12 | Extension Origin | Fraction of requests from `chrome-extension://` initiator | Direct extension attribution |
| F13 | URL Path Entropy | Shannon entropy of URL path characters across window | Low = same endpoint repeatedly, high = encoded exfil |
| F14 | Request Burst Count | Non-overlapping clusters of ≥3 requests within 2 seconds | Exfiltration bursts. Sliding scan: advance index past burst members before checking next cluster. |

---

## File Map

| File | Role |
|------|------|
| `__init__.py` | Package marker + module exports |
| `context_tagger.py` | JS injection user interaction tracking (click/keydown/scroll/touchstart only) + `page.evaluate()` on restored tabs + browser context enrichment (idle time, background tab, extension origin, worker detection) |
| `interceptor.py` | CDP network hook — per-page sessions with close cleanup, dual-dict request correlation with 30s TTL purge, targeted per-host blocking with stored handler references |
| `feature_engine.py` | 14-feature ML vector computation from per-host rolling windows |
| `anomaly_engine.py` | **(create — replaces beacon_model.py)** Isolation Forest model loading, training, and scoring. Normalises raw IF scores to 0–1 using calibration bounds from training data. Falls back gracefully when no model exists. |
| `reputation_engine.py` | **(create)** Async threat intelligence queries to AbuseIPDB, AlienVault OTX, VirusTotal, and URLhaus. Local feed matching for Feodo Tracker. In-memory TTL cache per host. DNS resolution with CDN-awareness. Smart-query gating. Returns normalised 0–1 reputation score. Degrades gracefully when API keys are missing or calls fail. |
| `risk_fusion.py` | **(create)** Weighted fusion of anomaly, reputation, and heuristic signals. Adaptive weights when any signal is unavailable. Override rules for high-confidence scenarios. Produces final score and verdict. |
| `alert_store.py` | SQLite alert persistence + in-memory cache. Defensive `mkdir(parents=True, exist_ok=True)` on init. |
| `analyzer.py` | **(modify)** Background asyncio analysis loop (every 10s) updated to call anomaly engine, reputation engine, and fusion engine instead of single classifier. Two-tier detection thresholds + collection mode with auto-flush. |

Supporting files (project root level):

- `models/c3_isolation_forest.pkl` — trained Isolation Forest model + calibration bounds (generate via `scripts/train_c3_model.py`)
- `scripts/train_c3_model.py` — Isolation Forest trainer using benign-only data with contamination parameter and calibration bound computation

Endpoints served directly by `core/main.py`:

- `GET /c3/test/beacon-page?interval=30000` — serves test beacon HTML inline (no file dependency)
- `GET /c3/test/beacon-target` and `POST /c3/test/beacon-target` — localhost beacon target for validation

Modified files:

- `core/main.py` — update C3 imports to use new engine modules, add TI API key configuration
- `frontend/dashboard.html` — update C3 alert cards to show three-signal breakdown (anomaly / reputation / heuristic)

---

## Integration Interface

`core/main.py` imports and calls:

```python
from .c3.context_tagger import c3_tagger     # setup(context) → JS injection + restored tab coverage
from .c3.interceptor   import c3_interceptor # start(pw_session) / stop() → CDP monitoring
from .c3.analyzer      import c3_analyzer    # start_loop(pw_session, broadcast_fn) / stop_loop()
```

---

## Key Design Decisions

### 1. CDP for monitoring, Playwright route only for blocking

CDP `Network.enable` events are fire-and-forget — the browser does NOT pause and wait for the Python handler. This means zero performance impact during normal browsing. A global `context.route("**/*")` would intercept every single request (images, fonts, CSS, JS, ads) and pause each one until the Python handler responds — causing noticeable slowdowns on complex pages (100–300 requests per page load).

Therefore: use CDP for all data collection. Use `context.route()` ONLY for blocking confirmed beacon hosts, registered as a specific pattern per host: `**://{host}/**`. Blocking is removed by calling `context.unroute(pattern)` without a handler parameter — this removes all routes for that URL pattern without needing to store the original handler reference. Zero overhead during normal monitoring.

### 2. Multi-tab CDP sessions with cleanup

Each browser tab requires its own CDP session via `context.new_cdp_session(page)`. When the user opens a new tab, C3 attaches a new CDP session via `context.on("page", _on_new_page)`. When a tab is closed, its CDP session becomes invalid — C3 cleans it up via `page.on("close", _cleanup_cdp_session)` and wraps all CDP calls in error handling to prevent crashes from dead sessions.

### 3. CDP request/response correlation with dual-dict

CDP does NOT guarantee that `Network.requestWillBeSent` arrives before `Network.responseReceived` for the same `requestId`. C3 handles this with two dicts: one for pending requests awaiting their response, and one for orphan responses that arrived before their request. When either event arrives, both dicts are checked and merged when a match is found. Stale entries older than 30 seconds are purged every 60 seconds to prevent memory accumulation from cancelled or timed-out requests.

### 4. User interaction tracking — intentional actions only

C3 detects user activity by injecting JavaScript into every page via `context.add_init_script()`. The JS listens for `click`, `keydown`, `scroll`, and `touchstart` events only. `mousemove` is explicitly excluded — it fires during passive cursor presence over the browser window, during cursor-following page animations, and during focus changes between applications. These are not evidence of deliberate user engagement and would artificially inflate F10 and deflate F09, weakening the two most novel research features.

Both `context.expose_function()` and `context.add_init_script()` must be registered after `pw_session.start()` but BEFORE the first `pw_session.navigate()` call.

### 5. Restored tab coverage for persistent context

In a Playwright persistent context, previous tabs may be restored on startup. These pages are already fully loaded — `add_init_script()` does not retroactively execute in them. To ensure complete F09/F10 coverage from session start, `context_tagger.setup()` iterates all pages in `context.pages` after registering the init script and injects the same tracking JavaScript directly via `page.evaluate()`. The init script handles all future navigations automatically. This two-path approach ensures no tab is ever missing the interaction tracker regardless of how it was created.

### 6. Worker-originated request handling

Requests from service workers, web workers, or other non-page contexts have no associated tab. C3 checks the CDP `initiator.type` field. If the type is not `"script"` or `"parser"`, the request is forced to `is_background_tab = True` and `user_was_active = False`. This correctly computes F10 and F11 for worker traffic without requiring page URL comparison.

### 7. Two-tier detection threshold

With 3–4 events from a host: compute non-timing features only (F05–F14) and allow SUSPICIOUS verdict but never BEACON. With 5+ events: compute all 14 features and allow full BEACON verdict with blocking. Exception: if threat intelligence confirms the host is known-malicious (reputation score above 0.8), BEACON verdict is permitted even with fewer than 5 events. This prevents premature false positives on newly observed hosts while still catching known bad infrastructure immediately.

### 8. Isolation Forest scoring and normalisation

scikit-learn `IsolationForest.score_samples()` returns raw anomaly scores where lower values (more negative) indicate more anomalous samples. C3 normalises these to a 0–1 range where higher means more suspicious. Calibration bounds are computed during training as the 5th percentile (most anomalous normal sample) and 95th percentile (most typical normal sample) of the training data's score distribution. Raw scores are linearly mapped within these bounds and clamped to 0–1, then inverted so that 1.0 represents maximum anomaly.

### 9. Threat intelligence design

Threat intelligence in C3 is additive, asynchronous, cached, optional, and non-blocking. The detection pipeline continues functioning even if all TI providers are unavailable. TI lookups run using `httpx.AsyncClient` to prevent browser slowdown, Playwright blocking, or analysis loop stalls.

**Sources and how each is used:**

| Source | Type | Free Tier | What It Checks | Score Mapping |
|--------|------|-----------|---------------|---------------|
| AbuseIPDB | API query | 1000 checks/day | IP abuse confidence score | `confidence_score / 100` |
| AlienVault OTX | API query | Unlimited (free key) | IOC pulse reputation for IPs and domains | `1.0` if IOC has malware/C2 pulses, scaled by pulse count |
| VirusTotal | API query | 4 requests/minute, 500/day | Domain and IP detection ratio | `positives / total_scanners` |
| URLhaus | API query | Unlimited, no key | Known malware distribution URLs | `1.0` if URL or host is listed, `0.0` if not |
| Feodo Tracker | Local feed | Unlimited, no key | Known botnet/C2 IP addresses (Dridex, TrickBot, QakBot, BumbleBee) | `1.0` if IP is in active feed, `0.0` if not |

**Critical design corrections:**

Feodo Tracker is NOT a per-request API. It publishes CSV and JSON feeds of known C2 IP addresses that are downloaded and checked locally. C3 downloads the Feodo IP blocklist on startup and refreshes it every 6 hours. All Feodo checks are instant local lookups with zero latency and no rate limit. This is the fastest and most reliable TI source in the pipeline.

AbuseIPDB and Feodo check IPs, not domains. The interceptor captures hostnames from URLs, not IP addresses. DNS resolution via `socket.getaddrinfo()` is required before querying these sources. However, resolving the IP of hosts on shared infrastructure (Cloudflare, AWS CloudFront, Akamai, Fastly) gives CDN edge IPs that would produce misleading reputation data. C3 maintains a list of known CDN domain patterns and skips IP-based lookups for hosts matching those patterns — domain-based sources (OTX, VirusTotal, URLhaus) are still queried for these hosts.

VirusTotal free tier is extremely limited at 4 requests per minute. Active browsing can hit 50+ unique hosts within minutes. Querying every host would exhaust the quota instantly. C3 uses smart-query gating: TI is only queried for hosts where the anomaly score or heuristic score already exceeds 0.2 (SUSPICIOUS-leaning). Hosts that are clearly safe from behavioural analysis alone are never sent to rate-limited APIs. This concentrates limited API calls on hosts that actually need reputation validation.

AlienVault OTX provides a free API with no strict rate limit. The official Python SDK (`OTXv2`) is synchronous. C3 uses raw `httpx.AsyncClient` against the OTX REST API (`/api/v1/indicators/`) instead of the SDK to maintain full async compatibility without thread executor overhead.

**Reputation scoring:** The aggregated reputation score is the maximum across all sources — a single high-confidence malicious hit from any source is sufficient.

**Reputation workflow:**

```
Analyzer loop identifies host with anomaly_score > 0.2 or heuristic_score > 0.2
        ↓
Check local TTL cache for host
        ↓
If cache hit → return cached score immediately
        ↓
If cache miss:
        ├── Resolve host IP via DNS (skip for CDN-pattern hosts)
        ├── Check Feodo local feed (IP match — instant)
        ├── Query URLhaus (host/URL — no key, no rate limit)
        ├── Query AlienVault OTX (domain + IP — free key, no strict limit)
        ├── Query AbuseIPDB (IP only — requires key, 1000/day)
        └── Query VirusTotal (domain — requires key, 4/min)
        ↓
All queries run concurrently via asyncio.gather()
        ↓
Normalise individual scores to 0–1
        ↓
reputation_score = max(all_source_scores)
        ↓
Store in TTL cache and return to fusion engine
```

**TTL cache policy:**

| Reputation Result | Cache Duration | Reason |
|------------------|----------------|--------|
| Clean (score below 0.1) | 1 hour | Legitimate hosts rarely become malicious mid-session |
| Suspicious (score 0.1–0.5) | 15 minutes | Re-check soon in case new intelligence arrives |
| Malicious (score above 0.5) | 24 hours | Confirmed malicious status is unlikely to change quickly |

**Offline behaviour:** If no API keys are configured, internet is unavailable, or all API quotas are exhausted, the reputation score returns `None`. The fusion engine automatically redistributes weights to anomaly and heuristic signals. Feodo local feed lookups continue working offline if the feed was previously downloaded. The system works fully offline — this is critical for a research project where API keys may not always be available.

### 10. Hybrid risk fusion with override rules

The fusion engine combines three signals using weighted addition. When all three signals are available: `final = 0.60 × anomaly + 0.25 × reputation + 0.15 × heuristic`. When the anomaly engine is unavailable (no trained model): `final = 0.55 × heuristic + 0.45 × reputation`. When reputation is unavailable (no API keys or offline): `final = 0.75 × anomaly + 0.25 × heuristic`. When only heuristics are available (day-one fallback): `final = heuristic_score`.

Override rules prevent dangerous misses: if reputation score is above 0.8, the final score is raised to at least 0.60 (known malicious infrastructure always triggers BEACON). If anomaly score is above 0.80 and heuristic score is above 0.50, the final score is raised to at least 0.60 (strong agreement between behavioural analysis and rule-based checks should be trusted).

### 11. Heuristic scoring rules

The heuristic scorer works without any trained model or API keys using these rules:

- IAT CV below 0.05 and IAT mean above 0 → +0.30 (perfectly regular timing)
- User active ratio below 0.1 → +0.25 (fires while user idle)
- Background tab ratio above 0.8 → +0.20 (background tab)
- Extension origin flag above 0 → +0.15 (extension-originated)
- URL path entropy below 0.5 → +0.10 (same endpoint repeatedly)
- Score capped at 1.0

Verdict thresholds: SAFE (below 0.3), SUSPICIOUS (0.3 to 0.6), BEACON (0.6 and above). Host blocking at 0.8 and above.

### 12. Collection data auto-flush

When collection mode is active, each computed feature vector is immediately appended to `data/c3_collection_in_progress.csv` as it is produced. Data is not held only in memory. If the server process crashes during a long collection session, all previously collected vectors survive on disk. The export endpoint finalises the in-progress file by renaming it with a timestamp and the collection label, then resets the in-progress file for the next session.

---

## Session Lifecycle Hooks

**On session start** — insert into `_bg_start_session()` in `core/main.py`, after `pw_session.start()` and BEFORE `navigate(home)`:

1. Call `c3_tagger.setup(pw_session.context)` — registers JS injection, covers restored tabs via `page.evaluate()`
2. Call `c3_interceptor.start(pw_session)` — attaches CDP sessions to all pages, registers page listener for new tabs
3. Call `c3_analyzer.start_loop(pw_session, _broadcast)` — starts background analysis task

**On session stop** — insert into `session_stop()` in `core/main.py`, BEFORE `pw_session.stop()`:

1. Call `c3_analyzer.stop_loop()` — cancels background task
2. Call `c3_interceptor.stop()` — detaches CDP sessions

---

## Endpoints (added to `core/main.py`)

| Method | Path | Returns |
|--------|------|---------|
| `GET` | `/c3/status` | `{running, hosts_monitored, alerts_count, requests_captured, model_type, ti_available}` |
| `GET` | `/c3/alerts` | List of beacon alerts with all 14 feature values and signal breakdown |
| `GET` | `/c3/hosts` | All monitored hosts with current scores and request counts |
| `GET` | `/c3/hosts/{host}` | Detailed rolling window + feature breakdown + signal breakdown for a specific host |
| `GET` | `/c3/requests` | Recent captured requests with context tags |
| `POST` | `/c3/collect/start` | Start collection mode — body: `{"label": 0 or 1}` |
| `POST` | `/c3/collect/stop` | Stop collection mode |
| `POST` | `/c3/collect/export` | Finalise and export collected CSV — returns `{"path": "..."}` |
| `GET` | `/c3/test/beacon-target` | Returns small fixed JSON — localhost beacon target for validation |
| `POST` | `/c3/test/beacon-target` | Same, accepts POST beacon check-ins |
| `GET` | `/c3/test/beacon-page` | Serves test beacon HTML — query param `?interval=30000` |

---

## WebSocket Events

| Event Type | Data | When |
|-----------|------|------|
| `c3_alert` | `{host, score, verdict, features, signal_breakdown, timestamp}` | Beacon detected |
| `c3_status` | `{running, hosts_monitored, requests_captured, model_type}` | Periodic status update |

---

## Dashboard Panel (`frontend/dashboard.html`)

The C3 panel contains a live monitoring interface with:

1. **Stats bar** — Requests Captured | Hosts Monitored | Beacons Detected | Blocked Hosts
2. **Tabs:**
   - **Live Monitor** — scrolling request table: host, method, size, tab context (active/background), user-active flag, beacon score. Colour-coded: green (below 0.3), yellow (0.3–0.6), red (above 0.6).
   - **Alerts** — expandable alert cards. Each card shows the three-signal breakdown (anomaly score, reputation score, heuristic score) and expands to show all 14 feature values as colour-coded bars: green (normal range), red (beacon range). This is the research evidence view for the panel presentation.
   - **Host Analysis** — table of all tracked hosts with current beacon score, request count, and signal breakdown. Click any host to expand its full feature breakdown.
   - **Data Collection** — start/stop collection, label selector (Normal / Beacon), sample count display, export button. Shows path of `c3_collection_in_progress.csv` with last-flush timestamp.
3. **Status badge** — shows "Active" when monitoring, indicates model type (IF / heuristic-only)
4. **WebSocket integration** — same pattern as C2 panel's live analysis feed

---

## Known Limitations

**Extension background service workers:** The WebSentinel Playwright browser is launched without `--load-extension` flags. Extension background service workers are separate browser targets not reachable via standard page CDP sessions. Detection capability is demonstrated via the test beacon page, which produces the same timing and context patterns. Loading real extensions via `--load-extension` is documented as future work.

**Isolation Forest cold start:** Until the model is trained on sufficient normal browsing data (recommended: 200+ feature vectors from 30+ minutes of diverse browsing), the system operates on heuristics and threat intelligence only. The heuristic layer provides day-one coverage by design.

**Threat intelligence rate limits:** VirusTotal free tier is limited to 4 requests per minute and 500 per day. AbuseIPDB allows 1000 checks per day. Smart-query gating mitigates this by only querying TI for behaviourally suspicious hosts (anomaly or heuristic score above 0.2). URLhaus, AlienVault OTX, and Feodo Tracker have no meaningful rate limits. The TTL cache further reduces repeat lookups. The system degrades gracefully when limits are reached.

**CDN and shared-infrastructure blind spots:** AbuseIPDB and Feodo check IP addresses. Hosts behind CDNs (Cloudflare, AWS CloudFront, Akamai) resolve to shared edge IPs that cannot produce meaningful IP reputation data. C3 skips IP-based lookups for CDN-pattern hosts and relies on domain-based sources (OTX, VirusTotal, URLhaus) for those destinations.

---

## Training Data: Self-Collection

All training data is collected by the running C3 system. Every feature value is measured by the actual system under real browser conditions. No synthetic approximations.

### Collection Workflow

**Step 1 — Collect normal traffic (Isolation Forest training data):**
Start WebSentinel, start the Playwright session, enable C3 collection mode with label = 0 (NORMAL). Browse normally for 30–60 minutes across varied sites: YouTube, Reddit, Gmail, news, shopping, social media. Use realistic browsing patterns — scroll, click, type, pause. C3 records all 14 features from real browser behaviour and auto-flushes to `data/c3_collection_in_progress.csv`. Target: 200+ feature vectors.

**Step 2 — Train the Isolation Forest:**
Run `scripts/train_c3_model.py`. The trainer loads all collection CSVs with label = 0, fits `IsolationForest` with `n_estimators=200` and `contamination=0.02`, computes calibration bounds from the training score distribution, and saves the model to `models/c3_isolation_forest.pkl`. Reports score distribution statistics.

**Step 3 — Collect beacon validation traffic (threshold validation only):**
Open the test beacon page (`GET /c3/test/beacon-page?interval=30000`) in a new background tab. Continue normal browsing in other tabs. C3 captures the periodic requests with: real idle time (F09 high), real user active ratio (F10 low), real background tab ratio (F11 high). Collect with label = 1 (BEACON).

**Step 4 — Vary beacon patterns:**
Repeat Step 3 with different intervals: 10s, 60s, 120s, 300s. Each creates a distinct timing profile for F01–F04. Also vary with `method=POST` for some intervals.

**Step 5 — Validate and tune:**
Run validation to verify normal traffic scores below 0.3 (SAFE) and beacon traffic scores above 0.6 (BEACON). Report anomaly score distribution for both classes. Adjust contamination or fusion weights if needed. Beacon validation data is used ONLY for threshold tuning, benchmark evaluation, and heuristic testing — NOT for primary model training.

### Supplemental Real Datasets (Optional — F01–F08 only)

| Dataset | URL | Use For |
|---------|-----|---------|
| **CTU-13** | `stratosphereips.org/datasets-ctu13` | Labelled botnet NetFlows — augment timing features F01–F08 |
| **Stratosphere IPS** | `stratosphereips.org/datasets-overview` | 300+ malware captures with labelled flows |
| **Malware-Traffic-Analysis.net** | `malware-traffic-analysis.net` | Cobalt Strike C2 PCAPs — real beacon timing patterns |
| **CIC-IDS2017** | `unb.ca/cic/datasets` | Botnet flow features in CSV format |

> **Note:** Network datasets provide F01–F08, F13–F14 only. Browser-context features F09–F12 do not exist in network captures and cannot be derived from them. Self-collected data is the sole source for these features.

---

## Implementation Order

| Step | Task | Verify |
|------|------|--------|
| 1 | Create `c3/anomaly_engine.py` — Isolation Forest loader, scorer, calibration normalisation, graceful fallback when no model exists | Unit test: score normalisation produces 0–1 range, fallback returns None |
| 2 | Create `c3/reputation_engine.py` — async AbuseIPDB + OTX + VirusTotal + URLhaus queries, Feodo local feed loader, DNS resolution with CDN-awareness, smart-query gating, TTL cache per host, graceful degradation without API keys | Unit test: cache hit/miss/expiry logic, CDN skip logic, offline fallback |
| 3 | Create `c3/risk_fusion.py` — weighted fusion with adaptive weights, override rules for high-confidence signals | Unit test: known inputs produce correct verdicts across all fallback scenarios |
| 4 | Update `c3/analyzer.py` — replace single classifier call with three-signal pipeline (anomaly → reputation → heuristic → fusion) | Integration: all three signals appear in host detail |
| 5 | Update `scripts/train_c3_model.py` — Isolation Forest trainer using benign-only data with calibration bounds | Run: produces `models/c3_isolation_forest.pkl` |
| 6 | Collect normal browsing data — browse 30–60 min with collection mode label=0 | Export CSV, verify 14 feature columns present, 200+ rows |
| 7 | Train Isolation Forest on normal data | Verify score distribution statistics, calibration bounds |
| 8 | Collect beacon validation data — open beacon page + browse, label=1, intervals 10s/30s/60s/120s/300s | Verify F09 high, F10 low, F11 high in collected rows |
| 9 | Validate detection accuracy | Normal traffic SAFE (below 0.3), beacon traffic BEACON (above 0.6) |
| 10 | End-to-end test with all three signals | Beacon page detected, alert shows signal breakdown, host blocked at score ≥ 0.8 |
| 11 | Update `frontend/dashboard.html` — add signal breakdown to alert cards and host detail | Visual check: anomaly/reputation/heuristic scores visible per alert |

---

## Implementation TODO

- [ ] Create `c3/anomaly_engine.py` — Isolation Forest loader + scorer + calibration normalisation + graceful fallback
- [ ] Create `c3/reputation_engine.py` — AbuseIPDB + AlienVault OTX + VirusTotal + URLhaus async queries + Feodo local feed + DNS resolution with CDN-awareness + smart-query gating + TTL cache + offline degradation
- [ ] Create `c3/risk_fusion.py` — weighted fusion with adaptive weights + override rules for known-malicious and strong-agreement scenarios
- [ ] Update `c3/analyzer.py` — integrate three-signal detection pipeline replacing single classifier call
- [ ] Update `scripts/train_c3_model.py` — Isolation Forest trainer using benign-only collection data
- [ ] Collect normal browsing data: 30–60 min across diverse sites (label=0, target 200+ vectors)
- [ ] Train Isolation Forest and verify score distribution
- [ ] Collect beacon validation data at 10s/30s/60s/120s/300s intervals (label=1)
- [ ] Validate: normal below 0.3, beacons above 0.6, end-to-end detection within 5 events
- [ ] Update dashboard to show three-signal breakdown in alert cards and host detail
- [x] Remove old `beacon_model.py` — deleted (XGBoost era, replaced by anomaly_engine.py + risk_fusion.py)

---

## AI Session Starter

> Paste this into a new AI chat to get instant context:
>
> "I'm building Component 3 of WebSentinel — a Browser Execution Aware C2 Beacon Detector.
> Project root: `R26-CS-003/`. Shared infra in `core/` (FastAPI + Playwright session at
> `core/playwright_session.py`). My component code is in `core/c3/`. The detection pipeline
> uses Isolation Forest anomaly detection on 14 browser-context features, fused with
> real-time threat intelligence (AbuseIPDB/OTX/VirusTotal/URLhaus/Feodo) and deterministic heuristic
> rules. CDP captures network requests, JS injection tracks user interaction. I need
> help with: [YOUR TASK]"