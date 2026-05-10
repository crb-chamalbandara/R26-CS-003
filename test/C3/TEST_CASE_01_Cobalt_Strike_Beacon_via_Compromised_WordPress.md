# Test Case 01 — Cobalt Strike C2 Beacon via Compromised WordPress Site

> **Component:** C3 — Browser Execution Aware C2 Beacon Detector  
> **Test Case ID:** TC-C3-01  
> **Date Created:** 2026-05-10  
> **Priority:** Critical  
> **Type:** End-to-End Functional & Detection Accuracy Test

---

## 1. Real-World Scenario Description

### Background Story

A corporate employee at **Meridian Financial Services** receives a phishing email linking to a **legitimate but compromised WordPress blog** (`blog.techinsights-daily.com`). The WordPress site was silently infected with a **Cobalt Strike Team Server** beacon dropper embedded in a malicious JavaScript file loaded by a tampered WordPress plugin.

When the employee opens the link in the WebSentinel-protected browser:

1. The page loads normally — it displays a genuine blog article about "2026 Tech Trends"
2. The compromised plugin silently injects a **hidden `<iframe>`** that loads a JavaScript beacon stager
3. The stager establishes a **periodic C2 callback** to the attacker's infrastructure at `cdn-static.update-services[.]xyz` every **30 seconds** using HTTPS GET requests
4. The beacon payload is disguised as a small JSON response (< 500 bytes) mimicking an analytics heartbeat
5. The employee switches to another tab to continue working, leaving the compromised blog tab in the **background**
6. The beacon continues firing silently from the background tab while the user is idle

### Why This Scenario Is Critical

- **Cobalt Strike** is the most commonly used C2 framework in real-world intrusions (used in 66% of all ransomware attacks per Mandiant 2025 M-Trends report)
- The beacon **uses HTTPS** and **mimics analytics traffic**, making it invisible to traditional signature-based IDS/IPS
- The compromised site is a **legitimate domain** — domain reputation alone cannot detect this
- The beacon fires from a **background tab while the user is idle** — this is the exact pattern C3's browser-context features (F09–F12) are designed to detect

---

## 2. Preconditions

| # | Precondition | Verification |
|---|-------------|--------------|
| P1 | WebSentinel backend is running on `127.0.0.1:8000` | `GET /health` returns `{"status": "ok"}` |
| P2 | Playwright persistent browser session is active | `GET /session/status` returns `{"running": true}` |
| P3 | C3 analyzer loop is running | `GET /c3/status` returns `{"analyzer_running": true}` |
| P4 | C3 Isolation Forest model is loaded | `GET /c3/status` returns `{"model_loaded": true}` |
| P5 | C3 interceptor is capturing requests | `GET /c3/status` returns `{"running": true}` |
| P6 | At least one TI source is available (optional but recommended) | `GET /c3/status` — `ti_available` is `true` |
| P7 | Normal browsing baseline is established (10+ minutes of browsing before test) | Multiple hosts visible in `GET /c3/hosts` with SAFE verdicts |

---

## 3. Test Data Setup

### Simulated Beacon Configuration

Since real Cobalt Strike infrastructure cannot be used in a controlled test environment, the C3 built-in test beacon endpoint is used to simulate identical network behaviour patterns.

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Beacon Interval | `30000` ms (30 seconds) | Matches Cobalt Strike default sleep interval |
| HTTP Method | `GET` | Matches Cobalt Strike HTTP-GET beacon profile |
| Beacon Target | `/c3/test/beacon-target` (localhost) | Simulates the C2 callback endpoint |
| Payload Size | < 500 bytes (JSON) | Matches real C2 check-in payload sizes |
| Tab Behaviour | Background tab (user switches away) | Simulates real-world victim behaviour |

### Beacon Page URL

```
http://127.0.0.1:8000/c3/test/beacon-page?interval=30000&method=GET
```

---

## 4. Test Execution Steps

### Phase 1: Establish Normal Browsing Baseline (5–10 minutes)

| Step | Action | Expected System Behaviour |
|------|--------|--------------------------|
| 1.1 | Open the Playwright browser session via `POST /session/start` | Session starts, C3 tagger/interceptor/analyzer initialise |
| 1.2 | Navigate to `https://www.google.com` and perform a search query | CDP captures requests to google.com. User interaction JS tracker records click/keydown events. F10 (user_active_ratio) ≈ 1.0 for google.com |
| 1.3 | Navigate to `https://www.youtube.com` and click on a video | Multiple requests captured. User activity tracked via click events. F09 (avg_idle_time_ms) stays low because user is actively clicking |
| 1.4 | Navigate to `https://en.wikipedia.org/wiki/Main_Page` and scroll through content | Scroll events tracked by C3 context tagger. F10 remains high (user is actively scrolling). Multiple hosts appear in `GET /c3/hosts` |
| 1.5 | Verify baseline is established | `GET /c3/hosts` shows multiple hosts with verdict = `SAFE` and scores < 0.3. At least 50+ requests captured (`requests_captured` in `/c3/status`) |

### Phase 2: Introduce Beacon Traffic (Background Tab Simulation)

| Step | Action | Expected System Behaviour |
|------|--------|--------------------------|
| 2.1 | Open a **new tab** in the Playwright browser | C3 interceptor attaches CDP session to new tab via `attach_page()`. Context tagger injects JS tracker into new page via `inject_page()` |
| 2.2 | Navigate the new tab to `http://127.0.0.1:8000/c3/test/beacon-page?interval=30000&method=GET` | Test beacon page loads. First beacon request fires immediately to `/c3/test/beacon-target`. CDP captures the request with host = `127.0.0.1` |
| 2.3 | **Switch back to the original tab** (e.g., Wikipedia) and continue browsing normally | The beacon tab becomes a **background tab**. `document.visibilityState` for the beacon tab = `"hidden"`. C3 context tagger records `is_background_tab = true` for beacon requests. User interaction events fire in the foreground tab only |
| 2.4 | Wait 60 seconds while continuing normal browsing in the foreground tab | Beacon fires 2 more GET requests from the background tab (at t=30s and t=60s). Interceptor accumulates 3 events in the rolling window for `127.0.0.1`. Analyzer loop runs 6 times (every 10s) — host has < 6 events so timing features are stripped |
| 2.5 | Wait an additional 120 seconds (total: 180 seconds from beacon start) | Beacon fires 4 more requests (total: ~6 events). Analyzer now computes **all 14 features** since event count ≥ 6. Anomaly engine scores the feature vector through the Isolation Forest model |

### Phase 3: Observe Detection Progression

| Step | Action | Expected Observation |
|------|--------|---------------------|
| 3.1 | Call `GET /c3/hosts/127.0.0.1` to inspect the host detail | **Features should show beacon-like patterns:** |
| | | — `iat_mean_ms` ≈ 30000 (±500ms due to JS timer jitter) |
| | | — `iat_cv` ≈ 0.01–0.03 (near-perfect regularity) |
| | | — `user_active_ratio` ≈ 0.0 (no user interaction in background tab) |
| | | — `background_tab_ratio` ≈ 1.0 (all requests from background) |
| | | — `avg_idle_time_ms` > 30000 (user has been idle in this tab) |
| | | — `payload_size_mean` < 500 bytes |
| | | — `url_path_entropy` low (same `/c3/test/beacon-target` endpoint) |
| 3.2 | Observe `signal_breakdown` in the host detail response | **Heuristic score** should fire multiple rules: |
| | | — `regular timing` (+0.30): iat_cv < 0.05 AND iat_mean > 0 AND uar < 0.50 |
| | | — `foreground requests firing while user idle` (+0.25): uar < 0.05 AND bg < 0.50 AND idle > 30s — OR `background traffic (non-extension)` (+0.20): bg > 0.80 |
| | | — `same endpoint with regular timing` (+0.10): path_ent < 0.50 AND iat_cv < 0.10 AND uar < 0.50 |
| | | **Total heuristic ≥ 0.50** |
| 3.3 | Continue waiting until 10+ beacon requests accumulate (~300 seconds total) | The `allow_beacon` flag becomes `true` (events ≥ 10). The early-window BEACON cap is lifted. Fusion engine combines anomaly + heuristic signals |
| 3.4 | Call `GET /c3/hosts/127.0.0.1` again | **Expected verdict:** `BEACON` with score ≥ 0.6 |
| | | **Signal breakdown:** anomaly > 0.5, heuristic > 0.5 |
| | | **Fusion detail:** weights show anomaly+heuristic combination |

### Phase 4: Verify Alert and Blocking

| Step | Action | Expected Observation |
|------|--------|---------------------|
| 4.1 | Call `GET /c3/alerts` | A beacon alert should exist with: `host = "127.0.0.1"`, `verdict = "BEACON"`, `score ≥ 0.6`. Alert includes complete 14-feature breakdown and signal_breakdown |
| 4.2 | If score ≥ 0.8: Verify host blocking | `GET /c3/status` — `blocked_hosts` list should include `"127.0.0.1"`. The Playwright route `**://127.0.0.1/**` should be registered to abort requests. Subsequent beacon requests from the background tab should fail (aborted by route handler) |
| 4.3 | Verify WebSocket broadcast | If a WebSocket client is connected to `/ws/events`, a `c3_alert` event should have been broadcast with the full alert payload |
| 4.4 | Verify SQLite persistence | Alert should be persisted in `~/.websentinel/c3_alerts.db`. Call `GET /c3/alerts` after server restart — alert should survive |

---

## 5. Expected Results Summary

| Metric | Expected Value | Tolerance |
|--------|---------------|-----------|
| **Final Verdict** | `BEACON` | Exact match required |
| **Final Score** | ≥ 0.60 | Score must cross BEACON threshold |
| **F01 (IAT Mean)** | ~30000 ms | ±2000 ms (JS timer variance) |
| **F02 (IAT CV)** | < 0.05 | Near-zero coefficient of variation |
| **F09 (Avg Idle Time)** | > 30000 ms | User was idle in the beacon tab |
| **F10 (User Active Ratio)** | < 0.05 | Near-zero: no clicks/keystrokes in background tab |
| **F11 (BG Tab Ratio)** | > 0.90 | Nearly all requests from background tab |
| **F13 (URL Path Entropy)** | < 1.0 | Same endpoint repeated |
| **Heuristic Score** | ≥ 0.50 | Multiple heuristic rules should fire |
| **Anomaly Score** (if model loaded) | > 0.40 | Timing pattern deviates from normal browsing baseline |
| **Detection Time** | ≤ 300 seconds from beacon start | Within 10 beacon pulses at 30s interval |
| **False Positives on Normal Hosts** | 0 | Google, YouTube, Wikipedia remain SAFE throughout |

---

## 6. Pass/Fail Criteria

### PASS Conditions (ALL must be true)

- [ ] C3 detects the simulated beacon host with verdict = `BEACON`
- [ ] Final fusion score ≥ 0.60
- [ ] Detection occurs within 300 seconds of beacon start (≤ 10 beacon pulses)
- [ ] At least 2 heuristic rules fire (confirmed in `signal_detail.heuristic`)
- [ ] Features F02 (IAT CV), F10 (User Active Ratio), F11 (BG Tab Ratio) are all in beacon range
- [ ] Alert is persisted in SQLite database
- [ ] No BEACON or SUSPICIOUS verdict on legitimately browsed hosts (google.com, youtube.com, wikipedia.org) during the test — these must remain SAFE
- [ ] If score ≥ 0.8: host blocking is active and subsequent beacon requests are aborted

### FAIL Conditions (ANY triggers failure)

- [ ] Beacon host is not detected as BEACON within 300 seconds
- [ ] Any legitimate browsing host receives a BEACON verdict (false positive)
- [ ] Heuristic score is 0.0 despite clear beacon pattern (rule logic error)
- [ ] Feature computation returns NaN or negative values
- [ ] Analyzer loop crashes or stops during the test
- [ ] Alert is not persisted in the database

---

## 7. Feature Validation Matrix

This matrix maps each of the 14 features to their expected behaviour during this test case. This is the evidence table for the research panel.

| Feature | Normal Browsing Host (e.g., google.com) | Beacon Host (127.0.0.1) | Detection Signal |
|---------|----------------------------------------|-------------------------|------------------|
| F01 IAT Mean (ms) | Variable (100–60000+) | ~30000 (consistent) | ⚠️ Moderate |
| F02 IAT CV | 0.5–1.5 (irregular) | < 0.05 (metronomic) | 🔴 **Strong** |
| F03 IAT Bowley Skewness | Variable | ~0.0 (symmetric) | ⚠️ Moderate |
| F04 IAT MAD (ms) | Variable | < 500 (very low deviation) | ⚠️ Moderate |
| F05 Requests/Hour | Variable | ~120 (30s interval) | ⚠️ Moderate |
| F06 Payload Size Mean | Variable (1KB–1MB) | < 500 bytes | ⚠️ Moderate |
| F07 Payload Size Std | Variable | ~0 (identical responses) | ⚠️ Moderate |
| F08 HTTP POST Ratio | Mixed | 0.0 (all GET) | ✅ Low |
| F09 Avg Idle Time (ms) | < 5000 (active user) | > 30000 (idle) | 🔴 **Strong — Research Novelty** |
| F10 User Active Ratio | ~1.0 (clicking/typing) | ~0.0 (no interaction) | 🔴 **Strong — Research Novelty** |
| F11 BG Tab Ratio | ~0.0 (foreground) | ~1.0 (background) | 🔴 **Strong — Research Novelty** |
| F12 Extension Origin | 0.0 | 0.0 | ✅ Not applicable |
| F13 URL Path Entropy | High (diverse URLs) | Low (same endpoint) | ⚠️ Moderate |
| F14 Request Burst Count | Variable | 0 (spaced intervals) | ✅ Low |

> **Research panel highlight:** Features F09, F10, and F11 (marked 🔴) are the **novel browser-execution-aware features** that traditional network IDS cannot compute. These are the features that differentiate C3 from existing network-based beacon detectors.

---

## 8. Three-Signal Pipeline Trace

This section documents the expected flow through C3's detection pipeline for research panel evaluation.

```
Step 1: CDP Network.requestWillBeSent fires on beacon tab
        ↓
Step 2: context_tagger.enrich_request() runs:
        - page.evaluate("document.visibilityState") → "hidden"
        - is_background_tab = true
        - idle_time_ms = now - last_interaction > 30000
        - user_was_active = false (idle > 5000ms AND background tab)
        ↓
Step 3: Event stored in rolling window for host "127.0.0.1"
        (deque maxlen=50, in-memory)
        ↓
Step 4: Analyzer loop fires (every 10 seconds):
        - compute_features(events) → 14-feature vector
        - _heuristic_score(features) → score=0.60, flags=["regular timing", "background traffic"]
        ↓
Step 5: Anomaly engine scores feature vector:
        - IsolationForest.score_samples(X) → raw score
        - Normalize using calibration bounds → anomaly_score ≈ 0.65
        ↓
Step 6: Reputation engine (smart-query gating):
        - anomaly_score > 0.2 → should_query_ti = true
        - 127.0.0.1 is private → returns None (local host skipped)
        ↓
Step 7: Risk fusion engine combines signals:
        - Weights: anomaly=0.65, heuristic=0.35 (no reputation)
        - final = 0.65 × 0.65 + 0.35 × 0.60 = 0.6325
        - Override check: anomaly ≥ 0.80 AND heuristic ≥ 0.50? → depends on scores
        - Verdict: BEACON (score ≥ 0.6)
        ↓
Step 8: _handle_beacon() triggered:
        - Alert stored in SQLite
        - If score ≥ 0.8: context.route("**://127.0.0.1/**") registered
        - WebSocket broadcast: {type: "c3_alert", data: {...}}
```

---

## 9. Cleanup Steps

| Step | Action |
|------|--------|
| 9.1 | Close the beacon test tab in the Playwright browser |
| 9.2 | If host was blocked: call unblock manually or restart session |
| 9.3 | Verify normal browsing hosts still score SAFE after cleanup |
| 9.4 | Optionally clear test alerts from SQLite database |

---

## 10. Notes for Research Panel Presentation

1. **This test demonstrates the core research contribution:** browser-execution-aware features (F09, F10, F11) that are impossible to compute from network captures alone
2. **The 30-second interval** matches real-world Cobalt Strike default sleep time — this is not a synthetic test parameter
3. **Background tab detection** via `document.visibilityState` is a browser-internal API that network IDS/IPS cannot access
4. **The three-signal fusion pipeline** (anomaly + reputation + heuristic) provides defence in depth — even if one signal fails, the others maintain detection capability
5. **Zero false positives on normal browsing** during the test validates that the Isolation Forest baseline learned genuine browsing patterns
