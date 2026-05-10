# Test Case 02 — Discord-Based C2 Beacon with Encrypted Exfiltration via Cloud API

> **Component:** C3 — Browser Execution Aware C2 Beacon Detector  
> **Test Case ID:** TC-C3-02  
> **Date Created:** 2026-05-10  
> **Priority:** Critical  
> **Type:** End-to-End Detection Under Evasion & Multi-Signal Fusion Test

---

## 1. Real-World Scenario Description

### Background Story

An Advanced Persistent Threat (APT) group has deployed a novel C2 framework that **abuses trusted cloud platforms** to evade traditional domain/IP reputation detection. The attack chain works as follows:

1. A university researcher downloads what appears to be a legitimate **Chrome browser extension** ("PDF Reader Pro") from an unofficial extension marketplace
2. The extension contains a **hidden service worker** that activates after a 5-minute delay to avoid sandbox detection
3. Once activated, the service worker establishes a **dual-channel C2 beacon pattern:**
   - **Channel A (Check-in):** Sends a small GET request every **60 seconds** to a Discord webhook URL (`https://discord.com/api/webhooks/...`) — this is the heartbeat callback
   - **Channel B (Exfiltration):** Every **5 minutes**, sends a larger POST request (2–5KB) to a Google Cloud Functions endpoint (`https://us-central1-*.cloudfunctions.net/data-sync`) containing encoded stolen data
4. The victim continues their normal research work — browsing academic papers, checking email, watching lecture recordings
5. The beacon operates entirely in the background, using the extension's service worker context, while the user is actively using other tabs

### Why This Scenario Is Uniquely Challenging

- **Trusted domains:** Both Discord and Google Cloud Functions are legitimate, widely-used platforms — neither will be flagged by reputation-based detection systems
- **Dual-channel with different intervals:** The C2 operator uses two different timing patterns (60s and 300s) on two different hosts, making single-host timing analysis less obvious
- **Extension-originated traffic:** Requests originate from a `chrome-extension://` context, not from a visible web page — traditional tab-based detection may miss this
- **POST exfiltration blends with GET check-ins:** The mix of methods across channels complicates HTTP method ratio analysis
- **The victim is ACTIVELY browsing** — unlike Test Case 01, the user is not idle. The key detection signal is that the beacon traffic is **independent of user activity** (F10 stays low for beacon hosts despite global user activity)
- **This is a documented real-world TTP:** Discord webhook abuse was observed in 2024-2025 by Trellix, Cisco Talos, and CrowdStrike in campaigns by APT groups including Pawn Storm and Lazarus Group

---

## 2. Preconditions

| # | Precondition | Verification |
|---|-------------|--------------|
| P1 | WebSentinel backend is running on `127.0.0.1:8000` | `GET /health` returns `{"status": "ok"}` |
| P2 | Playwright persistent browser session is active | `GET /session/status` returns `{"running": true}` |
| P3 | C3 analyzer loop is running | `GET /c3/status` returns `{"analyzer_running": true}` |
| P4 | C3 Isolation Forest model is loaded (trained on normal browsing data) | `GET /c3/status` returns `{"model_loaded": true}` |
| P5 | C3 interceptor is capturing requests | `GET /c3/status` returns `{"running": true}` |
| P6 | C3 RF Classifier model is loaded (optional, enhances detection) | `GET /c3/status` — `browser_model_loaded` is `true` |
| P7 | User has been browsing normally for at least 15 minutes before test begins | Multiple hosts with SAFE verdicts and 100+ captured requests |

---

## 3. Test Data Setup

### Simulated Dual-Channel Beacon Configuration

Since real Discord/GCF infrastructure cannot be controlled, the C3 built-in beacon endpoint is used with **two separate browser tabs** to simulate the dual-channel pattern. The two channels target the same localhost endpoint but with different timing and methods, simulating the behaviour C3 would see from different hosts.

#### Channel A — Check-in Heartbeat (Simulating Discord Webhook)

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Beacon Interval | `60000` ms (60 seconds) | Slower than Cobalt Strike default to evade burst detection |
| HTTP Method | `GET` | Check-in polling: "do you have commands for me?" |
| Payload Size | < 200 bytes | Minimal heartbeat response |
| Tab Behaviour | Background tab, no user interaction | Extension service worker simulation |

**URL:** `http://127.0.0.1:8000/c3/test/beacon-page?interval=60000&method=GET`

#### Channel B — Exfiltration (Simulating Google Cloud Function)

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Beacon Interval | `300000` ms (300 seconds = 5 minutes) | Low frequency to avoid volume-based detection |
| HTTP Method | `POST` | Exfiltration uploads use POST with JSON body |
| Payload Size | 2–5 KB (JSON body) | Encoded stolen data |
| Tab Behaviour | Background tab, no user interaction | Same extension context |

**URL:** `http://127.0.0.1:8000/c3/test/beacon-page?interval=300000&method=POST`

---

## 4. Test Execution Steps

### Phase 1: Establish Active Browsing Baseline (10–15 minutes)

This phase is critical because the attacker's evasion strategy relies on the victim being **actively browsing** — the beacon should be detectable despite high global user activity.

| Step | Action | Expected System Behaviour |
|------|--------|--------------------------|
| 1.1 | Open the Playwright session via `POST /session/start` | C3 components initialise: tagger → interceptor → analyzer |
| 1.2 | Navigate to `https://scholar.google.com` and search for "machine learning anomaly detection" | User interactions (click, keydown) tracked by JS injection. Requests captured for scholar.google.com. F10 ≈ 1.0 for this host |
| 1.3 | Click on 3–4 search results and read the abstracts | Multiple hosts appear (publisher sites). User activity is high across all. F09 stays low (< 5000ms) because user is actively clicking |
| 1.4 | Navigate to `https://mail.google.com` (or any email service) | Login and email browsing generates diverse request patterns. F13 (URL path entropy) is high for email hosts |
| 1.5 | Open `https://www.youtube.com` and play a lecture video | YouTube generates high-volume traffic (video streaming). CDN hosts are auto-whitelisted by `_SAFE_HOST_SUFFIXES` filter |
| 1.6 | Verify baseline is established | `GET /c3/hosts` shows 5+ hosts with SAFE verdicts. `GET /c3/status` shows `requests_captured > 100`. All normal hosts score < 0.3 |

### Phase 2: Deploy Dual-Channel Beacon (Simulated Extension Activity)

| Step | Action | Expected System Behaviour |
|------|--------|--------------------------|
| 2.1 | **Open Tab A (Check-in Channel):** Navigate a new tab to `http://127.0.0.1:8000/c3/test/beacon-page?interval=60000&method=GET` | C3 interceptor attaches CDP session. First beacon fires immediately. Context tagger injects JS tracker |
| 2.2 | **Open Tab B (Exfiltration Channel):** Navigate another new tab to `http://127.0.0.1:8000/c3/test/beacon-page?interval=300000&method=POST` | Second CDP session attached. First POST beacon fires immediately. Both beacon tabs are now open |
| 2.3 | **Switch back to the YouTube tab** and continue watching the video normally | Both beacon tabs become **background tabs**. `document.visibilityState` = `"hidden"` for both. The user is **actively watching** in the foreground — this is the evasion scenario. User interaction events (scroll, click) fire in the YouTube tab |
| 2.4 | Continue active browsing for 5 minutes — switch between Scholar, email, and YouTube | **Critical observation:** While the user is active in foreground tabs, the beacon tabs fire silently in the background. C3's per-host context enrichment correctly tags: - Beacon requests: `user_was_active = false` (the user's clicks are in OTHER tabs). - Beacon requests: `is_background_tab = true`. - Normal requests: `user_was_active = true`, `is_background_tab = false` |

### Phase 3: Monitor Channel A Detection (60-second interval)

| Step | Action | Expected Observation |
|------|--------|---------------------|
| 3.1 | After 6 minutes (≥ 6 beacon pulses for Channel A): Call `GET /c3/hosts` | Host `127.0.0.1` should appear with initial scoring. Note: Both channels target the same host in this test simulation, so events aggregate in one rolling window |
| 3.2 | Call `GET /c3/hosts/127.0.0.1` for detailed analysis | **Expected feature values (combined channels):** |
| | | — `iat_mean_ms`: mixture of 60s and 300s intervals → varies |
| | | — `iat_cv`: higher than a single-interval beacon but still below normal browsing (< 0.5) |
| | | — `user_active_ratio` ≈ 0.0 (no user interaction in beacon tabs) |
| | | — `background_tab_ratio` ≈ 1.0 (all requests from background tabs) |
| | | — `avg_idle_time_ms` > 60000 (user never interacted with these tabs) |
| | | — `http_post_ratio` > 0.0 (POST from Channel B) |
| | | — `url_path_entropy`: low (same endpoint pattern) |
| 3.3 | Inspect the `signal_breakdown` | **Heuristic signal expected rules:** |
| | | — `background traffic (non-extension)`: bg > 0.80 → +0.20 |
| | | — `foreground requests firing while user idle`: uar < 0.05 AND idle > 30s → +0.25 (if bg < 0.50 — may not fire if bg > 0.50) |
| | | — `regular timing` may fire if iat_cv is below threshold |
| | | **Expected heuristic score ≥ 0.30** |
| 3.4 | Inspect anomaly score (if model loaded) | Isolation Forest should score higher than normal because: |
| | | — Timing features deviate from diverse normal browsing baseline |
| | | — The model was trained on varied inter-arrival times; near-constant intervals are anomalous |

### Phase 4: Wait for Full BEACON Verdict (10+ events)

| Step | Action | Expected Observation |
|------|--------|---------------------|
| 4.1 | Wait until 10+ total beacon requests have been captured (~10 minutes from beacon start) | `allow_beacon = true` (events ≥ 10). The early-window cap is lifted |
| 4.2 | Call `GET /c3/hosts/127.0.0.1` | **Expected verdict:** `SUSPICIOUS` or `BEACON`. Score should be ≥ 0.3 at minimum |
| 4.3 | If verdict is `SUSPICIOUS`: verify it is progressing toward `BEACON` | As more beacon events accumulate with consistent background/idle pattern, the scores should increase. Heuristic rules strengthen as feature statistics stabilise |
| 4.4 | After 15+ minutes: Call `GET /c3/hosts/127.0.0.1` again | **Expected verdict:** `BEACON` with score ≥ 0.6. If anomaly model detects strong deviation AND heuristic confirms background/idle patterns, fusion should cross the BEACON threshold |

### Phase 5: Verify Multi-Signal Fusion and Alert Generation

| Step | Action | Expected Observation |
|------|--------|---------------------|
| 5.1 | Call `GET /c3/alerts` | At least one alert for host `127.0.0.1` with verdict = `BEACON`. Alert includes complete `signal_breakdown` and `features` |
| 5.2 | Verify the fusion engine weight selection | Since `127.0.0.1` is a local/private host, reputation returns `None` (local host skipped). Fusion should use: `anomaly × 0.65 + heuristic × 0.35` (no reputation). OR if browser model loaded: `anomaly × 0.45 + browser × 0.20 + heuristic × 0.35` |
| 5.3 | Verify safety guard did NOT cap the score incorrectly | Check `signal_detail.fusion` for override messages. If heuristic ≥ 0.10, the "anomaly-only cap" safety guard should NOT have activated |
| 5.4 | Verify no false positives on normal browsing hosts | Call `GET /c3/hosts`. All legitimate hosts (Google, YouTube, Wikipedia, etc.) must have: verdict = `SAFE`, score < 0.3. **Critical:** `google-analytics.com`, `googletagmanager.com` etc. are in the `_SAFE_HOST_SUFFIXES` allowlist and must be skipped entirely |

### Phase 6: Validate Simultaneous Active User + Background Beacon Discrimination

This is the **key research validation** step — proving that C3 can distinguish between user-driven traffic and beacon traffic **even when both are happening simultaneously**.

| Step | Action | Expected Observation |
|------|--------|---------------------|
| 6.1 | While beacons are still running, navigate to a new site (e.g., `https://www.reddit.com`) and actively browse | C3 captures reddit.com requests with: `user_was_active = true`, `is_background_tab = false`, `idle_time_ms < 5000` |
| 6.2 | Immediately after browsing Reddit, call `GET /c3/hosts/127.0.0.1` | **The beacon host features must NOT change** — beacon requests still show `user_was_active = false` because user activity was in a DIFFERENT tab. This proves C3's per-tab context enrichment works correctly |
| 6.3 | Compare feature vectors of reddit.com vs 127.0.0.1 | **reddit.com:** F09 < 5000, F10 ≈ 1.0, F11 ≈ 0.0 (active, foreground). **127.0.0.1:** F09 > 60000, F10 ≈ 0.0, F11 ≈ 1.0 (idle, background). This contrast is the **core research evidence** |

---

## 5. Expected Results Summary

| Metric | Expected Value | Tolerance |
|--------|---------------|-----------|
| **Final Verdict (Beacon Host)** | `BEACON` | Exact match required |
| **Final Score (Beacon Host)** | ≥ 0.60 | Must cross BEACON threshold |
| **F09 (Avg Idle Time - Beacon)** | > 60000 ms | User never interacted with beacon tabs |
| **F10 (User Active Ratio - Beacon)** | < 0.05 | Near-zero despite active user in other tabs |
| **F10 (User Active Ratio - Normal)** | > 0.50 | High ratio for actively browsed hosts |
| **F11 (BG Tab Ratio - Beacon)** | > 0.90 | All beacon requests from background |
| **F11 (BG Tab Ratio - Normal)** | < 0.20 | Normal browsing in foreground |
| **F08 (HTTP POST Ratio - Beacon)** | > 0.0 | POST requests from Channel B exfiltration |
| **Heuristic Score** | ≥ 0.30 | Background traffic + idle patterns detected |
| **Detection Time** | ≤ 900 seconds (15 min) | Accounting for slower 60s/300s intervals |
| **False Positives** | 0 | Zero BEACON/SUSPICIOUS on legitimate hosts |
| **Active User Discrimination** | Correct | F10 differs between user-driven and beacon traffic |

---

## 6. Pass/Fail Criteria

### PASS Conditions (ALL must be true)

- [ ] C3 detects the simulated beacon host with verdict = `BEACON` within 15 minutes
- [ ] Final fusion score ≥ 0.60
- [ ] Feature F10 (User Active Ratio) for the beacon host is < 0.05 despite the user being **actively browsing in other tabs** — this proves per-tab context discrimination
- [ ] Feature F11 (BG Tab Ratio) for the beacon host is > 0.90
- [ ] Feature F10 (User Active Ratio) for at least one normal browsing host is > 0.50 — proving the feature correctly measures user activity for legitimate traffic
- [ ] Heuristic score is ≥ 0.30 with at least 1 rule fired
- [ ] No legitimate host receives BEACON or SUSPICIOUS verdict throughout the test
- [ ] The `_SAFE_HOST_SUFFIXES` allowlist correctly skips analytics/CDN domains
- [ ] Alert is persisted in SQLite with complete signal breakdown
- [ ] The fusion engine correctly selects weights based on signal availability (no reputation for localhost)

### FAIL Conditions (ANY triggers failure)

- [ ] Beacon host is not detected within 15 minutes
- [ ] F10 (User Active Ratio) for the beacon host is > 0.20 (indicates per-tab context enrichment failure — user activity from other tabs is leaking into beacon host measurements)
- [ ] Any legitimate browsing host receives BEACON verdict
- [ ] The safety guard incorrectly caps the score when heuristic confirmation is present
- [ ] Fusion engine uses incorrect weight configuration for the available signals
- [ ] Analyzer loop error or crash during the test

---

## 7. Feature Discrimination Evidence Table

This is the **primary research evidence** table for the panel presentation. It shows how browser-execution-aware features discriminate beacon traffic from normal traffic **even when both occur simultaneously**.

| Feature | Normal Host (user-driven, foreground) | Beacon Host (automated, background) | Discrimination Power |
|---------|--------------------------------------|--------------------------------------|---------------------|
| F01 IAT Mean | Variable (50ms – 60000ms+) | Mixed 60s/300s intervals | ⚠️ Moderate |
| F02 IAT CV | 0.5–2.0 (highly variable) | < 0.5 (more regular than browsing) | ⚠️ Moderate |
| F09 Avg Idle Time | < 5000 ms (user is clicking) | > 60000 ms (no interaction in tab) | 🔴 **Strong — Novel** |
| F10 User Active Ratio | > 0.50 (user drives the requests) | < 0.05 (requests fire independently of user) | 🔴 **Strong — Novel** |
| F11 BG Tab Ratio | < 0.20 (user is looking at the page) | > 0.90 (tab is hidden) | 🔴 **Strong — Novel** |
| F13 URL Path Entropy | High (diverse pages visited) | Low (same API endpoint) | ⚠️ Moderate |

> **Key research insight:** Features F09, F10, and F11 provide **near-perfect class separation** between user-driven and automated traffic, even in this challenging scenario where the user is actively browsing. A traditional network IDS seeing the same packets would observe identical packet headers and timing — it cannot determine whether the user was looking at the page or not. This is the **fundamental advantage** of browser-execution-aware detection.

---

## 8. Detection Pipeline Trace — Dual-Channel Scenario

```
┌─────────────────────────────────────────────────────────────────────┐
│ Browser State at T=600s (10 minutes into test)                     │
│                                                                     │
│  Tab 1: YouTube (FOREGROUND) ← user watching video                 │
│  Tab 2: Beacon Channel A (BACKGROUND, hidden, 60s GET)             │
│  Tab 3: Beacon Channel B (BACKGROUND, hidden, 300s POST)           │
│  Tab 4: Scholar Google (BACKGROUND, user was here earlier)          │
└─────────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─ CDP Network Sessions (one per tab) ───────────────────────────────┐
│ Tab 1 CDP: youtube video chunk requests → host: googlevideo.com    │
│ Tab 2 CDP: GET /c3/test/beacon-target   → host: 127.0.0.1         │
│ Tab 3 CDP: POST /c3/test/beacon-target  → host: 127.0.0.1         │
│ Tab 4 CDP: (idle, no new requests)                                  │
└────────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─ Context Tagger enrichment ────────────────────────────────────────┐
│ For googlevideo.com request:                                        │
│   page.evaluate("document.visibilityState") → "visible"            │
│   idle_time_ms = 200 (user just scrolled 200ms ago)                │
│   user_was_active = true, is_background_tab = false                │
│                                                                     │
│ For 127.0.0.1 request (from Tab 2 or 3):                           │
│   page.evaluate("document.visibilityState") → "hidden"             │
│   idle_time_ms = 65000 (no interaction in THIS tab ever)           │
│   user_was_active = false, is_background_tab = true                │
│                                                                     │
│ KEY: User's click events in Tab 1 do NOT reset idle time for       │
│ Tab 2/3 because _last_interaction_by_origin is per-origin.         │
│ The global _last_interaction_ms IS recent, but the background tab  │
│ check (is_background_tab = true) prevents user_was_active = true.  │
└────────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─ Per-host rolling windows ─────────────────────────────────────────┐
│ googlevideo.com: [event1, event2, ...] (many, diverse, active)     │
│ 127.0.0.1:      [beacon1, beacon2, ...beacon10+] (regular, bg)    │
│ scholar.google.com: [event1, ...] (historic, declining)            │
└────────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─ Analyzer loop (every 10s) ────────────────────────────────────────┐
│ For each host with ≥ 3 events:                                      │
│   1. Skip if host in _SAFE_HOST_SUFFIXES                           │
│   2. compute_features(events) → 14-feature vector                  │
│   3. Strip timing features if events < 6                            │
│   4. _heuristic_score() → rules-based beacon score                 │
│   5. c3_anomaly_engine.score() → Isolation Forest anomaly score    │
│   6. c3_browser_anomaly_engine.score() → RF classifier score       │
│   7. Smart-query gating: query TI only if anomaly or heuristic > 0.2│
│   8. c3_reputation_engine.score_host() → reputation score          │
│   9. c3_risk_fusion.fuse() → final score + verdict                 │
│  10. If BEACON: _handle_beacon() → alert + optional block          │
└────────────────────────────────────────────────────────────────────┘
```

---

## 9. Cleanup Steps

| Step | Action |
|------|--------|
| 9.1 | Close Tab A (Channel A beacon) and Tab B (Channel B beacon) |
| 9.2 | Verify host blocking is removed (if triggered) via `GET /c3/status` |
| 9.3 | Continue browsing normally for 2 minutes and verify no lingering false positives |
| 9.4 | Optionally export test data via `POST /c3/collect/export` for analysis |
| 9.5 | Record final feature values from `GET /c3/hosts` for research documentation |

---

## 10. Notes for Research Panel Presentation

1. **This test case validates the hardest detection scenario:** the attacker deliberately uses trusted platforms (Discord, Google Cloud), and the victim is actively browsing, meaning global user-activity signals are high. Only **per-tab browser-context features** can distinguish the beacon from legitimate traffic

2. **Dual-channel C2 with mixed timing** is a documented real-world APT technique. APT groups use separate channels for command polling (fast) and data exfiltration (slow) to optimise operational security. C3's per-host rolling window aggregates both channels' requests and still detects the anomalous pattern

3. **The F10 discrimination experiment** (Phase 6, Steps 6.1–6.3) is the single most important research validation. If F10 correctly shows ~0.0 for the beacon host and ~1.0 for the normal host **at the same point in time**, it proves that browser-execution-aware features provide information unavailable to any network-layer detector

4. **The reputation engine's smart-query gating** is demonstrated here: normal hosts with low anomaly/heuristic scores are never sent to rate-limited TI APIs. Only the beacon host (which exceeds the 0.2 threshold) triggers TI queries — and since it's localhost, the reputation engine correctly identifies it as a local host and skips external lookups. In a real deployment with an external C2 domain, this is where AbuseIPDB/VirusTotal/URLhaus would add the reputation signal

5. **Fusion weight adaptation** is visible: without reputation signal (localhost), the fusion engine automatically redistributes to `anomaly × 0.65 + heuristic × 0.35` — demonstrating graceful degradation that ensures detection even when some signal sources are unavailable

6. **The `_SAFE_HOST_SUFFIXES` allowlist** prevents false positives from analytics/CDN traffic that produces beacon-like patterns (regular polling, small payloads, same endpoints). This is essential for real-world deployment where analytics trackers would otherwise dominate the alert queue
