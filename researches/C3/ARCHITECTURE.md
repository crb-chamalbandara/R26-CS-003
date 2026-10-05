# C3: Browser Execution Aware C2 Beacon Detector

C3 watches every request the monitored browser sends and asks one question per
destination host: is this a person browsing, or a program checking in with a
command-and-control (C2) server on a timer? It works inside the browser, so it
sees what a network sensor cannot: whether the user was touching the page when a
request fired, whether a script or an extension sent it, and whether a Referer
came with it.

This document describes the component as it is in the code. The model's full
engineering record is `C3_Final_Model_Results.md`; the notebook that
reproduces its numbers is `core/c3/C3_ML_Train.ipynb`.

> **Moved here on 2026-09-15** from `core/c3/`. That day every C3 file the app
> does not need at runtime (training and evaluation scripts, result files, the
> paper, the standalone test cases) was moved out of the repository to
> `Desktop\Removals in C3\L A S T - Removals\2026-09-15_runtime_only_clean\`,
> at the same relative paths. Files below marked *(archived)* are there.

---

## At a glance

| | |
|---|---|
| Watches | every request of every tab in the monitored Chromium (Chrome DevTools Protocol) |
| Scores | each destination host, every 10 seconds, over its last 50 requests (30 minutes at most) |
| ML signal | XGBoost, 20 traffic-shape features, `models/c3_beacon_classifier.pkl` |
| Rule signal | heuristic rules that need a timing rhythm before anything else counts |
| Risk score | 0.55 x ML + 0.45 x heuristic |
| Verdicts | SAFE below 30%, SUSPICIOUS from 30%, BEACON from 52% |
| BEACON also needs | ML at or above 50% and a timing rhythm, 10+ requests, 3 observations in a row |
| On BEACON | alert saved and shown, threat-intel lookup as evidence, optional 24 h block |

---

## Pipeline

```
Monitored Chromium (core/playwright_session.py)
   |  one CDP Network session per tab            core/c3/interceptor.py
   |  activity tracker in every page             core/c3/context_tagger.py
   v
Per-host window: last 50 requests, none older than 30 minutes
   |  URL, method, status, response size, request size, headers, timing
   |  + idle time, user active, tab visible, extension, initiator type
   v
Analyzer loop, every 10 s                       core/c3/analyzer.py
   |
   |-- 32 features ............................ core/c3/feature_engine.py
   |-- ML score (20 of them, decision scale) .. core/c3/ml_classifier.py
   |-- heuristic score (rhythm first) ......... analyzer._heuristic_score
   |-- fusion + verdict ....................... core/c3/risk_fusion.py
   |-- gates: 10-request floor, known-safe bar, 3 sustained observations
   v
BEACON --> threat-intel lookup (evidence only) . core/c3/reputation_engine.py
       --> alert saved .......................... core/c3/alert_store.py
       --> optional auto-block, 24 h ........... core/c3/interceptor.py + block_store.py
       --> dashboard (Live Monitor, Alerts, Host Analysis, Detection Lab, popup)
```

---

## Modules

| File | Role |
|---|---|
| `interceptor.py` | Attaches CDP to every tab; assembles each request from requestWillBeSent, responseReceived and loadingFinished without pausing the browser; keeps the per-host windows; applies and lifts blocks. |
| `context_tagger.py` | Injects a tracker for clicks, keys, scrolls and touches; gives every request its idle time, user-active flag, tab visibility, extension origin and initiator type. |
| `feature_engine.py` | Turns one host's window into 32 numbers (`FEATURE_ORDER`). |
| `ml_classifier.py` | Loads and validates the model, scores a window, maps the output onto the decision scale. |
| `analyzer.py` | The 10 s loop, the heuristic rules, every gate between a score and an alert. |
| `risk_fusion.py` | Combines ML and heuristic into the risk score and the verdict. |
| `reputation_engine.py` | AbuseIPDB and VirusTotal lookup after a confirmed BEACON. |
| `alert_store.py` | Alerts and analyst feedback in SQLite (`~/.websentinel/c3_alerts.db`). |
| `block_store.py` | Blocks with a 24 h expiry in SQLite (`~/.websentinel/c3_blocks.db`). |

---

## 1. Capture

- **What is recorded.** For every completed request: URL, host, method, status,
  response size, request size, request headers, send time. The response size is
  the Content-Length (the body size the model was trained on), falling back to
  bytes on the wire only when no length is declared.
- **Context per request.** Idle time is kept per destination origin: a click on
  one site does not reset the idle clock of a beacon to another. A top-level
  navigation counts as activity for the site navigated to. A request is "user
  active" when that origin saw activity in the last 30 s and the tab is visible.
  If the context cannot be read, safe defaults are used (user active, visible
  tab) and the request is marked as degraded, so missing context can never add
  suspicion.
- **Window.** The last 50 requests per host, and never anything older than 30
  minutes. A separate full log (up to 10,000 requests per host) feeds the Host
  Analysis view only.

## 2. Features (`feature_engine.py`)

32 features per host window. The model reads 20, all scale-free (ratios, shares,
normalised entropies), so a 2011 capture and a 2026 browser mean the same thing:

| Group | Features |
|---|---|
| Timing shape (8) | `iat_cv`, `iat_bowley_skewness`, `iat_norm_mad`, `iat_burstiness`, `iat_autocorr_lag1`, `iat_spread_ratio`, `iat_clock_share`, `iat_entropy_norm` |
| Size (4) | `payload_size_mean`, `payload_cv`, `payload_repeat_ratio`, `upload_download_ratio` |
| URL and method (5) | `url_path_entropy`, `unique_path_ratio`, `http_post_ratio`, `uri_len_norm`, `uri_char_entropy_norm` |
| Referer (1) | `referrer_absent_ratio` |
| Endpoint without query string (2) | `path_only_entropy`, `unique_path_only_ratio` |

The other 12 (`iat_mean_ms`, `iat_mad_ms`, `requests_per_hour`,
`payload_size_std`, `avg_idle_time_ms`, `user_active_ratio`,
`background_tab_ratio`, `extension_origin_ratio`, `degraded_context_ratio`,
`request_burst_count`, `same_site_ratio`, `script_initiator_ratio`) drive the
heuristic rules, label verdict quality, or feed the dashboard.
`test/C3/test_c3_feature_parity.py` checks on real captured requests that the
live engine and the training builder produce the same 20 values.

## 3. ML score (`ml_classifier.py`)

- **Model.** XGBoost, 300 trees of depth 4, no calibration, trained with equal
  weight per malware family. Monotone domain priors keep the score sensible
  where real data runs out: for example, it can only rise as the timing gets
  more regular or the Referer goes missing. The model file is a dict (`model`, `feature_names`,
  `threshold`, provenance); anything else, or a feature name the live engine
  does not produce, is refused and C3 falls back to heuristic-only scoring.
- **Threshold.** 0.137 on the raw output: the point where 5% of benign training
  windows (out-of-fold) would be flagged.
- **Decision scale.** The raw output is shifted in log-odds so that the model's
  own threshold lands exactly on 50%. The ranking, and every ROC/PR figure, is
  unchanged; "ML 50%" simply means "the model calls this C2". The dashboard,
  the fusion and the alerts all use this scale.
- **When it runs.** From 6 requests in a window; below that there is no timing
  sample and the host is scored on the heuristic alone.

## 4. Heuristic (`analyzer._heuristic_score`)

A beacon repeats on a timer, so the rules ask for a rhythm first. Without one
the heuristic is 0, whatever else is true (an idle user and a hidden tab
describe most of the web).

**Rhythm (one of the two is required):**

| Rule | Condition | Adds |
|---|---|---|
| Clockwork timing | `iat_cv` < 0.05 | +0.30 |
| Steady rhythm despite jitter | `iat_norm_mad` <= 0.20, `iat_spread_ratio` <= 0.70, median gap >= 0.5 s | +0.20 |

Both also need a real timing sample (6+ requests), fewer than half of the
requests with the user active, and a mean response under 8,000 bytes (media
streams are regular too, but large). The jitter limits come from the maths of
uniform jitter, not from fitting the evaluation data: they admit up to about
+/-40%, which covers Cobalt Strike's jitter up to its 50% setting.

**Supporting evidence (counted only with a rhythm):**

| Rule | Condition | Adds |
|---|---|---|
| Fires while the user is idle | user active < 5%, background tab < 50%, average idle > 30 s | +0.25 |
| Runs in a background tab | background tab > 80% | +0.20 (+0.08 instead if any request came from an extension) |
| Extension traffic in the foreground | extension > 50%, background tab < 50% | +0.10 |
| Started by page scripts | script initiator > 70% | +0.05 |
| Same endpoint every time | `path_only_entropy` < 0.50 (query string ignored) | +0.10 |
| Mostly POST check-ins | POST > 90% | +0.08 |
| Frequent requests | more than 500 per hour | +0.08 |
| Same-site sync (dampener) | same site as the page > 80% | x0.70 |

The total is capped at 1.0. Every rule that fired is shown by name on the alert.

## 5. Fusion and verdict (`risk_fusion.py`)

- **Risk score** = 0.55 x ML + 0.45 x heuristic. The split is the best of a
  measured sweep (`scripts/tune_c3_fusion_weights.py`). Without an ML score the
  heuristic alone is used.
- **Verdict:** SAFE below 0.30, SUSPICIOUS from 0.30, BEACON from 0.52.
- **Both engines must agree.** A score that reaches 0.52 is held at 0.51
  (SUSPICIOUS) if the ML score is below 50% (the model does not call it C2) or
  the heuristic is below 0.10 (no timing rhythm). The reason is written into the
  verdict text.
- **Reputation is never a scoring input.** Threat-intel results are evidence
  for the analyst.
- **Context caveat.** When the browser context of 50% or more of a window had
  to be substituted, the verdict says so.

## 6. From score to alert (`analyzer.py`)

Every 10 seconds, for every host with 3+ requests in its window:

1. Blocked hosts are skipped. A new host with fewer than 15 requests is skipped
   for its first 15 s (page loads arrive in bursts).
2. The ML score, the heuristic and the risk score are scaled together by a
   timing-maturity weight that rises smoothly from 0 at 6 requests to 1 at 20.
3. Known analytics and CDN hosts (a list of 19 suffixes) need 0.85, not 0.52,
   to be confirmed.
4. BEACON needs at least 10 requests in the window.
5. BEACON needs 3 observations in a row at SUSPICIOUS or above, each with new
   traffic from the host. A window that is only re-scored does not count, so a
   burst that stops is never confirmed.
6. On BEACON, an alert is written only on a cycle that saw new traffic, and at
   most once per host per 60 s. (A beacon that stops keeps its last verdict on
   screen but writes no further alerts.)
7. The threat-intel lookup runs: AbuseIPDB for the host's IP, VirusTotal for the
   domain, skipped for local and private addresses, cached 30 minutes.
8. Auto-block is off by default. When it is on and the score is at least 0.75,
   the host is blocked for 24 h (Playwright route abort plus CDP
   `Network.setBlockedURLs`), the block is saved, re-applied after a restart and
   lifted automatically when it expires.

## 7. Dashboard and API

Dashboard tabs: **Live Monitor** (every request, one line each), **Alerts**
(this session's incidents and a compact history), **Host Analysis** (every host
with its ML and heuristic score), **Detection Lab** (session summary, blocked
hosts, exports, threat-intel keys, the Real-World Beacon Test, pipeline status).
A confirmed BEACON opens a popup; any alert or host opens the full evidence view,
where an analyst can mark a verdict correct or a false positive (stored as
evidence, never fed back into scoring).

Main endpoints (`core/main.py`): `/c3/status`, `/c3/alerts`,
`/c3/alerts/{id}/feedback`, `/c3/alerts/feedback/stats`,
`/c3/alerts/feedback/export`, `/c3/hosts`, `/c3/hosts/{host}`, `/c3/requests`,
`/c3/hosts/{host}/block`, `/c3/hosts/{host}/unblock`, `/c3/auto-block/enable`,
`/c3/auto-block/disable`, `/c3/collect/start|stop|export`,
`/c3/test/beacon-page`, `/c3/test/beacon-target`, `/c3/test/real-world-beacon`.

## 8. The model: data, training, results

- **Training data (in the repository):** `data/c3_training_dataset_clear.csv`,
  the exact 52,909 windows the deployed model was trained on (310 C2 over 40
  C&C connections, 52,599 benign): the 20 features, then `label`, `family`,
  `capture` and `connection`. Retraining from it reproduces the deployed model
  tree for tree, with the same threshold; `core/c3/C3_ML_Train.ipynb` Section 5
  checks this every time it runs. Column definitions:
  `C3_Training_Dataset_Feature_Dictionary.md` (this folder). No synthetic data.
- **How it was built:** from a corpus of 62,321 windows of real HTTP from 26
  public captures (CTU-13, CTU-Normal and the Stratosphere Zeus captures), 6,890
  C2 windows from 6 malware families and 55,431 benign, built by
  `scripts/build_c3_18feat_dataset.py` into `data/c3_18feat_dataset.csv` (both
  *archived*). The trainer (`scripts/train_c3_final_model.py`, *archived*) kept
  C2 channels that were answered at least once and succeeded at least once, and
  at most 150 windows per connection.
- **Label correction.** 273,944 requests that the captures' own ground truth
  attributes to the bot, but never to a C&C channel (click-fraud polling,
  download retries), were withdrawn from the benign class as undetermined
  (6,143 windows).
- **Held-out results** (recomputed by `core/c3/C3_ML_Train.ipynb`): unseen
  malware family (LOFO), per window: accuracy 0.9693, precision 0.9564, recall
  0.9835, F1 0.9697; per family: 0.9264 / 0.9444 / 0.9064 / 0.9218, ROC-AUC
  0.9765.
- **End to end** (`scripts/eval_c3_real_world_pipeline.py` and
  `data/_c3_real_world_pipeline_results.json`, both *archived*): the same
  families through the whole pipeline, with and without assumed browser
  context. Periodic C2 is confirmed as BEACON; C2 without a timing rhythm is
  reported as SUSPICIOUS.

## 9. Tests

| Test | What it proves |
|---|---|
| `test/C3/test_c3_units.py` (154 tests) | Rules, fusion, gates, persistence, alerts, blocks, model loading, the decision scale, idle-host eviction, and that reusing an unchanged window's scores changes no verdict. The dashboard's Tests panel runs it. |
| Live Test Runner, C3 rows (`core/main.py`), 7 cases | Real Zeus C2 and real human browsing through the production pipeline, the most beacon-like hosts of a real 60-minute browsing session, a Cobalt Strike-style jittered beacon, the fusion rules, TC-02 (a live beacon in a real browser tab), and TC-03 (a beacon over a public ngrok tunnel, with the live threat-intel lookup). |
| `test/C3/tc03_real_world_c2_beacon.py` | The same TC-03 scenario as a standalone script, behind Detection Lab's Run Test button. |
| `test/C3/test_c3_feature_parity.py` (4 tests, *archived*) | Training builder and live engine agree on the 20 features, on 120 real captured requests. Last run 2026-09-15: 4 of 4 passed. |
| `test/C3/tc01_cobalt_strike_beacon.py` (*archived*) | Live GET beacon from a page the user left open. Last run 2026-09-14: all checks passed. |
| `test/C3/tc02_cloud_apt_exfiltration.py` (*archived*) | Live POST beacon in a second tab while the user browses in the first. Last run 2026-09-14: all checks passed. |
| `test/C3/tc03b_reputation_override_verification.py` (*archived*) | A real flagged IP cannot move the risk score. |

## 10. Known limitations (measured)

- **Referer.** The model's strongest input is a missing Referer. A beacon sent
  by an in-page `fetch()` carries one, so the model scores it low and the host
  shows as SUSPICIOUS (flagged by the rhythm), not BEACON. Fixing that needs a
  retrain.
- **Background tabs.** Playwright-driven Chromium reports every tab as visible,
  so `background_tab_ratio` stays 0 (`scripts/repro_c3_background_tab_blind.py`, *archived*).
  The per-origin idle clock still separates a beacon's tab from the one the user
  is using.
- **Slow beacons.** A host needs 10 requests inside the 30-minute window to be
  confirmed (one every 3 minutes or faster) and 20 for full timing weight (one
  every 90 s). Slower beacons are not confirmed.
- **Benign heartbeats** (one endpoint, tiny replies, no Referer, every few
  seconds) look like a beacon. In automated capture-background traffic, under
  the worst-case assumed context, 1.36% of windows reach BEACON.
- **C2 without a rhythm**, or a beacon whose sleep changes inside its window,
  is flagged SUSPICIOUS; confirmation waits for a steady rhythm.
- **Auto-block**: the operational false-block rate on live traffic has not been
  measured, which is why auto-block is off by default.

---

## 11. Cost of a cycle

Scoring one host means one feature pass plus one XGBoost prediction, and both run
on the shared event loop, so the cycle's cost is what a user feels as lag.
Measured on this machine, over a 50-request window:

| Step | Per host |
|---|---|
| `compute_features` | 1.34 ms |
| ML score (one prediction) | 0.41 ms |
| Both heuristic passes | under 0.01 ms |
| **Total** | **about 1.8 ms** |

Two things keep that from adding up:

- **An unchanged window is not re-scored.** The loop visits every host every 10
  seconds, and a host that has gone quiet keeps its window for up to 30 minutes,
  so most cycles used to recompute an identical answer. The features, both
  heuristic passes and the ML score are now reused when the window has not
  changed, keyed by its length and its first and last timestamps. Only pure
  functions are reused: fusion, the streak counters, the verdict and alerting
  still run every cycle, so no decision changes. Measured over 120 hosts and 4
  cycles: 325 ms per cycle before, 76 ms after, with byte-identical results.
- **Silent hosts are forgotten.** `_host_windows` and `_host_history` were
  created on a host's first request and only cleared on stop, so a session held
  every host it ever saw: about 38 MB for 800 dead hosts, all of them already
  too old to score, and all of them still listed in the Hosts tab.
  `evict_idle_hosts()` drops a host once its newest request is older than the
  30-minute window. Blocked hosts, whose capture log is deliberately frozen at
  the block boundary, and hosts still showing SUSPICIOUS or BEACON are kept.

The per-host loop also yields to the event loop every 25 hosts, so a busy session
cannot hold it for one long block.

---

## 12. The 2026-09-11 hardening pass

Code comments and tests refer to this pass by step number. The plan file that
described it was archived on 2026-09-17 (see `README.md`); the steps were:

| Step | What it added | Where |
|---|---|---|
| 1 | The two endpoint features (`path_only_entropy`, `unique_path_only_ratio`), so a cache-busting query string alone cannot move the URL signals. 18 ML features became 20. | `feature_engine.py`, `ml_classifier.py` |
| 2 | Payload size read from the response body (`content_length`), matching what training measured. Both raw measurements are kept on every event so the question can be re-checked on live traffic. | `interceptor.py` |
| 3 | `degraded_context_ratio`, so a verdict states plainly whether browser context was measured or substituted. | `feature_engine.py` |
| 4 | The temporal persistence gate (a BEACON must be seen in 3 consecutive observations that each saw new traffic) and the opt-in context-blind ML bypass. | `analyzer.py` |
| 5 | The Detection Lab's test beacon sends `referrerPolicy: 'no-referrer'`, because a real implant has no referring page. Without it a textbook beacon scored only 0.31 and could never reach BEACON. | `core/main.py` |
| 7 | Background-tab handling in the Playwright session. | `playwright_session.py`, `core/main.py` |
| 8 | The analyst feedback loop on alerts. | `alert_store.py`, `core/main.py` |

Step 6 left no trace in the code or the tests, so it is not described here rather
than guessed at.
