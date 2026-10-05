# Test Case 01: Cobalt Strike-style Beacon from a Compromised Page

> **Note, 2026-09-15.** This test is not part of the running app, so its script
> and launcher were moved out of the repository to
> `Desktop\Removals in C3\L A S T - Removals\2026-09-15_runtime_only_clean\test\C3\`.
> To run it again, copy both files back into `test/C3/`.

| | |
|---|---|
| Component | C3, Browser Execution Aware C2 Beacon Detector |
| Test case ID | TC-C3-01 |
| Script | `test/C3/tc01_cobalt_strike_beacon.py` |
| Launcher | `test/C3/run_testcase_01.bat` |
| Type | Live, end to end, in a real browser |
| Duration | about 2 minutes (5 s beacon) |
| Last run | 2026-09-14: all 7 checks passed |

## 1. Scenario

A WordPress site has been compromised and its pages now carry an injected
script. A visitor opens one of those pages, leaves it open and stops touching
it. The script checks in with its command-and-control server on a timer: the
same URL every time, a small request, no Referer. This is the shape of a
Cobalt Strike HTTP beacon (sleep with a little jitter, one endpoint).

What the test shows: C3 confirms this beacon through the live pipeline, with
both engines agreeing, and flags nothing else the browser visited.

## 2. How it runs

`run_testcase_01.bat` starts its own backend on `127.0.0.1:8001` (unless one is
already running there) and then runs the script:

1. **Connect.** Checks the backend, the C3 analyzer and that the ML model is
   loaded; starts the monitored browser session if needed.
2. **Baseline** (skip with `--no-baseline`). Opens Wikipedia for 20 s; ordinary
   browsing must stay SAFE.
3. **Beacon.** Sends the monitored browser to the backend's test page,
   `/c3/test/beacon-page?interval=5000&method=GET`. Its script fetches
   `/c3/test/beacon-target` every 5 s with `referrerPolicy: 'no-referrer'` and
   no cache-busting query string, like a real implant.
4. **Monitor.** Polls `/c3/hosts` every 10 s until the beacon host is BEACON
   (6-minute limit).
5. **Result and checks.**

Options: `--interval 30000` for a slower, more realistic pace (the run takes
longer), `--no-baseline` to skip step 2.

## 3. What C3 does with it

- The interceptor captures every check-in with its browser context. For 30 s
  after the page loads, its requests count as user activity (a navigation is
  treated as the user's doing); after that, with no clicks or keys, they count
  as idle.
- The heuristic first needs a timing rhythm. The page-load requests at the
  start of the window keep the plain `iat_cv` near 0.24, so the clockwork rule
  (`iat_cv` < 0.05) does not fire; the robust "steady rhythm despite jitter"
  rule does. Then "same endpoint every time", "started by page scripts" and
  "frequent requests (over 500/hour)" add to it.
- XGBoost reads the 20 traffic-shape features; a missing Referer and one fixed
  endpoint are strong C2 signs.
- BEACON needs a risk score of 52% or more with ML at 50% or more and a timing
  rhythm, plus 10 requests and 3 observations in a row with new traffic.
- The beacon goes to `127.0.0.1`, so the threat-intel lookup is skipped (local
  host). TC-03 covers the lookup.

## 4. Pass criteria

| # | Check | Why |
|---|---|---|
| 1 | Verdict is BEACON | the detection itself |
| 2 | Risk score >= 0.52 | the BEACON threshold |
| 3 | ML >= 0.50 | the model itself calls the traffic C2 |
| 4 | A timing rhythm was found (clockwork, or steady despite jitter) | BEACON must rest on a rhythm |
| 5 | Heuristic >= 0.30 | more than the rhythm alone (0.20) corroborates |
| 6 | `user_active_ratio` < 0.50 | the user was not using the beacon's page; this is also C3's own condition for counting a rhythm |
| 7 | No other host is BEACON | no false positive on the baseline traffic |

`background_tab_ratio` is printed for information only. Playwright-driven
Chromium reports every tab as visible, so it is 0 here
(`scripts/repro_c3_background_tab_blind.py`).

## 5. Measured result (2026-09-14)

Run against a fresh backend and browser profile:

| | |
|---|---|
| Verdict | BEACON, risk 63%, after 20 requests (90 s of beacon traffic) |
| ML | 80% |
| Heuristic | 42%: steady rhythm despite jitter, started by page scripts, same endpoint every time, frequent requests |
| `iat_cv` / `user_active_ratio` | 0.24 / 0.37 |
| False positives | none |
| Result | ALL CHECKS PASSED |

## 6. Change history

- **2026-09-14.** Three checks could not pass on a run that correctly reached
  BEACON and were replaced: `iat_cv < 0.10` (page-load requests keep it near
  0.24, which is why the robust rhythm rule exists), `user_active_ratio < 0.10`
  (the first 30 s after a navigation count as activity), and
  `background_tab_ratio > 0.80` (not observable under Playwright). An ML check
  was added. The previous version of this document described a retired design
  (Isolation Forest, 14 features, reputation inside the score) and was archived.
