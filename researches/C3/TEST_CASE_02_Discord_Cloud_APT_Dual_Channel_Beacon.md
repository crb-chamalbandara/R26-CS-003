# Test Case 02: Exfiltration Beacon in a Second Tab While the User Browses

> **Note, 2026-09-15.** This test is not part of the running app, so its script
> and launcher were moved out of the repository to
> `Desktop\Removals in C3\L A S T - Removals\2026-09-15_runtime_only_clean\test\C3\`.
> To run it again, copy both files back into `test/C3/`.

| | |
|---|---|
| Component | C3, Browser Execution Aware C2 Beacon Detector |
| Test case ID | TC-C3-02 |
| Script | `test/C3/tc02_cloud_apt_exfiltration.py` |
| Launcher | `test/C3/run_testcase_02.bat` |
| Type | Live, end to end, in a real browser, two tabs |
| Duration | about 2.5 minutes (8 s beacon) |
| Last run | 2026-09-14: all 9 checks passed |

## 1. Scenario

An APT implant (a malicious extension or an injected script) runs in a tab the
user has left open, and posts small check-ins to its C2 endpoint: the uplink of
an exfiltration channel. Meanwhile the user is busy in another tab, browsing
normally. The hard part for a detector is that the machine is plainly in use:
a global "is the user idle?" signal would say no, and hide the beacon.

What the test shows: C3 keeps activity per destination, so the user's browsing
in one tab does not make the beacon in the other look user-driven, and the
beacon is confirmed while the browsed sites stay clean.

## 2. How it runs

`run_testcase_02.bat` starts its own backend on `127.0.0.1:8001` (unless one is
already running there) and then runs the script:

1. **Connect.** Checks the backend, the C3 analyzer and the ML model; starts the
   monitored browser session if needed.
2. **Beacon tab.** Opens `/c3/test/beacon-page?interval=8000&method=POST` in a
   real second tab behind the page in use (`POST /session/background_tab`). Its
   script POSTs a small JSON body to `/c3/test/beacon-target` every 8 s, with no
   Referer.
3. **Active browsing** in the first tab while the beacon keeps sending:
   Wikipedia (12 s), a Google search (10 s), the Wikipedia article on command
   and control (10 s).
4. **Monitor.** Polls `/c3/hosts` every 10 s until the beacon host is BEACON
   (12-minute limit), then closes the beacon tab
   (`POST /session/background_tab/close_all`; also done on Ctrl+C).
5. **Result, per-tab comparison and checks.**

Option: `--interval 60000` for a slower, more realistic pace (the run takes much
longer).

## 3. What C3 does with it

- Idle time is tracked per destination origin. The navigations in the first tab
  mark those sites as in use; the beacon's origin gets no activity after its
  tab opens, so after 30 s its check-ins count as idle.
- The heuristic finds the rhythm (clockwork in the measured run), then adds
  "same endpoint every time", "mostly POST check-ins" and "started by page
  scripts".
- XGBoost reads the 20 traffic-shape features: no Referer, one endpoint, tiny
  replies of the same size, POST.
- BEACON needs a risk score of 52% or more with ML at 50% or more and a timing
  rhythm, plus 10 requests and 3 observations in a row with new traffic.
- The beacon goes to `127.0.0.1`, so the threat-intel lookup is skipped (local
  host).

## 4. Pass criteria

| # | Check | Why |
|---|---|---|
| 1 | Verdict is BEACON | the detection itself |
| 2 | Risk score >= 0.52 | the BEACON threshold |
| 3 | ML >= 0.50 | the model itself calls the traffic C2 |
| 4 | A timing rhythm was found | BEACON must rest on a rhythm |
| 5 | `user_active_ratio` < 0.50 for the beacon | the user was not using the beacon's tab |
| 6 | POST ratio > 0 | the exfiltration method is visible |
| 7 | Heuristic >= 0.30 | more than the rhythm alone corroborates |
| 8 | Beacon `user_active_ratio` below the browsed hosts' | per-tab (per-origin) discrimination, the point of this test |
| 9 | No other host is BEACON | no false positive on the sites the user browsed |

`background_tab_ratio` is printed for information only: the beacon runs in a
real second tab, but Playwright-driven Chromium reports every tab as visible
(`scripts/repro_c3_background_tab_blind.py`).

## 5. Measured result (2026-09-14)

Run against a fresh backend and browser profile:

| | |
|---|---|
| Verdict | BEACON, risk 62%, after 17 requests |
| ML | 78% |
| Heuristic | 42%: clockwork timing, started by page scripts, same endpoint every time, mostly POST check-ins |
| `user_active_ratio` | beacon 0.19, browsed hosts 1.00 |
| False positives | none |
| Result | ALL CHECKS PASSED |

## 6. Change history

- **2026-09-14.** The beacon used to be opened in the same tab the test then
  navigated to Wikipedia and Google, which unloaded the beacon page: it sent one
  or two requests and the test could never reach the 10 C3 needs. It now runs in
  a real second tab and is closed at the end. The unreachable
  `background_tab_ratio > 0.80` and `user_active_ratio < 0.10` checks were
  corrected as in TC-01, and ML and rhythm checks were added. The previous
  version of this document described a retired design (Isolation Forest,
  14 features, reputation inside the score) and was archived.
