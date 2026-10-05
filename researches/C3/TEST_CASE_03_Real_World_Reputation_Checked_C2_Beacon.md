# Test Case 03: Real-World C2 Beacon with a Live Threat-Intel Lookup

> **Note, 2026-09-15.** The Detection Lab **Run Test** path is part of the app
> and stays in the repository (`test_c3_real_world_beacon.bat` and the three
> `test/C3/tc03_*.py` scripts). The manual launcher `test/C3/run_testcase_03.bat`
> and the companion `tc03b_reputation_override_verification.py` (Section 7) are
> not needed at runtime and were moved to
> `Desktop\Removals in C3\L A S T - Removals\2026-09-15_runtime_only_clean\test\C3\`.

| | |
|---|---|
| Component | C3, Browser Execution Aware C2 Beacon Detector |
| Test case ID | TC-C3-03 |
| Script | `test/C3/tc03_real_world_c2_beacon.py` (+ `tc03_mimicry_server.py`, `tc03_get_ngrok_url.py`) |
| Launchers | The **Live Test Runner** row "TC-03 Real-world beacon over a public ngrok tunnel" (in-process, since 2026-09-17), Detection Lab's **Run Test** button (runs `test_c3_real_world_beacon.bat` in its own console), or `test/C3/run_testcase_03.bat` |
| Type | Live, end to end, over the public internet |
| Duration | about 3 to 6 minutes |

## 1. Scenario

A small C2 mimicry server that you own plays the attacker's infrastructure. It
is reachable from the internet through an ngrok tunnel from your own machine.
The monitored browser opens its page, whose script checks in every 1.5 s with
a small fixed POST to one endpoint, no Referer, and 2% timing jitter: the
"sleep and jitter" shape of a Cobalt Strike beacon.

This is the only C3 test whose beacon goes to a public host, so it is the only
one where C3's threat-intel lookup really runs (for `127.0.0.1`, as in TC-01 and
TC-02, the lookup is skipped). What it shows: the full pipeline, from capture to
a confirmed BEACON, a real AbuseIPDB / VirusTotal answer attached to the alert,
and, with auto-block on, the block decision.

## 2. Requirements

- **ngrok**, installed (on PATH or at the WinGet location) and signed in once:
  `ngrok config add-authtoken <your token>`.
- **A threat-intel key**, AbuseIPDB and/or VirusTotal, saved in Detection Lab
  (Threat Intelligence Keys). Without one, the two lookup checks cannot pass.
- For the Detection Lab button: WebSentinel running (backend on port 8765).

## 3a. How it runs (Live Test Runner path, since 2026-09-17)

The runner row does the whole scenario in the backend process, so it reports
pass or fail on the Tests panel like every other test case:

1. Finds `ngrok` (on PATH, or the WinGet install path). If it is not
   installed the row reports that and does not fail, because a missing
   optional tool is not a C3 defect.
2. Starts `test/C3/tc03_mimicry_server.py` on port 8080 (1500 ms, 2% jitter)
   and waits for it to listen.
3. Starts `ngrok http 8080` and reads the public HTTPS address from ngrok's
   local API, matching the tunnel by its own target port so another tunnel
   cannot be picked up by mistake.
4. Navigates the monitored browser to it (the navigation carries
   `ngrok-skip-browser-warning`), then polls C3's own host list until the
   verdict is BEACON, up to 3.5 minutes.
5. Checks the verdict, the ML score, that a timing rhythm was found, that the
   threat-intel lookup really ran on the public address, and that auto-block
   followed its own rule.
6. Stops the tunnel and the mimicry server, closes the page and lifts any
   block, whether the checks passed or not.

Measured on 2026-09-17: BEACON at 61% after 42 requests, 72 s from
navigation, ML 82%, heuristic 36%, AbuseIPDB and VirusTotal both queried and
both clean, alert written.

## 3. How it runs (Detection Lab path)

Detection Lab's **Run Test** calls `POST /c3/test/real-world-beacon`, which opens
`test_c3_real_world_beacon.bat` in a new console window:

1. Starts `tc03_mimicry_server.py` on port 8080 (1500 ms interval, 2% jitter).
2. Starts `ngrok http 8080` and reads the public HTTPS address from ngrok's
   local API (`tc03_get_ngrok_url.py`).
3. Runs `tc03_real_world_c2_beacon.py` against that address:
   - navigates the monitored browser straight to the tunnel page (same-origin
     traffic is the capture path that is reliable here; the script's docstring
     records the four designs tried before this one);
   - waits up to 165 s for BEACON, then up to 200 s more for the score to
     mature (it stops early once the host is blocked with auto-block on, or once
     ML reaches 80% and the heuristic 50% with it off);
   - reads the threat-intel result from the saved alert and runs the checks.
4. Stops the tunnel and the mimicry server.

Manual path: deploy `tc03_mimicry_server.py` on a host you own (a VPS, a
free-tier cloud VM, or your own tunnel), then run
`test\C3\run_testcase_03.bat --target-host <that host>`. The server's own
`--interval-ms` and `--jitter-pct` set the beacon's pace.

## 4. Pass criteria

| # | Check | Why |
|---|---|---|
| 1 | Verdict is BEACON | the detection itself |
| 2 | Risk score >= 0.52 | the BEACON threshold |
| 3 | POST ratio >= 0.967 | the one page-load GET has been diluted by check-ins, the state the test waits for |
| 4 | ML between 0.50 and 0.995 | the model calls the traffic C2, and is not stuck at 1.0 |
| 5 | Heuristic >= 0.20 | the rules genuinely contribute (above the 0.10 both-signal floor) |
| 6 | A real threat-intel lookup ran | not the local-host skip |
| 7 | The lookup returned a source result (Clean or FLAGGED) | the integration works end to end |
| 8 | No other (non-tunnel) host is BEACON | no false positive |
| 9 | Only with auto-block on: blocked if the score reached 0.75, held back below it | C3 followed its auto-block rule |

`user_active_ratio` and `same_site_ratio` are printed for information. Opening
the page directly marks it as in use for 30 s and makes all traffic same-site,
so the same-site dampener (x0.70) always applies here.

## 5. Measured behaviour

The five live runs made on this machine since the page stopped sending a
Referer (2026-09-08 to 2026-09-14) saved 46 alert windows. Re-scored with the
current code:

| | |
|---|---|
| Runs that reached BEACON | 5 of 5 |
| Confirmed windows | 38 of 46 (the rest were taken while a run was still maturing: SUSPICIOUS) |
| Risk of confirmed windows | 54% to just under 75% |
| ML / heuristic | 54% to 86% / 43% to 60% |
| Rules | clockwork timing, fires while the user is idle, started by page scripts, mostly POST check-ins, frequent requests; same-site dampener applied |
| Auto-block floor (75%) reached | in none of the 46 windows |

So with auto-block on, C3 is expected to confirm this beacon but hold back the
block, and check 9 passes on that. (The 2026-08 runs used an older page that
sent a Referer and are not comparable.)

## 6. Ethics and safety

- **Your own infrastructure only.** The target is your mimicry server behind
  your own tunnel (or a host you own). Never point this test at a third party.
- **Nothing harmful is exchanged.** The server is inert: no command channel, no
  code execution, no file transfer, no exfiltration. Each check-in gets the same
  small fixed JSON reply. It never contacts anyone itself.
- **Threat-intel services** are asked about your server's address through their
  official APIs with your own key, once per confirmed beacon, cached 30 minutes.
- **Clean-up** is automatic: the launcher stops the tunnel and the server.

## 7. Companion: TC-03b

`test/C3/tc03b_reputation_override_verification.py` (optional, read-only) looks
up a real, currently flagged IP (it never sends that IP a packet) and shows that
the risk score is the same whatever the reputation says: reputation is evidence
for the analyst, never part of the score.

## 8. Change history

- **2026-09-14.** Check 9 used to require a block whenever auto-block was on.
  Auto-block only acts at a score of 0.75 or more, and this beacon now scores
  54% to just under 75%, so C3 correctly did not block and the old check failed a
  correct run. It now checks the rule itself. This document was rewritten for the
  current design; the previous version (Isolation Forest era numbers, a
  `data:`-page design that was later abandoned) was archived.
