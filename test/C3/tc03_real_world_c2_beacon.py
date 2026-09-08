"""
TC-03 — Real-World Infrastructure C2 Beacon with Live Threat-Intel Lookup
===========================================================================
Unlike TC-01/TC-02 (which beacon to 127.0.0.1, so C3's reputation engine
skips the lookup entirely -- see core/c3/reputation_engine.py's
_is_private_or_local() guard), this test beacons against a REAL, publicly
resolvable IP/hostname that YOU deploy (see tc03_mimicry_server.py). That
makes this the only one of the three test cases that genuinely exercises
C3's full pipeline end-to-end: the ML + heuristic risk score PLUS a real
outbound AbuseIPDB / VirusTotal lookup, whose result is attached to the
alert as analyst evidence (it does not change the risk score).

ARCHITECTURE (four real, live-tested designs before this one -- each
attempt's actual failure is kept here rather than silently erased, because
each taught something the next one needed):

  1. Navigate directly to the mimicry server's own page. Live-tested
     2026-08-29: same_site_ratio stayed 1.0 (Rule 9 dampener fires), and at
     the time the ML signal on that profile (GET-based) was near-zero, so
     the dampened heuristic alone never reached BEACON_THRESHOLD.
  2. After probing the live model and re-deriving a POST + fixed-payload +
     zero-entropy-endpoint profile that scores ~0.91-0.96, navigate to a
     neutral `data:` URL instead, with the beacon loop injected via
     cross-origin fetch(). Live-tested 2026-08-30: broke CDP capture
     entirely -- Chromium isolates `data:` top-level navigations into a
     separate, unprivileged renderer process, which detaches C3's per-page
     CDP session (Playwright's own docs note `context.new_cdp_session()`
     does not survive a cross-process navigation). Requests genuinely
     fired and got real responses (confirmed via ngrok's own request-
     inspector log), but the backend never saw a single one over 130s.
  3. Revert to direct navigation (fixes CDP capture). Live-tested
     2026-08-30: reintroduced #1's same-site dampener, AND surfaced a more
     decisive problem -- the single one-time page-load GET request lands
     in the SAME per-host rolling window as every POST /checkin beacon.
     Probing the live model with the exact live feature values found the
     real driver was NOT same_site_ratio or url_path_entropy (both
     re-tested in isolation and found flat): it was http_post_ratio -- a
     hard cliff between 0.96 (prob 0.08) and 0.967 (prob 0.84).
  4. Try a real (non-`data:`) neutral `http://127.0.0.1` landing page,
     reasoning that a genuinely different host would keep the target's own
     window 100% POST. Live-tested 2026-08-30: this exposed a still more
     fundamental limit -- CDP in this session simply does not report
     cross-origin, JS-initiated fetch() requests AT ALL, regardless of
     `data:` vs real loopback origin, and regardless of CORS mode (tested
     both `no-cors` and plain `cors`; both confirmed reaching ngrok's own
     request-inspector log with zero backend-side capture). A live control
     test in the same session confirmed DIRECT navigation to the target
     captures instantly and reliably. Cross-origin fetch capture, whatever
     its cause, is not usable here; same-origin navigation is the only
     capture path this backend reliably supports.

THIS design accepts that constraint and works within it: navigate directly
to the target (reliable capture, attempt #3's approach), but instead of
fighting the http_post_ratio cliff, let C3's own rolling window (deque,
maxlen=50 -- see core/c3/interceptor.py) dilute it naturally. The one-time
GET stays a CONSTANT single event while POSTs accumulate, so the ratio
climbs every cycle; probing the live model at the exact ratios this
produces found the cliff sits between n=25 (1 GET + 24 POST, ratio 0.96,
prob 0.08) and n=30 (1 GET + 29 POST, ratio 0.967, prob 0.84) -- reaching
roughly 30 total requests, not 50, clears it. At a 4s interval that is
~120s of beacon traffic, comfortably inside the 3-minute budget. The
same-site dampener (Rule 9) still applies here, same as attempt #3 -- see
the live math in TEST_CASE_03's doc for why the heuristic term still
clears BEACON_THRESHOLD in combination with the now-correctly-diluted ML
term once n is large enough.

PREREQUISITE: deploy tc03_mimicry_server.py to your own real infrastructure
first (see TEST_CASE_03_Real_World_Reputation_Checked_C2_Beacon.md for
setup options), then pass its address via --target-host.

Run via:  run_testcase_03.bat --target-host <your-real-ip-or-hostname>
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from urllib import error, request as urlrequest

# ── Config ────────────────────────────────────────────────────────────────────
API              = "http://127.0.0.1:8765"
DEFAULT_PORT     = 8080
# 4s: fast enough to reach the ~30-event http_post_ratio dilution point
# (see the module docstring) inside the demo budget, slow enough that real
# network/timer jitter stays a small fraction of the interval.
DEFAULT_INTERVAL = 4_000          # ms
DEFAULT_JITTER   = 2              # percent -- see test_c3_real_world_beacon.bat's
                                   # JITTER_PCT for why (this default is cosmetic
                                   # only: the mimicry server's actual timing is
                                   # set by whoever launches it, not by this
                                   # script's own --jitter-pct, which this file
                                   # never reads for anything but the STEP 2 print)
POLL_EVERY       = 5
MIN_EVENTS       = 10            # C3's own hard floor (analyzer.py's allow_beacon)
DILUTION_EVENTS  = 30            # this test's own floor -- see the module docstring's cliff analysis
DETECT_MAX_WAIT  = 165           # hard stop for the detection-wait phase specifically
# Detection (up to DETECT_MAX_WAIT) + maturation (up to MATURATION_WAIT_S,
# its own separate budget -- see the loop below) can together reach ~365s
# in the slowest realistic case (165 + 200, MATURATION_WAIT_S raised
# 130 -> 200 on 2026-09-08 -- see that constant's own comment). This is a
# display-only figure (how much "budget" is shown remaining each poll);
# raised 300 -> 400 alongside that change so display doesn't read as
# over-budget/red in the worst case -- the panel-facing TARGET is still
# ~180s (3 min), this is just the ceiling.
TOTAL_BUDGET_S   = 400           # the whole demo, panel-facing budget
# The actual panel-facing goal: auto-block landing close to the 3-minute
# mark. Kept as its own constant (separate from TOTAL_BUDGET_S, the outer
# ceiling) purely so STEP 1's summary line can state the real target
# honestly instead of conflating it with the worst-case budget.
TARGET_AUTO_BLOCK_S = 180
# How long to keep polling AFTER the first BEACON confirmation, so the
# heuristic score can reach its real ceiling instead of being reported the
# instant it merely clears BEACON_THRESHOLD. analyzer.py's Rule 2 (+0.25,
# "foreground requests firing while user idle") needs user_active_ratio <
# 0.05, but the rolling 50-event window still has a handful of "fresh"
# (recently-navigated, so counted active) events in it right when BEACON
# first confirms (~53 requests in). Those age out of the window as more
# idle events accumulate -- no code change needed, just more elapsed time.
# This is a CEILING, not a fixed wait: the loop below exits as soon as
# user_active_ratio actually reaches 0 rather than always waiting the full
# amount, because every extra second here is also extra exposure to a real,
# separate risk -- live-tested 2026-08-30: ngrok's tunnel periodically
# re-establishes its underlying connection (roughly every 90-120s, outside
# this script's control), and each reconnect injects one oversized POST
# response into the window (a fresh-connection premium, same phenomenon
# that inflates the very first page-load GET -- see tc03_mimicry_server.py).
# The model has a hard, payload-size-independent cliff once payload_size_std
# crosses ~6-8 (measured via direct predict_proba() probing: 0.94 at std=5
# vs 0.47 at std=8, at multiple different mean values -- not fixable by
# picking a different payload target).
#
# This is a TRANSIENT dip, not a permanent one in principle -- the same
# dilution idea this whole test already relies on for http_post_ratio (see
# the module docstring): one oversized event among an ever-growing pool of
# uniform ones shrinks payload_size_std back down as more clean POSTs
# accumulate and the offending event ages out of the 50-slot window. In
# practice, live-tested 2026-08-30 across several runs: this network noise
# recurs more often than a single rare event (closer to every 20-40s than
# the ~90-120s first estimated), so the loop waits for the REAL target --
# the host actually auto-blocked, when auto-block is on -- rather than a
# fixed-band proxy, and gives it real time to happen under that noise.
#
# Widened 100 -> 130 on 2026-08-30 alongside slowing the beacon interval to
# 1500ms (see test_c3_real_world_beacon.bat): across 3 live runs, the first
# reconnect-driven dip consistently landed at ~63-71 REQUESTS in (not a fixed
# wall-clock time -- event-count-paced, despite earlier estimates), and the
# one clean run that reached full ML+Heuristic alignment did so ~45-50
# requests after that first dip (~116 total). At 1500ms that points to
# alignment around ~174s -- close to the panel's requested 3-minute mark --
# so this ceiling gives real margin past that estimate rather than cutting
# it off right at the target. Still not unbounded, and still the same
# principle: if alignment genuinely hasn't happened by the time this expires,
# that is the honest result to report, not a bug to paper over.
#
# WIDENED AGAIN, 130 -> 200, on 2026-09-08, alongside JITTER_PCT 5% -> 2%
# in test_c3_real_world_beacon.bat, after auto-block was reported not firing
# even on a run that clearly reached BEACON. Root cause, found by directly
# probing the live model (models/c3_xgb_scoped_calibrated_20260903.pkl) with
# synthetic windows built the same way tc03_mimicry_server.py's real traffic
# is shaped: analyzer.py's block-eligibility check (_handle_beacon(),
# core/c3/analyzer.py) only re-runs once every 60s -- its own alert cooldown
# also gates the auto-block check -- so a fused score that clears
# AUTO_BLOCK_SCORE_FLOOR (0.75) for only part of the maturation window can be
# missed if none of those 60s-spaced checks happens to land inside it. Two
# compounding causes of that narrowness, both measured directly against the
# deployed model+fusion (see JITTER_PCT's own comment for the first):
#   1. At 5% jitter, the 50-event window's sample iat_cv sits almost exactly
#      on analyzer.py Rule 1's "iat_cv < 0.05" cliff, so its +0.30 flips on
#      and off between consecutive windows -- a large, frequent swing.
#   2. Even fully matured (heuristic pinned at its ~0.60 ceiling, ALL
#      applicable rules firing every window -- confirmed flat at 0.6020
#      across 1,440 simulated mature windows), the ML term alone still
#      varies window to window (measured range 0.8709-0.9505, mean 0.9301 --
#      ordinary XGBoost sensitivity to which 50 requests are currently in the
#      window, not a bug), which alone can land fused as low as ~0.7499 -- a
#      hair under the floor -- on any single reading.
# Fixing #1 (JITTER_PCT) removes the large swing; widening the wait here
# gives the 60s-cooldown check more independent tries to land on a >=0.75
# reading despite #2's smaller, irreducible variance. Simulated over 500 runs
# at the real 60s check cadence, using the mimicry server's real, live-
# verified check-in reply size (80 bytes, confirmed via curl):
# 5%+130s = 76.2% of runs actually auto-block, 2%+130s = 97.6%,
# 2%+200s = 100%. Neither change alone was enough; both are needed
# together -- roll back together.
MATURATION_WAIT_S = 200

# ── ANSI helpers ──────────────────────────────────────────────────────────────
os.system("")
# Force UTF-8 stdout: the checkmark/cross characters below crash with
# UnicodeEncodeError under Windows' default console codepage (cp1252),
# especially when stdout is redirected to a file rather than a real TTY --
# a real bug this project found and fixed live once already.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass
_R = "\033[0m"; _B = "\033[1m"; _D = "\033[2m"
RED = "\033[91m"; YEL = "\033[93m"; GRN = "\033[92m"
CYN = "\033[96m"; BLU = "\033[94m"; WHT = "\033[97m"; MAG = "\033[95m"

def c(t, *codes): return "".join(codes) + str(t) + _R
def risk_col(s): return RED if s >= 0.52 else YEL if s >= 0.3 else GRN
def score_s(v):
    if v is None: return c(" n/a", _D)
    return c(f"{round(v*100):>3}%", risk_col(v))
def verdict_s(v):
    v = v.upper()
    if v == "BEACON":     return c("BEACON    ", _B, RED)
    if v == "SUSPICIOUS": return c("SUSPICIOUS", YEL)
    return c("SAFE      ", GRN)
def bar(pct, w=18):
    f = max(0, min(w, round(pct/100*w)))
    return c("#"*f, risk_col(pct/100)) + c("-"*(w-f), _D)

# ── HTTP helpers (talk only to the LOCAL WebSentinel backend) ────────────────
def _call(method, path, body=None, timeout=8):
    url = API + path
    data = json.dumps(body).encode() if body else None
    hdrs = {"Content-Type": "application/json"} if data else {}
    req = urlrequest.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urlrequest.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except error.HTTPError as e:  raise RuntimeError(f"HTTP {e.code} on {path}")
    except error.URLError as e:   raise RuntimeError(f"Cannot reach backend ({e.reason})")

def api_get(p, timeout=8):          return _call("GET", p, timeout=timeout)
def api_post(p, b=None, timeout=8): return _call("POST", p, b or {}, timeout=timeout)

def wait_backend(timeout=35):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try: return api_get("/health")
        except RuntimeError: time.sleep(2)
    sys.exit(c("\n  [FAIL] Backend not reachable.", RED))

def ensure_session() -> None:
    try:
        if api_get("/session/status").get("running"):
            return
    except RuntimeError:
        pass
    print(c("  Starting Playwright session...", _D), end="", flush=True)
    api_post("/session/start")
    deadline = time.time() + 40
    while time.time() < deadline:
        time.sleep(2)
        try:
            if api_get("/session/status").get("running"):
                print(c(" OK", GRN)); return
        except RuntimeError: pass
        print(".", end="", flush=True)
    print(c("\n  [FAIL] Session did not report running within 40s. "
            "If this recurs, check for orphaned ms-playwright chrome.exe "
            "processes holding the profile lock.", RED))
    sys.exit(1)

def navigate(url, attempts=3):
    # A real external host (through ngrok: DNS + fresh TLS handshake + tunnel
    # proxy hop) can legitimately take longer than the 8s default -- the
    # backend's own pw_session.navigate() already allows Playwright up to 30s
    # for page.goto(). Live-tested 2026-08-30: an 8s client-side timeout on
    # this specific call fired before a real (slow but successful) external
    # navigation finished, a false failure with nothing actually wrong.
    #
    # Retries because a freshly-registered ngrok tunnel can report itself as
    # up (via its local /api/tunnels) a few seconds before it is actually
    # stable for real external traffic -- live-tested 2026-08-30: the very
    # first navigation attempt against a brand-new tunnel failed with
    # net::ERR_CONNECTION_CLOSED, purely a startup-timing race, not a real
    # target problem (the tunnel worked normally seconds later).
    last_err = None
    for attempt in range(1, attempts + 1):
        try:
            return api_post("/session/navigate", {"url": url}, timeout=35)
        except RuntimeError as e:
            last_err = e
            if attempt < attempts:
                print(c(f"  [WARN] Navigate attempt {attempt}/{attempts} failed ({e}); "
                        f"retrying in 5s (likely tunnel still settling)...", YEL))
                time.sleep(5)
    print(c(f"  [FAIL] Navigate: {last_err}", RED))
    sys.exit(1)

def find_host(hosts, target):
    target = target.lower()
    return next((h for h in hosts if str(h.get("host", "")).lower() == target), None)

def divider(ch="-", col=CYN): print(c(ch*68, col))
def header(title):
    print(); divider("="); print(c(f"  {title}", _B, WHT)); divider("=")
def step(elapsed, msg): print(f"  {c(f'[+{int(elapsed):>3}s]', _D)}  {msg}")

def print_features(feats):
    if not feats: return
    rows = [
        ("iat_cv", "IAT CV (regularity) "), ("iat_mean_ms", "IAT Mean (ms)       "),
        ("user_active_ratio", "User Active Ratio   "), ("same_site_ratio", "Same-Site Ratio     "),
        ("avg_idle_time_ms", "Avg Idle Time (ms)  "), ("url_path_entropy", "URL Path Entropy    "),
        ("http_post_ratio", "POST Ratio          "), ("requests_per_hour", "Requests/Hour       "),
        ("payload_size_std", "Payload Size Std    "),
    ]
    print(c("\n  Feature Snapshot:", _B, WHT))
    print(c(f"  {'Feature':<22}  {'Value':>12}", _D))
    print(c(f"  {'-'*22}  {'-'*12}", _D))
    for key, label in rows:
        v = feats.get(key)
        if v is None: continue
        print(f"  {c(label, _D):<30}  {c(f'{float(v):.4f}', WHT):>12}")

def print_signals(sigs, detail_map=None):
    print(c("\n  Signal Breakdown:", _B, WHT))
    for key, label in [("ml", "XGBoost        "), ("heuristic", "Heuristic      "),
                        ("reputation", "Reputation (TI)")]:
        val = sigs.get(key)
        if val is not None:
            p = round(float(val)*100)
            print(f"    {c(label, _D)}  {score_s(val)}  [{bar(p)}]")
        else:
            print(f"    {c(label, _D)}  {c('n/a', _D)}")
    if detail_map:
        h_detail = detail_map.get("heuristic", "")
        if h_detail:
            print(c(f"\n  Heuristic rules fired: {h_detail}", YEL))
        r_detail = detail_map.get("reputation", "")
        if r_detail:
            print(c(f"  Reputation lookup:     {r_detail}", MAG))

# ── Pass/Fail validation ─────────────────────────────────────────────────────
_LOCAL_SKIP_MESSAGES = {"", "local host — skipped", "local host - skipped",
                         "pending beacon confirmation", "empty host"}

def validate(host_row, all_hosts, target_host, auto_block_enabled=False,
             auto_block_floor=0.75, is_blocked=False):
    results = []
    score   = float(host_row.get("score", 0))
    verdict = str(host_row.get("verdict", ""))
    feats   = host_row.get("features") or {}
    sigs    = host_row.get("signal_breakdown") or {}
    sig_detail = host_row.get("signal_detail") or {}

    def check(name, ok, detail=""):
        results.append((name, ok, detail))

    check("Verdict is BEACON",           verdict == "BEACON",  f"got {verdict}")
    check("Fusion score >= 0.52",        score >= 0.52,        f"got {score:.4f}")
    # NOT hard requirements, reported for transparency: this test navigates
    # directly to the beacon target (the only reliably-captured design, see
    # the module docstring), so user_active_ratio and same_site_ratio are
    # expected to be somewhat elevated / nonzero rather than a clean 0 --
    # neither blocks detection, since the ML term alone (once the rolling
    # window's http_post_ratio clears its cliff, see below) already carries
    # the fusion over BEACON_THRESHOLD.
    uar = feats.get("user_active_ratio")
    same_site = feats.get("same_site_ratio")
    if uar is not None:
        print(c(f"  [INFO]  user_active_ratio = {float(uar):.2f} "
                f"(direct navigation resets the target's own idle clock -- expected)", MAG))
    if same_site is not None:
        print(c(f"  [INFO]  same_site_ratio = {float(same_site):.2f} "
                f"(Rule 9 dampener {'applied' if float(same_site) > 0.80 else 'not applied'} -- expected, not a failure)", MAG))
    check("HTTP POST ratio >= 0.967 (rolling window has diluted the one-time page-load GET "
          "past the model's http_post_ratio cliff -- see the module docstring)",
          float(feats.get("http_post_ratio", 0)) >= 0.967, f"got {feats.get('http_post_ratio', '?')}")
    # Range check, not just a floor. RE-DERIVED 2026-09-03 against the
    # DEPLOYED model (c3_xgb_scoped_calibrated_20260903.pkl, isotonic-
    # calibrated, 18-feature). The previous band [0.85, 0.96) was calibrated
    # against models/c3_xgb_classifier.pkl -- the retired 6-feature model --
    # and this test could not pass it any more.
    #
    # Measured on a real 35-event run of tc03_mimicry_server.py, feeding the
    # captured events through the real feature_engine + the deployed engine:
    #     with the old Referer-sending beacon : ML 0.3305   (test unpassable)
    #     with the no-Referer beacon (fixed)  : ML 0.7890
    # A second probe holding features at slightly different measured values
    # gave 0.7357, so the realistic band is ~0.73-0.80.
    #
    # UPPER BOUND RAISED 0.92 -> 0.97 on 2026-09-08: those two probes were
    # both taken on an early (n~35), not-yet-fully-diluted window. Directly
    # probing the deployed model across 1,440 simulated FULLY MATURED windows
    # (n=50, uar=0 -- the state MATURATION_WAIT_S actually waits for) found
    # ML genuinely ranges 0.8709-0.9505 there, mean 0.9301 -- legitimately
    # above the old 0.92 ceiling most of the time, which would have failed
    # this check on a run that reached exactly the state the test is designed
    # to wait for. 0.97 keeps a real ceiling (still catches genuine
    # saturation near 1.0) without flagging the measured, correct range.
    ml_val = float(sigs.get("ml") or 0)
    check("ML score in [0.65, 0.97) -- strong but deliberately not maxed",
          0.65 <= ml_val < 0.97, f"got {ml_val}")
    # Ceiling, not just a floor: analyzer.py's Rule 9 same-site dampener
    # (x0.70) always applies to this design (direct navigation is the only
    # reliably-captured design -- see the module docstring), which caps the
    # achievable heuristic at ~0.60 (all compatible rules firing, including
    # Rule 2 once user_active_ratio decays below 0.05 -- see
    # MATURATION_WAIT_S above) no matter how the traffic is shaped. 0.50 is
    # comfortably inside that measured ceiling, allowing for run-to-run
    # timing variance without a false failure.
    # RELAXED 2026-09-03, with the arithmetic. The old >= 0.50 floor was set
    # when the ML term was contributing far less, so the heuristic had to do
    # most of the work. It is now strict enough to FAIL A RUN THAT CORRECTLY
    # REACHED BEACON: fusion is 0.55*ML + 0.45*heuristic (weights changed
    # 0.45/0.55 -> 0.55/0.45 on 2026-09-03), so at the measured ML of 0.789
    # the ML term alone contributes 0.434, and the heuristic only needs
    #     (0.52 - 0.434) / 0.45 = 0.191
    # to cross BEACON_THRESHOLD. A run landing at heuristic 0.35 would be a
    # correct BEACON (0.434 + 0.158 = 0.592) yet fail the old check.
    #
    # 0.20 is kept as a real floor rather than dropped, for two reasons: it is
    # just above the 0.191 the arithmetic requires, and it is comfortably above
    # risk_fusion.py's BOTH_SIGNAL_FLOOR (0.10), below which the both-signal
    # guard caps the score at 0.51 and BEACON becomes unreachable no matter
    # how confident ML is. So this still asserts the heuristic genuinely
    # contributed rather than the verdict resting on one signal.
    heur_val = float(sigs.get("heuristic") or 0)
    check("Heuristic score >= 0.20 -- genuinely contributes (above the both-signal "
          "floor, and enough to carry ML over BEACON_THRESHOLD)",
          heur_val >= 0.20, f"got {heur_val}")

    # The distinguishing check for this test case: proves the reputation
    # engine took the REAL-lookup code path rather than the private/local
    # skip path. A "clean" real result correctly leaves signal_breakdown's
    # reputation NUMBER as None (see reputation_engine.py's score_beacon() --
    # only a flagged result records a numeric score), so the detail STRING is
    # the only reliable evidence a real query ran; checking the numeric field
    # alone would incorrectly fail on your own clean VPS.
    rep_detail = str(sig_detail.get("reputation", ""))
    check("Real threat-intel lookup executed (not local-host-skipped)",
          rep_detail not in _LOCAL_SKIP_MESSAGES,
          f"signal_detail.reputation = {rep_detail!r}")
    check("Reputation lookup returned a parsed source result (Clean/FLAGGED)",
          rep_detail.startswith("Clean") or rep_detail.startswith("FLAGGED"),
          f"got {rep_detail!r} -- 'no TI data' means all configured sources returned nothing usable")

    # Excludes other ngrok-tunnel hosts specifically: live-tested 2026-08-30
    # (two runs back-to-back, same never-restarted Playwright session) --
    # C3's per-host state persists across runs within one session, so a
    # PRIOR run's own ngrok target (a different random subdomain each
    # launch, but still genuinely a beacon C3 was correct to flag) lingers
    # as BEACON until it decays, and would otherwise be misread as a fresh
    # cross-target false positive. A real false positive on an unrelated,
    # non-ngrok host (e.g. a normal site the browser also visited) still
    # fails this check.
    stale_own = [h for h in all_hosts
                 if h.get("host") != target_host
                 and "ngrok" in str(h.get("host", "")).lower()
                 and str(h.get("verdict", "")).upper() == "BEACON"]
    if stale_own:
        print(c(f"  [INFO]  Ignoring {len(stale_own)} other ngrok-tunnel host(s) still flagged "
                f"BEACON from a prior run in this session: "
                f"{', '.join(h.get('host', '') for h in stale_own)}", MAG))
    fp = [h for h in all_hosts
          if h.get("host") != target_host
          and "ngrok" not in str(h.get("host", "")).lower()
          and str(h.get("verdict", "")).upper() == "BEACON"]
    check("Zero false positives on other (non-tunnel) hosts", len(fp) == 0,
          f"{len(fp)} FP hosts: {', '.join(h.get('host', '') for h in fp)}" if fp else "clean")

    # Auto-block is opt-in (dashboard toggle) and orthogonal to detection
    # correctness, so this only checks it when it was actually on for this
    # run -- with it off, "did the host get blocked" isn't a meaningful
    # question and would fail every run regardless of detection quality.
    if auto_block_enabled:
        check(f"Auto-block fired (score >= {auto_block_floor:.2f} with auto-block enabled)",
              is_blocked, f"score={score:.4f}, blocked={is_blocked}")
    else:
        print(c(f"  [INFO]  auto_block_enabled=False -- skipping the auto-block-fired check "
                f"(toggle it on in the dashboard to exercise this)", MAG))

    return results

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="TC-03: Real-World Infrastructure C2 Beacon Test")
    ap.add_argument("--target-host", required=True,
                     help="Real public IP or hostname running tc03_mimicry_server.py")
    ap.add_argument("--target-port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--scheme", choices=["http", "https"], default="http")
    ap.add_argument("--interval-ms", type=int, default=DEFAULT_INTERVAL)
    ap.add_argument("--jitter-pct", type=int, default=DEFAULT_JITTER)
    args = ap.parse_args()
    target_host = args.target_host.strip().lower()
    t_demo_start = time.time()

    print()
    divider("=")
    print(c("  TEST CASE 03 — Real-World Infrastructure C2 Beacon + Live Reputation Check", _B, CYN))
    print(c("  Browser Execution Aware C2 Beacon Detector (C3)", _B, CYN))
    divider("=")
    print()
    print(c("  Scenario:", _B, WHT), "Jittered POST heartbeat to REAL, publicly-resolvable")
    print(c("            ", _D), "infrastructure — exercises the full pipeline including a genuine")
    print(c("            ", _D), "AbuseIPDB / VirusTotal lookup (impossible on 127.0.0.1).")
    print()
    print(f"  Target host      : {c(target_host, WHT)}")
    print(f"  Target timing    : {c(f'auto-block by ~{TARGET_AUTO_BLOCK_S}s (~3 min)', _B, MAG)}")
    print(f"  Outer budget     : {c(f'{TOTAL_BUDGET_S}s (worst-case ceiling, not the target)', _D, MAG)}")
    print()

    header("STEP 1 — Connect to WebSentinel Backend")
    print()
    wait_backend()
    c3 = api_get("/c3/status")
    # Read live, not hardcoded: analyzer.py's real auto-block floor, so this
    # line can never silently drift out of sync with the actual gate.
    auto_block_floor = float(c3.get("auto_block_score_floor", 0.75))
    print(f"  Expected verdict : {c('BEACON', _B, RED)} (score >= 0.52, auto-block at "
          f">= {round(auto_block_floor * 100)}%) via genuine ML + Heuristic agreement")
    print(c("  Backend       : Online", GRN))
    print(c(f"  C3 Model      : {'XGBoost' if c3.get('ml_model_loaded') else 'heuristic-only'} "
            f"({'loaded' if c3.get('ml_model_loaded') else 'heuristic-only'})",
            GRN if c3.get("ml_model_loaded") else YEL))
    ti_ok = bool(c3.get("ti_available"))
    print(c(f"  Threat Intel  : {'at least one key configured' if ti_ok else 'NO KEYS CONFIGURED'}",
            GRN if ti_ok else RED))
    if not ti_ok:
        print(c("\n  [WARN] No AbuseIPDB/VirusTotal key is configured in Settings.", YEL))
        print(c("         The reputation lookup this test exists to validate will return", YEL))
        print(c("         'no TI data' instead of a real source result.", YEL))
    print()
    ensure_session()

    header("STEP 2 — Deploy Real-World Beacon")
    target_url = f"{args.scheme}://{target_host}:{args.target_port}/"
    print(f"\n  Beacon target : {c(target_url, BLU)}")
    print(f"  Interval      : {args.interval_ms}ms ± {args.jitter_pct}% jitter (sleep + jitter, POST, fixed payload)")
    print()
    print(c("  Expected C3 detection path (both signals genuinely contribute):", _D))
    print(c("    1. Direct navigation is the only reliably-captured design in this backend --", _D))
    print(c("       cross-origin fetch capture was live-tested and found unsupported here", _D))
    print(c("    2. The one-time page-load GET dilutes below the model's http_post_ratio cliff", _D))
    print(c("       once the rolling window reaches ~30 total requests (see module docstring)", _D))
    print(c("    3. Regular timing + fixed endpoint fires several heuristic rules (Rule 9's", _D))
    print(c("       same-site dampener also applies here, but is not fatal -- see the docstring)", _D))
    print(c("    4. XGBoost scores POST + fixed-payload + zero-entropy-endpoint strongly (~0.85-0.96)", _D))
    print(c("    5. Fusion (45% ML + 55% Heuristic): both terms clear BEACON_THRESHOLD", _D))
    print(c("    6. Once BEACON confirms: reputation_engine.score_beacon() runs for REAL against", _D))
    print(c("       this target's real IP -- AbuseIPDB / VirusTotal are actually queried, and the", _D))
    print(c("       result is shown as evidence on the alert (it does not change the score)", _D))
    print()
    navigate(target_url)
    print(c("  Navigated to the real target; its own beacon loop is now running.", GRN))

    header("STEP 3 — Monitor C3 Detection (live)")
    print(f"\n  Need {MIN_EVENTS}+ requests for BEACON eligibility, "
          f"~{DILUTION_EVENTS}+ for the ML term to clear its cliff (see docstring)")
    print(c(f"  Polling /c3/hosts every {POLL_EVERY}s...\n", _D))
    print(c(f"  {'Time':>7}  {'Host':<24}  {'Reqs':>5}  {'Score':>6}  "
            f"{'Verdict':<12}  {'ML':>7}  {'Heuristic':>9}", _D))
    print(c(f"  {'---':>7}  {'-'*24}  {'---':>5}  {'---':>6}  "
            f"{'-'*12}  {'---':>7}  {'---':>9}", _D))

    auto_block_was_on = bool(c3.get("auto_block_enabled"))
    t0 = time.time(); last_poll = -POLL_EVERY; detected = False
    final_host_row = None; final_all_hosts = []
    first_beacon_t = None

    while True:
        now = time.time()
        if first_beacon_t is None:
            # Still detecting: bounded by DETECT_MAX_WAIT alone.
            if now - t0 >= DETECT_MAX_WAIT:
                break
        else:
            # Maturing: bounded by its OWN separate budget, not
            # DETECT_MAX_WAIT -- live-tested 2026-08-30: sharing one ceiling
            # meant a slightly-late detection (e.g. 115s instead of ~110s)
            # left too little of DETECT_MAX_WAIT remaining for maturation,
            # cutting it off mid-recovery from a transient ML dip right at
            # the deadline instead of letting it actually stabilize. See
            # MATURATION_WAIT_S's own comment for why that time is needed.
            if now - first_beacon_t >= MATURATION_WAIT_S:
                break
        if now - last_poll >= POLL_EVERY:
            last_poll = now
            el = now - t0
            budget_left = TOTAL_BUDGET_S - (now - t_demo_start)
            try:
                hosts = api_get("/c3/hosts")
                final_all_hosts = hosts
                hr = find_host(hosts, target_host)
                budget_s = c(f"[budget {budget_left:>4.0f}s left]", MAG if budget_left > 30 else RED)
                if hr is None:
                    step(el, c(f"{target_host:<24}  (no data yet)", _D) + "  " + budget_s)
                else:
                    sc = float(hr.get("score", 0)); vd = str(hr.get("verdict", "SAFE"))
                    rq = int(hr.get("request_count", 0))
                    sg = hr.get("signal_breakdown") or {}
                    maturing = c(" (maturing)", MAG) if first_beacon_t is not None else ""
                    step(el, f"{c(target_host, BLU):<32}  "
                             f"reqs={c(str(rq), WHT):<5}  {score_s(sc):>12}  "
                             f"{verdict_s(vd):<20}  "
                             f"M={score_s(sg.get('ml'))}  H={score_s(sg.get('heuristic'))}  {budget_s}{maturing}")
                    if vd.upper() == "BEACON":
                        final_host_row = hr
                        detected = True
                        if first_beacon_t is None:
                            first_beacon_t = now
                        # Exit the maturation phase the moment its actual goal
                        # is reached, not after the full MATURATION_WAIT_S
                        # ceiling regardless -- every extra second here is
                        # also extra exposure to a real, separate risk (see
                        # that constant's comment: ngrok connection-cycling
                        # noise that transiently pushes payload_size_std over
                        # the model's cliff). Two different goals depending
                        # on whether auto-block is actually on:
                        #   - auto-block ON: wait for the real thing (the
                        #     host actually blocked), not a proxy for it --
                        #     live-tested 2026-08-30 across several runs
                        #     found ML and heuristic don't reliably peak at
                        #     the same instant under real network noise, so
                        #     gating on "both signals in range simultaneously"
                        #     sometimes never triggered even after the full
                        #     budget, while the ACTUAL fused score crossing
                        #     the floor (and C3 blocking on it) is the one
                        #     unambiguous signal that matters.
                        #   - auto-block OFF: nothing to wait FOR (no block
                        #     will ever fire), so fall back to the heuristic-
                        #     matured proxy so the reported snapshot still
                        #     reflects Rule 2 having kicked in.
                        elif auto_block_was_on:
                            if bool(hr.get("blocked")):
                                break
                        elif float(sg.get("heuristic") or 0) >= 0.50 and float(sg.get("ml") or 0) >= 0.80:
                            break
            except RuntimeError as e:
                step(el, c(f"Poll error: {e}", YEL))
        time.sleep(0.5)

    if not detected and final_host_row is None:
        try:
            hosts = api_get("/c3/hosts")
            final_all_hosts = hosts
            final_host_row = find_host(hosts, target_host)
        except RuntimeError: pass

    # The /c3/hosts summary list (used for live polling above) does not
    # include signal_detail at all. Once BEACON is confirmed, _handle_
    # beacon() runs a real, async threat-intel lookup and enriches
    # signal_detail.reputation -- but for a CLEAN (non-flagged) result,
    # analyzer.py's very next 10s cycle regenerates signal_detail from
    # cached_score() (which, by design, stays None for a clean result --
    # only a flagged result feeds a numeric score back into fusion) and
    # overwrites the live display back to "pending beacon confirmation",
    # even though the lookup genuinely completed. Live-tested 2026-08-30:
    # confirmed via /c3/alerts, whose record is written once at
    # confirmation time and never overwritten by later cycles -- the
    # authoritative source for what the reputation lookup actually found.
    #
    # The lookup itself is a real outbound network call (AbuseIPDB / OTX /
    # VirusTotal) kicked off the instant BEACON confirms -- it is NOT
    # always finished by the time we get here. Live-tested 2026-08-30 (via
    # test_c3_real_world_beacon.bat): a single immediate /c3/alerts check
    # caught the lookup mid-flight and read back its still-pending
    # placeholder, failing both reputation checks even though the lookup
    # itself completed correctly a couple seconds later. Poll briefly
    # instead of checking once.
    if detected and final_host_row:
        # Merge in signal_detail only -- do NOT replace the whole row.
        # host_detail() recomputes "features" LIVE from the current window,
        # but "score"/"signal_breakdown" stay the STORED values from the
        # analyzer's last completed ~10s cycle (see host_detail()'s own
        # source): those two can legitimately be out of sync with each
        # other by up to one cycle. Live-tested 2026-08-30: wholesale
        # replacing final_host_row here showed a Feature Snapshot with a
        # freshly-elevated payload_size_std alongside a score/heuristic
        # breakdown that hadn't been recomputed from it yet -- a real,
        # confusing display inconsistency, not a detection problem.
        # final_host_row from the polling loop already has score, features,
        # and signal_breakdown all from the SAME analyzer cycle.
        try:
            detail = api_get(f"/c3/hosts/{target_host}")
            if detail.get("signal_detail"):
                final_host_row["signal_detail"] = detail["signal_detail"]
        except RuntimeError:
            pass
        # /c3/alerts holds a ONE-TIME snapshot written the instant BEACON
        # first confirmed -- it does not get updated as the score matures
        # (e.g. once Rule 2 starts contributing after MATURATION_WAIT_S).
        # Only take the reputation FIELD from it (the one piece the live
        # analyzer cycle is known to overwrite back to "pending" for a clean
        # result -- see the big comment above), not the whole
        # signal_detail/signal_breakdown: live-tested 2026-08-30, taking the
        # whole dict here clobbered the already-matured heuristic breakdown
        # back to its pre-maturation value.
        rep_deadline = time.time() + 15
        while time.time() < rep_deadline:
            try:
                alerts = api_get("/c3/alerts?limit=10")
                match = next((a for a in alerts if str(a.get("host", "")).lower() == target_host), None)
                if match and match.get("signal_detail"):
                    rep_value = match["signal_detail"].get("reputation", "")
                    final_host_row.setdefault("signal_detail", {})["reputation"] = rep_value
                    if str(rep_value) not in _LOCAL_SKIP_MESSAGES:
                        break
            except RuntimeError:
                pass
            time.sleep(2)

    # Re-fetch the summary list once more so "blocked" (only present on the
    # /c3/hosts summary row, not the /c3/hosts/{host} detail merged above)
    # reflects the state right after the maturation phase, not a stale
    # snapshot from mid-poll.
    is_blocked = False
    try:
        final_all_hosts = api_get("/c3/hosts")
        blocked_row = find_host(final_all_hosts, target_host)
        is_blocked = bool(blocked_row and blocked_row.get("blocked"))
    except RuntimeError:
        pass

    header("STEP 4 — Detection Result")
    print()
    total_elapsed = time.time() - t_demo_start
    budget_col = GRN if total_elapsed <= TOTAL_BUDGET_S else RED
    print(f"  Total demo time so far: {c(f'{total_elapsed:.0f}s', _B, budget_col)} "
          f"(budget: {TOTAL_BUDGET_S}s)")
    if detected and final_host_row:
        divider("!", RED)
        print(c("  !! BEACON DETECTED — real-world infrastructure pattern confirmed !!", _B, RED))
        divider("!", RED)
        sc = float(final_host_row.get("score", 0))
        print(f"\n  Host    : {c(target_host, _B, RED)}")
        print(f"  Score   : {c(str(round(sc*100))+'%', _B, RED)}  [{bar(round(sc*100))}]")
        print(f"  Verdict : {c('BEACON', _B, RED)}")
        if is_blocked:
            print(c("  Blocked : YES — auto-block fired, all traffic from this host is now aborted", _B, RED))
        elif auto_block_floor and sc >= auto_block_floor:
            print(c(f"  Blocked : no (auto-block is OFF — toggle it on in the dashboard to see this "
                    f"host actually get blocked; score {sc:.4f} already clears the "
                    f"{round(auto_block_floor*100)}% floor)", YEL))
        sigs = final_host_row.get("signal_breakdown") or {}
        sig_detail = final_host_row.get("signal_detail") or {}
        print_signals(sigs, sig_detail)
        print_features(final_host_row.get("features") or {})
    elif final_host_row:
        sc = float(final_host_row.get("score", 0))
        vd = str(final_host_row.get("verdict", "SAFE"))
        print(c(f"  Beacon host reached {vd} (score={sc:.4f}) but not BEACON within the wait window.", YEL))
        sigs = final_host_row.get("signal_breakdown") or {}
        sig_detail = final_host_row.get("signal_detail") or {}
        print_signals(sigs, sig_detail)
        print_features(final_host_row.get("features") or {})
    else:
        print(c("  No data captured for the target host. Is the mimicry server reachable", RED))
        print(c("  from this machine's browser (check firewall / port / scheme)?", RED))
        # Historically the most common real cause when tunnelling, and it
        # failed silently: ngrok's free tier serves an HTML "You are about
        # to visit..." interstitial instead of the tunnelled page on the
        # first browser-looking top-level navigation, so the beacon
        # <script> never executes and C3 correctly sees zero traffic.
        # FIXED 2026-09-08: core/playwright_session.py's navigate() now sets
        # `ngrok-skip-browser-warning` on the navigation itself (previously
        # only the check-in fetch() calls carried it) whenever the target
        # host contains "ngrok", so this should no longer be the cause on a
        # backend that includes that fix. Left here as a diagnostic in case
        # it still is -- e.g. an older/un-updated backend, or ngrok changing
        # its interstitial behaviour again.
        if "ngrok" in str(target_host).lower():
            print()
            print(c("  POSSIBLE CAUSE - ngrok free-tier browser interstitial:", _B, YEL))
            print(c("    The tunnel host is an ngrok domain. On the free tier ngrok can replace", YEL))
            print(c("    the first browser page-load with its own warning page, so the beacon", YEL))
            print(c("    script never runs and there is nothing for C3 to detect. The backend's", YEL))
            print(c("    navigate() should already send the bypass header automatically -- if", YEL))
            print(c("    you still see this, try ONE of:", YEL))
            print(c("      - open the tunnel URL once in the WebSentinel browser and click", YEL))
            print(c("        \"Visit Site\", then re-run this test (the bypass cookie persists", YEL))
            print(c("        for that browser profile); or", YEL))
            print(c("      - use a reserved/paid ngrok domain, which has no interstitial; or", YEL))
            print(c("      - run the mimicry server on a host you own and pass --target-host", YEL))
            print(c("        directly, which is the setup TEST_CASE_03's doc describes.", YEL))

    header("STEP 5 — Pass/Fail Validation")
    print()
    if final_host_row:
        # Re-read live rather than reuse STEP 1's snapshot: the presenter
        # may toggle auto-block on/off from the dashboard mid-run.
        try:
            auto_block_now = bool(api_get("/c3/status").get("auto_block_enabled"))
        except RuntimeError:
            auto_block_now = False
        results = validate(final_host_row, final_all_hosts, target_host,
                            auto_block_enabled=auto_block_now,
                            auto_block_floor=auto_block_floor, is_blocked=is_blocked)
        all_pass = True
        for name, ok, detail in results:
            icon = c("PASS", _B, GRN) if ok else c("FAIL", _B, RED)
            d = f"  ({detail})" if detail else ""
            print(f"  [{icon}]  {name}{c(d, _D)}")
            if not ok: all_pass = False
        print()
        divider("=")
        if all_pass:
            print(c("  TC-03 RESULT:  ALL CHECKS PASSED  ✓", _B, GRN))
        else:
            print(c("  TC-03 RESULT:  SOME CHECKS FAILED  ✗", _B, RED))
        divider("=")
    else:
        print(c("  TC-03 RESULT:  FAIL — no beacon data captured", _B, RED))
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(c("\n\n  Test stopped by user (Ctrl+C).", YEL))
        sys.exit(0)
