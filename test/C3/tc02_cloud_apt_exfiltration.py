"""
TC-02 — Cloud APT C2 Exfiltration Beacon (POST, Active User)
=============================================================
Simulates a 60-second POST exfiltration beacon from a background tab
while the user is ACTIVELY browsing in other tabs.  Validates that C3's
per-tab context enrichment correctly discriminates automated beacon
traffic from user-driven traffic (F10 near 0 for beacon, near 1 for
normal hosts) even when global user activity is high.

Key difference from TC-01:
  - POST method (exfiltration simulation)
  - Longer interval (60s realistic / 8s fast-demo)
  - User actively browsing during beacon phase
  - Validates F10 discrimination between beacon and normal hosts

Run via:  run_testcase_02.bat   (from project root)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from urllib import error, request as urlrequest

# ── Config ────────────────────────────────────────────────────────────────────
API              = "http://127.0.0.1:8001"
BEACON_HOST      = "127.0.0.1"
DEFAULT_INTERVAL = 8000          # ms  (fast demo; use --interval 60000 for realistic)
POLL_EVERY       = 10
MIN_EVENTS       = 10
MAX_WAIT         = 720           # 12 minutes hard stop

BROWSE_SITES = [
    ("https://en.wikipedia.org/wiki/Main_Page", "Wikipedia", 12),
    ("https://www.google.com/search?q=cybersecurity+research", "Google Search", 10),
    ("https://en.wikipedia.org/wiki/Command_and_control", "Wikipedia C2", 10),
]

# ── ANSI helpers ──────────────────────────────────────────────────────────────
os.system("")
_R = "\033[0m"; _B = "\033[1m"; _D = "\033[2m"
RED = "\033[91m"; YEL = "\033[93m"; GRN = "\033[92m"
CYN = "\033[96m"; BLU = "\033[94m"; WHT = "\033[97m"

def c(t, *codes): return "".join(codes) + str(t) + _R
def risk_col(s): return RED if s >= 0.6 else YEL if s >= 0.3 else GRN
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

# ── HTTP helpers ──────────────────────────────────────────────────────────────
def _call(method, path, body=None):
    url = API + path
    data = json.dumps(body).encode() if body else None
    hdrs = {"Content-Type": "application/json"} if data else {}
    req = urlrequest.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urlrequest.urlopen(req, timeout=8) as r:
            return json.loads(r.read().decode())
    except error.HTTPError as e:  raise RuntimeError(f"HTTP {e.code} on {path}")
    except error.URLError as e:   raise RuntimeError(f"Cannot reach backend ({e.reason})")

def api_get(p):          return _call("GET", p)
def api_post(p, b=None): return _call("POST", p, b or {})

# ── Setup helpers ─────────────────────────────────────────────────────────────
def wait_backend(timeout=35):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try: return api_get("/health")
        except RuntimeError: time.sleep(2)
    sys.exit(c("\n  [FAIL] Backend not reachable.", RED))

def ensure_session():
    try:
        if api_get("/session/status").get("running"): return
    except RuntimeError: pass
    print(c("  Starting Playwright session...", _D), end="", flush=True)
    api_post("/session/start")
    deadline = time.time() + 30
    while time.time() < deadline:
        time.sleep(2)
        try:
            if api_get("/session/status").get("running"):
                print(c(" OK", GRN)); return
        except RuntimeError: pass
        print(".", end="", flush=True)
    print(c("\n  [WARN] Session may not be ready.", YEL))

def navigate(url):
    try: api_post("/session/navigate", {"url": url})
    except RuntimeError as e: print(c(f"  [WARN] Navigate: {e}", YEL))

def find_host(hosts, target):
    return next((h for h in hosts if str(h.get("host","")) == target), None)

def divider(ch="-", col=CYN): print(c(ch*68, col))
def header(title):
    print(); divider("="); print(c(f"  {title}", _B, WHT)); divider("=")
def step(elapsed, msg): print(f"  {c(f'[+{int(elapsed):>3}s]', _D)}  {msg}")

# ── Feature & signal display ─────────────────────────────────────────────────
def print_features(feats):
    if not feats: return
    rows = [
        ("iat_cv",               "IAT CV (regularity) "),
        ("iat_mean_ms",          "IAT Mean (ms)       "),
        ("user_active_ratio",    "User Active Ratio   "),
        ("background_tab_ratio", "BG Tab Ratio        "),
        ("avg_idle_time_ms",     "Avg Idle Time (ms)  "),
        ("url_path_entropy",     "URL Path Entropy    "),
        ("http_post_ratio",      "POST Ratio          "),
        ("requests_per_hour",    "Requests/Hour       "),
    ]
    print(c("\n  Feature Snapshot:", _B, WHT))
    print(c(f"  {'Feature':<22}  {'Value':>12}  Risk", _D))
    print(c(f"  {'-'*22}  {'-'*12}  {'-'*20}", _D))
    for key, label in rows:
        v = feats.get(key)
        if v is None: continue
        v = float(v)
        if key == "iat_cv":
            risk = 100 if v < 0.05 else (60 if v < 0.10 else 10)
        elif key == "user_active_ratio":
            risk = round((1.0 - min(1.0, v)) * 100)
        elif key in ("background_tab_ratio", "http_post_ratio"):
            risk = round(min(1.0, v) * 100)
        else:
            risk = 0
        b = bar(risk) if risk > 0 else c("-"*18, _D)
        print(f"  {c(label, _D):<30}  {c(f'{v:.4f}', WHT):>12}  {b}")

def print_signals(sigs, detail_map=None):
    print(c("\n  Signal Breakdown:", _B, WHT))
    for key, label in [("anomaly","Anomaly (IF)   "),("browser_anomaly","Browser (RF)   "),
                        ("heuristic","Heuristic      "),("reputation","Reputation (TI)")]:
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

# ── F10 Discrimination display ────────────────────────────────────────────────
def print_f10_comparison(all_hosts, beacon_host):
    """Show F10 (User Active Ratio) side-by-side for beacon vs normal hosts."""
    print(c("\n  F10 User Active Ratio — Per-Tab Discrimination:", _B, WHT))
    print(c(f"  {'Host':<30}  {'F10':>8}  {'F11':>8}  {'Verdict':<12}  Bar", _D))
    print(c(f"  {'-'*30}  {'-'*8}  {'-'*8}  {'-'*12}  {'-'*20}", _D))

    # Beacon host first
    bh = find_host(all_hosts, beacon_host)
    if bh:
        feats = bh.get("features") or {}
        f10 = float(feats.get("user_active_ratio", 0))
        f11 = float(feats.get("background_tab_ratio", 0))
        vd  = str(bh.get("verdict", "SAFE"))
        risk = round((1.0 - f10) * 100)
        print(f"  {c(beacon_host + ' (BEACON)', RED):<38}  "
              f"{c(f'{f10:.4f}', RED):>8}  {c(f'{f11:.4f}', RED):>8}  "
              f"{verdict_s(vd):<12}  {bar(risk)}")

    # Normal hosts
    for h in all_hosts:
        host = str(h.get("host", ""))
        if host == beacon_host: continue
        feats = h.get("features") or {}
        if not feats: continue
        f10 = float(feats.get("user_active_ratio", 0))
        f11 = float(feats.get("background_tab_ratio", 0))
        vd  = str(h.get("verdict", "SAFE"))
        risk = round((1.0 - f10) * 100)
        hn  = host[:28]
        print(f"  {c(hn, GRN):<38}  "
              f"{c(f'{f10:.4f}', GRN):>8}  {c(f'{f11:.4f}', GRN):>8}  "
              f"{verdict_s(vd):<12}  {bar(risk)}")
        if len([1 for _ in all_hosts]) > 6:
            break  # limit display

    print()
    print(c("  Research insight: F10 ≈ 0.0 for beacon (automated, no user interaction)", _D))
    print(c("                   F10 > 0.5 for normal (user-driven clicks/keystrokes)", _D))
    print(c("  This discrimination is IMPOSSIBLE for network-layer IDS/IPS.", _B, YEL))

# ── Pass/Fail validation ─────────────────────────────────────────────────────
def validate(host_row, all_hosts):
    results = []
    score   = float(host_row.get("score", 0))
    verdict = str(host_row.get("verdict", ""))
    feats   = host_row.get("features") or {}
    sigs    = host_row.get("signal_breakdown") or {}

    def check(name, ok, detail=""):
        results.append((name, ok, detail))

    check("Verdict is BEACON",              verdict == "BEACON",     f"got {verdict}")
    check("Fusion score >= 0.60",           score >= 0.60,           f"got {score:.4f}")
    check("F10 User Active Ratio < 0.10 (beacon)",
          float(feats.get("user_active_ratio",1)) < 0.10,
          f"got {feats.get('user_active_ratio','?')}")
    check("F11 BG Tab Ratio > 0.80",
          float(feats.get("background_tab_ratio",0)) > 0.80,
          f"got {feats.get('background_tab_ratio','?')}")
    check("F08 POST Ratio > 0.0 (exfiltration method)",
          float(feats.get("http_post_ratio",0)) > 0.0,
          f"got {feats.get('http_post_ratio','?')}")
    check("Heuristic score >= 0.30",
          (sigs.get("heuristic") or 0) >= 0.30,
          f"got {sigs.get('heuristic','?')}")

    # F10 discrimination: beacon F10 should be much lower than any normal host
    beacon_f10 = float(feats.get("user_active_ratio", 0))
    normal_hosts = [h for h in all_hosts
                    if h.get("host") != BEACON_HOST and (h.get("features") or {})]
    if normal_hosts:
        best_normal_f10 = max(
            float((h.get("features") or {}).get("user_active_ratio", 0))
            for h in normal_hosts
        )
        check("F10 discrimination (beacon < normal)",
              beacon_f10 < best_normal_f10,
              f"beacon={beacon_f10:.3f}, normal={best_normal_f10:.3f}")

    # False-positive check
    fp = [h for h in all_hosts
          if h.get("host") != BEACON_HOST
          and str(h.get("verdict","")).upper() == "BEACON"]
    check("Zero false positives on normal hosts", len(fp) == 0,
          f"{len(fp)} FP hosts" if fp else "clean")

    return results

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="TC-02: Cloud APT Exfiltration Beacon Test")
    ap.add_argument("--interval", type=int, default=DEFAULT_INTERVAL,
                    help=f"Beacon pulse interval in ms (default {DEFAULT_INTERVAL})")
    args = ap.parse_args()
    interval = max(2000, min(300000, args.interval))

    # ── Banner ────────────────────────────────────────────────────
    print()
    divider("=")
    print(c("  TEST CASE 02 — Cloud APT C2 Exfiltration Beacon", _B, CYN))
    print(c("  Browser Execution Aware C2 Beacon Detector (C3)", _B, CYN))
    divider("=")
    print()
    print(c("  Scenario:", _B, WHT), "APT group uses a malicious extension that sends POST")
    print(c("            ", _D), "exfiltration beacons to a cloud endpoint while the")
    print(c("            ", _D), "user is ACTIVELY browsing in other tabs.")
    print()
    print(f"  Beacon interval  : {c(str(interval)+'ms', WHT)}")
    print(f"  Beacon method    : {c('POST', WHT)} (exfiltration)")
    print(f"  User activity    : {c('ACTIVE browsing during test', _B, YEL)}")
    print(f"  Key validation   : {c('F10 per-tab discrimination', _B, YEL)}")
    print()

    # ── Step 1: Connect ───────────────────────────────────────────
    header("STEP 1 — Connect to WebSentinel Backend")
    print()
    wait_backend()
    c3 = api_get("/c3/status")
    print(c("  Backend       : Online", GRN))
    print(c(f"  C3 Model      : {c3.get('model_type','?')} "
            f"({'loaded' if c3.get('model_loaded') else 'heuristic-only'})",
            GRN if c3.get("model_loaded") else YEL))
    print(c(f"  Analyzer      : {'running' if c3.get('analyzer_running') else 'stopped'}",
            GRN if c3.get("analyzer_running") else YEL))
    print()
    ensure_session()

    # ── Step 2: Deploy beacon FIRST ───────────────────────────────
    header("STEP 2 — Deploy Simulated APT Exfiltration Beacon")
    beacon_url = (f"http://{BEACON_HOST}:8001"
                  f"/c3/test/beacon-page?interval={interval}&method=POST")
    print(f"\n  Beacon URL    : {c(beacon_url, BLU)}")
    print(c("  Method        : POST with JSON body (exfiltration simulation)", _D))
    print()
    print(c("  Expected C3 detection path:", _D))
    print(c("    1. CDP captures every POST to /c3/test/beacon-target", _D))
    print(c("    2. Context tagger: background tab, user idle IN THIS TAB", _D))
    print(c("    3. Key: user clicks in OTHER tabs do NOT reset beacon tab idle", _D))
    print(c("    4. Heuristic rules: regular timing + background + same endpoint", _D))
    print(c("    5. Fusion score >= 0.60 → BEACON", _D))
    print()
    navigate(beacon_url)
    time.sleep(3)

    # ── Step 3: Active browsing (simultaneously with beacon) ──────
    header("STEP 3 — Active Browsing (user is working normally)")
    print(c("\n  The beacon fires in the background while we browse these sites:", _D))
    for url, name, dur in BROWSE_SITES:
        print(f"    • {c(name, BLU)} ({dur}s)")
    print()
    print(c("  This proves F10 discrimination: user activity in foreground tabs", _D))
    print(c("  does NOT affect the beacon tab's user_active_ratio.\n", _D))

    browse_start = time.time()
    for url, name, dur in BROWSE_SITES:
        print(f"  Browsing {c(name, BLU)} for {dur}s...")
        navigate(url)
        time.sleep(dur)
        # Show beacon accumulation progress
        try:
            hosts = api_get("/c3/hosts")
            hr = find_host(hosts, BEACON_HOST)
            if hr:
                rq = int(hr.get("request_count", 0))
                sc = float(hr.get("score", 0))
                print(c(f"    Beacon: {rq} requests captured, score={sc:.3f}", _D))
        except RuntimeError: pass

    print(c(f"\n  Active browsing complete ({int(time.time()-browse_start)}s).", GRN))

    # ── Step 4: Monitor detection ─────────────────────────────────
    header("STEP 4 — Monitor C3 Detection (live)")
    eta = max(0, (MIN_EVENTS * interval) // 1000 - int(time.time() - browse_start) + 30)
    print(f"\n  Need {MIN_EVENTS}+ requests for BEACON — ETA ~{eta}s remaining")
    print(c(f"  Polling /c3/hosts every {POLL_EVERY}s...\n", _D))
    print(c(f"  {'Time':>7}  {'Host':<22}  {'Reqs':>5}  {'Score':>6}  "
            f"{'Verdict':<12}  {'Anomaly':>7}  {'Heuristic':>9}", _D))
    print(c(f"  {'---':>7}  {'-'*22}  {'---':>5}  {'---':>6}  "
            f"{'-'*12}  {'---':>7}  {'---':>9}", _D))

    t0 = time.time(); last_poll = -POLL_EVERY; detected = False
    final_host_row = None; final_all_hosts = []

    while time.time() - t0 < MAX_WAIT:
        now = time.time()
        if now - last_poll >= POLL_EVERY:
            last_poll = now
            el = now - t0
            try:
                hosts = api_get("/c3/hosts")
                final_all_hosts = hosts
                hr = find_host(hosts, BEACON_HOST)
                if hr is None:
                    step(el, c(f"{BEACON_HOST:<22}  (no data yet)", _D))
                else:
                    sc = float(hr.get("score",0)); vd = str(hr.get("verdict","SAFE"))
                    rq = int(hr.get("request_count",0))
                    sg = hr.get("signal_breakdown") or {}
                    step(el, f"{c(BEACON_HOST,BLU):<30}  "
                             f"reqs={c(str(rq),WHT):<5}  {score_s(sc):>12}  "
                             f"{verdict_s(vd):<20}  "
                             f"A={score_s(sg.get('anomaly'))}  "
                             f"H={score_s(sg.get('heuristic'))}")
                    if rq < MIN_EVENTS:
                        rem = MIN_EVENTS - rq
                        print(c(f"           Need {rem} more requests...", _D))
                    if vd.upper() == "BEACON":
                        final_host_row = hr
                        detected = True
                        break
            except RuntimeError as e:
                step(el, c(f"Poll error: {e}", YEL))
        time.sleep(1)

    # Grab final state if not detected
    if not detected:
        try:
            hosts = api_get("/c3/hosts")
            final_all_hosts = hosts
            final_host_row = find_host(hosts, BEACON_HOST)
        except RuntimeError: pass

    # ── Step 5: Detection result ──────────────────────────────────
    header("STEP 5 — Detection Result")
    print()

    if detected and final_host_row:
        divider("!", RED)
        print(c("  !! BEACON DETECTED — APT exfiltration pattern confirmed !!", _B, RED))
        divider("!", RED)
        sc = float(final_host_row.get("score",0))
        print(f"\n  Host    : {c(BEACON_HOST, _B, RED)}")
        print(f"  Score   : {c(str(round(sc*100))+'%', _B, RED)}  [{bar(round(sc*100))}]")
        print(f"  Verdict : {c('BEACON', _B, RED)}")
        sigs = final_host_row.get("signal_breakdown") or {}
        sig_detail = final_host_row.get("signal_detail") or {}
        print_signals(sigs, sig_detail)
        print_features(final_host_row.get("features") or {})
    elif final_host_row:
        sc = float(final_host_row.get("score",0))
        vd = str(final_host_row.get("verdict","SAFE"))
        print(c(f"  Beacon host reached {vd} (score={sc:.4f}) but not BEACON.", YEL))
        sigs = final_host_row.get("signal_breakdown") or {}
        sig_detail = final_host_row.get("signal_detail") or {}
        print_signals(sigs, sig_detail)
        print_features(final_host_row.get("features") or {})
    else:
        print(c("  No data captured for beacon host.", RED))

    # ── Step 6: F10 Discrimination ────────────────────────────────
    header("STEP 6 — F10 Per-Tab Discrimination (Research Evidence)")
    if final_all_hosts:
        print_f10_comparison(final_all_hosts, BEACON_HOST)
    else:
        print(c("  No host data available for comparison.", YEL))

    # ── Step 7: Pass/Fail ─────────────────────────────────────────
    header("STEP 7 — Pass/Fail Validation")
    print()
    if final_host_row:
        results = validate(final_host_row, final_all_hosts)
        all_pass = True
        for name, ok, detail in results:
            icon = c("PASS", _B, GRN) if ok else c("FAIL", _B, RED)
            d = f"  ({detail})" if detail else ""
            print(f"  [{icon}]  {name}{c(d, _D)}")
            if not ok: all_pass = False
        print()
        divider("=")
        if all_pass:
            print(c("  TC-02 RESULT:  ALL CHECKS PASSED  ✓", _B, GRN))
        else:
            print(c("  TC-02 RESULT:  SOME CHECKS FAILED  ✗", _B, RED))
        divider("=")
    else:
        print(c("  TC-02 RESULT:  FAIL — no beacon data captured", _B, RED))
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(c("\n\n  Test stopped by user (Ctrl+C).", YEL))
        sys.exit(0)
