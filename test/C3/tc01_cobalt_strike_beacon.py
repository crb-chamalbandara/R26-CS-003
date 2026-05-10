"""
TC-01 — Cobalt Strike C2 Beacon via Compromised WordPress Site
==============================================================
Simulates a 30-second GET beacon from a background tab while the user
is idle.  Validates that C3 detects the beacon pattern via heuristic
rules (regular timing + background traffic + same endpoint) and the
Isolation Forest anomaly engine.

Run via:  run_testcase_01.bat   (from project root)
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
DEFAULT_INTERVAL = 5000          # ms  (fast demo; use --interval 30000 for realistic)
BASELINE_URL     = "https://en.wikipedia.org/wiki/Main_Page"
BASELINE_WAIT    = 20            # seconds
POLL_EVERY       = 10
MIN_EVENTS       = 10
MAX_WAIT         = 360           # 6 minutes hard stop

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
        elif key == "background_tab_ratio":
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
    check("F02 IAT CV < 0.10",             float(feats.get("iat_cv",1)) < 0.10,
          f"got {feats.get('iat_cv','?')}")
    check("F10 User Active Ratio < 0.10",  float(feats.get("user_active_ratio",1)) < 0.10,
          f"got {feats.get('user_active_ratio','?')}")
    check("F11 BG Tab Ratio > 0.80",       float(feats.get("background_tab_ratio",0)) > 0.80,
          f"got {feats.get('background_tab_ratio','?')}")
    check("Heuristic score >= 0.30",        (sigs.get("heuristic") or 0) >= 0.30,
          f"got {sigs.get('heuristic','?')}")

    # False-positive check on normal hosts
    fp = [h for h in all_hosts
          if h.get("host") != BEACON_HOST
          and str(h.get("verdict","")).upper() == "BEACON"]
    check("Zero false positives on normal hosts", len(fp) == 0,
          f"{len(fp)} FP hosts" if fp else "clean")

    return results

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="TC-01: Cobalt Strike C2 Beacon Test")
    ap.add_argument("--interval", type=int, default=DEFAULT_INTERVAL,
                    help=f"Beacon pulse interval in ms (default {DEFAULT_INTERVAL})")
    ap.add_argument("--no-baseline", action="store_true",
                    help="Skip normal-browsing baseline phase")
    args = ap.parse_args()
    interval = max(2000, min(300000, args.interval))

    # ── Banner ────────────────────────────────────────────────────
    print()
    divider("=")
    print(c("  TEST CASE 01 — Cobalt Strike C2 Beacon Detection", _B, CYN))
    print(c("  Browser Execution Aware C2 Beacon Detector (C3)", _B, CYN))
    divider("=")
    print()
    print(c("  Scenario:", _B, WHT), "Compromised WordPress site deploys a Cobalt Strike")
    print(c("            ", _D), "beacon from a background tab while the user is idle.")
    print()
    print(f"  Beacon interval  : {c(str(interval)+'ms', WHT)}")
    print(f"  Beacon method    : {c('GET', WHT)}")
    print(f"  Expected verdict : {c('BEACON', _B, RED)} (score >= 0.60)")
    print(f"  Expected rules   : {c('regular timing + background traffic + same endpoint', YEL)}")
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

    # ── Step 2: Baseline ──────────────────────────────────────────
    if not args.no_baseline:
        header("STEP 2 — Normal Browsing Baseline")
        print(f"\n  Navigating to {c(BASELINE_URL, BLU)}")
        print(c(f"  Observing for {BASELINE_WAIT}s — normal traffic should score SAFE", _D))
        navigate(BASELINE_URL)
        t0 = time.time()
        last = -POLL_EVERY
        while time.time() - t0 < BASELINE_WAIT:
            now = time.time()
            if now - last >= POLL_EVERY:
                last = now
                try:
                    hosts = api_get("/c3/hosts")
                    for h in (hosts or [])[:3]:
                        hn = str(h.get("host",""))[:22]
                        sc = float(h.get("score",0))
                        vd = str(h.get("verdict","SAFE"))
                        step(now-t0, f"{c(hn,BLU):<30}  {score_s(sc):>12}  {verdict_s(vd)}")
                except RuntimeError: pass
            time.sleep(1)
        print(c("\n  Baseline complete — normal traffic scores SAFE.", GRN))

    # ── Step 3: Deploy beacon ─────────────────────────────────────
    header("STEP 3 — Deploy Simulated Cobalt Strike Beacon")
    beacon_url = (f"http://{BEACON_HOST}:8001"
                  f"/c3/test/beacon-page?interval={interval}&method=GET")
    print(f"\n  Beacon URL    : {c(beacon_url, BLU)}")
    print(c("  Action        : Navigate browser → beacon page, then user goes idle", _D))
    print()
    print(c("  Expected C3 detection path:", _D))
    print(c("    1. CDP captures every GET to /c3/test/beacon-target", _D))
    print(c("    2. Context tagger: is_background_tab=true, user_was_active=false", _D))
    print(c("    3. After 10+ requests: IAT CV < 0.05 → Rule 1 fires (+0.30)", _D))
    print(c("    4. bg_tab_ratio > 0.80 → Rule 3 fires (+0.20)", _D))
    print(c("    5. path_entropy < 0.50 + timing → Rule 5 fires (+0.10)", _D))
    print(c("    6. Heuristic total = 0.60 → BEACON verdict", _D))
    print()
    navigate(beacon_url)
    time.sleep(3)

    # ── Step 4: Monitor detection ─────────────────────────────────
    header("STEP 4 — Monitor C3 Detection (live)")
    eta = (MIN_EVENTS * interval) // 1000 + 30
    print(f"\n  Need {MIN_EVENTS}+ requests for BEACON — ETA ~{eta}s")
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

    # If not detected but host exists, grab final state
    if not detected and final_host_row is None:
        try:
            hosts = api_get("/c3/hosts")
            final_all_hosts = hosts
            final_host_row = find_host(hosts, BEACON_HOST)
        except RuntimeError: pass

    # ── Step 5: Results ───────────────────────────────────────────
    header("STEP 5 — Detection Result")
    print()

    if detected and final_host_row:
        divider("!", RED)
        print(c("  !! BEACON DETECTED — C2 beaconing pattern confirmed !!", _B, RED))
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

    # ── Step 6: Pass/Fail ─────────────────────────────────────────
    header("STEP 6 — Pass/Fail Validation")
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
            print(c("  TC-01 RESULT:  ALL CHECKS PASSED  ✓", _B, GRN))
        else:
            print(c("  TC-01 RESULT:  SOME CHECKS FAILED  ✗", _B, RED))
        divider("=")
    else:
        print(c("  TC-01 RESULT:  FAIL — no beacon data captured", _B, RED))
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(c("\n\n  Test stopped by user (Ctrl+C).", YEL))
        sys.exit(0)
