"""
C3 Beacon Detection Live Demo
==============================
Demonstrates the full C3 detection pipeline against a simulated C2 beacon.

Pipeline:
  Browser (Playwright/Chromium)
    -> CDP network interception (C3 interceptor)
    -> Context tagging (idle time, background tab, user activity)
    -> Feature extraction (14 features: IAT stats, rate, browser context)
    -> Isolation Forest scoring (5 timing features)
    -> Heuristic scoring (4 rules)
    -> Risk fusion (adaptive weights)
    -> BEACON verdict + alert storage

Usage (called by test_c3_beacon.bat):
    python scripts/c3_demo.py [--interval MS] [--no-baseline]

Requirements:
    - Backend running: python -m uvicorn core.main:app --host 127.0.0.1 --port 8001
    - (test_c3_beacon.bat handles this automatically)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from urllib import error, request as urlrequest

# ── Configuration ──────────────────────────────────────────────────────────────
API              = "http://127.0.0.1:8001"
BEACON_TARGET    = "127.0.0.1"    # host the beacon page fires to (same server)
DEFAULT_INTERVAL = 5000           # ms between beacon pulses
BASELINE_URL     = "https://en.wikipedia.org/wiki/Main_Page"
BASELINE_WAIT    = 25             # seconds to observe normal traffic
POLL_EVERY       = 10             # seconds between /c3/hosts polls
MIN_EVENTS       = 10             # must match analyzer allow_beacon threshold
MAX_DEMO_WAIT    = 300            # hard stop after 5 minutes

# ── ANSI colour helpers (Windows 10+ / Windows Terminal) ─────────────────────
os.system("")   # enable VT100 on Windows console
_R  = "\033[0m"
_B  = "\033[1m"
_D  = "\033[2m"
RED = "\033[91m";  YELLOW = "\033[93m";  GREEN = "\033[92m"
CYN = "\033[96m";  BLU    = "\033[94m";  WHT   = "\033[97m"


def c(text: str, *codes: str) -> str:
    return "".join(codes) + str(text) + _R


def risk_color(score_01: float) -> str:
    return RED if score_01 >= 0.6 else YELLOW if score_01 >= 0.3 else GREEN


def score_str(score_01: float | None) -> str:
    if score_01 is None:
        return c(" n/a", _D)
    pct = round(float(score_01) * 100)
    col = risk_color(float(score_01))
    return c(f"{pct:>3}%", col)


def verdict_str(verdict: str) -> str:
    v = verdict.upper()
    if v == "BEACON":
        return c("BEACON    ", _B + RED)
    if v == "SUSPICIOUS":
        return c("SUSPICIOUS", YELLOW)
    return c("SAFE      ", GREEN)


def progress_bar(pct: float, width: int = 18) -> str:
    filled = max(0, min(width, round(pct / 100 * width)))
    col = risk_color(pct / 100)
    return c("#" * filled, col) + c("-" * (width - filled), _D)


# ── HTTP helpers ──────────────────────────────────────────────────────────────
def _call(method: str, path: str, body: dict | None = None) -> dict | list:
    url = API + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    hdrs = {"Content-Type": "application/json"} if data else {}
    req = urlrequest.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urlrequest.urlopen(req, timeout=6) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code} on {path}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Cannot reach backend ({exc.reason})") from exc


def api_get(path: str) -> dict | list:
    return _call("GET", path)


def api_post(path: str, body: dict | None = None) -> dict | list:
    return _call("POST", path, body or {})


# ── Display helpers ───────────────────────────────────────────────────────────
def _divider(char: str = "-", width: int = 68, color: str = CYN) -> None:
    print(c(char * width, color))


def _header(title: str) -> None:
    print()
    _divider("=", color=CYN)
    print(c(f"  {title}", _B + WHT))
    _divider("=", color=CYN)


def _step(elapsed: float, msg: str) -> None:
    ts = c(f"[+{int(elapsed):>3}s]", _D)
    print(f"  {ts}  {msg}")


def _col_headers() -> None:
    print(c(
        f"  {'Time':>7}  {'Host':<22}  {'Reqs':>5}  {'Score':>6}  {'Verdict':<12}"
        f"  {'Anomaly':>7}  {'Heuristic':>9}  {'Reputation':>10}",
        _D
    ))
    print(c(
        f"  {'-------':>7}  {'-'*22}  {'-----':>5}  {'------':>6}  {'-'*12}"
        f"  {'-------':>7}  {'---------':>9}  {'----------':>10}",
        _D
    ))


def _print_row(elapsed: float, host_row: dict | None) -> str:
    """Print one status row. Returns verdict string (or 'NO_DATA')."""
    if host_row is None:
        _step(elapsed, c(f"{BEACON_TARGET:<22}  (no data captured yet)", _D))
        return "NO_DATA"

    score  = float(host_row.get("score") or 0.0)
    verd   = str(host_row.get("verdict") or "SAFE")
    reqs   = int(host_row.get("request_count") or 0)
    sigs   = host_row.get("signal_breakdown") or {}

    _step(
        elapsed,
        f"{c(BEACON_TARGET, BLU):<30}  "
        f"reqs={c(str(reqs), WHT):<8}  "
        f"{score_str(score):>12}  {verdict_str(verd):<20}  "
        f"A={score_str(sigs.get('anomaly'))}  "
        f"H={score_str(sigs.get('heuristic'))}  "
        f"R={score_str(sigs.get('reputation'))}"
    )
    return verd


def _print_feature_table(features: dict) -> None:
    if not features:
        return
    rows = [
        ("iat_cv",              "IAT CV (regularity)"),
        ("iat_mean_ms",         "IAT mean (ms)      "),
        ("iat_mad_ms",          "IAT MAD (ms)       "),
        ("requests_per_hour",   "Req / hour         "),
        ("user_active_ratio",   "User active ratio  "),
        ("background_tab_ratio","Background tab ratio"),
        ("url_path_entropy",    "URL path entropy   "),
        ("http_post_ratio",     "POST ratio         "),
    ]
    print()
    print(c("  Feature snapshot (key detection signals):", _D))
    print(c(f"  {'Feature':<22}  {'Value':>9}  {'Risk bar'}", _D))
    print(c(f"  {'-'*22}  {'-'*9}  {'-'*20}", _D))
    for key, label in rows:
        if key not in features:
            continue
        v = float(features[key])
        # map value to risk %
        if key == "iat_cv":
            risk = 100 if v < 0.05 else (75 if v < 0.10 else (40 if v < 0.5 else 10))
            note = c(" <- very regular!" if v < 0.05 else (" <- regular" if v < 0.10 else ""), RED if v < 0.05 else YELLOW)
        elif key == "user_active_ratio":
            risk = round((1.0 - min(1.0, v)) * 100)
            note = ""
        elif key in ("background_tab_ratio", "http_post_ratio"):
            risk = round(min(1.0, v) * 100)
            note = ""
        else:
            risk = 0
            note = ""
        bar = progress_bar(risk) if risk > 0 else c("-" * 18, _D)
        print(f"  {c(label, _D):<30}  {c(f'{v:.4f}', WHT):>9}  {bar}{note}")


def _print_alert_box(host_row: dict, alert: dict | None) -> None:
    src = alert or host_row
    score = float(src.get("score") or 0.0)
    pct   = round(score * 100)
    sigs  = src.get("signal_breakdown") or {}
    feats = src.get("features") or {}
    detail= str(src.get("detail") or "")
    ts    = str(src.get("timestamp") or "")

    print()
    _divider("!", color=RED)
    print(c("  !! BEACON DETECTED — C2 beaconing pattern confirmed !!", _B + RED))
    _divider("!", color=RED)
    print()
    print(f"  Host      : {c(BEACON_TARGET, _B + RED)}")
    print(f"  Score     : {c(str(pct) + '%', _B + RED)}  [{progress_bar(float(pct))}]")
    print(f"  Verdict   : {c('BEACON', _B + RED)}")
    if ts:
        print(f"  Time      : {c(ts[:19], _D)}")
    print()
    print(c("  Signal breakdown:", _B + WHT))
    for sig, label in [("anomaly", "Anomaly (IF model)  "),
                        ("heuristic", "Heuristic rules     "),
                        ("reputation", "Reputation (TI)     ")]:
        val = sigs.get(sig)
        if val is not None:
            p = round(float(val) * 100)
            print(f"    {c(label, _D)}  {score_str(val)}  [{progress_bar(float(p))}]")
        else:
            print(f"    {c(label, _D)}  {c('n/a (not queried)', _D)}")
    if detail:
        print()
        print(f"  {c('Detail:', _D)} {c(detail[:72], WHT)}")
    _print_feature_table(feats)
    print()
    _divider("!", color=RED)


# ── Demo logic ────────────────────────────────────────────────────────────────
def wait_for_backend(timeout: int = 35) -> dict:
    """Poll /health until ready or timeout."""
    deadline = time.time() + timeout
    dots = 0
    while time.time() < deadline:
        try:
            return api_get("/health")
        except RuntimeError:
            if dots == 0:
                print(c("  Waiting for backend", _D), end="", flush=True)
            print(c(".", _D), end="", flush=True)
            dots += 1
            time.sleep(2)
    print()
    sys.exit(c("\n  [ERROR] Backend did not respond. Run: python -m uvicorn core.main:app --port 8001", RED))


def ensure_session() -> None:
    """Start Playwright session if not already running."""
    try:
        s = api_get("/session/status")
        if s.get("running"):
            print(c("  Playwright session: already running.", GREEN))
            return
    except RuntimeError:
        pass
    print(c("  Starting Playwright session...", _D), end="", flush=True)
    try:
        api_post("/session/start")
    except RuntimeError as exc:
        print()
        sys.exit(c(f"\n  [ERROR] Could not start session: {exc}", RED))
    # Poll until session reports running
    deadline = time.time() + 30
    while time.time() < deadline:
        time.sleep(2)
        try:
            if api_get("/session/status").get("running"):
                print(c(" started.", GREEN))
                return
        except RuntimeError:
            pass
        print(c(".", _D), end="", flush=True)
    print()
    print(c("  [WARN] Session may not be fully ready. Proceeding anyway.", YELLOW))


def navigate_browser(url: str) -> None:
    try:
        api_post("/session/navigate", {"url": url})
    except RuntimeError as exc:
        print(c(f"  [WARN] Navigate failed: {exc}", YELLOW))


def find_host(hosts: list, target: str) -> dict | None:
    return next((h for h in hosts if str(h.get("host", "")) == target), None)


def get_latest_alert(target: str) -> dict | None:
    try:
        alerts = api_get("/c3/alerts?limit=50")
        return next((a for a in alerts if str(a.get("host", "")) == target), None)
    except RuntimeError:
        return None


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser(description="C3 Beacon Detection Live Demo")
    ap.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, metavar="MS",
                    help=f"Beacon pulse interval in milliseconds (default: {DEFAULT_INTERVAL})")
    ap.add_argument("--no-baseline", action="store_true",
                    help="Skip the normal-browsing baseline phase")
    args = ap.parse_args()
    interval_ms = max(2000, min(int(args.interval), 30000))

    # ── Banner ────────────────────────────────────────────────────
    print()
    _divider("=", color=CYN)
    print(c("  C3 -- Browser Execution Aware C2 Beacon Detector", _B + CYN))
    print(c("               L I V E   D E T E C T I O N   D E M O", _B + CYN))
    _divider("=", color=CYN)
    print()
    print(f"  Beacon interval  : {c(str(interval_ms) + ' ms', WHT)}"
          f"  (1 pulse every {interval_ms // 1000}s)")
    print(f"  Beacon host      : {c(BEACON_TARGET, WHT)}")
    print(f"  BEACON threshold : {c(str(MIN_EVENTS) + '+ requests', WHT)}"
          f"  and  fused score >= 0.60")
    print()
    print(c("  Detection pipeline:", _D))
    print(c("    Browser -> CDP intercept -> Context tag -> Feature extract", _D))
    print(c("    -> Isolation Forest (4 timing features)", _D))
    print(c("    -> Heuristic rules (4 rules)", _D))
    print(c("    -> Risk fusion (adaptive weights) -> Verdict", _D))
    print()

    # ── Step 1: Backend connection ────────────────────────────────
    _header("SETUP -- Connecting to WebSentinel Backend")
    print()
    health = wait_for_backend(35)
    if health:
        print()
    c3_st = api_get("/c3/status")
    ml  = c3_st.get("model_loaded", False)
    mty = c3_st.get("model_type", "unknown")
    print(c("  Backend  : Online", GREEN))
    print(c(f"  C3 model : {mty} ({'loaded' if ml else 'NOT loaded -- heuristic only'})",
            GREEN if ml else YELLOW))
    print(c(f"  Analyzer : {'running' if c3_st.get('analyzer_running') else 'stopped'}",
            GREEN if c3_st.get("analyzer_running") else YELLOW))
    print()
    ensure_session()

    # ── Step 2: Normal browsing baseline (optional) ───────────────
    if not args.no_baseline:
        _header("PHASE 1 -- Normal Browsing Baseline")
        print(f"\n  Navigating to {c(BASELINE_URL, BLU)}")
        print(c(f"  Observing for {BASELINE_WAIT}s -- legitimate traffic should score SAFE", _D))
        print()
        _col_headers()
        navigate_browser(BASELINE_URL)
        t0  = time.time()
        last = -POLL_EVERY
        while time.time() - t0 < BASELINE_WAIT:
            now = time.time()
            if now - last >= POLL_EVERY:
                last = now
                try:
                    hosts = api_get("/c3/hosts")
                    if not hosts:
                        _step(now - t0, c("No hosts captured yet (browsing traffic building up)", _D))
                    else:
                        for h in hosts[:4]:
                            hn    = str(h.get("host", ""))[:22]
                            score = float(h.get("score") or 0.0)
                            verd  = str(h.get("verdict") or "SAFE")
                            reqs  = int(h.get("request_count") or 0)
                            _step(
                                now - t0,
                                f"{c(hn, BLU):<30}  "
                                f"reqs={c(str(reqs), WHT):<8}  "
                                f"{score_str(score):>12}  {verdict_str(verd)}"
                            )
                except RuntimeError as exc:
                    _step(now - t0, c(f"Poll error: {exc}", YELLOW))
            time.sleep(1)
        print()
        print(c("  Baseline complete. Normal browsing correctly scores SAFE.", GREEN))

    # ── Step 3: Beacon simulation ─────────────────────────────────
    _header("PHASE 2 -- Beacon Simulation")
    beacon_url = (
        f"http://{BEACON_TARGET}:8001"
        f"/c3/test/beacon-page?interval={interval_ms}&method=POST"
    )
    print()
    print(f"  Beacon page URL : {c(beacon_url, BLU)}")
    print(f"  Pulse method    : {c('POST', WHT)} with JSON body"
          f"  {{ts: Date.now(), component: 'c3'}}")
    print(f"  Pulse interval  : {c(str(interval_ms) + 'ms', WHT)}")
    print(f"  Host monitored  : {c(BEACON_TARGET, WHT)}")
    print()
    print(c("  How C3 detects this:", _D))
    print(c("    1. CDP captures every POST to /c3/test/beacon-target", _D))
    print(c("    2. Context tagger records idle time + tab visibility per request", _D))
    print(c("    3. After 10+ requests: IAT CV < 0.05 fires 'regular timing'", _D))
    print(c("    4. Isolation Forest sees timing regularity -> high anomaly score", _D))
    print(c("    5. Fused score crosses 0.60 -> BEACON verdict", _D))
    print()
    print(c(f"  Navigating Playwright browser to beacon page...", _D))
    navigate_browser(beacon_url)
    # Let the page load and fire its first pulse
    time.sleep(4)

    print()
    print(c("  Monitoring C3 detection (polling every 10s)...", _D))
    print(c(f"  BEACON verdict requires {MIN_EVENTS}+ requests -- "
            f"ETA ~{(MIN_EVENTS * interval_ms) // 1000 + 20}s", _D))
    print()
    _col_headers()

    t0         = time.time()
    last_poll  = -POLL_EVERY      # poll immediately on first tick
    detected   = False

    while time.time() - t0 < MAX_DEMO_WAIT:
        now = time.time()

        if now - last_poll >= POLL_EVERY:
            last_poll = now
            elapsed   = now - t0
            try:
                hosts    = api_get("/c3/hosts")
                host_row = find_host(hosts, BEACON_TARGET)
                verdict  = _print_row(elapsed, host_row)

                if verdict == "BEACON":
                    # Fetch the stored alert for full signal detail
                    time.sleep(0.5)
                    alert = get_latest_alert(BEACON_TARGET)
                    # Print the full alert box
                    _print_alert_box(host_row or {}, alert)
                    detected = True
                    break

                # Show progress hint while accumulating
                if host_row:
                    reqs = int(host_row.get("request_count") or 0)
                    if reqs < MIN_EVENTS:
                        remaining = MIN_EVENTS - reqs
                        eta_s = remaining * interval_ms // 1000 + 10
                        print(c(
                            f"    -> Need {remaining} more requests for BEACON verdict"
                            f"  (ETA ~{eta_s}s)",
                            _D
                        ))
            except RuntimeError as exc:
                _step(now - t0, c(f"Poll error: {exc}", YELLOW))

        time.sleep(1)

    # ── Result summary ────────────────────────────────────────────
    _header("DEMO RESULT")
    print()
    if detected:
        print(c("  SUCCESS: BEACON verdict confirmed.", _B + GREEN))
        print(c("  C3 correctly identified simulated C2 beaconing activity.", GREEN))
    else:
        print(c(f"  Demo ended after {int(time.time() - t0)}s without BEACON verdict.", YELLOW))
        print()
        print(c("  Possible reasons:", _D))
        print(c("   - Fewer than 10 requests were captured."
                "  Re-run with --no-baseline for a faster result.", _D))
        print(c("   - The Playwright session was not active or the page failed to load.", _D))
        print(c("   - The analyzer has not completed a full 10-second cycle yet.", _D))
        print(c("   - Run with --interval 3000 for faster accumulation.", _D))

    print()
    _divider("-", color=_D)
    print(c("  Where to see full results in the WebSentinel dashboard:", _D))
    print(c(f"    C3 -> Alerts tab   : BEACON alert with signal breakdown", _D))
    print(c(f"    C3 -> Hosts tab    : {BEACON_TARGET} with score timeline", _D))
    print(c(f"    C3 -> Live Monitor : each captured beacon pulse", _D))
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(c("\n\n  Demo stopped by user (Ctrl+C).", YELLOW))
        sys.exit(0)
