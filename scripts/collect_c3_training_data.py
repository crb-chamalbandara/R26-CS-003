"""
Automated C3 browser context training data collector.

Starts the WebSentinel backend, collects real benign browsing data and
simulated beacon data from the built-in beacon test page, exports both
CSVs, then trains the browser context model.

Total runtime: approximately 8-10 minutes.
No synthetic data is generated — all rows come from real browser sessions.

Usage:
    python -m scripts.collect_c3_training_data
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib import error, request as urlrequest

REPO_ROOT = Path(__file__).resolve().parent.parent
API       = "http://127.0.0.1:8001"
PYTHON    = REPO_ROOT / ".venv" / "Scripts" / "python.exe"

# Normal websites to browse for benign traffic.
# Wikipedia is ideal — each page loads many varied resource URLs,
# producing high url_path_entropy (the key benign signal).
BENIGN_SITES = [
    "https://en.wikipedia.org/wiki/Main_Page",
    "https://en.wikipedia.org/wiki/Machine_learning",
    "https://en.wikipedia.org/wiki/Botnet",
    "https://en.wikipedia.org/wiki/Network_security",
    "https://en.wikipedia.org/wiki/Cybersecurity",
    "https://en.wikipedia.org/wiki/Intrusion_detection_system",
    "https://en.wikipedia.org/wiki/Malware",
    "https://en.wikipedia.org/wiki/Command-and-control_server",
    "https://en.wikipedia.org/wiki/Browser_security",
    "https://en.wikipedia.org/wiki/Threat_Intelligence_Platform",
]

SECS_PER_SITE       = 25   # 25s per site (2+ analyzer cycles at 10s each)
BEACON_SECS         = 180  # 3 minutes of beacon firing (36+ pulses at 5s)
BEACON_INTERVAL_MS  = 5000

SEP = "=" * 60


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _call(method: str, path: str, body: dict | None = None):
    url  = API + path
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"Content-Type": "application/json"} if data else {}
    req  = urlrequest.Request(url, data=data, headers=hdrs, method=method)
    with urlrequest.urlopen(req, timeout=8) as resp:
        return json.loads(resp.read().decode())


def api_get(path: str):
    return _call("GET", path)


def api_post(path: str, body: dict | None = None):
    return _call("POST", path, body or {})


# ── Backend management ────────────────────────────────────────────────────────

def backend_running() -> bool:
    try:
        api_get("/health")
        return True
    except Exception:
        return False


def start_backend() -> subprocess.Popen:
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONPATH"] = str(REPO_ROOT)
    proc = subprocess.Popen(
        [str(PYTHON), "-m", "uvicorn", "core.main:app",
         "--host", "127.0.0.1", "--port", "8001"],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc


def wait_for_backend(timeout: int = 45) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if backend_running():
            return
        time.sleep(2)
        print("  Waiting for backend...", end="\r")
    print()
    sys.exit("[ERROR] Backend did not start within 45 seconds.")


# ── Session management ────────────────────────────────────────────────────────

def ensure_session() -> None:
    try:
        s = api_get("/session/status")
        if s.get("running"):
            print("  Playwright session: already running.")
            return
    except Exception:
        pass

    print("  Starting Playwright browser session...", end="", flush=True)
    api_post("/session/start")
    deadline = time.time() + 40
    while time.time() < deadline:
        time.sleep(2)
        try:
            if api_get("/session/status").get("running"):
                print(" ready.")
                return
        except Exception:
            pass
        print(".", end="", flush=True)
    print()
    sys.exit("[ERROR] Playwright session did not start within 40 seconds.")


def navigate(url: str) -> None:
    try:
        api_post("/session/navigate", {"url": url})
    except Exception as exc:
        print(f"  [WARN] Navigate failed: {exc}")


# ── Collection helpers ────────────────────────────────────────────────────────

def start_collection(label: int) -> None:
    api_post("/c3/collect/start", {"label": label})
    print(f"  Collection started  label={label}")


def stop_collection() -> None:
    try:
        api_post("/c3/collect/stop")
    except Exception:
        pass


def export_collection() -> str:
    result = api_post("/c3/collect/export")
    path = result.get("path", "")
    print(f"  Exported -> {path}")
    return path


def collection_samples() -> int:
    try:
        st = api_get("/c3/status")
        return int(st.get("collection_samples", 0))
    except Exception:
        return 0


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print()
    print(SEP)
    print(" C3 Browser Context  --  Training Data Collection")
    print(SEP)
    print(f" Step 1 : Collect benign browsing data  (label=0)")
    print(f"          {len(BENIGN_SITES)} sites x {SECS_PER_SITE}s = {len(BENIGN_SITES)*SECS_PER_SITE}s")
    print(f" Step 2 : Collect beacon data  (label=1)")
    print(f"          Beacon test page, {BEACON_SECS}s at {BEACON_INTERVAL_MS}ms interval")
    print(f" Step 3 : Train browser context model")
    print(f" Total  : ~{(len(BENIGN_SITES)*SECS_PER_SITE + BEACON_SECS + 90)//60} minutes")
    print(SEP)

    # ── Backend ───────────────────────────────────────────────────
    backend_proc = None
    if not backend_running():
        print("\n[1/3] Starting WebSentinel backend...")
        backend_proc = start_backend()
        wait_for_backend(45)
        print("  Backend ready.")
    else:
        print("\n[1/3] Backend already running.")

    ensure_session()
    time.sleep(3)  # let interceptor settle

    # ── Phase A: Benign collection ─────────────────────────────────
    print(f"\n[2/3] Benign collection  (label=0)  —  {len(BENIGN_SITES)} sites")
    print(f"      Each site: {SECS_PER_SITE}s  |  Analyzer cycle: 10s")
    print()

    start_collection(label=0)
    t0 = time.time()

    for i, url in enumerate(BENIGN_SITES, 1):
        domain = url.split("/")[2]
        print(f"  [{i:02d}/{len(BENIGN_SITES)}] Navigating -> {domain}")
        navigate(url)
        # Wait SECS_PER_SITE seconds, show progress
        site_t0 = time.time()
        while time.time() - site_t0 < SECS_PER_SITE:
            elapsed = time.time() - t0
            samples = collection_samples()
            print(
                f"         elapsed={int(elapsed):>3}s  "
                f"samples={samples:>4}  "
                f"site={int(time.time()-site_t0):>2}/{SECS_PER_SITE}s",
                end="\r",
            )
            time.sleep(2)
        print()

    benign_samples = collection_samples()
    print(f"\n  Benign collection complete — {benign_samples} samples")
    stop_collection()
    export_collection()

    # ── Phase B: Beacon collection ──────────────────────────────────
    beacon_url = (
        f"http://127.0.0.1:8001/c3/test/beacon-page"
        f"?interval={BEACON_INTERVAL_MS}&method=POST"
    )
    print(f"\n  Beacon collection  (label=1)  —  {BEACON_SECS}s")
    print(f"  Beacon URL: {beacon_url}")
    print()

    start_collection(label=1)
    navigate(beacon_url)
    time.sleep(4)  # let page load and fire first pulse

    t1 = time.time()
    while time.time() - t1 < BEACON_SECS:
        elapsed = time.time() - t1
        samples = collection_samples()
        expected_pulses = int(elapsed * 1000 / BEACON_INTERVAL_MS)
        print(
            f"  elapsed={int(elapsed):>3}/{BEACON_SECS}s  "
            f"samples={samples:>4}  "
            f"pulses≈{expected_pulses:>3}",
            end="\r",
        )
        time.sleep(2)
    print()

    beacon_samples = collection_samples()
    print(f"\n  Beacon collection complete — {beacon_samples} samples")
    stop_collection()
    export_collection()

    # ── Stop backend if we started it ─────────────────────────────
    if backend_proc is not None:
        print("\n  Stopping backend...")
        try:
            api_post("/session/stop")
        except Exception:
            pass
        time.sleep(2)
        backend_proc.terminate()
        try:
            backend_proc.wait(timeout=8)
        except Exception:
            backend_proc.kill()
        print("  Backend stopped.")

    # ── Train ──────────────────────────────────────────────────────
    print()
    print(SEP)
    print(" [3/3] Training browser context model...")
    print(SEP)

    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONPATH"] = str(REPO_ROOT)
    result = subprocess.run(
        [str(PYTHON), "-m", "scripts.train_c3_browser_model"],
        cwd=str(REPO_ROOT),
        env=env,
    )

    print()
    if result.returncode == 0:
        print(SEP)
        print(" Data collection and training complete!")
        print(" Restart the WebSentinel backend to activate the browser context model.")
        print(SEP)
    else:
        print(f"[ERROR] Training script exited with code {result.returncode}")

    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Stopped by user (Ctrl+C).")
        sys.exit(0)
    except Exception as exc:
        print(f"\n[ERROR] {exc}")
        sys.exit(1)
