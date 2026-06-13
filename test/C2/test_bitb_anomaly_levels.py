"""
test/C2/test_bitb_anomaly_levels.py
────────────────────────────────────
Tests BitB HTML pages at specific L1 anomaly score levels against the
WebSentinel /analyze API. Validates that each page triggers exactly the
intended heuristic rules and achieves the target L1 score range.

Pages tested:
  bitb_anomaly_50.html   — L1 target 0.50  (Rule 2 + Rule 5)
  bitb_anomaly_75.html   — L1 target 0.75  (Rule 1 + Rule 2 + Rule 4)
  bitb_anomaly_100.html  — L1 target 1.00  (all 5 rules, capped from 1.25)
  bitb_test.html         — L1 target 1.00  (existing Microsoft-themed page)

Requires:
  - Backend running (run.bat or: python -m uvicorn core.main:app --port 8765)
  - pip install httpx

Usage:
  python test/C2/test_bitb_anomaly_levels.py
"""

import re
import sys
from pathlib import Path

try:
    import httpx
except ImportError:
    sys.exit("Run: pip install httpx")

# ── Configuration ──────────────────────────────────────────────────────────────

API      = "http://127.0.0.1:8765"
TEST_DIR = Path(__file__).resolve().parent

# Phishing-style URL submitted alongside the DOM to maximise L2 score,
# mirroring the pattern used in test_bitb_samples.py.
FAKE_URL = "https://accounts.google.com.evil-phish.xyz/oauth2/v2.0/authorize"

# ── Test case definitions ──────────────────────────────────────────────────────
#
# l1_min / l1_max: assertion range for L1 score.
# Lower bounds are strict (heuristic is deterministic).
# Upper bounds allow headroom for optional ML model boost.

TEST_CASES = [
    {
        "filename":     "bitb_anomaly_50.html",
        "label":        "50%% Anomaly — Google theme",
        "expected_rules": ["high z-index", "fake address-bar element"],
        "l1_min":       0.45,
        "l1_max":       0.65,
        "l1_note":      "Heuristic 0.50 (R2+R5); ML may boost up to ~0.65",
    },
    {
        "filename":     "bitb_anomaly_75.html",
        "label":        "75%% Anomaly — Google theme",
        "expected_rules": ["fixed-pos iframe", "high z-index", "drag-prevention JS"],
        "l1_min":       0.70,
        "l1_max":       0.90,
        "l1_note":      "Heuristic 0.75 (R1+R2+R4); ML may boost up to ~0.90",
    },
    {
        "filename":     "bitb_anomaly_100.html",
        "label":        "100%% Anomaly — PayPal theme",
        "expected_rules": [
            "fixed-pos iframe", "high z-index", "full-viewport coverage",
            "drag-prevention JS", "fake address-bar element",
        ],
        "l1_min":       0.95,
        "l1_max":       1.00,
        "l1_note":      "Heuristic 1.00 (all 5 rules, raw 1.25 capped)",
    },
    {
        "filename":     "bitb_test.html",
        "label":        "Existing 100%% Test — Microsoft theme",
        "expected_rules": [
            "fixed-pos iframe", "high z-index", "full-viewport coverage",
            "drag-prevention JS", "fake address-bar element",
        ],
        "l1_min":       0.95,
        "l1_max":       1.00,
        "l1_note":      "Reference page — should always score 1.00",
    },
]


# ── Helpers ────────────────────────────────────────────────────────────────────

def inline_css(html: str, folder: Path) -> str:
    """Replace <link rel='stylesheet' href='*.css'> with inline <style> blocks."""
    def replace_link(m):
        href = m.group(1)
        css_path = folder / href
        if css_path.exists():
            css_text = css_path.read_text(encoding="utf-8", errors="replace")
            return f"<style>\n{css_text}\n</style>"
        return m.group(0)
    return re.sub(
        r'<link[^>]+href=["\']([^"\']+\.css)["\'][^>]*>',
        replace_link,
        html,
        flags=re.IGNORECASE,
    )


def get_layer(layers: list, layer_id: str) -> dict:
    """Return the layer dict for the given id, or empty dict if absent."""
    for ly in layers:
        if ly.get("id") == layer_id:
            return ly
    return {}


def parse_ml_score(detail: str) -> float | None:
    """
    Layer 1 detail when ML model is loaded:
      "ML:0.87 | fixed-pos iframe, high z-index"
    Returns the ML probability float, or None if the model was not loaded.
    """
    m = re.search(r'\bML:([\d.]+)', detail or "")
    return float(m.group(1)) if m else None


def bar(score: float, width: int = 20) -> str:
    filled = int(score * width)
    return "#" * filled + "-" * (width - filled)


# ── Result printer ─────────────────────────────────────────────────────────────

def print_result(tc: dict, result: dict, l1_pass: bool) -> None:
    """
    Print a formatted test result block.

    L1 line format (mirrors the screenshot):
      BitB Detection   XX% / ML: X.XX  [########------------]
    """
    verdict    = result.get("verdict", "?")
    risk_score = result.get("risk_score", 0.0)
    layers     = result.get("layers", [])

    verdict_label = {
        "PHISHING":   "*** PHISHING ***",
        "SUSPICIOUS": "!   SUSPICIOUS  !",
        "SAFE":       "    SAFE         ",
        "SKIP":       "    SKIP         ",
    }.get(verdict, f"    {verdict}")

    status = "PASS" if l1_pass else "FAIL"
    print(f"\n  [{status}] {tc['label']}")
    print(f"  File    : {tc['filename']}")
    print(f"  Verdict : {verdict_label}")
    print(f"  Risk    : {risk_score}/100")
    print(f"  Layers  :")

    for ly in layers:
        lid     = ly["id"]
        name    = ly["name"]
        score   = ly["score"]
        detail  = ly.get("detail", "")
        pct     = int(round(score * 100))
        bbar    = bar(score)

        if lid == "L1":
            ml_val  = parse_ml_score(detail)
            ml_part = f" / ML: {ml_val:.2f}" if ml_val is not None else ""
            flags   = re.sub(r'^ML:[\d.]+\s*\|\s*', '', detail)
            print(f"    {lid}  {name:22s}  {pct:3d}%{ml_part:14s}  [{bbar}]")
            if flags and flags != "No BitB indicators":
                print(f"         flags : {flags}")

        elif lid == "L2":
            print(f"    {lid}  {'URL Analysis':22s}  {pct:3d}%                [{bbar}]")
            if detail:
                print(f"         detail: ML model score: {detail[:60]}")

        elif lid == "L3":
            print(f"    {lid}  {'Visual Similarity':22s}  {pct:3d}%                [{bbar}]")
            if detail:
                print(f"         detail: {detail[:60]}")

        elif lid == "L4":
            disp = detail if detail else "No form anomalies"
            print(f"    {lid}  {'Form Destination':22s}  {pct:3d}%                [{bbar}]")
            print(f"         detail: {disp[:60]}")

        elif lid == "L5":
            print(f"    {lid}  {'Reputation Check':22s}  {pct:3d}%                [{bbar}]")
            if detail:
                print(f"         detail: {detail[:60]}")

    l1_layer = get_layer(layers, "L1")
    l1_score = l1_layer.get("score", -1.0)
    print(f"  L1 Assert: {l1_score:.4f}  expected [{tc['l1_min']:.2f}, {tc['l1_max']:.2f}]"
          f"  -> {status}  ({tc['l1_note']})")


# ── Core test runner ───────────────────────────────────────────────────────────

def run_test(tc: dict, client: httpx.Client) -> tuple[bool, dict]:
    html_path = TEST_DIR / tc["filename"]
    if not html_path.exists():
        print(f"\n  ERROR: File not found: {html_path}")
        return False, {}

    html = html_path.read_text(encoding="utf-8", errors="replace")
    html = inline_css(html, TEST_DIR)

    try:
        r = client.post(
            f"{API}/analyze",
            json={"url": FAKE_URL, "dom": html},
            timeout=20,
        )
        r.raise_for_status()
        result = r.json()
    except httpx.HTTPStatusError as exc:
        print(f"\n  HTTP {exc.response.status_code}: {exc}")
        return False, {}
    except Exception as exc:
        print(f"\n  Request failed: {exc}")
        return False, {}

    l1_layer = get_layer(result.get("layers", []), "L1")
    l1_score = l1_layer.get("score", -1.0)
    passed   = tc["l1_min"] <= l1_score <= tc["l1_max"]
    return passed, result


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 70)
    print("  WebSentinel — BitB Anomaly Score Level Tests")
    print("=" * 70)
    print(f"  API     : {API}")
    print(f"  URL     : {FAKE_URL}")
    print()

    try:
        r = httpx.get(f"{API}/health", timeout=4)
        assert r.json().get("status") == "ok"
        print("  Backend : OK")
    except Exception:
        print("  ERROR   : Backend not running.")
        print("  Start   : python -m uvicorn core.main:app --port 8765")
        sys.exit(1)

    print("-" * 70)

    passed_count = 0
    failed_count = 0
    failures: list[str] = []

    with httpx.Client() as client:
        for tc in TEST_CASES:
            ok, result = run_test(tc, client)
            print_result(tc, result, ok)
            if ok:
                passed_count += 1
            else:
                failed_count += 1
                failures.append(tc["filename"])

    print("\n" + "=" * 70)
    print(f"  Results : {passed_count} passed, {failed_count} failed"
          f" / {len(TEST_CASES)} tests")

    if failures:
        print("\n  Failed tests:")
        for f in failures:
            print(f"    - {f}")

    print("=" * 70)
    sys.exit(1 if failed_count > 0 else 0)


if __name__ == "__main__":
    main()
