"""
tests/test_bitb_samples.py
───────────────────────────
Tests each mrd0x/BITB template against the WebSentinel /analyze API.
Inlines external CSS into the HTML so DOM feature extraction sees all signals.

Requires backend running (run.bat) before executing.
Usage:
    python tests/test_bitb_samples.py
"""
import sys
import json
from pathlib import Path

try:
    import httpx
except ImportError:
    sys.exit("Run: pip install httpx")

API       = "http://127.0.0.1:8001"
SAMPLES   = Path(__file__).resolve().parent / "bitb_samples"

# Placeholder URL used as the "page URL" when sending to /analyze
FAKE_URL  = "https://login.microsoft.com.evil-phish.xyz/oauth2/v2.0/authorize"


def inline_css(html: str, folder: Path) -> str:
    """Replace <link rel='stylesheet' href='style.css'> with inline <style> block."""
    import re
    def replace_link(m):
        href = m.group(1)
        css_path = folder / href
        if css_path.exists():
            css_text = css_path.read_text(encoding="utf-8", errors="replace")
            return f"<style>\n{css_text}\n</style>"
        return m.group(0)
    return re.sub(r'<link[^>]+href=["\']([^"\']+\.css)["\'][^>]*>', replace_link, html, flags=re.IGNORECASE)


def test_sample(name: str, html: str, url: str, client: httpx.Client) -> dict:
    r = client.post(f"{API}/analyze", json={"url": url, "dom": html}, timeout=20)
    return r.json()


def print_result(name: str, result: dict):
    verdict    = result.get("verdict", "?")
    risk_score = result.get("risk_score", 0)
    layers     = result.get("layers", [])

    verdict_color = {
        "PHISHING":   "*** PHISHING ***",
        "SUSPICIOUS": "!   SUSPICIOUS  !",
        "SAFE":       "    SAFE        ",
    }.get(verdict, verdict)

    print(f"\n  Template : {name}")
    print(f"  Verdict  : {verdict_color}")
    print(f"  Risk     : {risk_score}/100")
    print(f"  Layers:")
    for ly in layers:
        filled = int(ly["score"] * 20)
        bar    = "#" * filled + "-" * (20 - filled)
        print(f"    {ly['id']}  {ly['name']:20s}  score={ly['score']:.4f}  [{bar}]")
        if ly["detail"]:
            print(f"         detail: {ly['detail']}")


def main():
    print("=" * 65)
    print("  WebSentinel — mrd0x/BITB Template Detection Test")
    print("=" * 65)

    # Check backend
    try:
        r = httpx.get(f"{API}/health", timeout=3)
        assert r.json().get("status") == "ok"
        print("  Backend: OK\n")
    except Exception:
        print("  ERROR: Backend not running. Launch run.bat first.")
        sys.exit(1)

    # Find all template folders (each has index.html)
    templates = sorted(p.parent for p in SAMPLES.rglob("index.html"))
    if not templates:
        print(f"  No templates found in {SAMPLES}")
        print("  Run: git clone https://github.com/mrd0x/BITB tests/bitb_samples")
        sys.exit(1)

    print(f"  Found {len(templates)} BITB templates\n")
    print("-" * 65)

    with httpx.Client() as client:
        for folder in templates:
            name = folder.name
            html_path = folder / "index.html"
            html = html_path.read_text(encoding="utf-8", errors="replace")

            # Inline external CSS so the DOM analyzer sees style signals
            html = inline_css(html, folder)

            result = test_sample(name, html, FAKE_URL, client)
            print_result(name, result)

    print("\n" + "=" * 65)
    print("  Done.")
    print("=" * 65)


if __name__ == "__main__":
    main()
