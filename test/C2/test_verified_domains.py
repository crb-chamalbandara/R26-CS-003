"""
test/C2/test_verified_domains.py
────────────────────────────────
Offline unit test for C2's verified-domain trust gate
(core/c2/verified_domains.py). No backend required.

Usage:
    python test/C2/test_verified_domains.py
"""
import os
import sys

# Make the repo root importable (this file lives in <root>/test/C2/).
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.c2.verified_domains import is_verified, registered_domain  # noqa: E402

# (url, expected registered_domain, expected is_verified)
CASES = [
    ("https://www.google.com/search?q=python", "google.com", True),
    ("https://github.com/foo/bar",             "github.com", True),
    ("https://login.microsoftonline.com/x",    "microsoftonline.com", True),
    # Brand-in-subdomain phishing on an unknown domain → not verified.
    ("http://paypal-secure-login.unknown-xyz123.tk/login", "unknown-xyz123.tk", False),
    # Free / shared hosting: parent is popular but subdomains are attacker-controlled.
    ("http://paypal-login.yolasite.com/x",     "yolasite.com", False),
    ("https://attacker.weebly.com/login",      "weebly.com",   False),
    ("https://my-phish.github.io/login",       "github.io",    False),
    # No registered domain (raw IP).
    ("http://192.168.0.1/login",               "",             False),
]


def main() -> int:
    failures = 0
    for url, exp_reg, exp_verified in CASES:
        reg = registered_domain(url)
        ver = is_verified(url)
        ok_reg = (reg == exp_reg)
        ok_ver = (ver == exp_verified)
        status = "PASS" if (ok_reg and ok_ver) else "FAIL"
        if status == "FAIL":
            failures += 1
        print(f"[{status}] reg={reg!r:32} verified={ver!s:5}  {url}")
        if not ok_reg:
            print(f"        expected reg={exp_reg!r}")
        if not ok_ver:
            print(f"        expected verified={exp_verified}")

    print("-" * 60)
    if failures:
        print(f"{failures} test(s) FAILED")
        return 1
    print(f"All {len(CASES)} verified-domain tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
