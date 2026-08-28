"""
C2 — Verified-domain trust gate
Matches a URL's registered domain (eTLD+1) against a world-verified allowlist
(data/verified_domains.txt, built from the Tranco list by
scripts/fetch_verified_domains.py).

core/main.py uses this to suppress false positives on known-good sites: a verified
domain skips the FP-prone heuristic layers (L1/L2/L4) but still gets a reputation
check (L5), so a compromised-but-listed domain can still be flagged.

Degrades safely: if tldextract or the list is missing, is_verified() returns False
and analysis behaves exactly as before.
"""
import os
from urllib.parse import urlparse

_LIST_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "data", "verified_domains.txt"
)

# ── Load the allowlist once at import ─────────────────────────────
_verified: set = set()
try:
    with open(_LIST_PATH, encoding="utf-8") as _f:
        _verified = {ln.strip().lower() for ln in _f if ln.strip()}
    print(f"[C2-verified] Loaded {len(_verified)} verified domains")
except FileNotFoundError:
    print("[C2-verified] No verified_domains.txt — verification disabled "
          "(run scripts/fetch_verified_domains.py)")

# ── Shared-hosting exclusions ─────────────────────────────────────
# Free / shared providers where attackers get arbitrary subdomains. Their parent
# domain is popular (and in Tranco) but a subdomain like paypal-login.yolasite.com
# must NOT be trusted. Reuse L2's free-host list and add a few more.
try:
    from .layer2_url import FREE_HOSTS
except Exception:
    FREE_HOSTS = set()

_EXTRA_EXCLUDED = {
    "github.io", "herokuapp.com", "glitch.me", "repl.co", "replit.app",
    "pages.dev", "workers.dev", "r2.dev", "amazonaws.com", "appspot.com",
    "googleusercontent.com", "translate.goog", "blogspot.com",
}

# ── eTLD+1 extractor (offline: bundled PSL snapshot, no network) ───
try:
    import tldextract
    _extractor = tldextract.TLDExtract(suffix_list_urls=())
except Exception:
    _extractor = None


def registered_domain(url: str) -> str:
    """eTLD+1 of a URL (e.g. www.google.com -> google.com); '' if unavailable."""
    if not url or _extractor is None:
        return ""
    try:
        ext = _extractor(url)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass
    return ""


def _is_shared_host(url: str, reg: str) -> bool:
    if reg in _EXTRA_EXCLUDED:
        return True
    try:
        host = (urlparse(url if "://" in url else "https://" + url).hostname or "").lower()
    except Exception:
        host = url.lower()
    return any(fh in host for fh in FREE_HOSTS)


def is_verified(url: str) -> bool:
    """True only when the registered domain is allowlisted AND not a shared host."""
    if not _verified:
        return False
    reg = registered_domain(url)
    if not reg or reg not in _verified:
        return False
    return not _is_shared_host(url, reg)
