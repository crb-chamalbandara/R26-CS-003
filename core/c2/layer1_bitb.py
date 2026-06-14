"""
C2 Layer 1 — Browser-in-the-Browser (BitB) / HTML Phishing detection
Combines a trained DOM-feature ML model with hard-coded heuristics.
Run scripts/prepare_html_dataset.py to train the model.

The scoring core is synchronous; check_bitb runs it in a worker thread so a large DOM
parse never blocks the event loop (important now that multiple tabs are analyzed at once).
"""
import re
import os
import pickle
import asyncio
import hashlib
from urllib.parse import urlparse

try:
    import pandas as pd
except Exception:
    pd = None
try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None

# ── Load trained model (optional) ────────────────────────────
_bitb_model = None
_MODEL_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "models", "bitb_classifier.pkl"
)
try:
    with open(_MODEL_PATH, "rb") as _f:
        _bitb_model = pickle.load(_f)
    print("[L1] Loaded trained BitB HTML classifier model")
except FileNotFoundError:
    print("[L1] No BitB model found — using heuristics only (run scripts/prepare_html_dataset.py)")

BRANDS = {
    "paypal", "microsoft", "apple", "amazon", "google", "facebook",
    "instagram", "netflix", "dropbox", "linkedin", "twitter",
    "wellsfargo", "chase", "hsbc", "dhl", "fedex", "irs",
}

_FEATURE_COLS = [
    "n_iframes", "has_fixed_iframe", "max_zindex", "full_viewport",
    "drag_prevent", "n_forms", "n_inputs", "n_pw_inputs",
    "n_hidden_inputs", "n_ext_scripts", "form_ext_action",
    "title_brand", "favicon_brand", "has_overlay",
    "has_redirect", "html_size_kb",
]

# ── Pre-compiled regexes (hot path — compiled once at import) ──
_RE_IFRAME_FIXED = re.compile(r'<iframe[^>]*style=["\'][^"\']*position\s*:\s*fixed')
_RE_ZINDEX_HIGH  = re.compile(r'z-index\s*:\s*(99[0-9]{2,}|[1-9]\d{4,})')
_RE_WIDTH_FULL   = re.compile(r'width\s*:\s*100(vw|%)')
_RE_HEIGHT_FULL  = re.compile(r'height\s*:\s*100(vh|%)')
_RE_DRAG         = re.compile(r'(ondragstart|onselectstart|user-select\s*:\s*none)')
_RE_FAKE_BAR     = re.compile(r'(fake.*address|address.*bar|browser.*bar)')
_RE_ZINDEX_NUM   = re.compile(r'z-index\s*:\s*(\d+)')
_RE_POS_FIXED    = re.compile(r'position\s*:\s*fixed')
_RE_OVERLAY      = re.compile(r'\b(overlay|modal)\b')
_RE_WINDOW_LOC   = re.compile(r'window\.location')

# ── Result cache — L1 is a pure function of (url, dom); memoize to skip re-parsing the
# same page (reloads, SPA re-fires, multiple tabs on the same site). ──
_l1_cache: dict = {}
_L1_CACHE_MAX = 256


def _extract_html_features(dom: str, lo: str, url: str = "") -> dict:
    """Extract the same 16 DOM features used during training. `lo` is the
    already-lowercased DOM (computed once by the caller)."""
    if BeautifulSoup is None:
        return {col: 0 for col in _FEATURE_COLS}
    try:
        soup = BeautifulSoup(dom, "lxml")
    except Exception:
        return {col: 0 for col in _FEATURE_COLS}

    iframes = soup.find_all("iframe")
    forms   = soup.find_all("form")
    inputs  = soup.find_all("input")
    scripts = soup.find_all("script")

    title = ""
    if soup.title and soup.title.string:
        title = soup.title.string.lower()

    favicon_url = ""
    for lnk in soup.find_all("link"):
        rel = lnk.get("rel", [])
        if isinstance(rel, list):
            rel = " ".join(rel)
        if "icon" in rel.lower():
            favicon_url = lnk.get("href", "").lower()
            break

    zindices = [int(m) for m in _RE_ZINDEX_NUM.findall(lo)]
    max_zindex = min(max(zindices) if zindices else 0, 9999)

    has_fixed_iframe = int(bool(iframes) and bool(_RE_POS_FIXED.search(lo)))
    full_viewport = int(
        bool(_RE_WIDTH_FULL.search(lo)) and bool(_RE_HEIGHT_FULL.search(lo))
    )
    drag_prevent = int(bool(_RE_DRAG.search(lo)))
    n_pw_inputs     = sum(1 for i in inputs if i.get("type", "").lower() == "password")
    n_hidden_inputs = sum(1 for i in inputs if i.get("type", "").lower() == "hidden")
    n_ext_scripts   = sum(1 for s in scripts if s.get("src", "").startswith("http"))

    form_ext_action = 0
    page_host = urlparse(url).hostname or "" if url else ""
    for f in forms:
        action = f.get("action", "")
        if action.startswith("http") and page_host:
            form_host = urlparse(action).hostname or ""
            if form_host and form_host != page_host:
                form_ext_action = 1
                break

    title_brand   = int(any(b in title for b in BRANDS))
    favicon_brand = int(any(b in favicon_url for b in BRANDS))
    has_overlay   = int(bool(_RE_OVERLAY.search(lo)))
    has_redirect  = int(bool(_RE_WINDOW_LOC.search(lo)))

    return {
        "n_iframes":        len(iframes),
        "has_fixed_iframe": has_fixed_iframe,
        "max_zindex":       max_zindex,
        "full_viewport":    full_viewport,
        "drag_prevent":     drag_prevent,
        "n_forms":          len(forms),
        "n_inputs":         len(inputs),
        "n_pw_inputs":      n_pw_inputs,
        "n_hidden_inputs":  n_hidden_inputs,
        "n_ext_scripts":    n_ext_scripts,
        "form_ext_action":  form_ext_action,
        "title_brand":      title_brand,
        "favicon_brand":    favicon_brand,
        "has_overlay":      has_overlay,
        "has_redirect":     has_redirect,
        "html_size_kb":     len(dom) // 1024,
    }


def _score_bitb(url: str, dom: str) -> dict:
    """Synchronous scoring core — heuristics, then overlay ML probability if available.
    Final score = max(heuristic, ml_prob) so heuristic signals are never suppressed."""
    dom_lo = dom.lower()                 # lowercased once, reused by the heuristics + features
    heuristic_score = 0.0
    flags = []

    # ── Heuristic rules ──────────────────────────────────────
    if _RE_IFRAME_FIXED.search(dom_lo):
        heuristic_score += 0.4
        flags.append("fixed-pos iframe")

    if _RE_ZINDEX_HIGH.search(dom_lo):
        heuristic_score += 0.2
        flags.append("high z-index")

    if _RE_WIDTH_FULL.search(dom_lo) and _RE_HEIGHT_FULL.search(dom_lo):
        heuristic_score += 0.2
        flags.append("full-viewport coverage")

    if _RE_DRAG.search(dom_lo):
        heuristic_score += 0.15
        flags.append("drag-prevention JS")

    if _RE_FAKE_BAR.search(dom_lo):
        heuristic_score += 0.3
        flags.append("fake address-bar element")

    heuristic_score = min(1.0, heuristic_score)

    # ── ML model overlay ──────────────────────────────────────
    if _bitb_model is not None and pd is not None:
        try:
            feats = _extract_html_features(dom, dom_lo, url)
            X = pd.DataFrame([feats])[_FEATURE_COLS]
            ml_prob = float(_bitb_model.predict_proba(X)[0][1])
            final_score = max(heuristic_score, ml_prob)
            detail_parts = [f"ML:{ml_prob:.2f}"]
            if flags:
                detail_parts.append(", ".join(flags))
            return {"score": round(final_score, 4), "detail": " | ".join(detail_parts)}
        except Exception:
            pass  # fall through to heuristic result

    detail = ", ".join(flags) if flags else "No BitB indicators"
    return {"score": round(heuristic_score, 4), "detail": detail}


async def check_bitb(url: str, dom: str) -> dict:
    """Detect BitB / HTML phishing. Memoized by (url, DOM digest) — identical pages skip the
    parse; on a miss the CPU-bound scoring runs in a worker thread so the event loop stays
    responsive while other tabs are analyzed."""
    if not dom:
        return {"score": 0.0, "detail": "No DOM available"}
    key = (url, hashlib.blake2b(dom.encode("utf-8", "replace"), digest_size=16).digest())
    cached = _l1_cache.get(key)
    if cached is not None:
        return cached
    res = await asyncio.to_thread(_score_bitb, url, dom)
    _l1_cache[key] = res
    if len(_l1_cache) > _L1_CACHE_MAX:
        for old in list(_l1_cache)[:len(_l1_cache) - _L1_CACHE_MAX]:
            _l1_cache.pop(old, None)
    return res
