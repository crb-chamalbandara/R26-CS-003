"""
C2 Layer 1 — Browser-in-the-Browser (BitB) / HTML Phishing detection
Combines a trained DOM-feature ML model with hard-coded heuristics.
Run scripts/prepare_html_dataset.py to train the model.
"""
import re
import os
import pickle
from urllib.parse import urlparse

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


def _extract_html_features(dom: str, url: str = "") -> dict:
    """Extract the same 16 DOM features used during training."""
    lo = dom.lower()
    try:
        from bs4 import BeautifulSoup
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

    zindices = [int(m) for m in re.findall(r"z-index\s*:\s*(\d+)", lo)]
    max_zindex = min(max(zindices) if zindices else 0, 9999)

    has_fixed_iframe = int(
        bool(iframes) and bool(re.search(r"position\s*:\s*fixed", lo))
    )
    full_viewport = int(
        bool(re.search(r"width\s*:\s*100(vw|%)", lo))
        and bool(re.search(r"height\s*:\s*100(vh|%)", lo))
    )
    drag_prevent = int(
        bool(re.search(r"(ondragstart|onselectstart|user-select\s*:\s*none)", lo))
    )
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
    has_overlay   = int(bool(re.search(r"\b(overlay|modal)\b", lo)))
    has_redirect  = int(bool(re.search(r"window\.location", lo)))

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


async def check_bitb(url: str, dom: str) -> dict:
    """
    Detect BitB / HTML phishing.
    Runs heuristic checks first, then overlays ML model probability if available.
    Final score = max(heuristic, ml_prob) so heuristic signals are never suppressed.
    """
    if not dom:
        return {"score": 0.0, "detail": "No DOM available"}

    dom_lo = dom.lower()
    heuristic_score = 0.0
    flags = []

    # ── Heuristic rules (unchanged) ──────────────────────────
    if re.search(r'<iframe[^>]*style=["\'][^"\']*position\s*:\s*fixed', dom_lo):
        heuristic_score += 0.4
        flags.append("fixed-pos iframe")

    if re.search(r'z-index\s*:\s*(99[0-9]{2,}|[1-9]\d{4,})', dom_lo):
        heuristic_score += 0.2
        flags.append("high z-index")

    if re.search(r'width\s*:\s*100(vw|%)', dom_lo) and re.search(r'height\s*:\s*100(vh|%)', dom_lo):
        heuristic_score += 0.2
        flags.append("full-viewport coverage")

    if re.search(r'(ondragstart|onselectstart|user-select\s*:\s*none)', dom_lo):
        heuristic_score += 0.15
        flags.append("drag-prevention JS")

    if re.search(r'(fake.*address|address.*bar|browser.*bar)', dom_lo):
        heuristic_score += 0.3
        flags.append("fake address-bar element")

    heuristic_score = min(1.0, heuristic_score)

    # ── ML model overlay ──────────────────────────────────────
    if _bitb_model is not None:
        try:
            import pandas as pd
            feats = _extract_html_features(dom, url)
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
