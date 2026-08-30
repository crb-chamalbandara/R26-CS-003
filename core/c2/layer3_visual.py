"""
C2 Layer 3 — Visual similarity
Compares page screenshot pHash against brand logo reference hashes.
Requires: Pillow, imagehash
data/logo_hashes.json populated by scripts/download_logos.py

HAS_HASHES lets callers skip the (expensive) screenshot capture when this layer can't
contribute. Scoring runs in a worker thread to keep the event loop responsive.
"""
import base64
import json
import os
import asyncio
import hashlib
from io import BytesIO
from urllib.parse import urlparse

try:
    import imagehash
    from PIL import Image
except Exception:
    imagehash = None
    Image = None

# Path relative to project root (two levels up from core/c2/)
_HASH_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "logo_hashes.json")
_logo_hashes: dict = {}

try:
    with open(_HASH_PATH) as f:
        _logo_hashes = json.load(f)
    print(f"[L3] Loaded {len(_logo_hashes)} logo hashes")
except FileNotFoundError:
    print("[L3] No logo_hashes.json — visual layer will return 0 until populated")

# True when L3 can actually do something (libs present + reference hashes loaded).
HAS_HASHES = bool(_logo_hashes) and imagehash is not None


def _score_visual(url: str, screenshot_b64: str) -> dict:
    try:
        img_bytes = base64.b64decode(screenshot_b64)
        img = Image.open(BytesIO(img_bytes)).convert("RGB")
        page_hash = imagehash.phash(img)

        best_brand = None
        best_sim   = 0.0
        for brand, h_str in _logo_hashes.items():
            ref_hash = imagehash.hex_to_hash(h_str)
            dist = page_hash - ref_hash
            sim  = max(0.0, 1.0 - dist / 64.0)
            if sim > best_sim:
                best_sim   = sim
                best_brand = brand

        if best_sim > 0.80:
            hostname = (urlparse(url).hostname or "").lower()
            if best_brand and best_brand.lower() not in hostname:
                score  = min(1.0, best_sim)
                detail = f"Impersonating {best_brand} (similarity {best_sim:.0%})"
                return {"score": round(score, 4), "detail": detail}

        return {"score": 0.0, "detail": f"No brand match (best: {best_brand or 'none'} @ {best_sim:.0%})"}
    except Exception as e:
        return {"score": 0.0, "detail": f"Error: {e}"}


# Pure function of (url, screenshot) — memoize so an unchanged page skips the pHash compute.
_l3_cache: dict = {}
_L3_CACHE_MAX = 256


async def check_visual(url: str, screenshot_b64: str) -> dict:
    """
    Args:
        url: current page URL (used for brand hint)
        screenshot_b64: base64-encoded JPEG screenshot from Playwright
    Returns:
        {"score": float 0-1, "detail": str}
    """
    if not screenshot_b64 or not HAS_HASHES:
        return {"score": 0.0, "detail": "No screenshot or logo hashes available"}
    key = (url, hashlib.blake2b(screenshot_b64.encode("ascii", "replace"), digest_size=16).digest())
    cached = _l3_cache.get(key)
    if cached is not None:
        return cached
    res = await asyncio.to_thread(_score_visual, url, screenshot_b64)
    _l3_cache[key] = res
    if len(_l3_cache) > _L3_CACHE_MAX:
        for old in list(_l3_cache)[:len(_l3_cache) - _L3_CACHE_MAX]:
            _l3_cache.pop(old, None)
    return res
