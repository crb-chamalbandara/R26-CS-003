"""
C2 Layer 3 — Visual similarity
Compares page screenshot pHash against brand logo reference hashes.
Requires: Pillow, imagehash
data/logo_hashes.json populated by scripts/download_logos.py
"""
import base64
import json
import os
from io import BytesIO

# Path relative to project root (two levels up from core/c2/)
_HASH_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "logo_hashes.json")
_logo_hashes: dict = {}

try:
    with open(_HASH_PATH) as f:
        _logo_hashes = json.load(f)
    print(f"[L3] Loaded {len(_logo_hashes)} logo hashes")
except FileNotFoundError:
    print("[L3] No logo_hashes.json — visual layer will return 0 until populated")


async def check_visual(url: str, screenshot_b64: str) -> dict:
    """
    Args:
        url: current page URL (used for brand hint)
        screenshot_b64: base64-encoded JPEG screenshot from Playwright
    Returns:
        {"score": float 0-1, "detail": str}
    """
    if not screenshot_b64 or not _logo_hashes:
        return {"score": 0.0, "detail": "No screenshot or logo hashes available"}

    try:
        import imagehash
        from PIL import Image

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
            from urllib.parse import urlparse
            hostname = (urlparse(url).hostname or "").lower()
            if best_brand and best_brand.lower() not in hostname:
                score  = min(1.0, best_sim)
                detail = f"Impersonating {best_brand} (similarity {best_sim:.0%})"
                return {"score": round(score, 4), "detail": detail}

        return {"score": 0.0, "detail": f"No brand match (best: {best_brand or 'none'} @ {best_sim:.0%})"}

    except ImportError:
        return {"score": 0.0, "detail": "imagehash not installed"}
    except Exception as e:
        return {"score": 0.0, "detail": f"Error: {e}"}
