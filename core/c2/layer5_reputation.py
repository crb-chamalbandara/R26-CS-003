"""
C2 Layer 5 — Reputation check
Queries PhishTank public API for real-time URL reputation.
Falls back gracefully when network is unavailable.
No API key required — PhishTank public endpoint.
"""
import httpx

PHISHTANK_URL = "https://checkurl.phishtank.com/checkurl/"


async def _check_phishtank(url: str) -> tuple[bool, str]:
<<<<<<< HEAD
    """POST url to PhishTank and return (is_phishing, detail_string)."""
    try:
        import urllib.parse as _up
        encoded = _up.quote(url, safe="")
        async with httpx.AsyncClient(timeout=6) as client:
            r = await client.post(
                PHISHTANK_URL,
                data={"url": encoded, "format": "json"},
                headers={"User-Agent": "phishtank/websentinel"},
=======
    # httpx form-encodes the data dict for us — passing a pre-`quote()`d value
    # double-encodes the URL and PhishTank then never matches.
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.post(
                PHISHTANK_URL,
                data={"url": url, "format": "json"},
                headers={"User-Agent": "phishtank/websentinel"}
>>>>>>> main
            )
            if r.status_code != 200:
                return False, ""
            data = r.json()
<<<<<<< HEAD
            results = data.get("results", {})
            if results.get("in_database") and results.get("valid"):
                return True, "PhishTank: confirmed phishing URL"
=======
            results = data.get("results", {}) or {}
            if results.get("in_database") and results.get("valid"):
                return True, "PhishTank match"
>>>>>>> main
    except Exception:
        pass
    return False, ""


async def check_reputation(url: str, gsb_key: str = "") -> dict:
    """
    Layer 5 reputation check using PhishTank.
    gsb_key parameter is accepted but unused (kept for API compatibility).
    """
    pt_hit, pt_detail = await _check_phishtank(url)

<<<<<<< HEAD
=======
    if gsb_hit:
        detail = f"Google Safe Browsing: {gsb_type}"
        return {"score": 0.85, "flagged": True, "source": "GSB", "detail": detail}
>>>>>>> main
    if pt_hit:
        return {"score": 0.90, "flagged": True, "source": "PhishTank", "detail": pt_detail}

<<<<<<< HEAD
    return {"score": 0.0, "detail": "PhishTank: clean"}
=======
    detail = "Clean" if gsb_key else "GSB key not configured"
    return {"score": 0.0, "flagged": False, "source": "none", "detail": detail}
>>>>>>> main
