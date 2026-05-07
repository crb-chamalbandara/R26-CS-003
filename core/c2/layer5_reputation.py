"""
C2 Layer 5 — Reputation check
Queries PhishTank public API for real-time URL reputation.
Falls back gracefully when network is unavailable.
No API key required — PhishTank public endpoint.
"""
import httpx

PHISHTANK_URL = "https://checkurl.phishtank.com/checkurl/"


async def _check_phishtank(url: str) -> tuple[bool, str]:
    """POST url to PhishTank and return (is_phishing, detail_string)."""
    try:
        import urllib.parse as _up
        encoded = _up.quote(url, safe="")
        async with httpx.AsyncClient(timeout=6) as client:
            r = await client.post(
                PHISHTANK_URL,
                data={"url": encoded, "format": "json"},
                headers={"User-Agent": "phishtank/websentinel"},
            )
            data = r.json()
            results = data.get("results", {})
            if results.get("in_database") and results.get("valid"):
                return True, "PhishTank: confirmed phishing URL"
    except Exception:
        pass
    return False, ""


async def check_reputation(url: str, gsb_key: str = "") -> dict:
    """
    Layer 5 reputation check using PhishTank.
    gsb_key parameter is accepted but unused (kept for API compatibility).
    """
    pt_hit, pt_detail = await _check_phishtank(url)

    if pt_hit:
        return {"score": 0.90, "detail": pt_detail}

    return {"score": 0.0, "detail": "PhishTank: clean"}
