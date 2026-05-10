"""
C2 Layer 5 — Reputation check
Queries Google Safe Browsing API v4 + PhishTank (public feed).
Both are async; falls back gracefully when keys/network unavailable.
"""
import httpx
from urllib.parse import urlparse


GSB_URL       = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
PHISHTANK_URL = "https://checkurl.phishtank.com/checkurl/"


async def _check_gsb(url: str, api_key: str) -> tuple[bool, str]:
    if not api_key:
        return False, ""
    payload = {
        "client":     {"clientId": "websentinel", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                 "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":    [{"url": url}],
        }
    }
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.post(f"{GSB_URL}?key={api_key}", json=payload)
            data = r.json()
            matches = data.get("matches", [])
            if matches:
                return True, matches[0].get("threatType", "THREAT")
    except Exception:
        pass
    return False, ""


async def _check_phishtank(url: str) -> tuple[bool, str]:
    # httpx form-encodes the data dict for us — passing a pre-`quote()`d value
    # double-encodes the URL and PhishTank then never matches.
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.post(
                PHISHTANK_URL,
                data={"url": url, "format": "json"},
                headers={"User-Agent": "phishtank/websentinel"}
            )
            if r.status_code != 200:
                return False, ""
            data = r.json()
            results = data.get("results", {}) or {}
            if results.get("in_database") and results.get("valid"):
                return True, "PhishTank match"
    except Exception:
        pass
    return False, ""


async def check_reputation(url: str, gsb_key: str = "") -> dict:
    gsb_hit, gsb_type  = await _check_gsb(url, gsb_key)
    pt_hit,  pt_detail = await _check_phishtank(url)

    if gsb_hit:
        return {"score": 0.85, "detail": f"Google Safe Browsing: {gsb_type}"}
    if pt_hit:
        return {"score": 0.90, "detail": pt_detail}

    return {"score": 0.0, "detail": "Clean" if gsb_key else "GSB key not configured"}
