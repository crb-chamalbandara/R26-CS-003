"""
C2 Layer 5 — Reputation check
Queries Google Safe Browsing API v4 + PhishTank (public feed), concurrently, with a
short-lived per-URL cache and a shared HTTP client so the network is not re-hit on every
navigation.
"""
import asyncio
import time

import httpx

GSB_URL       = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
PHISHTANK_URL = "https://checkurl.phishtank.com/checkurl/"
_TIMEOUT      = 3.0
_CACHE_TTL    = 600.0   # seconds — repeat visits within this window skip the network

# Shared async client (created lazily on the running loop, reused across calls).
_client: httpx.AsyncClient | None = None
# url-key -> (expiry_ts, result_dict)
_cache: dict = {}


def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(timeout=_TIMEOUT)
    return _client


async def aclose() -> None:
    """Close the shared HTTP client on shutdown (avoids an unclosed-client warning)."""
    global _client
    if _client is not None and not _client.is_closed:
        try:
            await _client.aclose()
        except Exception:
            pass
    _client = None


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
        r = await _get_client().post(f"{GSB_URL}?key={api_key}", json=payload)
        matches = r.json().get("matches", [])
        if matches:
            return True, matches[0].get("threatType", "THREAT")
    except Exception:
        pass
    return False, ""


async def _check_phishtank(url: str) -> tuple[bool, str]:
    # httpx form-encodes the data dict for us — passing a pre-`quote()`d value
    # double-encodes the URL and PhishTank then never matches.
    try:
        r = await _get_client().post(
            PHISHTANK_URL,
            data={"url": url, "format": "json"},
            headers={"User-Agent": "phishtank/websentinel"},
        )
        if r.status_code != 200:
            return False, ""
        results = r.json().get("results", {}) or {}
        if results.get("in_database") and results.get("valid"):
            return True, "PhishTank match"
    except Exception:
        pass
    return False, ""


async def check_reputation(url: str, gsb_key: str = "", phishtank_enabled: bool = True) -> dict:
    key = (url, bool(gsb_key), bool(phishtank_enabled))
    hit = _cache.get(key)
    now = time.monotonic()
    if hit and hit[0] > now:
        return hit[1]

    # Run both lookups concurrently; PhishTank is gated and a no-op when disabled.
    async def _pt():
        return await _check_phishtank(url) if phishtank_enabled else (False, "")

    (gsb_hit, gsb_type), (pt_hit, pt_detail) = await asyncio.gather(
        _check_gsb(url, gsb_key), _pt()
    )

    # Both feeds' verdicts, not just the one that won. A stored alert that says
    # only "PhishTank" cannot answer "did Safe Browsing also see this, or was it
    # simply not configured?" — which changes how much weight to give the hit.
    evidence = {
        "gsb_queried":       bool(gsb_key),
        "gsb_hit":           bool(gsb_hit),
        "gsb_threat_type":   gsb_type or None,
        "phishtank_queried": bool(phishtank_enabled),
        "phishtank_hit":     bool(pt_hit),
        "phishtank_detail":  pt_detail or None,
    }

    if gsb_hit:
        result = {"score": 0.85, "flagged": True, "source": "GSB",
                  "detail": f"Google Safe Browsing: {gsb_type}", "evidence": evidence}
    elif pt_hit:
        result = {"score": 0.90, "flagged": True, "source": "PhishTank",
                  "detail": pt_detail, "evidence": evidence}
    else:
        result = {"score": 0.0, "flagged": False, "source": "none",
                  "detail": "Clean" if gsb_key else "GSB key not configured",
                  "evidence": evidence}

    _cache[key] = (now + _CACHE_TTL, result)
    if len(_cache) > 2000:                 # bound memory
        for k in list(_cache)[:1000]:
            _cache.pop(k, None)
    return result
