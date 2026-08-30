"""
C2 Layer 5 — Reputation check
Queries PhishTank public API for real-time URL reputation.
Falls back gracefully when network is unavailable.
No API key required — PhishTank public endpoint.
"""
import httpx

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


async def check_reputation(url: str, gsb_key: str = "") -> dict:
    """
    Layer 5 reputation check using PhishTank.
    gsb_key parameter is accepted but unused (kept for API compatibility).
    """
    pt_hit, pt_detail = await _check_phishtank(url)

    if gsb_hit:
        result = {"score": 0.85, "flagged": True, "source": "GSB",
                  "detail": f"Google Safe Browsing: {gsb_type}"}
    elif pt_hit:
        result = {"score": 0.90, "flagged": True, "source": "PhishTank", "detail": pt_detail}
    else:
        result = {"score": 0.0, "flagged": False, "source": "none",
                  "detail": "Clean" if gsb_key else "GSB key not configured"}

    _cache[key] = (now + _CACHE_TTL, result)
    if len(_cache) > 2000:                 # bound memory
        for k in list(_cache)[:1000]:
            _cache.pop(k, None)
    return result
