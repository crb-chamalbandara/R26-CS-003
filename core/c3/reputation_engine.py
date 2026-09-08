"""
C3 reputation engine — beacon-triggered only.

Two sources:
  • AbuseIPDB  (IP confidence score)
  • VirusTotal  (domain report — multi-engine malicious/suspicious verdict count)

Called only when a BEACON verdict is confirmed, not on every analysis cycle,
to stay within free-tier API rate limits.

The result is shown to the analyst as supporting evidence on a confirmed
beacon. It is NOT an input to the risk score — see core/c3/risk_fusion.py,
where the score is ML + heuristic only.

(VirusTotal replaced Google Safe Browsing here on 2026-08-29. GSB is a
phishing/malware URL blocklist and is still used, unchanged, by C2's own
Layer-5 phishing check — this module no longer imports or depends on it.
OTX AlienVault was removed on 2026-08-30.)
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from typing import Optional

import httpx

# Both API keys are supplied at runtime from Settings (core/settings.json,
# gitignored) — never hardcode credentials in source. main.py forwards them via
# these set_*_key() functions at startup and whenever Settings are saved.
_abuseipdb_key: str = ""
_virustotal_key: str = ""


def set_abuseipdb_key(key: str) -> None:
    global _abuseipdb_key
    _abuseipdb_key = (key or "").strip()


def set_virustotal_key(key: str) -> None:
    global _virustotal_key
    _virustotal_key = (key or "").strip()


class C3ReputationEngine:
    _CACHE_TTL = 1800  # 30 min — beacon re-checks are rare

    def __init__(self) -> None:
        self._client: Optional[httpx.AsyncClient] = None
        self._cache: dict[str, dict] = {}

    # ── Public ────────────────────────────────────────────────────────────────

    def ti_available(self) -> bool:
        # True once at least one host/domain-reputation source (AbuseIPDB or
        # VirusTotal) is configured via Settings.
        return bool(_abuseipdb_key or _virustotal_key)

    def cached_score(self, host: str) -> Optional[float]:
        """Last combined TI score for a host if it is still fresh AND was a
        real hit (flagged), else None.

        score_beacon() populates the cache on the first beacon-triggered
        lookup. Re-reading it here lets the analyzer feed a *stable*
        reputation signal into every fusion cycle afterwards, instead of
        passing None between cycles (which made the fused score visibly
        oscillate once a beacon was confirmed) or re-hitting the rate-limited
        APIs every 10 s. A clean lookup (flagged is False) still returns None
        so it never dilutes the fused score with a spurious 0.0."""
        entry = self._cache.get(self._clean_host(host))
        if not entry or entry.get("expires_at", 0) <= time.time():
            return None
        payload = entry.get("payload") or {}
        if not payload.get("flagged"):
            return None
        try:
            return float(payload.get("score"))
        except (TypeError, ValueError):
            return None

    def cached_result(self, host: str) -> Optional[dict]:
        """The full last threat-intel result for a host if it is still fresh,
        whether flagged or clean: {score, flagged, sources, detail}.

        Unlike cached_score(), this also returns clean (0.0) results — the
        analyzer/dashboard show the real per-source numbers as evidence on a
        confirmed beacon, and "AbuseIPDB 0% / VirusTotal 0%" is a meaningful,
        real answer, not an absence of one. Returns None only when no lookup
        has run for this host yet (or the cached one has expired)."""
        entry = self._cache.get(self._clean_host(host))
        if not entry or entry.get("expires_at", 0) <= time.time():
            return None
        payload = entry.get("payload")
        return dict(payload) if isinstance(payload, dict) else None

    async def score_beacon(self, host: str, sample_url: str) -> dict:
        """
        Run both TI sources against a confirmed beacon host/URL.
        Returns a combined result with per-source breakdown.
        """
        clean_host = self._clean_host(host)
        if not clean_host:
            return self._empty("empty host")

        cached = self._cache.get(clean_host)
        if cached and cached.get("expires_at", 0) > time.time():
            return cached["payload"]

        if self._is_private_or_local(clean_host):
            return self._empty("local host — skipped")

        ips = await self._resolve_ips(clean_host)

        # Run both sources concurrently
        tasks: list = [
            self._check_abuseipdb(ips[0]) if ips else self._noop("abuseipdb"),
            self._check_virustotal(clean_host),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        sources: dict[str, float] = {}
        for result in results:
            if isinstance(result, Exception):
                continue
            name, value = result
            if value is not None:
                sources[name] = round(float(value), 4)

        combined = max(sources.values()) if sources else 0.0
        flagged  = combined >= 0.5

        parts = [f"{k}={v:.2f}" for k, v in sources.items()]
        detail = ("FLAGGED — " if flagged else "Clean — ") + ", ".join(parts) if parts else "no TI data"

        payload = {
            "score":   round(combined, 4),
            "flagged": flagged,
            "sources": sources,
            "detail":  detail,
        }
        self._cache[clean_host] = {"expires_at": time.time() + self._CACHE_TTL, "payload": payload}
        return payload

    # ── Sources ───────────────────────────────────────────────────────────────

    async def _check_abuseipdb(self, ip: str) -> tuple[str, Optional[float]]:
        if not _abuseipdb_key:
            return "abuseipdb", None
        try:
            client = await self._client_instance()
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": _abuseipdb_key, "Accept": "application/json"},
            )
            if resp.status_code != 200:
                return "abuseipdb", None
            data = resp.json()
            raw = float(((data.get("data") or {}).get("abuseConfidenceScore") or 0.0))
            return "abuseipdb", max(0.0, min(1.0, raw / 100.0))
        except Exception:
            return "abuseipdb", None

    async def _check_virustotal(self, host: str) -> tuple[str, Optional[float]]:
        """VirusTotal API v3 domain report. Score is derived from how many of
        VT's ~90 scanning engines flag the beacon's destination domain.

        The engine-count -> score mapping is calibrated against real VT data
        (measured 2026-08-29), NOT a round-number guess:
          google.com    -> malicious=1  (a single chronically-noisy engine)
          microsoft.com -> malicious=0
          cloudflare.com-> malicious=0
          SB test host  -> malicious=2 suspicious=2
          EICAR test    -> malicious=3 suspicious=2
        A lone `malicious == 1` is therefore treated as NO evidence -- scoring
        it (the previous `malicious >= 1` rule did) flagged google.com and many
        other Fortune-500 domains as malicious beacon destinations. Two engines
        is a weak signal, only actionable with corroboration; >= 3 is solid.

          malicious >= 3         -> 0.55 + 0.06*malicious + 0.03*suspicious (cap 0.95)
          malicious == 2         -> 0.50 if suspicious >= 2 else 0.35
          malicious <= 1         -> 0.30 if suspicious >= 4 else 0.0
        A 404 (domain unknown to VT) is 0.0, not None -- "no evidence", same as
        a clean AbuseIPDB result. 401/429/5xx return None so a bad key or a
        rate-limit hit simply drops this source instead of scoring it 0."""
        if not _virustotal_key or not host:
            return "virustotal", None
        try:
            client = await self._client_instance()
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{host}",
                headers={"x-apikey": _virustotal_key, "accept": "application/json"},
            )
            if resp.status_code == 404:
                return "virustotal", 0.0
            if resp.status_code != 200:
                return "virustotal", None
            attrs = ((resp.json().get("data") or {}).get("attributes") or {})
            stats = attrs.get("last_analysis_stats") or {}
            malicious = int(stats.get("malicious") or 0)
            suspicious = int(stats.get("suspicious") or 0)
            if malicious >= 3:
                return "virustotal", min(0.95, 0.55 + 0.06 * malicious + 0.03 * suspicious)
            if malicious == 2:
                return "virustotal", 0.50 if suspicious >= 2 else 0.35
            if suspicious >= 4:
                return "virustotal", 0.30
            return "virustotal", 0.0
        except Exception:
            return "virustotal", None

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _client_instance(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=8.0)
        return self._client

    async def _resolve_ips(self, host: str) -> list[str]:
        try:
            infos = await asyncio.to_thread(socket.getaddrinfo, host, None)
            ips = sorted({info[4][0] for info in infos})
            return [ip for ip in ips if not self._is_private_or_local(ip)]
        except Exception:
            return []

    @staticmethod
    def _clean_host(host: str) -> str:
        return str(host or "").lower().strip("[]")

    @staticmethod
    def _is_private_or_local(host: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
        except ValueError:
            return host in {"localhost"}

    @staticmethod
    async def _noop(name: str) -> tuple[str, None]:
        return name, None

    @staticmethod
    def _empty(reason: str) -> dict:
        return {"score": 0.0, "flagged": False, "sources": {}, "detail": reason}


c3_reputation_engine = C3ReputationEngine()

# =============================================================================
# WHAT THIS FILE DOES — plain English summary
# =============================================================================
#
# The reputation engine runs extra threat-intelligence checks only when a
# confirmed BEACON needs enrichment. This avoids exhausting API quotas during
# normal operation.
#
# Given a host and a sample URL it concurrently queries two sources:
#  - AbuseIPDB (IP confidence score),
#  - VirusTotal (domain report — count of engines flagging it malicious/suspicious).
#
# The engine resolves hosts to public IPs, skips private or local addresses,
# caches results for 30 minutes, and returns a simple combined score and a
# human-readable detail string. This result is analyst-facing evidence shown
# on a confirmed beacon; it is NOT fed into the risk score (see risk_fusion.py).
# =============================================================================
