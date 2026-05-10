"""
C3 reputation engine.

Provides optional threat intelligence scoring with caching and async queries.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import time
from typing import Optional

import httpx


_FEODO_JSON_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
_FEODO_CSV_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

_CDN_PATTERNS = (
    "cloudflare.net",
    "cloudfront.net",
    "akamai",
    "akamaiedge",
    "edgekey",
    "edgesuite",
    "fastly",
    "azureedge",
)

_TTL_CLEAN = 60 * 60
_TTL_SUSPICIOUS = 15 * 60
_TTL_MALICIOUS = 24 * 60 * 60


class C3ReputationEngine:
    def __init__(self) -> None:
        self._client: Optional[httpx.AsyncClient] = None
        self._cache: dict[str, dict] = {}
        self._feodo_ips: set[str] = set()
        self._feodo_last_fetch = 0.0
        self._feodo_refresh_s = 6 * 60 * 60
        self._urlhaus_enabled = True
        self._keys = {
            "abuseipdb": os.getenv("C3_ABUSEIPDB_KEY", "").strip(),
            "otx": os.getenv("C3_OTX_KEY", "").strip(),
            "virustotal": os.getenv("C3_VT_KEY", "").strip(),
        }

    def ti_available(self) -> bool:
        return self._urlhaus_enabled or bool(self._feodo_ips) or any(self._keys.values())

    async def score_host(self, host: str, sample_url: str | None, should_query: bool) -> dict:
        clean_host = self._clean_host(host)
        if not clean_host:
            return {"score": None, "sources": {}, "detail": "empty host"}
        if not should_query:
            return {"score": None, "sources": {}, "detail": "gated"}

        cached = self._cache.get(clean_host)
        now = time.time()
        if cached and cached.get("expires_at", 0) > now:
            return cached["payload"]

        if self._is_private_or_local(clean_host):
            return {"score": None, "sources": {}, "detail": "local host"}

        is_cdn = self._is_cdn_host(clean_host)
        ips = [] if is_cdn else await self._resolve_ips(clean_host)

        sources: dict[str, float] = {}
        tasks = []

        tasks.append(self._check_urlhaus(clean_host))
        if ips:
            tasks.append(self._check_feodo(ips))
        if self._keys.get("otx"):
            tasks.append(self._check_otx(clean_host, ips))
        if ips and self._keys.get("abuseipdb"):
            tasks.append(self._check_abuseipdb(ips[0]))
        if self._keys.get("virustotal"):
            tasks.append(self._check_virustotal(clean_host))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception):
                continue
            name, value = result
            if value is None:
                continue
            sources[name] = float(value)

        score = max(sources.values()) if sources else None
        detail = "reputation: " + ", ".join(f"{k}={v:.2f}" for k, v in sources.items()) if sources else "no ti hits"
        payload = {"score": score, "sources": sources, "detail": detail}

        if score is not None:
            ttl = self._ttl_for_score(score)
            self._cache[clean_host] = {"expires_at": now + ttl, "payload": payload}

        return payload

    async def _client_instance(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=8.0)
        return self._client

    async def _check_feodo(self, ips: list[str]) -> tuple[str, Optional[float]]:
        await self._ensure_feodo_loaded()
        if not self._feodo_ips:
            return "feodo", None
        hit = any(ip in self._feodo_ips for ip in ips)
        return "feodo", 1.0 if hit else 0.0

    async def _check_urlhaus(self, host: str) -> tuple[str, Optional[float]]:
        if not self._urlhaus_enabled:
            return "urlhaus", None
        try:
            client = await self._client_instance()
            resp = await client.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": host})
            if resp.status_code != 200:
                return "urlhaus", None
            data = resp.json()
            if data.get("query_status") != "ok":
                return "urlhaus", 0.0
            if int(data.get("url_count") or 0) > 0:
                return "urlhaus", 1.0
            return "urlhaus", 0.0
        except Exception:
            return "urlhaus", None

    async def _check_otx(self, host: str, ips: list[str]) -> tuple[str, Optional[float]]:
        key = self._keys.get("otx")
        if not key:
            return "otx", None
        tasks = [self._otx_domain(host, key)]
        if ips:
            tasks.append(self._otx_ip(ips[0], key))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        scores = [val for val in results if isinstance(val, (int, float))]
        return "otx", max(scores) if scores else None

    async def _otx_domain(self, host: str, key: str) -> Optional[float]:
        try:
            client = await self._client_instance()
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{host}/general"
            resp = await client.get(url, headers={"X-OTX-API-KEY": key})
            if resp.status_code != 200:
                return None
            data = resp.json()
            pulses = int(((data.get("pulse_info") or {}).get("count") or 0))
            if pulses <= 0:
                return 0.0
            return min(1.0, pulses / 10.0)
        except Exception:
            return None

    async def _otx_ip(self, ip: str, key: str) -> Optional[float]:
        try:
            client = await self._client_instance()
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
            resp = await client.get(url, headers={"X-OTX-API-KEY": key})
            if resp.status_code != 200:
                return None
            data = resp.json()
            pulses = int(((data.get("pulse_info") or {}).get("count") or 0))
            if pulses <= 0:
                return 0.0
            return min(1.0, pulses / 10.0)
        except Exception:
            return None

    async def _check_abuseipdb(self, ip: str) -> tuple[str, Optional[float]]:
        key = self._keys.get("abuseipdb")
        if not key:
            return "abuseipdb", None
        try:
            client = await self._client_instance()
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": key, "Accept": "application/json"},
            )
            if resp.status_code != 200:
                return "abuseipdb", None
            data = resp.json()
            score = float(((data.get("data") or {}).get("abuseConfidenceScore") or 0.0)) / 100.0
            return "abuseipdb", max(0.0, min(1.0, score))
        except Exception:
            return "abuseipdb", None

    async def _check_virustotal(self, host: str) -> tuple[str, Optional[float]]:
        key = self._keys.get("virustotal")
        if not key:
            return "virustotal", None
        try:
            client = await self._client_instance()
            url = f"https://www.virustotal.com/api/v3/domains/{host}"
            resp = await client.get(url, headers={"x-apikey": key})
            if resp.status_code != 200:
                return "virustotal", None
            data = resp.json()
            stats = (((data.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {})
            total = sum(int(v) for v in stats.values())
            malicious = int(stats.get("malicious") or 0)
            if total <= 0:
                return "virustotal", 0.0
            return "virustotal", max(0.0, min(1.0, malicious / total))
        except Exception:
            return "virustotal", None

    async def _ensure_feodo_loaded(self) -> None:
        now = time.time()
        if self._feodo_ips and (now - self._feodo_last_fetch) < self._feodo_refresh_s:
            return
        try:
            client = await self._client_instance()
            resp = await client.get(_FEODO_JSON_URL)
            if resp.status_code == 200:
                data = resp.json()
                ips = {item.get("ip_address") for item in data if isinstance(item, dict)}
                self._feodo_ips = {ip for ip in ips if ip}
                self._feodo_last_fetch = now
                return
        except Exception:
            pass

        try:
            client = await self._client_instance()
            resp = await client.get(_FEODO_CSV_URL)
            if resp.status_code != 200:
                return
            lines = resp.text.splitlines()
            ips = set()
            for line in lines:
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split(",") if p.strip()]
                if parts:
                    ips.add(parts[0])
            if ips:
                self._feodo_ips = ips
                self._feodo_last_fetch = now
        except Exception:
            return

    @staticmethod
    def _is_cdn_host(host: str) -> bool:
        lowered = host.lower()
        return any(pattern in lowered for pattern in _CDN_PATTERNS)

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

    async def _resolve_ips(self, host: str) -> list[str]:
        try:
            infos = await asyncio.to_thread(socket.getaddrinfo, host, None)
            ips = sorted({info[4][0] for info in infos})
            return [ip for ip in ips if not self._is_private_or_local(ip)]
        except Exception:
            return []

    @staticmethod
    def _ttl_for_score(score: float) -> int:
        if score < 0.1:
            return _TTL_CLEAN
        if score < 0.5:
            return _TTL_SUSPICIOUS
        return _TTL_MALICIOUS


c3_reputation_engine = C3ReputationEngine()
