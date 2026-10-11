"""
Component 1 - Network Intelligence

The sandbox says which hosts an extension talked to. A reviewer's next
questions are: is that server the extension's own, a well-known service, or
something unexplained? where does it live? and what exactly would I put on a
blocklist?

This module answers those from two sources, in order of cost:

  1. what we already know   the domains named in the extension's own code
                            (core/c1/profile.py) against the hosts contacted
  2. DNS                    the IP addresses behind each host

Nothing here changes a verdict. It is evidence for the report, and a lookup that
fails (offline, timeout) is recorded as such instead of being guessed, so an
empty field means "not looked up", never "clean".
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from .profile import _registered_domain

_MAX_DNS_HOSTS = 12
_DNS_TIMEOUT   = 4.0
_MAX_IOC_URLS  = 20

# Registered domains that are shared infrastructure, not the extension vendor's
# own server. A request to one of these is rarely meaningful by itself.
_KNOWN_SERVICES = frozenset((
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "gvt1.com",
    "cloudflare.com", "cloudflareinsights.com", "cloudfront.net", "amazonaws.com",
    "akamaihd.net", "fastly.net", "jsdelivr.net", "cdnjs.com", "unpkg.com",
    "microsoft.com", "windows.net", "azureedge.net", "mozilla.org",
    "youtube.com", "ytimg.com",
))


# ══════════════════════════════════════════════════════════════════════════════
#  Indicators
# ══════════════════════════════════════════════════════════════════════════════

def defang_host(host: str) -> str:
    """example.com -> example[.]com, so a pasted indicator cannot be clicked."""
    return str(host).replace(".", "[.]")


def defang_url(url: str) -> str:
    """https://a.com/p?x=1 -> hxxps[://]a[.]com/p  (scheme and host defanged,
    query string dropped: it often carries an install identifier)."""
    parsed = urlparse(str(url))
    scheme = {"http": "hxxp", "https": "hxxps"}.get(parsed.scheme, parsed.scheme)
    return f"{scheme}[://]{defang_host(parsed.netloc)}{parsed.path}"


def _bare(host: str) -> str:
    """Host without a port."""
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host.strip("[]")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(_bare(host))
        return True
    except ValueError:
        return False


def _kind(host: str, declared: set) -> str:
    """How to read this host: its own server, shared infrastructure, or neither."""
    bare = _bare(host)
    if _is_ip(bare):
        return "ip_literal"
    domain = _registered_domain(bare)
    if domain in _KNOWN_SERVICES:
        return "known_service"
    if bare in declared or domain in {_registered_domain(d) for d in declared}:
        return "declared"
    return "unexplained"


# ══════════════════════════════════════════════════════════════════════════════
#  Lookups
# ══════════════════════════════════════════════════════════════════════════════

async def _resolve(host: str) -> List[str]:
    try:
        loop = asyncio.get_running_loop()
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), _DNS_TIMEOUT)
    except Exception:
        return []
    ips: List[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips[:4]


# ══════════════════════════════════════════════════════════════════════════════
#  Entry point
# ══════════════════════════════════════════════════════════════════════════════

async def build_network_intel(observed: Optional[Dict[str, Any]], profile: Optional[Dict[str, Any]],
                              *, resolve_dns: bool = True) -> Dict[str, Any]:
    """Domain table, IP addresses and defanged indicators for one analysis.

    `observed` is the sandbox summary (empty when the sandbox did not run) and
    `profile` the static profile. Never raises: a failed lookup is recorded in
    `lookups` and the rest of the answer is still returned."""
    observed = observed if isinstance(observed, dict) else {}
    profile = profile if isinstance(profile, dict) else {}
    if os.environ.get("C1_NETINTEL_LOOKUPS", "").strip().lower() == "off":
        resolve_dns = False                          # offline runs and the test suite
    try:
        declared_eps = [e for e in (profile.get("endpoints") or []) if isinstance(e, dict)]
        declared = {_bare(str(e.get("host") or "")) for e in declared_eps if e.get("host")}

        table: Dict[str, Dict[str, Any]] = {}

        def row(host: str, role: str) -> Dict[str, Any]:
            if host not in table:
                table[host] = {"host": host, "domain": _registered_domain(_bare(host)), "role": role,
                               "requests": 0, "methods": [], "sources": [],
                               "kind": _kind(host, declared), "ips": []}
            return table[host]

        for h in observed.get("hosts") or []:
            r = row(str(h.get("host")), "contacted")
            r["requests"] = int(h.get("requests") or 0)
            r["methods"] = list(h.get("methods") or [])
            r["sources"] = list(h.get("sources") or [])
        for tab in observed.get("opened_tabs") or []:
            host = urlparse(str(tab)).netloc
            if host:
                row(host, "opened")
        for e in declared_eps:
            host = str(e.get("host") or "")
            if host and host not in table:
                row(host, "declared")

        order = {"contacted": 0, "opened": 1, "declared": 2}
        domains = sorted(table.values(), key=lambda d: (order[d["role"]], -d["requests"], d["host"]))

        lookups = {"dns": "off"}
        if resolve_dns:
            # A shared service the code merely mentions is not worth a lookup.
            names = [d for d in domains if not _is_ip(_bare(d["host"]))
                     and (d["role"] != "declared" or d["kind"] != "known_service")][:_MAX_DNS_HOSTS]
            if names:
                answers = await asyncio.gather(*[_resolve(_bare(d["host"])) for d in names])
                for d, ips in zip(names, answers):
                    d["ips"] = ips
                lookups["dns"] = "ok" if any(a for a in answers) else "no answers"
        for d in domains:
            if _is_ip(_bare(d["host"])):
                d["ips"] = [_bare(d["host"])]

        # Indicators: the extension's own infrastructure only. A real site the
        # sandbox visited is not the extension's, so it is left out, and so is a
        # shared service the code merely mentions (a video site its scripts
        # target, say) unless the extension was actually seen contacting it.
        relevant = [d for d in domains if d["role"] != "declared" or d["kind"] != "known_service"]
        ioc_hosts = [d for d in relevant if not _is_ip(_bare(d["host"]))]
        ips: List[str] = []
        for d in relevant:                      # an IP-literal endpoint is itself an IP indicator
            for ip in d["ips"]:
                if ip not in ips:
                    ips.append(ip)
        urls: List[str] = []
        for req in observed.get("requests") or []:
            clean = defang_url(str(req.get("url") or ""))
            if clean not in urls and len(urls) < _MAX_IOC_URLS:
                urls.append(clean)

        return {
            "domains": domains,
            "ips": ips,
            "lookups": lookups,
            "iocs": {
                "domains": [defang_host(d["host"]) for d in ioc_hosts],
                "ips":     [defang_host(ip) for ip in ips],
                "urls":    urls,
            },
        }
    except Exception as exc:        # evidence, never a reason to fail an analysis
        return {"domains": [], "ips": [], "lookups": {"error": str(exc)[:160]},
                "iocs": {"domains": [], "ips": [], "urls": []}}
