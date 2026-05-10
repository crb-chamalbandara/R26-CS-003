"""
C3 CDP network interceptor.

Attaches one CDP Network session per Playwright page, captures outbound
requests without pausing the browser, and stores per-host rolling windows.
"""
from __future__ import annotations

import asyncio
import time
from collections import deque
from urllib.parse import urlparse

from .context_tagger import c3_tagger


_SKIP_SCHEMES = {"about", "chrome", "devtools", "data", "blob", "file"}


class C3Interceptor:
    def __init__(self) -> None:
        self._pw_session = None
        self._context = None
        self._running = False
        self._sessions: dict[int, object] = {}
        self._page_by_session: dict[int, object] = {}
        self._pending_requests: dict[str, dict] = {}
        self._pending_responses: dict[str, dict] = {}
        self._pending_finished: dict[str, dict] = {}
        self._host_windows: dict[str, deque] = {}
        self._recent_requests: deque = deque(maxlen=200)
        self._blocked_hosts: set[str] = set()
        self._blocked_routes: dict[str, list[str]] = {}
        self._requests_captured = 0
        self._last_purge = time.time()

    @property
    def running(self) -> bool:
        return self._running

    async def start(self, pw_session) -> None:
        if self._running:
            return
        self._pw_session = pw_session
        self._context = pw_session.context
        self._running = True
        for page in list(getattr(self._context, "pages", []) or []):
            await self.attach_page(page)
        try:
            self._context.on("page", lambda page: asyncio.create_task(self.attach_page(page)))
        except Exception:
            pass

    async def stop(self) -> None:
        self._running = False
        self._requests_captured = 0
        for session in list(self._sessions.values()):
            try:
                await session.detach()
            except Exception:
                pass
        self._sessions.clear()
        self._page_by_session.clear()
        self._pending_requests.clear()
        self._pending_responses.clear()
        self._pending_finished.clear()

    async def attach_page(self, page) -> None:
        if not self._running or page is None:
            return
        key = id(page)
        if key in self._sessions:
            return
        try:
            await c3_tagger.inject_page(page)
            session = await self._context.new_cdp_session(page)
            await session.send("Network.enable")
            session.on("Network.requestWillBeSent", lambda params: asyncio.create_task(self._on_request(page, params)))
            session.on("Network.responseReceived", lambda params: asyncio.create_task(self._on_response(params)))
            session.on("Network.loadingFinished", lambda params: asyncio.create_task(self._on_finished(page, params)))
            page.on("close", lambda *_: asyncio.create_task(self._cleanup_page(page)))
            self._sessions[key] = session
            self._page_by_session[key] = page
        except Exception as exc:
            print(f"[C3] CDP attach failed: {exc}")

    async def block_host(self, host: str) -> None:
        host = self._clean_host(host)
        if not host or not self._context or host in self._blocked_hosts:
            return

        async def _handler(route):
            try:
                await route.abort()
            except Exception:
                pass

        patterns = [f"**://{host}/**", f"**://{host}:*/**"]
        registered: list[str] = []
        for pattern in patterns:
            try:
                await self._context.route(pattern, _handler)
                registered.append(pattern)
            except Exception:
                pass
        if registered:
            self._blocked_hosts.add(host)
            self._blocked_routes[host] = registered

    async def unblock_host(self, host: str) -> None:
        host = self._clean_host(host)
        patterns = self._blocked_routes.pop(host, [])
        for pattern in patterns:
            try:
                await self._context.unroute(pattern)
            except Exception:
                pass
        self._blocked_hosts.discard(host)

    def status(self) -> dict:
        return {
            "running": self._running,
            "hosts_monitored": len(self._host_windows),
            "requests_captured": self._requests_captured,
            "blocked_hosts": sorted(self._blocked_hosts),
            "blocked_count": len(self._blocked_hosts),
        }

    def host_snapshots(self) -> dict[str, list[dict]]:
        return {host: list(window) for host, window in self._host_windows.items()}

    def hosts_summary(self) -> list[dict]:
        rows = []
        for host, window in self._host_windows.items():
            last = window[-1] if window else {}
            rows.append({
                "host": host,
                "request_count": len(window),
                "last_seen": last.get("timestamp_iso", ""),
                "last_method": last.get("method", ""),
                "last_url": last.get("url", ""),
                "blocked": host in self._blocked_hosts,
            })
        return sorted(rows, key=lambda item: item.get("last_seen", ""), reverse=True)

    def host_events(self, host: str) -> list[dict]:
        return list(self._host_windows.get(self._clean_host(host), []))

    def recent_requests(self, limit: int = 50) -> list[dict]:
        return list(self._recent_requests)[:limit]

    async def _on_request(self, page, params: dict) -> None:
        request = params.get("request") or {}
        url = str(request.get("url") or "")
        parsed = urlparse(url)
        if parsed.scheme in _SKIP_SCHEMES or not parsed.hostname:
            return
        request_id = str(params.get("requestId") or "")
        if not request_id:
            return

        now = time.time()
        post_data = request.get("postData") or ""
        self._pending_requests[request_id] = {
            "request_id": request_id,
            "url": url,
            "host": self._clean_host(parsed.hostname),
            "method": str(request.get("method") or "GET").upper(),
            "headers": request.get("headers") or {},
            "request_size": len(post_data.encode("utf-8", errors="ignore")),
            "timestamp": now,
            "timestamp_iso": self._iso(now),
            "initiator": params.get("initiator") or {},
            "page": page,
        }
        await self._try_finalize(request_id)

    async def _on_response(self, params: dict) -> None:
        request_id = str(params.get("requestId") or "")
        if not request_id:
            return
        response = params.get("response") or {}
        headers = response.get("headers") or {}
        size = self._content_length(headers)
        self._pending_responses[request_id] = {
            "status": int(response.get("status") or 0),
            "response_size": size,
            "mime_type": response.get("mimeType") or "",
            "response_headers": headers,
            "timestamp": time.time(),
        }
        await self._try_finalize(request_id)

    async def _on_finished(self, page, params: dict) -> None:
        request_id = str(params.get("requestId") or "")
        if not request_id:
            return
        self._pending_finished[request_id] = {
            "encoded_size": int(params.get("encodedDataLength") or 0),
            "page": page,
            "timestamp": time.time(),
        }
        await self._try_finalize(request_id)

    async def _try_finalize(self, request_id: str) -> None:
        if time.time() - self._last_purge > 60:
            self._purge_stale()

        req = self._pending_requests.get(request_id)
        done = self._pending_finished.get(request_id)
        if not req or not done:
            return
        resp = self._pending_responses.get(request_id, {})

        self._pending_requests.pop(request_id, None)
        self._pending_responses.pop(request_id, None)
        self._pending_finished.pop(request_id, None)

        size = int(done.get("encoded_size") or resp.get("response_size") or req.get("request_size") or 0)
        try:
            context = await c3_tagger.enrich_request(
                done.get("page") or req.get("page"),
                req["url"],
                req.get("initiator") or {},
            )
        except Exception:
            context = {
                "idle_time_ms": 3_600_000,
                "user_was_active": False,
                "is_background_tab": True,
                "is_extension_origin": False,
                "initiator_type": "unknown",
                "initiator_url": "",
                "page_url": "",
                "last_event_type": "",
            }

        event = {
            "request_id": request_id,
            "url": req["url"],
            "host": req["host"],
            "method": req["method"],
            "status": int(resp.get("status") or 0),
            "size_bytes": size,
            "request_size": int(req.get("request_size") or 0),
            "request_headers": req.get("headers") or {},
            "timestamp": float(req["timestamp"]),
            "timestamp_iso": req["timestamp_iso"],
            **context,
        }
        window = self._host_windows.setdefault(event["host"], deque(maxlen=50))
        window.append(event)
        self._recent_requests.appendleft(event)
        self._requests_captured += 1

    async def _cleanup_page(self, page) -> None:
        key = id(page)
        session = self._sessions.pop(key, None)
        self._page_by_session.pop(key, None)
        if session:
            try:
                await session.detach()
            except Exception:
                pass

    def _purge_stale(self) -> None:
        cutoff = time.time() - 30
        self._last_purge = time.time()
        for mapping in (self._pending_requests, self._pending_responses, self._pending_finished):
            for request_id, item in list(mapping.items()):
                if float(item.get("timestamp") or 0.0) < cutoff:
                    mapping.pop(request_id, None)

    @staticmethod
    def _content_length(headers: dict) -> int:
        for key, value in headers.items():
            if str(key).lower() == "content-length":
                try:
                    return int(value)
                except Exception:
                    return 0
        return 0

    @staticmethod
    def _clean_host(host: str) -> str:
        return str(host or "").lower().strip("[]")

    @staticmethod
    def _iso(ts: float) -> str:
        from datetime import datetime

        return datetime.fromtimestamp(ts).isoformat()


c3_interceptor = C3Interceptor()
