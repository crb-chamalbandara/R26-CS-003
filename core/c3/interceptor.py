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

from .block_store import c3_block_store
from .context_tagger import c3_tagger


# These URL schemes do not represent real network connections to external hosts,
# so there is nothing useful to inspect or measure.
_SKIP_SCHEMES = {"about", "chrome", "devtools", "data", "blob", "file"}

# Per-host windows are capped by count (deque maxlen=50) but that alone does not
# expire events by age — a host that goes quiet for hours and then gets a couple
# of unrelated new requests would otherwise still mix hours-old and fresh events
# into the same feature computation. host_events()/host_snapshots() additionally
# exclude anything older than this from what they return, so scoring only ever
# sees a genuinely recent window. 1800s (30 min) matches the reputation-cache TTL
# already used elsewhere in C3, for consistency.
_MAX_EVENT_AGE_S = 1800.0

# Full per-host capture log for the Host Analysis detail view. This is SEPARATE
# from the 50-entry scoring window (_host_windows) below: the feature engine and
# the trained model are calibrated on <=50-request windows and must not change,
# but the dashboard should be able to show every request captured for a host up
# to the point it is blocked. Bounded so a busy non-beacon host (a video call, a
# websocket-polling SPA) that is never blocked cannot grow this without limit --
# 10,000 requests is ~14 h of a 5 s beacon or ~2.7 h of a 1 s beacon, far past
# the point any real beacon would already have alerted and (if auto-block is on)
# been blocked. Appends stop for a host the moment it is blocked, freezing its
# log at exactly the blocked-at boundary.
_HOST_HISTORY_MAX = 10_000

# How often sweep_expired_blocks() actually queries the block store, called
# from the analyzer's existing 10s loop. A 24-hour expiry window does not
# need per-cycle resolution; checking every 5 minutes is more than tight
# enough while keeping the added SQLite query cheap and infrequent.
_EXPIRY_SWEEP_INTERVAL_S = 300.0


class C3Interceptor:
    def __init__(self) -> None:
        self._pw_session = None          # reference to the shared Playwright browser session
        self._context = None             # the browser context (holds all open tabs)
        self._running = False            # True while the interceptor is active
        self._sessions: dict[int, object] = {}           # one CDP session per open tab
        self._page_by_session: dict[int, object] = {}   # maps session id → page object
        # Three pending-request dictionaries track the three CDP events that together
        # describe one complete request: request sent → response received → loading done.
        # A request is only stored to the host window once all three events arrive.
        self._pending_requests: dict[str, dict] = {}
        self._pending_responses: dict[str, dict] = {}
        self._pending_finished: dict[str, dict] = {}
        # Per-host rolling windows — each host gets a deque that holds the last 50
        # requests so the feature engine always works on a recent, fixed-size sample.
        self._host_windows: dict[str, deque] = {}
        # Full per-host capture log (see _HOST_HISTORY_MAX) — every request to a
        # host until it is blocked, for the Host Analysis view. Not used for
        # scoring; the 50-entry _host_windows above stays the scoring window.
        self._host_history: dict[str, deque] = {}
        self._recent_requests: deque = deque(maxlen=200)  # flat list for the live-monitor view
        self._blocked_hosts: set[str] = set()            # hosts whose traffic is being aborted
        self._blocked_routes: dict[str, list[str]] = {}  # route patterns per blocked host
        self._requests_captured = 0      # lifetime counter shown in the status panel
        self._last_purge = time.time()   # timestamp of the last stale-entry cleanup
        self._last_expiry_sweep = 0.0    # throttles sweep_expired_blocks() to once per _EXPIRY_SWEEP_INTERVAL_S

    @property
    def running(self) -> bool:
        return self._running

    async def start(self, pw_session) -> None:
        """Begin intercepting.  Called once when the backend starts the browser session."""
        if self._running:
            return
        self._pw_session = pw_session
        self._context = pw_session.context
        self._running = True
        # Attach to any tabs that were already open before start() was called.
        for page in list(getattr(self._context, "pages", []) or []):
            await self.attach_page(page)
        # Listen for new tabs that open later (e.g. links that open in a new tab).
        try:
            self._context.on("page", lambda page: asyncio.create_task(self.attach_page(page)))
        except Exception:
            pass
        # Reapply every block that has not yet hit its 24h expiry. Without
        # this, a block only ever lived in the in-memory _blocked_hosts/
        # _blocked_routes dicts tied to the now-torn-down Playwright context
        # from the previous session -- any restart (backend restart, session
        # restart from Settings, app relaunch) silently and permanently lost
        # every active block with no record it had ever existed.
        await self._reapply_persisted_blocks()

    async def _reapply_persisted_blocks(self) -> None:
        # Deliberately calls _apply_live_block(), NOT block_host() — this
        # only re-establishes the live route/CDP mechanics for a block that
        # already exists on disk; it must NOT call add_block() again, which
        # would refresh blocked_at/expires_at and silently reset the 24h
        # clock on every restart, defeating the whole point of a bounded
        # window.
        for record in c3_block_store.list_active():
            try:
                applied = await self._apply_live_block(record["host"])
                if applied:
                    print(f"[C3] Reapplied persisted block for {record['host']} "
                          f"(expires {record['expires_at']})")
            except Exception as exc:
                print(f"[C3] Failed to reapply block for {record['host']}: {exc}")

    async def stop(self) -> None:
        """Detach all CDP sessions and clear state.  Called on session/backend shutdown.

        Clears per-host windows, the live-monitor feed, and blocked-host state too —
        not just the CDP plumbing. Playwright route handlers registered via
        block_host() are bound to self._context, which is torn down along with the
        browser on session stop; if _blocked_hosts/_blocked_routes survived into a
        new session, the dashboard would keep showing hosts as "blocked" while the
        new context has no route registered for them at all — a false sense of
        protection. Likewise, leaving _host_windows/_recent_requests populated would
        let a fresh session's analysis mix in a previous session's request history.
        """
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
        self._host_windows.clear()
        self._host_history.clear()
        self._recent_requests.clear()
        self._blocked_hosts.clear()
        self._blocked_routes.clear()
        self._context = None

    async def attach_page(self, page) -> None:
        """Wire up CDP network monitoring for a single browser tab."""
        if not self._running or page is None:
            return
        key = id(page)
        if key in self._sessions:
            return  # already attached to this tab
        try:
            # Install the user-activity tracker script into this tab first,
            # so context enrichment knows if the user was active when each request fired.
            await c3_tagger.inject_page(page)
            # Open a Chrome DevTools Protocol session on this tab.
            session = await self._context.new_cdp_session(page)
            # Enable the Network domain so CDP starts firing network events.
            await session.send("Network.enable")
            # A fresh CDP session starts with no blocked-URL list of its own —
            # push the current one immediately so a newly-opened tab is
            # covered by existing blocks from the first request, not just
            # future ones (Playwright's own context.route() already covers
            # new pages automatically; CDP's per-session blocklist does not).
            if self._blocked_hosts:
                try:
                    await session.send("Network.setBlockedURLs", {"urls": self._cdp_blocked_patterns()})
                except Exception:
                    pass
            # Hook the three events that together describe one complete HTTP request.
            session.on("Network.requestWillBeSent", lambda params: asyncio.create_task(self._on_request(page, params)))
            session.on("Network.responseReceived",  lambda params: asyncio.create_task(self._on_response(params)))
            session.on("Network.loadingFinished",   lambda params: asyncio.create_task(self._on_finished(page, params)))
            # Clean up when the tab is closed.
            page.on("close", lambda *_: asyncio.create_task(self._cleanup_page(page)))
            self._sessions[key] = session
            self._page_by_session[key] = page
        except Exception as exc:
            print(f"[C3] CDP attach failed: {exc}")

    async def block_host(self, host: str, reason: str = "", score: float = 0.0) -> None:
        """
        Block a host confirmed as a beacon for 24 hours, persisted so the
        block survives a restart and expires automatically (see
        block_store.py). This is the public entry point (dashboard manual
        block, auto-block, and anywhere else in the app) — it both applies
        the live block AND (re)persists it, refreshing the 24h window. Use
        _apply_live_block() directly (not this method) when re-establishing
        an already-persisted block on startup, where the original expiry
        must NOT be refreshed.
        """
        host = self._clean_host(host)
        if not host:
            return
        applied = await self._apply_live_block(host)
        if applied:
            c3_block_store.add_block(host, reason=reason, score=score)

    async def _apply_live_block(self, host: str) -> bool:
        """
        Registers the actual traffic-blocking mechanics for one host: a
        Playwright context.route() abort handler (primary) plus CDP
        Network.setBlockedURLs on every attached page session (secondary,
        defense-in-depth — operates at the Chrome network-stack level rather
        than Playwright's own request-interception layer, so it can still
        block a request even if a route() handler is ever bypassed). Neither
        mechanism guarantees interception of traffic that never goes through
        this browser context at all (e.g. a native OS process, or — per
        Playwright's own documented limitation — some Service Worker
        traffic); this blocks what C3 can see and route, which is the
        browser-routed traffic C3's own threat model is about.
        Returns False (and does nothing else) if already live-blocked or if
        there is no browser context to register routes against, so callers
        can tell whether this was a genuine new block.
        """
        if not self._context or host in self._blocked_hosts:
            return False

        async def _handler(route):
            try:
                await route.abort()
            except Exception:
                pass

        # Register two URL patterns — one without a port and one with any port.
        patterns = [f"**://{host}/**", f"**://{host}:*/**"]
        registered: list[str] = []
        for pattern in patterns:
            try:
                await self._context.route(pattern, _handler)
                registered.append(pattern)
            except Exception:
                pass
        if not registered:
            return False
        self._blocked_hosts.add(host)
        self._blocked_routes[host] = registered
        await self._push_blocked_urls_to_all_sessions()
        return True

    def is_blocked(self, host: str) -> bool:
        """Whether a host currently has a live traffic block in effect
        (manual or auto -- both paths converge on _apply_live_block(), which
        is the single source of truth this reads from)."""
        return self._clean_host(host) in self._blocked_hosts

    async def unblock_host(self, host: str) -> None:
        """Remove the traffic block for a host (manual dashboard action, or
        the automatic 24h expiry sweep — see sweep_expired_blocks())."""
        host = self._clean_host(host)
        patterns = self._blocked_routes.pop(host, [])
        for pattern in patterns:
            try:
                await self._context.unroute(pattern)
            except Exception:
                pass
        self._blocked_hosts.discard(host)
        c3_block_store.remove_block(host)
        await self._push_blocked_urls_to_all_sessions()

    async def sweep_expired_blocks(self) -> list[str]:
        """Unblocks every host whose 24h window has passed. Called from the
        analyzer's existing loop (see analyzer.py), throttled internally so
        it only actually queries the block store every
        _EXPIRY_SWEEP_INTERVAL_S seconds regardless of how often it's
        called. Returns the hosts that were just unblocked, if any, so the
        caller can broadcast/log the change."""
        now = time.time()
        if now - self._last_expiry_sweep < _EXPIRY_SWEEP_INTERVAL_S:
            return []
        self._last_expiry_sweep = now
        expired = c3_block_store.list_expired()
        unblocked: list[str] = []
        for record in expired:
            host = record["host"]
            try:
                await self.unblock_host(host)
                unblocked.append(host)
                print(f"[C3] Auto-unblocked {host} — 24h block window expired")
            except Exception as exc:
                print(f"[C3] Failed to auto-unblock {host}: {exc}")
        return unblocked

    async def _push_blocked_urls_to_all_sessions(self) -> None:
        """Best-effort: push the current blocked-host pattern list to every
        attached CDP session via Network.setBlockedURLs. A full replacement
        list is required by the CDP method itself (it is not additive), so
        this re-sends the complete current set on every block/unblock and
        on every newly-attached page (see attach_page())."""
        patterns = self._cdp_blocked_patterns()
        for session in list(self._sessions.values()):
            try:
                await session.send("Network.setBlockedURLs", {"urls": patterns})
            except Exception:
                pass

    def _cdp_blocked_patterns(self) -> list[str]:
        patterns: list[str] = []
        for host in self._blocked_hosts:
            patterns.extend([f"*://{host}/*", f"*://{host}:*/*", f"*://{host}"])
        return patterns

    def status(self) -> dict:
        """Return a quick summary for the dashboard status panel."""
        active_blocks = c3_block_store.list_active()
        return {
            "running": self._running,
            "hosts_monitored": len(self._host_windows),
            "requests_captured": self._requests_captured,
            # Full records (host, blocked_at, expires_at, reason, score) —
            # sourced from the persisted store, not just the in-memory
            # _blocked_hosts set, so the dashboard can show real time-until-
            # auto-unblock instead of just a bare hostname.
            "blocked_hosts": active_blocks,
            "blocked_count": len(active_blocks),
        }

    def host_snapshots(self) -> dict[str, list[dict]]:
        """Return every host's rolling window, age-filtered — used by the analyzer loop."""
        return {host: self.host_events(host) for host in self._host_windows}

    def hosts_summary(self) -> list[dict]:
        """One summary row per host — used by the Hosts tab in the dashboard."""
        rows = []
        for host, window in self._host_windows.items():
            last = window[-1] if window else {}
            rows.append({
                "host": host,
                # Total captured for this host (full log), not just the 50-entry
                # scoring window — so the Hosts table matches the Host Analysis
                # detail count. window_count keeps the scoring-window size visible.
                "request_count": self.host_total_count(host),
                "window_count": len(window),
                "last_seen": last.get("timestamp_iso", ""),
                "last_method": last.get("method", ""),
                "last_url": last.get("url", ""),
                "blocked": host in self._blocked_hosts,
            })
        return sorted(rows, key=lambda item: item.get("last_seen", ""), reverse=True)

    def host_events(self, host: str) -> list[dict]:
        """
        Stored requests for a single host, excluding anything older than
        _MAX_EVENT_AGE_S — used for both scoring (via host_snapshots) and the
        dashboard detail view, so a score is never shown alongside events that
        were not actually part of the window that produced it.
        """
        window = self._host_windows.get(self._clean_host(host), [])
        cutoff = time.time() - _MAX_EVENT_AGE_S
        return [event for event in window if float(event.get("timestamp") or 0.0) >= cutoff]

    def host_all_events(self, host: str) -> list[dict]:
        """Every request captured for a host since it was first seen, up to the
        point it was blocked (see _HOST_HISTORY_MAX). Used by the Host Analysis
        detail view. Unlike host_events() this is NOT age-filtered and NOT
        capped at the 50-entry scoring window — it is the full capture log."""
        return list(self._host_history.get(self._clean_host(host), []))

    def host_total_count(self, host: str) -> int:
        """Total requests captured for a host (full log length; falls back to
        the scoring-window length for a host with no history entry yet)."""
        h = self._clean_host(host)
        hist = self._host_history.get(h)
        if hist is not None:
            return len(hist)
        return len(self._host_windows.get(h, []))

    def recent_requests(self, limit: int = 50) -> list[dict]:
        """The most recent requests across all hosts — used by the Live Monitor tab."""
        return list(self._recent_requests)[:limit]

    # ── CDP event handlers ────────────────────────────────────────────────────

    async def _on_request(self, page, params: dict) -> None:
        """CDP fires this the moment the browser is about to send a request."""
        request = params.get("request") or {}
        url = str(request.get("url") or "")
        parsed = urlparse(url)
        # Ignore internal browser URLs (chrome://, about:, etc.)
        if parsed.scheme in _SKIP_SCHEMES or not parsed.hostname:
            return
        request_id = str(params.get("requestId") or "")
        if not request_id:
            return

        now = time.time()
        post_data = request.get("postData") or ""
        # Save the request side of this event.  The response and finish events
        # will be correlated by request_id in _try_finalize().
        self._pending_requests[request_id] = {
            "request_id": request_id,
            "url": url,
            "host": self._clean_host(parsed.hostname),
            "method": str(request.get("method") or "GET").upper(),
            "headers": request.get("headers") or {},
            "request_size": len(post_data.encode("utf-8", errors="ignore")),
            "timestamp": now,
            "timestamp_iso": self._iso(now),
            "initiator": params.get("initiator") or {},  # what triggered the request (script, link, etc.)
            "page": page,
        }
        await self._try_finalize(request_id)

    async def _on_response(self, params: dict) -> None:
        """CDP fires this when the server's response headers arrive."""
        request_id = str(params.get("requestId") or "")
        if not request_id:
            return
        response = params.get("response") or {}
        headers = response.get("headers") or {}
        size = self._content_length(headers)  # bytes declared by Content-Length header
        self._pending_responses[request_id] = {
            "status": int(response.get("status") or 0),
            "response_size": size,
            "mime_type": response.get("mimeType") or "",
            "response_headers": headers,
            "timestamp": time.time(),
        }
        await self._try_finalize(request_id)

    async def _on_finished(self, page, params: dict) -> None:
        """CDP fires this when the entire response body has been received."""
        request_id = str(params.get("requestId") or "")
        if not request_id:
            return
        self._pending_finished[request_id] = {
            "encoded_size": int(params.get("encodedDataLength") or 0),  # actual bytes on the wire
            "page": page,
            "timestamp": time.time(),
        }
        await self._try_finalize(request_id)

    async def _try_finalize(self, request_id: str) -> None:
        """Assemble one complete request record once all three CDP events have arrived."""
        # Periodically remove entries that never completed (e.g. aborted requests).
        if time.time() - self._last_purge > 60:
            self._purge_stale()

        req  = self._pending_requests.get(request_id)
        done = self._pending_finished.get(request_id)
        # We need both the request and the finish event; the response event is optional.
        if not req or not done:
            return
        resp = self._pending_responses.get(request_id, {})

        # Remove from pending dictionaries now that we have everything.
        self._pending_requests.pop(request_id, None)
        self._pending_responses.pop(request_id, None)
        self._pending_finished.pop(request_id, None)

        # Prefer the actual on-wire size; fall back to Content-Length or request body size.
        size = int(done.get("encoded_size") or resp.get("response_size") or req.get("request_size") or 0)

        # Ask the context tagger to enrich this request with user-activity information.
        try:
            context = await c3_tagger.enrich_request(
                done.get("page") or req.get("page"),
                req["url"],
                req.get("initiator") or {},
            )
        except Exception:
            # If enrichment fails (e.g. a transient CDP lag), assume BENIGN
            # defaults, not the worst case. The previous defaults here
            # (1hr idle, background tab) manufactured the single strongest
            # evidence Rules 2 and 3 in analyzer.py look for, meaning a brief
            # enrichment hiccup could produce a false BEACON verdict on
            # otherwise-normal traffic. This matches the asymmetric-risk
            # philosophy already used elsewhere in C3 (the early-window cap
            # and the known-safe-host cap both withhold suspicion under
            # uncertainty rather than manufacture it) — a degraded event
            # should at worst fail to contribute evidence, never fabricate it.
            context = {
                "idle_time_ms": 0,
                "user_was_active": True,
                "is_background_tab": False,
                "is_extension_origin": False,
                "initiator_type": "unknown",
                "initiator_url": "",
                "page_url": "",
                "last_event_type": "",
                "is_degraded_context": True,  # visible for dashboard/debugging;
                                               # not yet consumed by compute_features()
            }

        # Build the final event record that goes into the host's rolling window.
        event = {
            "request_id": request_id,
            "url": req["url"],
            "host": req["host"],
            "method": req["method"],
            "status": int(resp.get("status") or 0),
            "size_bytes": size,
            "request_size": int(req.get("request_size") or 0),
            "request_headers": req.get("headers") or {},
            "timestamp": float(req["timestamp"]),   # when the request was sent (Unix time)
            "timestamp_iso": req["timestamp_iso"],
            **context,                              # idle_time_ms, user_was_active, etc.
        }

        # Append to the host's rolling window (oldest entry drops off at 50).
        window = self._host_windows.setdefault(event["host"], deque(maxlen=50))
        window.append(event)
        # Also append to the full per-host capture log for the Host Analysis
        # view — UNLESS the host is already blocked, in which case the log is
        # frozen at the block boundary (a blocked host should produce no new
        # real traffic, and the analyzer likewise stops re-scoring it).
        if event["host"] not in self._blocked_hosts:
            self._host_history.setdefault(
                event["host"], deque(maxlen=_HOST_HISTORY_MAX)
            ).append(event)
        # Also add to the flat recent-requests list for the live monitor.
        self._recent_requests.appendleft(event)
        self._requests_captured += 1

    async def _cleanup_page(self, page) -> None:
        """Detach the CDP session when a tab is closed."""
        key = id(page)
        session = self._sessions.pop(key, None)
        self._page_by_session.pop(key, None)
        if session:
            try:
                await session.detach()
            except Exception:
                pass

    def _purge_stale(self) -> None:
        """Remove pending entries older than 30 seconds that never completed."""
        cutoff = time.time() - 30
        self._last_purge = time.time()
        for mapping in (self._pending_requests, self._pending_responses, self._pending_finished):
            for request_id, item in list(mapping.items()):
                if float(item.get("timestamp") or 0.0) < cutoff:
                    mapping.pop(request_id, None)

    @staticmethod
    def _content_length(headers: dict) -> int:
        """Read the Content-Length header value, or return 0 if absent/invalid."""
        for key, value in headers.items():
            if str(key).lower() == "content-length":
                try:
                    return int(value)
                except Exception:
                    return 0
        return 0

    @staticmethod
    def _clean_host(host: str) -> str:
        """Normalise a hostname to lowercase and strip IPv6 brackets."""
        return str(host or "").lower().strip("[]")

    @staticmethod
    def _iso(ts: float) -> str:
        """Convert a Unix timestamp to a human-readable ISO string."""
        from datetime import datetime
        return datetime.fromtimestamp(ts).isoformat()


c3_interceptor = C3Interceptor()


# =============================================================================
# WHAT THIS FILE DOES — plain English summary
# =============================================================================
#
# This file is the "ears" of C3.  It plugs into the browser using the Chrome
# DevTools Protocol (CDP) — the same protocol that browser developer tools use —
# and listens to every HTTP request the browser sends, without slowing the
# browser down or blocking any traffic.
#
# For each open tab, it registers three event listeners:
#   1. requestWillBeSent  — browser is about to send a request
#   2. responseReceived   — server replied with headers
#   3. loadingFinished    — all response bytes have arrived
#
# Once all three events for a given request have arrived, the interceptor
# combines them into one complete record and stores it in a "rolling window"
# for that destination host.  The window holds the last 50 requests to each
# host.  The analyzer reads these windows every 10 seconds and looks for
# beacon-like patterns.
#
# The interceptor can also BLOCK a host once a BEACON verdict is confirmed —
# it registers a Playwright route handler that aborts every future request to
# that host.
# =============================================================================
