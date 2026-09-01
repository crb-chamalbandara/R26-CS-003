"""
C3 context tagger.

Tracks intentional browser user activity and enriches network requests with
execution context used by the beacon feature engine.
"""
from __future__ import annotations

import time
from urllib.parse import urlparse


# If no user interaction has happened in the last 30 seconds, the user is
# considered "idle" for the purposes of C3 feature extraction.
_ACTIVE_WINDOW_MS = 30_000


# This small JavaScript snippet is injected into every browser tab.
# It listens for clicks, key presses, scrolls, and touch events and reports
# them back to Python via the __websentinelC3Interaction callback.
# The "installed" guard at the top prevents double-installation if the script
# somehow runs twice in the same tab.
_TRACKER_JS = r"""
(() => {
  if (window.__websentinelC3Installed) return;
  window.__websentinelC3Installed = true;

  const send = (eventType) => {
    try {
      if (typeof window.__websentinelC3Interaction === "function") {
        window.__websentinelC3Interaction({
          ts: Date.now(),
          url: String(location.href || ""),
          visibility: String(document.visibilityState || "unknown"),
          eventType: String(eventType || "unknown")
        });
      }
    } catch (_) {}
  };

  ["click", "keydown", "scroll", "touchstart"].forEach((name) => {
    window.addEventListener(name, () => send(name), { passive: true, capture: true });
  });
})();
"""


class C3ContextTagger:
    def __init__(self) -> None:
        self._context = None         # the Playwright browser context
        self._installed = False      # True once the JS tracker has been registered
        # Initialise to current time so early requests are NOT falsely marked idle.
        # If left as 0, idle_time_ms = now_ms - 0 = unix epoch offset (huge), which
        # makes every request before the first user interaction appear idle-fired.
        self._last_interaction_ms = int(time.time() * 1000)
        # Per-origin last-interaction time — lets us tell the difference between
        # "user clicked on beacon tab" and "user clicked on a different tab".
        self._last_interaction_by_origin: dict[str, int] = {}
        self._last_event_type = ""   # "click", "keydown", etc. — stored for debugging

    async def setup(self, context) -> None:
        """Install interaction tracking for future and already-restored tabs."""
        if context is not self._context:
            self._installed = False
            # Reset interaction time when context changes (new browser session).
            self._last_interaction_ms = int(time.time() * 1000)
        self._context = context
        if not self._installed:
            try:
                # expose_function makes __websentinelC3Interaction available in JS,
                # calling self._record_interaction in Python when the JS calls it.
                await context.expose_function(
                    "__websentinelC3Interaction",
                    self._record_interaction,
                )
            except Exception:
                # expose_function throws if already registered on this context.
                pass
            try:
                # add_init_script means the tracker JS runs automatically in every
                # new tab that opens, before any page content loads.
                await context.add_init_script(_TRACKER_JS)
            except Exception:
                pass
            self._installed = True

        # Also inject directly into any tabs that are already open.
        for page in list(getattr(context, "pages", []) or []):
            await self.inject_page(page)

    async def inject_page(self, page) -> None:
        """Retrofit the tracker into a page that already existed at setup time."""
        try:
            await page.evaluate(_TRACKER_JS)
        except Exception:
            pass

    def _record_interaction(self, payload) -> None:
        """Called by JavaScript whenever the user clicks, types, scrolls, or touches."""
        now_ms = int(time.time() * 1000)
        ts = now_ms
        url = ""
        visibility = ""
        event_type = ""
        if isinstance(payload, dict):
            try:
                ts = int(payload.get("ts") or now_ms)
            except Exception:
                ts = now_ms
            url = str(payload.get("url") or "")
            visibility = str(payload.get("visibility") or "")
            event_type = str(payload.get("eventType") or "")

        # Update global last-interaction time (always move forward, never backward).
        self._last_interaction_ms = max(ts, self._last_interaction_ms)
        self._last_event_type = event_type

        # Also record per-origin so beacon-tab idle time is not reset by
        # activity happening in a completely different tab (different origin).
        origin = self._origin(url)
        if origin:
            self._last_interaction_by_origin[origin] = self._last_interaction_ms

        # A visible page firing an intentional event is enough to mark the user
        # active globally. Background requests are corrected in enrich_request().
        if visibility == "visible":
            self._last_interaction_ms = max(ts, self._last_interaction_ms)

    def record_navigation(self, url: str) -> None:
        """
        Called by main.py's navigation handler on every real top-level browser
        navigation (see playwright_session.py's framenavigated listener).

        A navigation is caused by the user (typed URL, clicked a link, submitted
        a form) even though it fires no click/keydown/scroll event on the *new*
        page — without this, the burst of page-load sub-requests that follows a
        navigation was wrongly scored as idle-fired, which was a real source of
        false positives on ordinary sites (e.g. Google/YouTube) immediately
        after navigating to them.

        Deliberately scoped to the navigated origin only, via the same
        per-origin map enrich_request() already reads — it must NOT touch the
        global _last_interaction_ms, otherwise a navigation on one site could
        incorrectly mark an unrelated background beacon on a different origin
        as user-driven.
        """
        now_ms = int(time.time() * 1000)
        origin = self._origin(url)
        if origin:
            self._last_interaction_by_origin[origin] = max(
                now_ms, self._last_interaction_by_origin.get(origin, 0)
            )

    async def enrich_request(self, page, request_url: str, initiator: dict | None) -> dict:
        """
        Attach user-context information to a captured network request.
        Returns a dict that the interceptor merges into the request event record.
        """
        now_ms = int(time.time() * 1000)

        # Use the per-origin idle time if available; otherwise use the global one.
        # This is the key C3 innovation: a request to beacon.evil.com has its own
        # idle clock, separate from clicks the user makes on google.com.
        origin = self._origin(request_url)
        per_origin_ms = self._last_interaction_by_origin.get(origin, 0)
        last_ms = per_origin_ms if per_origin_ms > 0 else self._last_interaction_ms
        idle_time_ms = now_ms - last_ms if last_ms else 3_600_000

        initiator_type = str((initiator or {}).get("type") or "")
        initiator_url = self._initiator_url(initiator or {})

        # Web workers and service workers have no visible tab, so they are always
        # considered background traffic.
        worker_like = initiator_type in {"worker", "serviceworker", "sharedworker"}
        is_background_tab = page is None or worker_like
        page_url = ""

        if page is not None and not worker_like:
            try:
                page_url = page.url or ""
            except Exception:
                page_url = ""
            try:
                # Ask the browser whether this tab is currently visible to the user.
                visibility = await page.evaluate("document.visibilityState")
                is_background_tab = visibility != "visible"
            except Exception:
                # If visibility cannot be queried, prefer foreground for normal pages
                # and let worker_like keep its stronger background signal.
                is_background_tab = False

        # The user was "active" only if they interacted recently AND the tab is visible.
        # A beacon running in a hidden tab is never "active" even if the user is typing
        # away in another tab.
        user_was_active = (idle_time_ms <= _ACTIVE_WINDOW_MS) and not is_background_tab

        # Flag requests that come from browser extensions (chrome-extension:// origin).
        is_extension_origin = any(
            str(value or "").startswith("chrome-extension://")
            for value in (request_url, initiator_url, page_url)
        )

        return {
            "idle_time_ms": idle_time_ms,          # how long since the user last interacted with this tab
            "user_was_active": user_was_active,    # True if user was active within the last 30 seconds
            "is_background_tab": is_background_tab,# True if the tab is hidden / minimised
            "is_extension_origin": is_extension_origin,  # True if the request came from an extension
            "initiator_type": initiator_type or "unknown",
            "initiator_url": initiator_url,
            "page_url": page_url,
            "last_event_type": self._last_event_type,
        }

    @staticmethod
    def _origin(url: str) -> str:
        """Return scheme + host (e.g. 'https://evil.com') from a full URL."""
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return ""
            return f"{parsed.scheme}://{parsed.netloc}".lower()
        except Exception:
            return ""

    @staticmethod
    def _initiator_url(initiator: dict) -> str:
        """Extract the URL of the script that triggered the request, if available."""
        try:
            if initiator.get("url"):
                return str(initiator["url"])
            stack = initiator.get("stack") or {}
            frames = stack.get("callFrames") or []
            if frames:
                return str(frames[0].get("url") or "")
        except Exception:
            pass
        return ""


c3_tagger = C3ContextTagger()


# =============================================================================
# WHAT THIS FILE DOES — plain English summary
# =============================================================================
#
# This file answers the question: "Was a real person driving this request,
# or did it fire on its own while the user was doing something else?"
#
# It works in two parts:
#
# Part 1 — the JavaScript tracker
#   A tiny script is injected into every browser tab.  It listens for clicks,
#   key presses, scrolls, and touch events and reports each one back to Python
#   along with the current page URL and whether the tab is visible.
#
# Part 2 — enrich_request()
#   Every time the interceptor captures a network request, it calls this method
#   to attach three extra labels:
#
#   • idle_time_ms        — how many milliseconds have passed since the user
#                           last interacted WITH THIS SPECIFIC SITE.  A C2
#                           beacon fires even after the user has been idle for
#                           hours; normal page resources do not.
#
#   • user_was_active     — True only if the user interacted in the last 30
#                           seconds AND the tab was visible at the time.
#
#   • is_background_tab   — True if the tab is hidden or minimised.  Real C2
#                           beacons almost always run from background tabs so
#                           the user does not notice them.
#
# The key insight that makes C3 unique: the idle clock is tracked PER WEBSITE.
# If the user is typing in Google but the beacon tab has been silent for
# 2 hours, the beacon request is correctly labelled as idle-fired — something
# a network-level IDS cannot know.
# =============================================================================
