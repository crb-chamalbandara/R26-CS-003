"""
C3 context tagger.

Tracks intentional browser user activity and enriches network requests with
execution context used by the beacon feature engine.
"""
from __future__ import annotations

import time
from urllib.parse import urlparse


_ACTIVE_WINDOW_MS = 5_000


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
        self._context = None
        self._installed = False
        # Initialise to current time so early requests are NOT falsely marked idle.
        # If left as 0, idle_time_ms = now_ms - 0 = unix epoch offset (huge), which
        # makes every request before the first user interaction appear idle-fired.
        self._last_interaction_ms = int(time.time() * 1000)
        self._last_interaction_by_origin: dict[str, int] = {}
        self._last_event_type = ""

    async def setup(self, context) -> None:
        """Install interaction tracking for future and already-restored tabs."""
        if context is not self._context:
            self._installed = False
            # Reset interaction time when context changes (new browser session).
            self._last_interaction_ms = int(time.time() * 1000)
        self._context = context
        if not self._installed:
            try:
                await context.expose_function(
                    "__websentinelC3Interaction",
                    self._record_interaction,
                )
            except Exception:
                # expose_function throws if already registered on this context.
                pass
            try:
                await context.add_init_script(_TRACKER_JS)
            except Exception:
                pass
            self._installed = True

        for page in list(getattr(context, "pages", []) or []):
            await self.inject_page(page)

    async def inject_page(self, page) -> None:
        """Retrofit the tracker into a page that already existed at setup time."""
        try:
            await page.evaluate(_TRACKER_JS)
        except Exception:
            pass

    def _record_interaction(self, payload) -> None:
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

        self._last_interaction_ms = max(ts, self._last_interaction_ms)
        self._last_event_type = event_type
        origin = self._origin(url)
        if origin:
            self._last_interaction_by_origin[origin] = self._last_interaction_ms

        # A visible page firing an intentional event is enough to mark the user
        # active globally. Background requests are corrected in enrich_request().
        if visibility == "visible":
            self._last_interaction_ms = max(ts, self._last_interaction_ms)

    async def enrich_request(self, page, request_url: str, initiator: dict | None) -> dict:
        now_ms = int(time.time() * 1000)
        origin = self._origin(request_url)
        last_ms = max(
            self._last_interaction_ms,
            self._last_interaction_by_origin.get(origin, 0),
        )
        idle_time_ms = now_ms - last_ms if last_ms else 3_600_000
        initiator_type = str((initiator or {}).get("type") or "")
        initiator_url = self._initiator_url(initiator or {})

        worker_like = initiator_type and initiator_type not in {"script", "parser"}
        is_background_tab = page is None or worker_like
        page_url = ""

        if page is not None and not worker_like:
            try:
                page_url = page.url or ""
            except Exception:
                page_url = ""
            try:
                visibility = await page.evaluate("document.visibilityState")
                is_background_tab = visibility != "visible"
            except Exception:
                # If visibility cannot be queried, prefer foreground for normal pages
                # and let worker_like keep its stronger background signal.
                is_background_tab = False

        user_was_active = (idle_time_ms <= _ACTIVE_WINDOW_MS) and not is_background_tab
        is_extension_origin = any(
            str(value or "").startswith("chrome-extension://")
            for value in (request_url, initiator_url, page_url)
        )

        return {
            "idle_time_ms": idle_time_ms,
            "user_was_active": user_was_active,
            "is_background_tab": is_background_tab,
            "is_extension_origin": is_extension_origin,
            "initiator_type": initiator_type or "unknown",
            "initiator_url": initiator_url,
            "page_url": page_url,
            "last_event_type": self._last_event_type,
        }

    @staticmethod
    def _origin(url: str) -> str:
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return ""
            return f"{parsed.scheme}://{parsed.netloc}".lower()
        except Exception:
            return ""

    @staticmethod
    def _initiator_url(initiator: dict) -> str:
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
