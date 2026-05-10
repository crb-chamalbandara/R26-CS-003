"""
WebSentinel — Shared Playwright Session Manager
Launches a persistent headful Chromium browser that any component can
instrument. Intercepts every main-frame navigation across ALL tabs,
extracts DOM + screenshot, then calls registered callbacks so the full
analysis pipeline can run.
"""
import asyncio
import base64
import os
from typing import Callable, List

_SKIP_PREFIXES = ("about:", "chrome:", "devtools:", "data:", "blob:")

# Persistent profile so cookies/logins survive between sessions
_PROFILE_DIR = os.path.join(
    os.path.expanduser("~"), ".websentinel", "profile"
)


class PlaywrightSession:
    def __init__(self) -> None:
        self._pw        = None
        self._ctx       = None   # BrowserContext (persistent)
        self._page      = None   # currently active page
        self._running   = False
        self._last_url  = ""
        self._callbacks: List[Callable] = []

    # ── Public properties ──────────────────────────────────────────
    @property
    def is_running(self) -> bool:
        return self._running and self._ctx is not None

    @property
    def context(self):
        return self._ctx

    # ── Lifecycle ──────────────────────────────────────────────────
    async def start(self) -> bool:
        if self.is_running:
            return True
        os.makedirs(_PROFILE_DIR, exist_ok=True)

        from playwright.async_api import async_playwright
        self._pw  = await async_playwright().start()
        self._ctx = await self._pw.chromium.launch_persistent_context(
            _PROFILE_DIR,
            headless=False,
            args=[
                "--window-size=1100,900",
                "--no-first-run",
                "--no-default-browser-check",
            ],
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
        )
        self._ctx.on("close", self._on_browser_close)
        # Handle any new tab / popup that the user or a page opens
        self._ctx.on("page", lambda p: asyncio.ensure_future(self._on_new_page(p)))

        # Attach listeners to all pages already open in the context
        pages = self._ctx.pages
        self._page = pages[0] if pages else await self._ctx.new_page()
        for page in self._ctx.pages:
            self._attach_nav_listener(page)

        self._running = True
        return True

    async def stop(self) -> None:
        self._running = False
        try:
            if self._ctx:
                await self._ctx.close()
        except Exception:
            pass
        try:
            if self._pw:
                await self._pw.stop()
        except Exception:
            pass
        self._ctx  = None
        self._page = None
        self._pw   = None

    # ── Navigation ─────────────────────────────────────────────────
    async def navigate(self, url: str) -> str:
        if not self.is_running:
            raise RuntimeError("Playwright session not running")
        await self._page.goto(url, wait_until="domcontentloaded", timeout=30_000)
        return self._page.url

    # ── Extraction helpers ─────────────────────────────────────────
    async def get_dom(self) -> str:
        if not self.is_running or self._page is None:
            return ""
        try:
            return await self._page.content()
        except Exception:
            return ""

    async def get_screenshot_b64(self) -> str:
        if not self.is_running or self._page is None:
            return ""
        try:
            data = await self._page.screenshot(type="jpeg", quality=75, full_page=False)
            return base64.b64encode(data).decode()
        except Exception:
            return ""

    async def current_url(self) -> str:
        if not self.is_running or self._page is None:
            return ""
        try:
            return self._page.url
        except Exception:
            return ""

    async def get_title(self) -> str:
        if not self.is_running or self._page is None:
            return ""
        try:
            return await self._page.title()
        except Exception:
            return ""

    # ── Callback registration ──────────────────────────────────────
    def add_nav_callback(self, cb: Callable) -> None:
        if cb not in self._callbacks:
            self._callbacks.append(cb)

    def clear_callbacks(self) -> None:
        self._callbacks.clear()

    # ── Internal helpers ───────────────────────────────────────────
    def _attach_nav_listener(self, page) -> None:
        """Attach a framenavigated listener to a specific page.

        Uses a closure so self._page is updated to whichever page
        triggered the navigation — this correctly handles multiple tabs.
        """
        async def _handler(frame) -> None:
            # Only care about main-frame (top-level) navigations
            if frame.parent_frame is not None:
                return
            # Mark this page as the currently active one
            self._page = page
            url = frame.url
            if not url or any(url.startswith(p) for p in _SKIP_PREFIXES):
                return
            if url == self._last_url:
                return
            self._last_url = url
            # Brief wait for DOM to settle after navigation starts
            await asyncio.sleep(0.5)
            if not self.is_running:
                return
            for cb in list(self._callbacks):
                asyncio.create_task(self._safe_call(cb, url))

        page.on("framenavigated", _handler)

    async def _on_new_page(self, page) -> None:
        """Called whenever the context opens a new tab or popup."""
        self._page = page
        self._attach_nav_listener(page)

    def _on_browser_close(self, _=None) -> None:
        self._running = False

    @staticmethod
    async def _safe_call(cb: Callable, url: str) -> None:
        try:
            await cb(url)
        except Exception as exc:
            print(f"[PW] Nav callback error: {exc}")


# Module-level singleton — import this everywhere
pw_session = PlaywrightSession()
