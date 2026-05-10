"""
WebSentinel — Shared Playwright Session Manager

Detection design
----------------
Detection triggers ONLY when the user clicks "Add to Chrome" — never on
page navigation. The click hook is injected via add_init_script and runs
silently with no visual change in the browser.

When the button is clicked the hook makes a same-origin fetch to
  /websentinel-trigger?ext_id=<id>&url=<page_url>
Playwright intercepts this via context.route() and calls the registered
click callbacks. All feedback is shown in the WebSentinel Dashboard only.

There is NO notification bar or visual overlay injected into the browser.
"""
import asyncio
import base64
import os
import shutil
import tempfile
from typing import Callable, List, Optional
from urllib.parse import urlparse, parse_qs

_SKIP_PREFIXES = ("about:", "chrome:", "devtools:", "data:", "blob:")

# ── Silent click hook ─────────────────────────────────────────────────────────
# Intercepts "Add to Chrome" button clicks (any tag, handles cr-button and
# shadow DOM wrappers), prevents the click, and signals the backend via a
# same-origin fetch that Playwright intercepts.  No visual changes in the browser.
_CLICK_HOOK = r"""
(function () {
  if (window.__ws_hooked) return;
  window.__ws_hooked = true;

  function getExtId() {
    var m = window.location.pathname.match(/\/([a-p]{32})(?:\/|$)/i);
    return m ? m[1].toLowerCase() : null;
  }

  function isInstallBtn(el) {
    if (!el) return false;
    var txt  = (el.textContent  || '').trim().toLowerCase();
    var aria = (el.getAttribute('aria-label') || '').toLowerCase();
    return txt  === 'add to chrome'          ||
           txt.includes('add to chrome')     ||
           aria.includes('add to chrome')    ||
           aria.includes('add extension');
  }

  document.addEventListener('click', function (e) {
    var el = e.target;
    for (var i = 0; i < 10; i++) {
      if (!el) break;
      if (isInstallBtn(el)) {
        e.preventDefault();
        e.stopImmediatePropagation();
        var extId = getExtId();
        if (extId) {
          /* Same-origin fetch — Playwright intercepts it, no CORS needed */
          fetch(
            '/websentinel-trigger'
            + '?ext_id=' + encodeURIComponent(extId)
            + '&url='    + encodeURIComponent(window.location.href)
          ).catch(function () {});
        }
        return false;
      }
      el = el.parentElement
           || (el.getRootNode && el.getRootNode().host)
           || null;
    }
  }, true);
})();
"""


class PlaywrightSession:
    def __init__(self) -> None:
        self._pw         = None
        self._ctx        = None
        self._page       = None
        self._running    = False
        self._last_url   = ""
        self._callbacks: List[Callable] = []       # nav callbacks
        self._click_cbs:  List[Callable] = []       # click callbacks
        self._extensions: List[str] = []
        self._session_dir: Optional[str] = None

    @property
    def is_running(self) -> bool:
        return self._running and self._ctx is not None

    @property
    def loaded_extensions(self) -> List[str]:
        return list(self._extensions)

    # ── Lifecycle ──────────────────────────────────────────────────
    async def start(self) -> bool:
        if self.is_running:
            return True

        self._session_dir = tempfile.mkdtemp(prefix="websentinel_")

        from playwright.async_api import async_playwright
        self._pw = await async_playwright().start()

        args = [
            "--start-maximized",
            "--no-first-run",
            "--no-default-browser-check",
        ]
        if self._extensions:
            paths = ",".join(self._extensions)
            args.append(f"--load-extension={paths}")
            args.append(f"--disable-extensions-except={paths}")
            ignore_args = [
                "--disable-extensions",
                "--disable-component-extensions-with-background-pages",
            ]
        else:
            ignore_args = [
                "--disable-component-extensions-with-background-pages",
            ]

        self._ctx = await self._pw.chromium.launch_persistent_context(
            self._session_dir,
            headless=False,
            viewport=None,          # disable viewport emulation → content fills the full window
            ignore_default_args=ignore_args,
            args=args,
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
        )

        # Silent click hook — no visual changes in browser
        await self._ctx.add_init_script(script=_CLICK_HOOK)

        # Intercept the signal sent by the click hook
        await self._ctx.route("**websentinel-trigger*", self._on_install_click)

        self._ctx.on("close", self._on_browser_close)
        self._ctx.on("page", lambda p: asyncio.ensure_future(self._on_new_page(p)))

        pages = self._ctx.pages
        self._page = pages[0] if pages else await self._ctx.new_page()
        for page in self._ctx.pages:
            self._attach_nav_listener(page)

        # Expand the viewport to fill the maximised window.
        # Playwright 1.59 doesn't auto-size the viewport from the OS window,
        # so we query the available screen area from JS and apply it.
        await self._sync_viewport(self._page)

        self._running = True
        return True

    async def _sync_viewport(self, page) -> None:
        """Set viewport = available screen dimensions so content fills the window."""
        try:
            dims = await page.evaluate(
                "() => ({width: window.screen.availWidth, height: window.screen.availHeight})"
            )
            if dims and dims.get("width") and dims.get("height"):
                await page.set_viewport_size(
                    {"width": dims["width"], "height": dims["height"]}
                )
        except Exception:
            pass

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
        if self._session_dir and os.path.isdir(self._session_dir):
            shutil.rmtree(self._session_dir, ignore_errors=True)
            self._session_dir = None

    # ── Extension management ───────────────────────────────────────
    async def load_extension(self, ext_path: str) -> bool:
        abs_path = os.path.abspath(ext_path)
        if abs_path not in self._extensions:
            self._extensions.append(abs_path)
        saved_nav   = list(self._callbacks)
        saved_click = list(self._click_cbs)
        if self.is_running:
            await self.stop()
        self._callbacks  = saved_nav
        self._click_cbs  = saved_click
        return await self.start()

    async def unload_extension(self, ext_path: str) -> bool:
        abs_path = os.path.abspath(ext_path)
        if abs_path in self._extensions:
            self._extensions.remove(abs_path)
        saved_nav   = list(self._callbacks)
        saved_click = list(self._click_cbs)
        if self.is_running:
            await self.stop()
        self._callbacks  = saved_nav
        self._click_cbs  = saved_click
        return await self.start()

    # ── Route handler — click hook signal ─────────────────────────
    async def _on_install_click(self, route, request) -> None:
        """
        Called by Playwright when the click hook fetches /websentinel-trigger.
        Fulfills the request immediately, then fires the click callbacks.
        """
        await route.fulfill(status=200, body=b"ok", content_type="text/plain")
        try:
            params  = parse_qs(urlparse(request.url).query)
            ext_id  = (params.get("ext_id", [""])[0] or "").strip().lower()
            page_url = (params.get("url",    [""])[0] or "").strip()
            print(f"[PW] Install click intercepted: ext_id={ext_id}")
            for cb in list(self._click_cbs):
                asyncio.create_task(self._safe_click_call(cb, ext_id, page_url))
        except Exception as exc:
            print(f"[PW] install click error: {exc}")

    @staticmethod
    async def _safe_click_call(cb: Callable, ext_id: str, url: str) -> None:
        try:
            await cb(ext_id, url)
        except Exception as exc:
            import traceback
            print(f"[PW] click callback error: {exc}")
            traceback.print_exc()

    # ── Callback registration ──────────────────────────────────────
    def add_nav_callback(self, cb: Callable) -> None:
        if cb not in self._callbacks:
            self._callbacks.append(cb)

    def add_click_callback(self, cb: Callable) -> None:
        if cb not in self._click_cbs:
            self._click_cbs.append(cb)

    def clear_callbacks(self) -> None:
        self._callbacks.clear()
        self._click_cbs.clear()

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

    # ── Internal ───────────────────────────────────────────────────
    def _attach_nav_listener(self, page) -> None:
        async def _handler(frame) -> None:
            if frame.parent_frame is not None:
                return
            self._page = page
            url = frame.url
            if not url or any(url.startswith(p) for p in _SKIP_PREFIXES):
                return
            if url == self._last_url:
                return
            self._last_url = url
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=5_000)
            except Exception:
                pass
            if not self.is_running:
                return
            for cb in list(self._callbacks):
                asyncio.create_task(self._safe_nav_call(cb, url, page))
        page.on("framenavigated", _handler)

    async def _on_new_page(self, page) -> None:
        self._page = page
        self._attach_nav_listener(page)
        await self._sync_viewport(page)

    def _on_browser_close(self, _=None) -> None:
        self._running = False

    @staticmethod
    async def _safe_nav_call(cb: Callable, url: str, page=None) -> None:
        try:
            try:
                await cb(url, page)
            except TypeError:
                await cb(url)
        except Exception as exc:
            import traceback
            print(f"[PW] Nav callback error for {url[:60]}: {exc}")
            traceback.print_exc()


pw_session = PlaywrightSession()
