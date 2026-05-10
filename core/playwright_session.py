"""
WebSentinel — Shared Playwright Session Manager

Combines:
- C4's persistent profile directory (PROFILE_DIR) and download prefs
- C1's extension loading, silent "Add to Chrome" click interception hook

Every main-frame navigation across all tabs fires registered nav callbacks.
"Add to Chrome" clicks fire registered click callbacks with no visual change.
"""
import asyncio
import base64
import os
import shutil
import tempfile
from typing import Callable, List, Optional
from urllib.parse import urlparse, parse_qs

_SKIP_PREFIXES = ("about:", "chrome:", "devtools:", "data:", "blob:")

# ── Persistent profile (C4 forensics reads this directory) ────────────────────
_PROFILE_DIR = os.path.join(os.path.expanduser("~"), ".websentinel", "profile")
_DOWNLOADS_DIR = os.path.join(os.path.expanduser("~"), "Downloads")

# Public alias — C4 imports this
PROFILE_DIR = _PROFILE_DIR

# ── Silent click hook (C1) ─────────────────────────────────────────────────────
# Intercepts "Add to Chrome" button clicks (any tag, handles cr-button and
# shadow DOM wrappers), prevents the click, and signals the backend via a
# same-origin fetch that Playwright intercepts. No visual changes in the browser.
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
        self._pw          = None
        self._ctx         = None
        self._page        = None
        self._running     = False
        self._last_url    = ""
        self._callbacks:  List[Callable] = []   # nav callbacks
        self._click_cbs:  List[Callable] = []   # C1 click callbacks
        self._extensions: List[str]      = []   # loaded extension paths
        self._session_dir: Optional[str] = None

    # ── Public properties ──────────────────────────────────────────
    @property
    def is_running(self) -> bool:
        return self._running and self._ctx is not None

    @property
    def context(self):
        """Expose the BrowserContext so C3 can attach its interceptors."""
        return self._ctx

    @property
    def loaded_extensions(self) -> List[str]:
        return list(self._extensions)

    # ── Download prefs (C4) ────────────────────────────────────────
    @staticmethod
    def _configure_download_prefs() -> None:
        import json
        prefs_path = os.path.join(_PROFILE_DIR, "Default", "Preferences")
        os.makedirs(os.path.dirname(prefs_path), exist_ok=True)
        prefs = {}
        if os.path.exists(prefs_path):
            try:
                with open(prefs_path, encoding="utf-8") as f:
                    prefs = json.load(f)
            except Exception:
                pass
        dl = prefs.setdefault("download", {})
        dl["default_directory"]   = _DOWNLOADS_DIR
        dl["prompt_for_download"] = False
        dl["directory_upgrade"]   = True
        try:
            with open(prefs_path, "w", encoding="utf-8") as f:
                json.dump(prefs, f)
        except Exception:
            pass

    # ── Lifecycle ──────────────────────────────────────────────────
    async def start(self) -> bool:
        if self.is_running:
            return True

        os.makedirs(_PROFILE_DIR, exist_ok=True)
        self._configure_download_prefs()
        # Use a temp session dir so C4 can still read PROFILE_DIR databases
        self._session_dir = tempfile.mkdtemp(prefix="websentinel_")

        from playwright.async_api import async_playwright
        self._pw = await async_playwright().start()

        # --start-maximized + viewport=None crashes Windows Explorer (shell restart)
        # on Windows 11 due to a DWM window-creation race. Use a fixed size instead.
        # --disable-gpu prevents the GPU compositor process from sending window
        # messages that trigger a Windows shell (explorer.exe) restart.
        args = [
            "--window-size=1400,900",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-gpu",
            "--disable-gpu-compositing",
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
            ignore_args = ["--disable-component-extensions-with-background-pages"]

        self._ctx = await self._pw.chromium.launch_persistent_context(
            self._session_dir,
            headless=False,
            viewport={"width": 1400, "height": 900},
            ignore_default_args=ignore_args,
            args=args,
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            downloads_path=_DOWNLOADS_DIR,
            accept_downloads=True,
        )

        # C1 click hook — silent, no visual changes
        await self._ctx.add_init_script(script=_CLICK_HOOK)
        await self._ctx.route("**websentinel-trigger*", self._on_install_click)

        self._ctx.on("close", self._on_browser_close)
        self._ctx.on("page", lambda p: asyncio.ensure_future(self._on_new_page(p)))

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
        if self._session_dir and os.path.isdir(self._session_dir):
            shutil.rmtree(self._session_dir, ignore_errors=True)
            self._session_dir = None


    # ── Extension management (C1) ──────────────────────────────────
    async def load_extension(self, ext_path: str) -> bool:
        abs_path = os.path.abspath(ext_path)
        if abs_path not in self._extensions:
            self._extensions.append(abs_path)
        saved_nav   = list(self._callbacks)
        saved_click = list(self._click_cbs)
        if self.is_running:
            await self.stop()
        self._callbacks = saved_nav
        self._click_cbs = saved_click
        return await self.start()

    async def unload_extension(self, ext_path: str) -> bool:
        abs_path = os.path.abspath(ext_path)
        if abs_path in self._extensions:
            self._extensions.remove(abs_path)
        saved_nav   = list(self._callbacks)
        saved_click = list(self._click_cbs)
        if self.is_running:
            await self.stop()
        self._callbacks = saved_nav
        self._click_cbs = saved_click
        return await self.start()

    # ── Route handler — C1 click hook signal ──────────────────────
    async def _on_install_click(self, route, request) -> None:
        await route.fulfill(status=200, body=b"ok", content_type="text/plain")
        try:
            params   = parse_qs(urlparse(request.url).query)
            ext_id   = (params.get("ext_id", [""])[0] or "").strip().lower()
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
