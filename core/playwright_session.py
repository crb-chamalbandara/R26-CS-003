"""
WebSentinel — Shared Playwright Session Manager

<<<<<<< HEAD
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
=======
Combines:
- C4's persistent profile directory (PROFILE_DIR) and download prefs
- C1's extension loading, silent "Add to Chrome" click interception hook

Every main-frame navigation across all tabs fires registered nav callbacks.
"Add to Chrome" clicks fire registered click callbacks with no visual change.
>>>>>>> main
"""
import asyncio
import base64
import os
<<<<<<< HEAD
import shutil
import tempfile
=======
>>>>>>> main
from typing import Callable, List, Optional
from urllib.parse import urlparse, parse_qs

_SKIP_PREFIXES = ("about:", "chrome:", "devtools:", "data:", "blob:")
_WS_INTERNAL   = ("websentinel-trigger", "websentinel-analyzing")

<<<<<<< HEAD
# ── Silent click hook ─────────────────────────────────────────────────────────
# Intercepts "Add to Chrome" button clicks (any tag, handles cr-button and
# shadow DOM wrappers), prevents the click, and signals the backend via a
# same-origin fetch that Playwright intercepts.  No visual changes in the browser.
=======
# ── Analyzing page — shown in the Playwright tab after intercepting install ───
_ANALYZING_HTML = """\
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>WebSentinel — Analyzing Extension</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0e1a;color:#e2e8f0;font-family:system-ui,sans-serif;
     display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center}
.card{max-width:440px;padding:48px 40px;background:#131929;
      border:1px solid #1e2d45;border-radius:16px}
.spin{width:56px;height:56px;border:4px solid #1e2d45;border-top-color:#3b82f6;
      border-radius:50%;animation:s .9s linear infinite;margin:0 auto 28px}
@keyframes s{to{transform:rotate(360deg)}}
h1{font-size:18px;font-weight:700;color:#f1f5f9;margin-bottom:10px}
.eid{font-size:11px;font-family:monospace;color:#64748b;background:#0a0e1a;
     padding:4px 10px;border-radius:6px;display:inline-block;margin-bottom:20px}
p{font-size:13px;color:#94a3b8;line-height:1.6}
.badge{margin-top:28px;font-size:11px;color:#3b82f6;letter-spacing:.05em}
</style>
</head>
<body>
<div class="card">
  <div class="spin"></div>
  <h1>Analyzing Extension</h1>
  <div class="eid">__EXT_ID__</div>
  <p>WebSentinel is scanning this extension for malicious behavior.<br>
     Check the <strong>WebSentinel dashboard &#x2192; C1</strong> panel for results.</p>
  <div class="badge">WEBSENTINEL &#xB7; C1 EXTENSION ANALYZER</div>
</div>
</body>
</html>"""

# ── Persistent profile (C4 forensics reads this directory) ────────────────────
_PROFILE_DIR = os.path.join(os.path.expanduser("~"), ".websentinel", "profile")
_DOWNLOADS_DIR = os.path.join(os.path.expanduser("~"), "Downloads")

# Public alias — C4 imports this
PROFILE_DIR = _PROFILE_DIR

# ── Silent click hook (C1) ─────────────────────────────────────────────────────
# On pointerdown (fires before click) we navigate the page away from the Web Store
# via window.location.replace(). Playwright intercepts the navigation as a route
# and serves the analyzing page HTML directly, so the browser never reaches
# Chrome's native extension-install API that causes STATUS_BREAKPOINT.
>>>>>>> main
_CLICK_HOOK = r"""
(function () {
  if (window.__ws_hooked) return;
  window.__ws_hooked = true;
<<<<<<< HEAD

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
=======
  try { console.log('[WebSentinel] click hook installed on', location.href); } catch(_) {}
  var _ws_intercepted = false;

  function getExtId() {
    var href = window.location.href || '';
    var m = href.match(/([a-p]{32})(?![a-p])/i);
    return m ? m[1].toLowerCase() : null;
  }

  function isButtonLike(el) {
    if (!el || el.nodeType !== 1) return false;
    var tag = (el.tagName || '').toUpperCase();
    if (tag === 'BUTTON' || tag === 'A' || tag === 'CR-BUTTON') return true;
    var role = (el.getAttribute && el.getAttribute('role')) || '';
    return role.toLowerCase() === 'button';
  }

  function looksLikeInstall(el) {
    if (!isButtonLike(el)) return false;
    var txt  = (el.textContent  || '').trim().toLowerCase();
    var aria = (el.getAttribute && (el.getAttribute('aria-label') || '')) || '';
    aria = aria.toLowerCase();
    if (txt.length > 60) txt = txt.slice(0, 60);
    return txt.indexOf('add to chrome') !== -1
        || aria.indexOf('add to chrome') !== -1
        || aria.indexOf('add extension') !== -1;
  }

  function handle(e) {
    // If we already fired on pointerdown, swallow the click too.
    if (_ws_intercepted) {
      e.preventDefault();
      e.stopImmediatePropagation();
      return false;
    }
    var path = (e.composedPath && e.composedPath()) || [];
    for (var i = 0; i < path.length; i++) {
      var el = path[i];
      if (looksLikeInstall(el)) {
        var extId = getExtId();
        try { console.log('[WebSentinel] install intercepted, ext_id=', extId); } catch(_) {}
        e.preventDefault();
        e.stopImmediatePropagation();
        e.stopPropagation();
        if (extId) {
          _ws_intercepted = true;
          var qs = '?ext_id=' + encodeURIComponent(extId)
                 + '&url='    + encodeURIComponent(window.location.href);
          // Use an absolute localhost URL so Chrome Web Store's service worker
          // (which only handles same-origin requests) cannot intercept it.
          // Playwright routes catch it before it ever hits the network.
          window.location.replace('http://127.0.0.1:8765/websentinel-trigger' + qs);
        }
        return false;
      }
    }
  }

  // pointerdown fires before click — navigate on the earliest possible event.
  document.addEventListener('pointerdown', handle, true);
  document.addEventListener('click',       handle, true);
>>>>>>> main
})();
"""


class PlaywrightSession:
    def __init__(self) -> None:
<<<<<<< HEAD
        self._pw         = None
        self._ctx        = None
        self._page       = None
        self._running    = False
        self._last_url   = ""
        self._callbacks: List[Callable] = []       # nav callbacks
        self._click_cbs:  List[Callable] = []       # click callbacks
        self._extensions: List[str] = []
        self._session_dir: Optional[str] = None
=======
        self._pw          = None
        self._ctx         = None
        self._page        = None
        self._running     = False
        self._last_url    = ""
        self._callbacks:  List[Callable] = []   # nav callbacks
        self._click_cbs:  List[Callable] = []   # C1 click callbacks
        self._extensions: List[str]      = []   # loaded extension paths
>>>>>>> main

    @property
    def is_running(self) -> bool:
        return self._running and self._ctx is not None

    @property
<<<<<<< HEAD
    def loaded_extensions(self) -> List[str]:
        return list(self._extensions)

=======
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

>>>>>>> main
    # ── Lifecycle ──────────────────────────────────────────────────
    async def start(self) -> bool:
        if self.is_running:
            return True

<<<<<<< HEAD
        self._session_dir = tempfile.mkdtemp(prefix="websentinel_")
=======
        os.makedirs(_PROFILE_DIR, exist_ok=True)
        self._configure_download_prefs()
>>>>>>> main

        from playwright.async_api import async_playwright
        self._pw = await async_playwright().start()

<<<<<<< HEAD
        args = [
            "--start-maximized",
            "--no-first-run",
            "--no-default-browser-check",
=======
        # --start-maximized + viewport=None crashes Windows Explorer (shell restart)
        # on Windows 11 due to a DWM window-creation race. Use a fixed size instead.
        # --disable-gpu / --in-process-gpu prevent the GPU compositor subprocess from
        # sending DWM window messages that trigger an explorer.exe shell restart.
        args = [
            "--window-size=1400,900",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-gpu",
            "--disable-gpu-compositing",
            "--in-process-gpu",
            "--disable-software-rasterizer",
            "--enable-unsafe-extension-debugging",  # enables Extensions CDP domain for hot-load
>>>>>>> main
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
<<<<<<< HEAD
            ignore_args = [
                "--disable-component-extensions-with-background-pages",
            ]
=======
            ignore_args = ["--disable-component-extensions-with-background-pages"]
>>>>>>> main

        self._ctx = await self._pw.chromium.launch_persistent_context(
            self._session_dir,
            headless=False,
<<<<<<< HEAD
            viewport=None,          # disable viewport emulation → content fills the full window
=======
            viewport={"width": 1400, "height": 900},
>>>>>>> main
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

<<<<<<< HEAD
        # Silent click hook — no visual changes in browser
        await self._ctx.add_init_script(script=_CLICK_HOOK)

        # Intercept the signal sent by the click hook
        await self._ctx.route("**websentinel-trigger*", self._on_install_click)
=======
        # C1 click hook — silent, no visual changes
        await self._ctx.add_init_script(script=_CLICK_HOOK)
        # Use a regex so the route fires regardless of URL scheme or the exact
        # query-string shape (sendBeacon is a POST with no querystring, fetch
        # is GET with one — both must match).
        import re as _re
        await self._ctx.route(
            _re.compile(r"/websentinel-trigger(\?|$)"),
            self._on_install_click,
        )
>>>>>>> main

        self._ctx.on("close", self._on_browser_close)
        self._ctx.on("page", lambda p: asyncio.ensure_future(self._on_new_page(p)))

        pages = self._ctx.pages
        self._page = pages[0] if pages else await self._ctx.new_page()
        # Navigate to Google if the tab is blank (fresh start)
        if self._page.url in ("", "about:blank"):
            try:
                await self._page.goto("https://www.google.com", wait_until="domcontentloaded", timeout=15_000)
            except Exception:
                pass
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


    # ── Extension management (C1) ──────────────────────────────────
    def register_extension(self, ext_path: str) -> None:
        """Add extension to the launch list without restarting the session.
        The extension becomes active on the next session start."""
        abs_path = os.path.abspath(ext_path)
        if abs_path not in self._extensions:
            self._extensions.append(abs_path)

    async def load_extension(self, ext_path: str, restore_url: str = "") -> bool:
        abs_path = os.path.abspath(ext_path)

        # Try CDP-based hot-load first — no restart needed.
        # Requires --enable-unsafe-extension-debugging (set in start()).
        if self.is_running and self._page:
            try:
                cdp = await self._ctx.new_cdp_session(self._page)
                result = await cdp.send("Extensions.loadUnpacked", {"path": abs_path})
                await cdp.detach()
                ext_cdp_id = result.get("id", "")
                if ext_cdp_id:
                    if abs_path not in self._extensions:
                        self._extensions.append(abs_path)
                    print(f"[PW] Extension hot-loaded (no restart): id={ext_cdp_id}")
                    return True
                print("[PW] CDP loadUnpacked returned no id — falling back to restart")
            except Exception as cdp_err:
                print(f"[PW] CDP hot-load unavailable ({cdp_err}) — restarting session")

        # Fallback: must restart — save current page URL to restore after.
        if abs_path not in self._extensions:
            self._extensions.append(abs_path)

        saved_url = restore_url
        if not saved_url and self.is_running and self._page:
            try:
                url = self._page.url or ""
                if url and not any(url.startswith(p) for p in _SKIP_PREFIXES) \
                        and not any(s in url for s in _WS_INTERNAL):
                    saved_url = url
            except Exception:
                pass

        saved_nav   = list(self._callbacks)
        saved_click = list(self._click_cbs)
        if self.is_running:
            await self.stop()
        self._callbacks = saved_nav
        self._click_cbs = saved_click
        ok = await self.start()

        if ok and saved_url and self._page:
            try:
                await self._page.goto(saved_url, wait_until="domcontentloaded", timeout=15_000)
            except Exception:
                pass

        return ok

    async def unload_extension(self, ext_path: str) -> bool:
        abs_path = os.path.abspath(ext_path)
        if abs_path in self._extensions:
            self._extensions.remove(abs_path)

        saved_url = ""
        if self.is_running and self._page:
            try:
                url = self._page.url or ""
                if url and not any(url.startswith(p) for p in _SKIP_PREFIXES) \
                        and not any(s in url for s in _WS_INTERNAL):
                    saved_url = url
            except Exception:
                pass

        saved_nav   = list(self._callbacks)
        saved_click = list(self._click_cbs)
        if self.is_running:
            await self.stop()
        self._callbacks = saved_nav
        self._click_cbs = saved_click
        ok = await self.start()

        if ok and saved_url and self._page:
            try:
                await self._page.goto(saved_url, wait_until="domcontentloaded", timeout=15_000)
            except Exception:
                pass

        return ok

    # ── Route handler — C1 click hook signal ──────────────────────
    async def _on_install_click(self, route, request) -> None:
        try:
            params   = parse_qs(urlparse(request.url).query)
            ext_id   = (params.get("ext_id", [""])[0] or "").strip().lower()
            page_url = (params.get("url",    [""])[0] or "").strip()
        except Exception:
            ext_id = ""
            page_url = ""

        if request.resource_type == "document":
            # Page navigation — serve the analyzing page, then return to previous URL.
            html = _ANALYZING_HTML.replace("__EXT_ID__", ext_id or "unknown")
            await route.fulfill(
                status=200,
                content_type="text/html; charset=utf-8",
                body=html.encode("utf-8"),
            )
            # After 1.5 s the browser silently returns to the original page so
            # the user can continue browsing uninterrupted.
            if page_url:
                asyncio.create_task(self._return_to_page(page_url))
        else:
            # Fetch / sendBeacon fallback
            await route.fulfill(status=200, body=b"ok", content_type="text/plain")

        if ext_id:
            print(f"[PW] Install click intercepted: ext_id={ext_id}")
            for cb in list(self._click_cbs):
                asyncio.create_task(self._safe_click_call(cb, ext_id, page_url))

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

    async def set_page_html(self, html: str) -> None:
        if not self.is_running or self._page is None:
            return
        try:
            await self._page.set_content(html, wait_until="commit", timeout=5_000)
        except Exception:
            pass

    async def _return_to_page(self, url: str, delay: float = 1.5) -> None:
        await asyncio.sleep(delay)
        if self._page and self.is_running and url:
            try:
                await self._page.goto(url, wait_until="domcontentloaded", timeout=15_000)
            except Exception:
                pass

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
            if any(s in url for s in _WS_INTERNAL):
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
