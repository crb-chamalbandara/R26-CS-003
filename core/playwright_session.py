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
from typing import Callable, List, Optional
from urllib.parse import urlparse, parse_qs

_SKIP_PREFIXES = ("about:", "chrome:", "devtools:", "data:", "blob:")
_WS_INTERNAL   = ("websentinel-trigger", "websentinel-analyzing")


def _etld1(host: str) -> str:
    """Cheap registrable-host key (last two labels) for same-site comparison."""
    host = (host or "").lower().split(":")[0]
    parts = [p for p in host.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else host

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
_CLICK_HOOK = r"""
(function () {
  if (window.__ws_hooked) return;
  window.__ws_hooked = true;
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
})();
"""

# ── C2 interstitial — injected into the live page on a warn/block verdict ───────
# Pure client-side: "Continue anyway" removes the overlay, "Go back" uses history.
# Receives a payload: {level, url, score, verdict, reasons[]}.
_INTERSTITIAL_JS = r"""
(d) => {
  try {
    var old = document.getElementById('__ws_overlay'); if (old) old.remove();
    var oldb = document.getElementById('__ws_banner');  if (oldb) oldb.remove();
    var Z = '2147483647';

    if (d.level === 'block') {
      var ov = document.createElement('div');
      ov.id = '__ws_overlay';
      ov.style.cssText = 'position:fixed;inset:0;z-index:'+Z+';background:rgba(7,10,18,.94);'
        + 'backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);display:flex;'
        + 'align-items:center;justify-content:center;font-family:system-ui,Segoe UI,sans-serif';
      var reasons = (d.reasons||[]).map(function(r){return '<li style="margin:4px 0">'+r+'</li>';}).join('');
      ov.innerHTML =
          '<div style="max-width:560px;margin:20px;padding:36px 40px;background:#15110f;'
        + 'border:1px solid #5b1a1a;border-radius:16px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.6)">'
        + '<div style="font-size:46px;line-height:1">⛔</div>'
        + '<h1 style="color:#f87171;font-size:22px;margin:14px 0 6px">Dangerous site blocked</h1>'
        + '<p style="color:#cbd5e1;font-size:13px;margin:0 0 4px">WebSentinel flagged this page as <b>'
        + (d.verdict||'PHISHING')+'</b> (risk '+d.score+'%).</p>'
        + '<div style="color:#94a3b8;font-size:11px;word-break:break-all;margin:8px 0 14px">'+(d.url||'')+'</div>'
        + (reasons ? '<ul style="text-align:left;color:#fca5a5;font-size:12px;margin:0 auto 18px;max-width:420px;padding-left:18px">'+reasons+'</ul>' : '')
        + '<div style="display:flex;gap:12px;justify-content:center">'
        + '<button id="__ws_back" style="cursor:pointer;border:0;border-radius:9px;padding:11px 20px;font-size:13px;font-weight:600;background:#2563eb;color:#fff">Go back to safety</button>'
        + '<button id="__ws_continue" style="cursor:pointer;border:1px solid #5b1a1a;border-radius:9px;padding:11px 20px;font-size:13px;background:transparent;color:#9ca3af">Continue anyway</button>'
        + '</div></div>';
      document.documentElement.appendChild(ov);
      var bk = document.getElementById('__ws_back');
      if (bk) bk.onclick = function(){ try{ if(history.length>1){history.back();} else {location.href='https://www.google.com';} }catch(e){ ov.remove(); } };
      var co = document.getElementById('__ws_continue');
      if (co) co.onclick = function(){ ov.remove(); };
    } else {
      var bn = document.createElement('div');
      bn.id = '__ws_banner';
      bn.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:'+Z+';background:#7c5e10;'
        + 'color:#fde68a;font-family:system-ui,Segoe UI,sans-serif;font-size:13px;'
        + 'padding:10px 16px;display:flex;align-items:center;gap:10px;box-shadow:0 2px 12px rgba(0,0,0,.4)';
      bn.innerHTML =
          '<span style="font-size:16px">⚠️</span>'
        + '<span style="flex:1">WebSentinel: this page looks <b>suspicious</b> (risk '+d.score+'%). '
        + 'Be careful before entering credentials or personal data.</span>'
        + '<button id="__ws_bclose" style="cursor:pointer;border:0;background:rgba(0,0,0,.25);color:#fde68a;border-radius:6px;padding:4px 10px;font-size:12px">Dismiss</button>';
      document.documentElement.appendChild(bn);
      var bc = document.getElementById('__ws_bclose');
      if (bc) bc.onclick = function(){ bn.remove(); };
    }
  } catch(e) {}
}
"""

# ── C2 L6 runtime instrumentation (OFFLINE BATCH CAPTURE ONLY) ─────────────────
# In-page monkeypatch that records behaviours into window.__ws_runtime. Used ONLY by
# scripts/capture_fusion_vectors.py against saved HTML samples — it is NOT installed on
# the live session, because overriding fetch/XHR/addEventListener trips anti-bot
# integrity checks (e.g. Cloudflare) and breaks real browsing. The live session
# collects the same signals non-invasively (network events + CDP) in get_runtime_signals().
_RUNTIME_HOOK = r"""
(function () {
  if (window.__ws_rt_hooked) return;
  window.__ws_rt_hooked = true;
  var R = window.__ws_runtime = {
    kb_listeners: 0, kb_on_password: false,
    clipboard_listeners: 0, clipboard_api: false,
    drag_block: 0, exfil_hosts: [], form_submit_external: false,
    page_host: location.host
  };
  function pushHost(u, method) {
    try {
      var m = (method || 'GET').toUpperCase();
      if (m !== 'POST') return;                 // only credential-style sinks
      var h = new URL(u, location.href).host;
      if (h && h !== location.host && R.exfil_hosts.indexOf(h) === -1) R.exfil_hosts.push(h);
    } catch (e) {}
  }
  function isPwd(el) {
    try { return el && el.tagName === 'INPUT' && (el.type || '').toLowerCase() === 'password'; }
    catch (e) { return false; }
  }

  // addEventListener wrapper
  try {
    var origAdd = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function (type, fn, opts) {
      try {
        var t = (type || '').toLowerCase();
        if (t === 'keydown' || t === 'keypress' || t === 'keyup' || t === 'input') {
          R.kb_listeners++;
          if (isPwd(this)) R.kb_on_password = true;
        } else if (t === 'copy' || t === 'cut' || t === 'paste') {
          R.clipboard_listeners++;
        } else if (t === 'dragstart' || t === 'selectstart' || t === 'contextmenu') {
          R.drag_block++;
        }
      } catch (e) {}
      return origAdd.call(this, type, fn, opts);
    };
  } catch (e) {}

  // fetch
  try {
    var origFetch = window.fetch;
    window.fetch = function (input, init) {
      try {
        var u = (typeof input === 'string') ? input : (input && input.url);
        var m = (init && init.method) || (input && input.method) || 'GET';
        pushHost(u, m);
      } catch (e) {}
      return origFetch.apply(this, arguments);
    };
  } catch (e) {}

  // XMLHttpRequest
  try {
    var origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url) {
      try { this.__ws_m = method; this.__ws_u = url; } catch (e) {}
      return origOpen.apply(this, arguments);
    };
    var origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function () {
      try { pushHost(this.__ws_u, this.__ws_m); } catch (e) {}
      return origSend.apply(this, arguments);
    };
  } catch (e) {}

  // sendBeacon (always POST-like)
  try {
    if (navigator.sendBeacon) {
      var origBeacon = navigator.sendBeacon.bind(navigator);
      navigator.sendBeacon = function (u, data) { pushHost(u, 'POST'); return origBeacon(u, data); };
    }
  } catch (e) {}

  // clipboard read API
  try {
    if (navigator.clipboard) {
      ['readText', 'read'].forEach(function (k) {
        var o = navigator.clipboard[k];
        if (typeof o === 'function') {
          navigator.clipboard[k] = function () { R.clipboard_api = true; return o.apply(navigator.clipboard, arguments); };
        }
      });
    }
  } catch (e) {}

  // form submit → off-origin action
  try {
    var origSubmit = HTMLFormElement.prototype.submit;
    HTMLFormElement.prototype.submit = function () {
      try {
        var a = this.getAttribute('action') || '';
        if (a) { var h = new URL(a, location.href).host; if (h && h !== location.host) R.form_submit_external = true; }
      } catch (e) {}
      return origSubmit.apply(this, arguments);
    };
    document.addEventListener('submit', function (e) {
      try {
        var f = e.target; var a = (f && f.getAttribute('action')) || '';
        if (a) { var h = new URL(a, location.href).host; if (h && h !== location.host) R.form_submit_external = true; }
      } catch (e2) {}
    }, true);
  } catch (e) {}
})();
"""

# Active probe — focus the password field and fire synthetic key/input events so
# keyloggers that attach handlers lazily are tripped. Never submits the form.
_RUNTIME_PROBE_JS = r"""
() => {
  try {
    var pw = document.querySelector('input[type=password]');
    if (!pw) return false;
    pw.focus();
    ['keydown', 'keypress', 'input', 'keyup'].forEach(function (t) {
      var ev = (t === 'input')
        ? new Event('input', { bubbles: true })
        : new KeyboardEvent(t, { bubbles: true, key: 'a', code: 'KeyA' });
      pw.dispatchEvent(ev);
    });
    return true;
  } catch (e) { return false; }
}
"""


class PlaywrightSession:
    def __init__(self) -> None:
        self._pw          = None
        self._ctx         = None
        self._page        = None
        self._running     = False
        self._callbacks:  List[Callable] = []   # nav callbacks
        self._click_cbs:  List[Callable] = []   # C1 click callbacks
        self._close_cbs:  List[Callable] = []   # tab-close callbacks (tab_id)
        self._extensions: List[str]      = []   # loaded extension paths
        # Per-page state (keyed by page) so multiple tabs are tracked independently.
        # L6 runtime is collected non-invasively (no in-page tampering, so anti-bot
        # challenges like Cloudflare are not broken).
        self._net_posts:  dict = {}             # page -> set of off-origin POST hosts
        self._page_host:  dict = {}             # page -> current main-frame host
        self._last_url_by_page: dict = {}       # page -> last analyzed URL (per-tab dedup)
        self._page_ids:   dict = {}             # page -> stable tab id (for the dashboard)
        self._page_seq:   int  = 0

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
        # Force PDFs to actually download instead of opening in Chrome's inline
        # viewer, so a live "download" test produces a real downloads-table row.
        prefs.setdefault("plugins", {})["always_open_pdf_externally"] = True
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

        from playwright.async_api import async_playwright
        self._pw = await async_playwright().start()

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
            _PROFILE_DIR,
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
        # C2 L6 runtime — observe off-origin POSTs at the network layer (no page tampering,
        # so Cloudflare / anti-bot challenges are not broken). Listener signals are read
        # on demand via CDP in get_runtime_signals().
        self._ctx.on("request", self._on_request)
        # Use a regex so the route fires regardless of URL scheme or the exact
        # query-string shape (sendBeacon is a POST with no querystring, fetch
        # is GET with one — both must match).
        import re as _re
        await self._ctx.route(
            _re.compile(r"/websentinel-trigger(\?|$)"),
            self._on_install_click,
        )

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
        # Persistent profile (_PROFILE_DIR) is intentionally kept on stop —
        # it stores browser history and extension data for C4 forensics.

    # ── Extension management (C1) ──────────────────────────────────
    def register_extension(self, ext_path: str) -> None:
        """Add extension to the launch list without restarting the session.
        The extension becomes active on the next session start."""
        abs_path = os.path.abspath(ext_path)
        if abs_path not in self._extensions:
            self._extensions.append(abs_path)

    async def load_extension(self, ext_path: str, restore_url: str = "") -> bool:
        abs_path = os.path.abspath(ext_path)

        # Chromium requires extensions to be declared at launch via --load-extension.
        # CDP hot-loading (Extensions.loadUnpacked) is experimental and unreliable
        # in Playwright's bundled Chromium — skip it and go straight to restart.
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

    def add_close_callback(self, cb: Callable) -> None:
        """cb(tab_id: int) fires when a tab closes — lets the dashboard drop its card."""
        if cb not in self._close_cbs:
            self._close_cbs.append(cb)

    def clear_callbacks(self) -> None:
        self._callbacks.clear()
        self._click_cbs.clear()
        self._close_cbs.clear()

    def tab_id(self, page) -> int:
        """Stable per-tab id assigned on first sight — used to show tabs separately."""
        tid = self._page_ids.get(page)
        if tid is None:
            self._page_seq += 1
            tid = self._page_seq
            self._page_ids[page] = tid
        return tid

    # ── Navigation ─────────────────────────────────────────────────
    async def navigate(self, url: str, timeout: int = 30_000) -> str:
        if not self.is_running:
            raise RuntimeError("Playwright session not running")
        await self._page.goto(url, wait_until="domcontentloaded", timeout=timeout)
        return self._page.url

    async def download_file(self, url: str, timeout: int = 20_000) -> dict:
        """Trigger a genuine browser download and report where it landed on disk.

        Navigating straight to a downloadable resource makes Chromium abort the
        navigation itself (net::ERR_ABORTED) once it hands the response to the
        download manager — that's expected, the download event still fires.
        """
        if not self.is_running:
            raise RuntimeError("Playwright session not running")
        async with self._page.expect_download(timeout=timeout) as dl_info:
            try:
                await self._page.goto(url, timeout=timeout)
            except Exception:
                pass
        download = await dl_info.value
        path = await download.path()
        return {
            "suggested_filename": download.suggested_filename,
            "path": str(path) if path else "",
            "url": download.url,
        }

    async def set_page_html(self, html: str) -> None:
        if not self.is_running or self._page is None:
            return
        try:
            await self._page.set_content(html, wait_until="commit", timeout=5_000)
        except Exception:
            pass

    async def inject_interstitial(self, level: str, result: dict, page=None) -> None:
        """Inject a C2 warning banner ('warn') or blocking overlay ('block') into the
        given page (defaults to the active page). Client-side only: 'Continue anyway'
        removes the overlay, 'Go back' uses browser history. No-op if unavailable."""
        target = page or self._page
        if not self.is_running or target is None:
            return
        layers = result.get("layers") or []
        payload = {
            "level":   level,
            "url":     result.get("url", ""),
            "score":   round(float(result.get("risk_score", 0))),
            "verdict": result.get("verdict", ""),
            "reasons": [
                f'{l.get("name") or l.get("id", "")}: {l.get("detail", "")}'.strip(": ")
                for l in layers
                if float(l.get("score", 0)) > 0.28 and l.get("detail")
            ][:4],
        }
        try:
            await target.evaluate(_INTERSTITIAL_JS, payload)
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
    # Each accepts an optional `page` so per-tab analysis reads from the tab that
    # actually navigated, not the session's last-active page (multi-tab correctness).
    async def get_dom(self, page=None) -> str:
        target = page or self._page
        if not self.is_running or target is None:
            return ""
        try:
            return await target.content()
        except Exception:
            return ""

    async def get_screenshot_b64(self, page=None) -> str:
        target = page or self._page
        if not self.is_running or target is None:
            return ""
        try:
            data = await target.screenshot(type="jpeg", quality=75, full_page=False)
            return base64.b64encode(data).decode()
        except Exception:
            return ""

    def _on_request(self, request) -> None:
        """Network-layer observer: record off-origin POST destinations per page.
        Non-invasive — does not touch the page's JS, so anti-bot challenges still pass."""
        try:
            if (request.method or "").upper() != "POST":
                return
            host = (urlparse(request.url).hostname or "").lower()
            if not host:
                return
            page = request.frame.page
        except Exception:
            return
        page_host = self._page_host.get(page, "")
        if page_host and _etld1(host) == _etld1(page_host):
            return  # same-site POST — not exfil
        self._net_posts.setdefault(page, set()).add(host)

    async def _collect_listeners(self, page=None) -> dict:
        """Count keystroke/clipboard/drag listeners via CDP DOMDebugger.getEventListeners
        on document, window and any password field — read-only, no page modification."""
        out = {"kb_listeners": 0, "kb_on_password": False,
               "clipboard_listeners": 0, "drag_block": 0}
        KB   = {"keydown", "keypress", "keyup", "input"}
        CLIP = {"copy", "cut", "paste"}
        DRAG = {"dragstart", "selectstart", "contextmenu"}
        cdp = None
        try:
            cdp = await self._ctx.new_cdp_session(page or self._page)

            async def listeners_for(expr):
                r = await cdp.send("Runtime.evaluate", {"expression": expr})
                oid = (r.get("result") or {}).get("objectId")
                if not oid:
                    return []
                res = await cdp.send("DOMDebugger.getEventListeners", {"objectId": oid})
                return res.get("listeners", []) or []

            for expr in ("document", "window"):
                for l in await listeners_for(expr):
                    t = l.get("type", "")
                    if t in KB:   out["kb_listeners"] += 1
                    elif t in CLIP: out["clipboard_listeners"] += 1
                    elif t in DRAG: out["drag_block"] += 1
            for l in await listeners_for("document.querySelector('input[type=password]')"):
                t = l.get("type", "")
                if t in KB:
                    out["kb_listeners"] += 1
                    out["kb_on_password"] = True
                elif t in CLIP:
                    out["clipboard_listeners"] += 1
        except Exception:
            pass
        finally:
            if cdp is not None:
                try:
                    await cdp.detach()
                except Exception:
                    pass
        return out

    async def get_runtime_signals(self, active_probe: bool = False, page=None) -> dict:
        """Collect L6 runtime signals non-invasively: off-origin POSTs from the network
        observer + listener counts via CDP. With active_probe, dispatch synthetic key
        events at the password field first (never submits)."""
        target = page or self._page
        if not self.is_running or target is None:
            return {}
        host = self._page_host.get(target, "") or (urlparse(target.url).hostname or "").lower()
        signals = {
            "page_host": host,
            "exfil_hosts": sorted(self._net_posts.get(target, set())),
            "kb_listeners": 0, "kb_on_password": False,
            "clipboard_listeners": 0, "clipboard_api": False,
            "drag_block": 0, "form_submit_external": False,
        }
        try:
            if active_probe:
                try:
                    await target.evaluate(_RUNTIME_PROBE_JS)
                except Exception:
                    pass
            signals.update(await self._collect_listeners(target))
        except Exception:
            pass
        return signals

    async def current_url(self, page=None) -> str:
        target = page or self._page
        if not self.is_running or target is None:
            return ""
        try:
            return target.url
        except Exception:
            return ""

    async def get_title(self, page=None) -> str:
        target = page or self._page
        if not self.is_running or target is None:
            return ""
        try:
            return await target.title()
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
            if url == self._last_url_by_page.get(page):   # per-tab dedup
                return
            self._last_url_by_page[page] = url
            # Reset L6 network state for the new page load.
            self._page_host[page] = (urlparse(url).hostname or "").lower()
            self._net_posts[page] = set()
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=5_000)
            except Exception:
                pass
            if not self.is_running:
                return
            for cb in list(self._callbacks):
                asyncio.create_task(self._safe_nav_call(cb, url, page))

        def _on_close(_=None) -> None:
            tid = self._page_ids.pop(page, None)
            self._net_posts.pop(page, None)
            self._page_host.pop(page, None)
            self._last_url_by_page.pop(page, None)
            if tid is not None:
                for cb in list(self._close_cbs):
                    asyncio.ensure_future(self._safe_close_call(cb, tid))

        page.on("framenavigated", _handler)
        page.on("close", _on_close)

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

    @staticmethod
    async def _safe_close_call(cb: Callable, tab_id: int) -> None:
        try:
            await cb(tab_id)
        except Exception as exc:
            print(f"[PW] Close callback error: {exc}")


pw_session = PlaywrightSession()
