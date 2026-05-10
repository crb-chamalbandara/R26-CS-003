"""
Component 1 — Dynamic Sandbox Runner
Loads an unpacked Chrome extension in an isolated Playwright Chromium context,
monitors behaviour for a configurable timeout, scores the signals, and returns
a structured report.

Architecture note: each run gets its own temp profile dir so no state leaks
between analyses. No Docker required for Phase 3 — isolation is handled at
the Playwright context level.
"""
from __future__ import annotations

import asyncio
import base64
import os
import re
import tempfile
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse


# ── Signal weights (0-100 total) ─────────────────────────────────────────────
_WEIGHTS: Dict[str, int] = {
    "EVAL_AT_RUNTIME":              25,
    "WEBSOCKET_TO_EXTERNAL":        25,
    "COOKIE_EXFILTRATION_RISK":     45,
    "COOKIE_READ_WITH_EXTERNAL":    30,
    "DATA_POST_TO_EXTERNAL":        20,
    "FORM_SUBMIT_OBSERVED":         15,
    "KEYBOARD_MONITORING":          10,
    "SUSPICIOUS_DOMAIN":            20,
    "HIGH_REQUEST_VOLUME":          10,
}

# ── Suspicious URL helpers ────────────────────────────────────────────────────
_IP_RE   = re.compile(r'^https?://\d{1,3}(?:\.\d{1,3}){3}')
_DATA_RE = re.compile(r'^data:', re.IGNORECASE)

_CHROME_SCHEMES = frozenset(
    ("chrome", "chrome-extension", "devtools", "about", "blob", "data")
)


def _is_external(url: str) -> bool:
    try:
        p = urlparse(url)
        return bool(p.scheme and p.netloc and p.scheme not in _CHROME_SCHEMES)
    except Exception:
        return False


def _is_suspicious_url(url: str) -> bool:
    return bool(_IP_RE.match(url) or _DATA_RE.match(url))


# ── Monitoring hooks injected into every page context ────────────────────────
# The hooks overwrite built-ins so we capture calls made by content scripts
# and the page itself. Results are accumulated in window.__c1_signals.
_MONITOR_JS = r"""
(function () {
    if (window.__c1_monitor) return;
    window.__c1_monitor = true;
    window.__c1_signals = [];

    function _log(obj) { window.__c1_signals.push(obj); }

    /* eval */
    var _ev = window.eval;
    window.eval = function (code) {
        _log({ t: 'eval', len: typeof code === 'string' ? code.length : 0 });
        return _ev.call(this, code);
    };

    /* fetch */
    var _fe = window.fetch;
    window.fetch = function (input, init) {
        var url = typeof input === 'string' ? input
                  : (input && input.url) ? input.url : String(input);
        _log({ t: 'fetch', url: url.slice(0, 300),
               method: (init && init.method) || 'GET',
               body_len: (init && init.body) ? String(init.body).length : 0 });
        return _fe.apply(this, arguments);
    };

    /* XMLHttpRequest */
    var _open = XMLHttpRequest.prototype.open;
    var _send = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (method, url) {
        this._c1m = method; this._c1u = String(url).slice(0, 300);
        return _open.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function (body) {
        _log({ t: 'xhr', method: this._c1m || 'GET', url: this._c1u || '',
               body_len: body ? String(body).length : 0 });
        return _send.apply(this, arguments);
    };

    /* WebSocket */
    var _WS = window.WebSocket;
    window.WebSocket = function (url, proto) {
        _log({ t: 'ws', url: String(url).slice(0, 300) });
        return proto ? new _WS(url, proto) : new _WS(url);
    };
    try { window.WebSocket.prototype = _WS.prototype; } catch (_) {}

    /* document.cookie */
    try {
        var _cd = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie')
               || Object.getOwnPropertyDescriptor(HTMLDocument.prototype, 'cookie');
        if (_cd) {
            Object.defineProperty(document, 'cookie', {
                get: function () { _log({ t: 'cookie_read' }); return _cd.get.call(this); },
                set: function (v) {
                    _log({ t: 'cookie_write', preview: String(v).slice(0, 80) });
                    return _cd.set.call(this, v);
                },
                configurable: true
            });
        }
    } catch (_) {}

    /* keyboard listeners */
    var _ael = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function (type, fn, opts) {
        if (type === 'keydown' || type === 'keypress' || type === 'keyup') {
            _log({ t: 'key_listener', event: type });
        }
        return _ael.apply(this, arguments);
    };

    /* form submit */
    document.addEventListener('submit', function (e) {
        var f = e.target;
        _log({ t: 'form_submit', action: (f && f.action) ? f.action.slice(0, 200) : '' });
    }, true);
})();
"""

# ── Minimal test page (served as data-URI, no external server needed) ────────
_TEST_PAGE = base64.b64encode(b"""<!DOCTYPE html>
<html>
<head><title>SandboxTest</title></head>
<body>
<form id="f" action="https://example.com/login" method="POST">
  <input type="text"     name="username" value="testuser_sandbox" />
  <input type="password" name="password" value="testpass_sandbox" />
  <button type="submit">Login</button>
</form>
<div id="content">Sensitive content area</div>
<script>
  document.cookie = "session=sandbox_session_xyz_test";
  document.cookie = "auth=sandbox_auth_token_test";
</script>
</body>
</html>
""").decode()


# ── Signal scoring ────────────────────────────────────────────────────────────
def _score(
    net_log: List[Dict],
    page_sigs: List[Dict],
) -> Tuple[int, List[str]]:
    """Reduce raw signals to a 0-100 score and a list of flag strings."""
    has_eval       = False
    has_key        = False
    has_ws_ext     = False
    has_cookie_rd  = False
    has_form_sub   = False
    external_urls: set = set()
    posts: List[Dict]  = []
    sus_domains: set   = set()

    for s in page_sigs:
        t = s.get("t", "")
        if t == "eval":
            has_eval = True
        elif t == "cookie_read":
            # Only actual reads count — the test page itself writes cookies via its
            # own <script>, so cookie_write events come from the page not the extension.
            # Counting writes caused COOKIE_EXFILTRATION_RISK false positives on any
            # extension that made legitimate background network requests.
            has_cookie_rd = True
        elif t == "key_listener":
            has_key = True
        elif t == "ws":
            url = s.get("url", "")
            if _is_external(url):
                has_ws_ext = True
                external_urls.add(url)
        elif t == "form_submit":
            has_form_sub = True
        elif t in ("fetch", "xhr"):
            url = s.get("url", "")
            if _is_external(url):
                external_urls.add(url)
                if s.get("body_len", 0) > 10:
                    posts.append(s)

    for r in net_log:
        url = r.get("url", "")
        if not _is_external(url):
            continue
        external_urls.add(url)
        if r.get("method", "GET").upper() in ("POST", "PUT", "PATCH"):
            posts.append(r)
        if _is_suspicious_url(url):
            sus_domains.add(urlparse(url).netloc[:50])

    # ── Build flags ───────────────────────────────────────────────
    flags: List[str] = []
    score = 0

    if has_eval:
        flags.append("EVAL_AT_RUNTIME");      score += _WEIGHTS["EVAL_AT_RUNTIME"]
    if has_key:
        flags.append("KEYBOARD_MONITORING");  score += _WEIGHTS["KEYBOARD_MONITORING"]
    if has_ws_ext:
        flags.append("WEBSOCKET_TO_EXTERNAL"); score += _WEIGHTS["WEBSOCKET_TO_EXTERNAL"]
    if has_form_sub and external_urls:
        flags.append("FORM_SUBMIT_OBSERVED"); score += _WEIGHTS["FORM_SUBMIT_OBSERVED"]

    if posts and has_cookie_rd:
        flags.append("COOKIE_EXFILTRATION_RISK");    score += _WEIGHTS["COOKIE_EXFILTRATION_RISK"]
    elif has_cookie_rd and external_urls:
        flags.append("COOKIE_READ_WITH_EXTERNAL");   score += _WEIGHTS["COOKIE_READ_WITH_EXTERNAL"]
    elif posts:
        flags.append("DATA_POST_TO_EXTERNAL");       score += _WEIGHTS["DATA_POST_TO_EXTERNAL"]

    for d in sus_domains:
        flags.append(f"SUSPICIOUS_DOMAIN:{d}");      score += _WEIGHTS["SUSPICIOUS_DOMAIN"]

    if len(external_urls) > 20:
        # Raised from 8 → 20. Cloud-connected extensions (Adobe, Grammarly, etc.)
        # routinely make 10-15 background requests for license checks, analytics,
        # and sync — flagging them at 8 caused false positives on legitimate extensions.
        flags.append(f"HIGH_REQUEST_VOLUME:{len(external_urls)}");
        score += _WEIGHTS["HIGH_REQUEST_VOLUME"]

    return min(score, 100), flags


# ── Main sandbox entry point ──────────────────────────────────────────────────
async def run_sandbox(
    extension_path: str,
    timeout_seconds: int = 20,
) -> Dict[str, Any]:
    """
    Load an unpacked extension, observe it on a test page, and return scored
    behavioral signals.

    Args:
        extension_path:  Absolute path to the unpacked extension directory
                         (must contain manifest.json).
        timeout_seconds: How long to let the extension run on the test page.

    Returns a dict matching the C1 dynamic output contract:
        {
          "executed":        bool,
          "score":           int  (0–100),
          "signals":         list[str],
          "network_requests": list[dict],
          "page_signals":    list[dict],
          "detail":          str,
          "error":           str | None,
        }
    """
    result: Dict[str, Any] = {
        "executed": False,
        "score": 0,
        "signals": [],
        "network_requests": [],
        "page_signals": [],
        "detail": "",
        "error": None,
    }

    ext_path = os.path.abspath(extension_path)

    if not os.path.isdir(ext_path):
        result["error"]  = f"Extension directory not found: {ext_path}"
        result["detail"] = result["error"]
        return result

    if not os.path.exists(os.path.join(ext_path, "manifest.json")):
        result["error"]  = "manifest.json not found in extension directory"
        result["detail"] = result["error"]
        return result

    try:
        from playwright.async_api import async_playwright

        with tempfile.TemporaryDirectory(prefix="c1_sandbox_") as profile_dir:
            net_log: List[Dict] = []

            async with async_playwright() as pw:
                # Extensions require headless=False (Playwright limitation).
                # --start-minimized hides the window in the taskbar on Windows so it
                # doesn't disrupt the user during analysis.
                # --disable-features=ExtensionManifestV2DeprecationWarning suppresses
                # the blocking error dialog shown for MV2 extensions in newer Chromium.
                ctx = await pw.chromium.launch_persistent_context(
                    profile_dir,
                    headless=False,
                    args=[
                        f"--disable-extensions-except={ext_path}",
                        f"--load-extension={ext_path}",
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--start-minimized",
                        "--disable-features=ExtensionManifestV2DeprecationWarning",
                    ],
                )

                # Register the request listener immediately after context creation —
                # BEFORE ctx.new_page() — so background-page network calls made after
                # a short delay (setTimeout in the extension) are captured.
                def _req_cb(req) -> None:
                    try:
                        net_log.append({
                            "url":           req.url[:300],
                            "method":        req.method,
                            "resource_type": req.resource_type,
                        })
                    except Exception:
                        pass

                ctx.on("request", _req_cb)

                page = await ctx.new_page()

                # Inject monitoring hooks before any page script runs
                await page.add_init_script(_MONITOR_JS)

                # Load the test page (data-URI — no server required)
                await page.goto(
                    f"data:text/html;base64,{_TEST_PAGE}",
                    wait_until="networkidle",
                    timeout=12_000,
                )

                # Give the extension time to act on the page
                observe_secs = min(max(timeout_seconds, 5), 30)
                await asyncio.sleep(observe_secs)

                # Collect signals recorded by the monitor hooks
                try:
                    page_sigs = await page.evaluate("() => window.__c1_signals || []")
                except Exception:
                    page_sigs = []

                await ctx.close()

        result["executed"]         = True
        result["network_requests"] = net_log
        result["page_signals"]     = page_sigs if isinstance(page_sigs, list) else []

        dyn_score, flags = _score(net_log, result["page_signals"])
        result["score"]   = dyn_score
        result["signals"] = flags
        result["detail"]  = (
            f"Sandbox completed. dynamic_score={dyn_score}. "
            f"Network={len(net_log)} requests, "
            f"PageSignals={len(result['page_signals'])}."
        )
        if flags:
            result["detail"] += " Flags: " + ", ".join(flags) + "."

    except Exception as exc:
        result["error"]  = str(exc)
        result["detail"] = f"Sandbox error: {exc}"

    return result
