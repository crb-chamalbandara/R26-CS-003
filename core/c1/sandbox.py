"""
Component 1 — Dynamic Sandbox Runner
Loads an unpacked Chrome extension in a Playwright Chromium context, monitors
behaviour for a configurable timeout, scores the signals, and returns a
structured report.

Two layers, deliberately separated
----------------------------------
`observe_extension()` is the *observation* half: launch Chromium with the
extension loaded, instrument it, watch it, score what it did. It knows nothing
about containment — it runs wherever it is called.

`run_sandbox()` is the *containment* half: it picks an isolation backend
(see core/c1/isolation/) and has that backend perform the observation, then
attaches an IsolationReport stating where the analysis actually happened.

That split is what lets the same observation code run directly on the host
(fast, weakly isolated) or inside a disposable virtual machine (slow, properly
isolated) without the detection logic differing between them — so results from
the two are comparable.

Isolation note: each run always gets its own temp profile dir, so browser
state never leaks between analyses. That is a real property but a narrow one;
the backend's IsolationReport is the authority on everything else.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
from typing import Any, Dict, List, Optional, Tuple
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


# ── Who made a request ────────────────────────────────────────────────────────
# The request listener sees everything the browser sends, including the traffic
# of whichever web page happens to be open. Only some of that can be laid at the
# extension's door, so every request is tagged with where it came from:
#
#   background   the extension's own service worker or background page
#   bait_page    the page we serve (it runs no scripts of its own, so anything it
#                does was done by the extension)
#   browse_page  the real sites visited afterwards  -- the site's traffic
#   other_page   any other tab, e.g. a welcome page the extension opened
#                                                   -- the site's traffic
#   page         could not be told (kept as before: counted)
#
# The two kinds of "site's traffic" are listed in the report but never scored:
# an analytics POST from a news site says nothing about the extension. (The fact
# that the extension opened a tab at all is reported separately.)
_UNATTRIBUTED_SOURCES = frozenset(("browse_page", "other_page"))

# Real pages visited after the bait page, so a content blocker or a content
# script has something real to act on. Public, login-free, stable. What they do
# is reported, but never changes the score (see _UNATTRIBUTED_SOURCES).
_BROWSE_URLS = (
    "https://example.com/",
    "https://en.wikipedia.org/wiki/Main_Page",
    "https://www.bbc.com/news",
)
_BROWSE_NAV_TIMEOUT_MS = 10_000
_BROWSE_DWELL_MS       = 2_500
_BROWSE_STEP_SECONDS   = 8.0        # any single browser call in the visit
_BROWSE_BUDGET_SECONDS = 60.0       # the whole visit: it must never be able to stall an analysis
_MAX_NET_LOG           = 1500       # a noisy page must not grow the result without bound


_READ_SECONDS = 8.0     # one read-back from the browser (a page, a worker, a content-script world)


async def _bounded(coro, default=None, seconds: float = _READ_SECONDS):
    """Await a browser call, but give up after `seconds` and return `default`.

    The reads that collect what the hooks recorded all go through here. A page
    or a worker that is busy, hung or already gone must cost a few seconds at
    worst, never the whole analysis."""
    try:
        return await asyncio.wait_for(coro, seconds)
    except Exception:
        return default


def _progress(text: str) -> None:
    """One short line per phase. Inside the VM stdout is captured as the guest
    log, which the host returns when a run times out, so a stall shows where."""
    try:
        print("[c1-observe] " + text, flush=True)
    except Exception:
        pass


def _request_source(req, bait_page, browse_page) -> str:
    """Tag one request with who most plausibly made it (see above)."""
    try:
        if req.service_worker:
            return "background"
    except Exception:
        pass
    try:
        frame = req.frame
        if frame.url.startswith("chrome-extension://"):
            return "background"             # an MV2 background page
        owner = frame.page
        if bait_page is not None and owner is bait_page:
            return "bait_page"
        if browse_page is not None and owner is browse_page:
            return "browse_page"
        return "other_page"
    except Exception:
        return "page"


def _body_shape(req) -> Tuple[bool, int, List[str]]:
    """(has a body, its size in bytes, top-level field names).

    Field names only: the values can be personal data, and the names are what
    show whether a request carries an install ID or a page address."""
    try:
        raw = req.post_data_buffer
    except Exception:
        raw = None
    if not raw:
        return False, 0, []
    keys: List[str] = []
    try:
        text = raw.decode("utf-8", errors="ignore")
        if text.lstrip().startswith("{"):
            data = json.loads(text)
            if isinstance(data, dict):
                keys = [str(k)[:40] for k in list(data)[:12]]
        elif "=" in text and "\n" not in text[:200]:
            keys = [p.split("=", 1)[0][:40] for p in text.split("&")[:12] if "=" in p]
    except Exception:
        pass
    return True, len(raw), keys


# ── Monitoring hooks injected into every page context ────────────────────────
# The hooks overwrite built-ins so we capture calls made by content scripts
# and the page itself. Results are accumulated in window.__c1_signals.
_MONITOR_JS = r"""
(function () {
    if (window.__c1_monitor) return;
    window.__c1_monitor = true;
    window.__c1_signals = [];
    window.__c1_counters = { dom: 0 };

    function _log(obj) { window.__c1_signals.push(obj); }

    /* DOM changes. The bait page runs no scripts of its own, so on that page
       every change is the extension's; on real pages it is a mixed count. */
    try {
        new MutationObserver(function (m) { window.__c1_counters.dom += m.length; })
            .observe(document, { childList: true, subtree: true, attributes: true });
    } catch (_) {}

    /* eval */
    var _ev = window.eval;
    window.eval = function (code) {
        var _s = typeof code === 'string' ? code : '';
        /* Ignore our OWN signal readback. Playwright's page.evaluate() runs its
           expression through the page's window.eval, which this hook has just
           patched — so reading the buffer logged an 'eval' every single time and
           EVAL_AT_RUNTIME fired for 100% of extensions, including ones that run
           no code at all. Only suppress strings referencing our private symbols
           (__c1_signals, __c1_counters); genuine extension eval() is still
           recorded, with its first characters so a reviewer can see what it ran. */
        if (_s.indexOf('__c1_') === -1) {
            _log({ t: 'eval', len: _s.length, preview: _s.slice(0, 100) });
        }
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

# The extension's background context (an MV3 service worker, or an MV2
# background page) has no `window` — it is a separate JS realm entirely, so
# the page-level hooks above cannot see anything that happens there. That
# matters because a real malicious extension has every reason to run its
# fetch/WebSocket C2 from the background context rather than from a visible
# tab: nothing about it is ever rendered, so there is no page for a page-level
# hook to attach to in the first place. This is the `self`-based equivalent,
# injected directly into that context once it is found (see
# `_instrument_worker` below) rather than via add_init_script, which has no
# service-worker equivalent in Playwright's public API.
_SW_MONITOR_JS = r"""
(function () {
    if (self.__c1_sw_monitor) return;
    self.__c1_sw_monitor = true;
    self.__c1_sw_signals = [];

    function _log(obj) { self.__c1_sw_signals.push(obj); }

    var _fe = self.fetch;
    if (_fe) {
        self.fetch = function (input, init) {
            var url = typeof input === 'string' ? input
                      : (input && input.url) ? input.url : String(input);
            _log({ t: 'fetch', url: url.slice(0, 300),
                   method: (init && init.method) || 'GET',
                   body_len: (init && init.body) ? String(init.body).length : 0,
                   src: 'background' });
            return _fe.apply(this, arguments);
        };
    }

    var _WS = self.WebSocket;
    if (_WS) {
        self.WebSocket = function (url, proto) {
            _log({ t: 'ws', url: String(url).slice(0, 300), src: 'background' });
            return proto ? new _WS(url, proto) : new _WS(url);
        };
        try { self.WebSocket.prototype = _WS.prototype; } catch (_) {}
    }
})();
"""

# ── Bait page ─────────────────────────────────────────────────────────────────
# Previously served as a data: URI. Chromium treats data: pages as a unique
# opaque origin: it refuses to run content scripts there at all (regardless of
# the extension's declared match patterns) and cookies set on it are not
# addressable the way a real origin's are. An extension that only acts on
# pages it can actually inject into, or that reads/writes real cookies, would
# do nothing on the old bait page and be scored as clean for reasons that have
# nothing to do with its behaviour.
#
# Fixed by intercepting a real http:// navigation instead of loading a data:
# URI, so no server process is needed but the page is a genuine addressable
# origin. The host name is on the IANA-reserved `.invalid` TLD (RFC 2606): it
# can never resolve, so if route interception ever fails to catch a
# sub-request it fails safe with a DNS error instead of silently reaching a
# real external site.
_BAIT_ORIGIN = "http://sandbox-bait.invalid"
_BAIT_URL = _BAIT_ORIGIN + "/bait.html"

_TEST_PAGE_HTML = """<!DOCTYPE html>
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
"""


async def _serve_bait_page(route) -> None:
    await route.fulfill(status=200, content_type="text/html; charset=utf-8",
                         body=_TEST_PAGE_HTML)


async def _pull_background_signals(ctx) -> List[Dict]:
    """Read back whatever `_SW_MONITOR_JS` / `_MONITOR_JS` recorded in the
    extension's background context. Returns the full accumulated list each
    call (not a delta) — callers replace, they don't append, same as the
    page-signals read."""
    out: List[Dict] = []
    for worker in list(ctx.service_workers):
        # worker torn down mid-read, or not yet instrumented: just skipped
        sig = await _bounded(worker.evaluate("() => self.__c1_sw_signals || []"))
        if isinstance(sig, list):
            out.extend(sig)
    for bg in list(ctx.background_pages):
        sig = await _bounded(bg.evaluate("() => window.__c1_signals || []"))
        if isinstance(sig, list):
            out.extend(sig)
    return out


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
        # A real site's own traffic is not the extension's behaviour.
        if r.get("source") in _UNATTRIBUTED_SOURCES:
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


# ── Observation summary ───────────────────────────────────────────────────────
# The raw observation is far too big to keep: a real extension routinely makes
# 200+ requests in a single run, and every analysis is persisted as JSON inside
# the stored report (see db.py). What the report actually needs is per-host
# aggregate, not per-request detail — so aggregate here, once, and store that.
#
# The interesting axis is WHERE a request came from. The same host contacted by
# a content script (running on the page you are looking at) and by the
# background service worker (running whether or not any page is open) mean
# different things: persistent C2 lives in the background context precisely
# because nothing about it is ever rendered. That attribution only exists
# because the background and isolated worlds are now instrumented separately,
# and it is what the report's network view is built on.

_MAX_SUMMARY_HOSTS    = 40
_MAX_SUMMARY_REQUESTS = 60
_MAX_PAGE_HOSTS       = 12

# What the network layer says about a request, translated to the labels the
# report already uses for "who made it".
_SOURCE_LABEL = {"background": "background", "bait_page": "page", "page": "page"}


def _host_of(url: str) -> str:
    try:
        netloc = urlparse(url).netloc
        return netloc[:120] if netloc else ""
    except Exception:
        return ""


def _behaviour(result: Dict[str, Any], scored_signals: List[Dict]) -> Dict[str, Any]:
    """What the extension did, as counts a reviewer can read at a glance.

    Built only from signals that are scored (bait page, background, content
    script), so every number here is attributable to the extension."""
    def count(kind: str) -> int:
        return sum(1 for s in scored_signals if isinstance(s, dict) and s.get("t") == kind)

    samples: List[str] = []
    for sig in scored_signals:
        if isinstance(sig, dict) and sig.get("t") == "eval":
            preview = str(sig.get("preview") or "").strip()
            if preview and preview not in samples:
                samples.append(preview[:100])
            if len(samples) >= 5:
                break

    by_realm = {"background": 0, "content_script": 0, "page": 0}
    for sig in scored_signals:
        if isinstance(sig, dict) and sig.get("t") in ("fetch", "xhr", "ws"):
            realm = str(sig.get("src") or "page")
            by_realm[realm if realm in by_realm else "page"] += 1

    counters = result.get("counters") if isinstance(result.get("counters"), dict) else {}
    return {
        "dom_mutations":  int(counters.get("dom_mutations") or 0),
        "console_errors": int(counters.get("console_errors") or 0),
        "cookie_reads":   count("cookie_read"),
        "eval_calls":     count("eval"),
        "eval_samples":   samples,
        "key_listeners":  count("key_listener"),
        "form_submits":   count("form_submit"),
        "websockets":     count("ws"),
        "calls_by_realm": by_realm,
    }


def summarise_observations(result: Dict[str, Any]) -> Dict[str, Any]:
    """Compact, storable rollup of one observation run.

    Pure function over an `observe_extension()` payload — no I/O, no browser.
    Hosts are capped at `_MAX_SUMMARY_HOSTS`, keeping the busiest, so a noisy
    extension cannot bloat the stored report unboundedly; `truncated` records
    whether anything was dropped rather than leaving the reader to assume the
    list is complete.
    """
    if not isinstance(result, dict):
        return {"hosts": [], "counts": {}, "truncated": False}

    net_log = result.get("network_requests") or []
    page    = result.get("page_signals") or []
    backgr  = result.get("background_signals") or []
    content = result.get("content_script_signals") or []

    hosts: Dict[str, Dict[str, Any]] = {}
    page_hosts: Dict[str, int] = {}                 # a real site's own traffic: listed, not attributed
    requests: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    def touch(host: str) -> Dict[str, Any]:
        if host not in hosts:
            hosts[host] = {"host": host, "requests": 0, "methods": [],
                           "sources": [], "suspicious": False}
        return hosts[host]

    # Request counts and methods come from the network listener, which sees
    # every request regardless of which JS realm issued it. A request tagged as
    # a real site's own traffic is counted apart: the extension did not make it.
    attributed = 0
    for req in net_log:
        if not isinstance(req, dict):
            continue
        url = str(req.get("url", ""))
        if not _is_external(url):
            continue
        host = _host_of(url)
        if not host:
            continue
        source = str(req.get("source") or "page")
        if source in _UNATTRIBUTED_SOURCES:
            page_hosts[host] = page_hosts.get(host, 0) + 1
            continue
        attributed += 1
        entry = touch(host)
        entry["requests"] += 1
        method = str(req.get("method", "GET")).upper()
        if method not in entry["methods"]:
            entry["methods"].append(method)
        if _is_suspicious_url(url):
            entry["suspicious"] = True
        label = _SOURCE_LABEL.get(source, "page")
        if source != "page" and label not in entry["sources"]:
            entry["sources"].append(label)      # a bare "page" tag carries no information

        # One row per distinct request, so the report can show the actual calls
        # (path, method, whether it carried data) and not only a host total.
        row = requests.setdefault((method, url, label), {
            "method": method, "url": url[:220], "source": label, "count": 0,
        })
        row["count"] += 1
        if req.get("has_body"):      # body fields appear only on calls that carried data
            row["has_body"] = True
            row["body_size"] = max(row.get("body_size", 0), int(req.get("body_size") or 0))
            row["body_keys"] = row.get("body_keys") or list(req.get("body_keys") or [])[:12]

    # Realm attribution comes from the in-page hooks, which do know who called.
    for signals, source in ((page, "page"),
                            (backgr, "background"),
                            (content, "content_script")):
        for sig in signals:
            if not isinstance(sig, dict):
                continue
            if sig.get("t") not in ("fetch", "xhr", "ws"):
                continue
            url = str(sig.get("url", ""))
            if not _is_external(url):
                continue
            host = _host_of(url)
            if not host:
                continue
            entry = touch(host)
            src = str(sig.get("src") or source)
            if src not in entry["sources"]:
                entry["sources"].append(src)
            if sig.get("t") == "ws":
                entry["suspicious"] = True

    ordered = sorted(hosts.values(),
                     key=lambda h: (-h["requests"], h["host"]))
    truncated = len(ordered) > _MAX_SUMMARY_HOSTS

    # Calls that carry data come first, then the ones from the background
    # worker, then the rest by how often they repeat.
    calls = sorted(requests.values(), key=lambda r: (
        not r.get("has_body"), r["source"] != "background", -r["count"], r["url"]))

    outside = sorted(page_hosts.items(), key=lambda kv: (-kv[1], kv[0]))
    scored = list(page) + list(backgr) + list(content)
    browse = result.get("browse") if isinstance(result.get("browse"), dict) else {}

    return {
        "hosts": ordered[:_MAX_SUMMARY_HOSTS],
        "truncated": truncated,
        "counts": {
            "requests":       len(net_log),
            "attributed":     attributed,
            "hosts":          len(hosts),
            "signals":        len(page) + len(backgr) + len(content),
            "page":           len(page),
            "background":     len(backgr),
            "content_script": len(content),
            "page_requests":  sum(page_hosts.values()),
            "page_hosts":     len(page_hosts),
        },
        # Each distinct call the extension made, capped; `requests_truncated`
        # says whether the cap dropped any.
        "requests":           calls[:_MAX_SUMMARY_REQUESTS],
        "requests_truncated": len(calls) > _MAX_SUMMARY_REQUESTS,
        # Traffic of the real sites the sandbox visited (and of tabs the
        # extension opened): shown for context, never attributed or scored.
        "page_hosts": [{"host": h, "requests": n} for h, n in outside[:_MAX_PAGE_HOSTS]],
        "opened_tabs": [str(u)[:200] for u in (result.get("opened_tabs") or [])][:5],
        "behaviour":  _behaviour(result, scored),
        "browse":     browse,
    }


# ── Did Chromium actually load the extension? ─────────────────────────────────
# A dynamic score of 0 is meaningless if the extension never ran. Chromium
# refuses an unpacked extension for several ordinary reasons — unindexable
# declarativeNetRequest rulesets, a manifest it rejects, a directory it cannot
# write to — and when that happens the sandbox still starts, still browses the
# bait page, and still reports "no malicious behaviour observed". Fusing that
# into the verdict actively *lowers* the threat score of an extension the
# analysis never even saw, so the load has to be verified, not assumed.

async def _verify_extension_loaded(ctx, manifest: dict,
                                   settle_seconds: float = 8.0) -> Tuple[Optional[bool], str]:
    """(loaded, note). `loaded` is None when it cannot be determined.

    An extension that declares a background context must produce one. If the
    manifest declares none there is nothing reliable to look for, so this
    reports None rather than guessing.
    """
    background = (manifest or {}).get("background") or {}
    declares_background = bool(background)

    if not declares_background:
        return None, ("Extension declares no background context, so its load "
                      "could not be confirmed independently.")

    deadline = asyncio.get_event_loop().time() + settle_seconds
    while asyncio.get_event_loop().time() < deadline:
        if ctx.service_workers or ctx.background_pages:
            return True, ""
        await asyncio.sleep(0.5)

    return False, ("Chromium did not start the extension's background context. "
                   "The extension was rejected at load time, so nothing was "
                   "observed and the dynamic score carries no information.")


def _read_manifest(ext_path: str) -> dict:
    try:
        with open(os.path.join(ext_path, "manifest.json"), "r",
                  encoding="utf-8-sig", errors="ignore") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _patch_content_scripts_with_monitor(staged_ext_path: str, manifest: dict) -> None:
    """Prepend the page-world monitor hook to every declared content script
    file, in place, inside an already-copied extension directory.

    A content script runs in an isolated JS world that a CDP session can only
    reach *after* the browser creates it, but Chromium creates that world and
    starts running the script's own top-level code in the same tick — there
    is no gap an out-of-process host can inject into after the fact. (This
    was verified directly: DevTools' own worldName-based pre-registration
    creates a separate shadow world with the same display name rather than
    reaching the extension's real one — two different context ids were
    observed for what DevTools displays as the identical named world.) The one
    place that is guaranteed to run first, in the real world, is the script
    file itself, so the hook is spliced into the actual bytes Chromium is
    about to execute instead.

    Content script files are always classic scripts (unlike a "type":"module"
    service worker), so prepending a plain IIFE ahead of the extension's own
    code cannot break an import declaration the way it could for a module
    background script — this technique is deliberately scoped to content
    scripts for that reason.
    """
    patched: set = set()
    for entry in manifest.get("content_scripts") or []:
        if not isinstance(entry, dict):
            continue
        for rel in entry.get("js") or []:
            norm = os.path.normpath(str(rel))
            if norm in patched:
                continue
            patched.add(norm)
            target = os.path.join(staged_ext_path, norm)
            try:
                with open(target, "r", encoding="utf-8", errors="ignore") as handle:
                    original = handle.read()
                with open(target, "w", encoding="utf-8") as handle:
                    handle.write(_MONITOR_JS + "\n" + original)
            except OSError:
                pass    # declared file missing on disk; nothing to patch


def _display_name(manifest: dict, ext_dir: str) -> str:
    """The extension's name as Chromium shows it.

    Chromium names a content script's isolated world after this, and a manifest
    that stores a translation key (`__MSG_title__`) would otherwise never match
    it, hiding every content-script signal. Resolved from the extension's own
    _locales folder; "" when it cannot be."""
    name = str(manifest.get("name") or "")
    match = re.fullmatch(r"__MSG_(\w+)__", name)
    if not match:
        return name
    key = match.group(1).lower()
    for locale in (str(manifest.get("default_locale") or "en"), "en", "en_US"):
        try:
            with open(os.path.join(ext_dir, "_locales", locale, "messages.json"),
                      "r", encoding="utf-8-sig", errors="ignore") as handle:
                messages = json.load(handle)
        except (OSError, ValueError):
            continue
        for k, v in (messages or {}).items():
            if str(k).lower() == key and isinstance(v, dict) and v.get("message"):
                return str(v["message"])
    return ""


async def _track_isolated_world(ctx, page, ext_name: str):
    """Follow the extension's content-script world on one page.

    Returns an async function that reads back whatever the monitor recorded
    there. A content script does not run in the page's JS world: it gets an
    isolated one that shares the DOM but not the JS objects, so the page-level
    hook cannot see it and its signals must be read through the world's own
    context id, learned from Runtime.executionContextCreated events.

    Only reads. The hook itself is baked into the declared content script
    files (`_patch_content_scripts_with_monitor`); installing it into a world
    after the fact was tried for scripts an extension registers from code, and
    removed: inside the VM it starved the extension's own background worker,
    which is exactly the observer effect an analyzer must not have.

    Chromium names that world after the extension's display name, and
    Playwright's own utility world is also of type "isolated", so the name
    match is what keeps the two apart. With no usable name there is nothing to
    match on and the reader returns nothing (main-world coverage still applies).
    """
    context_ids: List[int] = []
    cdp = None
    if ext_name:
        try:
            cdp = await ctx.new_cdp_session(page)

            def _on_context(event: dict) -> None:
                c = event.get("context") or {}
                aux = c.get("auxData") or {}
                if aux.get("type") == "isolated" and c.get("name") == ext_name:
                    context_ids.append(c["id"])

            cdp.on("Runtime.executionContextCreated", _on_context)
            await cdp.send("Runtime.enable")
        except Exception:
            cdp = None      # CDP unavailable: main-world coverage still applies

    async def pull() -> List[Dict]:
        out: List[Dict] = []
        if not cdp:
            return out
        for cid in list(context_ids):
            # a world that navigated away or was torn down answers with an
            # error, or not at all: either way it is skipped
            r = await _bounded(cdp.send("Runtime.evaluate", {
                "expression": "window.__c1_signals || []",
                "contextId": cid,
                "returnByValue": True,
            }), {})
            val = ((r or {}).get("result") or {}).get("value")
            if isinstance(val, list):
                for s in val:
                    s = dict(s)
                    s.setdefault("src", "content_script")
                    out.append(s)
        return out

    return pull


def _new_browse_report() -> Dict[str, Any]:
    return {
        "enabled": True, "visited": [], "failed": [],
        "dom_mutations": 0, "page_cookie_reads": 0, "page_eval_calls": 0,
        "content_script": {"requests": 0, "cookie_reads": 0, "key_listeners": 0},
        "console_errors": 0,
    }


async def _step(coro):
    """One browser call, bounded. A heavy real page in a slow or GPU-less VM can
    leave a call waiting indefinitely, and nothing in the visit is worth that."""
    return await asyncio.wait_for(coro, _BROWSE_STEP_SECONDS)


async def _browse_real_pages(ctx, holders: Dict[str, Any], phase: Dict[str, str],
                             ext_name: str, console_errors: List[int],
                             report: Dict[str, Any]) -> Dict[str, Any]:
    """Visit a few real public pages so the extension has something real to act on.

    Everything observed here is reported and none of it is scored: the sites'
    own scripts make requests, read cookies and call eval, and none of that is
    the extension's behaviour. (The extension's own requests still carry their
    source tag, so a background worker's calls stay attributable.)

    `report` is filled in as the visit goes, so when the caller's time budget
    cuts it short what was already seen is kept rather than thrown away.
    """
    phase["name"] = "browse"
    page = await _step(ctx.new_page())
    holders["browse"] = page

    def _on_console(msg) -> None:
        try:
            if msg.type == "error":
                console_errors[0] += 1
        except Exception:
            pass

    page.on("console", _on_console)
    await _step(page.add_init_script(_MONITOR_JS))
    pull_isolated = await _step(_track_isolated_world(ctx, page, ext_name))

    for url in _BROWSE_URLS:
        _progress(f"visiting {url}")
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=_BROWSE_NAV_TIMEOUT_MS)
            await page.wait_for_timeout(_BROWSE_DWELL_MS)
            try:
                await _step(page.evaluate("() => window.scrollTo(0, document.body.scrollHeight / 2)"))
            except Exception:
                pass
            await page.wait_for_timeout(500)
        except Exception as exc:
            report["failed"].append({"url": url, "error": (str(exc).split("\n")[0] or type(exc).__name__)[:120]})
            continue
        report["visited"].append(url)
        # Read this page's record before the next navigation replaces it.
        try:
            counters = await _step(page.evaluate("() => window.__c1_counters || {}"))
            report["dom_mutations"] += int((counters or {}).get("dom") or 0)
            signals = await _step(page.evaluate("() => window.__c1_signals || []"))
            report["page_cookie_reads"] += sum(1 for s in signals if s.get("t") == "cookie_read")
            report["page_eval_calls"]   += sum(1 for s in signals if s.get("t") == "eval")
        except Exception:
            pass
        try:
            cs_signals = await _step(pull_isolated())
        except Exception:
            cs_signals = []
        for s in cs_signals:
            kind = s.get("t")
            if kind in ("fetch", "xhr"):
                report["content_script"]["requests"] += 1
            elif kind == "cookie_read":
                report["content_script"]["cookie_reads"] += 1
            elif kind == "key_listener":
                report["content_script"]["key_listeners"] += 1

    report["console_errors"] = console_errors[0]
    try:
        await _step(page.close())
    except Exception:
        pass
    return report


# ── Observation ───────────────────────────────────────────────────────────────
# Adaptive-window tuning. An extension gets at least _MIN_OBSERVE_SECONDS
# regardless, and the window only closes early after _QUIET_PERIOD_SECONDS with
# no new network request and no new page signal. A sleeper that waits longer
# than the quiet period before acting would be missed — that is the trade, and
# `early_exit=False` buys the full fixed window back for a deep scan.
_MIN_OBSERVE_SECONDS   = 6.0
_QUIET_PERIOD_SECONDS  = 5.0
_ACTIVITY_POLL_SECONDS = 1.0


async def observe_extension(
    extension_path: str,
    timeout_seconds: int = 20,
    early_exit: bool = True,
    browse: bool = True,
) -> Dict[str, Any]:
    """
    Load an unpacked extension, observe it on a test page, and return scored
    behavioral signals.

    This is the observation half of the sandbox and carries NO containment of
    its own beyond a throwaway browser profile: it launches Chromium wherever
    the calling process happens to be. Isolation is the backend's job — call
    `run_sandbox()` unless you are a backend yourself.

    Args:
        extension_path:  Absolute path to the unpacked extension directory
                         (must contain manifest.json).
        timeout_seconds: How long to let the extension run on the test page.
        browse:          After the bait page, visit a few real public pages
                         and report what the extension did there. Reported
                         only; it never changes the score.

    Returns a dict matching the C1 dynamic output contract:
        {
          "executed":        bool,
          "score":           int  (0–100),
          "signals":         list[str],
          "network_requests": list[dict],   # each tagged with its source/phase
          "page_signals":    list[dict],
          "background_signals": list[dict],
          "content_script_signals": list[dict],
          "counters":        dict,          # DOM changes, console errors (bait page)
          "browse":          dict,          # what happened on the real pages
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
        # Activity from the extension's own service worker / background page —
        # a separate JS realm the page-level hooks cannot see.
        "background_signals": [],
        # Activity from the extension's content script — also a separate JS
        # realm (an "isolated world"), by design not the same realm a
        # page-level hook or even the background-page hook can see. All three
        # buckets are kept distinct so the evidence trail shows where each
        # signal actually came from; all three feed the same scoring.
        "content_script_signals": [],
        "detail": "",
        "error": None,
        # Whether Chromium actually loaded the extension. None means we could
        # not tell (the extension declares no background context to look for).
        # A dynamic score of 0 means nothing unless this is True.
        "extension_loaded": None,
        "load_error": None,
        # Counts that are not signals: DOM changes and console errors seen on
        # the bait page, and a record of the real-page visit (see `browse`).
        "counters": {},
        "opened_tabs": [],
        "browse": {},
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

        with tempfile.TemporaryDirectory(prefix="c1_sandbox_") as profile_dir, \
             tempfile.TemporaryDirectory(prefix="c1_ext_stage_") as stage_root:
            net_log: List[Dict] = []

            # Loaded from a copy, never the original: patching content script
            # files (below) must not mutate the extension the caller handed
            # in, and this is also where the VM backend's guest_agent.py
            # stages the extension for its own, unrelated reason (the read-
            # only mapping can't be written into by Chromium at load time).
            staged_ext_path = os.path.join(stage_root, "ext")
            shutil.copytree(ext_path, staged_ext_path)
            manifest = _read_manifest(staged_ext_path)
            _patch_content_scripts_with_monitor(staged_ext_path, manifest)

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
                        f"--disable-extensions-except={staged_ext_path}",
                        f"--load-extension={staged_ext_path}",
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--start-minimized",
                        "--disable-features=ExtensionManifestV2DeprecationWarning",
                        # A failed extension load raises a modal "Error Loading
                        # Extension" dialog that blocks the browser until it is
                        # dismissed — which nobody is there to do. Observed on
                        # an adblocker whose declarativeNetRequest rulesets
                        # could not be indexed: the run sat on the dialog for
                        # its whole timeout and reported a clean score.
                        "--noerrdialogs",
                        # The sandbox window is minimised, and Chromium throttles
                        # timers, renderers and occluded windows in the
                        # background. That suppresses exactly the delayed
                        # extension activity the sandbox exists to catch, so it
                        # has to be turned off — this is a detection fix as much
                        # as a speed one.
                        "--disable-background-timer-throttling",
                        "--disable-renderer-backgrounding",
                        "--disable-backgrounding-occluded-windows",
                        # Startup work the analysis never needs. Cuts several
                        # seconds off launch and stops Chromium's own service
                        # traffic being counted as the extension's.
                        "--no-first-run",
                        "--no-default-browser-check",
                        "--disable-default-apps",
                        "--disable-component-update",
                        "--disable-client-side-phishing-detection",
                        "--disable-sync",
                        "--disable-background-networking",
                        "--metrics-recording-only",
                        "--mute-audio",
                        "--disable-gpu",
                    ],
                )

                # Register the request listener immediately after context creation —
                # BEFORE ctx.new_page() — so background-page network calls made after
                # a short delay (setTimeout in the extension) are captured.
                #
                # `holders` and `phase` are read by the listener each time it
                # fires, so it can tag a request with the page it came from and
                # whether it happened on the bait page or the real-page visit.
                holders: Dict[str, Any] = {"bait": None, "browse": None}
                phase: Dict[str, str] = {"name": "bait"}

                def _req_cb(req) -> None:
                    try:
                        if req.url.startswith(_BAIT_ORIGIN):
                            return  # our own intercepted bait page, not extension traffic
                        if len(net_log) >= _MAX_NET_LOG:
                            return
                        entry = {
                            "url":           req.url[:300],
                            "method":        req.method,
                            "resource_type": req.resource_type,
                            "source":        _request_source(req, holders["bait"], holders["browse"]),
                            "phase":         phase["name"],
                        }
                        has_body, size, keys = _body_shape(req)
                        if has_body:
                            entry.update(has_body=True, body_size=size, body_keys=keys)
                        net_log.append(entry)
                    except Exception:
                        pass

                ctx.on("request", _req_cb)

                # A service worker can spin up the instant the extension loads —
                # potentially before this line runs — so the listener is attached
                # first and any worker that already exists is caught immediately
                # after, closing the race rather than assuming event order.
                instrumented: set = set()

                async def _instrument_worker(worker) -> None:
                    if id(worker) in instrumented:
                        return
                    instrumented.add(id(worker))
                    try:
                        await worker.evaluate(_SW_MONITOR_JS)
                    except Exception:
                        pass    # torn down before we could reach it

                async def _instrument_background_page(bg) -> None:
                    if id(bg) in instrumented:
                        return
                    instrumented.add(id(bg))
                    try:
                        await bg.evaluate(_MONITOR_JS)
                    except Exception:
                        pass

                ctx.on("serviceworker", lambda w: asyncio.ensure_future(_instrument_worker(w)))
                ctx.on("backgroundpage", lambda b: asyncio.ensure_future(_instrument_background_page(b)))
                for w in ctx.service_workers:
                    await _instrument_worker(w)
                for b in ctx.background_pages:
                    await _instrument_background_page(b)

                # Confirm the extension actually loaded before drawing any
                # conclusion from what it did or did not do. `manifest` was
                # already read from the staged copy above, when patching it.
                loaded, load_note = await _verify_extension_loaded(ctx, manifest)
                result["extension_loaded"] = loaded
                if loaded is False:
                    result["load_error"] = load_note

                # A service worker that started only once the background context
                # settled (rather than immediately at launch) would have missed
                # the sweep above — sweep again now that _verify_extension_loaded
                # has given it time to appear.
                for w in ctx.service_workers:
                    await _instrument_worker(w)
                for b in ctx.background_pages:
                    await _instrument_background_page(b)

                _progress("extension loaded=%s, opening the test page" % result["extension_loaded"])
                page = await ctx.new_page()

                # Inject monitoring hooks before any page script runs
                await page.add_init_script(_MONITOR_JS)

                # A content script runs in an isolated JS world the page-level
                # hook cannot see, so it is followed separately: the hook is
                # baked into the declared content script files (see
                # `_patch_content_scripts_with_monitor`) and read back through
                # the world's own context id. See `_track_isolated_world`.
                #
                # The name Chromium gives that world is the extension's
                # display name, so an i18n placeholder (`__MSG_x__`) in the
                # manifest is resolved from the extension's own _locales first.
                ext_name = _display_name(manifest, staged_ext_path)
                holders["bait"] = page
                bait_console = [0]

                def _on_bait_console(msg) -> None:
                    try:
                        if msg.type == "error":
                            bait_console[0] += 1
                    except Exception:
                        pass

                page.on("console", _on_bait_console)
                _pull_isolated_world_signals = await _track_isolated_world(ctx, page, ext_name)

                # Intercept the bait navigation instead of resolving it over the
                # network — see the _BAIT_ORIGIN comment for why this replaced a
                # data: URI. domcontentloaded, not networkidle: the page has no
                # real subresources, so networkidle only adds its own settle
                # delay to every analysis for nothing.
                await page.route(_BAIT_URL, _serve_bait_page)
                await page.goto(
                    _BAIT_URL,
                    wait_until="domcontentloaded",
                    timeout=12_000,
                )
                _progress("test page loaded, watching the extension for up to %ds" % int(min(max(timeout_seconds, 5), 30)))

                # Give the extension time to act on the page.
                #
                # Sitting out a fixed window is the single largest cost of a
                # VM-isolated analysis, and most of it is spent watching an
                # extension that already did everything it was going to do in
                # the first second. So: watch for activity, and stop once the
                # extension has gone quiet for long enough to be convincing.
                # The full window is still the cap, and an extension that keeps
                # acting is still watched for all of it.
                observe_secs = float(min(max(timeout_seconds, 5), 30))
                page_sigs: List = []
                bg_sigs: List = []
                cs_sigs: List = []
                observed_for = observe_secs

                if early_exit:
                    loop = asyncio.get_event_loop()
                    start = loop.time()
                    last_activity = start
                    last_counts = (0, 0, 0, 0)
                    min_observe = min(_MIN_OBSERVE_SECONDS, observe_secs)

                    while True:
                        elapsed = loop.time() - start
                        if elapsed >= observe_secs:
                            break
                        await asyncio.sleep(min(_ACTIVITY_POLL_SECONDS,
                                                observe_secs - elapsed))
                        # page navigated or closed: nothing to read
                        page_sigs = await _bounded(
                            page.evaluate("() => window.__c1_signals || []"), [])
                        # A service worker that starts mid-observation (on an
                        # alarm, or on first use) is only caught by instrumenting
                        # it here too, not just at start-of-run.
                        for w in ctx.service_workers:
                            await _instrument_worker(w)
                        for b in ctx.background_pages:
                            await _instrument_background_page(b)
                        bg_sigs = await _pull_background_signals(ctx)
                        cs_sigs = await _pull_isolated_world_signals()
                        counts = (len(net_log), len(page_sigs), len(bg_sigs), len(cs_sigs))
                        if counts != last_counts:
                            last_counts = counts
                            last_activity = loop.time()
                        elapsed = loop.time() - start
                        if (elapsed >= min_observe
                                and loop.time() - last_activity >= _QUIET_PERIOD_SECONDS):
                            break
                    observed_for = round(loop.time() - start, 1)
                else:
                    await asyncio.sleep(observe_secs)

                _progress("watched for %ss" % observed_for)
                # DOM changes and console errors on the bait page. Read now,
                # before any other page is opened, while "everything that
                # changed here was the extension" still holds.
                counters = await _bounded(page.evaluate("() => window.__c1_counters || {}"), {})
                result["counters"] = {"dom_mutations": int((counters or {}).get("dom") or 0),
                                      "console_errors": bait_console[0]}

                # Tabs the extension opened on its own (a welcome or survey page
                # is the usual one). The first request of such a tab happens
                # before the browser lets us watch it, so the tab itself is the
                # evidence, not its request.
                result["opened_tabs"] = [
                    t.url[:200] for t in ctx.pages
                    if t is not page and t.url.startswith(("http://", "https://"))
                ][:5]

                # Then a few real pages, so a content blocker or a content script
                # has something real to act on. Observed and reported, never
                # scored (see _browse_real_pages). Skipped when the extension
                # never loaded, since there is nothing to watch.
                if browse and result["extension_loaded"] is not False:
                    browse_report = _new_browse_report()
                    try:
                        await asyncio.wait_for(
                            _browse_real_pages(ctx, holders, phase, ext_name, [0], browse_report),
                            _BROWSE_BUDGET_SECONDS)
                    except asyncio.TimeoutError:
                        browse_report["error"] = ("stopped after %d s; what was seen so far is kept"
                                                  % int(_BROWSE_BUDGET_SECONDS))
                    except Exception as exc:
                        browse_report["error"] = (str(exc).split("\n")[0] or type(exc).__name__)[:160]
                    result["browse"] = browse_report
                    _progress("real-page visit done: %d visited, %d failed" % (
                        len(browse_report["visited"]), len(browse_report["failed"])))
                else:
                    result["browse"] = {"enabled": False}

                # Final read of whatever the monitor hooks recorded
                page_sigs = await _bounded(page.evaluate("() => window.__c1_signals || []"), page_sigs)
                bg_sigs = await _pull_background_signals(ctx)
                cs_sigs = await _pull_isolated_world_signals()
                result["observed_seconds"] = observed_for

                _progress("observation finished, closing the browser")
                try:
                    await asyncio.wait_for(ctx.close(), 30)
                except Exception:
                    pass        # the browser is torn down with the driver either way

        result["network_requests"]       = net_log
        result["page_signals"]           = page_sigs if isinstance(page_sigs, list) else []
        result["background_signals"]     = bg_sigs if isinstance(bg_sigs, list) else []
        result["content_script_signals"] = cs_sigs if isinstance(cs_sigs, list) else []

        if result["extension_loaded"] is False:
            # The browser ran, the extension did not. Reporting this as a
            # completed observation with a score of 0 would let a load failure
            # dilute the static verdict — which is how an 86/100 extension came
            # out at 60 and was downgraded from MALICIOUS to SUSPICIOUS.
            result["executed"] = False
            result["score"]    = 0
            result["signals"]  = ["EXTENSION_LOAD_FAILED"]
            result["error"]    = result["load_error"]
            result["detail"]   = (
                "Sandbox started but Chromium rejected the extension, so no "
                "behaviour could be observed. " + (result["load_error"] or "")
            )
        else:
            result["executed"] = True
            all_sigs = (result["page_signals"] + result["background_signals"]
                        + result["content_script_signals"])
            dyn_score, flags = _score(net_log, all_sigs)
            result["score"]   = dyn_score
            result["signals"] = flags
            result["detail"]  = (
                f"Sandbox completed. dynamic_score={dyn_score}. "
                f"Network={len(net_log)} requests, "
                f"PageSignals={len(result['page_signals'])}, "
                f"BackgroundSignals={len(result['background_signals'])}, "
                f"ContentScriptSignals={len(result['content_script_signals'])}."
            )
            if result["extension_loaded"] is None:
                result["detail"] += " Extension load could not be confirmed."
            if flags:
                result["detail"] += " Flags: " + ", ".join(flags) + "."

    except Exception as exc:
        result["error"]  = str(exc)
        result["detail"] = f"Sandbox error: {exc}"

    return result


# ── Containment ───────────────────────────────────────────────────────────────
# Process-wide defaults, set once from settings at startup (and again whenever
# the operator changes them). analyzer.py calls run_sandbox() from several
# places and none of them should have to know about isolation policy, so the
# choice lives here rather than being threaded through every call site.
_DEFAULT_BACKEND: str = ""            # "" = strongest available
_DEFAULT_NETWORK_POLICY: str = ""     # "" = backend default (unrestricted)


def configure(backend: str = "", network_policy: str = "") -> Dict[str, str]:
    """Set the isolation backend and network policy for subsequent analyses."""
    global _DEFAULT_BACKEND, _DEFAULT_NETWORK_POLICY
    _DEFAULT_BACKEND = (backend or "").strip().lower()
    _DEFAULT_NETWORK_POLICY = (network_policy or "").strip().lower()
    return current_configuration()


def current_configuration() -> Dict[str, str]:
    return {"backend": _DEFAULT_BACKEND or "auto",
            "network_policy": _DEFAULT_NETWORK_POLICY or "unrestricted"}


async def run_sandbox(
    extension_path: str,
    timeout_seconds: int = 20,
    backend: str = "",
    network_policy: str = "",
) -> Dict[str, Any]:
    """Run the dynamic analysis under the strongest isolation available.

    This is the entry point every caller should use. It selects an isolation
    backend, has that backend perform the observation, and attaches an
    `isolation` block stating what containment the run actually had — so a
    dynamic score is never reported without the context of where it was
    measured.

    Args:
        extension_path:  Absolute path to the unpacked extension directory.
        timeout_seconds: Observation window inside the sandbox.
        backend:         Force a specific backend by name ("inprocess",
                         "windows_sandbox"). Empty uses the configured
                         default, which in turn defaults to the strongest
                         available.
        network_policy:  "unrestricted" or "disabled" — backends that cannot
                         enforce it say so in their report rather than
                         pretending.

    Returns the observation payload plus `result["isolation"]`.
    """
    from .isolation import select_backend

    chosen, note = select_backend(
        backend or _DEFAULT_BACKEND,
        network_policy=network_policy or _DEFAULT_NETWORK_POLICY,
    )
    result = await chosen.run(extension_path, timeout_seconds)

    report = result.get("isolation")
    if isinstance(report, dict) and note and note not in report.get("warnings", []):
        report.setdefault("warnings", []).append(note)
    return result
