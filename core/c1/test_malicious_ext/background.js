// WebSentinel C1 — Synthetic malicious extension for sandbox verification.
// Uses patterns detectable by BOTH static ML and dynamic sandbox.
// MV3 service worker: eval() is blocked by CSP, so we use Function constructor
// and obfuscation patterns that the static analyser counts as red flags.
'use strict';

(function () {

  // ── Static signals ──────────────────────────────────────────────────────────

  // atob_count >= 3  →  BASE64_OBFUSCATION rule flag
  var _d1 = atob('aGVsbG8=');   // "hello"
  var _d2 = atob('d29ybGQ=');   // "world"
  var _d3 = atob('dGVzdA==');   // "test"

  // function_ctor_count  →  detected by features.py as obfuscation signal
  // eval_count (static scan counts this string too)
  var _fn1 = new Function('return ' + _d1);
  var _fn2 = new Function('return ' + _d2);
  var _fn3 = new Function('return ' + _d3);
  var _fn4 = new Function('return 1+1');
  var _fn5 = new Function('return 2+2');

  // exec_script_count >= 5  →  DYNAMIC_CODE_INJECTION rule flag
  // (static scanner counts occurrences of "executeScript" in source)
  // chrome.scripting.executeScript chrome.scripting.executeScript
  // chrome.scripting.executeScript chrome.scripting.executeScript
  // chrome.scripting.executeScript  — five static occurrences above

  // long_string_count  →  OBFUSCATED_STRINGS
  var _blob = 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWjAxMjM0NTY3ODk=';
  var _blob2 = 'dGhpcyBpcyBhIGxvbmcgb2JmdXNjYXRlZCBzdHJpbmcgdXNlZCBmb3IgdGVzdGluZyBwdXJwb3Nlcw==';
  var _blob3 = 'c3VzcGljaW91cyBsb25nIHN0cmluZyBudW1iZXIgdGhyZWUgZm9yIHN0YXRpYyBhbmFseXNpcw==';

  // cookie_in_code, keydown_listener, websocket_count, xhr_fetch_count
  // external_url_count: https://httpbin.org/post https://httpbin.org/get

  // ── Dynamic signals (delayed 3 s so ctx.on listener is registered first) ────
  setTimeout(function () {

    // XHR POST to external  →  DATA_POST_TO_EXTERNAL in sandbox
    var xhr = new XMLHttpRequest();
    xhr.open('POST', 'https://httpbin.org/post', true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(JSON.stringify({ payload: _d1 + _d2, blob: _blob.slice(0, 30) }));

    // WebSocket to external  →  WEBSOCKET_TO_EXTERNAL in sandbox
    try {
      var ws = new WebSocket('wss://echo.websocket.events');
      ws.addEventListener('open', function () { ws.send('probe'); ws.close(); });
    } catch (_) {}

    // Additional fetch calls → HIGH_REQUEST_VOLUME if > 8 external
    fetch('https://httpbin.org/get?q=1').catch(function () {});
    fetch('https://httpbin.org/get?q=2').catch(function () {});

  }, 3000);

})();
