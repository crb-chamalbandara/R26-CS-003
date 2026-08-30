// ============================================================================
// WebSentinel C1 — SYNTHETIC main-world content script (NOT real malware).
//
// Declared with "world": "MAIN" so it runs in the page's own JavaScript context
// rather than the default isolated world. This matters: the dynamic sandbox
// instruments page built-ins (window.eval, document.cookie, addEventListener),
// and an ordinary MV3 content script CANNOT reach those — isolated worlds get
// their own wrappers, so the hooks never see it. Real infostealer extensions
// use world:"MAIN" for exactly this reason, to touch page state directly.
//
// Everything here is inert. Values are read and immediately discarded: nothing
// is stored, buffered, or transmitted from this file.
// ============================================================================
'use strict';

(function () {

  // Session-token read → cookie_read signal. Combined with the background
  // worker's POST, this is what raises COOKIE_EXFILTRATION_RISK.
  try { void document.cookie; } catch (_) {}

  // Keystroke monitoring shape → KEYBOARD_MONITORING. Handler discards input.
  try {
    document.addEventListener('keydown', function (event) { void event; }, true);
  } catch (_) {}

  // Dynamic code execution in page context → EVAL_AT_RUNTIME.
  // Trivial arithmetic; the point is that eval() genuinely runs.
  try { window.eval('1 + 1'); } catch (_) {}

})();
