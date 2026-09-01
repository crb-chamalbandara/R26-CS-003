// ============================================================================
// WebSentinel C1 — SYNTHETIC content script (NOT real malware).
//
// Registered for <all_urls> so the fixture exercises has_content_scripts, and
// carries the keystroke-monitoring shape that a real infostealer would have.
// It captures nothing: the handler discards the event immediately and there is
// no storage, no network call, and no reference to any field value.
// ============================================================================
'use strict';

(function () {

  // Keystroke listener shape (→ keydown_listener). Deliberately inert.
  document.addEventListener('keydown', function (event) {
    void event;          // discarded — nothing is recorded, buffered, or sent
  }, true);

  // Session-token surface (→ cookie_in_code). Read and dropped.
  try { void document.cookie; } catch (_) {}

})();
