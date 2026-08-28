# C2 — Features Added & Design Rationale

## 1. Verified-domain trust gate

**Problem.** C2 flagged legitimate, complex sites (e.g. `google.com`) as risky: the L1 heuristics
fire on normal markup (`position:fixed`, high `z-index`, `user-select:none`/overlays) and L2 adds
keyword/brand points. There was no concept of a "known-good" site beyond a manual whitelist.

**Design.**
- A **world-verified allowlist** of the most popular domains, built from the **Tranco** list
  (research-grade, citable) into [`data/verified_domains.txt`](../../data/verified_domains.txt)
  (top 50,000) by [`scripts/fetch_verified_domains.py`](../../scripts/fetch_verified_domains.py).
- Matching is on the **registered domain (eTLD+1)** via `tldextract` (offline PSL snapshot), so
  `www.google.com → google.com`. See [`core/c2/verified_domains.py`](../../core/c2/verified_domains.py).
- **Shared-host exclusion.** Free/shared providers (`yolasite.com`, `weebly.com`, `github.io`, …)
  appear in Tranco, so a naive match would trust attacker subdomains like
  `paypal-login.yolasite.com`. The gate excludes these (reusing L2's `FREE_HOSTS` + extras).
- **Trust behaviour (in `analyze()`):** a verified domain **skips the FP-prone heuristic layers
  (L1/L2/L4)** but **still runs L5 reputation**. If reputation flags it → `PHISHING` (override);
  otherwise a new **`VERIFIED`** verdict (risk 0). This kills false positives while keeping a
  safety net for a compromised-but-listed domain.

**Result.** `google.com` → `VERIFIED` (0), while the same BitB DOM on a `.tk` or a
`*.yolasite.com` subdomain still gets the full scan.

## 2. L6 — Runtime Behavioral Layer (new)

**Motivation.** L1–L5 are static (DOM/URL/screenshot). BitB / credential-phishing kits also
exhibit *runtime* behaviour that static inspection misses.

**Signals & scoring** ([`core/c2/layer6_runtime.py`](../../core/c2/layer6_runtime.py)):
- keystroke listeners on the password field (keylogger) — strong
- clipboard hooks (copy/cut/paste) — medium
- drag / selection / context-menu blocking (kit anti-inspection) — weak (runtime confirm of L1)
- **off-origin credential exfil** — POST sinks to a different registrable host — strong

**Collection design (important).** The first implementation injected an in-page script that
overrode `fetch` / `XMLHttpRequest` / `addEventListener` before page scripts ran. This **broke
Cloudflare** (and other anti-bot) integrity checks → "checking your browser" loops. It was
re-implemented **non-invasively** in [`core/playwright_session.py`](../../core/playwright_session.py):
- off-origin POSTs are observed at the **network layer** (`context.on("request")`), and
- listener counts are read via the **Chrome DevTools Protocol** (`DOMDebugger.getEventListeners`)
  on `document` / `window` / password fields.

Neither touches the page's JavaScript, so real browsing (incl. Cloudflare sites) is unaffected.
The old in-page hook is retained **only** for offline batch capture (saved HTML, no anti-bot).

## 3. Threshold interstitial (warning / blocking / continue)

A risk-driven, in-browser interstitial shown in the live Chromium window
([`inject_interstitial`](../../core/playwright_session.py)):
- **block** (risk ≥ `block_threshold`, default 60): a full-page "Dangerous site blocked" overlay
  with the reasons, **Go back to safety**, and **Continue anyway**.
- **warn** (risk ≥ `warn_threshold`, default 30): a dismissible amber banner.

Both are pure client-side (Continue removes the overlay; Back uses history). Thresholds and an
on/off toggle are configurable in settings + the dashboard. **Timing note:** analysis runs on
`framenavigated` (after load), so the interstitial covers the loaded page *before the user
reads/submits* — it is an "after-load, before-interaction" guard, not a pre-request block.

## 4. Configurable + learned fusion

Previously the layer weights and verdict cutoffs were hard-coded. Now:
- `weights`, `verdict_suspicious`, `verdict_phishing` (and the interstitial thresholds + a
  `phishtank_enabled` flag) live in settings.
- `analyze()` fuses via `_fuse_score`: if [`models/c2_fusion.pkl`](../../models/) (a learned
  meta-classifier) is present **and all six layers ran**, it uses the calibrated probability;
  otherwise it falls back to the configurable **weighted sum**. This mirrors the existing
  "model-if-available, else heuristic" pattern.

## 5. Multi-tab correctness + per-tab Live Analysis UI

- **Correctness.** The session exposed a single "current page", so concurrent tab navigations all
  read the last tab's content. Per-page extraction now threads the specific `page` through
  `get_dom` / `get_screenshot_b64` / `get_title` / `get_runtime_signals` / `inject_interstitial`,
  with per-tab navigation de-dup and per-tab cleanup on close.
- **UI.** Each analysis carries a stable `tab_id` (+ title); the dashboard renders **one live card
  per open tab**, and a `tab_closed` event removes a tab's card. A `closedTabs` guard prevents a
  late in-flight analysis from re-creating a closed tab's card (ghost-card fix).
