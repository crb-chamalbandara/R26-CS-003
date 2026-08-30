# C2 — Performance Optimization

C2 runs on **every navigation** and, after the multi-tab work, across multiple tabs on a single
asyncio event loop. Two optimization rounds reduced latency and stopped the pipeline from blocking
the loop — **without changing any verdict** (re-verified each round).

## Baseline (measured)

Per-layer CPU cost on a 22 KB DOM (no network):

| L1 BitB | L2 URL | L3 Visual | L4 Form | L6 Runtime |
|---------|--------|-----------|---------|-----------|
| **33.3 ms** | 6.9 ms | 8.8 ms | 0.2 ms | 0.0 ms |

Two structural problems were found:
1. The CPU layers were synchronous bodies inside `async def`, so each `await check_*` **blocked the
   event loop**; `analyze()` also awaited layers **sequentially**.
2. L5 reputation made a **PhishTank network POST on every navigation** (even with no GSB key), run
   sequentially with GSB (up to ~10 s), with a fresh HTTP client per call and no caching.

## Round 1 — concurrency, off-loop CPU, network

- **Concurrent layers:** `analyze()` now runs all layers with `asyncio.gather` (order preserved).
- **Off-loop CPU:** L1/L2/L3 expose a sync core run via `asyncio.to_thread`, so a big-DOM parse on
  one tab no longer freezes other tabs / the WebSocket.
- **L5 reputation:** GSB + PhishTank now run **concurrently**; a **10-min per-URL TTL cache**; a
  **shared `httpx` client**; 3 s timeout; and a `phishtank_enabled` gate.
- **Stop wasted captures:** the nav handler **skips the screenshot** when L3 is off or has no logo
  hashes, and **skips DOM/screenshot/runtime entirely** for verified/whitelisted/skip URLs.
- **L1 micro-opt:** lowercase the DOM once (was twice).

**Result:** full `analyze()` ≈ **44 ms** concurrent (vs ~53 ms sequential sum); a gated/cached L5
call ≈ **0.07 ms** (vs a multi-second PhishTank POST).

## Round 2 — repeat-visit memoization + hygiene

- **Per-layer content-hash memoization** (the main win). L1/L2/L3 are pure functions of their
  inputs, so each caches its result (bounded, FIFO):
  - L1 by `(url, blake2b(dom))`, L2 by `url`, L3 by `(url, blake2b(screenshot))`.
  - Safe & never stale — `analyze()` copies `score`/`detail` into fresh dicts, so cached objects
    are never mutated. Reloads / SPA re-fires / same-site tabs skip the recompute.
  - Measured: **L1 42 ms → 0.094 ms on a cache hit** (~450×), identical score; a changed DOM
    correctly recomputes.
- **Pre-compiled L1 regexes** (≈10 patterns compiled once at import).
- **Shared HTTP client closed on shutdown** (`aclose()` in L5, called from `lifespan`) — no
  leaked/unclosed-client warning.
- **Non-blocking broadcast:** `_broadcast` sends to all WebSocket clients via `asyncio.gather`, so
  one slow client can't delay per-tab live updates.

## Net effect

First visit to a page costs the same, but **reloads/revisits/same-site tabs are near-instant**
(L1's ~33–42 ms parse skipped), verified/whitelisted navigations capture nothing expensive, the
network stays off the hot path (reputation cache), and big-DOM analysis no longer stalls the
dashboard across tabs.

## Verification

After each round: `test/C2/test_layer6_runtime.py` (6/6), `test/C2/test_verified_domains.py` (8/8),
and the c2 live-runner cases (5/5) passed; L1 score unchanged (0.9994 on the test DOM); backend
compiles; dashboard JS passes `node --check`. ML inference under `to_thread` is thread-safe
(xgboost/sklearn predict; per-call BeautifulSoup).
