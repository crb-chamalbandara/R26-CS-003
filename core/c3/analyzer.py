"""
C3 analyzer loop.

Periodically computes per-host features, scores them, persists alerts, broadcasts
status, and manages training-data collection mode.
"""
from __future__ import annotations

import asyncio
import csv
import os
import time
from datetime import datetime
from pathlib import Path

from .alert_store import c3_alert_store
from .ml_classifier import c3_ml_engine
from .feature_engine import FEATURE_ORDER, compute_features
from .interceptor import c3_interceptor
from .reputation_engine import c3_reputation_engine
from .risk_fusion import (
    BEACON_THRESHOLD,
    DEGRADED_CONTEXT_LABEL_THRESHOLD,
    HEURISTIC_WEIGHT,
    ML_WEIGHT,
    SUSPICIOUS_THRESHOLD,
    UNCONFIRMED_CAP,
    c3_risk_fusion,
)

# Confirmation bar for hosts on the known-safe list below: they legitimately
# produce beacon-shaped traffic, so they need much stronger evidence than the
# normal BEACON_THRESHOLD before a verdict is confirmed.
KNOWN_SAFE_CONFIRMATION_BAR = 0.85

# Fused-score floor for auto-block (opt-in; see enable_auto_block() below).
# Lowered 0.80 -> 0.75 on 2026-08-30 at explicit user request, after measuring
# that 0.80 was structurally unreachable for a beacon captured via direct
# browser navigation (the only capture path this backend's CDP interceptor
# reliably supports -- see test/C3/tc03_real_world_c2_beacon.py). That design
# makes same_site_ratio == 1.0, so risk_fusion.py's Rule-9-driven same-site
# dampener (heuristic *= 0.70) always applies; even with every other
# achievable heuristic rule firing and the ML score near 1.0, the fused score
# (ML_WEIGHT*ml + HEURISTIC_WEIGHT*heuristic -- reputation is never a scoring
# input, see risk_fusion.py's docstring) tops out around 0.78, so 0.80 is only
# reachable via ML+Heuristic if both signals genuinely peak together.
#
# RE-MEASURED 2026-09-13 against the current final model
# (models/c3_beacon_classifier.pkl) and the current 0.55/0.45 weight split --
# do this again after any future model or weight change, the number moves:
# the highest single-window fused score across all 52,599 real in-scope benign
# windows (background/idle context assumed, the same condition
# scripts/tune_c3_fusion_weights.py uses) is 0.7609, ABOVE this floor. Two
# windows exceed 0.75, both from CTU-13 lab-background traffic (not clean
# human browsing -- see the "capture background" row in
# C3_Final_Model_Results.md's beacon-shaped-window count), and both carry an
# ML score above 0.95 in isolation.
#
# This does NOT mean auto-block would fire on them: _handle_beacon() (which
# performs the block) only runs when verdict == "BEACON", and reaching BEACON
# already requires PERSISTENCE_CYCLES(3) consecutive live 10s-cycle
# observations at or above SUSPICIOUS from the SAME host (see the gate in
# _analyze_once() below) -- a fact this single offline capture window cannot
# test, because it is one measurement, not a live host sustaining evidence
# over time. scripts/measure_c3_autoblock_risk.py exists to measure exactly
# that host-level, persistence-gated question and its own output currently
# self-flags as inconclusive, for a different, structural reason: the offline
# corpus has no real browser-context signal to drive the heuristic side (see
# data/_c3_autoblock_risk.json's "warning" field). So the true operational
# false-auto-block rate remains genuinely unmeasured, not zero and not merely
# "not yet re-run" -- it is a real open question this project has not been
# able to answer from capture data alone, disclosed here rather than assumed
# safe because the old number happened to be below the floor.
#
# RE-MEASURED 2026-09-14 after the ML decision scale + rhythm-gated heuristic
# (the fused scale moved, so the numbers above are history). Held-out LOFO
# windows, every window - benign included - given the worst-case assumed
# context (idle user, background tab / foreground tab):
#   real human browsing (CTU-Normal, 3,898 windows): max fused 0.647 / 0.670,
#       none reach 0.75;
#   capture background (49,825 windows, automated OS traffic - not browser
#       traffic): 0.53% / 0.62% reach 0.75 (max 0.873 / 0.896);
#   confirmed C2 BEACON windows: median 0.833 / 0.856.
# The same persistence-gate caveat above still applies. Kept at 0.75: this is
# a safety setting the user chose, and nothing measured here argues for
# lowering it.
AUTO_BLOCK_SCORE_FLOOR = 0.75

# Timing-sample maturity horizon.
#
# A coefficient-of-variation estimate (iat_cv, the core beacon-timing signal)
# is only meaningful once several inter-arrival intervals have been observed;
# below that it is noise. The previous design handled this with a HARD on/off
# at 6 events plus a separate linear "sample-size confidence" that snapped to
# full at 9 events plus a hard 0.51 cap that released at exactly 10 -- three
# discontinuities a fast beacon crosses within one or two 10 s cycles, which
# is exactly why the ML score, the heuristic score AND the fused score were
# all seen to "jump from ~25% to ~80%+ in one step".
#
# Instead, _timing_confidence(n) below returns a 0..1 weight that ramps
# SMOOTHLY from the 6-event floor to a matured sample at
# _TIMING_CONF_FULL_EVENTS (= 2x the 10-event confirmation bar), and the
# timing-dependent signals (ML + the heuristic's regular-timing rules) are
# trusted in proportion to it. At w == 1.0 every downstream calculation
# collapses EXACTLY to the plain fusion, so a normal full window (>= 20
# events) is scored identically to having no maturity weighting at all --
# only the 6..19 event ramp-up region changes, and it changes from a cliff
# into a climb. This is model-averaging toward the no-timing-evidence
# prediction (a standard small-sample shrinkage), not a fixed cosmetic clamp
# on how fast the number may move.
_TIMING_CONF_MIN_EVENTS = 6    # 5 intervals -- floor for any CV estimate
_TIMING_CONF_FULL_EVENTS = 20  # 2x the allow_beacon bar -- a matured sample

# ---------------------------------------------------------------------------
# HEURISTIC RHYTHM RULES (see _heuristic_score)
# ---------------------------------------------------------------------------
# Clockwork: gaps nearly identical. Unchanged from the original Rule 1.
_CLOCKWORK_CV = 0.05
# Steady rhythm despite jitter, added 2026-09-14. iat_cv alone misses a
# "sleep + jitter" beacon: +/-20% jitter already puts iat_cv at ~0.12. These
# robust measures ignore a few outliers: iat_norm_mad = MAD / median gap,
# iat_spread_ratio = (p90 - p10) / median gap. The limits come from the jitter
# maths, NOT from fitting the evaluation data: uniform jitter of +/-J gives
# norm_mad ~ J/2 and spread ~ 1.6J, so 0.20 / 0.70 admit up to ~+/-40% jitter
# (Cobalt Strike's "50% jitter" setting included). Real browsing sits far away
# (held-out CTU-Normal medians 0.92 / 24).
_STEADY_NORM_MAD = 0.20
_STEADY_SPREAD = 0.70
# Below half a second the "rhythm" is a burst of page-load requests, not a
# check-in timer (the fastest test beacon in this repo polls every 1 s).
_STEADY_MIN_GAP_MS = 500.0
# Check-ins are small; media streaming is regular too but 100 KB+ per request.
_RULE_MAX_PAYLOAD = 8_000

# ---------------------------------------------------------------------------
# TEMPORAL PERSISTENCE GATE (the 2026-09-11 hardening pass, step 4)
# ---------------------------------------------------------------------------
# How many separate observations at or above SUSPICIOUS a host must produce
# before a BEACON verdict is CONFIRMED.
#
# The rationale is a real difference in behaviour, not a tuning knob: a C2
# beacon runs for minutes to hours, so it is present in observation after
# observation. The false-positive shapes this targets -- web-push keep-alives
# and extension filter-list updates -- are bursty: they look beacon-like in one
# or two windows and then stop. Every cycle used to be judged independently, so
# a single unlucky window could confirm a BEACON and an hour-old beacon got no
# more credit than one seen once.
#
# This does NOT raise any threshold. It makes the detector less impulsive, not
# less sensitive -- a genuine beacon clears it and simply takes longer.
#
# Measured, not assumed: see scripts/measure_c3_persistence.py.
PERSISTENCE_CYCLES = 3

# ---------------------------------------------------------------------------
# CONTEXT-BLIND BYPASS  (Section 8 Step 4, "THE SECOND, BIGGER PRIZE")
# ---------------------------------------------------------------------------
# OFF BY DEFAULT, DELIBERATELY. Turning this on changes what C3 is willing to
# confirm on a single signal, which risk_fusion.py's docstring calls "a product
# decision, not a tuning one". It is opt-in for the same reason auto-block is.
#
# WHAT IT DOES: when browser context could not be measured at all, the
# heuristic sits near 0 and BOTH_SIGNAL_FLOOR caps every score below BEACON --
# context-blind recall is 0.0000 by construction. With this enabled, a window
# may still confirm if ALL THREE hold:
#     1. the context was genuinely unavailable   (knowable only via Step 3)
#     2. ML >= CONTEXT_BLIND_ML_BYPASS           (0.95)
#     3. condition 2 has held for PERSISTENCE_CYCLES consecutive observations
#
# WHY IT IS DEFENSIBLE NOW WHEN THE SINGLE-WINDOW FORM WAS REJECTED.
# Section 3.4 rejected a single-window ML >= 0.95 bypass: 78.8% context-blind
# recall at a 0.441% false-beacon rate. Re-measured with the persistence
# requirement over the same in-scope population (55,844 windows / 55,514 real
# benign), scripts/measure_c3_persistence.py:
#
#     N    context-blind recall    false-beacon rate
#     1          78.79%                 0.2918%      <- reproduces Section 3.4
#     2          67.88%                 0.0540%
#     3          60.61%                 0.0270%      <- this setting
#     5          50.61%                 0.0018%
#
# N=1 reproducing 78.79% against the documented 78.8% is the check that the
# measurement is on the right population. At N=3 the false-beacon rate is ~16x
# below the rate that got the original form rejected, while 60.61% of
# context-blind C2 is still caught -- against 0.00% today.
#
# NOTE FOR ANYONE RE-RUNNING THIS: measure on the IN-SCOPE set (build_scoped),
# not the raw corpus. On the raw corpus the same code reports 3.95% recall,
# because the uncapped dead-channel and long-sequence windows swamp it, and
# that number led to the opposite conclusion on a first pass.
#
# SCALE NOTE (2026-09-14): the ML score compared against 0.95 is now on the
# model's decision scale (ml_classifier.to_decision_scale). The figures above
# were measured on the 2026-09-03 calibrated model's scale, so re-measure with
# scripts/measure_c3_persistence.py before ever enabling this.
CONTEXT_BLIND_BYPASS_ENABLED = False
CONTEXT_BLIND_ML_BYPASS = 0.95

# Well-known analytics, CDN, and ad-serving domains that legitimately produce
# high-frequency, low-payload, same-endpoint traffic resembling beacons.
_SAFE_HOST_SUFFIXES: tuple[str, ...] = (
    "google-analytics.com",
    "analytics.google.com",
    "googletagmanager.com",
    "googletagservices.com",
    "googlesyndication.com",
    "doubleclick.net",
    "pixel.facebook.com",
    "facebook.net",
    "pixel.twitter.com",
    "analytics.twitter.com",
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "use.fontawesome.com",
    "ajax.googleapis.com",
    "static.cloudflareinsights.com",
    # First-party product domains that legitimately produce regular
    # service-worker/background traffic (the exact case record_navigation()
    # in context_tagger.py was added to fix). Kept here too as a second,
    # independent safety net at the fusion layer rather than relying on the
    # navigation fix alone.
    "youtube.com",
    "accounts.google.com",
)


def _is_safe_host(host: str) -> bool:
    h = host.lower()
    return any(h == s or h.endswith("." + s) for s in _SAFE_HOST_SUFFIXES)


class C3Analyzer:
    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._broadcast = None
        self._host_scores: dict[str, dict] = {}
        self._last_alert_ts: dict[str, float] = {}
        self._collection_label: int | None = None
        self._collection_samples = 0
        self._last_collection_flush: str | None = None
        self._data_dir = Path(__file__).resolve().parents[2] / "data"
        self._collection_path = self._data_dir / "c3_collection_in_progress.csv"
        self._host_first_seen: dict[str, float] = {}
        # Temporal persistence state (Step 4). _host_streak counts consecutive
        # observations at or above SUSPICIOUS; _host_last_event_ts is what makes
        # "observation" mean "saw new traffic" rather than "the loop ran again"
        # -- see the gate in _analyze_once() for why that distinction decides
        # whether this gate works at all.
        self._host_streak: dict[str, int] = {}
        self._host_last_event_ts: dict[str, float] = {}
        # Separate counter for the context-blind bypass. It counts consecutive
        # observations at ML >= CONTEXT_BLIND_ML_BYPASS specifically, which is
        # the condition that was actually measured -- reusing _host_streak
        # (score >= SUSPICIOUS) would be a weaker requirement than the one the
        # 0.0270% false-beacon rate was measured under.
        self._host_ml_streak: dict[str, int] = {}
        # Per-host memo of the four PURE results below, keyed by a fingerprint of
        # the window they were computed from. The loop re-scores every host on
        # every 10s cycle whether or not it sent anything new, and a host that
        # went quiet keeps its window for up to 30 minutes -- so most cycles were
        # recomputing an identical answer. compute_features() plus one XGBoost
        # predict is ~1.8 ms per host, so 200 tracked hosts cost ~0.5 s of solid
        # event-loop time every cycle, which is exactly when the UI stutters.
        # Only pure functions of the window are memoised; fusion, the streak
        # counters, the verdict and alerting all still run every cycle, so the
        # decision path is unchanged.
        self._host_calc_cache: dict[str, tuple] = {}
        # Auto-blocking on a confirmed BEACON is opt-in, off by default. Blocking is
        # a hard-to-reverse action on live traffic and Playwright route-based
        # blocking does not guarantee interception of service-worker traffic, so
        # the default posture during research/evaluation is: alert always fires,
        # blocking only happens if explicitly enabled (see enable_auto_block()).
        self._auto_block_enabled: bool = False

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def start_loop(self, pw_session, broadcast_fn) -> None:
        if self.running:
            return
        self._broadcast = broadcast_fn
        self._task = asyncio.create_task(self._loop())

    async def stop_loop(self) -> None:
        if not self._task:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None
        # Clear per-host scoring state along with the loop -- c3_interceptor.stop()
        # clears the request windows it's derived from, so stale entries here would
        # otherwise linger in hosts()/status() (alerts_count, host summaries) after
        # a session restart even though the traffic that produced them is gone.
        self._host_scores.clear()
        self._host_calc_cache.clear()
        self._host_first_seen.clear()
        self._last_alert_ts.clear()
        self._host_streak.clear()
        self._host_last_event_ts.clear()
        self._host_ml_streak.clear()

    def status(self) -> dict:
        base = c3_interceptor.status()
        base.update({
            "analyzer_running": self.running,
            "alerts_count": c3_alert_store.count(),
            "ml_model_loaded": c3_ml_engine.model_loaded,
            # Where the model calls a window C2, on the scale the ML score is
            # shown and fused on (the decision scale: always 0.50). The
            # dashboard colours the ML score from here. None = no model.
            "ml_threshold": c3_ml_engine.decision_point,
            # The same point as a raw model probability (a 5% false-positive
            # budget, set at training time) - for reference and reports.
            "ml_raw_threshold": c3_ml_engine.threshold,
            # Real trained feature_importances_, not a hand-ranked guess --
            # powers the "what the model weighs most" chart in the Detection
            # Lab's HTML report. {} when no model is loaded.
            "ml_feature_importance": c3_ml_engine.feature_importance(),
            "ti_available": c3_reputation_engine.ti_available(),  # AbuseIPDB or VirusTotal configured
            "collection_active": self._collection_label is not None,
            "collection_label": self._collection_label,
            "collection_samples": self._collection_samples,
            "collection_path": str(self._collection_path),
            "last_collection_flush": self._last_collection_flush,
            "auto_block_enabled": self._auto_block_enabled,
            # Exposed so the dashboard can display/compare against the real
            # threshold instead of duplicating it as a second hardcoded
            # literal that could silently drift out of sync with this one.
            "auto_block_score_floor": AUTO_BLOCK_SCORE_FLOOR,
            # Same reason, for the fusion weights and verdict thresholds. The
            # dashboard used to hardcode `{ml: 0.45, heuristic: 0.55}` in its
            # own c3FusionWeights(); when risk_fusion.py moved to 0.55/0.45 on
            # 2026-09-03 the dashboard silently kept drawing the old split, so
            # its contribution donut disagreed with the score beside it. These
            # fields make risk_fusion.py the single source of truth.
            "fusion_ml_weight": ML_WEIGHT,
            "fusion_heuristic_weight": HEURISTIC_WEIGHT,
            "beacon_threshold": BEACON_THRESHOLD,
            "suspicious_threshold": SUSPICIOUS_THRESHOLD,
        })
        return base

    def enable_auto_block(self) -> dict:
        self._auto_block_enabled = True
        return self.status()

    def disable_auto_block(self) -> dict:
        self._auto_block_enabled = False
        return self.status()

    def hosts(self) -> list[dict]:
        summaries = {row["host"]: row for row in c3_interceptor.hosts_summary()}
        for host, result in self._host_scores.items():
            summaries.setdefault(host, {"host": host})
            summaries[host].update({
                "score": result.get("score", 0.0),
                "verdict": result.get("verdict", "SAFE"),
                "detail": result.get("detail", ""),
                "features": result.get("features", {}),
                "signal_breakdown": result.get("signal_breakdown", {}),
                # Steps 3 and 4. Without these the Host Analysis view cannot
                # show the context caveat or the sustained-evidence count, so
                # the same host reads differently depending on which tab it was
                # opened from -- which is exactly the kind of inconsistency
                # Step 3 exists to remove.
                "signal_detail": result.get("signal_detail", {}),
                "context_degraded_ratio": result.get("context_degraded_ratio", 0.0),
                "context_unavailable": result.get("context_unavailable", False),
                "persistence_streak": result.get("persistence_streak", 0),
                "persistence_required": result.get("persistence_required",
                                                   PERSISTENCE_CYCLES),
            })
        return sorted(
            summaries.values(),
            key=lambda item: (float(item.get("score") or 0.0), item.get("last_seen", "")),
            reverse=True,
        )

    def host_detail(self, host: str) -> dict:
        # Scoring window (<= 50, age-filtered) -- features shown here must reflect
        # what the score was computed from, so they stay tied to this window.
        window = c3_interceptor.host_events(host)
        # Full capture log -- every request to this host up to the point it was
        # blocked. This is what the Host Analysis request list / timeline show,
        # so the view is no longer silently truncated at 50.
        all_events = c3_interceptor.host_all_events(host)
        result = self._host_scores.get(host, {})
        # Only fall back to computing features here when the host has not been
        # scored yet. This runs on every click of a host row, and the analyzer
        # has almost always already stored the very features this would
        # recompute, so computing first and then discarding the result cost a
        # feature pass per popup for nothing.
        features = result.get("features")
        if features is None:
            features = compute_features(window) if window else {}
            # Threshold must match _analyze_once()'s timing floor (_TIMING_CONF_MIN_EVENTS)
            # -- otherwise a host with exactly 5 events could show live (unstripped) timing
            # features here before its first analyzer cycle, then have them zeroed out
            # once _analyze_once() actually scores it, showing two different feature
            # sets for the same window depending only on request timing.
            if window and len(window) < _TIMING_CONF_MIN_EVENTS:
                features = self._strip_timing_features(features)
        return {
            "host": host,
            "request_count": len(all_events) or len(window),
            "window_request_count": len(window),
            "events": all_events or window,
            "score": result.get("score", 0.0),
            "verdict": result.get("verdict", "SAFE"),
            "detail": result.get("detail", ""),
            "features": features,
            "signal_breakdown": result.get("signal_breakdown", {}),
            "signal_detail": result.get("signal_detail", {}),
        }

    def recent_requests(self, limit: int = 50) -> list[dict]:
        return c3_interceptor.recent_requests(limit)

    def start_collection(self, label: int) -> dict:
        self._collection_label = 1 if int(label) else 0
        self._collection_samples = 0
        self._last_collection_flush = None
        self._ensure_collection_file()
        return self.status()

    def stop_collection(self) -> dict:
        self._collection_label = None
        return self.status()

    def export_collection(self) -> dict:
        self._data_dir.mkdir(parents=True, exist_ok=True)
        if not self._collection_path.exists():
            self._ensure_collection_file()
        label = "mixed" if self._collection_label is None else str(self._collection_label)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        final_path = self._data_dir / f"c3_collection_{label}_{stamp}.csv"
        try:
            self._collection_path.replace(final_path)
        except FileNotFoundError:
            self._ensure_collection_file()
            self._collection_path.replace(final_path)
        self._collection_samples = 0
        self._last_collection_flush = None
        self._ensure_collection_file()
        return {"path": str(final_path), "status": "exported"}

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(10)
            try:
                await self._analyze_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                print(f"[C3] Analyzer loop error: {exc}")

    async def _analyze_once(self) -> None:
        # Auto-unblock any host whose 24h block window has passed. Cheap to
        # call every cycle -- sweep_expired_blocks() throttles its own real
        # work internally (see interceptor.py's _EXPIRY_SWEEP_INTERVAL_S), so
        # this is a no-op most cycles.
        unblocked = await c3_interceptor.sweep_expired_blocks()
        if unblocked and self._broadcast:
            await self._broadcast({"type": "c3_unblocked", "data": {"hosts": unblocked}})

        # Forget hosts that have been silent long enough that their events no
        # longer reach the scoring window, so the per-host stores do not grow for
        # the whole session. Hosts that are blocked, or that still carry a
        # non-SAFE verdict an analyst may be looking at, are kept. Like the block
        # sweep above this throttles its own real work, so it is a no-op on most
        # cycles.
        still_interesting = {
            host for host, result in self._host_scores.items()
            if result.get("verdict") in ("BEACON", "SUSPICIOUS")
        }
        for host in c3_interceptor.evict_idle_hosts(keep=still_interesting):
            self._host_scores.pop(host, None)
            self._host_calc_cache.pop(host, None)
            self._host_first_seen.pop(host, None)
            self._host_streak.pop(host, None)
            self._host_last_event_ts.pop(host, None)
            self._host_ml_streak.pop(host, None)

        snapshots = c3_interceptor.host_snapshots()
        now = datetime.now()
        now_ts = time.time()
        for scanned, (host, events) in enumerate(snapshots.items()):
            # Scoring a host is synchronous work on the shared event loop, so a
            # session with many live hosts would hold it for one long block and
            # visibly stutter the UI. Give the loop a chance to run between
            # hosts; the whole cycle still finishes in a fraction of the 10s
            # interval.
            if scanned and scanned % 25 == 0:
                await asyncio.sleep(0)
            if len(events) < 3:
                continue
            # A blocked host's window keeps holding whatever pre-block events
            # were already in it -- blocking does not clear it, and a truly
            # blocked host should generate no new traffic to replace them.
            # Without this check, the analyzer kept re-scoring that same
            # stale, already-perfect-looking beacon window on every 10s
            # cycle, re-confirming BEACON and re-alerting (and re-attempting
            # auto-block, a harmless no-op) roughly every 60s -- the
            # _handle_beacon() cooldown period -- even though zero new
            # traffic had actually occurred since the block took effect.
            # This is what made blocking look broken (a fresh "beacon
            # detected" toast a few minutes later) even when the live
            # traffic block itself was working correctly the whole time.
            # The host's real last score/verdict stays visible on the
            # dashboard regardless -- it is simply frozen at whatever
            # self._host_scores held at the moment the block was applied,
            # instead of being overwritten by a re-analysis of stale data.
            if c3_interceptor.is_blocked(host):
                continue
            # Known analytics/CDN/font hosts are no longer skipped outright -- a
            # compromised or abused "safe" host would otherwise be invisible to C3
            # entirely. Instead they are fully analyzed and a lowered-prior bar is
            # applied below, after the fusion score is computed.
            is_known_safe = _is_safe_host(host)
            # Navigation cooldown: new hosts produce a page-load burst that looks like a beacon.
            # Skip scoring for 15 s from first observation when the event window is still small.
            # Uses first-seen time + event count, not burst count, to avoid suppressing real beacons
            # that genuinely fire many requests at startup.
            if host not in self._host_first_seen:
                self._host_first_seen[host] = now_ts
            if len(events) < 15 and (now_ts - self._host_first_seen[host]) < 15.0:
                continue
            n_events = len(events)
            allow_beacon = n_events >= 10

            # ---- Feature views ---------------------------------------------
            # feats_full   : the real computed features (real iat_cv + timing
            #                stats).
            # feats_neutral: timing features neutralised (see
            #                _strip_timing_features) -- the "no trustworthy
            #                regular-timing signal" view.
            # Everything computed in this block is a pure function of `events`,
            # so when the window has not changed since the last cycle the answer
            # cannot have changed either. The fingerprint is the window's length
            # plus its first and last timestamps: a new request either grows the
            # deque or, once it is full at 50, pushes the oldest entry off and
            # moves the first timestamp, and host_events() ages entries off the
            # front the same way. model_loaded is in the key because a model
            # reload would change the ML score for an unchanged window.
            cache_key = (n_events,
                         float(events[0].get("timestamp") or 0.0),
                         float(events[-1].get("timestamp") or 0.0),
                         c3_ml_engine.model_loaded)
            cached = self._host_calc_cache.get(host)
            if cached is not None and cached[0] == cache_key:
                _, feats_full, feats_neutral, heur_full, flags_full, heur_neutral, ml_prob = cached
            else:
                feats_full = compute_features(events)
                feats_neutral = self._strip_timing_features(feats_full)
                if n_events < _TIMING_CONF_MIN_EVENTS:
                    # Fewer than 5 inter-arrival intervals -> no reliable timing
                    # signal at all; score exactly as if timing were neutralised
                    # (unchanged from the old hard allow_timing gate).
                    feats_full = feats_neutral
                # Every rule needs a timing rhythm, and the neutral view has no
                # timing, so heur_neutral is 0 on any real window.
                heur_full, flags_full = self._heuristic_score(feats_full)
                heur_neutral, _ = self._heuristic_score(feats_neutral)
                # On the model's decision scale (50% = its own C2 threshold).
                # This used to blend in a second score from a "timing-neutral"
                # vector (iat_cv forced to 1.0 while the other seven timing
                # features still said "perfectly on the clock") - an input no
                # real window produces.
                if c3_ml_engine.model_loaded and n_events >= _TIMING_CONF_MIN_EVENTS:
                    ml_prob, _ml_dt = c3_ml_engine.score(feats_full)
                else:
                    ml_prob = None
                self._host_calc_cache[host] = (cache_key, feats_full, feats_neutral,
                                               heur_full, flags_full, heur_neutral, ml_prob)

            # ---- Timing-sample maturity (0..1) ---------------------------
            # How much the timing-dependent signals are trusted yet. Ramps
            # smoothly 6 -> 20 events, then 1.0. Replaces the old hard
            # allow_timing on/off + _sample_size_confidence + fixed 0.51 cap
            # + per-cycle score clamp -- none of which tracked real evidence.
            w = self._timing_confidence(n_events)

            # ---- Heuristic: full-timing and timing-neutral views --------
            # heur_neutral is 0 on any real window, so the displayed heuristic is
            # simply scaled by maturity (w) - the same as the ML score and the
            # fused score below, so the three numbers stay in proportion.
            heuristic_disp = round(w * heur_full + (1.0 - w) * heur_neutral, 4)
            # Rule names are joined with ", " and the dashboard splits them back
            # into chips, so neither a rule name nor this message may hold a comma.
            heuristic_detail = "Heuristic: " + (
                ", ".join(flags_full) if flags_full
                else "no beacon rhythm in the timing (other rules need one)")

            # ---- ML -----------------------------------------------------
            # Scaled by timing maturity like the heuristic above.
            ml_full = c3_ml_engine.decision_score(ml_prob) if ml_prob is not None else None
            if ml_full is not None:
                ml_disp = round(w * ml_full, 4)
                ml_detail = (f"XGBoost model over {n_events} requests, raw output "
                             f"{ml_prob:.3f}, the model's C2 line is "
                             f"{c3_ml_engine.threshold:.3f} (shown as 50%)")
            else:
                ml_disp = None
                ml_detail = f"timing window too small (<{_TIMING_CONF_MIN_EVENTS} requests)"

            latest_url = str(events[-1].get("url") or "") if events else ""

            # ---- "Did we actually see new traffic?" ----------------------
            # Computed once here because BOTH persistence counters need it, and
            # the context-blind one is needed before fuse() runs. The analyzer
            # re-scores every host on every cycle whether or not it sent
            # anything new, so a counter that advanced per CYCLE would climb on
            # a host that had already gone silent -- see the persistence gate
            # below for the full reasoning.
            latest_ts = float(events[-1].get("timestamp") or 0.0) if events else 0.0
            prev_ts = self._host_last_event_ts.get(host)
            has_new_evidence = (prev_ts is None) or (latest_ts > prev_ts)
            self._host_last_event_ts[host] = latest_ts

            # ---- Context-blind bypass eligibility (Step 4, opt-in) -------
            # Counts consecutive observations at ML >= 0.95 -- the exact
            # condition the 0.0270% false-beacon rate was measured under.
            if ml_full is not None and float(ml_full) >= CONTEXT_BLIND_ML_BYPASS:
                ml_streak = self._host_ml_streak.get(host, 0)
                if has_new_evidence:
                    ml_streak += 1
            else:
                ml_streak = 0
            self._host_ml_streak[host] = ml_streak

            # ---- Reputation: reuse the last fresh TI result for this host
            # (populated by _handle_beacon()'s beacon-triggered lookup). This
            # is analyst-facing evidence shown alongside the score, NOT a
            # score input -- fuse() is called with reputation=None below and
            # ignores it regardless (see core/c3/risk_fusion.py). cached_result()
            # returns clean 0.0 lookups too, so the dashboard can show the real
            # per-source AbuseIPDB / VirusTotal numbers once a beacon is checked.
            rep_cached = c3_reputation_engine.cached_result(host)
            reputation_sources = dict((rep_cached or {}).get("sources") or {})
            reputation_score = (
                float(rep_cached["score"]) if (rep_cached and reputation_sources) else None
            )

            # ---- Fuse, then interpolate by timing-sample maturity -------
            # fusion_with_ml  : full timing signals + ML  (what a mature
            #                   window is judged on).
            # fusion_no_timing: timing-neutral heuristic only, no ML  (what
            #                   we could conclude with no timing evidence).
            # The reported score rides from the LOWER of the two up to
            # fusion_with_ml as the timing sample matures (w: 0 -> 1). The
            # min() anchor means a window can never read HIGHER early (while
            # immature) than the mature judgement it is heading toward, so
            # the number only ever climbs toward the truth, never overshoots
            # and settles back. At w == 1 this is exactly fusion_with_ml,
            # i.e. the plain fusion -- no residual effect on mature windows.
            # Context quality (Step 3). Share of this window's events whose
            # browser context was substituted rather than measured. Passed to
            # fuse() for the verdict caveat only -- it does not move the score.
            degraded_ratio = float(feats_full.get("degraded_context_ratio", 0.0) or 0.0)
            # All three conditions, or nothing. The flag is False by default.
            context_blind_ok = bool(
                CONTEXT_BLIND_BYPASS_ENABLED
                and degraded_ratio >= DEGRADED_CONTEXT_LABEL_THRESHOLD
                and ml_streak >= PERSISTENCE_CYCLES
            )
            fusion_with_ml = c3_risk_fusion.fuse(ml_full, None, heur_full,
                                                 degraded_ratio, context_blind_ok)
            fusion_no_timing = c3_risk_fusion.fuse(None, None, heur_neutral, degraded_ratio)
            anchor = min(fusion_no_timing["score"], fusion_with_ml["score"])
            score = anchor + w * (fusion_with_ml["score"] - anchor)
            detail = fusion_with_ml["detail"] if w >= 0.5 else fusion_no_timing["detail"]
            if w < 1.0:
                detail += (f"; timing sample {n_events}/{_TIMING_CONF_FULL_EVENTS} requests")

            verdict = ("BEACON" if score >= BEACON_THRESHOLD
                       else "SUSPICIOUS" if score >= SUSPICIOUS_THRESHOLD else "SAFE")

            # Hard confirmation floor: never CONFIRM a beacon on fewer than
            # 10 requests, whatever the score (C3's sustained-evidence
            # stance). Only the verdict is held back here -- the score
            # itself is left to keep climbing so the dashboard still shows
            # progress toward confirmation.
            if verdict == "BEACON" and not allow_beacon:
                verdict = "SUSPICIOUS"
                detail += f"; {n_events}/10 requests before confirming"

            # Lowered-prior handling for known-safe hosts: still fully scored
            # above, but require much stronger evidence (>=0.85) before
            # confirming BEACON, since this class of host legitimately
            # produces beacon-shaped traffic.
            if is_known_safe and score < KNOWN_SAFE_CONFIRMATION_BAR:
                if score >= BEACON_THRESHOLD:
                    score = UNCONFIRMED_CAP
                verdict = "SUSPICIOUS" if score >= SUSPICIOUS_THRESHOLD else "SAFE"
                detail += (f"; known analytics/CDN host, confirm bar "
                           f"{KNOWN_SAFE_CONFIRMATION_BAR:.0%}")

            # ---- Temporal persistence gate (Step 4) ---------------------
            # Placed AFTER the known-safe cap so it gates the final score.
            #
            # "Observation" must mean "we saw new traffic", not "the loop ran
            # again". The analyzer re-scores every host with >= 3 events in its
            # rolling window on EVERY 10s cycle, whether or not that host sent
            # anything new -- the window is a deque that keeps its contents. So
            # a naive per-cycle counter would keep climbing on a host that had
            # already gone silent, and would confirm BEACON on exactly the
            # bursty-then-stopped traffic this gate exists to reject. It would
            # have looked like it worked while doing the opposite.
            #
            # Hence: advance only when the newest event is newer than the last
            # one we counted. A cycle with no new traffic HOLDS the streak
            # rather than resetting it, because a 60s beacon only produces new
            # events every sixth cycle and resetting would make it unconfirmable.
            # The streak resets only when the evidence itself falls away, i.e.
            # the score drops below SUSPICIOUS.
            #
            # has_new_evidence is computed ONCE, earlier in this loop, because
            # the context-blind bypass counter needs it before fuse() runs.
            # Do not recompute it here: _host_last_event_ts has already been
            # updated by then, so a second computation reads prev_ts == latest_ts
            # and returns False every time -- which would silently freeze this
            # streak at 0 and stop any beacon from ever being confirmed.
            if score >= SUSPICIOUS_THRESHOLD:
                streak = self._host_streak.get(host, 0)
                if has_new_evidence:
                    streak += 1
            else:
                streak = 0
            self._host_streak[host] = streak

            if verdict == "BEACON" and streak < PERSISTENCE_CYCLES:
                verdict = "SUSPICIOUS"
                detail += (f"; {streak}/{PERSISTENCE_CYCLES} sustained observations, "
                           f"a beacon must persist before it is confirmed")

            signal_breakdown = {
                "ml": ml_disp,
                "reputation": reputation_score,
                "reputation_sources": reputation_sources,
                "heuristic": heuristic_disp,
            }
            context_unavailable = bool(fusion_with_ml.get("context_unavailable"))
            signal_detail = {
                "ml": ml_detail,
                "reputation": ((rep_cached or {}).get("detail")
                               or "Runs once a beacon is confirmed"),
                "heuristic": heuristic_detail,
                "fusion": detail,
                # Step 3: say plainly whether the browser-context half of the
                # evidence was measured or substituted. An analyst reading a
                # low heuristic score needs to know which of the two it was.
                "context": (
                    f"Browser context substituted for {degraded_ratio:.0%} of "
                    f"requests, heuristic evidence is not fully measured"
                    if context_unavailable else
                    (f"Browser context measured for all {n_events} requests"
                     if degraded_ratio <= 0.0 else
                     f"Browser context substituted for {degraded_ratio:.0%} of requests")
                ),
            }

            result = {
                "score": round(score, 4),
                "verdict": verdict,
                "detail": detail,
                "source": "fusion",
                "signal_breakdown": signal_breakdown,
                "signal_detail": signal_detail,
                "host": host,
                "latest_url": latest_url,
                "features": feats_full,
                "request_count": n_events,
                "timestamp": now.isoformat(),
                # Step 3 -- surfaced as first-class fields so the dashboard and
                # the alert log can show the caveat without re-deriving it.
                "context_degraded_ratio": round(degraded_ratio, 4),
                "context_unavailable": context_unavailable,
                # Step 4 -- how much sustained evidence this host has produced.
                "persistence_streak": streak,
                "persistence_required": PERSISTENCE_CYCLES,
            }
            self._host_scores[host] = result
            self._append_collection_row(host, result)

            # Alert only on a cycle that saw new traffic from this host. The
            # scoring window keeps a host's last requests for up to 30 minutes
            # after it goes quiet, and re-scoring that unchanged window
            # re-confirms BEACON every cycle - so a beacon that had STOPPED kept
            # writing a fresh alert every 60 s (the _handle_beacon cooldown) on
            # evidence that never changed. Measured 2026-09-14 on this loop: 10
            # new alerts in 10 quiet minutes. A live beacon is unaffected: it
            # keeps sending, so it still re-alerts at most once per cooldown.
            # The dashboard keeps showing the host's last verdict either way.
            if result["verdict"] == "BEACON" and has_new_evidence:
                await self._handle_beacon(host, result)

        if self._broadcast:
            await self._broadcast({"type": "c3_status", "data": self.status()})

    async def _handle_beacon(self, host: str, result: dict) -> None:
        last = self._last_alert_ts.get(host, 0.0)
        if time.time() - last < 60:
            return
        self._last_alert_ts[host] = time.time()

        # Run the threat-intel lookup now that a BEACON is confirmed (this
        # timing preserves API rate limits). The result is recorded as
        # analyst-facing evidence on the alert -- it does NOT change the risk
        # score or the verdict, both of which were already decided by the
        # ML + heuristic fusion (see core/c3/risk_fusion.py).
        latest_url = str(result.get("latest_url", ""))
        rep = await c3_reputation_engine.score_beacon(host, latest_url)
        # Per-source scores (0-1), e.g. {"abuseipdb": 0.0, "virustotal": 0.0}.
        # A real lookup ran iff at least one source returned a value (or the
        # combined result is flagged); a clean 0.0 is a real answer and IS
        # shown (as "AbuseIPDB 0% / VirusTotal 0%").
        rep_sources = dict(rep.get("sources") or {})
        rep_ran = bool(rep_sources) or bool(rep.get("flagged"))
        rep_score = float(rep.get("score", 0.0)) if rep_ran else None

        # Attach reputation data as evidence only (never touches score/verdict).
        result["signal_breakdown"]["reputation"] = rep_score
        result["signal_breakdown"]["reputation_sources"] = rep_sources
        result["signal_detail"]["reputation"] = rep.get("detail", "")
        if rep.get("flagged"):
            result["detail"] += f" | TI: {rep.get('detail', '')}"

        if host in self._host_scores:
            hs = self._host_scores[host]
            hs["detail"] = result["detail"]
            hs["signal_breakdown"]["reputation"] = rep_score
            hs["signal_breakdown"]["reputation_sources"] = rep_sources
            hs["signal_detail"]["reputation"] = rep.get("detail", "")

        alert = c3_alert_store.add_alert(result)
        if self._auto_block_enabled and result.get("score", 0.0) >= AUTO_BLOCK_SCORE_FLOOR:
            await c3_interceptor.block_host(
                host, reason="auto-block: confirmed BEACON", score=result.get("score", 0.0),
            )
        if self._broadcast:
            await self._broadcast({"type": "c3_alert", "data": alert})

    def _append_collection_row(self, host: str, result: dict) -> None:
        if self._collection_label is None:
            return
        self._ensure_collection_file()
        features = result.get("features") or {}
        row = {
            "timestamp": result.get("timestamp", datetime.now().isoformat()),
            "host": host,
            "label": self._collection_label,
            "score": result.get("score", 0.0),
            "verdict": result.get("verdict", "SAFE"),
            "request_count": result.get("request_count", 0),
        }
        row.update({name: features.get(name, 0.0) for name in FEATURE_ORDER})
        with open(self._collection_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self._collection_fields())
            writer.writerow(row)
        self._collection_samples += 1
        self._last_collection_flush = datetime.now().isoformat()

    def _ensure_collection_file(self) -> None:
        self._data_dir.mkdir(parents=True, exist_ok=True)
        if self._collection_path.exists() and os.path.getsize(self._collection_path) > 0:
            return
        with open(self._collection_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self._collection_fields())
            writer.writeheader()

    @staticmethod
    def _timing_confidence(n_events: int) -> float:
        """Timing-sample maturity as a smooth 0..1 weight (see the
        _TIMING_CONF_* constants at module level for the full rationale).

          n <= 6   -> 0.0   (fewer than 5 intervals: no CV estimate at all)
          6 < n < 20 -> smoothstep ramp, eased at both ends (no slope kink
                        at either boundary, so nothing "snaps" as the count
                        crosses an integer)
          n >= 20  -> 1.0   (a matured timing sample; downstream math then
                        collapses exactly to the plain fusion)

        Callers weight the timing-dependent signals (ML score + the
        heuristic's regular-timing rules) by this, so the same real evidence
        is revealed gradually as it accrues instead of in one step."""
        lo, hi = _TIMING_CONF_MIN_EVENTS, _TIMING_CONF_FULL_EVENTS
        if n_events <= lo:
            return 0.0
        if n_events >= hi:
            return 1.0
        t = (n_events - lo) / (hi - lo)
        return t * t * (3.0 - 2.0 * t)  # smoothstep

    @staticmethod
    def _strip_timing_features(features: dict) -> dict:
        """Neutralise timing features for windows too small (<6 events) for
        stable inter-arrival statistics.

        iat_mean_ms / iat_bowley_skewness / iat_mad_ms -> 0.0 (their natural
        "no signal" value). Both heuristic rhythm rules require
        ``iat_mean_ms > 0``, and every other heuristic rule needs a rhythm, so
        a stripped window always scores 0 on the heuristic.

        iat_cv -> 1.0, NOT 0.0.  iat_cv measures how regular the timing is,
        where 0.0 means *perfectly metronomic*, so zeroing an unmeasured
        window would make it look like a flawless beacon to any
        ``iat_cv < threshold`` check.  1.0 = "irregular / unknown".
        """
        trimmed = dict(features)
        trimmed["iat_mean_ms"] = 0.0
        trimmed["iat_bowley_skewness"] = 0.0
        trimmed["iat_mad_ms"] = 0.0
        trimmed["iat_cv"] = 1.0
        return trimmed

    @staticmethod
    def _median_gap_ms(features: dict) -> float:
        """Median gap between requests, recovered from two features every window
        already carries (iat_norm_mad = MAD / median). Falls back to the mean
        when the MAD is exactly 0 (more than half the gaps identical)."""
        norm_mad = float(features.get("iat_norm_mad", 0.0))
        if norm_mad > 0:
            return float(features.get("iat_mad_ms", 0.0)) / norm_mad
        return float(features.get("iat_mean_ms", 0.0))

    @staticmethod
    def _heuristic_score(features: dict) -> tuple[float, list[str]]:
        """Rule-based beacon score, 0..1, plus the plain-language rule names
        that fired (shown to the analyst as-is).

        A beacon is traffic that repeats on a timer, so the rules ask one
        question first - does the timing have a beacon rhythm? - and count the
        supporting evidence only when it does. Supporting evidence on its own
        (the user is idle, the tab is hidden) describes most of the web: that
        alone, plus a high ML score, is what confirmed an ad-verification CDN
        with random timing (cdn.doubleverify.com, iat_cv 3.36) as a BEACON on
        2026-09-11. Rework measured on held-out real windows and on real live
        windows before it was adopted - see risk_fusion.py's rule 2.
        """
        iat_cv = float(features.get("iat_cv", 1.0))
        iat_mean = float(features.get("iat_mean_ms", 0.0))
        uar = float(features.get("user_active_ratio", 1.0))
        payload_mean = float(features.get("payload_size_mean", 0.0))

        # ---- 1. Rhythm (required) ----------------------------------------
        # Only a real timing sample counts (iat_mean > 0 - the small-window
        # view in _strip_timing_features zeroes it), only while the user is
        # not actively interacting, and only for small messages: media
        # streaming is also perfectly regular but moves 100 KB+ per request,
        # while C2 check-ins are almost always under 2 KB (8 KB = headroom).
        score = 0.0
        flags: list[str] = []
        can_beacon = iat_mean > 0 and uar < 0.50 and payload_mean < _RULE_MAX_PAYLOAD
        if can_beacon and iat_cv < _CLOCKWORK_CV:
            score += 0.30
            flags.append("clockwork timing (near-identical gaps)")
        elif (can_beacon
              and float(features.get("iat_norm_mad", 1.0)) <= _STEADY_NORM_MAD
              and float(features.get("iat_spread_ratio", 99.0)) <= _STEADY_SPREAD
              and C3Analyzer._median_gap_ms(features) >= _STEADY_MIN_GAP_MS):
            score += 0.20
            flags.append("steady rhythm despite jitter")
        else:
            return 0.0, []

        # ---- 2. Supporting evidence (counted only with a rhythm) ------------
        bg = float(features.get("background_tab_ratio", 0.0))
        ext = float(features.get("extension_origin_ratio", 0.0))

        # Nobody touched the page for 30 s+ yet it keeps sending. Foreground
        # only - a hidden tab is the next rule.
        if uar < 0.05 and bg < 0.50 and float(features.get("avg_idle_time_ms", 0.0)) > 30_000:
            score += 0.25
            flags.append("fires while the user is idle")

        # Runs from a tab the user is not looking at. Smaller weight when an
        # extension is the source: ad blockers and password managers poll too.
        if bg > 0.80:
            if ext == 0.0:
                score += 0.20
                flags.append("runs in a background tab")
            else:
                score += 0.08
                flags.append("runs in a background tab (extension)")

        # An extension talking on a timer from the page the user is on - the
        # malicious-extension C2 shape (filter-list updates run in background).
        if ext > 0.5 and bg < 0.50:
            score += 0.10
            flags.append("extension traffic in the foreground")

        # Sent by page JavaScript (CDP initiator "script"), not by the HTML
        # parser loading the page. Weak on its own, so a small weight.
        if float(features.get("script_initiator_ratio", 0.0)) > 0.70:
            score += 0.05
            flags.append("started by page scripts")

        # One endpoint over and over. Measured WITHOUT the query string, so a
        # beacon that appends a random parameter per check-in
        # (/gate.php?r=8f21ba07) is still seen as one endpoint.
        if float(features.get("path_only_entropy", 1.0)) < 0.50:
            score += 0.10
            flags.append("same endpoint every time")

        # C2 check-ins and exfiltration commonly POST. Only ever read together
        # with a rhythm, so an ordinary POST-heavy API client does not trigger it.
        if float(features.get("http_post_ratio", 0.0)) > 0.90:
            score += 0.08
            flags.append("mostly POST check-ins")

        # Polls faster than every ~7 s.
        if float(features.get("requests_per_hour", 0.0)) > 500:
            score += 0.08
            flags.append("frequent requests (over 500/hour)")

        # ---- 3. Same-site dampener (last, multiplicative) ------------------
        # SPAs (Slack, Gmail) legitimately poll their OWN backend on a timer.
        # When most requests go to the same site (eTLD+1) as the page the user
        # is on, everything above is reduced. It never adds suspicion.
        if float(features.get("same_site_ratio", 0.0)) > 0.80:
            score *= 0.70
            flags.append("same-site sync (score reduced)")

        return min(1.0, score), flags

    @staticmethod
    def _collection_fields() -> list[str]:
        return ["timestamp", "host", "label", "score", "verdict", "request_count", *FEATURE_ORDER]


c3_analyzer = C3Analyzer()

# =============================================================================
# WHAT THIS FILE DOES -- plain English summary
# =============================================================================
#
# This file is the orchestration loop for C3. Every 10 seconds it inspects the
# recent requests captured by the browser interceptor, groups them by destination
# host, computes the 32 C3 features for each host (feature_engine.py), and
# scores those features using the heuristic rules and the XGBoost classifier.
#
# The analyzer applies smooth gating so noisy or very small windows do not
# trigger false positives: the ML score, the heuristic score and the fused
# score are all scaled by how many inter-arrival intervals have been observed
# -- 0 below 6 events, ramping smoothly to full at 20 (_timing_confidence()) --
# so the three numbers climb together and stay in proportion. A host is only
# allowed to reach a confirmed BEACON verdict after at least 10 requests.
#
# The heuristic first asks whether the timing has a beacon rhythm (clockwork,
# or steady despite jitter); only then does it count supporting evidence such
# as an idle user, a hidden tab or one endpoint hit over and over. The ML score
# is shown on the model's decision scale, where 50% is the model's own C2 line.
#
# The risk score blends exactly two signals -- the ML score and the heuristic
# score (55% ML / 45% heuristic, see risk_fusion.py). A BEACON needs both to
# agree: ML at 50% or more and a rhythm in the timing. It stores per-host results for the
# dashboard, writes labeled rows to the collection CSV when collection mode is
# active, and, when a BEACON is confirmed, runs a threat-intel reputation
# lookup (recorded as analyst-facing evidence on the alert, not folded into
# the score), persists an alert, optionally blocks the host in the browser,
# and broadcasts the alert to listeners.
#
# The collection helpers in this file allow labeling and exporting training
# data so the models can be retrained from real browser captures.
# =============================================================================
