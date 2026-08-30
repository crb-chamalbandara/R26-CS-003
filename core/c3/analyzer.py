"""
C3 analyzer loop.

Periodically computes per-host features, scores them, persists alerts, broadcasts
status, and manages training-data collection mode.
"""
from __future__ import annotations

import asyncio
import csv
import os
from datetime import datetime
from pathlib import Path

from .alert_store import c3_alert_store
from .anomaly_engine import c3_rf_engine
from .feature_engine import FEATURE_ORDER, compute_features
from .interceptor import c3_interceptor
from .reputation_engine import c3_reputation_engine
from .risk_fusion import (
    BEACON_THRESHOLD,
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
# achievable heuristic rule firing and the ML score near 1.0, the fused
# score (0.45*rf + 0.55*heuristic) tops out around 0.78 -- 0.80 could only
# ever be reached via reputation actually being flagged (i.e. a genuinely
# malicious IP), never through beacon timing/payload shape alone. 0.75 is
# still comfortably above BEACON_THRESHOLD (0.52) and the highest fused
# score any benign hard-negative window has been measured to reach
# (0.5138 -- see risk_fusion.py's threshold history), so this does not
# introduce new false auto-blocks; it only makes a confirmed, high-confidence
# BEACON (strong ML + multiple corroborating heuristic rules) reachable.
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
        # Per-host scoring inputs from the most recent _analyze_once() cycle
        # (rf_full, heur_full, heur_neutral, w). _handle_beacon() reuses them
        # to re-fuse with reputation on the SAME footing the cycle used, so
        # the reputation-enriched score never disagrees with what the next
        # cycle will independently recompute. Cleared in stop_loop() with the
        # rest of the per-host state.
        self._host_score_inputs: dict[str, dict] = {}
        self._last_alert_ts: dict[str, float] = {}
        self._collection_label: int | None = None
        self._collection_samples = 0
        self._last_collection_flush: str | None = None
        self._data_dir = Path(__file__).resolve().parents[2] / "data"
        self._collection_path = self._data_dir / "c3_collection_in_progress.csv"
        self._host_first_seen: dict[str, float] = {}
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
        # Clear per-host scoring state along with the loop — c3_interceptor.stop()
        # clears the request windows it's derived from, so stale entries here would
        # otherwise linger in hosts()/status() (alerts_count, host summaries) after
        # a session restart even though the traffic that produced them is gone.
        self._host_scores.clear()
        self._host_score_inputs.clear()
        self._host_first_seen.clear()
        self._last_alert_ts.clear()

    def status(self) -> dict:
        base = c3_interceptor.status()
        base.update({
            "analyzer_running": self.running,
            "alerts_count": c3_alert_store.count(),
            "rf_model_loaded": c3_rf_engine.model_loaded,
            "ti_available": c3_reputation_engine.ti_available(),  # any of AbuseIPDB / OTX / VirusTotal configured
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
            })
        return sorted(
            summaries.values(),
            key=lambda item: (float(item.get("score") or 0.0), item.get("last_seen", "")),
            reverse=True,
        )

    def host_detail(self, host: str) -> dict:
        # Scoring window (<= 50, age-filtered) — features shown here must reflect
        # what the score was computed from, so they stay tied to this window.
        window = c3_interceptor.host_events(host)
        # Full capture log — every request to this host up to the point it was
        # blocked. This is what the Host Analysis request list / timeline show,
        # so the view is no longer silently truncated at 50.
        all_events = c3_interceptor.host_all_events(host)
        result = self._host_scores.get(host, {})
        features = compute_features(window) if window else {}
        # Threshold must match _analyze_once()'s timing floor (_TIMING_CONF_MIN_EVENTS)
        # — otherwise a host with exactly 5 events could show live (unstripped) timing
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
            "features": result.get("features", features),
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
        import time as _time
        # Auto-unblock any host whose 24h block window has passed. Cheap to
        # call every cycle -- sweep_expired_blocks() throttles its own real
        # work internally (see interceptor.py's _EXPIRY_SWEEP_INTERVAL_S), so
        # this is a no-op most cycles.
        unblocked = await c3_interceptor.sweep_expired_blocks()
        if unblocked and self._broadcast:
            await self._broadcast({"type": "c3_unblocked", "data": {"hosts": unblocked}})

        snapshots = c3_interceptor.host_snapshots()
        now = datetime.now()
        now_ts = _time.time()
        for host, events in snapshots.items():
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
            # Known analytics/CDN/font hosts are no longer skipped outright — a
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
            feats_full = compute_features(events)
            feats_neutral = self._strip_timing_features(feats_full)
            if n_events < _TIMING_CONF_MIN_EVENTS:
                # Fewer than 5 inter-arrival intervals -> no reliable timing
                # signal at all; score exactly as if timing were neutralised
                # (unchanged from the old hard allow_timing gate).
                feats_full = feats_neutral

            # ---- Timing-sample maturity (0..1) ---------------------------
            # How much the timing-dependent signals are trusted yet. Ramps
            # smoothly 6 -> 20 events, then 1.0. Replaces the old hard
            # allow_timing on/off + _sample_size_confidence + fixed 0.51 cap
            # + per-cycle score clamp -- none of which tracked real evidence.
            w = self._timing_confidence(n_events)

            # ---- Heuristic: full-timing and timing-neutral views --------
            heur_full, flags_full = self._heuristic_score(feats_full)
            heur_neutral, flags_neutral = self._heuristic_score(feats_neutral)
            # Displayed heuristic climbs with maturity instead of snapping on
            # the instant the shared iat_cv rule-band is crossed.
            heuristic_disp = round(w * heur_full + (1.0 - w) * heur_neutral, 4)
            heuristic_flags = flags_full if w >= 0.5 else flags_neutral
            heuristic_detail = "Heuristic: " + (", ".join(heuristic_flags) if heuristic_flags else "no indicators")

            # ---- ML: full-timing and timing-neutral views --------------
            if c3_rf_engine.model_loaded and n_events >= _TIMING_CONF_MIN_EVENTS:
                rf_full, _rf_dt = c3_rf_engine.score(feats_full)
                rf_neutral, _ = c3_rf_engine.score(feats_neutral)
            else:
                rf_full = rf_neutral = None
            if rf_full is not None and rf_neutral is not None:
                rf_disp = round(w * rf_full + (1.0 - w) * rf_neutral, 4)
                rf_detail = (f"XGB timing-confidence-weighted: full={rf_full:.3f} "
                             f"neutral={rf_neutral:.3f} w={w:.2f} ({n_events} events)")
            elif rf_full is not None:
                rf_disp = round(rf_full, 4)
                rf_detail = f"XGB prob={rf_full:.4f}"
            else:
                rf_disp = None
                rf_detail = f"timing window too small (<{_TIMING_CONF_MIN_EVENTS} events)"

            latest_url = str(events[-1].get("url") or "") if events else ""

            # ---- Reputation: reuse the last fresh TI verdict for this host
            # (populated by _handle_beacon()'s beacon-triggered lookup).
            # Feeding it into every cycle keeps the fused score stable
            # between cycles instead of dropping the signal to None and
            # letting the score fall back down.
            reputation_score = c3_reputation_engine.cached_score(host)

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
            fusion_with_ml = c3_risk_fusion.fuse(rf_full, reputation_score, heur_full)
            fusion_no_timing = c3_risk_fusion.fuse(None, reputation_score, heur_neutral)
            anchor = min(fusion_no_timing["score"], fusion_with_ml["score"])
            score = anchor + w * (fusion_with_ml["score"] - anchor)
            detail = fusion_with_ml["detail"] if w >= 0.5 else fusion_no_timing["detail"]
            if w < 1.0:
                detail += (f"; timing-sample maturity {w * 100:.0f}% "
                           f"({n_events}/{_TIMING_CONF_FULL_EVENTS} events) — score "
                           f"climbs toward the timing-informed value as the window fills")

            verdict = ("BEACON" if score >= BEACON_THRESHOLD
                       else "SUSPICIOUS" if score >= SUSPICIOUS_THRESHOLD else "SAFE")

            # Hard confirmation floor: never CONFIRM a beacon on fewer than
            # 10 requests, whatever the score (C3's sustained-evidence
            # stance). Only the verdict is held back here -- the score
            # itself is left to keep climbing so the dashboard still shows
            # progress toward confirmation.
            if verdict == "BEACON" and not allow_beacon:
                verdict = "SUSPICIOUS"
                detail += f"; awaiting sustained evidence ({n_events}/10 requests) before confirming"

            # Lowered-prior handling for known-safe hosts: still fully scored
            # above, but require much stronger evidence (>=0.85) before
            # confirming BEACON, since this class of host legitimately
            # produces beacon-shaped traffic.
            if is_known_safe and score < KNOWN_SAFE_CONFIRMATION_BAR:
                if score >= BEACON_THRESHOLD:
                    score = UNCONFIRMED_CAP
                verdict = "SUSPICIOUS" if score >= SUSPICIOUS_THRESHOLD else "SAFE"
                detail += (f"; known analytics/CDN host — needs stronger evidence "
                           f"(score ≥ {KNOWN_SAFE_CONFIRMATION_BAR:.0%}) before confirming")

            # Carry the exact scoring inputs to _handle_beacon() so its
            # reputation re-fuse sits on the same footing this cycle used.
            self._host_score_inputs[host] = {
                "rf_full": rf_full,
                "heur_full": heur_full,
                "heur_neutral": heur_neutral,
                "w": w,
            }

            signal_breakdown = {
                "rf": rf_disp,
                "reputation": reputation_score,
                "heuristic": heuristic_disp,
            }
            signal_detail = {
                "rf": rf_detail,
                "reputation": (f"cached TI hit — score {reputation_score:.2f}"
                               if reputation_score is not None
                               else "pending beacon confirmation"),
                "heuristic": heuristic_detail,
                "fusion": detail,
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
            }
            self._host_scores[host] = result
            self._append_collection_row(host, result)

            if result["verdict"] == "BEACON":
                await self._handle_beacon(host, result)

        if self._broadcast:
            await self._broadcast({"type": "c3_status", "data": self.status()})

    async def _handle_beacon(self, host: str, result: dict) -> None:
        import time

        last = self._last_alert_ts.get(host, 0.0)
        if time.time() - last < 60:
            return
        self._last_alert_ts[host] = time.time()

        # Run reputation check now that a BEACON is confirmed — preserves API rate limits.
        latest_url = str(result.get("latest_url", ""))
        rep = await c3_reputation_engine.score_beacon(host, latest_url)
        rep_score = float(rep.get("score", 0.0)) if rep.get("flagged") else None

        # Re-fuse with the now-known reputation score, on the SAME
        # timing-sample-maturity footing _analyze_once() used this cycle
        # (reused from self._host_score_inputs), so the reputation-enriched
        # number never disagrees with what the next cycle independently
        # recomputes -- which, now that _analyze_once() also feeds the
        # cached reputation score into every fusion, it otherwise would.
        # score is only ever RAISED here (never lowered) and the verdict
        # stays pinned at BEACON: the cycle already confirmed BEACON from
        # ML + heuristic evidence alone, so reputation is corroboration that
        # can strengthen the persisted score but must never undo a verdict
        # already correctly reached without it.
        si = self._host_score_inputs.get(host)
        if si is not None:
            w = float(si.get("w", 1.0))
            heur_full = float(si.get("heur_full") or 0.0)
            heur_neutral = float(si.get("heur_neutral") or 0.0)
            rf_full = si.get("rf_full")
            ref_with_ml = c3_risk_fusion.fuse(rf_full, rep_score, heur_full)
            ref_no_timing = c3_risk_fusion.fuse(None, rep_score, heur_neutral)
            ref_anchor = min(ref_no_timing["score"], ref_with_ml["score"])
            refused_score = ref_anchor + w * (ref_with_ml["score"] - ref_anchor)
            refused_detail = ref_with_ml["detail"]
        else:
            # No cached inputs (host confirmed before _analyze_once cached
            # them, or a direct call) -- fall back to a plain single re-fuse
            # from the stored display signals.
            ref = c3_risk_fusion.fuse(
                result["signal_breakdown"].get("rf"), rep_score,
                result["signal_breakdown"].get("heuristic"),
            )
            refused_score = ref["score"]
            refused_detail = ref["detail"]
        if refused_score > result["score"]:
            result["score"] = round(refused_score, 4)
            result["detail"] += f" | re-fused with reputation: {refused_detail}"

        # Enrich stored result with reputation data.
        result["signal_breakdown"]["reputation"] = rep_score
        result["signal_detail"]["reputation"] = rep.get("detail", "")
        if rep.get("flagged"):
            result["detail"] += f" | TI: {rep.get('detail', '')}"

        if host in self._host_scores:
            self._host_scores[host]["score"] = result["score"]
            self._host_scores[host]["detail"] = result["detail"]
            self._host_scores[host]["signal_breakdown"]["reputation"] = rep_score
            self._host_scores[host]["signal_detail"]["reputation"] = rep.get("detail", "")

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
        "no signal" value; Rules 1/5/8 gate on ``iat_mean_ms > 0`` so a 0.0
        here blocks them).

        iat_cv -> 1.0, NOT 0.0.  iat_cv measures how regular the timing is,
        where 0.0 means *perfectly metronomic*.  Zeroing an unmeasured window
        makes it look like a flawless beacon to every ``iat_cv < threshold``
        check -- and Rules 4/6/7 test exactly that WITHOUT carrying the
        companion ``iat_mean_ms > 0`` guard that Rules 1/5/8 have, so a 4-5
        event window (e.g. a foreground extension) could otherwise pick up
        "regular timing" score with no timing evidence at all.  1.0 =
        "irregular / unknown", which is non-triggering for every rule (no
        rule fires on a HIGH iat_cv).
        """
        trimmed = dict(features)
        trimmed["iat_mean_ms"] = 0.0
        trimmed["iat_bowley_skewness"] = 0.0
        trimmed["iat_mad_ms"] = 0.0
        trimmed["iat_cv"] = 1.0
        return trimmed

    @staticmethod
    def _heuristic_score(features: dict) -> tuple[float, list[str]]:
        score = 0.0
        flags: list[str] = []

        iat_cv = float(features.get("iat_cv", 1.0))
        iat_mean = float(features.get("iat_mean_ms", 0.0))
        uar = float(features.get("user_active_ratio", 1.0))
        bg = float(features.get("background_tab_ratio", 0.0))
        ext = float(features.get("extension_origin_ratio", 0.0))
        path_ent = float(features.get("url_path_entropy", 1.0))
        avg_idle = float(features.get("avg_idle_time_ms", 0.0))
        payload_mean = float(features.get("payload_size_mean", 0.0))
        post_ratio = float(features.get("http_post_ratio", 0.0))
        req_rate = float(features.get("requests_per_hour", 0.0))

        # Rule 1: Very regular inter-arrival timing (strongest beacon signal).
        # iat_cv < 0.05 means near-perfect metronomic intervals.
        # Guard: only flag as beacon timing if user is NOT actively interacting AND
        # payload is small. Video streaming has iat_cv ≈ 0.01 but payload > 100 KB.
        # C2 beacons are almost always < 2 KB; 8 KB threshold gives safe headroom.
        if iat_cv < 0.05 and iat_mean > 0 and uar < 0.50 and payload_mean < 8_000:
            score += 0.30
            flags.append("regular timing (small payload)")

        # Rule 2: Foreground traffic firing with long idle time AND zero user activity.
        # Guard: skip if mostly background traffic (already covered by Rule 3).
        # Require BOTH uar=0 AND avg_idle > 30s to avoid false-firing on passive reading.
        # avg_idle > 30000ms (30s): user has been inactive for at least 30 seconds.
        if uar < 0.05 and bg < 0.50 and avg_idle > 30_000:
            score += 0.25
            flags.append("foreground requests firing while user idle")

        # Rule 3: Traffic predominantly from background tabs.
        # Reduced weight if extension origin already explains the background activity.
        if bg > 0.80:
            if ext == 0.0:
                score += 0.20
                flags.append("background traffic (non-extension)")
            else:
                score += 0.08
                flags.append("background traffic (extension)")

        # Rule 4: Extension-origin foreground beacon pattern.
        # Unconditional ext > 0 → +0.15 caused false positives on uBlock Origin / password
        # managers that fetch filter lists in the background. This compound version only fires
        # when extension requests are foreground (not background) AND timing is near-perfect —
        # a pattern that matches malicious extension C2 but not legitimate filter downloads.
        if ext > 0.5 and bg < 0.50 and iat_cv < 0.05:
            score += 0.10
            flags.append("extension foreground beacon pattern")

        # Rule 5: Same endpoint WITH regular timing AND no user activity — compound rule.
        # Standalone low-entropy fires on analytics/CDN; require all three conditions.
        if path_ent < 0.50 and iat_cv < 0.10 and iat_mean > 0 and uar < 0.50:
            score += 0.10
            flags.append("same endpoint with regular timing")

        # Rule 6: Script-initiated regular traffic — weak supporting signal.
        # CDP marks a request initiator.type == "script" when JS code (not the
        # HTML parser) triggered it; combined with regular timing this leans
        # toward programmatic/injected behaviour rather than a normal resource
        # load. No labeled data yet to calibrate this precisely, so the weight
        # is deliberately small and it never fires alone (matches how Rules
        # 4-5 already avoid single-weak-signal firing). Placed BEFORE Rule 9 so
        # a legitimate same-site SPA sync (which is also typically
        # script-initiated) gets this contribution dampened along with
        # Rules 1-3, rather than escaping the same-site guard.
        script_ratio = float(features.get("script_initiator_ratio", 0.0))
        if script_ratio > 0.70 and iat_cv < 0.10:
            score += 0.05
            flags.append("script-initiated regular traffic")

        # Rule 7: High POST ratio with regular timing. C2 frameworks commonly
        # use POST for check-ins/data exfil; no other rule here reads HTTP
        # method at all, so this is the only place that signal is used.
        # Guarded the same way Rule 1 is (regular timing + small payload) so
        # it does not fire on legitimate POST-heavy traffic (GraphQL/REST API
        # clients, which often POST even for reads).
        if post_ratio > 0.90 and iat_cv < 0.10 and payload_mean < 8_000:
            score += 0.08
            flags.append("high POST ratio with regular timing")

        # Rule 8: Sustained high request rate while the user is inactive.
        # requests_per_hour is mathematically close to 1 / iat_mean_ms, so it
        # mostly overlaps Rule 1 — its distinct value is not requiring Rule
        # 1's strict iat_cv < 0.05 near-perfect-regularity gate. A beacon
        # using deliberate timing jitter (a known evasion technique against
        # regularity-based detection) can dodge Rule 1 while still polling
        # frequently; this rule catches that case. Small weight, no
        # calibration data yet.
        # iat_mean > 0 reuses Rule 1/5's timing-reliability guard: it is 0.0
        # whenever the window is too small for stable stats (see
        # _strip_timing_features), which matters here because
        # requests_per_hour's own 60s floor still allows a legitimate
        # page-load burst to read up to ~1,200/hr (see the floor's comment
        # in feature_engine.py) — without this guard that burst alone could
        # clear the 500/hr threshold before there is enough data to trust it.
        if req_rate > 500 and uar < 0.50 and payload_mean < 8_000 and iat_mean > 0:
            score += 0.08
            flags.append("high-frequency requests while user inactive")

        # Rule 9: Same-site background sync dampener (Plane 2, deterministic —
        # measured from the browser's own DOM/CDP state, not learned).
        # SPAs (Slack/Gmail/etc.) legitimately fire regular, idle, background,
        # script-initiated requests to their OWN other subdomains — the exact
        # shape Rules 1-3 and 6-8 look for. same_site_ratio compares
        # destination vs. active-page eTLD+1 (via tldextract, so compound
        # TLDs like .co.uk are handled correctly). Applied multiplicative and
        # LAST: it only ever reduces suspicion caused by the rules above,
        # never adds any on its own, and never overrides a genuinely high
        # score from an unrelated destination.
        same_site = float(features.get("same_site_ratio", 0.0))
        if same_site > 0.80:
            score *= 0.70
            flags.append("same-site background sync (dampened)")

        return min(1.0, score), flags

    @staticmethod
    def _collection_fields() -> list[str]:
        return ["timestamp", "host", "label", "score", "verdict", "request_count", *FEATURE_ORDER]


c3_analyzer = C3Analyzer()

# =============================================================================
# WHAT THIS FILE DOES — plain English summary
# =============================================================================
#
# This file is the orchestration loop for C3. Every 10 seconds it inspects the
# recent requests captured by the browser interceptor, groups them by destination
# host, computes the 16 C3 features for each host, and scores those features
# using the heuristic rules and the RF classifier.
#
# The analyzer applies smooth gating so noisy or very small windows do not
# trigger false positives: the timing-dependent signals (the ML score and the
# heuristic's regular-timing rules) are trusted in proportion to how many
# inter-arrival intervals have been observed -- 0 below 6 events, ramping
# smoothly to full trust at 20 (_timing_confidence()) -- and a host is only
# allowed to reach a confirmed BEACON verdict after at least 10 requests.
# Browser-context heuristic rules run on all windows. This replaced an older
# hard on/off gate whose discontinuities made the ML, heuristic and fused
# scores appear to "jump" the instant an event count was crossed.
#
# The analyzer blends signals from heuristics, ML scores, and reputation
# (reusing the last fresh threat-intel verdict for a host between cycles). It
# stores per-host results for the dashboard, writes labeled rows to the
# collection CSV when collection mode is active, and, when a BEACON is
# confirmed, runs reputation checks, persists an alert, optionally blocks the
# host in the browser, and broadcasts the alert to listeners.
#
# The collection helpers in this file allow labeling and exporting training
# data so the models can be retrained from real browser captures.
# =============================================================================
