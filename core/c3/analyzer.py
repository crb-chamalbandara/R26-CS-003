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
from .anomaly_engine import c3_anomaly_engine, c3_browser_anomaly_engine
from .feature_engine import FEATURE_ORDER, compute_features
from .interceptor import c3_interceptor
from .reputation_engine import c3_reputation_engine
from .risk_fusion import c3_risk_fusion

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

    def status(self) -> dict:
        base = c3_interceptor.status()
        base.update({
            "analyzer_running": self.running,
            "alerts_count": c3_alert_store.count(),
            "model_loaded": c3_anomaly_engine.model_loaded,
            "model_type": c3_anomaly_engine.model_type,
            "browser_model_loaded": c3_browser_anomaly_engine.model_loaded,
            "ti_available": c3_reputation_engine.ti_available(),
            "collection_active": self._collection_label is not None,
            "collection_label": self._collection_label,
            "collection_samples": self._collection_samples,
            "collection_path": str(self._collection_path),
            "last_collection_flush": self._last_collection_flush,
        })
        return base

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
        events = c3_interceptor.host_events(host)
        result = self._host_scores.get(host, {})
        features = compute_features(events) if events else {}
        if events and len(events) < 5:
            features = self._strip_timing_features(features)
        return {
            "host": host,
            "request_count": len(events),
            "events": events,
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
        snapshots = c3_interceptor.host_snapshots()
        now = datetime.now()
        for host, events in snapshots.items():
            if len(events) < 3:
                continue
            if _is_safe_host(host):
                continue
            features = compute_features(events)
            # Reliable timing features require at least 5 inter-arrival intervals (6 events).
            # Below that threshold, zero out timing so the model does not score on noise.
            # Browser-context features (idle_time, user_active, bg_tab) are always valid.
            allow_timing = len(events) >= 6
            allow_beacon = len(events) >= 10
            if not allow_timing:
                features = self._strip_timing_features(features)

            # Heuristic runs on ALL features — browser-context rules work even with <6 events.
            heuristic_score, heuristic_flags = self._heuristic_score(features)
            heuristic_detail = "Heuristic: " + (", ".join(heuristic_flags) if heuristic_flags else "no indicators")

            # Anomaly model only scores when timing is valid (allow_timing).
            anomaly_score, anomaly_detail = c3_anomaly_engine.score(features) if allow_timing else (None, "timing window too small (<6 events)")
            browser_score, browser_detail = c3_browser_anomaly_engine.score(features) if allow_timing else (None, "timing window too small")
            should_query_ti = (anomaly_score or 0.0) > 0.2 or (browser_score or 0.0) > 0.2 or heuristic_score > 0.2
            latest_url = str(events[-1].get("url") or "") if events else ""
            rep_result = await c3_reputation_engine.score_host(host, latest_url, should_query_ti)
            reputation_score = rep_result.get("score")

            fusion = c3_risk_fusion.fuse(anomaly_score, reputation_score, heuristic_score, browser_score)
            score = float(fusion.get("score", 0.0))
            verdict = fusion.get("verdict", "SAFE")
            detail = fusion.get("detail", "")

            if not allow_beacon and (reputation_score is None or float(reputation_score) < 0.8):
                if score >= 0.6:
                    score = 0.59
                verdict = "SUSPICIOUS" if score >= 0.3 else "SAFE"
                detail += "; early window capped below BEACON until 10 requests"

            signal_breakdown = {
                "anomaly": anomaly_score,
                "browser_anomaly": browser_score,
                "reputation": reputation_score,
                "heuristic": heuristic_score,
            }
            signal_detail = {
                "anomaly": anomaly_detail,
                "browser_anomaly": browser_detail,
                "reputation": rep_result.get("detail", ""),
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
                "features": features,
                "request_count": len(events),
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
        alert = c3_alert_store.add_alert(result)
        if result.get("score", 0.0) >= 0.8:
            await c3_interceptor.block_host(host)
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
    def _strip_timing_features(features: dict) -> dict:
        trimmed = dict(features)
        for key in ("iat_mean_ms", "iat_cv", "iat_bowley_skewness", "iat_mad_ms"):
            trimmed[key] = 0.0
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

        # Rule 1: Very regular inter-arrival timing (strongest beacon signal).
        # iat_cv < 0.05 means near-perfect metronomic intervals.
        # Guard: only flag as beacon timing if user is NOT actively interacting.
        # A user clicking links at regular intervals will also have iat_cv≈0 — that is NOT a beacon.
        if iat_cv < 0.05 and iat_mean > 0 and uar < 0.50:
            score += 0.30
            flags.append("regular timing")

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

        # Rule 4: Extension-origin requests.
        if ext > 0.0:
            score += 0.15
            flags.append("extension origin")

        # Rule 5: Same endpoint WITH regular timing AND no user activity — compound rule.
        # Standalone low-entropy fires on analytics/CDN; require all three conditions.
        if path_ent < 0.50 and iat_cv < 0.10 and iat_mean > 0 and uar < 0.50:
            score += 0.10
            flags.append("same endpoint with regular timing")

        return min(1.0, score), flags

    @staticmethod
    def _collection_fields() -> list[str]:
        return ["timestamp", "host", "label", "score", "verdict", "request_count", *FEATURE_ORDER]


c3_analyzer = C3Analyzer()
