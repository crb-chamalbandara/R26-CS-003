"""
C3 Unit Tests -- Behavioral Anomaly & Beacon Detection
Run from project root:  python test/C3/test_c3_units.py
"""
import math
import os
import pickle
import sqlite3
import sys
import tempfile
import time
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.c3.alert_store import C3AlertStore
from core.c3.analyzer import C3Analyzer, PERSISTENCE_CYCLES
from core.c3.ml_classifier import C3XGBoostEngine
from core.c3.block_store import C3BlockStore
from core.c3.feature_engine import compute_features, FEATURE_ORDER
from core.c3.interceptor import C3Interceptor
from core.c3.risk_fusion import BEACON_THRESHOLD, C3RiskFusion


def _make_events(n, interval_ms=5000, method="GET", background=True, user_active=False):
    """Build a list of synthetic beacon-like request events."""
    now = time.time()
    events = []
    for i in range(n):
        events.append({
            "timestamp": now + i * (interval_ms / 1000.0),
            "url": f"http://c2server.com/beacon?seq={i}",
            "method": method,
            "size_bytes": 256,
            "idle_time_ms": 4800,
            "user_was_active": user_active,
            "is_background_tab": background,
            "is_extension_origin": False,
        })
    return events


class _DummyMLModel:
    """Module-level (not nested) so pickle can actually serialize it --
    pickle requires classes to be importable by module path."""
    def predict_proba(self, X):
        return [[0.5, 0.5]]


def _make_fixed_url_events(n, interval_ms=5000):
    """Beacon fixture that hits the exact same endpoint every time (no varying
    query string) -- needed for url_path_entropy comparisons specifically.
    _make_events() above appends a unique ?seq={i} to every URL, which
    feature_engine.py's own _path_for_entropy() deliberately counts as a
    *different* path per request (see its comment: two calls to
    /beacon?ts=1 and /beacon?ts=2 count as different paths, on purpose, so a
    beacon that varies its query string per call isn't rewarded with a
    falsely-low entropy score). That makes _make_events() unsuitable as a
    "low entropy" fixture -- it actually produces the maximum possible
    entropy for its event count. Use this fixture instead when the test
    needs genuine same-endpoint (zero-entropy) traffic.
    """
    now = time.time()
    events = []
    for i in range(n):
        events.append({
            "timestamp": now + i * (interval_ms / 1000.0),
            "url": "http://c2server.com/beacon",
            "method": "GET",
            "size_bytes": 256,
            "idle_time_ms": 4800,
            "user_was_active": False,
            "is_background_tab": True,
            "is_extension_origin": False,
        })
    return events


def _make_normal_events(n):
    """Build a list of realistic user-driven browsing events."""
    now = time.time()
    events = []
    urls = [
        "https://github.com/pulls",
        "https://google.com/search?q=python",
        "https://stackoverflow.com/questions",
        "https://wikipedia.org/wiki/Main_Page",
        "https://news.ycombinator.com/",
    ]
    for i in range(n):
        events.append({
            "timestamp": now + i * (30 + i % 7),   # irregular human IAT
            "url": urls[i % len(urls)],
            "method": "GET",
            "size_bytes": 50000 + (i * 1200),
            "idle_time_ms": 100,
            "user_was_active": True,
            "is_background_tab": False,
            "is_extension_origin": False,
        })
    return events


# ── Feature Engine Tests ───────────────────────────────────────────────────────
class TestFeatureEngine(unittest.TestCase):

    def test_returns_all_required_feature_keys(self):
        feats = compute_features(_make_events(20))
        for key in FEATURE_ORDER:
            self.assertIn(key, feats, f"Missing feature: {key}")

    def test_beacon_events_low_iat_cv(self):
        """Regular beacons have very low inter-arrival time coefficient of variation."""
        feats = compute_features(_make_events(30, interval_ms=5000))
        self.assertLess(feats["iat_cv"], 0.10,
                        "Regular beacon IAT CV should be < 0.10")

    def test_human_browsing_high_iat_cv(self):
        """Human browsing is irregular -- high IAT CV."""
        feats = compute_features(_make_normal_events(20))
        self.assertGreater(feats["iat_cv"], 0.10,
                           "Human browsing IAT CV should be > 0.10")

    def test_background_tab_ratio_is_1_for_beacon(self):
        feats = compute_features(_make_events(15, background=True))
        self.assertAlmostEqual(feats["background_tab_ratio"], 1.0, places=2)

    def test_background_tab_ratio_is_0_for_foreground(self):
        feats = compute_features(_make_events(15, background=False))
        self.assertAlmostEqual(feats["background_tab_ratio"], 0.0, places=2)

    def test_user_active_ratio_reflects_activity(self):
        active_feats = compute_features(_make_events(10, user_active=True))
        idle_feats = compute_features(_make_events(10, user_active=False))
        self.assertAlmostEqual(active_feats["user_active_ratio"], 1.0, places=2)
        self.assertAlmostEqual(idle_feats["user_active_ratio"], 0.0, places=2)

    def test_post_ratio_correct(self):
        events = _make_events(10, method="POST")
        feats = compute_features(events)
        self.assertAlmostEqual(feats["http_post_ratio"], 1.0, places=2)

    def test_get_ratio_correct(self):
        events = _make_events(10, method="GET")
        feats = compute_features(events)
        self.assertAlmostEqual(feats["http_post_ratio"], 0.0, places=2)

    def test_requests_per_hour_reasonable(self):
        feats = compute_features(_make_events(12, interval_ms=5000))
        # 12 events at 5s interval ≈ 720 RPH
        self.assertGreater(feats["requests_per_hour"], 100)
        self.assertLessEqual(feats["requests_per_hour"], 100_000)

    def test_single_event_does_not_crash(self):
        feats = compute_features(_make_events(1))
        self.assertIn("iat_mean_ms", feats)
        self.assertEqual(feats["iat_cv"], 0.0)

    def test_empty_events_returns_zero_features(self):
        feats = compute_features([])
        self.assertIsInstance(feats, dict)

    def test_same_url_low_path_entropy(self):
        """Beacon always hitting the same path → zero URL path entropy."""
        feats = compute_features(_make_fixed_url_events(20))
        self.assertEqual(feats["url_path_entropy"], 0.0)

    def test_varied_urls_higher_entropy(self):
        feats = compute_features(_make_normal_events(20))
        beacon_feats = compute_features(_make_fixed_url_events(20))
        self.assertGreater(
            feats["url_path_entropy"],
            beacon_feats["url_path_entropy"],
        )

    def test_payload_size_mean_correct(self):
        events = _make_events(5)
        for e in events:
            e["size_bytes"] = 1000
        feats = compute_features(events)
        self.assertAlmostEqual(feats["payload_size_mean"], 1000.0, places=1)


# ── Risk Fusion Tests ──────────────────────────────────────────────────────────
class TestRiskFusion(unittest.TestCase):

    def setUp(self):
        self.fusion = C3RiskFusion()

    def test_verdict_beacon_when_score_ge_0_6(self):
        result = self.fusion.fuse(ml=0.8, reputation=0.9, heuristic=0.7)
        self.assertEqual(result["verdict"], "BEACON")
        self.assertGreaterEqual(result["score"], 0.6)

    def test_verdict_safe_when_all_zero(self):
        result = self.fusion.fuse(ml=0.0, reputation=0.0, heuristic=0.0)
        self.assertEqual(result["verdict"], "SAFE")
        self.assertLess(result["score"], 0.3)

    def test_verdict_suspicious_mid_range(self):
        result = self.fusion.fuse(ml=0.5, reputation=None, heuristic=0.3)
        self.assertEqual(result["verdict"], "SUSPICIOUS")
        self.assertGreaterEqual(result["score"], 0.3)
        self.assertLess(result["score"], 0.6)

    def test_ml_alone_does_not_reach_beacon_without_heuristic(self):
        """A high ML score with no heuristic support must NOT reach BEACON --
        both signals have to be involved (the both-signal gate holds it just
        below the threshold)."""
        result = self.fusion.fuse(ml=0.95, reputation=None, heuristic=0.0)
        self.assertLess(result["score"], BEACON_THRESHOLD,
                        "ML-only score must stay below the BEACON threshold")
        self.assertNotEqual(result["verdict"], "BEACON")

    def test_heuristic_alone_does_not_reach_beacon_without_ml(self):
        """Symmetric case: a high heuristic score with a near-zero ML score
        must NOT reach BEACON while an ML score exists at all."""
        result = self.fusion.fuse(ml=0.02, reputation=None, heuristic=0.98)
        self.assertLess(result["score"], BEACON_THRESHOLD,
                        "heuristic-only score must stay below the BEACON threshold")
        self.assertNotEqual(result["verdict"], "BEACON")

    def test_ml_below_its_own_c2_line_cannot_confirm(self):
        """0.55*0.45 + 0.45*0.90 = 0.6525 clears BEACON_THRESHOLD, but ML 0.45
        is below the model's own decision point (0.50 on the decision scale):
        the model does not call this C2, so it is held just below confirmed."""
        result = self.fusion.fuse(ml=0.45, reputation=None, heuristic=0.90)
        self.assertNotEqual(result["verdict"], "BEACON")
        self.assertLess(result["score"], BEACON_THRESHOLD)
        self.assertIn("below its 50% line", result["detail"])

    def test_both_engines_agreeing_confirms(self):
        result = self.fusion.fuse(ml=0.55, reputation=None, heuristic=0.60)
        self.assertEqual(result["verdict"], "BEACON")
        self.assertAlmostEqual(result["score"], 0.5725, places=4)

    def test_reputation_is_evidence_only_and_never_changes_the_score(self):
        """Threat-intel reputation is analyst-facing evidence, not a score
        input: fuse() must return the same score/verdict with and without it."""
        with_rep = self.fusion.fuse(ml=0.4, reputation=0.95, heuristic=0.3)
        without_rep = self.fusion.fuse(ml=0.4, reputation=None, heuristic=0.3)
        self.assertEqual(with_rep["score"], without_rep["score"])
        self.assertEqual(with_rep["verdict"], without_rep["verdict"])
        # A strong reputation hit on its own does not manufacture a BEACON.
        self.assertNotEqual(
            self.fusion.fuse(ml=None, reputation=0.85, heuristic=0.1)["verdict"],
            "BEACON",
        )

    def test_score_clamped_between_0_and_1(self):
        result = self.fusion.fuse(ml=1.0, reputation=1.0, heuristic=1.0)
        self.assertLessEqual(result["score"], 1.0)
        self.assertGreaterEqual(result["score"], 0.0)

    def test_result_has_required_keys(self):
        result = self.fusion.fuse(ml=0.5, reputation=0.5, heuristic=0.5)
        self.assertIn("score", result)
        self.assertIn("verdict", result)
        self.assertIn("detail", result)

    def test_heuristic_only_mode_when_no_ml_or_rep(self):
        result = self.fusion.fuse(ml=None, reputation=None, heuristic=0.7)
        self.assertAlmostEqual(result["score"], 0.7, places=2)
        self.assertEqual(result["verdict"], "BEACON")

    def test_full_signal_fusion(self):
        result = self.fusion.fuse(
            ml=0.8,
            reputation=0.7,
            heuristic=0.6,
        )
        self.assertGreaterEqual(result["score"], 0.6)
        self.assertEqual(result["verdict"], "BEACON")

    def test_none_inputs_handled_gracefully(self):
        result = self.fusion.fuse(ml=None, reputation=None, heuristic=None)
        self.assertIn("verdict", result)
        self.assertEqual(result["verdict"], "SAFE")


# ── Feature + Fusion Integration ──────────────────────────────────────────────
class TestFeatureFusionIntegration(unittest.TestCase):
    """Check that beacon-like traffic through feature_engine feeds correctly into fusion."""

    def setUp(self):
        self.fusion = C3RiskFusion()

    def test_beacon_features_lead_to_high_heuristic(self):
        feats = compute_features(_make_events(30, interval_ms=5000))
        # A regular beacon: IAT CV < 0.05, BG tab ratio = 1.0
        self.assertLess(feats["iat_cv"], 0.10)
        self.assertAlmostEqual(feats["background_tab_ratio"], 1.0, places=2)

    def test_normal_features_lead_to_safe_fusion(self):
        feats = compute_features(_make_normal_events(20))
        # Simulate a heuristic score derived from features
        heuristic = 0.0
        if feats["iat_cv"] < 0.10:
            heuristic += 0.30
        if feats["background_tab_ratio"] > 0.80:
            heuristic += 0.20
        # Normal browsing: low heuristic → SAFE
        result = self.fusion.fuse(ml=None, reputation=None, heuristic=heuristic)
        # Normal events should not reach BEACON threshold
        self.assertLess(result["score"], 0.60)


# ── Heuristic Scoring Rules (analyzer.py _heuristic_score) ────────────────────
# Rhythm first: every rule needs the timing to have a beacon rhythm (clockwork,
# or steady despite jitter). Supporting evidence - idle user, hidden tab, one
# endpoint - is counted only on top of a rhythm, never on its own. Each test
# sets only the keys it needs; the missing-key defaults (iat_cv 1.0,
# user_active_ratio 1.0, iat_mean_ms 0.0, ...) are all non-triggering.
_CLOCKWORK = {"iat_cv": 0.02, "iat_mean_ms": 5000.0,
              "user_active_ratio": 0.1, "payload_size_mean": 500.0}


class TestHeuristicScoreRules(unittest.TestCase):

    def score(self, **extra):
        return C3Analyzer._heuristic_score({**_CLOCKWORK, **extra})

    # ---- rhythm --------------------------------------------------------
    def test_clockwork_timing_small_payload(self):
        score, flags = self.score()
        self.assertAlmostEqual(score, 0.30, places=4)
        self.assertEqual(flags, ["clockwork timing (near-identical gaps)"])

    def test_no_rhythm_on_large_payload(self):
        """Video streaming is perfectly regular too, but 100 KB+ per request."""
        self.assertEqual(self.score(payload_size_mean=50_000.0), (0.0, []))

    def test_no_rhythm_while_user_active(self):
        self.assertEqual(self.score(user_active_ratio=0.9), (0.0, []))

    def test_no_rhythm_without_a_timing_sample(self):
        """iat_mean_ms 0 = the stripped small-window view: nothing may fire."""
        self.assertEqual(self.score(iat_mean_ms=0.0), (0.0, []))

    def test_steady_rhythm_despite_jitter(self):
        """+/-20% jitter puts iat_cv near 0.12 - past the clockwork cut - but
        80% of the gaps still sit close to the median gap."""
        score, flags = C3Analyzer._heuristic_score({
            "iat_cv": 0.12, "iat_mean_ms": 5000.0, "iat_mad_ms": 500.0,
            "iat_norm_mad": 0.10, "iat_spread_ratio": 0.32,
            "user_active_ratio": 0.1, "payload_size_mean": 500.0})
        self.assertAlmostEqual(score, 0.20, places=4)
        self.assertEqual(flags, ["steady rhythm despite jitter"])

    def test_steady_rhythm_rejects_a_page_load_burst(self):
        """Tightly spaced gaps under half a second are a burst, not a timer."""
        score, _ = C3Analyzer._heuristic_score({
            "iat_cv": 0.12, "iat_mean_ms": 200.0, "iat_mad_ms": 20.0,
            "iat_norm_mad": 0.10, "iat_spread_ratio": 0.32,
            "user_active_ratio": 0.1, "payload_size_mean": 500.0})
        self.assertEqual(score, 0.0)

    def test_steady_rhythm_rejects_wide_spread(self):
        score, _ = C3Analyzer._heuristic_score({
            "iat_cv": 0.12, "iat_mean_ms": 5000.0, "iat_mad_ms": 500.0,
            "iat_norm_mad": 0.10, "iat_spread_ratio": 2.0,
            "user_active_ratio": 0.1, "payload_size_mean": 500.0})
        self.assertEqual(score, 0.0)

    def test_median_gap_is_recovered_from_the_mad(self):
        self.assertAlmostEqual(C3Analyzer._median_gap_ms(
            {"iat_mad_ms": 500.0, "iat_norm_mad": 0.10, "iat_mean_ms": 9999.0}), 5000.0)
        # MAD exactly 0 (over half the gaps identical) -> the mean is used
        self.assertAlmostEqual(C3Analyzer._median_gap_ms(
            {"iat_mad_ms": 0.0, "iat_norm_mad": 0.0, "iat_mean_ms": 1500.0}), 1500.0)

    # ---- supporting evidence is never counted on its own ---------------
    def test_idle_user_alone_scores_zero(self):
        score, flags = C3Analyzer._heuristic_score(
            {"user_active_ratio": 0.0, "background_tab_ratio": 0.1, "avg_idle_time_ms": 60_000.0})
        self.assertEqual((score, flags), (0.0, []))

    def test_background_tab_alone_scores_zero(self):
        score, flags = C3Analyzer._heuristic_score(
            {"background_tab_ratio": 0.9, "extension_origin_ratio": 0.0})
        self.assertEqual((score, flags), (0.0, []))

    def test_real_ad_cdn_with_random_timing_scores_zero(self):
        """Regression, REAL values: cdn.doubleverify.com from the 60-minute
        browsing run (data/_c3_false_positive_run.json). The old rules gave it
        0.25 for "user idle", which let ML 0.76 confirm it as a BEACON."""
        score, flags = C3Analyzer._heuristic_score({
            "iat_cv": 3.359578, "iat_mean_ms": 27018.3406, "iat_mad_ms": 48.1689,
            "iat_norm_mad": 0.580988, "iat_spread_ratio": 33.03711,
            "user_active_ratio": 0.043478, "background_tab_ratio": 0.0,
            "extension_origin_ratio": 0.0, "avg_idle_time_ms": 769856.5652,
            "payload_size_mean": 50566.5, "http_post_ratio": 0.0,
            "requests_per_hour": 136.2038, "script_initiator_ratio": 1.0,
            "path_only_entropy": 1.0, "same_site_ratio": 0.0})
        self.assertEqual((score, flags), (0.0, []))
        fused = C3RiskFusion().fuse(ml=0.97, reputation=None, heuristic=score)
        self.assertNotEqual(fused["verdict"], "BEACON")

    # ---- supporting evidence on top of a rhythm ------------------------
    def test_idle_user_adds_to_a_rhythm(self):
        score, flags = self.score(user_active_ratio=0.0, background_tab_ratio=0.1,
                                  avg_idle_time_ms=60_000.0)
        self.assertAlmostEqual(score, 0.55, places=4)
        self.assertIn("fires while the user is idle", flags)

    def test_background_tab_adds_to_a_rhythm(self):
        score, flags = self.score(background_tab_ratio=0.9)
        self.assertAlmostEqual(score, 0.50, places=4)
        self.assertIn("runs in a background tab", flags)

    def test_background_extension_gets_the_smaller_weight(self):
        score, flags = self.score(background_tab_ratio=0.9, extension_origin_ratio=0.3)
        self.assertAlmostEqual(score, 0.38, places=4)
        self.assertIn("runs in a background tab (extension)", flags)

    def test_extension_in_the_foreground(self):
        score, flags = self.score(extension_origin_ratio=0.9, background_tab_ratio=0.1)
        self.assertAlmostEqual(score, 0.40, places=4)
        self.assertIn("extension traffic in the foreground", flags)

    def test_started_by_page_scripts(self):
        score, flags = self.score(script_initiator_ratio=0.9)
        self.assertAlmostEqual(score, 0.35, places=4)
        self.assertIn("started by page scripts", flags)
        self.assertAlmostEqual(self.score(script_initiator_ratio=0.3)[0], 0.30, places=4)

    def test_same_endpoint_ignores_the_query_string(self):
        """A cache-busting beacon (/gate.php?r=<random>) is still one endpoint:
        full-URL entropy is high, path-only entropy is 0."""
        score, flags = self.score(url_path_entropy=4.0, path_only_entropy=0.0)
        self.assertAlmostEqual(score, 0.40, places=4)
        self.assertIn("same endpoint every time", flags)

    def test_mostly_post_checkins(self):
        score, flags = self.score(http_post_ratio=0.95)
        self.assertAlmostEqual(score, 0.38, places=4)
        self.assertIn("mostly POST check-ins", flags)
        self.assertAlmostEqual(self.score(http_post_ratio=0.40)[0], 0.30, places=4)

    def test_frequent_requests(self):
        score, flags = self.score(requests_per_hour=800.0)
        self.assertAlmostEqual(score, 0.38, places=4)
        self.assertIn("frequent requests (over 500/hour)", flags)
        self.assertAlmostEqual(self.score(requests_per_hour=200.0)[0], 0.30, places=4)

    # ---- same-site dampener --------------------------------------------
    def test_same_site_dampens_the_score(self):
        score, flags = self.score(background_tab_ratio=0.9, same_site_ratio=0.9)
        self.assertAlmostEqual(score, 0.50 * 0.70, places=4)
        self.assertIn("same-site sync (score reduced)", flags)

    def test_no_dampening_below_the_same_site_threshold(self):
        score, flags = self.score(background_tab_ratio=0.9, same_site_ratio=0.50)
        self.assertAlmostEqual(score, 0.50, places=4)
        self.assertNotIn("same-site sync (score reduced)", flags)

    def test_same_site_never_adds_suspicion_on_its_own(self):
        self.assertEqual(C3Analyzer._heuristic_score({"same_site_ratio": 0.95}), (0.0, []))

    def test_empty_features_score_zero(self):
        self.assertEqual(C3Analyzer._heuristic_score({}), (0.0, []))

    def test_end_to_end_beacon_fixture_score_locked(self):
        """Regression lock on real feature_engine output: the 30-event beacon
        fixture (background tab, 5 s interval, 256 B, a unique ?seq= per
        request) scores 0.68 = clockwork 0.30 + background tab 0.20 + same
        endpoint 0.10 + frequent requests 0.08. "Same endpoint" is new here:
        the query string no longer hides that every request hits /beacon."""
        feats = compute_features(_make_events(30, interval_ms=5000))
        score, flags = C3Analyzer._heuristic_score(feats)
        self.assertAlmostEqual(score, 0.68, places=4)
        self.assertEqual(flags, ["clockwork timing (near-identical gaps)",
                                 "runs in a background tab",
                                 "same endpoint every time",
                                 "frequent requests (over 500/hour)"])


# ── Feature Engine Edge Cases (feature_engine.compute_features) ───────────────
# NaN/Inf/negative/missing-value robustness. statistics.pstdev/median raise on
# inf/nan, which previously crashed compute_features() for an entire analyzer
# cycle (all hosts, not just the bad one) over a single malformed reading.
class TestFeatureEngineEdgeCases(unittest.TestCase):

    def test_nan_size_bytes_does_not_crash(self):
        events = [
            {"timestamp": 1000.0, "size_bytes": float("nan"), "method": "GET", "url": "http://x.com/a"},
            {"timestamp": 1005.0, "size_bytes": 100, "method": "GET", "url": "http://x.com/b"},
            {"timestamp": 1010.0, "size_bytes": 100, "method": "GET", "url": "http://x.com/c"},
        ]
        feats = compute_features(events)  # must not raise
        self.assertFalse(math.isnan(feats["payload_size_mean"]))
        self.assertFalse(math.isnan(feats["payload_size_std"]))

    def test_inf_idle_time_does_not_crash(self):
        events = [
            {"timestamp": 1000.0, "size_bytes": 50, "idle_time_ms": float("inf"), "method": "GET", "url": "http://x.com/a"},
            {"timestamp": 1005.0, "size_bytes": 50, "idle_time_ms": 1000, "method": "GET", "url": "http://x.com/b"},
        ]
        feats = compute_features(events)  # must not raise
        self.assertTrue(math.isfinite(feats["avg_idle_time_ms"]))

    def test_nan_timestamp_does_not_crash_sort_or_iat(self):
        events = [
            {"timestamp": float("nan"), "size_bytes": 50, "method": "GET", "url": "http://x.com/a"},
            {"timestamp": 1005.0, "size_bytes": 50, "method": "GET", "url": "http://x.com/b"},
            {"timestamp": 1010.0, "size_bytes": 50, "method": "GET", "url": "http://x.com/c"},
        ]
        feats = compute_features(events)  # must not raise
        for key in FEATURE_ORDER:
            self.assertTrue(math.isfinite(feats[key]), f"{key} is not finite: {feats[key]}")

    def test_negative_out_of_order_timestamp_handled(self):
        events = [
            {"timestamp": 1010.0, "size_bytes": 100, "method": "GET", "url": "http://x.com/a"},
            {"timestamp": -5.0, "size_bytes": 100, "method": "GET", "url": "http://x.com/b"},
            {"timestamp": 1005.0, "size_bytes": 100, "method": "GET", "url": "http://x.com/c"},
        ]
        feats = compute_features(events)  # must not raise
        self.assertGreaterEqual(feats["iat_mean_ms"], 0.0)

    def test_missing_keys_entirely_handled(self):
        feats = compute_features([{}, {}, {}, {}])
        self.assertEqual(feats["payload_size_mean"], 0.0)
        self.assertEqual(feats["http_post_ratio"], 0.0)

    def test_empty_events_all_zero(self):
        feats = compute_features([])
        for key in FEATURE_ORDER:
            self.assertEqual(feats[key], 0.0)


# ── Model Loading Compatibility (ml_classifier.C3XGBoostEngine) ─────────
# An incompatible/malformed model file must fail safe (model_loaded stays
# False, score() returns None) rather than being silently accepted and
# producing wrong or crashing predictions later.
class TestModelLoadingCompatibility(unittest.TestCase):

    def _engine_with_payload(self, payload) -> C3XGBoostEngine:
        tmp = tempfile.NamedTemporaryFile(suffix=".pkl", delete=False)
        tmp_path = tmp.name
        try:
            pickle.dump(payload, tmp)
        finally:
            tmp.close()  # must close before reload()/unlink can reopen or remove it on Windows
        try:
            engine = C3XGBoostEngine.__new__(C3XGBoostEngine)
            engine._model = None
            engine._feature_names = []
            engine._threshold = 0.5
            engine._model_path = tmp_path
            engine.reload()
            return engine
        finally:
            os.unlink(tmp_path)

    def test_valid_payload_loads(self):
        engine = self._engine_with_payload({
            "model": _DummyMLModel(),
            "feature_names": ["iat_mean_ms", "iat_cv"],
            "threshold": 0.5,
        })
        self.assertTrue(engine.model_loaded)

    def test_non_dict_payload_rejected(self):
        """A bare model-only pickle has no feature_names to validate -- must
        be rejected rather than silently guessed at (old legacy format)."""
        engine = self._engine_with_payload(_DummyMLModel())
        self.assertFalse(engine.model_loaded)
        score, detail = engine.score({"iat_mean_ms": 100})
        self.assertIsNone(score)

    def test_unknown_feature_names_rejected(self):
        engine = self._engine_with_payload({
            "model": _DummyMLModel(),
            "feature_names": ["totally_made_up_feature", "iat_cv"],
            "threshold": 0.5,
        })
        self.assertFalse(engine.model_loaded)

    def test_missing_feature_names_rejected(self):
        engine = self._engine_with_payload({"model": _DummyMLModel(), "threshold": 0.5})
        self.assertFalse(engine.model_loaded)

    def test_model_without_predict_proba_rejected(self):
        engine = self._engine_with_payload({
            "model": object(), "feature_names": ["iat_cv"], "threshold": 0.5,
        })
        self.assertFalse(engine.model_loaded)

    def test_missing_file_fails_safe(self):
        engine = C3XGBoostEngine.__new__(C3XGBoostEngine)
        engine._model = None
        engine._feature_names = []
        engine._threshold = 0.5
        engine._model_path = "C:/definitely/does/not/exist.pkl"
        result = engine.reload()
        self.assertFalse(result)
        self.assertFalse(engine.model_loaded)

    def test_threshold_is_reported_only_for_a_loaded_model(self):
        """The dashboard colours ML scores from status()'s ml_threshold, so a
        rejected model must report None, not a default."""
        loaded = self._engine_with_payload({
            "model": _DummyMLModel(), "feature_names": ["iat_cv"], "threshold": 0.137,
        })
        self.assertAlmostEqual(loaded.threshold, 0.137)
        self.assertEqual(loaded.decision_point, 0.5)
        rejected = self._engine_with_payload({
            "model": object(), "feature_names": ["iat_cv"], "threshold": 0.137,
        })
        self.assertIsNone(rejected.threshold)
        self.assertIsNone(rejected.decision_point)

    def test_status_reports_the_decision_point_and_the_raw_threshold(self):
        from core.c3.analyzer import c3_analyzer
        from core.c3.ml_classifier import c3_ml_engine
        status = c3_analyzer.status()
        self.assertEqual(status["ml_threshold"], c3_ml_engine.decision_point)
        self.assertEqual(status["ml_raw_threshold"], c3_ml_engine.threshold)


# ── ML Decision Scale (ml_classifier.to_decision_scale) ──────────────────────
# The uncalibrated model calls C2 at a raw 0.137; C3 shows and fuses the score
# on a scale where that point is exactly 50%.
class TestMlDecisionScale(unittest.TestCase):

    def test_the_models_threshold_maps_to_exactly_half(self):
        from core.c3.ml_classifier import to_decision_scale
        for thr in (0.137, 0.05, 0.5, 0.9):
            self.assertAlmostEqual(to_decision_scale(thr, thr), 0.5, places=9)

    def test_order_is_preserved(self):
        """Strictly increasing, so the model's ranking (and every ROC/PR figure
        measured for it) is untouched."""
        from core.c3.ml_classifier import to_decision_scale
        probs = [0.0, 1e-4, 0.01, 0.1, 0.137, 0.2, 0.5, 0.9, 0.999, 1.0]
        mapped = [to_decision_scale(p, 0.137) for p in probs]
        self.assertEqual(mapped, sorted(mapped))
        self.assertTrue(all(0.0 < m < 1.0 for m in mapped))

    def test_array_input(self):
        import numpy as np
        from core.c3.ml_classifier import to_decision_scale
        out = to_decision_scale(np.array([0.137, 0.5]), 0.137)
        self.assertEqual(out.shape, (2,))
        self.assertAlmostEqual(float(out[0]), 0.5, places=9)

    def test_engine_uses_its_loaded_threshold(self):
        from core.c3.ml_classifier import c3_ml_engine
        if not c3_ml_engine.model_loaded:
            self.skipTest("no deployed model on disk")
        self.assertAlmostEqual(c3_ml_engine.decision_score(c3_ml_engine.threshold), 0.5, places=9)


# ── Alert Store Schema (alert_store.C3AlertStore) ──────────────────────────────
# signal_detail was previously computed by the analyzer but silently dropped
# on persist, permanently losing the alert card's per-signal explanation text.
class TestAlertStoreSignalDetail(unittest.TestCase):

    def setUp(self):
        # ignore_cleanup_errors: SQLite on Windows can briefly hold a file
        # lock past the connection's context-manager exit -- a test-cleanup
        # timing quirk, not a bug in alert_store.py itself.
        self._tmpdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self._db_path = os.path.join(self._tmpdir.name, "test_alerts.db")

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_signal_detail_round_trips(self):
        store = C3AlertStore(db_path=self._db_path)
        store.add_alert({
            "host": "evil.example", "score": 0.8, "verdict": "BEACON", "detail": "x",
            "features": {}, "signal_breakdown": {"ml": 0.6},
            "signal_detail": {"ml": "XGB prob=0.6000 threshold=0.50 [bot]"},
        })
        # Fresh instance simulates a backend restart reading from disk.
        reloaded = C3AlertStore(db_path=self._db_path)
        alert = reloaded.list_alerts(1)[0]
        self.assertEqual(alert["signal_detail"], {"ml": "XGB prob=0.6000 threshold=0.50 [bot]"})

    def test_missing_signal_detail_defaults_to_empty_dict(self):
        store = C3AlertStore(db_path=self._db_path)
        store.add_alert({"host": "x", "score": 0.7, "verdict": "BEACON", "detail": "x"})
        alert = store.list_alerts(1)[0]
        self.assertEqual(alert["signal_detail"], {})

    def test_migration_adds_column_to_old_schema_db_without_data_loss(self):
        """Simulates a real pre-existing DB from before signal_detail_json existed."""
        import sqlite3
        conn = sqlite3.connect(self._db_path)
        conn.execute("""
            CREATE TABLE c3_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT NOT NULL,
                score REAL NOT NULL, verdict TEXT NOT NULL, detail TEXT NOT NULL,
                features_json TEXT NOT NULL, signals_json TEXT NOT NULL DEFAULT '{}',
                timestamp TEXT NOT NULL
            )
        """)
        conn.execute(
            "INSERT INTO c3_alerts(host, score, verdict, detail, features_json, signals_json, timestamp) "
            "VALUES ('old-host', 0.9, 'BEACON', 'pre-existing', '{}', '{}', '2026-01-01T00:00:00')"
        )
        conn.commit()
        conn.close()

        store = C3AlertStore(db_path=self._db_path)  # triggers migration
        self.assertEqual(store.count(), 1)
        alert = store.list_alerts(1)[0]
        self.assertEqual(alert["host"], "old-host")
        self.assertEqual(alert["signal_detail"], {})  # can't recover data never saved, but doesn't crash


# ── Reputation is evidence-only (analyzer._handle_beacon) ─────────────────────
# Threat-intel reputation is looked up once a BEACON is confirmed and recorded
# on the alert as analyst-facing evidence. It is NOT an input to the risk
# score (see core/c3/risk_fusion.py) -- _handle_beacon() must never move the
# score or the verdict based on it, whether the lookup is flagged or clean.
class TestHandleBeaconReputationEvidence(unittest.IsolatedAsyncioTestCase):

    def _make_result(self, score, ml, heuristic):
        return {
            "score": score, "verdict": "BEACON", "detail": "initial",
            "source": "fusion",
            "signal_breakdown": {"ml": ml, "reputation": None, "heuristic": heuristic},
            "signal_detail": {"ml": "x", "heuristic": "y", "reputation": "pending", "fusion": "z"},
            "host": "evil.example", "latest_url": "http://evil.example/beacon",
            "features": {}, "request_count": 20, "timestamp": "2026-01-01T00:00:00",
        }

    async def test_flagged_reputation_recorded_without_changing_score(self):
        analyzer = C3Analyzer()
        result = self._make_result(score=0.65, ml=0.2, heuristic=0.9)
        with mock.patch("core.c3.analyzer.c3_reputation_engine") as rep_mock, \
             mock.patch("core.c3.analyzer.c3_alert_store") as store_mock, \
             mock.patch("core.c3.analyzer.c3_interceptor"):
            rep_mock.score_beacon = mock.AsyncMock(
                return_value={"score": 0.9, "flagged": True,
                              "sources": {"abuseipdb": 0.9, "virustotal": 0.0},
                              "detail": "FLAGGED: abuseipdb=0.90, virustotal=0.00"}
            )
            store_mock.add_alert = mock.Mock(side_effect=lambda r: r)
            await analyzer._handle_beacon("evil.example", result)
        self.assertEqual(result["score"], 0.65)                      # score untouched
        self.assertEqual(result["verdict"], "BEACON")
        self.assertEqual(result["signal_breakdown"]["reputation"], 0.9)  # recorded as evidence
        # Per-source scores carried through for the popups (out of 100%).
        self.assertEqual(result["signal_breakdown"]["reputation_sources"],
                         {"abuseipdb": 0.9, "virustotal": 0.0})
        self.assertIn("TI:", result["detail"])

    async def test_clean_reputation_recorded_as_zero_without_changing_score(self):
        analyzer = C3Analyzer()
        result = self._make_result(score=0.75, ml=0.2, heuristic=0.95)
        with mock.patch("core.c3.analyzer.c3_reputation_engine") as rep_mock, \
             mock.patch("core.c3.analyzer.c3_alert_store") as store_mock, \
             mock.patch("core.c3.analyzer.c3_interceptor"):
            rep_mock.score_beacon = mock.AsyncMock(
                return_value={"score": 0.0, "flagged": False,
                              "sources": {"abuseipdb": 0.0, "virustotal": 0.0},
                              "detail": "Clean: abuseipdb=0.00, virustotal=0.00"}
            )
            store_mock.add_alert = mock.Mock(side_effect=lambda r: r)
            await analyzer._handle_beacon("evil.example", result)
        self.assertEqual(result["score"], 0.75)                      # score untouched
        self.assertEqual(result["verdict"], "BEACON")
        # A clean lookup that ran IS a real answer -- recorded as 0%, not "n/a".
        self.assertEqual(result["signal_breakdown"]["reputation"], 0.0)
        self.assertEqual(result["signal_breakdown"]["reputation_sources"],
                         {"abuseipdb": 0.0, "virustotal": 0.0})
        self.assertNotIn("TI:", result["detail"])

    async def test_skipped_reputation_stays_not_available(self):
        analyzer = C3Analyzer()
        result = self._make_result(score=0.75, ml=0.2, heuristic=0.95)
        with mock.patch("core.c3.analyzer.c3_reputation_engine") as rep_mock, \
             mock.patch("core.c3.analyzer.c3_alert_store") as store_mock, \
             mock.patch("core.c3.analyzer.c3_interceptor"):
            rep_mock.score_beacon = mock.AsyncMock(
                return_value={"score": 0.0, "flagged": False, "sources": {},
                              "detail": "local host - skipped"}
            )
            store_mock.add_alert = mock.Mock(side_effect=lambda r: r)
            await analyzer._handle_beacon("evil.example", result)
        self.assertEqual(result["score"], 0.75)
        self.assertIsNone(result["signal_breakdown"]["reputation"])
        self.assertEqual(result["signal_breakdown"]["reputation_sources"], {})


# ── Reputation Engine: VirusTotal scoring + cached_score ───────────────────
# The VT engine-count -> score map is calibrated against real VT data
# (measured 2026-08-29): google.com sits at malicious==1 (one chronically-
# noisy engine), so `malicious >= 1` -- the rule this replaced -- flagged
# google.com and many Fortune-500 domains as malicious beacon destinations.
# cached_score() must mirror a lookup's `flagged` bit so a clean result never
# feeds a spurious 0.0 into every fusion cycle.
class TestReputationSkipsLocalHosts(unittest.IsolatedAsyncioTestCase):
    """A loopback name must never reach DNS or an outside threat-intel service."""

    def test_localhost_and_its_subdomains_are_local(self):
        from core.c3.reputation_engine import C3ReputationEngine
        local = C3ReputationEngine._is_private_or_local
        for host in ("localhost", "c3-beacon-1789459120.localhost", "a.b.localhost",
                     "x.localhost.", "127.0.0.1", "10.1.2.3", "::1"):
            self.assertTrue(local(host), host)
        for host in ("localhost.evil.example", "evil-localhost", "example.com", "8.8.8.8"):
            self.assertFalse(local(host), host)

    async def test_localhost_subdomain_is_skipped_without_any_lookup(self):
        from core.c3.reputation_engine import C3ReputationEngine
        eng = C3ReputationEngine()
        with mock.patch.object(eng, "_resolve_ips", new=mock.AsyncMock(return_value=[])) as dns, \
             mock.patch.object(eng, "_check_virustotal", new=mock.AsyncMock()) as vt, \
             mock.patch.object(eng, "_check_abuseipdb", new=mock.AsyncMock()) as abuse:
            res = await eng.score_beacon("c3-beacon-1.localhost",
                                         "http://c3-beacon-1.localhost:8765/c3/test/beacon-target")
        self.assertEqual(res["detail"], "local host - skipped")
        dns.assert_not_called()
        vt.assert_not_called()
        abuse.assert_not_called()


class TestReputationVirusTotalScoring(unittest.IsolatedAsyncioTestCase):

    def _engine_with_response(self, status, stats):
        from core.c3.reputation_engine import C3ReputationEngine, set_virustotal_key
        set_virustotal_key("unit-test-key")
        eng = C3ReputationEngine()

        class _Resp:
            status_code = status
            def json(self_inner):
                return {"data": {"attributes": {"last_analysis_stats": stats}}} if stats is not None else {}

        class _Client:
            async def get(self_inner, url, headers=None):
                return _Resp()

        eng._client = _Client()
        return eng

    async def test_benign_single_noisy_engine_scores_zero(self):
        # google.com's real VT profile -- must NOT flag.
        eng = self._engine_with_response(200, {"malicious": 1, "suspicious": 0, "harmless": 62})
        self.assertEqual(await eng._check_virustotal("google.com"), ("virustotal", 0.0))

    async def test_zero_detections_scores_zero(self):
        eng = self._engine_with_response(200, {"malicious": 0, "suspicious": 0, "harmless": 60})
        self.assertEqual(await eng._check_virustotal("microsoft.com"), ("virustotal", 0.0))

    async def test_two_engines_needs_corroboration(self):
        eng = self._engine_with_response(200, {"malicious": 2, "suspicious": 0})
        _, v = await eng._check_virustotal("x.example")
        self.assertEqual(v, 0.35)                    # below the 0.5 flag line
        eng = self._engine_with_response(200, {"malicious": 2, "suspicious": 2})
        _, v = await eng._check_virustotal("x.example")
        self.assertGreaterEqual(v, 0.5)              # 2 mal + 2 susp -> actionable

    async def test_three_plus_engines_scale_up(self):
        eng = self._engine_with_response(200, {"malicious": 3, "suspicious": 2})
        _, v = await eng._check_virustotal("eicar.example")
        self.assertGreater(v, 0.5)
        eng = self._engine_with_response(200, {"malicious": 12, "suspicious": 4})
        _, v = await eng._check_virustotal("c2.example")
        self.assertLessEqual(v, 0.95)
        self.assertGreaterEqual(v, 0.9)

    async def test_404_is_no_evidence_not_none(self):
        eng = self._engine_with_response(404, None)
        self.assertEqual(await eng._check_virustotal("unknown.example"), ("virustotal", 0.0))

    async def test_auth_or_ratelimit_error_drops_source(self):
        for code in (401, 429, 500):
            eng = self._engine_with_response(code, None)
            self.assertEqual(await eng._check_virustotal("x.example"), ("virustotal", None))

    async def test_no_key_returns_none(self):
        from core.c3.reputation_engine import C3ReputationEngine, set_virustotal_key
        set_virustotal_key("")
        eng = C3ReputationEngine()
        self.assertEqual(await eng._check_virustotal("x.example"), ("virustotal", None))

    def test_cached_score_mirrors_flagged_bit(self):
        from core.c3.reputation_engine import C3ReputationEngine
        eng = C3ReputationEngine()
        eng._cache["clean.example"] = {
            "expires_at": time.time() + 999,
            "payload": {"score": 0.0, "flagged": False},
        }
        eng._cache["bad.example"] = {
            "expires_at": time.time() + 999,
            "payload": {"score": 0.82, "flagged": True},
        }
        eng._cache["stale.example"] = {
            "expires_at": time.time() - 1,
            "payload": {"score": 0.9, "flagged": True},
        }
        self.assertIsNone(eng.cached_score("clean.example"))   # clean -> no signal
        self.assertEqual(eng.cached_score("bad.example"), 0.82)
        self.assertIsNone(eng.cached_score("stale.example"))   # expired -> no signal
        self.assertIsNone(eng.cached_score("never-seen.example"))


# ── Block Store (block_store.C3BlockStore) ──────────────────────────────────
# Each block is a real, disk-persisted row with a 24h expiry -- these tests
# lock in the exact behavior core/c3/interceptor.py relies on: is_blocked()
# reflects only non-expired rows, list_active()/list_expired() partition
# correctly, and re-adding an already-blocked host (upsert) refreshes its
# expiry rather than erroring or duplicating.
class TestC3BlockStore(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self._db_path = os.path.join(self._tmpdir.name, "test_blocks.db")
        self.store = C3BlockStore(db_path=self._db_path)

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_add_block_persists_and_is_blocked_true(self):
        self.store.add_block("evil.example", reason="test", score=0.9)
        self.assertTrue(self.store.is_blocked("evil.example"))

    def test_unknown_host_is_not_blocked(self):
        self.assertFalse(self.store.is_blocked("never-blocked.example"))

    def test_add_block_sets_24h_expiry(self):
        row = self.store.add_block("evil.example")
        blocked_at = datetime.fromisoformat(row["blocked_at"])
        expires_at = datetime.fromisoformat(row["expires_at"])
        delta_hours = (expires_at - blocked_at).total_seconds() / 3600.0
        self.assertAlmostEqual(delta_hours, 24.0, places=3)

    def test_list_active_excludes_expired(self):
        self.store.add_block("fresh.example")
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        with closing(sqlite3.connect(self._db_path)) as conn, conn:
            conn.execute(
                "INSERT INTO c3_blocked_hosts(host,blocked_at,expires_at,reason,score) "
                "VALUES (?,?,?,?,?)", ("stale.example", past, past, "stale", 0.0),
            )
        active_hosts = [r["host"] for r in self.store.list_active()]
        self.assertIn("fresh.example", active_hosts)
        self.assertNotIn("stale.example", active_hosts)

    def test_list_expired_only_returns_past_expiry(self):
        self.store.add_block("fresh.example")
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        with closing(sqlite3.connect(self._db_path)) as conn, conn:
            conn.execute(
                "INSERT INTO c3_blocked_hosts(host,blocked_at,expires_at,reason,score) "
                "VALUES (?,?,?,?,?)", ("stale.example", past, past, "stale", 0.0),
            )
        expired_hosts = [r["host"] for r in self.store.list_expired()]
        self.assertEqual(expired_hosts, ["stale.example"])

    def test_remove_block_clears_is_blocked(self):
        self.store.add_block("evil.example")
        self.store.remove_block("evil.example")
        self.assertFalse(self.store.is_blocked("evil.example"))

    def test_readd_refreshes_expiry_upsert_not_duplicate(self):
        first = self.store.add_block("repeat.example")
        second = self.store.add_block("repeat.example")
        self.assertGreaterEqual(second["expires_at"], first["expires_at"])
        self.assertEqual(len(self.store.list_active()), 1)

    def test_host_normalized_lowercase(self):
        self.store.add_block("EVIL.EXAMPLE")
        self.assertTrue(self.store.is_blocked("evil.example"))


# ── Interceptor Blocking (interceptor.C3Interceptor) ────────────────────────
# block_host()/unblock_host()/sweep_expired_blocks()/_reapply_persisted_blocks()
# are the actual fix for "blocking doesn't survive a restart and never
# expires" -- these tests use a mocked Playwright context (AsyncMock) so they
# do not need a real browser, and patch the module-level c3_block_store
# singleton so no test here ever touches the real ~/.websentinel/c3_blocks.db.
class TestInterceptorBlocking(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self._db_path = os.path.join(self._tmpdir.name, "test_blocks.db")
        self._store = C3BlockStore(db_path=self._db_path)
        self._patcher = mock.patch("core.c3.interceptor.c3_block_store", self._store)
        self._patcher.start()

    def tearDown(self):
        self._patcher.stop()
        self._tmpdir.cleanup()

    def _interceptor(self):
        ic = C3Interceptor()
        ic._context = mock.AsyncMock()
        ic._running = True
        return ic

    async def test_block_host_registers_routes_and_persists(self):
        ic = self._interceptor()
        await ic.block_host("evil.example", reason="test", score=0.9)
        self.assertEqual(ic._context.route.call_count, 2)
        self.assertIn("evil.example", ic._blocked_hosts)
        self.assertTrue(self._store.is_blocked("evil.example"))

    async def test_block_host_is_idempotent_while_live_blocked(self):
        ic = self._interceptor()
        await ic.block_host("evil.example")
        await ic.block_host("evil.example")
        self.assertEqual(ic._context.route.call_count, 2)  # not 4

    async def test_is_blocked_reflects_live_state(self):
        ic = self._interceptor()
        self.assertFalse(ic.is_blocked("evil.example"))
        await ic.block_host("evil.example")
        self.assertTrue(ic.is_blocked("EVIL.example"))  # case-insensitive
        await ic.unblock_host("evil.example")
        self.assertFalse(ic.is_blocked("evil.example"))

    async def test_unblock_host_clears_routes_and_persistence(self):
        ic = self._interceptor()
        await ic.block_host("evil.example")
        await ic.unblock_host("evil.example")
        self.assertEqual(ic._context.unroute.call_count, 2)
        self.assertNotIn("evil.example", ic._blocked_hosts)
        self.assertFalse(self._store.is_blocked("evil.example"))

    async def test_sweep_expired_blocks_unblocks_only_expired(self):
        ic = self._interceptor()
        await ic.block_host("fresh.example")
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        with closing(sqlite3.connect(self._db_path)) as conn, conn:
            conn.execute(
                "INSERT INTO c3_blocked_hosts(host,blocked_at,expires_at,reason,score) "
                "VALUES (?,?,?,?,?)", ("stale.example", past, past, "stale", 0.0),
            )
        ic._blocked_hosts.add("stale.example")
        ic._blocked_routes["stale.example"] = ["**://stale.example/**"]
        ic._last_expiry_sweep = 0.0  # bypass the real 300s throttle for this test
        unblocked = await ic.sweep_expired_blocks()
        self.assertEqual(unblocked, ["stale.example"])
        self.assertIn("fresh.example", ic._blocked_hosts)
        self.assertNotIn("stale.example", ic._blocked_hosts)

    async def test_sweep_expired_blocks_throttled_between_calls(self):
        ic = self._interceptor()
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        with closing(sqlite3.connect(self._db_path)) as conn, conn:
            conn.execute(
                "INSERT INTO c3_blocked_hosts(host,blocked_at,expires_at,reason,score) "
                "VALUES (?,?,?,?,?)", ("stale.example", past, past, "stale", 0.0),
            )
        ic._last_expiry_sweep = time.time()  # just swept -- next call should no-op
        unblocked = await ic.sweep_expired_blocks()
        self.assertEqual(unblocked, [])

    async def test_reapply_persisted_blocks_restores_live_block(self):
        self._store.add_block("reapply.example", reason="pre-restart")
        ic = self._interceptor()  # simulates a fresh instance after a restart
        await ic._reapply_persisted_blocks()
        self.assertIn("reapply.example", ic._blocked_hosts)

    async def test_reapply_does_not_refresh_expiry(self):
        """The one subtlety that matters most: reapplying an already-
        persisted block on startup must NOT reset its 24h clock, or a host
        would never actually expire across repeated restarts."""
        self._store.add_block("reapply.example")
        before = self._store.list_active()[0]["expires_at"]
        ic = self._interceptor()
        await ic._reapply_persisted_blocks()
        after = self._store.list_active()[0]["expires_at"]
        self.assertEqual(before, after)


# ── Timing-Sample Maturity Ramp (analyzer._timing_confidence) ──────────────
# Replaces the old THREE discontinuities (hard allow_timing on/off at 6, a
# _sample_size_confidence that snapped to full at 9, and a hard 0.51 cap that
# released at exactly 10) that a fast beacon crossed within one or two 10s
# cycles -- the real cause of the "ML score, heuristic score AND fused score
# all jump from ~25% to ~80%+ in one step" report. This is a single smooth
# 0..1 weight: 0 below 6 events, smoothstep ramp to 1.0 at 20, flat after.
# At w == 1.0 every downstream calc collapses exactly to the plain fusion.
class TestTimingConfidenceRamp(unittest.TestCase):

    def test_zero_below_min_events(self):
        self.assertEqual(C3Analyzer._timing_confidence(3), 0.0)
        self.assertEqual(C3Analyzer._timing_confidence(6), 0.0)

    def test_full_at_and_beyond_mature_sample(self):
        self.assertEqual(C3Analyzer._timing_confidence(20), 1.0)
        self.assertEqual(C3Analyzer._timing_confidence(50), 1.0)
        self.assertEqual(C3Analyzer._timing_confidence(500), 1.0)

    def test_strictly_between_0_and_1_in_the_ramp(self):
        for n in range(7, 20):
            v = C3Analyzer._timing_confidence(n)
            self.assertGreater(v, 0.0)
            self.assertLess(v, 1.0)

    def test_monotonically_increasing(self):
        values = [C3Analyzer._timing_confidence(n) for n in range(3, 30)]
        self.assertEqual(values, sorted(values))

    def test_no_single_step_jump_exceeds_15pct(self):
        # The whole point: no event-count increment may move the weight (and
        # therefore, downstream, the fused score) by a large step.
        vals = [C3Analyzer._timing_confidence(n) for n in range(3, 30)]
        steps = [b - a for a, b in zip(vals, vals[1:])]
        self.assertLess(max(steps), 0.15)

    def test_smoothstep_midpoint_is_half(self):
        # n = 13 is the midpoint of the 6..20 ramp; smoothstep(0.5) == 0.5.
        self.assertAlmostEqual(C3Analyzer._timing_confidence(13), 0.5, places=4)


# ── Analyzer Skips Already-Blocked Hosts (analyzer._analyze_once) ──────────
# The actual fix for "auto-block message appears but the same host triggers
# a beacon alert again a few minutes later": a blocked host's rolling window
# keeps holding its last pre-block events forever (blocking does not clear
# it), so without this skip the analyzer kept re-scoring that same stale
# window every 10s cycle and re-confirming/re-alerting BEACON roughly every
# 60s even though zero new traffic had occurred since the block.
class TestContextBlindBypass(unittest.TestCase):
    """Step 4's "second prize": confirm a BEACON with NO browser context, but
    only on sustained high-confidence ML, and only when switched on.

    Section 3.4 rejected a single-window ML >= 0.95 bypass (78.8% context-blind
    recall at a 0.441% false-beacon rate). Re-measured with the persistence
    requirement over the in-scope population, the false-beacon rate falls to
    0.0270% while still catching 60.61% -- against 0.00% today, since
    BOTH_SIGNAL_FLOOR makes context-blind BEACON unreachable by construction.

    It stays OFF by default regardless: this changes what C3 will confirm on a
    single signal, which is a product decision.
    Added 2026-09-11 by the hardening pass, step 4.
    """

    def setUp(self):
        self.fusion = C3RiskFusion()

    def test_off_by_default(self):
        """The flag must ship False. A future edit that flips it should have
        to break this test to do so."""
        from core.c3 import analyzer as analyzer_mod
        self.assertFalse(analyzer_mod.CONTEXT_BLIND_BYPASS_ENABLED)
        self.assertEqual(analyzer_mod.CONTEXT_BLIND_ML_BYPASS, 0.95)

    def test_context_blind_beacon_is_unreachable_without_the_bypass(self):
        """The behaviour Section 3.4 documents: heuristic 0 caps everything."""
        result = self.fusion.fuse(ml=0.99, reputation=None, heuristic=0.0)
        self.assertNotEqual(result["verdict"], "BEACON")
        self.assertLessEqual(result["score"], 0.51)

    def test_bypass_allows_the_beacon_when_granted(self):
        result = self.fusion.fuse(ml=0.99, reputation=None, heuristic=0.0,
                                  degraded_context_ratio=1.0,
                                  allow_context_blind_beacon=True)
        self.assertEqual(result["verdict"], "BEACON")
        # The verdict must SAY it rests on ML alone. An analyst seeing a
        # context-blind confirmation needs that stated, not implied.
        self.assertIn("without browser-context evidence", result["detail"].lower())

    def test_bypass_does_not_rescue_a_low_ml_score(self):
        """The bypass lifts the both-signal cap; it does not invent a score.
        0.55 * 0.60 = 0.33, still short of BEACON on its own."""
        result = self.fusion.fuse(ml=0.60, reputation=None, heuristic=0.0,
                                  degraded_context_ratio=1.0,
                                  allow_context_blind_beacon=True)
        self.assertNotEqual(result["verdict"], "BEACON")

    def test_bypass_never_applies_to_a_missing_ml_signal(self):
        """A heuristic-only window must never confirm, even with the bypass
        granted -- the bypass lifts the cap for the ML side only.

        At ML 0.02 the weights alone keep it below 0.52 (0.011 + 0.45). Since
        2026-09-14 the ML side also has to reach the model's own C2 line
        (ML_CONFIRM_FLOOR 0.50), so the "heuristic-only cap" branch now fires
        whenever a strong heuristic lifts a sub-0.50 ML score past 0.52 - see
        TestRiskFusion.test_ml_below_its_own_c2_line_cannot_confirm."""
        result = self.fusion.fuse(ml=0.02, reputation=None, heuristic=1.0,
                                  degraded_context_ratio=1.0,
                                  allow_context_blind_beacon=True)
        self.assertNotEqual(result["verdict"], "BEACON")
        self.assertLess(result["score"], BEACON_THRESHOLD)

    def test_default_call_still_caps(self):
        """Every existing 3-arg and 4-arg call site must keep the old guard."""
        for args in ((0.99, None, 0.0), (0.99, None, 0.0, 1.0)):
            result = self.fusion.fuse(*args)
            self.assertNotEqual(result["verdict"], "BEACON",
                                f"bypass leaked into call {args}")


class TestAnalystFeedbackLoop(unittest.TestCase):
    """Step 8: record whether a verdict was actually right.

    Section 3.7: nothing in C3 recorded this, so every false-positive
    measurement had to be redone by hand and model drift after deployment was
    invisible. This is the smallest useful version -- one label, one note, one
    timestamp -- and it is EVIDENCE, never an input to scoring.
    Added 2026-09-11 by the hardening pass, step 8.
    """

    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self.store = C3AlertStore(self._tmp.name)

    def tearDown(self):
        try:
            os.unlink(self._tmp.name)
        except OSError:
            pass

    def _add(self, host="c2.example", score=0.71):
        return self.store.add_alert({
            "host": host, "score": score, "verdict": "BEACON",
            "detail": "test", "features": {"iat_cv": 0.01},
            "signal_breakdown": {"ml": 0.8, "heuristic": 0.6},
            "signal_detail": {"ml": "x"},
        })

    def test_new_alerts_start_unlabelled(self):
        alert = self._add()
        self.assertIsNone(alert["analyst_verdict"])
        stats = self.store.feedback_stats()
        self.assertEqual(stats["labelled"], 0)
        self.assertEqual(stats["unlabelled"], 1)

    def test_feedback_persists_to_disk(self):
        alert = self._add()
        self.store.set_feedback(alert["id"], "false_positive")
        reopened = C3AlertStore(self._tmp.name)
        self.assertEqual(reopened.list_alerts()[0]["analyst_verdict"], "false_positive")

    def test_feedback_updates_the_hot_cache_immediately(self):
        alert = self._add()
        self.store.set_feedback(alert["id"], "correct", note="confirmed beacon")
        cached = self.store.list_alerts()[0]
        self.assertEqual(cached["analyst_verdict"], "correct")
        self.assertEqual(cached["analyst_note"], "confirmed beacon")

    def test_invalid_verdict_is_rejected(self):
        alert = self._add()
        for bad in ("", "maybe", "TRUE", "yes"):
            with self.assertRaises(ValueError):
                self.store.set_feedback(alert["id"], bad)

    def test_unknown_alert_id_is_rejected(self):
        with self.assertRaises(KeyError):
            self.store.set_feedback(99999, "correct")

    def test_fp_rate_is_over_labelled_alerts_only(self):
        """An unreviewed alert is not evidence of correctness. Folding
        unlabelled alerts into the denominator would flatter the number."""
        ids = [self._add(host=f"h{i}.example")["id"] for i in range(10)]
        self.store.set_feedback(ids[0], "false_positive")
        self.store.set_feedback(ids[1], "correct")
        self.store.set_feedback(ids[2], "correct")
        stats = self.store.feedback_stats()
        self.assertEqual(stats["total_alerts"], 10)
        self.assertEqual(stats["labelled"], 3)
        self.assertEqual(stats["unlabelled"], 7)
        # 1 of 3 labelled, NOT 1 of 10.
        self.assertAlmostEqual(stats["false_positive_rate"], 0.3333, places=3)

    def test_fp_rate_is_none_when_nothing_is_labelled(self):
        self._add()
        self.assertIsNone(self.store.feedback_stats()["false_positive_rate"])

    def test_export_returns_only_labelled_alerts_with_their_features(self):
        ids = [self._add(host=f"h{i}.example")["id"] for i in range(3)]
        self.store.set_feedback(ids[1], "false_positive", note="push keepalive")
        rows = self.store.export_feedback()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["analyst_verdict"], "false_positive")
        self.assertEqual(rows[0]["analyst_note"], "push keepalive")
        # Features must ride along -- this export is the seed of the labelled
        # fusion-outcome dataset risk_fusion.py says does not exist.
        self.assertIn("iat_cv", rows[0]["features"])

    def test_migration_adds_columns_to_an_older_database(self):
        """An existing deployment's DB predates these columns entirely."""
        path = self._tmp.name + ".legacy.db"
        try:
            with closing(sqlite3.connect(path)) as conn, conn:
                conn.execute(
                    "CREATE TABLE c3_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    " host TEXT NOT NULL, score REAL NOT NULL, verdict TEXT NOT NULL,"
                    " detail TEXT NOT NULL, features_json TEXT NOT NULL,"
                    " timestamp TEXT NOT NULL)")
                conn.execute(
                    "INSERT INTO c3_alerts(host,score,verdict,detail,features_json,"
                    "timestamp) VALUES ('old.example',0.9,'BEACON','legacy','{}','t')")
            store = C3AlertStore(path)
            row = store.list_alerts()[0]
            self.assertEqual(row["host"], "old.example")
            self.assertIsNone(row["analyst_verdict"])
            store.set_feedback(row["id"], "correct")
            self.assertEqual(store.feedback_stats()["correct"], 1)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass


class TestTemporalPersistenceGate(unittest.IsolatedAsyncioTestCase):
    """Step 4: a BEACON must persist across observations before confirming.

    The subtle part -- and the part that would make this gate silently do the
    OPPOSITE of its job -- is what counts as an "observation". The analyzer
    re-scores every host with >=3 events in its rolling deque on every 10s
    cycle, whether or not that host sent anything new. A naive per-cycle
    counter therefore keeps climbing on a host that has already gone SILENT,
    which is exactly the bursty-then-stopped false positive this gate targets.
    Added 2026-09-11 by the hardening pass, step 4.
    """

    async def _run_cycles(self, windows):
        """Drive real _analyze_once() once per supplied window snapshot."""
        analyzer = C3Analyzer()
        verdicts, streaks = [], []
        for events in windows:
            with mock.patch("core.c3.analyzer.c3_interceptor") as ic, \
                 mock.patch("core.c3.analyzer.c3_reputation_engine") as rep, \
                 mock.patch("core.c3.analyzer.c3_alert_store") as store:
                ic.sweep_expired_blocks = mock.AsyncMock(return_value=[])
                ic.host_snapshots = mock.Mock(return_value={"beacon.example": events})
                ic.is_blocked = mock.Mock(return_value=False)
                rep.cached_score = mock.Mock(return_value=None)
                rep.cached_result = mock.Mock(return_value=None)
                rep.score_beacon = mock.AsyncMock(
                    return_value={"score": 0.0, "flagged": False, "detail": "n/a"})
                store.add_alert = mock.Mock(side_effect=lambda r: r)
                # Bypass the 15s navigation cooldown so the test exercises the
                # persistence gate rather than the cooldown.
                analyzer._host_first_seen["beacon.example"] = 0.0
                await analyzer._analyze_once()
            row = analyzer._host_scores.get("beacon.example", {})
            verdicts.append(row.get("verdict"))
            streaks.append(row.get("persistence_streak"))
        return verdicts, streaks

    @staticmethod
    def _beacon_events(n, start=1000.0, interval=5.0):
        return [{
            "timestamp": start + i * interval,
            "size_bytes": 87, "request_size": 0,
            "url": "https://beacon.example/gate.php", "host": "beacon.example",
            "method": "GET", "request_headers": {},
            "idle_time_ms": 200000, "user_was_active": False,
            "is_background_tab": True, "is_extension_origin": False,
            "initiator_type": "script", "page_url": "", "status": 200,
        } for i in range(n)]

    async def test_streak_does_not_advance_on_a_stale_window(self):
        """THE critical case. The same window re-scored many times is one
        observation, not many -- otherwise a host that burst once and stopped
        would be confirmed simply because the loop kept running."""
        events = self._beacon_events(30)
        _, streaks = await self._run_cycles([events, events, events, events, events])
        self.assertEqual(streaks[0], 1, "first sighting should count")
        self.assertTrue(all(s == 1 for s in streaks),
                        f"stale re-scoring inflated the streak: {streaks}")

    async def test_streak_advances_when_new_traffic_arrives(self):
        windows = [self._beacon_events(30 + i) for i in range(4)]
        _, streaks = await self._run_cycles(windows)
        self.assertEqual(streaks, [1, 2, 3, 4])

    async def test_beacon_is_withheld_until_the_streak_is_met(self):
        windows = [self._beacon_events(30 + i) for i in range(PERSISTENCE_CYCLES)]
        verdicts, streaks = await self._run_cycles(windows)
        # Every observation before the last must be held back from BEACON.
        for i, verdict in enumerate(verdicts[:-1]):
            self.assertNotEqual(verdict, "BEACON",
                                f"confirmed at observation {i + 1} of {PERSISTENCE_CYCLES}")
        self.assertEqual(streaks[-1], PERSISTENCE_CYCLES)

    async def test_a_persistent_beacon_is_still_confirmed(self):
        """The gate must delay a real beacon, never permanently block it."""
        windows = [self._beacon_events(30 + i) for i in range(8)]
        verdicts, _ = await self._run_cycles(windows)
        self.assertIn("BEACON", verdicts,
                      f"persistent beacon never confirmed: {verdicts}")

    async def test_streak_resets_when_evidence_falls_away(self):
        quiet = [{
            "timestamp": 5000.0 + i * 0.3, "size_bytes": 4000, "request_size": 0,
            "url": f"https://beacon.example/page{i}?q={i}", "host": "beacon.example",
            "method": "GET", "request_headers": {"Referer": "https://beacon.example/"},
            "idle_time_ms": 0, "user_was_active": True,
            "is_background_tab": False, "is_extension_origin": False,
            "initiator_type": "parser", "page_url": "https://beacon.example/",
            "status": 200,
        } for i in range(30)]
        windows = [self._beacon_events(30), self._beacon_events(31), quiet]
        _, streaks = await self._run_cycles(windows)
        self.assertEqual(streaks[-1], 0,
                         f"streak survived the evidence falling away: {streaks}")


class TestNoRealertOnStaleWindow(unittest.IsolatedAsyncioTestCase):
    """A beacon that has STOPPED must not keep producing new alerts.

    The scoring window keeps a host's last requests for up to 30 minutes, so
    re-scoring it re-confirms BEACON every cycle. Until 2026-09-14 that wrote a
    fresh alert every 60 s (the _handle_beacon cooldown) on evidence that had
    not changed - measured: 10 new alerts in 10 quiet minutes. Alerts are now
    written only on a cycle that saw new traffic from the host."""

    HOST = "beacon.example"

    async def _cycles(self, analyzer, windows, alerts):
        for events in windows:
            with mock.patch("core.c3.analyzer.c3_interceptor") as ic, \
                 mock.patch("core.c3.analyzer.c3_reputation_engine") as rep, \
                 mock.patch("core.c3.analyzer.c3_alert_store") as store:
                ic.sweep_expired_blocks = mock.AsyncMock(return_value=[])
                ic.host_snapshots = mock.Mock(return_value={self.HOST: events})
                ic.is_blocked = mock.Mock(return_value=False)
                rep.cached_result = mock.Mock(return_value=None)
                rep.score_beacon = mock.AsyncMock(
                    return_value={"score": 0.0, "flagged": False, "detail": "n/a"})
                store.add_alert = mock.Mock(side_effect=lambda r: alerts.append(r) or r)
                analyzer._host_first_seen[self.HOST] = 0.0
                await analyzer._analyze_once()

    def _live(self):
        # One more request per cycle, as a beacon that keeps sending produces.
        return [TestTemporalPersistenceGate._beacon_events(30 + i)
                for i in range(PERSISTENCE_CYCLES)]

    async def test_a_stopped_beacon_writes_no_further_alerts(self):
        analyzer, alerts = C3Analyzer(), []
        live = self._live()
        await self._cycles(analyzer, live, alerts)
        self.assertEqual(len(alerts), 1, "the confirmed beacon should alert once")
        analyzer._last_alert_ts.clear()          # as if the 60 s cooldown had passed
        await self._cycles(analyzer, [live[-1]] * 5, alerts)   # same window, nothing new
        self.assertEqual(analyzer._host_scores[self.HOST]["verdict"], "BEACON",
                         "the host's last verdict must stay visible")
        self.assertEqual(len(alerts), 1,
                         f"an unchanged window re-alerted {len(alerts) - 1} time(s)")

    async def test_a_beacon_that_resumes_alerts_again(self):
        analyzer, alerts = C3Analyzer(), []
        await self._cycles(analyzer, self._live(), alerts)
        analyzer._last_alert_ts.clear()
        resumed = TestTemporalPersistenceGate._beacon_events(30 + PERSISTENCE_CYCLES)
        await self._cycles(analyzer, [resumed], alerts)
        self.assertEqual(len(alerts), 2, "new traffic after the cooldown must alert again")


class TestScoresRampTogether(unittest.IsolatedAsyncioTestCase):
    """While the timing sample matures (6..20 requests) the displayed ML score,
    the displayed heuristic score and the fused score must all be scaled by
    the same maturity weight, so an early reading keeps the same ML:heuristic
    proportion as the mature one. (The displayed ML used to be blended with a
    score from an invented "timing-neutral" vector, which is how a young
    beacon could read "ML 8%, heuristic 47%".)"""

    async def test_display_and_score_share_one_maturity_weight(self):
        from core.c3.ml_classifier import c3_ml_engine
        from core.c3.risk_fusion import c3_risk_fusion
        if not c3_ml_engine.model_loaded:
            self.skipTest("no deployed model on disk")
        events = TestTemporalPersistenceGate._beacon_events(13)   # w = 0.5 exactly
        analyzer = C3Analyzer()
        with mock.patch("core.c3.analyzer.c3_interceptor") as ic, \
             mock.patch("core.c3.analyzer.c3_reputation_engine") as rep, \
             mock.patch("core.c3.analyzer.c3_alert_store"):
            ic.sweep_expired_blocks = mock.AsyncMock(return_value=[])
            ic.host_snapshots = mock.Mock(return_value={"beacon.example": events})
            ic.is_blocked = mock.Mock(return_value=False)
            rep.cached_result = mock.Mock(return_value=None)
            analyzer._host_first_seen["beacon.example"] = 0.0
            await analyzer._analyze_once()
        row = analyzer._host_scores["beacon.example"]
        feats = compute_features(events)
        ml_full = c3_ml_engine.decision_score(c3_ml_engine.score(feats)[0])
        heur_full, _ = C3Analyzer._heuristic_score(feats)
        w = C3Analyzer._timing_confidence(13)
        self.assertAlmostEqual(w, 0.5, places=6)
        self.assertAlmostEqual(row["signal_breakdown"]["ml"], round(w * ml_full, 4), places=4)
        self.assertAlmostEqual(row["signal_breakdown"]["heuristic"], round(w * heur_full, 4), places=4)
        fused_full = c3_risk_fusion.fuse(ml_full, None, heur_full)["score"]
        self.assertAlmostEqual(row["score"], round(w * fused_full, 4), places=3)


class TestDegradedContextVisibility(unittest.TestCase):
    """Step 3: a window whose context was substituted must SAY so.

    interceptor.py falls back to benign context defaults (idle 0, user active,
    foreground) when CDP enrichment throws. That is the right call -- the
    alternative manufactures false beacons -- but those benign values drive the
    heuristic toward 0, and risk_fusion's BOTH_SIGNAL_FLOOR then caps the fused
    score below BEACON however confident ML is. Before this change the flag was
    written by interceptor.py and read by nothing, so that blindness was
    completely invisible.

    These tests pin the visibility, NOT a scoring change: Step 3 is explicitly
    "do not change the score".
    Added 2026-09-11 by the hardening pass, step 3.
    """

    def _events(self, n, degraded):
        return [{
            "timestamp": 1000.0 + i * 5.0,
            "size_bytes": 100, "request_size": 0,
            "url": "https://c2.example/gate.php", "host": "c2.example",
            "method": "GET", "request_headers": {},
            "is_degraded_context": (i < degraded),
        } for i in range(n)]

    def test_ratio_is_zero_when_every_event_has_real_context(self):
        feats = compute_features(self._events(10, degraded=0))
        self.assertEqual(feats["degraded_context_ratio"], 0.0)

    def test_ratio_counts_the_degraded_share(self):
        feats = compute_features(self._events(10, degraded=4))
        self.assertAlmostEqual(feats["degraded_context_ratio"], 0.4, places=6)

    def test_missing_key_reads_as_not_degraded(self):
        """context_tagger's success path omits the key entirely, so absence
        must mean 'context was measured', never 'unknown'."""
        events = [{"timestamp": 1000.0 + i, "size_bytes": 10, "request_size": 0,
                   "url": "https://x.example/a", "host": "x.example",
                   "method": "GET", "request_headers": {}} for i in range(6)]
        self.assertEqual(compute_features(events)["degraded_context_ratio"], 0.0)

    def test_fusion_labels_the_verdict_when_context_is_mostly_substituted(self):
        fusion = C3RiskFusion()
        result = fusion.fuse(0.9, None, 0.4, 0.8)
        self.assertTrue(result["context_unavailable"])
        self.assertIn("context unavailable", result["detail"].lower())
        self.assertAlmostEqual(result["context_degraded_ratio"], 0.8, places=6)

    def test_fusion_stays_quiet_when_context_was_measured(self):
        fusion = C3RiskFusion()
        result = fusion.fuse(0.9, None, 0.4, 0.0)
        self.assertFalse(result["context_unavailable"])
        self.assertNotIn("context unavailable", result["detail"].lower())

    def test_the_label_does_not_change_the_score_or_verdict(self):
        """The whole point of Step 3 is visibility WITHOUT a scoring change."""
        fusion = C3RiskFusion()
        for ml, heur in ((0.9, 0.4), (0.2, 0.8), (0.55, 0.55), (0.02, 0.99)):
            clean = fusion.fuse(ml, None, heur, 0.0)
            degraded = fusion.fuse(ml, None, heur, 1.0)
            self.assertEqual(clean["score"], degraded["score"],
                             f"score moved for ml={ml} heur={heur}")
            self.assertEqual(clean["verdict"], degraded["verdict"],
                             f"verdict moved for ml={ml} heur={heur}")

    def test_default_keeps_every_existing_call_site_working(self):
        """fuse() is called with three arguments in 14 places; the new
        parameter must be optional and inert by default."""
        fusion = C3RiskFusion()
        result = fusion.fuse(0.6, None, 0.5)
        self.assertFalse(result["context_unavailable"])
        self.assertEqual(result["context_degraded_ratio"], 0.0)

    def test_ratio_is_not_an_ml_feature(self):
        """Adding it to the model would require a retrain and would change
        scoring -- which Step 3 explicitly defers to Step 4."""
        from core.c3.ml_classifier import ML_FEATURE_SUBSET
        self.assertNotIn("degraded_context_ratio", ML_FEATURE_SUBSET)
        self.assertIn("degraded_context_ratio", FEATURE_ORDER)


class TestPayloadSizeTrainServeParity(unittest.IsolatedAsyncioTestCase):
    """size_bytes must be the response BODY length, not the on-wire length.

    The four payload features (payload_size_mean, payload_cv,
    payload_repeat_ratio, upload_download_ratio) were trained on Zeek's
    resp_bytes = uncompressed response body, headers excluded. CDP's
    encodedDataLength is a different quantity: post-compression and INCLUDING
    response headers. Preferring it meant every payload feature was computed on
    a different scale at serving time than at training time.

    test_c3_feature_parity.py pins the same definition from the other side --
    it feeds capture resp_bytes in as size_bytes. These tests pin the ordering
    inside the interceptor so it cannot silently revert.
    Added 2026-09-11 with the Step 2 fix (the 2026-09-11 hardening pass).
    """

    async def _finalize(self, content_length, encoded_size, request_size):
        interceptor = C3Interceptor()
        request_id = "REQ-PARITY-1"
        interceptor._pending_requests[request_id] = {
            "request_id": request_id, "url": "https://gate.example/gate.php",
            "host": "gate.example", "method": "GET", "headers": {},
            "request_size": request_size, "timestamp": 1000.0,
            "timestamp_iso": "2026-09-11T00:00:00", "initiator": {}, "page": None,
        }
        if content_length is not None:
            interceptor._pending_responses[request_id] = {
                "status": 200, "response_size": content_length, "mime_type": "text/html",
                "response_headers": {}, "timestamp": 1000.0,
            }
        interceptor._pending_finished[request_id] = {
            "encoded_size": encoded_size, "page": None, "timestamp": 1000.1,
        }
        await interceptor._try_finalize(request_id)
        return interceptor._recent_requests[0]

    async def test_content_length_wins_over_encoded_length(self):
        # A 512-byte beacon body, gzipped to ~300 on the wire plus ~250 bytes
        # of response headers -> encodedDataLength 550. Training saw 512.
        event = await self._finalize(content_length=512, encoded_size=550, request_size=8)
        self.assertEqual(event["size_bytes"], 512)
        self.assertEqual(event["size_source"], "content_length")

    async def test_encoded_length_is_still_the_fallback(self):
        # Chunked transfer declares no Content-Length; the on-wire number is
        # better than nothing, and size_source records that it was used.
        event = await self._finalize(content_length=None, encoded_size=550, request_size=8)
        self.assertEqual(event["size_bytes"], 550)
        self.assertEqual(event["size_source"], "encoded_length")

    async def test_request_body_is_the_last_resort(self):
        event = await self._finalize(content_length=None, encoded_size=0, request_size=8)
        self.assertEqual(event["size_bytes"], 8)
        self.assertEqual(event["size_source"], "request_size")

    async def test_size_source_is_always_present_for_auditing(self):
        event = await self._finalize(content_length=None, encoded_size=0, request_size=0)
        self.assertEqual(event["size_bytes"], 0)
        self.assertEqual(event["size_source"], "none")


class TestAnalyzerSkipsBlockedHosts(unittest.IsolatedAsyncioTestCase):

    async def test_blocked_host_is_never_rescored(self):
        analyzer = C3Analyzer()
        stale_beacon_events = _make_events(20, interval_ms=5000)
        with mock.patch("core.c3.analyzer.c3_interceptor") as ic_mock:
            ic_mock.sweep_expired_blocks = mock.AsyncMock(return_value=[])
            ic_mock.host_snapshots = mock.Mock(return_value={"blocked.example": stale_beacon_events})
            ic_mock.is_blocked = mock.Mock(return_value=True)
            await analyzer._analyze_once()
        self.assertNotIn("blocked.example", analyzer._host_scores)

    async def test_unblocked_host_is_scored_normally(self):
        # This synthetic window is regular enough it may independently reach
        # a real BEACON verdict, which would route through _handle_beacon()
        # -- reputation_engine and alert_store are mocked defensively so that
        # path (if taken) never makes a real outbound API call or DB write;
        # the assertion below only cares that the host WAS scored at all.
        analyzer = C3Analyzer()
        beacon_events = _make_events(20, interval_ms=5000)
        with mock.patch("core.c3.analyzer.c3_interceptor") as ic_mock, \
             mock.patch("core.c3.analyzer.c3_reputation_engine") as rep_mock, \
             mock.patch("core.c3.analyzer.c3_alert_store") as store_mock:
            ic_mock.sweep_expired_blocks = mock.AsyncMock(return_value=[])
            ic_mock.host_snapshots = mock.Mock(return_value={"normal.example": beacon_events})
            ic_mock.is_blocked = mock.Mock(return_value=False)
            # _analyze_once() now reads the last cached TI verdict every cycle
            # (see reputation_engine.cached_score) -- return None so this host
            # is scored on ML + heuristic alone, as before.
            rep_mock.cached_score = mock.Mock(return_value=None)
            rep_mock.score_beacon = mock.AsyncMock(
                return_value={"score": 0.0, "flagged": False, "detail": "no TI data"}
            )
            store_mock.add_alert = mock.Mock(side_effect=lambda r: r)
            await analyzer._analyze_once()
        self.assertIn("normal.example", analyzer._host_scores)


class TestIdleHostEviction(unittest.TestCase):
    """Per-host stores are created on a host's first request and, before this,
    were only cleared by stop() -- so a long session kept every host it ever
    saw. Eviction must free the silent ones without touching anything still in
    use."""

    def _seed(self, interceptor, host, age_s):
        from collections import deque
        from core.c3.interceptor import _HOST_HISTORY_MAX
        event = {"host": host, "timestamp": time.time() - age_s, "method": "GET",
                 "url": f"https://{host}/x", "size_bytes": 10, "timestamp_iso": ""}
        interceptor._host_windows.setdefault(host, deque(maxlen=50)).append(event)
        interceptor._host_history.setdefault(host, deque(maxlen=_HOST_HISTORY_MAX)).append(event)

    def test_silent_host_is_dropped_from_both_stores(self):
        from core.c3.interceptor import _MAX_EVENT_AGE_S
        ic = C3Interceptor()
        self._seed(ic, "silent.example", _MAX_EVENT_AGE_S + 60)
        self.assertEqual(ic.evict_idle_hosts(force=True), ["silent.example"])
        self.assertNotIn("silent.example", ic._host_windows)
        self.assertNotIn("silent.example", ic._host_history)

    def test_active_host_is_kept(self):
        ic = C3Interceptor()
        self._seed(ic, "active.example", 5)
        self.assertEqual(ic.evict_idle_hosts(force=True), [])
        self.assertIn("active.example", ic._host_windows)

    def test_blocked_host_is_kept_even_when_silent(self):
        # A blocked host's capture log is deliberately frozen at the block
        # boundary; evicting it would erase the evidence for the block.
        from core.c3.interceptor import _MAX_EVENT_AGE_S
        ic = C3Interceptor()
        self._seed(ic, "blocked.example", _MAX_EVENT_AGE_S + 60)
        ic._blocked_hosts.add("blocked.example")
        self.assertEqual(ic.evict_idle_hosts(force=True), [])
        self.assertIn("blocked.example", ic._host_windows)

    def test_host_named_in_keep_is_kept(self):
        from core.c3.interceptor import _MAX_EVENT_AGE_S
        ic = C3Interceptor()
        self._seed(ic, "watched.example", _MAX_EVENT_AGE_S + 60)
        self.assertEqual(ic.evict_idle_hosts(keep={"watched.example"}, force=True), [])
        self.assertIn("watched.example", ic._host_windows)

    def test_sweep_is_throttled_between_calls(self):
        from core.c3.interceptor import _MAX_EVENT_AGE_S
        ic = C3Interceptor()
        self._seed(ic, "silent.example", _MAX_EVENT_AGE_S + 60)
        ic.evict_idle_hosts(force=True)
        self._seed(ic, "other.example", _MAX_EVENT_AGE_S + 60)
        self.assertEqual(ic.evict_idle_hosts(), [])
        self.assertIn("other.example", ic._host_windows)


class TestUnchangedWindowIsNotRescored(unittest.IsolatedAsyncioTestCase):
    """The loop re-scores every host every cycle, and a host that has gone quiet
    keeps its window for up to 30 minutes. Reusing the previous cycle's pure
    results must not change the verdict by even a digit."""

    def _mocks(self, ic_mock, rep_mock, store_mock, events):
        ic_mock.sweep_expired_blocks = mock.AsyncMock(return_value=[])
        ic_mock.evict_idle_hosts = mock.Mock(return_value=[])
        ic_mock.host_snapshots = mock.Mock(return_value={"quiet.example": events})
        ic_mock.is_blocked = mock.Mock(return_value=False)
        rep_mock.cached_result = mock.Mock(return_value=None)
        rep_mock.score_beacon = mock.AsyncMock(
            return_value={"score": 0.0, "flagged": False, "detail": "no TI data"})
        store_mock.add_alert = mock.Mock(side_effect=lambda r: r)

    async def _run(self, cycles, use_cache):
        analyzer = C3Analyzer()
        events = _make_events(20, interval_ms=5000)
        with mock.patch("core.c3.analyzer.c3_interceptor") as ic_mock, \
             mock.patch("core.c3.analyzer.c3_reputation_engine") as rep_mock, \
             mock.patch("core.c3.analyzer.c3_alert_store") as store_mock:
            self._mocks(ic_mock, rep_mock, store_mock, events)
            analyzer._host_first_seen["quiet.example"] = 0.0   # skip the 15s cooldown
            for _ in range(cycles):
                await analyzer._analyze_once()
                if not use_cache:
                    analyzer._host_calc_cache.clear()
        result = dict(analyzer._host_scores["quiet.example"])
        result.pop("timestamp", None)
        return result

    async def test_cached_and_uncached_cycles_agree(self):
        self.assertEqual(await self._run(3, True), await self._run(3, False))

    async def test_cache_is_reused_while_the_window_stands_still(self):
        analyzer = C3Analyzer()
        events = _make_events(20, interval_ms=5000)
        with mock.patch("core.c3.analyzer.c3_interceptor") as ic_mock, \
             mock.patch("core.c3.analyzer.c3_reputation_engine") as rep_mock, \
             mock.patch("core.c3.analyzer.c3_alert_store") as store_mock, \
             mock.patch("core.c3.analyzer.compute_features",
                        side_effect=compute_features) as feat_spy:
            self._mocks(ic_mock, rep_mock, store_mock, events)
            analyzer._host_first_seen["quiet.example"] = 0.0
            for _ in range(4):
                await analyzer._analyze_once()
        self.assertEqual(feat_spy.call_count, 1)

    async def test_new_traffic_recomputes(self):
        analyzer = C3Analyzer()
        events = _make_events(20, interval_ms=5000)
        with mock.patch("core.c3.analyzer.c3_interceptor") as ic_mock, \
             mock.patch("core.c3.analyzer.c3_reputation_engine") as rep_mock, \
             mock.patch("core.c3.analyzer.c3_alert_store") as store_mock, \
             mock.patch("core.c3.analyzer.compute_features",
                        side_effect=compute_features) as feat_spy:
            self._mocks(ic_mock, rep_mock, store_mock, events)
            analyzer._host_first_seen["quiet.example"] = 0.0
            await analyzer._analyze_once()
            events.append(dict(events[-1], timestamp=events[-1]["timestamp"] + 5.0))
            await analyzer._analyze_once()
        self.assertEqual(feat_spy.call_count, 2)


class _OneLineRunner(unittest.TextTestRunner):
    """Print every result on one line ("test_x (module.Class.test_x) ... ok").

    The dashboard's Tests panel (core/main.py, _run_test_component) counts
    results by matching that one-line form. With descriptions on, unittest
    prints a test's docstring on a second line and moves "... ok" there, so
    the 36 tests that have docstrings were not counted (108 of 144 shown)."""

    def __init__(self, *args, **kwargs):
        kwargs["descriptions"] = False
        super().__init__(*args, **kwargs)


if __name__ == "__main__":
    print("\n=== C3 Behavioral Anomaly Unit Tests ===\n")
    unittest.main(verbosity=2, testRunner=_OneLineRunner)
