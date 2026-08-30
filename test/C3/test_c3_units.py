"""
C3 Unit Tests — Behavioral Anomaly & Beacon Detection
Run from project root:  python Test/C3/test_c3_units.py
"""
import math
import os
import pickle
import sqlite3
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.c3.alert_store import C3AlertStore
from core.c3.analyzer import C3Analyzer
from core.c3.anomaly_engine import C3RFClassifierEngine
from core.c3.block_store import C3BlockStore
from core.c3.feature_engine import compute_features, FEATURE_ORDER
from core.c3.interceptor import C3Interceptor
from core.c3.risk_fusion import C3RiskFusion


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


class _DummyRfModel:
    """Module-level (not nested) so pickle can actually serialize it --
    pickle requires classes to be importable by module path."""
    def predict_proba(self, X):
        return [[0.5, 0.5]]


def _make_fixed_url_events(n, interval_ms=5000):
    """Beacon fixture that hits the exact same endpoint every time (no varying
    query string) — needed for url_path_entropy comparisons specifically.
    _make_events() above appends a unique ?seq={i} to every URL, which
    feature_engine.py's own _path_for_entropy() deliberately counts as a
    *different* path per request (see its comment: two calls to
    /beacon?ts=1 and /beacon?ts=2 count as different paths, on purpose, so a
    beacon that varies its query string per call isn't rewarded with a
    falsely-low entropy score). That makes _make_events() unsuitable as a
    "low entropy" fixture — it actually produces the maximum possible
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
        """Human browsing is irregular — high IAT CV."""
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
        result = self.fusion.fuse(rf=0.8, reputation=0.9, heuristic=0.7)
        self.assertEqual(result["verdict"], "BEACON")
        self.assertGreaterEqual(result["score"], 0.6)

    def test_verdict_safe_when_all_zero(self):
        result = self.fusion.fuse(rf=0.0, reputation=0.0, heuristic=0.0)
        self.assertEqual(result["verdict"], "SAFE")
        self.assertLess(result["score"], 0.3)

    def test_verdict_suspicious_mid_range(self):
        result = self.fusion.fuse(rf=0.5, reputation=None, heuristic=0.3)
        self.assertEqual(result["verdict"], "SUSPICIOUS")
        self.assertGreaterEqual(result["score"], 0.3)
        self.assertLess(result["score"], 0.6)

    def test_rf_only_does_not_reach_beacon_without_heuristic(self):
        """High RF score alone should NOT reach BEACON — RF is trained on only
        187 real positive examples, so heuristic confirmation is still required."""
        result = self.fusion.fuse(rf=0.95, reputation=None, heuristic=0.0)
        self.assertLess(result["score"], 0.60,
                        "RF-only score should stay below 0.60")
        self.assertNotEqual(result["verdict"], "BEACON")

    def test_reputation_override_triggers_at_0_8(self):
        """Reputation >= 0.8 forces score to at least 0.60."""
        result = self.fusion.fuse(rf=None, reputation=0.85, heuristic=0.1)
        self.assertGreaterEqual(result["score"], 0.60)
        self.assertEqual(result["verdict"], "BEACON")

    def test_score_clamped_between_0_and_1(self):
        result = self.fusion.fuse(rf=1.0, reputation=1.0, heuristic=1.0)
        self.assertLessEqual(result["score"], 1.0)
        self.assertGreaterEqual(result["score"], 0.0)

    def test_result_has_required_keys(self):
        result = self.fusion.fuse(rf=0.5, reputation=0.5, heuristic=0.5)
        self.assertIn("score", result)
        self.assertIn("verdict", result)
        self.assertIn("detail", result)

    def test_heuristic_only_mode_when_no_rf_or_rep(self):
        result = self.fusion.fuse(rf=None, reputation=None, heuristic=0.7)
        self.assertAlmostEqual(result["score"], 0.7, places=2)
        self.assertEqual(result["verdict"], "BEACON")

    def test_full_signal_fusion(self):
        result = self.fusion.fuse(
            rf=0.8,
            reputation=0.7,
            heuristic=0.6,
        )
        self.assertGreaterEqual(result["score"], 0.6)
        self.assertEqual(result["verdict"], "BEACON")

    def test_none_inputs_handled_gracefully(self):
        result = self.fusion.fuse(rf=None, reputation=None, heuristic=None)
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
        result = self.fusion.fuse(rf=None, reputation=None, heuristic=heuristic)
        # Normal events should not reach BEACON threshold
        self.assertLess(result["score"], 0.60)


# ── Heuristic Scoring Rules (analyzer.py _heuristic_score) ────────────────────
# Direct, isolated tests of each rule — _heuristic_score() had zero direct test
# coverage before this file (existing integration tests above hand-reimplement
# a different mini-heuristic inline). Each test sets only the feature keys
# needed to trigger exactly one rule; every rule's threshold is checked against
# the OTHER rules' trigger conditions to confirm no cross-firing, since
# _heuristic_score()'s missing-key defaults (e.g. iat_cv defaults to 1.0,
# user_active_ratio defaults to 1.0) are themselves "safe" values that don't
# trigger any rule — verified by inspection of analyzer.py:355-411.
class TestHeuristicScoreRules(unittest.TestCase):

    def test_rule1_regular_timing_small_payload(self):
        feats = {"iat_cv": 0.02, "iat_mean_ms": 5000.0,
                  "user_active_ratio": 0.1, "payload_size_mean": 500.0}
        score, flags = C3Analyzer._heuristic_score(feats)
        self.assertAlmostEqual(score, 0.30, places=4)
        self.assertIn("regular timing (small payload)", flags)

    def test_rule1_does_not_fire_on_large_payload(self):
        """Video streaming has iat_cv ~ 0.01 but large payload — must not flag."""
        feats = {"iat_cv": 0.02, "iat_mean_ms": 5000.0,
                  "user_active_ratio": 0.1, "payload_size_mean": 50_000.0}
        score, flags = C3Analyzer._heuristic_score(feats)
        self.assertEqual(score, 0.0)
        self.assertEqual(flags, [])

    def test_rule2_foreground_idle(self):
        feats = {"user_active_ratio": 0.0, "background_tab_ratio": 0.1,
                  "avg_idle_time_ms": 60_000.0}
        score, flags = C3Analyzer._heuristic_score(feats)
        self.assertAlmostEqual(score, 0.25, places=4)
        self.assertIn("foreground requests firing while user idle", flags)

    def test_rule3_background_non_extension(self):
        feats = {"background_tab_ratio": 0.9, "extension_origin_ratio": 0.0}
        score, flags = C3Analyzer._heuristic_score(feats)
        self.assertAlmostEqual(score, 0.20, places=4)
        self.assertIn("background traffic (non-extension)", flags)

    def test_rule3_background_extension_reduced_weight(self):
        feats = {"background_tab_ratio": 0.9, "extension_origin_ratio": 0.3}
        score, flags = C3Analyzer._heuristic_score(feats)
        self.assertAlmostEqual(score, 0.08, places=4)
        self.assertIn("background traffic (extension)", flags)

    def test_rule4_extension_foreground_beacon(self):
        feats = {"extension_origin_ratio": 0.9, "background_tab_ratio": 0.1,
                  "iat_cv": 0.01, "iat_mean_ms": 5000.0, "user_active_ratio": 0.9}
        score, flags = C3Analyzer._heuristic_score(feats)
        self.assertAlmostEqual(score, 0.10, places=4)
        self.assertIn("extension foreground beacon pattern", flags)

    def test_rule5_same_endpoint_regular_timing(self):
        feats = {"url_path_entropy": 0.1, "iat_cv": 0.05, "iat_mean_ms": 5000.0,
                  "user_active_ratio": 0.1, "payload_size_mean": 50_000.0}
        score, flags = C3Analyzer._heuristic_score(feats)
        self.assertAlmostEqual(score, 0.10, places=4)
        self.assertIn("same endpoint with regular timing", flags)

    def test_rule6_script_initiated_regular_traffic(self):
        feats = {"script_initiator_ratio": 0.9, "iat_cv": 0.05}
        score, flags = C3Analyzer._heuristic_score(feats)
        self.assertAlmostEqual(score, 0.05, places=4)
        self.assertIn("script-initiated regular traffic", flags)

    def test_rule6_does_not_fire_without_regular_timing(self):
        feats = {"script_initiator_ratio": 0.9, "iat_cv": 0.50}
        score, flags = C3Analyzer._heuristic_score(feats)
        self.assertEqual(score, 0.0)

    def test_rule6_does_not_fire_with_low_script_ratio(self):
        feats = {"script_initiator_ratio": 0.30, "iat_cv": 0.05}
        score, flags = C3Analyzer._heuristic_score(feats)
        self.assertEqual(score, 0.0)

    def test_rule7_high_post_ratio_regular_timing(self):
        feats = {"http_post_ratio": 0.95, "iat_cv": 0.05}
        score, flags = C3Analyzer._heuristic_score(feats)
        self.assertAlmostEqual(score, 0.08, places=4)
        self.assertIn("high POST ratio with regular timing", flags)

    def test_rule7_does_not_fire_without_regular_timing(self):
        feats = {"http_post_ratio": 0.95, "iat_cv": 0.50}
        score, flags = C3Analyzer._heuristic_score(feats)
        self.assertEqual(score, 0.0)

    def test_rule7_does_not_fire_with_low_post_ratio(self):
        feats = {"http_post_ratio": 0.40, "iat_cv": 0.05}
        score, flags = C3Analyzer._heuristic_score(feats)
        self.assertEqual(score, 0.0)

    def test_rule8_high_rate_while_inactive(self):
        feats = {"requests_per_hour": 800.0, "user_active_ratio": 0.1, "iat_mean_ms": 5000.0}
        score, flags = C3Analyzer._heuristic_score(feats)
        self.assertAlmostEqual(score, 0.08, places=4)
        self.assertIn("high-frequency requests while user inactive", flags)

    def test_rule8_does_not_fire_when_timing_unreliable(self):
        """iat_mean_ms == 0.0 (small-window default) must block Rule 8, since
        requests_per_hour's 60s floor still lets a page-load burst alone
        clear the 500/hr threshold before timing is considered reliable."""
        feats = {"requests_per_hour": 800.0, "user_active_ratio": 0.1}
        score, flags = C3Analyzer._heuristic_score(feats)
        self.assertEqual(score, 0.0)

    def test_rule8_does_not_fire_when_user_active(self):
        feats = {"requests_per_hour": 800.0, "user_active_ratio": 0.9}
        score, flags = C3Analyzer._heuristic_score(feats)
        self.assertEqual(score, 0.0)

    def test_rule8_does_not_fire_below_rate_threshold(self):
        feats = {"requests_per_hour": 200.0, "user_active_ratio": 0.1}
        score, flags = C3Analyzer._heuristic_score(feats)
        self.assertEqual(score, 0.0)

    def test_rule9_same_site_dampens_existing_score(self):
        """A high same-site ratio must reduce (not zero out) an existing score."""
        feats = {"background_tab_ratio": 0.9, "extension_origin_ratio": 0.0,
                  "same_site_ratio": 0.9}
        score, flags = C3Analyzer._heuristic_score(feats)
        self.assertAlmostEqual(score, 0.20 * 0.70, places=4)
        self.assertIn("background traffic (non-extension)", flags)
        self.assertIn("same-site background sync (dampened)", flags)

    def test_rule9_no_dampening_below_threshold(self):
        feats = {"background_tab_ratio": 0.9, "extension_origin_ratio": 0.0,
                  "same_site_ratio": 0.50}
        score, flags = C3Analyzer._heuristic_score(feats)
        self.assertAlmostEqual(score, 0.20, places=4)
        self.assertNotIn("same-site background sync (dampened)", flags)

    def test_rule9_dampens_rule6_contribution_too(self):
        """
        Script-initiated + regular timing is exactly what a legitimate SPA's
        own background sync also looks like, so Rule 6's contribution must
        be dampened by Rule 9 too, not escape it.
        """
        feats = {"script_initiator_ratio": 0.9, "iat_cv": 0.05, "same_site_ratio": 0.9}
        score, flags = C3Analyzer._heuristic_score(feats)
        self.assertAlmostEqual(score, 0.05 * 0.70, places=4)

    def test_rule9_never_adds_suspicion_on_its_own(self):
        """High same_site_ratio alone (no other rule firing) must stay at 0.0."""
        feats = {"same_site_ratio": 0.95}
        score, flags = C3Analyzer._heuristic_score(feats)
        self.assertEqual(score, 0.0)

    def test_empty_features_score_zero(self):
        """Every rule's default-for-missing-key value must be non-triggering."""
        score, flags = C3Analyzer._heuristic_score({})
        self.assertEqual(score, 0.0)
        self.assertEqual(flags, [])

    def test_end_to_end_beacon_fixture_score_locked(self):
        """
        Regression lock: the existing 30-event synthetic beacon fixture
        (background tab, 5s interval, 256B payload, unique-query-per-request
        URLs) scores 0.58 via Rule 1 (0.30) + Rule 3 non-extension branch
        (0.20) + Rule 8 (0.08 — its ~745 req/hr extrapolated rate clears the
        500/hr gate while the user is inactive). Was 0.50 before Rule 8
        existed; the increase is intentional — this fixture genuinely shows
        the sustained-high-rate-while-inactive pattern Rule 8 targets, not a
        bug. Fails loudly if a later change alters existing-rule behavior for
        real feature_engine.py output (not just the isolated dicts above).
        """
        feats = compute_features(_make_events(30, interval_ms=5000))
        score, flags = C3Analyzer._heuristic_score(feats)
        self.assertAlmostEqual(score, 0.58, places=4)
        self.assertIn("regular timing (small payload)", flags)
        self.assertIn("background traffic (non-extension)", flags)
        self.assertIn("high-frequency requests while user inactive", flags)


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


# ── Model Loading Compatibility (anomaly_engine.C3RFClassifierEngine) ─────────
# An incompatible/malformed model file must fail safe (model_loaded stays
# False, score() returns None) rather than being silently accepted and
# producing wrong or crashing predictions later.
class TestModelLoadingCompatibility(unittest.TestCase):

    def _engine_with_payload(self, payload) -> C3RFClassifierEngine:
        tmp = tempfile.NamedTemporaryFile(suffix=".pkl", delete=False)
        tmp_path = tmp.name
        try:
            pickle.dump(payload, tmp)
        finally:
            tmp.close()  # must close before reload()/unlink can reopen or remove it on Windows
        try:
            engine = C3RFClassifierEngine.__new__(C3RFClassifierEngine)
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
            "model": _DummyRfModel(),
            "feature_names": ["iat_mean_ms", "iat_cv"],
            "threshold": 0.5,
        })
        self.assertTrue(engine.model_loaded)

    def test_non_dict_payload_rejected(self):
        """A bare model-only pickle has no feature_names to validate -- must
        be rejected rather than silently guessed at (old legacy format)."""
        engine = self._engine_with_payload(_DummyRfModel())
        self.assertFalse(engine.model_loaded)
        score, detail = engine.score({"iat_mean_ms": 100})
        self.assertIsNone(score)

    def test_unknown_feature_names_rejected(self):
        engine = self._engine_with_payload({
            "model": _DummyRfModel(),
            "feature_names": ["totally_made_up_feature", "iat_cv"],
            "threshold": 0.5,
        })
        self.assertFalse(engine.model_loaded)

    def test_missing_feature_names_rejected(self):
        engine = self._engine_with_payload({"model": _DummyRfModel(), "threshold": 0.5})
        self.assertFalse(engine.model_loaded)

    def test_model_without_predict_proba_rejected(self):
        engine = self._engine_with_payload({
            "model": object(), "feature_names": ["iat_cv"], "threshold": 0.5,
        })
        self.assertFalse(engine.model_loaded)

    def test_missing_file_fails_safe(self):
        engine = C3RFClassifierEngine.__new__(C3RFClassifierEngine)
        engine._model = None
        engine._feature_names = []
        engine._threshold = 0.5
        engine._model_path = "C:/definitely/does/not/exist.pkl"
        result = engine.reload()
        self.assertFalse(result)
        self.assertFalse(engine.model_loaded)


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
            "features": {}, "signal_breakdown": {"rf": 0.6},
            "signal_detail": {"rf": "RF prob=0.6000 threshold=0.50 [bot]"},
        })
        # Fresh instance simulates a backend restart reading from disk.
        reloaded = C3AlertStore(db_path=self._db_path)
        alert = reloaded.list_alerts(1)[0]
        self.assertEqual(alert["signal_detail"], {"rf": "RF prob=0.6000 threshold=0.50 [bot]"})

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


# ── Reputation Re-Fuse (analyzer._handle_beacon) ───────────────────────────────
# fuse()'s reputation weight-table entries were previously unreachable dead
# code: _analyze_once() always calls fuse() with reputation=None, so
# reputation only ever decorated signal_breakdown for display without
# actually influencing the persisted score. _handle_beacon() now re-fuses
# with the real reputation score once known -- these tests confirm it can
# only ever raise the score (never lower it) and never changes the verdict
# away from the BEACON that was already independently confirmed.
class TestHandleBeaconReputationRefuse(unittest.IsolatedAsyncioTestCase):

    def _make_result(self, score, rf, heuristic):
        return {
            "score": score, "verdict": "BEACON", "detail": "initial",
            "source": "fusion",
            "signal_breakdown": {"rf": rf, "reputation": None, "heuristic": heuristic},
            "signal_detail": {"rf": "x", "heuristic": "y", "reputation": "pending", "fusion": "z"},
            "host": "evil.example", "latest_url": "http://evil.example/beacon",
            "features": {}, "request_count": 20, "timestamp": "2026-01-01T00:00:00",
        }

    async def test_flagged_reputation_can_raise_score(self):
        analyzer = C3Analyzer()
        result = self._make_result(score=0.65, rf=0.2, heuristic=0.9)
        with mock.patch("core.c3.analyzer.c3_reputation_engine") as rep_mock, \
             mock.patch("core.c3.analyzer.c3_alert_store") as store_mock, \
             mock.patch("core.c3.analyzer.c3_interceptor"):
            rep_mock.score_beacon = mock.AsyncMock(
                return_value={"score": 0.9, "flagged": True, "detail": "abuseipdb=0.90"}
            )
            store_mock.add_alert = mock.Mock(side_effect=lambda r: r)
            await analyzer._handle_beacon("evil.example", result)
        self.assertGreaterEqual(result["score"], 0.65)
        self.assertEqual(result["verdict"], "BEACON")

    async def test_clean_reputation_never_lowers_score(self):
        analyzer = C3Analyzer()
        result = self._make_result(score=0.75, rf=0.2, heuristic=0.95)
        original_score = result["score"]
        with mock.patch("core.c3.analyzer.c3_reputation_engine") as rep_mock, \
             mock.patch("core.c3.analyzer.c3_alert_store") as store_mock, \
             mock.patch("core.c3.analyzer.c3_interceptor"):
            rep_mock.score_beacon = mock.AsyncMock(
                return_value={"score": 0.0, "flagged": False, "detail": "no TI data"}
            )
            store_mock.add_alert = mock.Mock(side_effect=lambda r: r)
            await analyzer._handle_beacon("evil.example", result)
        self.assertGreaterEqual(result["score"], original_score)
        self.assertEqual(result["verdict"], "BEACON")


# ── Reputation Engine: VirusTotal scoring + cached_score ───────────────────
# The VT engine-count -> score map is calibrated against real VT data
# (measured 2026-08-29): google.com sits at malicious==1 (one chronically-
# noisy engine), so `malicious >= 1` -- the rule this replaced -- flagged
# google.com and many Fortune-500 domains as malicious beacon destinations.
# cached_score() must mirror a lookup's `flagged` bit so a clean result never
# feeds a spurious 0.0 into every fusion cycle.
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
        with sqlite3.connect(self._db_path) as conn:
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
        with sqlite3.connect(self._db_path) as conn:
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
        with sqlite3.connect(self._db_path) as conn:
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
        with sqlite3.connect(self._db_path) as conn:
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


if __name__ == "__main__":
    print("\n=== C3 Behavioral Anomaly Unit Tests ===\n")
    unittest.main(verbosity=2)
