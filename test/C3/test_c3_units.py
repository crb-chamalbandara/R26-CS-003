"""
C3 Unit Tests — Behavioral Anomaly & Beacon Detection
Run from project root:  python Test/C3/test_c3_units.py
"""
import sys
import os
import time
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.c3.feature_engine import compute_features, FEATURE_ORDER
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
        """Beacon always hitting the same path → low URL path entropy."""
        feats = compute_features(_make_events(20))
        self.assertLess(feats["url_path_entropy"], 5.0)

    def test_varied_urls_higher_entropy(self):
        feats = compute_features(_make_normal_events(20))
        beacon_feats = compute_features(_make_events(20))
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
        result = self.fusion.fuse(anomaly=0.8, reputation=0.9, heuristic=0.7)
        self.assertEqual(result["verdict"], "BEACON")
        self.assertGreaterEqual(result["score"], 0.6)

    def test_verdict_safe_when_all_zero(self):
        result = self.fusion.fuse(anomaly=0.0, reputation=0.0, heuristic=0.0)
        self.assertEqual(result["verdict"], "SAFE")
        self.assertLess(result["score"], 0.3)

    def test_verdict_suspicious_mid_range(self):
        result = self.fusion.fuse(anomaly=0.4, reputation=None, heuristic=0.2)
        self.assertEqual(result["verdict"], "SUSPICIOUS")
        self.assertGreaterEqual(result["score"], 0.3)
        self.assertLess(result["score"], 0.6)

    def test_anomaly_only_capped_below_beacon_without_heuristic(self):
        """High anomaly alone should NOT reach BEACON — heuristic confirmation required."""
        result = self.fusion.fuse(anomaly=0.95, reputation=None, heuristic=0.0)
        self.assertLess(result["score"], 0.60,
                        "Anomaly-only score should be capped below 0.60")
        self.assertNotEqual(result["verdict"], "BEACON")

    def test_reputation_override_triggers_at_0_8(self):
        """Reputation >= 0.8 forces score to at least 0.60."""
        result = self.fusion.fuse(anomaly=None, reputation=0.85, heuristic=0.1)
        self.assertGreaterEqual(result["score"], 0.60)
        self.assertEqual(result["verdict"], "BEACON")

    def test_score_clamped_between_0_and_1(self):
        result = self.fusion.fuse(anomaly=1.0, reputation=1.0, heuristic=1.0,
                                  browser_anomaly=1.0)
        self.assertLessEqual(result["score"], 1.0)
        self.assertGreaterEqual(result["score"], 0.0)

    def test_result_has_required_keys(self):
        result = self.fusion.fuse(anomaly=0.5, reputation=0.5, heuristic=0.5)
        self.assertIn("score", result)
        self.assertIn("verdict", result)
        self.assertIn("detail", result)

    def test_heuristic_only_mode_when_no_anomaly_or_rep(self):
        result = self.fusion.fuse(anomaly=None, reputation=None, heuristic=0.7)
        self.assertAlmostEqual(result["score"], 0.7, places=2)
        self.assertEqual(result["verdict"], "BEACON")

    def test_full_four_signal_fusion(self):
        result = self.fusion.fuse(
            anomaly=0.7,
            reputation=0.6,
            heuristic=0.5,
            browser_anomaly=0.6,
        )
        self.assertGreaterEqual(result["score"], 0.6)
        self.assertEqual(result["verdict"], "BEACON")

    def test_none_inputs_handled_gracefully(self):
        result = self.fusion.fuse(anomaly=None, reputation=None, heuristic=None)
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
        result = self.fusion.fuse(anomaly=None, reputation=None, heuristic=heuristic)
        # Normal events should not reach BEACON threshold
        self.assertLess(result["score"], 0.60)


if __name__ == "__main__":
    print("\n=== C3 Behavioral Anomaly Unit Tests ===\n")
    unittest.main(verbosity=2)
