"""
C3 train/serve PARITY test for the 18 supervised features.

Run from the project root:  python test/C3/test_c3_feature_parity.py

WHY THIS TEST EXISTS
--------------------
The model in models/c3_xgb_classifier_18feat_20260902.pkl is trained offline by
scripts/build_c3_18feat_dataset.py, which reads capture log files. At runtime the
same 18 numbers are produced by core/c3/feature_engine.compute_features(), which
reads live Chrome DevTools Protocol events. Those are two separate
implementations of one definition.

If they ever disagree, the model is scored on inputs it was never trained on and
its output is meaningless - which is exactly the failure the previous model hit
(NetFlow flow-total bytes were fed to a feature named payload_size_mean, and the
model scored 0.0000 on every real browser beacon).

So this test takes REAL request rows from two real captures, feeds them through
BOTH implementations, and asserts the 18 features agree to 1e-6.

The fixture test/C3/fixtures/parity_sample_real.csv holds 120 genuine request
records - 60 Zeus V1 command-and-control requests from
CTU-Malware-Capture-Botnet-25-1 and 60 human browsing requests from
CTU-Normal-30. Nothing in it is synthetic or hand-written.
"""
import csv
import importlib.util
import math
import os
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import numpy as np

from core.c3.anomaly_engine import c3_ml_engine
from core.c3.feature_engine import compute_features

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "fixtures", "parity_sample_real.csv")
BUILDER = os.path.join(_ROOT, "scripts", "build_c3_18feat_dataset.py")

MODEL_FEATURES = [
    "iat_cv", "iat_bowley_skewness", "iat_norm_mad", "iat_burstiness",
    "iat_autocorr_lag1", "iat_spread_ratio", "iat_clock_share", "iat_entropy_norm",
    "payload_size_mean", "payload_cv", "payload_repeat_ratio", "upload_download_ratio",
    "url_path_entropy", "unique_path_ratio", "http_post_ratio",
    "uri_len_norm", "uri_char_entropy_norm", "referrer_absent_ratio",
]


def _load_builder():
    spec = importlib.util.spec_from_file_location("c3_builder", BUILDER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_rows():
    samples = {}
    with open(FIXTURE, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            samples.setdefault(row["sample"], []).append(row)
    return samples


def _as_live_events(rows):
    """Turn capture rows into the event dicts core/c3/interceptor.py produces."""
    events = []
    for row in rows:
        referer = (row["referrer"] or "").strip()
        headers = {} if referer in ("", "-", "(empty)") else {"Referer": referer}
        events.append({
            "timestamp": float(row["ts"]),
            "size_bytes": float(row["resp_bytes"]),
            "request_size": float(row["req_bytes"]),
            "url": "https://capture.invalid" + (row["uri"] or "/"),
            "host": "capture.invalid",
            "method": (row["method"] or "GET").upper(),
            "request_headers": headers,
            "status": row["status"],
        })
    return events


def _as_builder_args(rows):
    return (
        np.array([float(r["ts"]) for r in rows], dtype=float),
        np.array([float(r["resp_bytes"]) for r in rows], dtype=float),
        np.array([float(r["req_bytes"]) for r in rows], dtype=float),
        [(r["method"] or "GET").upper() for r in rows],
        [r["uri"] or "/" for r in rows],
        [r["referrer"] or "-" for r in rows],
        [r["status"] or "-" for r in rows],
    )


class TestFeatureParity(unittest.TestCase):
    """The live engine and the training builder must agree on all 18 features."""

    @classmethod
    def setUpClass(cls):
        cls.builder = _load_builder()
        cls.samples = _load_rows()

    def test_fixture_is_real_and_has_both_classes(self):
        self.assertIn("zeus_c2_real", self.samples)
        self.assertIn("ctu_normal_browsing_real", self.samples)
        for name, rows in self.samples.items():
            self.assertGreaterEqual(len(rows), 4, f"{name}: window too small to score")

    def test_all_18_features_match_the_training_builder(self):
        for name, rows in self.samples.items():
            live = compute_features(_as_live_events(rows))
            offline = self.builder.window_features(*_as_builder_args(rows))
            for feature in MODEL_FEATURES:
                with self.subTest(sample=name, feature=feature):
                    self.assertIn(feature, live, "live engine does not produce it")
                    self.assertIn(feature, offline, "builder does not produce it")
                    self.assertTrue(
                        math.isclose(float(live[feature]), float(offline[feature]),
                                     rel_tol=1e-6, abs_tol=1e-6),
                        f"{name}.{feature}: live={live[feature]} offline={offline[feature]}",
                    )

    def test_real_c2_and_real_browsing_are_actually_separated(self):
        """A parity test that passed on two identical vectors would prove
        nothing, so check the two real samples really do look different on the
        features the model leans on."""
        c2 = compute_features(_as_live_events(self.samples["zeus_c2_real"]))
        benign = compute_features(_as_live_events(self.samples["ctu_normal_browsing_real"]))
        self.assertGreater(c2["referrer_absent_ratio"], benign["referrer_absent_ratio"])
        self.assertLess(c2["unique_path_ratio"], benign["unique_path_ratio"])
        self.assertLess(c2["url_path_entropy"], benign["url_path_entropy"])

    def test_the_deployed_model_can_read_the_live_vector(self):
        """The DEPLOYED model must find every feature it needs, by name, in
        what the live engine produces.

        The model path is taken from the engine itself rather than hardcoded.
        A hardcoded path silently stops testing the deployed model the moment
        anomaly_engine.py is pointed somewhere else -- which is exactly what
        happened on 2026-09-03, when this test kept passing against the
        superseded 18-feature pickle after the calibrated model went live."""
        import pickle
        path = c3_ml_engine._model_path
        if not os.path.exists(path):
            self.skipTest(f"deployed model not present at {path}")
        with open(path, "rb") as fh:
            payload = pickle.load(fh)
        live = compute_features(_as_live_events(self.samples["zeus_c2_real"]))
        missing = [f for f in payload["feature_names"] if f not in live]
        self.assertEqual(missing, [], f"live engine is missing {missing}")
        vector = np.array([[float(live[f]) for f in payload["feature_names"]]])
        score = float(payload["model"].predict_proba(vector)[0][1])
        self.assertTrue(0.0 <= score <= 1.0)

        # and the engine's own scoring path must agree with the raw model
        engine_score, _ = c3_ml_engine.score(live)
        self.assertIsNotNone(engine_score, "deployed engine returned no score")
        self.assertAlmostEqual(score, engine_score, places=6,
                               msg="engine.score() disagrees with the model")
        print(f"\n    real Zeus C2 window scores {score:.4f} on the deployed "
              f"model ({os.path.basename(str(path))})")


if __name__ == "__main__":
    print("\n=== C3 Feature Parity Tests (train vs serve) ===\n")
    unittest.main(verbosity=2)
