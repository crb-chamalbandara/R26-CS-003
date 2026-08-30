"""
C3 anomaly engine.

Loads the supervised XGBoost C2-beacon classifier and exposes its score (0-1).

Model history for this slot:
  - Isolation Forest (timing-only + a never-trained browser-context variant)
    — removed; unsupervised, trained on unlabeled pcap, not C2-specific.
  - RandomForest on CTU-13 label_c2 — replaced 2026-08-27, archived at
    models/archive/c3_rf_classifier_PRE_XGB_20260827.pkl.
  - XGBoost on CTU-13 + IoT-23 NetFlow label_c2 — replaced 2026-08-28,
    archived at models/archive/c3_xgb_classifier_NETFLOW_PRE_HTTP_20260828.pkl.
    See C3_FullPipeline_XGB_Results.md.
  - XGBoost on CTU-13 HTTP (Zeek http.log), 9-feature, absolute-timing —
    2026-08-28, archived at
    models/archive/c3_xgb_classifier_HTTP_ABSTIMING_20260828.pkl. Honest
    LOSO precision 0.383 / recall 0.192 — the best precision this slot has
    had — but its dominant features (iat_mad_ms 46%, iat_mean_ms 10%) are
    absolute-scale, so it produces ~0.000-0.001 on any beacon faster than
    CTU-13's own ~74-120s native cadence, regardless of how regular the
    timing is. See C3_XGB_HTTP_Deployment_Results.md and
    C3_ML_Abstain_Fix.md (which also documents, and then reverts, a same-day
    attempt to paper over that with a "return None" abstain instead of
    fixing the model itself).
  - XGBoost, CADENCE-INVARIANT, regularized + monotone-constrained (current)
    — 2026-08-28. Drops iat_mean_ms/iat_mad_ms (absolute-scale) entirely;
    keeps only iat_cv (scale-invariant regularity) plus payload/URL/POST/
    burst features. Trained with max_depth=3, min_child_weight=10 (a single
    outlier row cannot define a leaf) and monotone_constraints on iat_cv and
    request_burst_count (probability may only DECREASE as either rises —
    encodes this project's own measured/documented direction for both,
    rather than letting a 110-row dataset spuriously reverse it). Produces
    real, cross-validated signal on beacons at ANY cadence, including fast
    ones the previous model always scored ~0 on. Train with
    scripts/train_c3_xgb_regularized_cadence.py.

The RF->XGBoost swap was made together with lowering risk_fusion.py's BEACON
threshold 0.60 -> 0.52; XGBoost's advantage there is calibration — across
1,200 adversarial benign windows its highest fused score was 0.5139 versus
the RF's 0.5585. Measured out-of-fold at the time: 80.0% recall on beacons
with iat_cv < 0.05 at zero false positives.

WHY THE CADENCE-INVARIANT SWAP, AND ITS COST (measured, not hidden): the
absolute-timing HTTP model fixed the earlier NetFlow payload-scale bug but
left every fast beacon scoring ~0 -- confirmed live via C3's own Detection
Lab test (5s beacon, scored 0.0012), which looks like the ML layer is not
working when demonstrated. Root cause: with only 110 real positives
clustered at 74-120s, the model leaned on absolute interval magnitude
instead of genuine relative regularity (iat_cv sat at 2.75% feature
importance). The cadence-invariant retrain forces reliance on iat_cv
instead, at a measured cost: honest LOSO precision on real C2 fell from
0.383 to ~0.07-0.24 depending on tuning (recall rose to ~0.30), and a
1,200-window hard-negative sweep found roughly 1-4 false BEACONs per 1,800
draws (~0.1-0.2%) versus 0 for the absolute-timing model, concentrated on
`push_keepalive`/`extension_filter_list_update`-shaped traffic that this
project's own docs already flag as structurally indistinguishable from a
beacon by timing+context alone without a reputation signal. Kept anyway,
deliberately, because this system is being demonstrated as a research
prototype where showing the ML layer visibly contribute is the priority,
and the false-positive cost is disclosed rather than hidden. See
C3_ML_Live_Score_Fix.md for the full comparison and the honest tradeoff
table -- reconsider this choice before any real (non-demo) deployment.

ADDENDUM 2026-08-28 (v2, same day): `request_burst_count` REMOVED. It
carried 70% of v1's feature importance yet acted as a near-binary cliff
(score 0.62 -> 0.02 going from burst=0 to burst=1, confirmed by direct
sensitivity sweep) because almost no real positive training window has a
nonzero value for it -- too little contrasting data to learn anything
graduated. This caused a real live symptom: ML scored 14% on an actual
beacon test while heuristic scored 76%. Dropping the feature forces the
model to genuinely combine the rest (iat_cv rose 9%->41% importance; score
now responds smoothly to it instead of ignoring it below a cliff). A second,
independent bug was fixed alongside this: core/main.py's Detection Lab test
beacon was cache-busting its own URL with `?ts=`, making every check-in look
like a different endpoint -- unrealistic (real C2 polls one fixed URI) and
actively defeating the url_path_entropy feature and the heuristic's Rule 5.
See C3_ML_Feature_Correlation_Fix.md.
"""
from __future__ import annotations

import pickle
from pathlib import Path
from typing import Optional

import numpy as np

from .feature_engine import FEATURE_ORDER


# The 6 features this CADENCE-INVARIANT, BURST-FREE model reads. Deliberately
# EXCLUDES iat_mean_ms/iat_mad_ms (absolute-scale timing -- see the module
# docstring: only 110 real positives meant the model latched onto absolute
# interval magnitude, scoring ~0 on fast beacons) AND request_burst_count
# (v2 addendum: carried 70% of importance yet acted as a near-binary cliff,
# not a graduated signal -- too little real data with nonzero burst counts).
# Keep in sync with FEATURES in scripts/train_c3_xgb_regularized_cadence.py.
# The 3 excluded network features plus the 7 other live features
# (requests_per_hour + the 6 browser-context/deterministic ones) are unused
# by the ML model on purpose -- all still have a home in the heuristic rules
# in analyzer.py (iat_mean_ms/iat_mad_ms/request_burst_count feed the
# heuristic's own checks via feature_engine.py; same_site_ratio,
# script_initiator_ratio, and the 4 browser-context features drive Rules
# 2-9; requests_per_hour drives Rule 8) so nothing goes unused system-wide.
RF_FEATURE_SUBSET = [
    "iat_cv", "iat_bowley_skewness",
    "payload_size_mean", "payload_size_std",
    "url_path_entropy", "http_post_ratio",
]


class C3RFClassifierEngine:
    """
    Supervised XGBoost classifier — C3's sole ML signal.
    Returns predict_proba(bot_class) as the score (0–1).

    (Class name kept as C3RFClassifierEngine to avoid churning every import
    and the `rf_model_loaded` API key the dashboard reads; the estimator it
    holds is an XGBClassifier. reload() logs the real class name.)

    Trained on CTU-13's Zeek http.log captures, labeled for real C2-channel
    HTTP traffic specifically (label_c2 — see build_ctu13_http_dataset.py),
    not CTU-13's original IP-based "Botnet" label (confirmed to be a
    flood/scan detector, not a C2 detector). This IS C2-specific, but
    trained on only 110 usable real positive windows after filtering for
    reliable timing stats — too little real data to trust unconfirmed,
    which is why risk_fusion.py never lets this score alone confirm a
    BEACON verdict without heuristic corroboration (see the safety guard in
    C3RiskFusion.fuse()). CADENCE-INVARIANT variant (drops absolute-scale
    timing, monotone-constrained) chosen specifically so this score is
    real and non-zero on beacons of any speed, including fast ones — at a
    disclosed false-positive cost on hard negatives, see the module
    docstring and C3_ML_Live_Score_Fix.md.

    Train with: scripts/train_c3_xgb_regularized_cadence.py
    """

    def __init__(self) -> None:
        self._model = None
        self._feature_names: list[str] = RF_FEATURE_SUBSET
        self._threshold: float = 0.5
        # XGBoost replaced the RandomForest here on 2026-08-27, then
        # NetFlow-scale -> HTTP-scale (absolute timing) -> HTTP-scale
        # (cadence-invariant, current) on 2026-08-28 (see this file's module
        # docstring for why each swap happened). Rollback paths:
        #   -> RandomForest: point this path at
        #      models/archive/c3_rf_classifier_PRE_XGB_20260827.pkl AND
        #      restore BEACON_THRESHOLD=0.60 in risk_fusion.py (required
        #      together — see C3_FullPipeline_XGB_Results.md).
        #   -> NetFlow-scale XGBoost: point this path at
        #      models/archive/c3_xgb_classifier_NETFLOW_PRE_HTTP_20260828.pkl.
        #   -> HTTP-scale, absolute-timing (best precision, silent on fast
        #      beacons): point this path at
        #      models/archive/c3_xgb_classifier_HTTP_ABSTIMING_20260828.pkl.
        #   -> HTTP-scale, cadence-invariant but still burst-count-gated
        #      (v1 of the current approach; cliff-prone, see the module
        #      docstring's v2 addendum): point this path at
        #      models/archive/c3_xgb_classifier_BURSTGATED_20260828.pkl.
        #   BEACON_THRESHOLD stays at 0.52 in every case (re-validated per
        #      swap — see C3_XGB_HTTP_Deployment_Results.md,
        #      C3_ML_Live_Score_Fix.md, and C3_ML_Feature_Correlation_Fix.md).
        self._model_path = (
            Path(__file__).resolve().parents[2] / "models" / "c3_xgb_classifier.pkl"
        )
        self.reload()

    def reload(self) -> bool:
        """
        Load models/c3_xgb_classifier.pkl, validating it before accepting it —
        an incompatible or malformed model must fail safe (fall back to
        heuristic-only scoring, which the rest of C3 already handles
        gracefully) rather than be silently loaded and produce wrong or
        crashing predictions later. Validates:
          - payload is the {model, feature_names, threshold} dict format
            every current training script (train_c3_xgb_production.py etc.)
            produces. A bare model-only pickle has no feature_names to
            score against and is rejected rather than guessed at.
          - the model actually implements predict_proba.
          - every name in feature_names exists in the live feature schema
            (feature_engine.FEATURE_ORDER) — catches a model saved against
            renamed/removed/typo'd features before it ever reaches score().
        """
        self._model = None
        try:
            with open(self._model_path, "rb") as f:
                payload = pickle.load(f)

            if not isinstance(payload, dict):
                raise ValueError(
                    "model file is not the {model, feature_names, threshold} "
                    "payload format this system requires -- refusing to guess"
                )

            model = payload.get("model")
            feature_names = payload.get("feature_names")
            threshold = payload.get("threshold", 0.5)

            if model is None or not hasattr(model, "predict_proba"):
                raise ValueError("payload does not contain a valid classifier")
            if not feature_names or not isinstance(feature_names, list):
                raise ValueError("payload missing a valid feature_names list")
            unknown = [name for name in feature_names if name not in FEATURE_ORDER]
            if unknown:
                raise ValueError(
                    f"feature_names contains names not in the live feature "
                    f"schema (feature_engine.FEATURE_ORDER): {unknown}"
                )

            self._model = model
            self._feature_names = feature_names
            self._threshold = float(threshold)
            trained_on = payload.get("trained_on", "unknown")
            # Report the actual estimator class — this slot held a RandomForest
            # until 2026-08-27 and now holds an XGBClassifier, so a hardcoded
            # "RF" label here would misreport which model is live.
            print(
                f"[C3] ML classifier loaded ({type(model).__name__}): "
                f"{len(feature_names)} features ({', '.join(feature_names)}), "
                f"model_threshold={self._threshold:.2f}, trained_on={trained_on!r}"
            )
            return True
        except FileNotFoundError:
            print("[C3] No ML classifier model — run scripts/train_c3_xgb_regularized_cadence.py to train")
        except Exception as exc:
            print(f"[C3] Could not load RF Classifier model, falling back to "
                  f"heuristic-only scoring: {exc}")
        return False

    @property
    def model_loaded(self) -> bool:
        return self._model is not None

    def score(self, features: dict) -> tuple[Optional[float], str]:
        if not self._model:
            return None, "ML classifier model not loaded"
        try:
            values = [float(features.get(name, 0.0)) for name in self._feature_names]
            X = np.array([values], dtype=float)
            # predict_proba returns [P(human), P(bot)]; we want P(bot).
            prob = float(self._model.predict_proba(X)[0][1])
            verdict = "bot" if prob >= self._threshold else "human"
            return prob, (
                f"XGB prob={prob:.4f} threshold={self._threshold:.2f} [{verdict}]"
            )
        except Exception as exc:
            return None, f"ML classifier score failed: {exc}"


c3_rf_engine = C3RFClassifierEngine()


# =============================================================================
# WHAT THIS FILE DOES — plain English summary
# =============================================================================
#
# This file loads the one machine-learning model C3 uses to score suspicious
# traffic patterns: a supervised XGBoost classifier trained on real CTU-13
# HTTP captures (Zeek http.log), relabeled for genuine C2-channel traffic
# specifically. It uses 6 cadence-invariant features (regularity ratio +
# byte-size + burst stats + URL/method patterns — deliberately NOT absolute
# timing, so it produces a real, non-zero score at any beacon speed) and
# outputs a probability from 0 to 1: "how likely is this a C2 beacon?"
#
# risk_fusion.py blends this score with the heuristic score (and reputation,
# when available) to produce the final verdict. Because this classifier was
# trained on only 110 real positive examples, its score alone is never
# allowed to confirm a BEACON verdict — risk_fusion.py requires heuristic
# corroboration before crossing the BEACON threshold on this signal.
#
# If no trained model file is found on disk, the engine gracefully falls back
# to heuristic-only mode — the detector still works, just without the ML boost.
# =============================================================================
