"""
C3 anomaly engine.

Loads the supervised XGBoost C2-beacon classifier and exposes its score (0-1).

Several entries below cite C3_*.md write-ups that were working notes and are
no longer in the repository (they were gitignored and never committed); the
measurements they recorded are summarised inline here. Current, present-in-
repo write-ups are C3_18Feature_Model_Results.md and
C3_Scoped_Model_Results.md.

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
  - XGBoost, CADENCE-INVARIANT, regularized + monotone-constrained, 6-feature
    — 2026-08-28. Drops iat_mean_ms/iat_mad_ms (absolute-scale) entirely;
    keeps only iat_cv (scale-invariant regularity) plus payload/URL/POST/
    burst features. Trained with max_depth=3, min_child_weight=10 (a single
    outlier row cannot define a leaf) and monotone_constraints on iat_cv and
    request_burst_count (probability may only DECREASE as either rises —
    encodes this project's own measured/documented direction for both,
    rather than letting a 110-row dataset spuriously reverse it). Produces
    real, cross-validated signal on beacons at ANY cadence, including fast
    ones the previous model always scored ~0 on. Its training script,
    scripts/train_c3_xgb_regularized_cadence.py, has since been removed.
  - XGBoost, 18-feature, scale-free — 2026-09-02, at
    models/c3_xgb_classifier_18feat_20260902.pkl. Uncalibrated. See
    C3_18Feature_Model_Results.md, and Publish_ML_improve.txt for the
    correction to its headline accuracy claim.
  - XGBoost, 18-feature, ISOTONIC-CALIBRATED, scoped to active periodic C2
    (CURRENT) — 2026-09-03, models/c3_xgb_scoped_calibrated_20260903.pkl.
    Two dataset defects were fixed first: (1) pseudo-replication — 95% of C2
    windows came from ONE (src,dst) pair, so window-level metrics were
    dominated by a single session; (2) an out-of-scope positive — a dead-C&C
    403 retry storm whose timing is indistinguishable from browsing
    (iat_cv 1.61 vs 0.005 for every other family) was teaching the model a
    concept contradicting periodic beaconing. Scope criterion is
    error_status_ratio < 1.0 (the channel completed at least one exchange),
    chosen so it is not circular with the timing features used to detect.
    Measured, balanced held-out: unseen malware family 83.8% accuracy /
    82.9% F1 / ROC-AUC 0.927; unseen C&C source 96.2% / 96.6% / 0.991.
    Deployed together with risk_fusion.py's move to ML 0.55 / Heuristic 0.45
    — roll both back together. See C3_Scoped_Model_Results.md.

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


# The 18 features the CURRENT model reads, by name. All are SCALE-FREE
# (ratios, shares, normalised entropies) and every one is produced by
# feature_engine.compute_features() from data core/c3/interceptor.py already
# records. Train/serve agreement is asserted on real capture rows by
# test/C3/test_c3_feature_parity.py.
#
# The other 11 of feature_engine.FEATURE_ORDER's 29 are unused by the ML model
# on purpose, and none of them goes unused system-wide -- they drive the
# heuristic rules in analyzer.py instead (iat_mean_ms and request_burst_count
# feed the heuristic's own checks; same_site_ratio, script_initiator_ratio and
# the 4 browser-context features drive Rules 2-9; requests_per_hour drives
# Rule 8).
#
# HISTORY -- the 6-feature CADENCE-INVARIANT, BURST-FREE set that ran until
# 2026-09-02 was: iat_cv, iat_bowley_skewness, payload_size_mean,
# payload_size_std, url_path_entropy, http_post_ratio. It deliberately
# excluded iat_mean_ms/iat_mad_ms (absolute-scale timing: only 110 real
# positives meant the model latched onto absolute interval magnitude, scoring
# ~0 on fast beacons) and request_burst_count (carried 70% of importance yet
# acted as a near-binary cliff). Kept here for rollback context only -- to
# actually roll back, see the rollback paths in __init__ below.
#
# Why it was replaced, measured on 68,464 non-overlapping real windows across
# 6 malware families (scripts/train_c3_18feat.py, C3_18Feature_Model_Results.md):
#
#                                       6 features      18 features
#   unseen-family ROC-AUC (LOFO mean)      0.5605          0.8213
#   unseen-family recall @1% FPR           0.1243          0.2908
#   balanced accuracy, held-out captures   0.9020          0.9390
#   hardest case (unseen capture + host)   0.7703          0.8176
#   false positives on held-out browsing   0.89 / 0.44 / 0.13 %   0.0 / 0.06 / 0.0 %
#
# The new features are all SCALE-FREE (ratios, shares, normalised entropies).
# That is the point: the 6-feature model leaned on absolute byte counts and
# absolute intervals, which do not mean the same thing in a 2011 capture and a
# 2026 browser, and it scored a mean of 0.028 on real C2 windows as a result.
# The 18-feature model scores 0.987 on the same windows while scoring LOWER on
# real human browsing than its predecessor did.
ML_FEATURE_SUBSET = [
    # timing shape (8) -- how regular the request cadence is, measured in ways
    # that survive jitter and one long pause
    "iat_cv", "iat_bowley_skewness", "iat_norm_mad", "iat_burstiness",
    "iat_autocorr_lag1", "iat_spread_ratio", "iat_clock_share", "iat_entropy_norm",
    # size (4) -- check-ins are small and repeat the same size; exfiltration
    # inverts the usual upload/download direction
    "payload_size_mean", "payload_cv", "payload_repeat_ratio", "upload_download_ratio",
    # url and method shape (5) -- a beacon calls one endpoint over and over
    "url_path_entropy", "unique_path_ratio", "http_post_ratio",
    "uri_len_norm", "uri_char_entropy_norm",
    # request behaviour (1) -- timer-driven requests carry no Referer
    "referrer_absent_ratio",
]


class C3XGBoostEngine:
    """
    Supervised XGBoost classifier — C3's sole ML signal.
    Returns predict_proba(bot_class) as the score (0–1).

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

    Train with: scripts/train_c3_scoped_model.py
    """

    def __init__(self) -> None:
        self._model = None
        self._feature_names: list[str] = ML_FEATURE_SUBSET
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
        #   -> 6-feature cadence-invariant (what ran until 2026-09-02): point
        #      this path at models/c3_xgb_classifier.pkl AND restore the
        #      6-name ML_FEATURE_SUBSET above. A copy of that model and of the
        #      C3 code that went with it is kept in
        #      core/c3/backup_ml_20260902/ with md5sums.
        #   BEACON_THRESHOLD stays at 0.52 in every case (re-validated per
        #      swap — see C3_XGB_HTTP_Deployment_Results.md,
        #      C3_ML_Live_Score_Fix.md, C3_ML_Feature_Correlation_Fix.md and,
        #      for this swap, C3_18Feature_Model_Results.md).
        #   -> 18-feature UNCALIBRATED (what ran 2026-09-02 to 2026-09-03):
        #      point this path at models/c3_xgb_classifier_18feat_20260902.pkl
        #      AND restore ML_WEIGHT/HEURISTIC_WEIGHT in risk_fusion.py to
        #      0.45/0.55. The two were changed together and must be rolled back
        #      together -- see C3_Scoped_Model_Results.md.
        #
        #   C3-v2 independently added a fallback here to an archived
        #   cadence-invariant model (c3_xgb_classifier_BURSTGATED_20260828.pkl)
        #   for a fresh clone with no models/*.pkl (gitignored). Not carried
        #   forward on this merge: that archived model is the one this file's
        #   own history measured as a near-binary cliff (score 0.62 -> 0.02
        #   crossing burst=0/1, and 14% ML vs 76% heuristic on a real beacon --
        #   see the ADDENDUM above) -- silently running it would be a worse
        #   outcome than the explicit fallback reload() already has below:
        #   fail loudly ("No ML classifier model — run
        #   scripts/train_c3_scoped_model.py to train") and drop to
        #   heuristic-only, rather than silently serving a known-flawed score.
        self._model_path = (
            Path(__file__).resolve().parents[2] / "models"
            / "c3_xgb_scoped_calibrated_20260903.pkl"
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
            # A calibrated model (CalibratedClassifierCV) does not expose
            # feature_importances_ -- the attribute lives on the base
            # estimators it wraps. The training script averages them into the
            # payload so the dashboard's Detection Lab keeps showing real,
            # trained importances instead of silently going blank.
            self._payload_importances = payload.get("feature_importances") or {}
            # Deliberately a short, single-line confirmation, matching the
            # one-line startup style every other component already uses
            # ([L1]/[L2]/[L3], [C2-verified], [C2-fusion]). This used to dump
            # all 18 feature names, the estimator class and the full
            # trained_on provenance string on every launch, which is a wall
            # of text in the console for information that is not lost by
            # dropping it here: the feature names, threshold, trained_on
            # string and trained importances all remain inside the model
            # payload itself (models/*.pkl, read by scripts/build_*_notebook.py)
            # and are mirrored in data/_c3_scoped_model_results.json, while
            # the live feature list and importances are already served to the
            # dashboard by C3Analyzer.status() / feature_importance().
            # A failed load still prints its own explicit message below.
            print(
                f"[C3] ML classifier loaded: {len(feature_names)} features, "
                f"threshold {self._threshold:.2f}"
            )
            return True
        except FileNotFoundError:
            print("[C3] No ML classifier model — run "
                  "scripts/train_c3_scoped_model.py to train")
        except Exception as exc:
            print(f"[C3] Could not load ML classifier model, falling back to "
                  f"heuristic-only scoring: {exc}")
        return False

    @property
    def model_loaded(self) -> bool:
        return self._model is not None

    def feature_importance(self) -> dict[str, float]:
        """
        Real, trained feature_importances_ from the loaded model -- not a
        guess, not hand-ranked. Used by the dashboard's Detection Lab report
        to show what the ML side actually weighs most, so that claim is
        always traceable back to the live model rather than asserted.
        Returns {} if no model is loaded or the estimator doesn't expose
        importances (e.g. a non-tree model swapped in later).
        """
        if not self._model:
            return {}
        if not hasattr(self._model, "feature_importances_"):
            # Calibrated wrapper: importances were averaged across its base
            # estimators at training time and stored in the payload.
            return dict(getattr(self, "_payload_importances", {}) or {})
        try:
            values = [float(v) for v in self._model.feature_importances_]
        except Exception:
            return dict(getattr(self, "_payload_importances", {}) or {})
        return dict(zip(self._feature_names, values))

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


c3_ml_engine = C3XGBoostEngine()


# =============================================================================
# WHAT THIS FILE DOES — plain English summary
# =============================================================================
#
# This file loads the one machine-learning model C3 uses to score suspicious
# traffic patterns: a supervised XGBoost classifier, isotonic-calibrated,
# trained on real HTTP captures relabeled for genuine C2-channel traffic and
# scoped to ACTIVE, PERIODIC C2 channels. It reads 18 scale-free features
# (timing regularity, payload shape, URL shape, and whether a Referer is
# present — deliberately NOT absolute timing or absolute byte counts, so it
# produces a real, non-zero score at any beacon speed) and outputs a
# probability from 0 to 1: "how likely is this a C2 beacon?"
#
# risk_fusion.py blends this score with the heuristic score ONLY to produce
# the final verdict — reputation is never a scoring input (see
# risk_fusion.py's docstring). Its score alone is still never allowed to
# confirm a BEACON verdict: risk_fusion.py's both-signal guard requires
# heuristic corroboration before crossing the BEACON threshold. That guard,
# not the weight split, is why a network-only capture cannot reach BEACON —
# measured 2026-09-03, see C3_Scoped_Model_Results.md.
#
# If no trained model file is found on disk, the engine gracefully falls back
# to heuristic-only mode — the detector still works, just without the ML boost.
# =============================================================================
