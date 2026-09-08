"""
C3 risk fusion.

Combines the two detection signals — the ML (XGBoost) classifier score and the
heuristic rule score — into one final risk number (0–1) and a verdict:
SAFE, SUSPICIOUS, or BEACON.

Design rules (fixed, by explicit decision — not learned from data; there is no
labelled fusion-outcome dataset in this project to calibrate against):

  1. The score is ALWAYS   0.55 * ML  +  0.45 * heuristic.
     Nothing else moves it — no overrides, no reputation term.

     CHANGED 2026-09-03, 0.45/0.55 -> 0.55/0.45, on measurement rather than
     preference. scripts/tune_c3_fusion_weights.py swept the ML weight from
     0.45 to 0.70 over 55,844 real in-scope windows, taking ML scores from the
     deployed engine, heuristic scores from the deployed rules, and calling
     this very function with only the weights patched. Balanced BEACON metrics
     under the background/idle context condition:

         ML weight   accuracy  precision  recall     F1
            0.45       0.9361    0.9892   0.8818   0.9324
            0.50       0.9509    0.9825   0.9182   0.9493
            0.55       0.9742    0.9672   0.9818   0.9745   <- peak
            0.60       0.9706    0.9446   1.0000   0.9715
            0.70       0.9658    0.9360   1.0000   0.9669

     0.55 is the maximum; past it precision falls faster than recall rises.
     The cost is small and disclosed: SUSPICIOUS-or-above F1 drifts 0.9451 ->
     0.9384 across the same change. Rolling back means restoring 0.45/0.55
     here AND pointing anomaly_engine.py at the pre-calibration model — the
     two were changed together.

  2. BOTH signals must be involved before a BEACON is confirmed. A single
     signal on its own is not enough: if the blended score reaches the BEACON
     threshold but either the ML score or the heuristic score is essentially
     absent (< BOTH_SIGNAL_FLOOR), the score is held just below the threshold
     until the missing signal shows up. This is symmetric — it guards against
     "ML alone" and against "heuristic alone" equally.

     MEASURED CONSEQUENCE, 2026-09-03: this guard, not the weight split, is
     what makes BEACON unreachable when no browser context is available. A
     capture carries no context, so the heuristic sits at 0.0 and the guard
     caps every score at UNCONFIRMED_CAP -- context-blind BEACON recall is
     0.0000 at EVERY ML weight from 0.45 to 0.70, not just at 0.45. Bypassing
     the guard for high-confidence ML was measured and NOT adopted: at
     ML >= 0.95 it would catch 78.8% of real C2 context-blind but raise a
     0.441% false-beacon rate on 55,514 real benign windows, against the zero
     false beacons the current design produces. That trade is a product
     decision, not a tuning one. SUSPICIOUS-or-above is unaffected and does
     fire correctly context-blind (F1 0.9666).

  3. Threat-intelligence reputation is NOT an input to the score. It is looked
     up once a BEACON is confirmed (reputation_engine.py) and shown to the
     analyst as supporting evidence only. fuse() still accepts a `reputation`
     argument for call-site compatibility, but ignores it for scoring.

  4. When there is no ML score at all yet (model not loaded, or the timing
     window is too small for the model — see analyzer.py), fusion falls back
     to heuristic-only. The analyzer's own 10-request confirmation bar and
     timing-maturity ramp gate that path.
"""
from __future__ import annotations


# Verdict thresholds. These are named constants rather than inline literals
# because the both-signal guard below MUST stay strictly under BEACON_THRESHOLD
# to do its job — when the threshold was lowered 0.60 -> 0.52 the old hardcoded
# cap of 0.59 silently stopped blocking anything, since 0.59 >= 0.52. Deriving
# the cap from the threshold makes that class of bug impossible.
BEACON_THRESHOLD = 0.52
SUSPICIOUS_THRESHOLD = 0.30
# Score assigned just below BEACON when one of the two signals is missing.
UNCONFIRMED_CAP = round(BEACON_THRESHOLD - 0.01, 4)

# A signal contributing less than this is treated as "not really present", so
# the other signal cannot single-handedly carry the score to BEACON. 0.10 is
# carried over from the previous ML-only guard (which capped when the heuristic
# was < 0.10); it is now applied symmetrically to the ML side as well.
BOTH_SIGNAL_FLOOR = 0.10

# Fusion weights. Both signals always contribute. The split is no longer a
# bare design choice: 0.55/0.45 is the measured optimum of a 0.45-0.70 sweep
# over 55,844 real windows (see rule 1 in the module docstring for the table
# and scripts/tune_c3_fusion_weights.py to reproduce it).
ML_WEIGHT = 0.55
HEURISTIC_WEIGHT = 0.45

# Plain-language summary of each weight combination, keyed by which signals were
# available. End users see this text directly in the dashboard, so it stays in
# display terms ("ML"/"Heuristic" + rounded percentages).
_WEIGHT_SUMMARY_LABELS = {
    ("ml", "heuristic"): "ML 55% + Heuristic 45% weighting",
    ("heuristic",): "Heuristic rules only (no ML signal yet)",
}

# Plain-language translation for each internal guard tag appended to detail.
_OVERRIDE_LABELS = {
    "ml-only cap: awaiting heuristic confirmation":
        "held just below confirmed — the ML score alone is not enough without a heuristic rule also firing",
    "heuristic-only cap: awaiting ml confirmation":
        "held just below confirmed — the heuristic score alone is not enough without ML agreement",
}


def _weights_key(weights: dict) -> tuple:
    """Order-independent lookup key for _WEIGHT_SUMMARY_LABELS."""
    order = ("ml", "heuristic")
    return tuple(k for k in order if k in weights)


class C3RiskFusion:
    def fuse(
        self,
        ml: float | None,
        reputation: float | None,
        heuristic: float | None,
    ) -> dict:
        heuristic_value = float(heuristic or 0.0)
        has_ml = ml is not None
        # `reputation` is intentionally unused: threat-intel reputation is
        # analyst-facing evidence on a confirmed beacon, never a score input
        # (see module docstring rule 3). The parameter is kept so existing
        # call sites in analyzer.py do not have to change.
        _ = reputation

        if has_ml:
            weights = {"ml": ML_WEIGHT, "heuristic": HEURISTIC_WEIGHT}
            score = float(ml) * ML_WEIGHT + heuristic_value * HEURISTIC_WEIGHT
        else:
            weights = {"heuristic": 1.0}
            score = heuristic_value

        overrides: list[str] = []

        # Both-signal requirement. Only applies when an ML score exists at all
        # (has_ml). If the blended score reaches BEACON but one side is
        # essentially absent, hold it just below the threshold and name the
        # missing signal, so the verdict never rests on a single value.
        if has_ml and score >= BEACON_THRESHOLD:
            if float(ml) < BOTH_SIGNAL_FLOOR:
                score = min(score, UNCONFIRMED_CAP)
                overrides.append("heuristic-only cap: awaiting ml confirmation")
            elif heuristic_value < BOTH_SIGNAL_FLOOR:
                score = min(score, UNCONFIRMED_CAP)
                overrides.append("ml-only cap: awaiting heuristic confirmation")

        score = max(0.0, min(1.0, float(score)))
        # BEACON threshold lowered 0.60 -> 0.52 on 2026-08-27, together with the
        # RF -> XGBoost swap in anomaly_engine.py. Measured out-of-fold against
        # real CTU-13 + IoT-23 C2 windows and 1,200 adversarial benign windows
        # (SPA background sync, third-party analytics, video streaming,
        # extension filter updates, push keepalives):
        #     XGBoost @ 0.52 -> 80.0% recall on metronomic C2, 0 false positives
        #     XGBoost @ 0.60 -> 25.0% recall,                   0 false positives
        #     RF      @ 0.52 -> 60.0% recall,                   3 false positives
        # 0.52 sits just above the highest fused score any benign window
        # produced under XGBoost (0.5139); under RF that ceiling was 0.5585, so
        # this threshold is ONLY safe with an XGBoost model. Reverting to RF
        # requires restoring 0.60 here. See C3_FullPipeline_XGB_Results.md.
        #
        # RE-VALIDATED 2026-08-28 after anomaly_engine.py's model swap from the
        # NetFlow-scale XGBoost to the HTTP-scale retrain: max fused score under
        # the new model was 0.5138 on the same 1,200-draw hard-negative sweep --
        # 0.52 is still safely above it. See C3_XGB_HTTP_Deployment_Results.md.
        verdict = ("BEACON" if score >= BEACON_THRESHOLD
                   else "SUSPICIOUS" if score >= SUSPICIOUS_THRESHOLD else "SAFE")
        # Plain-language explanation for end users (shown directly in the
        # dashboard's Alerts/Host Analysis reasoning text) — internal weight-
        # table keys ("ml") are translated to their display names ("ML") here
        # so the UI never has to know about the underlying key names.
        detail = _WEIGHT_SUMMARY_LABELS.get(_weights_key(weights), "Heuristic rules only")
        if overrides:
            detail += "; " + "; ".join(_OVERRIDE_LABELS.get(o, o) for o in overrides)

        return {
            "score": round(score, 4),
            "verdict": verdict,
            "detail": detail,
            "weights": weights,
        }


c3_risk_fusion = C3RiskFusion()

# =============================================================================
# WHAT THIS FILE DOES — plain English summary
# =============================================================================
#
# This module merges the two detection signals — the ML classifier score and
# the heuristic rule score — into one final risk number and a verdict:
# SAFE, SUSPICIOUS, or BEACON.
#
# The score is always  0.55 * ML  +  0.45 * heuristic. Nothing else changes it.
#
# A confirmed BEACON needs BOTH signals: if the blended score reaches the
# threshold but one signal is essentially absent, the score is held just below
# the threshold until the other signal appears. When there is no ML score yet
# (model not loaded, or too small a timing window), fusion falls back to
# heuristic-only and the analyzer's own request-count bar gates it.
#
# Threat-intelligence reputation is looked up separately once a BEACON is
# confirmed and shown to the analyst as evidence — it is not part of this
# score.
#
# The result includes the final score (0–1), the text verdict, a short
# explanation, and the numeric weights used so the decision is auditable.
# =============================================================================
