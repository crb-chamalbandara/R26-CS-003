"""
C3 risk fusion.

Combines the ML (XGBoost) classifier, reputation, and heuristic scores using
a fixed, hand-picked weight table (see fuse() below) that is selected based
on which signals are available for a given host. These weights are explicit
design parameters, not learned or statistically calibrated from data — there
is no labeled fusion-outcome dataset in this project to calibrate them against.
"""
from __future__ import annotations


# Verdict thresholds. These are named constants rather than inline literals
# because the "ml-only cap" guard below MUST stay strictly under BEACON_THRESHOLD
# to do its job — when the threshold was lowered 0.60 -> 0.52 the old hardcoded
# cap of 0.59 silently stopped blocking anything, since 0.59 >= 0.52. Deriving
# the cap from the threshold makes that class of bug impossible.
BEACON_THRESHOLD = 0.52
SUSPICIOUS_THRESHOLD = 0.30
# Score assigned just below BEACON when a signal is deliberately withheld.
UNCONFIRMED_CAP = round(BEACON_THRESHOLD - 0.01, 4)

# Plain-language summary of each fixed weight combination, keyed by which
# signals were available (see fuse() below for when each is selected).
# End users see this text directly in the dashboard, so it stays in display
# terms ("ML"/"Heuristic"/"Reputation" + rounded percentages) rather than the
# internal weight-dict keys or raw decimal weights.
_WEIGHT_SUMMARY_LABELS = {
    ("rf", "reputation", "heuristic"): "ML 29% + Reputation 35% + Heuristic 36% weighting",
    ("rf", "heuristic"): "ML 45% + Heuristic 55% weighting",
    ("reputation", "heuristic"): "Reputation 45% + Heuristic 55% weighting",
    ("heuristic",): "Heuristic rules only (no ML or reputation signal yet)",
}

# Plain-language translation for each internal override tag appended to detail.
_OVERRIDE_LABELS = {
    "reputation override": "raised to confirmed threshold on strong threat-intel match",
    "rf+heuristic override": "raised to confirmed threshold on strong ML + heuristic agreement",
    "high-confidence ml + heuristic corroboration": "confirmed on high-confidence ML corroborated by a heuristic rule",
    "heuristic corroboration override": "confirmed on strong multi-rule heuristic corroboration despite a low ML score",
    "ml-only cap: awaiting heuristic confirmation": "held just below confirmed — ML alone is not enough without heuristic or reputation support",
}


def _weights_key(weights: dict) -> tuple:
    """Order-independent lookup key for _WEIGHT_SUMMARY_LABELS."""
    order = ("rf", "reputation", "heuristic")
    return tuple(k for k in order if k in weights)


class C3RiskFusion:
    def fuse(
        self,
        rf: float | None,
        reputation: float | None,
        heuristic: float | None,
    ) -> dict:
        heuristic_value = float(heuristic or 0.0)
        has_rf         = rf is not None
        has_reputation = reputation is not None

        # ML (XGBoost) is trained on real CTU-13 HTTP C2-channel traffic
        # (label_c2), so it is C2-specific, but on very little of it -- only
        # 110 usable positive windows after filtering for reliable timing
        # stats, honest (LOSO) recall ~28% / precision ~6% (standalone, no
        # fusion -- see scripts/train_c3_xgb_regularized_cadence.py's own
        # saved results). That is too little real data for the model to
        # outweigh heuristic + reputation, which is why it still contributes
        # real, but secondary, supporting weight rather than dominant weight.
        #
        # RF:HEURISTIC RATIO RE-MEASURED 2026-08-29 (was 0.30:0.70, now
        # 0.20:0.80). This model is strong on some real beacon shapes (POST,
        # tiny fixed payload, or CTU-13's own ~74-120s native cadence -- ML
        # alone often >0.80-0.98 there) but weak on others (GET method,
        # moderate payload, realistic 5-10% timing jitter -- ML alone often
        # <0.02 there even though the heuristic correctly flags them), a
        # genuine, disclosed limitation of training on only 110 real
        # positives (see Future_Plans.txt Part 2, Finding #1). Because this
        # split is inconsistent by beacon SHAPE rather than uniformly weak,
        # simply raising the ML weight does not help across the board: it
        # was directly tested via scripts/test_c3_fusion_weight_sweep.py,
        # sweeping w_ml from 0.05 to 0.60 against a 6-profile real beacon
        # battery (fast/slow, GET/POST, idle/active-elsewhere, CTU-13-native
        # cadence -- OOF-ensemble ML scores, real heuristic scores) and the
        # existing 1,200-draw hard-negative sweep (6 profiles x 200 real
        # benign CTU-13 rows). Result: recall was FLAT at 4/6 beacon profiles
        # for every w_ml in [0.10, 0.20], with hard-negative false-BEACONs
        # also flat at 9/1200 (0.75%) across that same band; w_ml=0.30 (the
        # previous value) caught only 2/6 at 6/1200 (0.5%) FP -- i.e. raising
        # ML weight past ~0.20 actively LOSES real detections (profiles
        # where ML is near-zero get dragged down, not up) without lowering
        # FP enough to justify it. 0.20 -- the highest w_ml within the tied-
        # optimal band -- was chosen over 0.10-0.18 (which tie on both
        # measured metrics) specifically to keep the ML signal maximally
        # visible in the fused score, consistent with this project's
        # standing goal of showing the ML layer visibly contribute for
        # demonstration purposes (see C3_ML_Live_Score_Fix.md) -- not
        # arbitrary, since all tied candidates were otherwise equal on the
        # only two metrics that were actually measured.
        # Honest cost, not hidden: the false-BEACON rate on hard negatives
        # rose from 0.5% to 0.75% (6->9 of 1,200) as a direct result of this
        # change -- a real, small, disclosed trade for nearly doubling
        # measured recall (2/6 -> 4/6) on a more diverse beacon battery than
        # this fusion weight had previously been tested against.
        # The reputation-present triple keeps reputation's own weight
        # unchanged (0.35 -- untouched by this measurement) and rescales
        # rf:heuristic proportionally within the remaining 0.65 budget using
        # the same 0.45:0.55 ratio (0.65*0.45=0.2925, 0.65*0.55=0.3575,
        # rounded to 0.29/0.36 -- rounding error cancels exactly, still
        # sums to 1.00 with reputation's 0.35).
        #
        # RAISED AGAIN 2026-08-29 (same day, follow-up) at explicit user
        # request: wanted ML's nominal contribution at 30-45% specifically
        # (their own design preference, not a re-measurement), while keeping
        # overall accuracy at least as good as the 0.20 config above. A bare
        # base-weight bump into that band was tested first and confirmed the
        # same non-monotonic problem already on record: at w_ml=0.30-0.45
        # with no other change, recall on the 6-profile beacon battery fell
        # back to 2/6 (same as the original pre-tuning 0.30 baseline),
        # because the 3 lost profiles (tc01_5s_hidden_idle,
        # cs_10s_5pct_jitter, tc02_8s_post_active_elsewhere) all have
        # near-zero ML scores (0.01-0.19) that a higher ML weight drags the
        # fused score down with, even though heuristic alone (0.65-0.73,
        # 3-5 rules firing) correctly flags all three.
        #
        # Fix: rather than fight the weight split, added ONE new override
        # below ("heuristic corroboration override") symmetric to the
        # existing high-confidence-ML override -- that one confirms on
        # rf>=0.88 with heuristic support; this one confirms on overwhelming
        # heuristic (>=0.65, meaning 3+ independent rules fired) regardless
        # of rf. Swept w_ml x heuristic-override-threshold together via
        # scripts/test_c3_fusion_heuristic_override_experiment.py against
        # the same 6-profile beacon battery and 1,200-draw hard-negative
        # sweep. The override threshold could not go below 0.65: at 0.60 or
        # 0.55 it started firing on real benign push_keepalive_third_party
        # draws (whose heuristic score reaches up to 0.73 on hard
        # negatives -- see the hard-negative heuristic distribution saved in
        # data/_xgb_fusion_heuristic_override_experiment_results.json), 5-7
        # NEW false BEACONs beyond the w_ml-only baseline. At exactly 0.65
        # (tied with 0.60, so the higher/safer threshold was kept), zero new
        # false positives were introduced at any tested w_ml in [0.30, 0.45].
        # RESULT at the chosen w_ml=0.45 (the best-performing point in the
        # requested band, not merely its upper bound -- see below) + 0.65
        # override: 5/6 beacon recall and 7/1,200 (0.583%) hard-negative
        # false BEACONs -- BOTH metrics better than the prior 0.20/0.80
        # config's 4/6 recall and 9/1,200 (0.75%), not a recall-for-FP
        # trade. w_ml=0.45 specifically beat 0.30/0.35 (4/6 recall, 9/1,200
        # FP at the same 0.65 override) and 0.40 (4/6 recall, 7/1,200 FP) on
        # recall while tying them on FP or better -- i.e. it strictly
        # dominates every other point tested in [0.30, 0.45], so it was not
        # a tiebreak pick. Full sweep table in
        # data/_xgb_fusion_heuristic_override_experiment_results.json.
        if has_rf and has_reputation:
            weights = {"rf": 0.29, "reputation": 0.35, "heuristic": 0.36}
        elif has_rf and not has_reputation:
            weights = {"rf": 0.45, "heuristic": 0.55}
        elif has_reputation and not has_rf:
            weights = {"heuristic": 0.55, "reputation": 0.45}
        else:
            weights = {"heuristic": 1.0}

        score = 0.0
        if has_rf:
            score += float(rf) * weights.get("rf", 0.0)
        if has_reputation:
            score += float(reputation) * weights.get("reputation", 0.0)
        score += heuristic_value * weights.get("heuristic", 0.0)

        overrides = []
        if has_reputation and float(reputation) >= 0.8:
            score = max(score, 0.60)
            overrides.append("reputation override")
        if has_rf and float(rf) >= 0.80 and heuristic_value >= 0.65:
            score = max(score, 0.60)
            overrides.append("rf+heuristic override")

        # A strongly-confident ML score (>= 0.88) corroborated by at least one
        # FULL heuristic rule firing (>= 0.30 -- Rule 1 "regular timing + small
        # payload + user idle", or Rule 2 "foreground idle", or Rule 3-nonext
        # "background traffic") is sufficient to CONFIRM a beacon.
        #
        # Without this, the rf:0.30 / heuristic:0.70 weight split caps a
        # textbook metronomic beacon that fires ONLY Rule 1 (foreground tab,
        # idle user, small payload, varying URL -> heuristic exactly 0.30) at
        #     0.30 * rf  +  0.70 * 0.30   ==   ~0.51  even at rf = 1.0
        # -- one hundredth below BEACON_THRESHOLD, so it never confirms despite
        # unambiguous evidence. Measured on 5,779 real benign browser windows:
        # only 0.05% ever reach rf >= 0.88 AND regular-timing + small-payload at
        # once (and those are non-interactive 2011 lab-host captures), versus
        # ~99% of real metronomic Zeus C2 windows. Promotes only to
        # BEACON_THRESHOLD, not 0.60 ("just confirmed", not "high confidence"),
        # and stays subordinate to analyzer.py's early-window cap (needs >= 10
        # requests) and known-safe-host cap (needs >= 0.85 for analytics/CDN),
        # both applied after fuse() returns.
        if has_rf and float(rf) >= 0.88 and heuristic_value >= 0.30:
            score = max(score, BEACON_THRESHOLD)
            overrides.append("high-confidence ml + heuristic corroboration")

        # Symmetric counterpart to the override above: overwhelming heuristic
        # corroboration (>= 0.65, meaning multiple independent rules fired --
        # e.g. regular timing + background tab + same-endpoint + script-
        # initiated) is sufficient to CONFIRM a beacon even when the ML score
        # is low, since this XGBoost model is known-weak (near-zero) on real
        # GET/jittered/moderate-payload beacon shapes it has few training
        # examples of (see the weight-history comment above and
        # Future_Plans.txt Part 2, Finding #1). 0.65 is a measured floor, not
        # a round-number guess: on the real 1,200-draw hard-negative sweep,
        # the highest heuristic score any benign profile reached was 0.73
        # (push_keepalive_third_party), and thresholds below 0.65 (0.60,
        # 0.55) measurably let some of those same benign draws through as
        # new false BEACONs. Requires has_rf (an ML score exists at all) so
        # this stays scoped to the branches this was tested against; it does
        # not change the heuristic-only branch below, where heuristic already
        # gets full weight and this would be a no-op anyway.
        if has_rf and heuristic_value >= 0.65:
            score = max(score, BEACON_THRESHOLD)
            overrides.append("heuristic corroboration override")

        # Safety guard: do NOT reach BEACON on the ML signal alone (no reputation,
        # no heuristic corroboration). The model is C2-specific but trained on
        # only 110 real positive windows (see anomaly_engine.py) -- statistically
        # too thin to trust unconfirmed, so a high ML score by itself is still not
        # sufficient evidence and heuristic confirmation is still required.
        # Both the trigger and the cap are derived from BEACON_THRESHOLD so the
        # guard keeps working if that threshold is ever retuned again.
        if score >= BEACON_THRESHOLD and not has_reputation and heuristic_value < 0.10:
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
        # requires restoring 0.60 here. See C3_FullPipeline_XGB_Results.md,
        # including the caveat that 0.52 was selected against that same benign
        # sample and still needs validation on independent benign traffic.
        #
        # RE-VALIDATED 2026-08-28 after anomaly_engine.py's model swap from the
        # NetFlow-scale XGBoost above to the HTTP-scale retrain: re-ran the same
        # style of hard-negative sweep (1,200 real-network-row + adversarial
        # browser-context windows). Max fused score under the new model was
        # 0.5138 (vs 0.5139 under the old one) -- 0.52 is still safely above it,
        # so the threshold did not need to change. See
        # C3_XGB_HTTP_Deployment_Results.md.
        #
        # RE-VALIDATED AGAIN 2026-08-29 after the rf:heuristic weight change
        # above (0.30:0.70 -> 0.20:0.80): re-ran the same 1,200-draw
        # hard-negative sweep under the new weight. False-BEACON count rose
        # from 6/1,200 to 9/1,200 (still 0.75% -- small and disclosed, see
        # the weight-change comment above); 0.52 was not moved, since the
        # goal of this change was the rf:heuristic ratio specifically, not
        # the threshold, and the resulting FP rate is still low enough that
        # moving the threshold to compensate was not warranted. Revisit this
        # threshold specifically if a future change pushes the hard-negative
        # rate materially higher. See scripts/test_c3_fusion_weight_sweep.py
        # and data/_xgb_fusion_weight_sweep_results.json for the full sweep.
        #
        # RE-VALIDATED A THIRD TIME 2026-08-29 (same day) after raising
        # rf:heuristic again to 0.45:0.55 plus the new heuristic-corroboration
        # override (see the weight-history comment above): hard-negative
        # false-BEACON count actually FELL to 7/1,200 (0.583%) -- lower than
        # the immediately-prior 9/1,200, not higher -- so 0.52 needed no
        # change here either. See
        # scripts/test_c3_fusion_heuristic_override_experiment.py and
        # data/_xgb_fusion_heuristic_override_experiment_results.json.
        verdict = ("BEACON" if score >= BEACON_THRESHOLD
                   else "SUSPICIOUS" if score >= SUSPICIOUS_THRESHOLD else "SAFE")
        # Plain-language explanation for end users (shown directly in the
        # dashboard's Alerts/Host Analysis reasoning text) — internal weight-
        # table keys ("rf") are translated to their display names ("ML") here
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
# This module merges the different signals (ML classifier score, heuristic
# score, and reputation, when available) into one final risk number and a
# verdict: SAFE, SUSPICIOUS, or BEACON.
#
# It selects from a fixed, hand-picked weight table depending on which
# signals are available (not a learned/statistically-tuned weighting) and
# applies simple overrides so high-confidence threat intelligence or combined
# ML+heuristic evidence can elevate the score. It also contains a safety cap
# to prevent declaring BEACON on the ML signal alone, since that classifier
# is trained on only a small number of real C2 examples (110 usable windows)
# and is not reliable enough yet to trust unconfirmed.
#
# The fusion result includes the final score (0–1), the text verdict, a short
# explanation of the weights and any overrides, and the numeric weights used
# so the decision is auditable.
# =============================================================================
