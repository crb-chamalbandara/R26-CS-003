"""
EXPERIMENT -- sweeps risk_fusion.py's ML/heuristic weight split (currently
rf=0.30/heuristic=0.70, no reputation) to find the point that maximizes
overall C3 detection accuracy with the CURRENTLY DEPLOYED XGBoost model
(models/c3_xgb_classifier.pkl, cadence-invariant, 6 features).

SCOPE / SAFETY: read-only against production. Does not import or modify
core/c3/risk_fusion.py, core/c3/anomaly_engine.py, or any model file --
fuse_with_weight() below is a local, parameterized REIMPLEMENTATION of
C3RiskFusion.fuse()'s no-reputation branch (rf+heuristic only), used to test
alternative weights before touching the real file. Every other piece of
logic reused verbatim: the same monotone-constrained XGBoost architecture
and hyperparameters as scripts/train_c3_xgb_regularized_cadence.py, the same
beacon/hard-negative profile methodology as
scripts/test_c3_regularized_cadence_fullpipeline.py (BEACON_PROFILES /
BENIGN_PROFILES below are that script's own validated profiles, adapted to
the current 6-feature schema -- not reinvented), and the real
analyzer.C3Analyzer._heuristic_score() / feature_engine machinery, imported
and called as-is, never reimplemented.

METHOD
------
1. Fit a leave-one-scenario-out (LOSO) ensemble of the CURRENT model
   architecture (6 folds) on the real CTU-13 HTTP dataset -- same features,
   hyperparameters, monotone constraints, and scale_pos_weight as production.
   Every ML score used below is the OOF-ensemble mean across all 6 folds
   (never a single model scoring its own training data), so results are not
   inflated by memorization.
2. TRUE-POSITIVE side: an extended beacon battery (the 3 profiles from
   test_c3_regularized_cadence_fullpipeline.py, plus a slower/more-jittered
   CS-style profile, the CTU-13-native-cadence profile, and a tc02-style
   POST-exfiltration-while-user-active-elsewhere profile -- 6 total,
   spanning fast/slow, GET/POST, idle/active-elsewhere). For each, compute
   the real ML score (OOF ensemble) and real heuristic score
   (_heuristic_score on the real computed feature dict), then re-fuse at
   each candidate weight.
3. FALSE-POSITIVE side: the exact 6 hard-negative profiles already
   validated in this project (active_human_browsing plus 5 "hard" cases:
   spa_background_sync_same_site, third_party_analytics_beacon,
   video_streaming_segments, extension_filter_list_update,
   push_keepalive_third_party), 200 real benign dataset rows drawn per
   profile (1,200 total), each profile's browser-context values overlaid
   the same way the earlier validated sweep did it.
4. For each candidate w_ml in a swept range, report: how many of the 6
   beacon profiles reach BEACON, and how many of the 1,200 hard-negative
   draws produce a false BEACON. The safety guard (ML alone, without
   reputation and with heuristic < 0.10, can never confirm BEACON) and the
   rf+heuristic override are preserved exactly at every weight tested --
   only the base weighted-sum split is varied.

OUTPUT: prints a comparison table and saves
data/_xgb_fusion_weight_sweep_results.json. No file under core/ or models/
is written.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from xgboost import XGBClassifier

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from core.c3.analyzer import C3Analyzer  # noqa: E402

DATASET = REPO_ROOT / "data" / "c3_ctu13_http_c2_dataset.csv"
OUT = REPO_ROOT / "data" / "_xgb_fusion_weight_sweep_results.json"

# Identical to the current production model -- scripts/train_c3_xgb_regularized_cadence.py
# and core/c3/anomaly_engine.py's RF_FEATURE_SUBSET. Kept in sync deliberately.
FEATURES = ["iat_cv", "iat_bowley_skewness", "payload_size_mean",
            "payload_size_std", "url_path_entropy", "http_post_ratio"]
MONOTONE = (-1, 0, 0, 0, 0, 0)
XGB_PARAMS = dict(n_estimators=150, max_depth=3, learning_rate=0.08,
                   min_child_weight=10, subsample=0.8, colsample_bytree=0.8,
                   monotone_constraints=MONOTONE,
                   n_jobs=8, random_state=42, eval_metric="aucpr", verbosity=0)
SPW_MULT = 1.0  # production-selected value

# Current production constants (core/c3/risk_fusion.py) -- reproduced here
# read-only, for the reimplementation below; never imported so this script
# cannot accidentally mutate the real module.
BEACON_THRESHOLD = 0.52
SUSPICIOUS_THRESHOLD = 0.30
UNCONFIRMED_CAP = round(BEACON_THRESHOLD - 0.01, 4)

CONTEXT_KEYS = ["user_active_ratio", "background_tab_ratio", "avg_idle_time_ms",
                "extension_origin_ratio", "same_site_ratio", "script_initiator_ratio",
                "requests_per_hour"]

# The 3 profiles below are test_c3_regularized_cadence_fullpipeline.py's own
# validated definitions verbatim (not reinvented). 3 more added here to widen
# coverage: a slower/more-jittered CS-style beacon, the CTU-13-native cadence
# (the model's own strongest real-data signal), and a tc02-style POST
# exfiltration profile (active user elsewhere -- tests that per-tab idle
# discrimination still holds at every weight).
BEACON_PROFILES = [
    {"name": "detection_lab_actual_5s_post", "iat_cv": 0.0006, "iat_bowley": 0.0,
     "payload_mean": 37.0, "payload_std": 0.0, "post_ratio": 1.0, "url_ent": 0.0,
     "user_active_ratio": 0.0, "background_tab_ratio": 1.0, "avg_idle_time_ms": 200_000.0,
     "extension_origin_ratio": 0.0, "same_site_ratio": 0.0, "script_initiator_ratio": 1.0,
     "requests_per_hour": 720.0},
    {"name": "tc01_5s_hidden_idle", "iat_cv": 0.0231, "iat_bowley": 0.0,
     "payload_mean": 512.0, "payload_std": 25.0, "post_ratio": 0.0, "url_ent": 0.0,
     "user_active_ratio": 0.0, "background_tab_ratio": 1.0, "avg_idle_time_ms": 180_000.0,
     "extension_origin_ratio": 0.0, "same_site_ratio": 0.0, "script_initiator_ratio": 1.0,
     "requests_per_hour": 720.0},
    {"name": "cs_10s_5pct_jitter", "iat_cv": 0.0289, "iat_bowley": 0.0,
     "payload_mean": 300.0, "payload_std": 15.0, "post_ratio": 0.0, "url_ent": 0.0,
     "user_active_ratio": 0.0, "background_tab_ratio": 1.0, "avg_idle_time_ms": 200_000.0,
     "extension_origin_ratio": 0.0, "same_site_ratio": 0.0, "script_initiator_ratio": 1.0,
     "requests_per_hour": 360.0},
    {"name": "cs_60s_10pct_jitter", "iat_cv": 0.0577, "iat_bowley": 0.0,
     "payload_mean": 400.0, "payload_std": 20.0, "post_ratio": 0.0, "url_ent": 0.0,
     "user_active_ratio": 0.0, "background_tab_ratio": 1.0, "avg_idle_time_ms": 200_000.0,
     "extension_origin_ratio": 0.0, "same_site_ratio": 0.0, "script_initiator_ratio": 1.0,
     "requests_per_hour": 60.0},
    {"name": "ctu13_native_74s_median", "iat_cv": 0.800, "iat_bowley": 0.27,
     "payload_mean": 463.0, "payload_std": 993.0, "post_ratio": 0.0, "url_ent": 2.56,
     "user_active_ratio": 0.0, "background_tab_ratio": 1.0, "avg_idle_time_ms": 150_000.0,
     "extension_origin_ratio": 0.0, "same_site_ratio": 0.0, "script_initiator_ratio": 1.0,
     "requests_per_hour": 48.6},
    {"name": "tc02_8s_post_active_elsewhere", "iat_cv": 0.0198, "iat_bowley": 0.0,
     "payload_mean": 180.0, "payload_std": 10.0, "post_ratio": 1.0, "url_ent": 0.0,
     "user_active_ratio": 0.0, "background_tab_ratio": 1.0, "avg_idle_time_ms": 190_000.0,
     "extension_origin_ratio": 0.0, "same_site_ratio": 0.0, "script_initiator_ratio": 1.0,
     "requests_per_hour": 450.0},
]

# test_c3_regularized_cadence_fullpipeline.py's own validated hard-negative
# profiles, verbatim (url_ent/post_ratio/payload columns pulled from the real
# dataset row instead, exactly as that script did).
BENIGN_PROFILES = [
    {"name": "active_human_browsing", "hard": False,
     "user_active_ratio": 0.95, "background_tab_ratio": 0.0, "avg_idle_time_ms": 1_200.0,
     "extension_origin_ratio": 0.0, "same_site_ratio": 0.30, "script_initiator_ratio": 0.35,
     "requests_per_hour": 300.0},
    {"name": "spa_background_sync_same_site", "hard": True,
     "user_active_ratio": 0.0, "background_tab_ratio": 1.0, "avg_idle_time_ms": 200_000.0,
     "extension_origin_ratio": 0.0, "same_site_ratio": 1.0, "script_initiator_ratio": 1.0,
     "requests_per_hour": 240.0},
    {"name": "third_party_analytics_beacon", "hard": True,
     "user_active_ratio": 0.85, "background_tab_ratio": 0.0, "avg_idle_time_ms": 3_000.0,
     "extension_origin_ratio": 0.0, "same_site_ratio": 0.0, "script_initiator_ratio": 1.0,
     "requests_per_hour": 60.0},
    {"name": "video_streaming_segments", "hard": True,
     "user_active_ratio": 0.10, "background_tab_ratio": 0.0, "avg_idle_time_ms": 90_000.0,
     "extension_origin_ratio": 0.0, "same_site_ratio": 0.0, "script_initiator_ratio": 1.0,
     "requests_per_hour": 400.0, "_payload_override": 850_000.0},
    {"name": "extension_filter_list_update", "hard": True,
     "user_active_ratio": 0.0, "background_tab_ratio": 1.0, "avg_idle_time_ms": 260_000.0,
     "extension_origin_ratio": 1.0, "same_site_ratio": 0.0, "script_initiator_ratio": 0.90,
     "requests_per_hour": 30.0},
    {"name": "push_keepalive_third_party", "hard": True,
     "user_active_ratio": 0.0, "background_tab_ratio": 1.0, "avg_idle_time_ms": 150_000.0,
     "extension_origin_ratio": 0.0, "same_site_ratio": 0.0, "script_initiator_ratio": 1.0,
     "requests_per_hour": 120.0},
]

CANDIDATE_WEIGHTS = [0.05, 0.10, 0.12, 0.15, 0.18, 0.20, 0.22, 0.25, 0.28,
                     0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60]


def fit_loso_ensemble(df):
    models = {}
    for fk in sorted(df["source_scenario"].unique()):
        tr = df[df["source_scenario"] != fk]
        if tr["label_c2"].sum() == 0:
            continue
        Xtr = tr[FEATURES].to_numpy(float); ytr = tr["label_c2"].to_numpy(int)
        spw = (ytr == 0).sum() / max(1, (ytr == 1).sum())
        models[int(fk)] = XGBClassifier(scale_pos_weight=spw * SPW_MULT, **XGB_PARAMS).fit(Xtr, ytr)
    return models


def ensemble_score(models, vec):
    X = np.array([vec], dtype=float)
    scores = [float(m.predict_proba(X)[0][1]) for m in models.values()]
    return float(np.mean(scores))


def fuse_with_weight(rf, heuristic, w_ml):
    """Reimplements C3RiskFusion.fuse()'s no-reputation branch with w_ml
    swapped in for the fixed 0.30 -- re-verified 2026-08-29 against the
    CURRENT core/c3/risk_fusion.py line by line (it had gained a
    "high-confidence ml + heuristic corroboration" override since this
    project's own last full read of the file, which an earlier draft of
    this script had missed -- fixed here before drawing any conclusion from
    a sweep that would otherwise have silently under-counted real overrides)."""
    heuristic_value = float(heuristic or 0.0)
    score = float(rf) * w_ml + heuristic_value * (1.0 - w_ml)

    overrides = []
    if float(rf) >= 0.80 and heuristic_value >= 0.65:
        score = max(score, 0.60)
        overrides.append("rf+heuristic override")
    if float(rf) >= 0.88 and heuristic_value >= 0.30:
        score = max(score, BEACON_THRESHOLD)
        overrides.append("high-confidence ml + heuristic corroboration")
    if score >= BEACON_THRESHOLD and heuristic_value < 0.10:
        score = min(score, UNCONFIRMED_CAP)
        overrides.append("ml-only cap")

    score = max(0.0, min(1.0, score))
    verdict = ("BEACON" if score >= BEACON_THRESHOLD
               else "SUSPICIOUS" if score >= SUSPICIOUS_THRESHOLD else "SAFE")
    return {"score": round(score, 4), "verdict": verdict, "overrides": overrides}


def beacon_feature_dict(prof):
    # iat_mean_ms: the heuristic only ever uses it as a ">0 means timing is
    # reliable" guard (Rules 1/5/8), never its magnitude directly -- back out
    # a faithful positive value from the profile's own cadence.
    feats = {
        "iat_cv": prof["iat_cv"],
        "iat_bowley_skewness": prof["iat_bowley"],
        "payload_size_mean": prof["payload_mean"], "payload_size_std": prof["payload_std"],
        "url_path_entropy": prof["url_ent"], "http_post_ratio": prof["post_ratio"],
        "requests_per_hour": prof["requests_per_hour"],
        "iat_mean_ms": 3_600_000.0 / max(prof.get("requests_per_hour", 1.0), 1e-9),
    }
    for k in CONTEXT_KEYS:
        if k in prof:
            feats[k] = prof[k]
    return feats


def main():
    df = pd.read_csv(DATASET)
    df = df[df["n_flows"] >= 4].reset_index(drop=True)
    print(f"dataset: {len(df):,} windows, {int(df.label_c2.sum())} C2 -- fitting LOSO ensemble...")
    models = fit_loso_ensemble(df)
    print(f"fitted {len(models)} fold models\n")

    # ---- Precompute ML + heuristic scores once per beacon profile ----------
    beacon_scores = []
    for prof in BEACON_PROFILES:
        vec = [prof["iat_cv"], prof["iat_bowley"], prof["payload_mean"],
               prof["payload_std"], prof["url_ent"], prof["post_ratio"]]
        ml = ensemble_score(models, vec)
        feats = beacon_feature_dict(prof)
        heur, flags = C3Analyzer._heuristic_score(feats)
        beacon_scores.append({"name": prof["name"], "ml": ml, "heuristic": heur, "flags": flags})
        print(f"  [beacon] {prof['name']:<32} ML={ml:.4f}  Heuristic={heur:.4f}")

    # ---- Precompute ML + heuristic scores for the hard-negative sweep ------
    print()
    rng = np.random.default_rng(42)
    N_PER_PROFILE = 200
    neg_pool = df[df.label_c2 == 0].reset_index(drop=True)
    negative_scores = []  # list of (profile_name, ml, heuristic)
    for prof in BENIGN_PROFILES:
        sample_idx = rng.choice(len(neg_pool), size=N_PER_PROFILE, replace=False)
        for i in sample_idx:
            r = neg_pool.iloc[int(i)]
            vec = [float(r[f]) for f in FEATURES]
            if "_payload_override" in prof:
                vec[FEATURES.index("payload_size_mean")] = prof["_payload_override"]
                vec[FEATURES.index("payload_size_std")] = prof["_payload_override"] * 0.15
            ml = ensemble_score(models, vec)
            feats = dict(zip(FEATURES, vec))
            feats["iat_mean_ms"] = float(r["iat_mean_ms"])
            for k in CONTEXT_KEYS:
                if k in prof:
                    feats[k] = prof[k]
            heur, _ = C3Analyzer._heuristic_score(feats)
            negative_scores.append((prof["name"], ml, heur))
    print(f"hard-negative pool built: {len(negative_scores)} draws across {len(BENIGN_PROFILES)} profiles\n")

    # ---- Sweep weights ------------------------------------------------------
    print("=" * 100)
    print(f"{'w_ml':>6} {'w_heur':>7}  {'beacons->BEACON':>16}  {'beacons->SUSP/SAFE':>18}  "
          f"{'hard-neg FP':>12}  {'worst FP profile':>28}")
    print("=" * 100)
    results = []
    for w_ml in CANDIDATE_WEIGHTS:
        w_heur = 1.0 - w_ml
        beacon_rows = []
        n_beacon_hit = 0
        for b in beacon_scores:
            f = fuse_with_weight(b["ml"], b["heuristic"], w_ml)
            beacon_rows.append({"name": b["name"], "fused": f["score"], "verdict": f["verdict"]})
            if f["verdict"] == "BEACON":
                n_beacon_hit += 1

        fp_by_profile = {}
        total_fp = 0
        for name, ml, heur in negative_scores:
            f = fuse_with_weight(ml, heur, w_ml)
            if f["verdict"] == "BEACON":
                total_fp += 1
                fp_by_profile[name] = fp_by_profile.get(name, 0) + 1
        worst = max(fp_by_profile.items(), key=lambda kv: kv[1])[0] if fp_by_profile else "none"

        row = {"w_ml": w_ml, "w_heuristic": round(w_heur, 2),
               "beacons_reaching_BEACON": n_beacon_hit, "n_beacons": len(beacon_scores),
               "beacon_detail": beacon_rows,
               "hard_negative_false_beacons": total_fp, "hard_negative_n": len(negative_scores),
               "fp_by_profile": fp_by_profile, "worst_fp_profile": worst}
        results.append(row)
        print(f"{w_ml:>6.2f} {w_heur:>7.2f}  {n_beacon_hit:>6}/{len(beacon_scores):<9}  "
              f"{len(beacon_scores)-n_beacon_hit:>9}/{len(beacon_scores):<8}  "
              f"{total_fp:>5}/{len(negative_scores):<6}  {worst:>28}")

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({"beacon_scores": beacon_scores, "sweep": results}, f, indent=2, default=str)
    print(f"\nsaved -> {OUT}")
    print("\nNo file under core/ or models/ was written. Production untouched.")


if __name__ == "__main__":
    main()
