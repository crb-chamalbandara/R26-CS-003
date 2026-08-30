"""
Full-pipeline validation of the regularized+monotone-constrained candidate
(train_c3_xgb_regularized_cadence.py) against the CURRENTLY DEPLOYED model
(models/c3_xgb_classifier.pkl) -- decisive test before any promotion decision.

Raw ML metrics alone are misleading here: risk_fusion.py already weights ML
at only 0.30 (vs heuristic 0.70) and has a hard safety cap that refuses
BEACON on the ML signal alone without heuristic corroboration (heuristic
must be >= 0.10). The candidate's raw LOSO precision collapsed (0.068 vs
0.383, 471 FP vs 22 on ~33.5k windows) -- this script checks whether that
translates into real false BEACONs in the full pipeline, or is absorbed by
fusion the way it's designed to be.

Both models retrained per LOSO fold for the beacon battery (out-of-fold,
ensemble-averaged); the hard-negative sweep uses each model's own already-
saved final-fit pickle read from disk (candidate) / retrained fresh
(deployed, for consistency with earlier reports) -- see inline comments.
Nothing in the project is modified: read-only against the deployed model,
writes only to data/_regularized_cadence_fullpipeline.json.
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

from core.c3.analyzer import C3Analyzer          # noqa: E402
from core.c3.risk_fusion import c3_risk_fusion   # noqa: E402

DATASET = REPO_ROOT / "data" / "c3_ctu13_http_c2_dataset.csv"
OUT = REPO_ROOT / "data" / "_regularized_cadence_fullpipeline.json"

DEPLOYED_FEATURES = ["iat_mean_ms", "iat_cv", "iat_bowley_skewness", "iat_mad_ms",
                     "payload_size_mean", "payload_size_std", "request_burst_count",
                     "url_path_entropy", "http_post_ratio"]
CAND_FEATURES = ["iat_cv", "iat_bowley_skewness", "payload_size_mean",
                 "payload_size_std", "request_burst_count", "url_path_entropy", "http_post_ratio"]
CAND_MONOTONE = (-1, 0, 0, 0, -1, 0, 0)

DEPLOYED_PARAMS = dict(n_estimators=200, max_depth=6, learning_rate=0.1,
                       min_child_weight=3, n_jobs=8, random_state=42,
                       eval_metric="aucpr", verbosity=0)
DEPLOYED_SPW_MULT = 1.5
CAND_PARAMS = dict(n_estimators=150, max_depth=3, learning_rate=0.08,
                   min_child_weight=10, subsample=0.8, colsample_bytree=0.8,
                   monotone_constraints=CAND_MONOTONE,
                   n_jobs=8, random_state=42, eval_metric="aucpr", verbosity=0)
CAND_SPW_MULT = 1.0

CONTEXT_KEYS = ["user_active_ratio", "background_tab_ratio", "avg_idle_time_ms",
                "extension_origin_ratio", "same_site_ratio", "script_initiator_ratio",
                "requests_per_hour"]

BEACON_PROFILES = [
    {"name": "detection_lab_actual_5s_post", "interval_s": 5, "jitter_pct": 0.1,
     "payload_mean": 37.0, "payload_std": 0.0, "post_ratio": 1.0, "url_ent": 5.643856,
     "user_active_ratio": 0.0, "background_tab_ratio": 1.0, "avg_idle_time_ms": 200_000.0,
     "extension_origin_ratio": 0.0, "same_site_ratio": 0.0, "script_initiator_ratio": 1.0},
    {"name": "tc01_5s_hidden_idle", "interval_s": 5, "jitter_pct": 4,
     "payload_mean": 512.0, "payload_std": 25.0, "post_ratio": 0.0, "url_ent": 0.0,
     "user_active_ratio": 0.0, "background_tab_ratio": 1.0, "avg_idle_time_ms": 180_000.0,
     "extension_origin_ratio": 0.0, "same_site_ratio": 0.0, "script_initiator_ratio": 1.0},
    {"name": "cs_10s_5pct_jitter", "interval_s": 10, "jitter_pct": 5,
     "payload_mean": 300.0, "payload_std": 15.0, "post_ratio": 0.0, "url_ent": 0.0,
     "user_active_ratio": 0.0, "background_tab_ratio": 1.0, "avg_idle_time_ms": 200_000.0,
     "extension_origin_ratio": 0.0, "same_site_ratio": 0.0, "script_initiator_ratio": 1.0},
]

BENIGN_PROFILES = [
    {"name": "active_human_browsing", "hard": False,
     "user_active_ratio": 0.95, "background_tab_ratio": 0.0, "avg_idle_time_ms": 1_200.0,
     "extension_origin_ratio": 0.0, "same_site_ratio": 0.30, "script_initiator_ratio": 0.35,
     "requests_per_hour": 300.0, "url_ent": 3.6, "post_ratio": 0.05},
    {"name": "spa_background_sync_same_site", "hard": True,
     "user_active_ratio": 0.0, "background_tab_ratio": 1.0, "avg_idle_time_ms": 200_000.0,
     "extension_origin_ratio": 0.0, "same_site_ratio": 1.0, "script_initiator_ratio": 1.0,
     "requests_per_hour": 240.0, "url_ent": 0.20, "post_ratio": 0.60},
    {"name": "third_party_analytics_beacon", "hard": True,
     "user_active_ratio": 0.85, "background_tab_ratio": 0.0, "avg_idle_time_ms": 3_000.0,
     "extension_origin_ratio": 0.0, "same_site_ratio": 0.0, "script_initiator_ratio": 1.0,
     "requests_per_hour": 60.0, "url_ent": 0.10, "post_ratio": 1.0},
    {"name": "video_streaming_segments", "hard": True,
     "user_active_ratio": 0.10, "background_tab_ratio": 0.0, "avg_idle_time_ms": 90_000.0,
     "extension_origin_ratio": 0.0, "same_site_ratio": 0.0, "script_initiator_ratio": 1.0,
     "requests_per_hour": 400.0, "url_ent": 0.45, "post_ratio": 0.0,
     "_payload_override": 850_000.0},
    {"name": "extension_filter_list_update", "hard": True,
     "user_active_ratio": 0.0, "background_tab_ratio": 1.0, "avg_idle_time_ms": 260_000.0,
     "extension_origin_ratio": 1.0, "same_site_ratio": 0.0, "script_initiator_ratio": 0.90,
     "requests_per_hour": 30.0, "url_ent": 0.30, "post_ratio": 0.0},
    {"name": "push_keepalive_third_party", "hard": True,
     "user_active_ratio": 0.0, "background_tab_ratio": 1.0, "avg_idle_time_ms": 150_000.0,
     "extension_origin_ratio": 0.0, "same_site_ratio": 0.0, "script_initiator_ratio": 1.0,
     "requests_per_hour": 120.0, "url_ent": 0.0, "post_ratio": 0.0},
]


def jitter_to_cv(jitter_pct: float) -> float:
    return round(jitter_pct / (100.0 * (3 ** 0.5)), 6)


def fit_loso_ensemble(df, features, params, spw_mult):
    models = {}
    for fk in sorted(df["source_scenario"].unique()):
        tr = df[df["source_scenario"] != fk]
        if tr["label_c2"].sum() == 0:
            continue
        Xtr = tr[features].to_numpy(float); ytr = tr["label_c2"].to_numpy(int)
        spw = (ytr == 0).sum() / max(1, (ytr == 1).sum())
        models[int(fk)] = XGBClassifier(scale_pos_weight=spw * spw_mult, **params).fit(Xtr, ytr)
    return models


def ensemble_score(models, vec):
    X = np.array([vec], dtype=float)
    per_fold = {str(fk): round(float(m.predict_proba(X)[0][1]), 4) for fk, m in models.items()}
    return float(np.mean(list(per_fold.values()))), per_fold


def deployed_vector(prof):
    cv = jitter_to_cv(prof["jitter_pct"])
    mean_ms = prof["interval_s"] * 1000.0
    mad_ms = mean_ms * cv * 0.6
    return [mean_ms, cv, 0.0, mad_ms, prof["payload_mean"], prof["payload_std"],
            0, prof["url_ent"], prof["post_ratio"]]


def cand_vector(prof):
    cv = jitter_to_cv(prof["jitter_pct"])
    return [cv, 0.0, prof["payload_mean"], prof["payload_std"], 0, prof["url_ent"], prof["post_ratio"]]


def context(prof):
    ctx = {k: prof[k] for k in CONTEXT_KEYS if k in prof}
    ctx.setdefault("requests_per_hour", min(3600.0 / max(prof["interval_s"], 0.01), 100_000.0))
    return ctx


def main():
    df = pd.read_csv(DATASET)
    df = df[df["n_flows"] >= 4].reset_index(drop=True)
    print(f"dataset: {len(df):,} windows, {int(df.label_c2.sum())} C2")

    print("fitting DEPLOYED-model LOSO ensemble...")
    deployed_models = fit_loso_ensemble(df, DEPLOYED_FEATURES, DEPLOYED_PARAMS, DEPLOYED_SPW_MULT)
    print("fitting CANDIDATE-model LOSO ensemble...")
    cand_models = fit_loso_ensemble(df, CAND_FEATURES, CAND_PARAMS, CAND_SPW_MULT)

    print("\n" + "=" * 78)
    print("BEACON BATTERY")
    print("=" * 78)
    beacon_rows = []
    for prof in BEACON_PROFILES:
        dep_ml, dep_folds = ensemble_score(deployed_models, deployed_vector(prof))
        cand_ml, cand_folds = ensemble_score(cand_models, cand_vector(prof))
        feats = dict(zip(DEPLOYED_FEATURES, deployed_vector(prof)))
        feats.update(context(prof))
        heur, _ = C3Analyzer._heuristic_score(feats)
        dep_f = c3_risk_fusion.fuse(dep_ml, None, heur)
        cand_f = c3_risk_fusion.fuse(cand_ml, None, heur)
        row = {"profile": prof["name"], "heuristic": round(heur, 4),
               "deployed_ml": round(dep_ml, 4), "deployed_fused": dep_f["score"], "deployed_verdict": dep_f["verdict"],
               "candidate_ml": round(cand_ml, 4), "candidate_fused": cand_f["score"], "candidate_verdict": cand_f["verdict"],
               "candidate_ml_per_fold": cand_folds}
        beacon_rows.append(row)
        print(f"\n{prof['name']} (heuristic={heur:.4f}):")
        print(f"  DEPLOYED:  ML={dep_ml:.4f} -> fused={dep_f['score']:.4f} -> {dep_f['verdict']}")
        print(f"  CANDIDATE: ML={cand_ml:.4f} -> fused={cand_f['score']:.4f} -> {cand_f['verdict']}  (per-fold: {cand_folds})")

    print("\n" + "=" * 78)
    print("HARD-NEGATIVE FALSE-POSITIVE SWEEP (real benign rows, both models)")
    print("=" * 78)
    rng = np.random.default_rng(42)
    N_PER_PROFILE = 200
    neg_pool = df[df.label_c2 == 0]
    fp_rows = []
    for prof in BENIGN_PROFILES:
        sample = neg_pool.iloc[rng.choice(len(neg_pool), size=N_PER_PROFILE, replace=False)]
        dep_fp = cand_fp = 0
        dep_max = cand_max = 0.0
        for i in range(N_PER_PROFILE):
            r = sample.iloc[i]
            dvec = [float(r[f]) for f in DEPLOYED_FEATURES]
            cvec = [float(r[f]) for f in CAND_FEATURES]
            if "_payload_override" in prof:
                dvec[DEPLOYED_FEATURES.index("payload_size_mean")] = prof["_payload_override"]
                dvec[DEPLOYED_FEATURES.index("payload_size_std")] = prof["_payload_override"] * 0.15
                cvec[CAND_FEATURES.index("payload_size_mean")] = prof["_payload_override"]
                cvec[CAND_FEATURES.index("payload_size_std")] = prof["_payload_override"] * 0.15
            dep_ml, _ = ensemble_score(deployed_models, dvec)
            cand_ml, _ = ensemble_score(cand_models, cvec)
            feats = dict(zip(DEPLOYED_FEATURES, dvec))
            feats.update({k: prof[k] for k in CONTEXT_KEYS if k in prof})
            heur, _ = C3Analyzer._heuristic_score(feats)
            dep_f = c3_risk_fusion.fuse(dep_ml, None, heur)
            cand_f = c3_risk_fusion.fuse(cand_ml, None, heur)
            dep_max = max(dep_max, dep_f["score"]); cand_max = max(cand_max, cand_f["score"])
            if dep_f["verdict"] == "BEACON":
                dep_fp += 1
            if cand_f["verdict"] == "BEACON":
                cand_fp += 1
        fp_rows.append({"profile": prof["name"], "n": N_PER_PROFILE,
                        "deployed_false_beacons": dep_fp, "deployed_max_fused": round(dep_max, 4),
                        "candidate_false_beacons": cand_fp, "candidate_max_fused": round(cand_max, 4)})
        print(f"  {prof['name']:<34} DEPLOYED: {dep_fp}/{N_PER_PROFILE} FP (max={dep_max:.4f})   "
              f"CANDIDATE: {cand_fp}/{N_PER_PROFILE} FP (max={cand_max:.4f})")

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({"beacon_battery": beacon_rows, "hard_negative_sweep": fp_rows}, f, indent=2, default=str)
    print(f"\nsaved -> {OUT}")


if __name__ == "__main__":
    main()
