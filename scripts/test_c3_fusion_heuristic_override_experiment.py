"""
EXPERIMENT -- follow-up to test_c3_fusion_weight_sweep.py. That sweep found
w_ml=0.20 recall-optimal (4/6 beacon battery) and showed the user-requested
0.30-0.45 band regresses to 2/6 (loses tc01_5s_hidden_idle, cs_10s_5pct_jitter,
tc02_8s_post_active_elsewhere -- all cases where this model's ML score is
near-zero, ~0.01-0.19, even though the heuristic engine correctly flags them
with 3-5 independent rules firing).

This script asks: can w_ml stay in [0.30, 0.45] (as requested) WITHOUT losing
that recall, by adding one narrowly-targeted override -- "heuristic alone is
overwhelming (>= H_THRESH, multiple independent rules) -> floor at
BEACON_THRESHOLD regardless of rf" -- symmetric to the existing "ML alone is
overwhelming (rf>=0.88) + heuristic>=0.30 -> floor" override already in
risk_fusion.py. The critical question is whether H_THRESH can be set high
enough to rescue the 3 lost real beacons WITHOUT reintroducing false BEACONs
on the same 1,200-draw real hard-negative sweep used throughout this project.

SCOPE / SAFETY: read-only against production, same as test_c3_fusion_weight_sweep.py.
Imports its LOSO-fit + profile + scoring machinery verbatim (no reimplementation,
no new data). Writes only data/_xgb_fusion_heuristic_override_experiment_results.json.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import pandas as pd  # noqa: E402

from scripts.test_c3_fusion_weight_sweep import (  # noqa: E402
    BEACON_PROFILES, BENIGN_PROFILES, BEACON_THRESHOLD, CONTEXT_KEYS,
    DATASET, FEATURES, UNCONFIRMED_CAP, beacon_feature_dict,
    ensemble_score, fit_loso_ensemble,
)
from core.c3.analyzer import C3Analyzer  # noqa: E402

OUT = REPO_ROOT / "data" / "_xgb_fusion_heuristic_override_experiment_results.json"

W_ML_CANDIDATES = [0.30, 0.35, 0.40, 0.45]
# None = baseline (no new override, matches test_c3_fusion_weight_sweep.py exactly).
HEUR_OVERRIDE_CANDIDATES = [None, 0.55, 0.60, 0.65, 0.70, 0.75]


def fuse_with_weight_and_override(rf, heuristic, w_ml, heur_override):
    """Same as test_c3_fusion_weight_sweep.fuse_with_weight(), plus one
    candidate new override: heuristic alone >= heur_override -> floor at
    BEACON_THRESHOLD, regardless of rf. Every other rule identical and in
    the same order as the real core/c3/risk_fusion.py."""
    heuristic_value = float(heuristic or 0.0)
    score = float(rf) * w_ml + heuristic_value * (1.0 - w_ml)

    overrides = []
    if float(rf) >= 0.80 and heuristic_value >= 0.65:
        score = max(score, 0.60)
        overrides.append("rf+heuristic override")
    if float(rf) >= 0.88 and heuristic_value >= 0.30:
        score = max(score, BEACON_THRESHOLD)
        overrides.append("high-confidence ml + heuristic corroboration")
    if heur_override is not None and heuristic_value >= heur_override:
        score = max(score, BEACON_THRESHOLD)
        overrides.append("heuristic corroboration override")
    if score >= BEACON_THRESHOLD and heuristic_value < 0.10:
        score = min(score, UNCONFIRMED_CAP)
        overrides.append("ml-only cap")

    score = max(0.0, min(1.0, score))
    verdict = ("BEACON" if score >= BEACON_THRESHOLD
               else "SUSPICIOUS" if score >= 0.30 else "SAFE")
    return {"score": round(score, 4), "verdict": verdict, "overrides": overrides}


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
        beacon_scores.append({"name": prof["name"], "ml": ml, "heuristic": heur})
        print(f"  [beacon] {prof['name']:<32} ML={ml:.4f}  Heuristic={heur:.4f}")

    # ---- Precompute ML + heuristic scores for the hard-negative sweep ------
    print()
    rng = np.random.default_rng(42)  # same seed -> identical 1,200 draws as the earlier sweep
    N_PER_PROFILE = 200
    neg_pool = df[df.label_c2 == 0].reset_index(drop=True)
    negative_scores = []
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
    print(f"hard-negative pool built: {len(negative_scores)} draws across {len(BENIGN_PROFILES)} profiles")

    # Report the real heuristic-score distribution seen on hard negatives --
    # this is the number that determines whether any heur_override threshold
    # is actually safe, so print it explicitly rather than inferring it.
    heur_vals = np.array([h for _, _, h in negative_scores])
    print(f"hard-negative heuristic score distribution: "
          f"min={heur_vals.min():.3f} p50={np.median(heur_vals):.3f} "
          f"p95={np.percentile(heur_vals, 95):.3f} p99={np.percentile(heur_vals, 99):.3f} "
          f"max={heur_vals.max():.3f}\n")

    # ---- Sweep (w_ml x heur_override) ---------------------------------------
    print("=" * 110)
    print(f"{'w_ml':>6} {'heur_ovr':>9}  {'beacons->BEACON':>16}  {'hard-neg FP':>12}  "
          f"{'new FPs vs baseline':>20}  {'worst FP profile':>28}")
    print("=" * 110)

    # baseline FP set (heur_override=None) per w_ml, to measure exactly which
    # additional hard-negative draws a candidate override newly flips to BEACON.
    baseline_fp_idx = {}
    for w_ml in W_ML_CANDIDATES:
        s = set()
        for idx, (name, ml, heur) in enumerate(negative_scores):
            f = fuse_with_weight_and_override(ml, heur, w_ml, None)
            if f["verdict"] == "BEACON":
                s.add(idx)
        baseline_fp_idx[w_ml] = s

    results = []
    for w_ml in W_ML_CANDIDATES:
        for heur_ovr in HEUR_OVERRIDE_CANDIDATES:
            beacon_rows = []
            n_beacon_hit = 0
            for b in beacon_scores:
                f = fuse_with_weight_and_override(b["ml"], b["heuristic"], w_ml, heur_ovr)
                beacon_rows.append({"name": b["name"], "fused": f["score"], "verdict": f["verdict"]})
                if f["verdict"] == "BEACON":
                    n_beacon_hit += 1

            fp_by_profile = {}
            total_fp = 0
            fp_idx = set()
            for idx, (name, ml, heur) in enumerate(negative_scores):
                f = fuse_with_weight_and_override(ml, heur, w_ml, heur_ovr)
                if f["verdict"] == "BEACON":
                    total_fp += 1
                    fp_idx.add(idx)
                    fp_by_profile[name] = fp_by_profile.get(name, 0) + 1
            new_fps = fp_idx - baseline_fp_idx[w_ml]
            worst = max(fp_by_profile.items(), key=lambda kv: kv[1])[0] if fp_by_profile else "none"

            row = {"w_ml": w_ml, "heur_override": heur_ovr,
                   "beacons_reaching_BEACON": n_beacon_hit, "n_beacons": len(beacon_scores),
                   "beacon_detail": beacon_rows,
                   "hard_negative_false_beacons": total_fp, "hard_negative_n": len(negative_scores),
                   "new_fps_vs_baseline": len(new_fps), "fp_by_profile": fp_by_profile,
                   "worst_fp_profile": worst}
            results.append(row)
            ovr_label = "none" if heur_ovr is None else f"{heur_ovr:.2f}"
            print(f"{w_ml:>6.2f} {ovr_label:>9}  {n_beacon_hit:>6}/{len(beacon_scores):<9}  "
                  f"{total_fp:>5}/{len(negative_scores):<6}  {len(new_fps):>20}  {worst:>28}")

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({"beacon_scores": beacon_scores,
                    "hard_negative_heuristic_distribution": {
                        "min": float(heur_vals.min()), "p50": float(np.median(heur_vals)),
                        "p95": float(np.percentile(heur_vals, 95)),
                        "p99": float(np.percentile(heur_vals, 99)), "max": float(heur_vals.max())},
                    "sweep": results}, f, indent=2, default=str)
    print(f"\nsaved -> {OUT}")
    print("No file under core/ or models/ was written. Production untouched.")


if __name__ == "__main__":
    main()
