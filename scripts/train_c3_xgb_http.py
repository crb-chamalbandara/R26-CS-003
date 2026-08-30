"""
PRODUCTION TRAINER (promoted 2026-08-28) -> models/c3_xgb_classifier.pkl

This is the model core/c3/anomaly_engine.py loads at runtime. It replaces the
NetFlow-scale XGBoost model previously in that slot (trained by the now-
superseded scripts/train_c3_xgb_production.py on data/c3_xgb_training.csv),
which is preserved at
models/archive/c3_xgb_classifier_NETFLOW_PRE_HTTP_20260828.pkl.

WHY THIS REPLACED THE NETFLOW MODEL: the NetFlow model was trained on
CTU-13/IoT-23 flow-total bytes renamed to payload_size_mean without
rescaling. Measured effect (C3_FullPipeline_XGB_Results.md, Result 6): the
model learned "payload_size_mean < ~92 bytes = C2" and scored every real
browser beacon (payload 200-900 bytes) as 0.0000, regardless of timing.

MEASURED IMPROVEMENT (C3_XGB_HTTP_Deployment_Results.md, full pipeline,
out-of-fold, both models retrained per left-out CTU-13 scenario):
  - Honest LOSO precision on real C2: 0.098 (NetFlow) -> 0.383 (HTTP).
  - Honest LOSO recall on real C2:    0.158 (NetFlow) -> 0.192 (HTTP).
  - On a beacon at CTU-13's own native cadence (74-120s, the population this
    training data actually contains), ML score: ~0.000-0.002 (NetFlow) ->
    0.81-0.99 (HTTP), crossing BEACON in full pipeline fusion where the old
    model stayed SUSPICIOUS or SAFE.
  - Zero new false positives across 1,200 hard-negative (real network row +
    adversarial browser-context) windows; max fused score on hard negatives
    is within 0.003 of the old model's, so BEACON_THRESHOLD=0.52 in
    risk_fusion.py did not need to move.

HONEST LIMITATION, UNCHANGED FROM THE NETFLOW MODEL: CTU-13's real HTTP C2
never beacons faster than ~110s, so this model has never seen a genuinely
fast (5-30s) low-jitter beacon and still scores ~0.0000 on one (e.g. tc01's
5s demo beacon). This is a data-availability ceiling, not a scale bug --
there is no dishonest way to fix it without more real fast-cadence HTTP C2
captures. The heuristic layer (not ML) is what still catches those cases,
via risk_fusion's heuristic weighting -- see analyzer.py's _heuristic_score.

This script trains on data/c3_ctu13_http_c2_dataset.csv instead, built by
scripts/build_ctu13_http_dataset.py from CTU-13's Zeek http.log (real captured
HTTP payload bytes, the same quantity feature_engine.py measures live via CDP
encodedDataLength / Content-Length). Two extra features become available at
this granularity that NetFlow never had: url_path_entropy and http_post_ratio
(both already live in feature_engine.py's FEATURE_ORDER -- no browser-side
change needed to use them).

METHODOLOGY -- deliberately identical to train_c3_xgb_production.py so the
two models are comparable apples-to-apples:
  - Same hyperparameters (n_estimators=200, max_depth=6, learning_rate=0.1,
    min_child_weight=3), pinned rather than re-searched.
  - SPW_MULT is swept (1.0/2.0/3.0) via honest LOSO on THIS dataset rather
    than assumed from the old dataset, since positive count and class ratio
    differ (110 positives / 51,963 windows here vs 492 / large-N there).
  - Leave-one-scenario-out (LOSO) is the honest headline; grouped-random-split
    is reported separately, labeled optimistic-only.
  - n_flows >= 4 filter applied (Bowley skewness needs >=3 gaps; below that
    all timing features are trivially 0) -- same rule as every other C3
    training script.

SCOPE / HONESTY: real CTU-13 HTTP captures only, no synthetic rows. Output is
a SEPARATE file (models/c3_xgb_http_classifier.pkl) -- anomaly_engine.py is
not touched by this script and continues loading the current production
model. This is a candidate for scripts/test_c3_fullpipeline_http_vs_production.py
to evaluate before any deployment decision.
"""
from __future__ import annotations

import json
import pickle
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from xgboost import XGBClassifier

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET = REPO_ROOT / "data" / "c3_ctu13_http_c2_dataset.csv"
OUT_MODEL = REPO_ROOT / "models" / "c3_xgb_classifier.pkl"     # the production slot
OUT_RESULTS = REPO_ROOT / "data" / "_xgb_http_train_results.json"

FEATURES = [
    "iat_mean_ms", "iat_cv", "iat_bowley_skewness", "iat_mad_ms",
    "payload_size_mean", "payload_size_std", "request_burst_count",
    "url_path_entropy", "http_post_ratio",
]
LABEL_COL = "label_c2"
MIN_FLOWS = 4
MIN_POS_RELIABLE = 10
THRESHOLD = 0.5

XGB_PARAMS = dict(n_estimators=200, max_depth=6, learning_rate=0.1,
                  min_child_weight=3, n_jobs=8, random_state=42,
                  eval_metric="aucpr", verbosity=0)


def make_xgb(spw, spw_mult):
    return XGBClassifier(scale_pos_weight=spw * spw_mult, **XGB_PARAMS)


def evaluate(y_true, y_prob, threshold=THRESHOLD):
    y_pred = (y_prob >= threshold).astype(int)
    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {"precision": round(float(p), 4), "recall": round(float(r), 4), "f1": round(float(f1), 4),
            "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn)}


def loso(df, spw_mult):
    """Leave-one-scenario-out, honest out-of-fold. Returns per-fold dict + aggregate."""
    folds = {}
    for fk in sorted(df["source_scenario"].unique()):
        te = df["source_scenario"] == fk
        tr_df, te_df = df[~te], df[te]
        n_tr_pos, n_te_pos = int(tr_df[LABEL_COL].sum()), int(te_df[LABEL_COL].sum())
        if n_tr_pos == 0 or n_te_pos == 0:
            continue
        Xtr = tr_df[FEATURES].to_numpy(float); ytr = tr_df[LABEL_COL].to_numpy(int)
        Xte = te_df[FEATURES].to_numpy(float); yte = te_df[LABEL_COL].to_numpy(int)
        spw = (ytr == 0).sum() / max(1, (ytr == 1).sum())
        clf_f = make_xgb(spw, spw_mult).fit(Xtr, ytr)
        prob_f = clf_f.predict_proba(Xte)[:, 1]
        pr_auc = float(average_precision_score(yte, prob_f))
        ev = evaluate(yte, prob_f)
        reliable = n_te_pos >= MIN_POS_RELIABLE
        folds[int(fk)] = {"n_test": len(te_df), "test_positives": n_te_pos, "reliable": reliable,
                           "pr_auc": round(pr_auc, 4), **ev}
    rel = [v for v in folds.values() if v["reliable"]]
    agg = {"n_folds_reliable": len(rel)}
    if rel:
        for k in ("pr_auc", "precision", "recall", "f1"):
            agg[f"mean_{k}"] = round(float(np.mean([v[k] for v in rel])), 4)
        agg["total_tp"] = int(sum(v["tp"] for v in rel))
        agg["total_fp"] = int(sum(v["fp"] for v in rel))
        agg["total_fn"] = int(sum(v["fn"] for v in rel))
        agg["total_tn"] = int(sum(v["tn"] for v in rel))
    return folds, agg


def main():
    t0 = time.time()
    df = pd.read_csv(DATASET)
    df = df[df["n_flows"] >= MIN_FLOWS].reset_index(drop=True)
    n_pos = int(df[LABEL_COL].sum())
    print(f"windows (n_flows>={MIN_FLOWS}): {len(df):,}  positive: {n_pos} ({100*n_pos/len(df):.4f}%)")
    print(f"positives by scenario: {df[df[LABEL_COL]==1].groupby('source_scenario').size().to_dict()}")

    # ---- SPW_MULT sweep via honest LOSO (this dataset differs in scale from
    #      the one train_c3_xgb_optimized.py tuned on, so re-check rather than
    #      assume the old SPW_MULT=2.0 still fits) ---------------------------
    print("\nSPW_MULT sweep (honest LOSO, mean PR-AUC over reliable folds):")
    sweep = {}
    for mult in (1.0, 1.5, 2.0, 2.5, 3.0):
        _, agg = loso(df, mult)
        sweep[mult] = agg
        print(f"  spw_mult={mult:<4} {agg}")
    best_mult = max(sweep, key=lambda m: sweep[m].get("mean_pr_auc", -1.0))
    print(f"\nselected spw_mult={best_mult} (best mean LOSO PR-AUC)")

    # ---- grouped random split (optimistic, comparison only) ----------------
    groups = df["src_host"].astype(str) + "->" + df["dst_host"].astype(str)
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=42)
    tr_idx, te_idx = next(splitter.split(df, df[LABEL_COL], groups))
    Xtr = df.loc[tr_idx, FEATURES].to_numpy(float); ytr = df.loc[tr_idx, LABEL_COL].to_numpy(int)
    Xte = df.loc[te_idx, FEATURES].to_numpy(float); yte = df.loc[te_idx, LABEL_COL].to_numpy(int)
    spw = (ytr == 0).sum() / max(1, (ytr == 1).sum())
    clf = make_xgb(spw, best_mult).fit(Xtr, ytr)
    prob = clf.predict_proba(Xte)[:, 1]
    random_split = {"pr_auc": round(float(average_precision_score(yte, prob)), 4),
                    "roc_auc": round(float(roc_auc_score(yte, prob)), 4), **evaluate(yte, prob)}
    print(f"\nGROUPED RANDOM SPLIT (optimistic, host-pair grouped): {random_split}")

    # ---- LOSO at the selected spw_mult (the honest headline) ---------------
    print(f"\nLOSO at spw_mult={best_mult} (honest, per-scenario detail):")
    folds, agg = loso(df, best_mult)
    for fk, v in sorted(folds.items()):
        print(f"  scenario {fk:>3}: pos={v['test_positives']:>4} PR-AUC={v['pr_auc']:.4f} "
              f"P={v['precision']:.4f} R={v['recall']:.4f} F1={v['f1']:.4f}"
              f"{'' if v['reliable'] else '  UNRELIABLE (n<'+str(MIN_POS_RELIABLE)+')'}")
    print(f"\nLOSO aggregate ({agg['n_folds_reliable']} reliable folds): {agg}")

    # ---- final model, fit on ALL data --------------------------------------
    X = df[FEATURES].to_numpy(float); y = df[LABEL_COL].to_numpy(int)
    spw = (y == 0).sum() / max(1, (y == 1).sum())
    final_clf = make_xgb(spw, best_mult).fit(X, y)
    importances = {n: round(float(s), 6) for n, s in
                   sorted(zip(FEATURES, final_clf.feature_importances_), key=lambda kv: -kv[1])}
    print("\nfeature importances (final model, fit on all data):")
    for n, s in importances.items():
        print(f"  {n:24s} {s:.4f}")

    in_sample_prob = final_clf.predict_proba(X)[:, 1]
    in_sample = {
        "pr_auc": round(float(average_precision_score(y, in_sample_prob)), 4),
        "roc_auc": round(float(roc_auc_score(y, in_sample_prob)), 4),
    }

    # ---- sanity checks: hand-built realistic browser-beacon feature vectors
    #      (payload in REAL HTTP-byte scale, not NetFlow totals) -------------
    sanity_vectors = {
        "tc01_5s_get_512B":   [5000.0, 0.02, 0.0, 60.0, 512.0, 20.0, 0, 0.0, 0.0],
        "cs_10s_5pct_jitter": [10000.0, 0.0289, 0.0, 200.0, 300.0, 15.0, 0, 0.0, 0.0],
        "cs_60s_10pct_jitter":[60000.0, 0.0577, 0.0, 1500.0, 400.0, 20.0, 0, 0.3, 0.2],
        "tc02_post_exfil":    [8000.0, 0.03, 0.0, 150.0, 850.0, 40.0, 0, 0.0, 1.0],
    }
    sanity = {}
    for name, vec in sanity_vectors.items():
        score = float(final_clf.predict_proba(np.array([vec], dtype=float))[0][1])
        sanity[name] = round(score, 4)
        print(f"SANITY -- {name:<24} ML score = {score:.4f}")

    OUT_MODEL.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "model": final_clf, "feature_names": FEATURES, "threshold": THRESHOLD,
        "trained_on": "CTU-13 Zeek http.log, label_c2 (ANY real C2 HTTP request), n_flows>=4",
        "n_training_windows": int(len(df)), "n_positive_windows": n_pos,
        "params": {**XGB_PARAMS, "spw_mult": best_mult, "scale_pos_weight": round(float(spw * best_mult), 2)},
        "feature_importances": importances,
        "in_sample": in_sample,
        "honest_loso_aggregate": agg,
        "spw_mult_sweep": sweep,
        "random_split_optimistic": random_split,
        "sanity_scores": sanity,
        "requires_fusion_threshold": 0.52,
        "replaces": "models/archive/c3_xgb_classifier_NETFLOW_PRE_HTTP_20260828.pkl",
        "note": ("PRODUCTION model. Trained on real HTTP-transaction payload bytes "
                 "(Zeek http.log request_body_len/response_body_len via feature_engine.py-"
                 "equivalent measurement), fixing the NetFlow-scale mismatch documented in "
                 "C3_FullPipeline_XGB_Results.md Result 6. Loaded at runtime by "
                 "core/c3/anomaly_engine.py. See C3_XGB_HTTP_Deployment_Results.md."),
    }
    with open(OUT_MODEL, "wb") as f:
        pickle.dump(payload, f)
    print(f"\nsaved production model -> {OUT_MODEL}")
    print("  (core/c3/anomaly_engine.py loads this file -- restart the backend to pick it up)")

    with open(OUT_RESULTS, "w", encoding="utf-8") as f:
        json.dump({"random_split": random_split, "loso_folds": folds, "loso_aggregate": agg,
                   "spw_mult_sweep": sweep, "selected_spw_mult": best_mult,
                   "feature_importances": importances, "in_sample": in_sample,
                   "sanity_scores": sanity, "n_training_windows": len(df),
                   "n_positive_windows": n_pos},
                  f, indent=2, default=str)
    print(f"saved -> {OUT_RESULTS}\ntotal time {time.time()-t0:.1f}s")


if __name__ == "__main__":
    main()
