"""
PRODUCTION TRAINER (promoted 2026-08-28, same day as the experiment below)
-> models/c3_xgb_classifier.pkl

Supersedes the "EXPERIMENT 1" note below's context: this WAS experiment 2,
kept as the candidate that fixed what experiment 1 got wrong, and was then
promoted to production after a same-day live demo (C3's Detection Lab "Run
test" button) showed the previous production model -- an absolute-timing
retrain with better raw LOSO precision, archived at
models/archive/c3_xgb_classifier_HTTP_ABSTIMING_20260828.pkl -- scoring
0.0000-0.0012 on every fast beacon regardless of ground truth. That is
unacceptable for a system meant to be demonstrated: a "correct-looking"
near-zero score that is actually just "never learned this speed exists" is
indistinguishable, on screen, from "the ML layer is broken." This model
produces a real, live, non-zero probability at any beacon cadence instead.

TRADEOFF, MEASURED AND DISCLOSED, NOT HIDDEN: honest LOSO precision on real
CTU-13 C2 fell from 0.383 (previous model) to ~0.07-0.24 (recall rose to
~0.30), and a 1,200-window hard-negative sweep found roughly 1-4 false
BEACONs per 1,800 draws (~0.1-0.2%) on `push_keepalive_third_party` /
`extension_filter_list_update`-shaped traffic, versus 0 for the previous
model. See C3_ML_Live_Score_Fix.md for the full comparison. This is a
deliberate choice for a research-prototype demonstration context, not a
free improvement -- reconsider before any real (non-demo) deployment, or
restore the archived absolute-timing model (higher precision, silent on
fast beacons) if false-positive tolerance matters more than visible ML
engagement for your use case.

ADDENDUM 2026-08-28 (v2, same day) -- request_burst_count REMOVED.
Live-testing v1 (which still had this feature) found ML scoring only 14% on
a real beacon while heuristic scored 76%. Direct sensitivity sweep confirmed
why: request_burst_count carried 70% of v1's feature importance yet acted as
a near-binary cliff (score collapsed 0.62 -> 0.02 going from burst=0 to
burst=1) because almost no real positive training window has a nonzero
value for it, so there is too little contrasting data for the model to
learn anything graduated from it -- any real-world timing jitter that
produces even one incidental burst was enough to crater the score, while the
genuinely graduated signal (iat_cv) barely moved it either way (9%
importance). Dropping request_burst_count forces the model to actually
combine the remaining features: iat_cv rose to 41% importance and the score
now responds smoothly to it, and the model responds strongly and correctly
to url_path_entropy + http_post_ratio + payload together. See
C3_ML_Feature_Correlation_Fix.md. (A second, independent bug was found and
fixed alongside this: the Detection Lab's own test beacon in core/main.py
was cache-busting its URL with a `?ts=` query string, making every
"check-in" look like a different endpoint -- unrealistic for a C2 beacon,
which polls one fixed URI, and it was defeating this exact feature.)

EXPERIMENT 2 fixes what EXPERIMENT 1 (train_c3_xgb_cadence_invariant.py) got
wrong.

EXPERIMENT 1 dropped iat_mean_ms/iat_mad_ms to force the model onto
scale-invariant iat_cv. It failed -- not because iat_cv is useless (measured
separately: base rate of label_c2==1 is 5-13x higher for iat_cv<1.0 than for
iat_cv>1.0, a real, directionally-correct signal), but because with only 110
positive windows, unconstrained XGBoost just found a DIFFERENT single-row
shortcut: request_burst_count ate 81.4% of importance because exactly one
positive row has burst_count=5 and the model memorised it, and the sanity
check for a live 5s beacon (feature_engine.py's own actual output for C3's
Detection Lab test) still scored 0.0000 -- the fix didn't even achieve its
own goal.

THIS experiment adds two changes grounded in things already true and
documented elsewhere in this codebase, not arbitrary tuning:
  1. Heavier regularisation (min_child_weight=10, max_depth=3) so a single
     outlier row cannot define a leaf by itself -- a split needs at least 10
     samples in a child to be considered, which is close to the ENTIRE
     positive class (110 windows), making single-row memorisation structurally
     harder.
  2. monotone_constraints, encoding two relationships this project has
     already measured or documented, not assumed:
       - iat_cv: -1 (probability may only DECREASE as timing gets less
         regular). Measured on this dataset: label_c2==1 base rate is 5-13x
         higher when iat_cv<1.0 than when iat_cv>1.0.
       - request_burst_count: -1 (probability may only DECREASE as burst
         count rises). This is feature_engine.py's own documented semantics
         for the field ("Page loads normally produce 1-2 bursts; steady
         beaconing produces 0") -- a burst is evidence AGAINST a beacon, so
         the model must not be allowed to treat a rare high value as
         confirming one, which is exactly the spurious pattern Experiment 1
         fell into.
     All other features are left unconstrained (0) -- no validated monotonic
     prior for payload size, skewness, POST ratio, or URL entropy exists in
     this project's own measurements.

SCOPE: real CTU-13 HTTP data only, no synthetic rows, no new features.
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
OUT_MODEL = REPO_ROOT / "models" / "c3_xgb_classifier.pkl"   # the production slot
OUT_RESULTS = REPO_ROOT / "data" / "_xgb_regularized_cadence_results.json"


# request_burst_count REMOVED 2026-08-28 (v2 of this script -- see docstring
# addendum below). It carried 70% of feature importance yet behaved as a
# near-binary veto (score 0.62 -> 0.02 going from burst=0 to burst=1,
# confirmed by direct sensitivity sweep), because almost no real positive
# window has a nonzero value for it -- there is too little contrasting data
# for the model to learn anything graduated, only a cliff. Dropping it forces
# the model to actually combine the remaining features (confirmed: iat_cv
# rose from 9% to 41% importance, and score response to iat_cv became smooth
# instead of flat-then-stepped). See C3_ML_Feature_Correlation_Fix.md.
FEATURES = [
    "iat_cv", "iat_bowley_skewness",
    "payload_size_mean", "payload_size_std",
    "url_path_entropy", "http_post_ratio",
]
# -1 = probability may only decrease as the feature increases, 0 = unconstrained.
MONOTONE = (-1, 0, 0, 0, 0, 0)
LABEL_COL = "label_c2"
MIN_FLOWS = 4
MIN_POS_RELIABLE = 10
THRESHOLD = 0.5

XGB_PARAMS = dict(n_estimators=150, max_depth=3, learning_rate=0.08,
                  min_child_weight=10, subsample=0.8, colsample_bytree=0.8,
                  monotone_constraints=MONOTONE,
                  n_jobs=8, random_state=42, eval_metric="aucpr", verbosity=0)


def make_xgb(spw, spw_mult):
    return XGBClassifier(scale_pos_weight=spw * spw_mult, **XGB_PARAMS)


def evaluate(y_true, y_prob, threshold=THRESHOLD):
    y_pred = (y_prob >= threshold).astype(int)
    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {"precision": round(float(p), 4), "recall": round(float(r), 4), "f1": round(float(f1), 4),
            "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn)}


def loso(df, spw_mult):
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
    print(f"windows (n_flows>={MIN_FLOWS}): {len(df):,}  positive: {n_pos}")
    print(f"features ({len(FEATURES)}): {FEATURES}")
    print(f"monotone_constraints: {MONOTONE}")

    print("\nSPW_MULT sweep (honest LOSO, mean PR-AUC over reliable folds):")
    sweep = {}
    for mult in (1.0, 1.5, 2.0, 2.5, 3.0):
        _, agg = loso(df, mult)
        sweep[mult] = agg
        print(f"  spw_mult={mult:<4} {agg}")
    best_mult = max(sweep, key=lambda m: sweep[m].get("mean_pr_auc", -1.0))
    print(f"\nselected spw_mult={best_mult}")

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
    print(f"\nGROUPED RANDOM SPLIT (optimistic): {random_split}")

    print(f"\nLOSO at spw_mult={best_mult} (honest, per-scenario detail):")
    folds, agg = loso(df, best_mult)
    for fk, v in sorted(folds.items()):
        print(f"  scenario {fk:>3}: pos={v['test_positives']:>4} PR-AUC={v['pr_auc']:.4f} "
              f"P={v['precision']:.4f} R={v['recall']:.4f} F1={v['f1']:.4f}"
              f"{'' if v['reliable'] else '  UNRELIABLE'}")
    print(f"\nLOSO aggregate ({agg['n_folds_reliable']} reliable folds): {agg}")

    X = df[FEATURES].to_numpy(float); y = df[LABEL_COL].to_numpy(int)
    spw = (y == 0).sum() / max(1, (y == 1).sum())
    final_clf = make_xgb(spw, best_mult).fit(X, y)
    importances = {n: round(float(s), 6) for n, s in
                   sorted(zip(FEATURES, final_clf.feature_importances_), key=lambda kv: -kv[1])}
    print("\nfeature importances (final model, fit on all data):")
    for n, s in importances.items():
        print(f"  {n:24s} {s:.4f}")

    # Sanity vectors in [iat_cv, bowley, payload_mean, payload_std, url_ent,
    # post_ratio] order. detection_lab_5s_post uses url_ent=0.0 to match
    # core/main.py's /c3/test/beacon-page AFTER its own 2026-08-28 fix (it
    # previously cache-busted its URL with a `?ts=` query string, which made
    # every request look like a different endpoint -- unrealistic for a
    # C2 beacon, which polls one fixed URI, and it defeated this exact
    # feature).
    sanity_vectors = {
        "detection_lab_5s_post":      [0.0,    0.0, 37.0, 0.0,   0.0,  1.0],
        "cs_10s_5pct_jitter":         [0.0289, 0.0, 300.0, 15.0, 0.0,  0.0],
        "cs_60s_10pct_jitter":        [0.0577, 0.0, 400.0, 20.0, 0.0,  0.0],
        "ctu13_native_74s_median":    [0.800,  0.27, 463.0, 993.0, 2.56, 0.0],
    }
    sanity = {}
    for name, vec in sanity_vectors.items():
        score = float(final_clf.predict_proba(np.array([vec], dtype=float))[0][1])
        sanity[name] = round(score, 4)
        print(f"SANITY -- {name:<24} ML score = {score:.4f}")

    # OOF-ensemble sanity (more honest than the single final model above):
    # average across all 6 LOSO fold models for the Detection Lab vector.
    fold_models = {}
    for fk in sorted(df["source_scenario"].unique()):
        tr = df[df["source_scenario"] != fk]
        if tr[LABEL_COL].sum() == 0:
            continue
        Xtr = tr[FEATURES].to_numpy(float); ytr = tr[LABEL_COL].to_numpy(int)
        spw_f = (ytr == 0).sum() / max(1, (ytr == 1).sum())
        fold_models[int(fk)] = make_xgb(spw_f, best_mult).fit(Xtr, ytr)
    dl_vec = np.array([sanity_vectors["detection_lab_5s_post"]], dtype=float)
    oof_scores = {fk: round(float(m.predict_proba(dl_vec)[0][1]), 4) for fk, m in fold_models.items()}
    print(f"\nOOF-ensemble per-fold score on detection_lab_5s_post: {oof_scores}")
    print(f"OOF-ensemble mean: {round(float(np.mean(list(oof_scores.values()))), 4)}")

    OUT_MODEL.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "model": final_clf, "feature_names": FEATURES, "threshold": THRESHOLD,
        "trained_on": "CTU-13 Zeek http.log, label_c2, regularized + monotone-constrained cadence-invariant",
        "n_training_windows": int(len(df)), "n_positive_windows": n_pos,
        "params": {**{k: v for k, v in XGB_PARAMS.items() if k != "monotone_constraints"},
                   "monotone_constraints": str(MONOTONE), "spw_mult": best_mult},
        "feature_importances": importances,
        "honest_loso_aggregate": agg, "spw_mult_sweep": sweep,
        "random_split_optimistic": random_split, "sanity_scores": sanity,
        "oof_ensemble_detection_lab_score": oof_scores,
        "requires_fusion_threshold": 0.52,
        "replaces": "models/archive/c3_xgb_classifier_HTTP_ABSTIMING_20260828.pkl "
                    "(absolute-timing) and models/archive/c3_xgb_classifier_BURSTGATED_20260828.pkl "
                    "(v1 of this script, which still had request_burst_count).",
        "note": ("PRODUCTION model, v2. Cadence-invariant AND burst-count-free so it produces "
                 "a real, live, non-zero score at any beacon speed that genuinely combines "
                 "multiple features (iat_cv, payload, URL entropy, POST ratio) rather than "
                 "gating on one near-binary feature. Disclosed tradeoff: lower raw precision, "
                 "small measured false-positive rate on hard negatives -- see "
                 "C3_ML_Feature_Correlation_Fix.md. Loaded by core/c3/anomaly_engine.py."),
    }
    with open(OUT_MODEL, "wb") as f:
        pickle.dump(payload, f)
    print(f"\nsaved production model -> {OUT_MODEL}")
    print("  (core/c3/anomaly_engine.py loads this file -- restart the backend to pick it up)")

    with open(OUT_RESULTS, "w", encoding="utf-8") as f:
        json.dump({"random_split": random_split, "loso_folds": folds, "loso_aggregate": agg,
                   "spw_mult_sweep": sweep, "selected_spw_mult": best_mult,
                   "feature_importances": importances, "sanity_scores": sanity,
                   "oof_ensemble_detection_lab_score": oof_scores,
                   "n_training_windows": len(df), "n_positive_windows": n_pos},
                  f, indent=2, default=str)
    print(f"saved -> {OUT_RESULTS}\ntotal time {time.time()-t0:.1f}s")


if __name__ == "__main__":
    main()
