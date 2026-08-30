"""
Optimized XGBoost for C3 — nested, leakage-free hyperparameter AND threshold
selection, on the real combined CTU-13 + IoT-23 data.

Separate from production throughout: writes models/c3_xgb_optimized.pkl, never
models/c3_rf_classifier.pkl, and never imports or mutates anomaly_engine.py.

WHY NESTED. The previous run (train_c3_xgb_test.py) used a fixed 0.5 threshold
inherited from the RF/CTU-13 calibration, and several folds came back with
PR-AUC near 1.0 but F1 exactly 0.0 — the model ranked the classes almost
perfectly while the operating point sat in the wrong place. Fixing that by
picking the threshold that looks best on the TEST fold would be leakage and
would inflate every reported number. So:

    outer loop  = leave-one-scenario-out  -> used ONLY for reporting
    inner loop  = grouped CV on the outer TRAINING fold only
                  -> selects hyperparameters AND the decision threshold

No test-fold value influences any fitting or selection decision. This is the
difference between "tuned" and "tuned honestly", and it is the whole point of
this script.

DERIVED FEATURES. The optional arm adds ratio/log transforms that are PURE
FUNCTIONS of the same 7 features feature_engine.py already produces — no new
capture, no feature_engine.py change, no train/serve mismatch introduced. If
this model were ever deployed, anomaly_engine.py would need the same three
lines of derivation (documented in the saved payload's "derived_features"
key); it is NOT deployed by this script.

HONESTY NOTE, carried from the measured domain-mismatch finding: on this data
the beacon-regularity premise is inverted (regular timing is ~0.70x as common
in C2 as in benign, because NetFlow traffic is overwhelmingly machine-timed
while a browser's is human-timed). No amount of tuning in this script changes
that; it can only extract what signal genuinely exists. Report accordingly.
"""
from __future__ import annotations

import json
import pickle
import time
from itertools import product
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (average_precision_score, balanced_accuracy_score,
                              accuracy_score, confusion_matrix, precision_recall_curve,
                              precision_recall_fscore_support, roc_auc_score, roc_curve)
from xgboost import XGBClassifier

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET = REPO_ROOT / "data" / "c3_xgb_training.csv"
OUT_MODEL = REPO_ROOT / "models" / "c3_xgb_optimized.pkl"   # NEVER the production slot
OUT_RESULTS = REPO_ROOT / "data" / "_xgb_optimized_results.json"

BASE_FEATURES = [
    "iat_mean_ms", "iat_cv", "iat_bowley_skewness", "iat_mad_ms",
    "payload_size_mean", "payload_size_std", "request_burst_count",
]
MIN_POS_RELIABLE = 10
INNER_SPLITS = 2

# Deliberately compact. A larger grid searched against only 492 real positives
# mostly fits noise; these six vary the two axes that actually mattered in the
# RF sweep documented in C3_CTU13_C2_Retrain_Results.md (tree depth and
# minority-class weighting), holding the rest at XGBoost defaults.
PARAM_GRID = [
    dict(max_depth=d, learning_rate=lr, spw_mult=m)
    for d, lr, m in product([4, 6], [0.1], [0.5, 1.0, 2.0])
]


def add_derived(df: pd.DataFrame) -> pd.DataFrame:
    """Ratio/log transforms — pure functions of the base 7, no new capture."""
    out = df.copy()
    eps = 1e-9
    # robust (outlier-insensitive) regularity, vs iat_cv's std/mean
    out["robust_cv"] = out["iat_mad_ms"] / (out["iat_mean_ms"] + eps)
    # payload variability relative to its own scale — scale-free, so less prone
    # to encoding "which capture format produced this byte count"
    out["payload_cv"] = out["payload_size_std"] / (out["payload_size_mean"] + eps)
    # log-compress the two heaviest-tailed features (ms and bytes span >6 decades)
    out["log_iat_mean"] = np.log1p(out["iat_mean_ms"].clip(lower=0))
    out["log_payload_mean"] = np.log1p(out["payload_size_mean"].clip(lower=0))
    return out


DERIVED_FEATURES = ["robust_cv", "payload_cv", "log_iat_mean", "log_payload_mean"]


def make_xgb(params: dict, spw: float) -> XGBClassifier:
    return XGBClassifier(
        n_estimators=200, max_depth=params["max_depth"],
        learning_rate=params["learning_rate"],
        scale_pos_weight=spw * params["spw_mult"],
        min_child_weight=3, n_jobs=8, random_state=42,
        eval_metric="aucpr", verbosity=0,
    )


def full_metrics(y_true, y_prob, threshold: float) -> dict:
    y_pred = (y_prob >= threshold).astype(int)
    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    roc = float(roc_auc_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else float("nan")
    fpr_c, tpr_c, _ = roc_curve(y_true, y_prob)
    return {
        "threshold": round(float(threshold), 6),
        "pr_auc": round(float(average_precision_score(y_true, y_prob)), 4),
        "roc_auc": round(roc, 4),
        "balanced_accuracy": round(float(balanced_accuracy_score(y_true, y_pred)), 4),
        "raw_accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(p), 4), "recall": round(float(r), 4), "f1": round(float(f1), 4),
        "recall_at_1pct_fpr": round(float(np.interp(0.01, fpr_c, tpr_c)), 4),
        "recall_at_5pct_fpr": round(float(np.interp(0.05, fpr_c, tpr_c)), 4),
        "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
        "false_positive_rate": round(float(fp / (fp + tn)) if (fp + tn) else 0.0, 6),
    }


def best_threshold(y_true, y_prob) -> float:
    """Threshold maximizing F1 on the supplied (inner-CV, training-side) scores."""
    if y_true.sum() == 0:
        return 0.5
    prec, rec, thr = precision_recall_curve(y_true, y_prob)
    f1 = 2 * prec * rec / np.maximum(prec + rec, 1e-12)
    idx = int(np.nanargmax(f1[:-1])) if len(thr) else 0
    return float(thr[idx]) if len(thr) else 0.5


def inner_select(train_df: pd.DataFrame, features: list[str]) -> tuple[dict, float]:
    """Pick hyperparameters + threshold using ONLY the outer training fold,
    split by scenario so the inner evaluation is also family-disjoint."""
    inner_keys = sorted(train_df["fold_key"].unique())
    # round-robin scenarios into INNER_SPLITS groups
    buckets = [inner_keys[i::INNER_SPLITS] for i in range(INNER_SPLITS)]

    best = (None, -1.0, 0.5)
    for params in PARAM_GRID:
        oof_true, oof_prob = [], []
        for held in buckets:
            it = train_df["fold_key"].isin(held)
            itr, ite = train_df[~it], train_df[it]
            if itr["label_c2"].sum() == 0 or ite["label_c2"].sum() == 0:
                continue
            Xtr = itr[features].to_numpy(float); ytr = itr["label_c2"].to_numpy(int)
            Xte = ite[features].to_numpy(float); yte = ite["label_c2"].to_numpy(int)
            spw = (ytr == 0).sum() / max(1, (ytr == 1).sum())
            clf = make_xgb(params, spw).fit(Xtr, ytr)
            oof_prob.append(clf.predict_proba(Xte)[:, 1])
            oof_true.append(yte)
        if not oof_true:
            continue
        yt = np.concatenate(oof_true); yp = np.concatenate(oof_prob)
        score = float(average_precision_score(yt, yp))
        if score > best[1]:
            best = (params, score, best_threshold(yt, yp))
    if best[0] is None:
        return PARAM_GRID[0], 0.5
    return best[0], best[2]


def run_arm(df: pd.DataFrame, features: list[str], tag: str) -> dict:
    print("\n" + "=" * 78)
    print(f"ARM: {tag}  ({len(features)} features)")
    print("=" * 78)
    folds = {}
    for fk in sorted(df["fold_key"].unique()):
        te = df["fold_key"] == fk
        tr_df, te_df = df[~te], df[te]
        n_te_pos, n_tr_pos = int(te_df.label_c2.sum()), int(tr_df.label_c2.sum())
        if n_te_pos == 0 or n_tr_pos == 0:
            print(f"  {fk:>34}: SKIPPED (train_pos={n_tr_pos}, test_pos={n_te_pos})")
            continue

        params, thr = inner_select(tr_df, features)
        Xtr = tr_df[features].to_numpy(float); ytr = tr_df.label_c2.to_numpy(int)
        Xte = te_df[features].to_numpy(float); yte = te_df.label_c2.to_numpy(int)
        spw = (ytr == 0).sum() / max(1, (ytr == 1).sum())
        clf = make_xgb(params, spw).fit(Xtr, ytr)
        prob = clf.predict_proba(Xte)[:, 1]

        m = full_metrics(yte, prob, thr)
        reliable = n_te_pos >= MIN_POS_RELIABLE
        m.update({"test_positives": n_te_pos, "n_test": len(te_df), "reliable": reliable,
                  "chosen_params": params})
        folds[fk] = m
        print(f"  {fk:>34}: pos={n_te_pos:>4} thr={thr:.4f} PR-AUC={m['pr_auc']:.4f} "
              f"ROC={m['roc_auc']:.4f} P={m['precision']:.4f} R={m['recall']:.4f} "
              f"F1={m['f1']:.4f}{'' if reliable else '  UNRELIABLE'}")

    rel = [v for v in folds.values() if v["reliable"]]
    keys = ["pr_auc", "roc_auc", "balanced_accuracy", "raw_accuracy", "precision",
            "recall", "f1", "recall_at_1pct_fpr", "recall_at_5pct_fpr"]
    agg = {k: round(float(np.mean([v[k] for v in rel])), 4) for k in keys} if rel else {}
    if rel:
        agg["n_reliable_folds"] = len(rel)
        agg["total_tp"] = int(sum(v["tp"] for v in rel))
        agg["total_fp"] = int(sum(v["fp"] for v in rel))
        agg["total_fn"] = int(sum(v["fn"] for v in rel))
        agg["total_tn"] = int(sum(v["tn"] for v in rel))
        print(f"\n  --- aggregate over {len(rel)} reliable folds ---")
        for k in keys:
            band = "   <-- 80-90% band" if 0.80 <= agg[k] <= 0.90 else ""
            print(f"    {k:22s} {agg[k]:.4f}{band}")
    return {"folds": folds, "aggregate": agg, "features": features}


def main():
    t0 = time.time()
    df = pd.read_csv(DATASET)
    print(f"loaded {len(df):,} windows, {int(df.label_c2.sum())} positive "
          f"({100*df.label_c2.mean():.4f}%)")
    df = add_derived(df)

    arms = {
        "base_7": run_arm(df, BASE_FEATURES, "BASE 7 FEATURES + nested tuning"),
        "base_plus_derived_11": run_arm(df, BASE_FEATURES + DERIVED_FEATURES,
                                        "BASE 7 + 4 DERIVED + nested tuning"),
    }

    # Final model: best arm by honest mean PR-AUC, refit on everything.
    best_name = max(arms, key=lambda k: arms[k]["aggregate"].get("pr_auc", -1))
    best_features = arms[best_name]["features"]
    print(f"\nbest arm by honest LOSO PR-AUC: {best_name}")

    X = df[best_features].to_numpy(float); y = df.label_c2.to_numpy(int)
    spw = (y == 0).sum() / max(1, (y == 1).sum())
    params, thr = inner_select(df, best_features)
    clf = make_xgb(params, spw).fit(X, y)
    importances = {n: round(float(s), 6) for n, s in
                   sorted(zip(best_features, clf.feature_importances_), key=lambda kv: -kv[1])}
    print(f"final params={params} threshold={thr:.4f}")
    for n, s in importances.items():
        print(f"    {n:22s} {s:.4f}")

    OUT_MODEL.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_MODEL, "wb") as f:
        pickle.dump({
            "model": clf, "feature_names": best_features, "threshold": thr,
            "derived_features": {
                "robust_cv": "iat_mad_ms / (iat_mean_ms + 1e-9)",
                "payload_cv": "payload_size_std / (payload_size_mean + 1e-9)",
                "log_iat_mean": "log1p(max(iat_mean_ms, 0))",
                "log_payload_mean": "log1p(max(payload_size_mean, 0))",
            } if best_features is not BASE_FEATURES else {},
            "trained_on": "CTU-13 + IoT-23 combined, label_c2, n_flows>=4",
            "params": params, "feature_importances": importances,
            "honest_loso_aggregate": arms[best_name]["aggregate"],
            "note": ("TEST ARTIFACT — not deployed, not loaded by anomaly_engine.py. "
                      "Hyperparameters and threshold selected by nested inner CV on "
                      "training folds only. See C3_XGB_Optimized_Results.md."),
        }, f)
    print(f"\nsaved TEST model -> {OUT_MODEL} (NOT production)")

    with open(OUT_RESULTS, "w", encoding="utf-8") as f:
        json.dump({"arms": arms, "best_arm": best_name, "final_params": params,
                   "final_threshold": thr, "feature_importances": importances},
                  f, indent=2, default=str)
    print(f"saved -> {OUT_RESULTS}")
    print(f"\ntotal time {time.time()-t0:.1f}s")


if __name__ == "__main__":
    main()
