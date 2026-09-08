"""
Train and HONESTLY evaluate the 18-feature C3 C2-beacon classifier.

Dataset: data/c3_18feat_dataset.csv  (built by build_c3_18feat_dataset.py)
         68,464 non-overlapping windows of real HTTP requests,
         6,890 real C2 windows across 6 malware families.

WHAT THIS SCRIPT REFUSES TO DO
------------------------------
  * No random train/test split. Every split is by CAPTURE or by FAMILY, so a
    window from a capture can never appear on both sides.
  * No threshold chosen on the test fold. The decision threshold is picked by
    an inner grouped 3-fold CV inside the TRAINING data only, then applied
    unchanged to the held-out fold.
  * No plain accuracy quoted on the imbalanced set (always-say-benign scores
    89.9% there and means nothing). Plain accuracy is only reported on a
    CLASS-BALANCED held-out test set, where it is a real number.

THREE EVALUATIONS
-----------------
  E1  LEAVE-ONE-FAMILY-OUT. The whole malware family, and every capture it
      appears in, is removed from training. This is the hardest and most
      honest test: can the detector find a C2 family it has never seen?
      Benign captures are also rotated so each fold's benign side contains
      CTU-Normal captures the model never saw.
  E2  BALANCED HELD-OUT TEST SET. Whole captures are held out, then the
      benign side is subsampled to the size of the C2 side, so plain accuracy
      is meaningful. This is the operational number: a known family, an
      unseen capture.
  E3  SAME PROTOCOLS, 6 ORIGINAL FEATURES ONLY. Identical data, identical
      folds, identical hyper-parameters - the only difference is the feature
      set, so any gap is attributable to the features and nothing else.

Outputs (all new files):
  data/_c3_18feat_results.json
  models/c3_xgb_classifier_18feat_20260902.pkl      (NOT the production slot)
"""
from __future__ import annotations

import json
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, average_precision_score,
                             balanced_accuracy_score, confusion_matrix,
                             precision_recall_fscore_support, roc_auc_score)
from sklearn.model_selection import GroupKFold
from xgboost import XGBClassifier

REPO_ROOT = Path(__file__).resolve().parent.parent
DATASET = REPO_ROOT / "data" / "c3_18feat_dataset.csv"
OUT_RESULTS = REPO_ROOT / "data" / "_c3_18feat_results.json"
OUT_MODEL = REPO_ROOT / "models" / "c3_xgb_classifier_18feat_20260902.pkl"

FEATURES_18 = [
    "iat_cv", "iat_bowley_skewness", "iat_norm_mad", "iat_burstiness",
    "iat_autocorr_lag1", "iat_spread_ratio", "iat_clock_share", "iat_entropy_norm",
    "payload_size_mean", "payload_cv", "payload_repeat_ratio", "upload_download_ratio",
    "url_path_entropy", "unique_path_ratio", "http_post_ratio",
    "uri_len_norm", "uri_char_entropy_norm",
    "referrer_absent_ratio",
]

# Domain priors. -1 = a LOWER value means more beacon-like, +1 = a HIGHER value
# means more beacon-like, 0 = let the model decide. These stop the model
# inventing a non-physical rule on a region of feature space it never saw,
# which is exactly the failure mode that killed the previous model.
MONOTONE_18 = (-1, 0, -1, -1, 0, -1, +1, -1,
                0, -1, +1, 0,
               -1, -1, 0, 0, 0, +1)

FEATURES_6 = ["iat_cv", "iat_bowley_skewness", "payload_size_mean",
              "payload_size_std_PROXY", "url_path_entropy", "http_post_ratio"]
# payload_size_std is not in the new CSV (payload_cv replaced it); for a fair
# baseline the original 6-feature model is reproduced with payload_cv in that
# slot, which carries the same information in scale-free form.
FEATURES_6 = ["iat_cv", "iat_bowley_skewness", "payload_size_mean",
              "payload_cv", "url_path_entropy", "http_post_ratio"]
MONOTONE_6 = (-1, 0, 0, 0, 0, 0)

XGB_PARAMS = dict(n_estimators=300, max_depth=4, learning_rate=0.06,
                  min_child_weight=8, subsample=0.85, colsample_bytree=0.85,
                  reg_lambda=2.0, n_jobs=8, random_state=42,
                  eval_metric="aucpr", verbosity=0)

MIN_POS_RELIABLE = 10
# Each CTU-Normal capture is pinned to one evaluation fold so that every fold's
# benign side contains real browsing captures absent from its training data.
NORMAL_FOLD_ASSIGNMENT = {
    "Neris":    ["normal-22", "normal-14", "normal-25"],
    "ZeusV1":   ["normal-30", "normal-20", "normal-26"],
    "Zeus78":   ["normal-32", "normal-21", "normal-18"],
    "FastFlux": ["normal-31", "normal-23"],
    "Sogou":    ["normal-29", "normal-24"],
    "ZeusB26":  ["normal-27", "normal-28", "normal-33"],
}


def family_weights(families: np.ndarray, labels: np.ndarray,
                   groups: np.ndarray | None = None) -> np.ndarray:
    """Re-weight so the loss is not dominated by whichever capture is biggest.

    Positive side: every malware family carries the same total weight. Without
    this, Zeus78 is 95% of the positives and the model simply learns Zeus78.

    Negative side: the benign class as a whole carries the same total weight as
    the positive class, and inside it the two KINDS of benign traffic are given
    equal weight - real human browsing (the CTU-Normal captures) and lab
    background traffic (everything else). Unweighted, browsing is only 4,600 of
    61,574 negatives, so the model's idea of "normal" would be a 2011 lab
    network rather than a person using a browser, which is the population C3
    actually runs against.

    This is re-weighting, not resampling: no row is duplicated or invented."""
    weights = np.ones(len(labels), dtype=float)
    pos = labels == 1
    fams = np.unique(families[pos])
    if len(fams):
        for fam in fams:
            mask = pos & (families == fam)
            weights[mask] = 1.0 / mask.sum()
        weights[pos] *= (1000.0 / len(fams))

    neg = ~pos
    total_neg_weight = weights[pos].sum() if pos.any() else 1.0
    if groups is None:
        weights[neg] = total_neg_weight / max(neg.sum(), 1)
        return weights

    browsing = neg & np.char.startswith(groups.astype(str), "normal-")
    background = neg & ~browsing
    halves = [m for m in (browsing, background) if m.sum() > 0]
    for mask in halves:
        weights[mask] = (total_neg_weight / len(halves)) / mask.sum()
    return weights


def pick_threshold(X, y, groups, families, features, monotone) -> dict:
    """Choose decision thresholds by inner grouped 3-fold CV on TRAINING data
    only. Never sees the outer test fold.

    Two operating points are derived, and the difference between them matters:

      "f1"   - the threshold that maximises F1 on the out-of-fold TRAINING
               predictions. This is the textbook choice and it TRANSFERS BADLY:
               it is fitted to the score distribution of the malware families
               present in training, and an unseen family lands somewhere else
               entirely.
      "fpr1" - the 99th percentile of the out-of-fold BENIGN scores, i.e. the
               threshold that spends a 1% false-positive budget. It is defined
               only by the negative class, which is the part of the
               distribution that does NOT change when a new malware family
               appears, so it transfers. "fpr5" is the same at 5%.

    Both are reported so the transfer gap is visible rather than hidden.
    """
    uniq = np.unique(groups)
    n_splits = min(3, len(uniq))
    if n_splits < 2 or y.sum() < 5:
        return {"f1": 0.5, "fpr1": 0.5, "fpr5": 0.5}
    oof = np.zeros(len(y), dtype=float)
    for tr, te in GroupKFold(n_splits=n_splits).split(X, y, groups):
        if y[tr].sum() == 0:
            continue
        clf = XGBClassifier(monotone_constraints=monotone, **XGB_PARAMS)
        clf.fit(X[tr], y[tr], sample_weight=family_weights(families[tr], y[tr], groups[tr]))
        oof[te] = clf.predict_proba(X[te])[:, 1]

    best_t, best_f1 = 0.5, -1.0
    for t in np.arange(0.05, 0.96, 0.01):
        pred = (oof >= t).astype(int)
        if pred.sum() == 0:
            continue
        _, _, f1, _ = precision_recall_fscore_support(y, pred, average="binary",
                                                      zero_division=0)
        if f1 > best_f1:
            best_f1, best_t = f1, float(t)

    benign_scores = oof[y == 0]
    return {
        "f1": round(best_t, 4),
        "fpr1": round(float(np.quantile(benign_scores, 0.99)), 4),
        "fpr5": round(float(np.quantile(benign_scores, 0.95)), 4),
    }


def score_fold(y_true, proba, threshold) -> dict:
    pred = (proba >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    prec, rec, f1, _ = precision_recall_fscore_support(y_true, pred, average="binary",
                                                       zero_division=0)
    out = {
        "n_test": int(len(y_true)), "test_positives": int(y_true.sum()),
        "threshold": float(threshold),
        "precision": round(float(prec), 4), "recall": round(float(rec), 4),
        "f1": round(float(f1), 4),
        "balanced_accuracy": round(float(balanced_accuracy_score(y_true, pred)), 4),
        "accuracy": round(float(accuracy_score(y_true, pred)), 4),
        "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
    }
    if 0 < y_true.sum() < len(y_true):
        out["roc_auc"] = round(float(roc_auc_score(y_true, proba)), 4)
        out["pr_auc"] = round(float(average_precision_score(y_true, proba)), 4)
        fpr_sorted = np.sort(proba[y_true == 0])
        for pct, key in ((1, "recall_at_1pct_fpr"), (5, "recall_at_5pct_fpr")):
            cut = fpr_sorted[int(len(fpr_sorted) * (1 - pct / 100.0))] if len(fpr_sorted) else 1.0
            out[key] = round(float(np.mean(proba[y_true == 1] >= cut)), 4)
    else:
        out["roc_auc"] = None
        out["pr_auc"] = None
    return out


def run_lofo(df, features, monotone, tag) -> dict:
    """E1 - leave-one-family-out."""
    y_all = df["label"].to_numpy(int)
    fam_all = df["family"].to_numpy(str)
    grp_all = df["group"].to_numpy(str)
    X_all = df[features].to_numpy(float)

    families = [f for f in pd.unique(fam_all) if f != "benign"]
    folds = {}
    for fam in sorted(families):
        pos_mask = (fam_all == fam) & (y_all == 1)
        if pos_mask.sum() == 0:
            continue
        held_groups = set(pd.unique(grp_all[pos_mask]))
        held_groups |= set(NORMAL_FOLD_ASSIGNMENT.get(fam, []))
        test_mask = np.isin(grp_all, list(held_groups))
        train_mask = ~test_mask
        if y_all[train_mask].sum() == 0 or y_all[test_mask].sum() == 0:
            continue

        thrs = pick_threshold(X_all[train_mask], y_all[train_mask],
                              grp_all[train_mask], fam_all[train_mask],
                              features, monotone)
        clf = XGBClassifier(monotone_constraints=monotone, **XGB_PARAMS)
        clf.fit(X_all[train_mask], y_all[train_mask],
                sample_weight=family_weights(fam_all[train_mask], y_all[train_mask], grp_all[train_mask]))
        proba = clf.predict_proba(X_all[test_mask])[:, 1]
        res = score_fold(y_all[test_mask], proba, thrs["fpr1"])
        res["at_operating_points"] = {
            name: score_fold(y_all[test_mask], proba, t) for name, t in thrs.items()
        }
        res["thresholds"] = thrs
        res["held_out_groups"] = sorted(held_groups)
        res["reliable"] = bool(res["test_positives"] >= MIN_POS_RELIABLE)
        res["train_positives"] = int(y_all[train_mask].sum())
        folds[fam] = res
        flag = "" if res["reliable"] else "  (too few positives - excluded from mean)"
        f1p = res["at_operating_points"]["f1"]
        print(f"  [{tag}] LOFO {fam:9s} pos={res['test_positives']:5d} "
              f"ROC={res['roc_auc']} PR={res['pr_auc']} | @1%FPR "
              f"R={res['recall']} P={res['precision']} F1={res['f1']} "
              f"BalAcc={res['balanced_accuracy']} | @F1-thr F1={f1p['f1']}{flag}",
              flush=True)

    rel = [v for v in folds.values() if v["reliable"]]
    agg = {}
    if rel:
        agg = {
            "n_folds_reliable": len(rel),
            "mean_roc_auc": round(float(np.mean([v["roc_auc"] for v in rel])), 4),
            "mean_pr_auc": round(float(np.mean([v["pr_auc"] for v in rel])), 4),
            "mean_precision": round(float(np.mean([v["precision"] for v in rel])), 4),
            "mean_recall": round(float(np.mean([v["recall"] for v in rel])), 4),
            "mean_f1": round(float(np.mean([v["f1"] for v in rel])), 4),
            "mean_balanced_accuracy": round(float(np.mean([v["balanced_accuracy"] for v in rel])), 4),
            "mean_recall_at_1pct_fpr": round(float(np.mean([v["recall_at_1pct_fpr"] for v in rel])), 4),
            "mean_recall_at_5pct_fpr": round(float(np.mean([v["recall_at_5pct_fpr"] for v in rel])), 4),
            "total_tp": int(sum(v["tp"] for v in rel)),
            "total_fp": int(sum(v["fp"] for v in rel)),
            "total_fn": int(sum(v["fn"] for v in rel)),
            "total_tn": int(sum(v["tn"] for v in rel)),
        }
    return {"folds": folds, "aggregate": agg}


# E2 - three held-out scenarios, from easiest to hardest, each reported
# separately so nothing hides behind an average. In every one, the benign side
# comes from CTU-Normal captures that are absent from that scenario's training
# set, and the C2 side is traffic the model has not seen.
HOLDOUT_SCENARIOS = {
    "S1_unseen_C2_server": {
        "pairs": ["10.0.2.106->95.211.9.145"],
        "groups": ["normal-30", "normal-26"],
        "note": "ZeusV1: the held-out C&C server is never seen in training; the "
                "other two servers of the same family are.",
    },
    "S2_unseen_capture_and_host": {
        "pairs": [],
        "groups": ["ctu13-s9", "normal-22", "normal-25"],
        "note": "Neris: the whole capture and the infected host are held out; "
                "the family is seen in CTU-13 scenarios 1 and 2.",
    },
    "S3_unseen_capture_same_server": {
        "pairs": [],
        "groups": ["zeus-78-2", "normal-32", "normal-18"],
        "note": "Zeus78: same family AND same C&C server as training capture "
                "78-1, different capture day. Easiest case - disclosed as such.",
    },
}


def run_holdout_scenario(df, features, monotone, tag, name, spec, seed=42) -> dict:
    """Whole captures (or one whole C&C server) held out, then the benign side
    subsampled to the size of the C2 side so that plain accuracy is a real
    number rather than a restatement of the class ratio."""
    grp = df["group"].to_numpy(str)
    pair = df["pair"].to_numpy(str)
    test_mask = np.isin(grp, spec["groups"])
    if spec["pairs"]:
        test_mask = test_mask | np.isin(pair, spec["pairs"])
    train_mask = ~test_mask

    y_tr = df["label"].to_numpy(int)[train_mask]
    X_tr = df[features].to_numpy(float)[train_mask]
    fam_tr = df["family"].to_numpy(str)[train_mask]
    grp_tr = grp[train_mask]

    test_df = df[test_mask]
    pos, neg = test_df[test_df["label"] == 1], test_df[test_df["label"] == 0]
    if len(pos) == 0 or len(neg) == 0:
        return {"error": "scenario has only one class", "note": spec["note"]}
    n = min(len(pos), len(neg))
    rng = np.random.default_rng(seed)
    bal = pd.concat([pos.iloc[rng.choice(len(pos), n, replace=False)],
                     neg.iloc[rng.choice(len(neg), n, replace=False)]])

    thrs = pick_threshold(X_tr, y_tr, grp_tr, fam_tr, features, monotone)
    clf = XGBClassifier(monotone_constraints=monotone, **XGB_PARAMS)
    clf.fit(X_tr, y_tr, sample_weight=family_weights(fam_tr, y_tr, grp_tr))

    proba = clf.predict_proba(bal[features].to_numpy(float))[:, 1]
    y_bal = bal["label"].to_numpy(int)
    res = score_fold(y_bal, proba, thrs["fpr1"])
    res["at_operating_points"] = {k: score_fold(y_bal, proba, t) for k, t in thrs.items()}
    res["thresholds"] = thrs
    res["note"] = spec["note"]
    res["held_out"] = {"groups": spec["groups"], "pairs": spec["pairs"]}
    res["test_positives_available"] = int(len(pos))
    res["test_negatives_available"] = int(len(neg))
    res["train_windows"] = int(train_mask.sum())
    res["train_positives"] = int(y_tr.sum())

    # False positives on real human browsing only - the operationally
    # meaningful FPR for a browser-resident detector.
    browsing = test_df[test_df["group"].str.startswith("normal-")]
    if len(browsing):
        b_proba = clf.predict_proba(browsing[features].to_numpy(float))[:, 1]
        res["browsing_only"] = {
            "n": int(len(browsing)),
            "fpr_at_fpr1_threshold": round(float(np.mean(b_proba >= thrs["fpr1"])), 4),
            "fpr_at_f1_threshold": round(float(np.mean(b_proba >= thrs["f1"])), 4),
        }

    best = res["at_operating_points"]["f1"]
    print(f"  [{tag}] {name:28s} n={2*n:5d} ROC={res['roc_auc']} | "
          f"@1%FPR-thr ACC={res['accuracy']} R={res['recall']} P={res['precision']} | "
          f"@F1-thr ACC={best['accuracy']} F1={best['f1']}", flush=True)
    return res


def run_all_holdouts(df, features, monotone, tag) -> dict:
    out = {}
    for name, spec in HOLDOUT_SCENARIOS.items():
        out[name] = run_holdout_scenario(df, features, monotone, tag, name, spec)
    good = [v for v in out.values() if "error" not in v]
    if good:
        out["mean_over_scenarios"] = {
            "accuracy_at_fpr1": round(float(np.mean([v["accuracy"] for v in good])), 4),
            "accuracy_at_f1_thr": round(float(np.mean(
                [v["at_operating_points"]["f1"]["accuracy"] for v in good])), 4),
            "roc_auc": round(float(np.mean([v["roc_auc"] for v in good])), 4),
            "recall_at_1pct_fpr": round(float(np.mean([v["recall_at_1pct_fpr"] for v in good])), 4),
        }
    return out


def main() -> None:
    df = pd.read_csv(DATASET)
    print(f"dataset: {len(df):,} windows, {int(df['label'].sum()):,} positives "
          f"({df['label'].mean():.4f} prevalence)\n")

    results = {"dataset": {
        "rows": int(len(df)), "positives": int(df["label"].sum()),
        "prevalence": round(float(df["label"].mean()), 6),
        "positives_by_family": df[df["label"] == 1]["family"].value_counts().to_dict(),
        "windows_by_group": df.groupby("group")["label"].agg(["size", "sum"]).to_dict(),
    }}

    print("=" * 78)
    print("E1  LEAVE-ONE-FAMILY-OUT   (hardest test: unseen malware family)")
    print("=" * 78)
    results["E1_lofo_18feat"] = run_lofo(df, FEATURES_18, MONOTONE_18, "18f")
    print()
    results["E1_lofo_6feat"] = run_lofo(df, FEATURES_6, MONOTONE_6, " 6f")

    print()
    print("=" * 78)
    print("E2  BALANCED HELD-OUT CAPTURES   (operational test: real accuracy)")
    print("=" * 78)
    results["E2_holdouts_18feat"] = run_all_holdouts(df, FEATURES_18, MONOTONE_18, "18f")
    print()
    results["E2_holdouts_6feat"] = run_all_holdouts(df, FEATURES_6, MONOTONE_6, " 6f")

    print()
    print("=" * 78)
    print("FINAL FIT (all data) + feature importances")
    print("=" * 78)
    X = df[FEATURES_18].to_numpy(float)
    y = df["label"].to_numpy(int)
    fam = df["family"].to_numpy(str)
    grp = df["group"].to_numpy(str)
    thrs = pick_threshold(X, y, grp, fam, FEATURES_18, MONOTONE_18)
    final = XGBClassifier(monotone_constraints=MONOTONE_18, **XGB_PARAMS)
    final.fit(X, y, sample_weight=family_weights(fam, y, grp))
    imps = dict(sorted(zip(FEATURES_18,
                           [round(float(v), 6) for v in final.feature_importances_]),
                       key=lambda kv: -kv[1]))
    results["final_thresholds"] = thrs
    results["feature_importances"] = imps
    for k, v in imps.items():
        print(f"  {k:24s} {v:.4f}")

    OUT_MODEL.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_MODEL, "wb") as fh:
        pickle.dump({
            "model": final,
            "feature_names": FEATURES_18,
            "threshold": thrs["fpr1"],   # scalar the C3 loader reads
            "thresholds": thrs,
            "trained_on": "data/c3_18feat_dataset.csv - real CTU-13 + Zeus + "
                          "CTU-Normal HTTP captures, 18 features, family-balanced weights",
            "n_training_windows": int(len(df)),
            "n_positive_windows": int(y.sum()),
            "monotone_constraints": str(MONOTONE_18),
            "params": XGB_PARAMS,
            "feature_importances": imps,
            "honest_lofo": results["E1_lofo_18feat"]["aggregate"],
            "balanced_holdout": results["E2_holdouts_18feat"].get("mean_over_scenarios"),
            "note": "COMPARISON / CANDIDATE MODEL. Not wired into "
                    "core/c3/anomaly_engine.py. The production slot "
                    "models/c3_xgb_classifier.pkl is untouched.",
        }, fh)
    print(f"\nwrote {OUT_MODEL}")

    with open(OUT_RESULTS, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=1, default=str)
    print(f"wrote {OUT_RESULTS}")


if __name__ == "__main__":
    main()
