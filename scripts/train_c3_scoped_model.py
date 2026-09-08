"""
C3 model trained and evaluated on a DEFINED SCOPE: active, periodic C2
channels. Fixes two measured methodology defects in the previous dataset.

DEFECT 1 - PSEUDO-REPLICATION (measured)
----------------------------------------
Zeus78 contributes 6,551 of 6,890 C2 windows (95.1%) but all 6,551 come from
ONE (src,dst) pair, 10.0.2.108->81.88.48.95 - one host, one C&C server, one
continuous session cut into consecutive blocks. Statistically that is n=1, not
n=6,551. Across the whole dataset there are 53 distinct C2 pairs, of which
Zeus78 is 1 (1.9%). Window-level metrics were therefore dominated by a single
session. Fix: MAX_WINDOWS_PER_PAIR caps any one pair's contribution.

DEFECT 2 - AN OUT-OF-SCOPE CHANNEL IN THE POSITIVE CLASS (measured)
-------------------------------------------------------------------
C3 detects PERIODIC BEACONING. Feature medians, C2 windows only:

    feature            Zeus78     other C2     benign
    iat_cv              1.613        0.005      1.909
    iat_clock_share     0.082        1.000      0.095
    iat_norm_mad        0.740        0.001      0.836

Every other family beacons on a near-perfect timer. Zeus78's inter-arrival
timing is statistically indistinguishable from ordinary browsing - it is the
dead-C&C 403 retry storm (retry backoff), not a beacon. Training on it forces
the model to hold two contradictory concepts at once, which blunts exactly the
timing features the detector depends on. `uri_char_entropy_norm` is outright
inverted between the two (Zeus78 below benign, other C2 above).

SCOPE CRITERION, chosen so it is NOT circular with the timing features we
detect with: a C2 window is in scope if its channel actually functioned, i.e.
`error_status_ratio < 1.0` (at least one successful exchange). A channel on
which every single request failed is not an active command-and-control
channel. Measured: Zeus78 C2 error_status_ratio = 1.000 for every window;
other families' C2 = 0.043 mean.

This is a scope definition, not a filter tuned to improve a number. Zeus78 is
still evaluated - Section "OUT OF SCOPE" below reports it explicitly rather
than dropping it silently.

Protocols reported:
  LOFO       leave-one-family-out over in-scope families (unseen family)
  LOPO       leave-one-PAIR-out, grouped (unseen C2 source; 52 independent
             units instead of 6 pseudo-replicated folds)
Both use isotonic calibration + environment-calibrated threshold, balanced
held-out sets, N_SEEDS negative draws averaged.

Outputs: data/_c3_scoped_model_results.json
         models/c3_xgb_scoped_CANDIDATE_20260903.pkl   (NOT production)
"""
from __future__ import annotations

import json
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (accuracy_score, confusion_matrix,
                             precision_recall_fscore_support, roc_auc_score)
from sklearn.model_selection import GroupKFold
from xgboost import XGBClassifier

sys.path.insert(0, str(Path(__file__).resolve().parent))
from train_c3_18feat import (DATASET, FEATURES_18, MONOTONE_18, XGB_PARAMS,
                             MIN_POS_RELIABLE, NORMAL_FOLD_ASSIGNMENT,
                             family_weights)

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_RESULTS = REPO_ROOT / "data" / "_c3_scoped_model_results.json"
OUT_MODEL = REPO_ROOT / "models" / "c3_xgb_scoped_CANDIDATE_20260903.pkl"

N_SEEDS = 5
INNER_SPLITS = 3
FPR_GRID = [0.02, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30]
MAX_WINDOWS_PER_PAIR = 150     # anti-pseudo-replication cap


def build_scoped(df: pd.DataFrame):
    """Apply the scope criterion and the per-pair cap. Returns (in_scope_df,
    out_of_scope_c2_df)."""
    dead = (df["label"] == 1) & (df["error_status_ratio"] >= 1.0)
    out_of_scope = df[dead].copy()
    keep = df[~dead].copy()

    parts = []
    for (lab, pair), g in keep.groupby(["label", "pair"], sort=False):
        if len(g) > MAX_WINDOWS_PER_PAIR:
            g = g.sample(MAX_WINDOWS_PER_PAIR, random_state=42)
        parts.append(g)
    capped = pd.concat(parts).sort_index()
    return capped, out_of_scope


def threshold_at_fpr(neg_scores: np.ndarray, target_fpr: float) -> float:
    """Smallest threshold whose ACHIEVED false-positive rate on `neg_scores`
    is <= target_fpr.

    np.quantile is wrong here. Isotonic calibration is a step function, so its
    output has heavy ties: quantile(neg, 1-fpr) frequently returns a value
    shared by a large share of the negatives, and `p >= thr` then admits every
    one of them. Measured symptom: a fold with ROC-AUC 0.965 scored precision
    0.519 because a requested 25% FPR was delivered as 93%.

    Scanning unique values in ascending order and taking the first that meets
    the budget gives the requested FPR exactly, and the smallest such
    threshold keeps recall as high as the budget allows."""
    uniq = np.unique(neg_scores)
    for t in uniq:
        if float((neg_scores >= t).mean()) <= target_fpr:
            return float(t)
    return float(uniq[-1] + 1e-9)


def fit_calibrated(Xtr, ytr, wtr, grp_tr):
    base = XGBClassifier(monotone_constraints=MONOTONE_18, **XGB_PARAMS)
    n_grp = len(np.unique(grp_tr))
    cv = list(GroupKFold(n_splits=min(INNER_SPLITS, n_grp)).split(Xtr, ytr, grp_tr))
    cal = CalibratedClassifierCV(base, method="isotonic", cv=cv)
    cal.fit(Xtr, ytr, sample_weight=wtr)
    return cal


def pick_target_fpr(Xtr, ytr, grp_tr, fam_tr) -> float:
    n_grp = len(np.unique(grp_tr))
    splits = list(GroupKFold(n_splits=min(INNER_SPLITS, n_grp))
                  .split(Xtr, ytr, grp_tr))
    rng = np.random.default_rng(7)
    per = {f: [] for f in FPR_GRID}
    for tr, va in splits:
        if ytr[tr].sum() == 0 or ytr[va].sum() == 0:
            continue
        w = family_weights(fam_tr[tr], ytr[tr], grp_tr[tr])
        cal = fit_calibrated(Xtr[tr], ytr[tr], w, grp_tr[tr])
        p, yv = cal.predict_proba(Xtr[va])[:, 1], ytr[va]
        neg = p[yv == 0]
        if not len(neg):
            continue
        ip, ineg = np.flatnonzero(yv == 1), np.flatnonzero(yv == 0)
        k = min(len(ip), len(ineg))
        sel = np.concatenate([rng.choice(ip, k, replace=False),
                              rng.choice(ineg, k, replace=False)])
        for f in FPR_GRID:
            t = threshold_at_fpr(neg, f)
            _, _, f1, _ = precision_recall_fscore_support(
                yv[sel], (p[sel] >= t).astype(int), average="binary",
                zero_division=0)
            per[f].append(f1)
    means = {f: (float(np.mean(v)) if v else -1.0) for f, v in per.items()}
    return max(means, key=means.get)


def score(y, p, thr) -> dict:
    pred = (p >= thr).astype(int)
    pr, rc, f1, _ = precision_recall_fscore_support(y, pred, average="binary",
                                                    zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    out = {"accuracy": float(accuracy_score(y, pred)), "precision": float(pr),
           "recall": float(rc), "f1": float(f1),
           "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn)}
    if 0 < y.sum() < len(y):
        out["roc_auc"] = float(roc_auc_score(y, p))
    return out


def balanced_mean(y, p, thr) -> dict:
    ip, ineg = np.flatnonzero(y == 1), np.flatnonzero(y == 0)
    k = min(len(ip), len(ineg))
    draws = []
    for s in range(N_SEEDS):
        rng = np.random.default_rng(1000 + s)
        sel = np.concatenate([rng.choice(ip, k, replace=False),
                              rng.choice(ineg, k, replace=False)])
        draws.append(score(y[sel], p[sel], thr))
    out = {m: float(np.mean([d[m] for d in draws]))
           for m in ("accuracy", "precision", "recall", "f1", "roc_auc")}
    out["n_balanced"] = int(2 * k)
    return out


def run_fold(df, test_mask):
    X = df[FEATURES_18].to_numpy(float)
    y = df["label"].to_numpy(int)
    fam = df["family"].to_numpy(str)
    grp = df["group"].to_numpy(str)
    tr = ~test_mask
    if y[tr].sum() == 0 or y[test_mask].sum() == 0:
        return None
    w = family_weights(fam[tr], y[tr], grp[tr])
    fpr = pick_target_fpr(X[tr], y[tr], grp[tr], fam[tr])
    cal = fit_calibrated(X[tr], y[tr], w, grp[tr])
    p = cal.predict_proba(X[test_mask])[:, 1]
    yt = y[test_mask]
    thr = threshold_at_fpr(p[yt == 0], fpr)
    r = balanced_mean(yt, p, thr)
    r.update({"target_fpr": fpr, "n_test_positives": int(yt.sum()),
              "n_train_positives": int(y[tr].sum())})
    return r


def main() -> None:
    raw = pd.read_csv(DATASET)
    df, oos = build_scoped(raw)
    df = df.reset_index(drop=True)

    pos = df[df.label == 1]
    print(f"raw dataset      {len(raw):,} windows, {int(raw.label.sum()):,} C2, "
          f"{raw[raw.label==1]['pair'].nunique()} C2 pairs")
    print(f"out of scope     {len(oos):,} C2 windows removed "
          f"(error_status_ratio == 1.0, channel never succeeded)")
    print(f"in scope, capped {len(df):,} windows, {len(pos):,} C2, "
          f"{pos['pair'].nunique()} C2 pairs, cap={MAX_WINDOWS_PER_PAIR}/pair")
    print("C2 per family:", pos.groupby("family").size().to_dict(), "\n")

    results = {"scope": {
        "criterion": "C2 window in scope iff error_status_ratio < 1.0 "
                     "(the channel completed at least one exchange)",
        "max_windows_per_pair": MAX_WINDOWS_PER_PAIR,
        "removed_c2_windows": int(len(oos)),
        "removed_families": oos["family"].value_counts().to_dict(),
        "in_scope_c2_windows": int(len(pos)),
        "in_scope_c2_pairs": int(pos["pair"].nunique()),
    }, "LOFO": {}, "LOPO": {}}

    fam_arr = df["family"].to_numpy(str)
    grp_arr = df["group"].to_numpy(str)
    y_arr = df["label"].to_numpy(int)

    print("=" * 78)
    print("LOFO  leave-one-family-out (unseen malware family), in scope")
    print("=" * 78)
    for held in sorted(set(fam_arr[y_arr == 1])):
        hg = set(df.loc[fam_arr == held, "group"].unique())
        hg |= set(NORMAL_FOLD_ASSIGNMENT.get(held, []))
        tm = np.isin(grp_arr, list(hg))
        r = run_fold(df, tm)
        if r is None:
            continue
        r["reliable"] = bool(r["n_test_positives"] >= MIN_POS_RELIABLE)
        results["LOFO"][held] = r
        ok = all(r[m] >= 0.75 for m in ("accuracy", "precision", "recall", "f1"))
        flag = "" if r["reliable"] else "  (too few positives - excluded)"
        print(f"  {held:9s} pos={r['n_test_positives']:4d} "
              f"trainpos={r['n_train_positives']:4d} fpr={r['target_fpr']:.2f}  "
              f"acc={r['accuracy']:.4f} prec={r['precision']:.4f} "
              f"rec={r['recall']:.4f} f1={r['f1']:.4f} auc={r['roc_auc']:.4f}"
              f"  {'ALL>=75%' if ok else ''}{flag}")
    rel = [v for v in results["LOFO"].values() if v["reliable"]]
    results["LOFO_mean"] = {m: round(float(np.mean([v[m] for v in rel])), 4)
                            for m in ("accuracy", "precision", "recall",
                                      "f1", "roc_auc")}
    print(f"  MEAN (reliable)                            "
          f"acc={results['LOFO_mean']['accuracy']:.4f} "
          f"prec={results['LOFO_mean']['precision']:.4f} "
          f"rec={results['LOFO_mean']['recall']:.4f} "
          f"f1={results['LOFO_mean']['f1']:.4f} "
          f"auc={results['LOFO_mean']['roc_auc']:.4f}")

    print()
    print("=" * 78)
    print("LOPO  grouped leave-one-C2-source-out (unseen C&C pair)")
    print("=" * 78)
    pair_arr = df["pair"].to_numpy(str)
    c2_pairs = sorted(set(pair_arr[y_arr == 1]))
    gk_scores, gk_labels = [], []
    fold_rows = []
    for pr in c2_pairs:
        tm = pair_arr == pr
        n_pos = int(y_arr[tm].sum())
        if n_pos < 3:
            continue
        # test fold = this C2 pair's windows + a benign slice never used to fit
        hg = set(NORMAL_FOLD_ASSIGNMENT.get(
            df.loc[tm, "family"].iloc[0], []))
        tm_full = tm | np.isin(grp_arr, list(hg))
        r = run_fold(df, tm_full)
        if r is None:
            continue
        fold_rows.append(r)
        results["LOPO"][pr] = r
        print(f"  {pr:34s} pos={r['n_test_positives']:4d} "
              f"acc={r['accuracy']:.3f} prec={r['precision']:.3f} "
              f"rec={r['recall']:.3f} f1={r['f1']:.3f} auc={r['roc_auc']:.3f}")
    if fold_rows:
        results["LOPO_mean"] = {
            m: round(float(np.mean([v[m] for v in fold_rows])), 4)
            for m in ("accuracy", "precision", "recall", "f1", "roc_auc")}
        print(f"  MEAN over {len(fold_rows)} unseen C2 sources          "
              f"acc={results['LOPO_mean']['accuracy']:.4f} "
              f"prec={results['LOPO_mean']['precision']:.4f} "
              f"rec={results['LOPO_mean']['recall']:.4f} "
              f"f1={results['LOPO_mean']['f1']:.4f} "
              f"auc={results['LOPO_mean']['roc_auc']:.4f}")

    # ---- final fit on in-scope data ----
    X = df[FEATURES_18].to_numpy(float)
    y = y_arr
    fpr = pick_target_fpr(X, y, grp_arr, fam_arr)
    cal = fit_calibrated(X, y, family_weights(fam_arr, y, grp_arr), grp_arr)
    thr = threshold_at_fpr(cal.predict_proba(X[y == 0])[:, 1], fpr)
    results["final_fit"] = {"target_fpr": fpr, "threshold": thr,
                            "n_windows": int(len(df)), "n_positives": int(y.sum())}
    print(f"\nfinal fit: target_fpr={fpr}, threshold={thr:.4f}")

    # ---- out-of-scope reporting: the dead-channel C2, scored honestly ----
    # The benign side must NOT have been in training, or this number is
    # inflated: the model has already seen those windows and scores them low.
    # Refit excluding the benign captures used as the comparison negatives.
    if len(oos):
        oos_fams = list(oos["family"].unique())
        held_ben = set()
        for f in oos_fams:
            held_ben |= set(NORMAL_FOLD_ASSIGNMENT.get(f, []))
        ben_mask = np.isin(grp_arr, list(held_ben)) & (y == 0)
        if ben_mask.sum() == 0:                      # fall back, disclosed
            ben_mask = (y == 0)
            clean = False
        else:
            clean = True
        fit_mask = ~ben_mask
        cal_oos = fit_calibrated(X[fit_mask], y[fit_mask],
                                 family_weights(fam_arr[fit_mask], y[fit_mask],
                                                grp_arr[fit_mask]),
                                 grp_arr[fit_mask])
        pb = cal_oos.predict_proba(X[ben_mask])[:, 1]
        po = cal_oos.predict_proba(oos[FEATURES_18].to_numpy(float))[:, 1]
        thr_oos = threshold_at_fpr(pb, fpr)
        yy = np.r_[np.ones(len(po)), np.zeros(len(pb))]
        pp = np.r_[po, pb]
        results["out_of_scope"] = {
            "family_counts": oos["family"].value_counts().to_dict(),
            "n_windows": int(len(oos)),
            "benign_comparison_windows": int(ben_mask.sum()),
            "benign_held_out_of_training": clean,
            "median_score": float(np.median(po)),
            "recall_at_threshold": float((po >= thr_oos).mean()),
            "roc_auc_vs_benign": float(roc_auc_score(yy, pp)),
            "note": "Dead-channel C2 (every request errored), non-periodic: "
                    "iat_cv 1.61 vs 0.005 for in-scope C2. Excluded from the "
                    "headline by the scope criterion, reported here. Benign "
                    "comparison captures were held out of this model's "
                    "training so the number is not inflated.",
        }
        print(f"\nOUT OF SCOPE ({int(len(oos))} windows, {oos_fams}) vs "
              f"{int(ben_mask.sum())} held-out benign: "
              f"median score {np.median(po):.3f}, "
              f"caught {100*(po >= thr_oos).mean():.1f}%, "
              f"AUC {roc_auc_score(yy, pp):.3f}"
              f"{'' if clean else '  (benign NOT held out - disclosed)'}")

    OUT_MODEL.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_MODEL, "wb") as fh:
        pickle.dump({
            "model": cal, "feature_names": FEATURES_18, "threshold": thr,
            "target_fpr": fpr,
            "trained_on": "data/c3_18feat_dataset.csv, scoped to active "
                          "periodic C2 (error_status_ratio<1.0), "
                          f"<={MAX_WINDOWS_PER_PAIR} windows/pair",
            "calibration": "isotonic, grouped inner CV",
            "scope": results["scope"],
            "LOFO_mean": results["LOFO_mean"],
            "LOPO_mean": results.get("LOPO_mean"),
            "note": "CANDIDATE. Not wired into anomaly_engine.py.",
        }, fh)
    print(f"wrote {OUT_MODEL}")
    with open(OUT_RESULTS, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=1, default=str)
    print(f"wrote {OUT_RESULTS}")


if __name__ == "__main__":
    main()
