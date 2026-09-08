"""
Build pooled out-of-fold predictions for ML_Publish.ipynb's performance
charts (ROC curve, precision-recall curve, confusion matrix, score
distribution, calibration curve).

WHY POOLED, AND WHY LOFO ONLY
-----------------------------
Each LOFO fold refits a model with that entire malware family withheld, so
its predictions on that family are genuinely out-of-sample. Pooling the
RELIABLE folds (>= MIN_POS_RELIABLE positives: FastFlux, Neris, ZeusV1) into
one array is the standard cross-validation technique for a single
representative curve — equivalent to sklearn's cross_val_predict.

LOFO is used rather than LOPO for this because its NORMAL_FOLD_ASSIGNMENT
benign captures are disjoint per family (verified below: no capture is
assigned to two families), so pooling introduces no duplicate benign window.
LOPO's benign sides overlap across pairs of the same family and would
double-count some windows if pooled the same way — a real methodology
difference, not a preference.

Outputs: data/_c3_curve_data.json
Touches no production file; read only by scripts/build_ml_publish_notebook.py.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from train_c3_18feat import DATASET, FEATURES_18, MIN_POS_RELIABLE, family_weights
from train_c3_scoped_model import (build_scoped, fit_calibrated, pick_target_fpr,
                                   threshold_at_fpr, NORMAL_FOLD_ASSIGNMENT)

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT = REPO_ROOT / "data" / "_c3_curve_data.json"


def main() -> None:
    # disjointness check the module docstring claims
    seen = {}
    for fam, caps in NORMAL_FOLD_ASSIGNMENT.items():
        for c in caps:
            assert c not in seen, f"{c} assigned to both {seen[c]} and {fam}"
            seen[c] = fam
    print(f"verified: {len(seen)} normal-* captures, each assigned to exactly "
          f"one family\n")

    raw = pd.read_csv(DATASET)
    df, _ = build_scoped(raw)
    df = df.reset_index(drop=True)

    X_all = df[FEATURES_18].to_numpy(float)
    y_all = df["label"].to_numpy(int)
    fam_all = df["family"].to_numpy(str)
    grp_all = df["group"].to_numpy(str)

    y_true_pool, proba_pool, pred_pool, fam_pool = [], [], [], []
    fold_info = {}

    for held in sorted(set(fam_all[y_all == 1])):
        hg = set(df.loc[fam_all == held, "group"].unique())
        hg |= set(NORMAL_FOLD_ASSIGNMENT.get(held, []))
        test_mask = np.isin(grp_all, list(hg))
        train_mask = ~test_mask
        if y_all[train_mask].sum() == 0 or y_all[test_mask].sum() == 0:
            continue
        n_pos = int(y_all[test_mask].sum())
        if n_pos < MIN_POS_RELIABLE:
            print(f"skip {held:10s}: only {n_pos} positives (< {MIN_POS_RELIABLE})")
            continue

        w = family_weights(fam_all[train_mask], y_all[train_mask], grp_all[train_mask])
        fpr = pick_target_fpr(X_all[train_mask], y_all[train_mask],
                              grp_all[train_mask], fam_all[train_mask])
        cal = fit_calibrated(X_all[train_mask], y_all[train_mask], w, grp_all[train_mask])
        p = cal.predict_proba(X_all[test_mask])[:, 1]
        yt = y_all[test_mask]
        thr = threshold_at_fpr(p[yt == 0], fpr)
        pred = (p >= thr).astype(int)

        y_true_pool.append(yt)
        proba_pool.append(p)
        pred_pool.append(pred)
        fam_pool.append(np.full(len(yt), held))
        fold_info[held] = {"n_test": int(len(yt)), "n_positives": n_pos,
                           "target_fpr": fpr, "threshold": thr}
        print(f"{held:10s} n_test={len(yt):6d} pos={n_pos:5d} "
              f"fpr={fpr:.2f} thr={thr:.4f}")

    y_true = np.concatenate(y_true_pool)
    proba = np.concatenate(proba_pool)
    pred = np.concatenate(pred_pool)
    fam = np.concatenate(fam_pool)

    print(f"\npooled out-of-fold: {len(y_true):,} windows, {int(y_true.sum())} "
          f"C2, {len(fold_info)} folds {list(fold_info.keys())}")

    out = {
        "protocol": "LOFO pooled out-of-fold predictions, reliable folds only "
                    f"(n_positives >= {MIN_POS_RELIABLE}). Each fold's model "
                    "never saw that family during fitting, calibration, or "
                    "thresholding -- these are genuine held-out predictions, "
                    "not in-sample.",
        "folds": fold_info,
        "y_true": y_true.tolist(),
        "proba": proba.tolist(),
        "pred_at_fold_threshold": pred.tolist(),
        "family": fam.tolist(),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(out, fh)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
