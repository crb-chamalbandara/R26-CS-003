"""
Measure C3's END-TO-END verdict accuracy as a function of the ML/heuristic
fusion weight, and pick the weight on evidence.

WHY THIS EXISTS
---------------
risk_fusion.py scores `ML_WEIGHT*ml + HEURISTIC_WEIGHT*heuristic` and calls
BEACON at 0.52. With the shipped 0.45/0.55 split, an ML score of 1.0 with no
heuristic corroboration produces 0.45 -- structurally below BEACON. A
"both-signal guard" additionally caps the score at 0.51 whenever either signal
is under 0.10. Together these mean BEACON is unreachable on ML confidence
alone, no matter how good the model is. That guard was justified by the model
being trained on ~110 positives; the deployed model is now isotonic-calibrated
on 50 independent C2 sources with 83.8% LOFO accuracy, so the justification is
worth re-testing rather than assuming.

HOW IT IS MEASURED
------------------
Real feature rows from the in-scope dataset, real ML scores from the DEPLOYED
engine (core.c3.anomaly_engine), real heuristic scores from the DEPLOYED rules
(core.c3.analyzer.C3Analyzer._heuristic_score), and the REAL fusion function
(core.c3.risk_fusion.c3_risk_fusion.fuse) with only the module-level weights
patched. Nothing is reimplemented.

BROWSER CONTEXT, HONESTLY
-------------------------
Network captures carry no browser context, and 4 of the heuristic's inputs are
context features. Two conditions are reported rather than one invented middle:

  A  context-blind  - context features left at analyzer.py's own defaults
                      (user_active_ratio 1.0, background_tab_ratio 0.0,
                      avg_idle_time_ms 0, iat_mean_ms 0 which disables
                      Rules 1/5/8). This is the most-benign assumption and is
                      exactly what interceptor.py falls back to.
  B  background/idle - user_active_ratio 0.0, background_tab_ratio 1.0,
                      avg_idle_time_ms 200000. A LABELLED ASSUMPTION about
                      what a real browser beacon looks like, not measured data.

Verdicts are scored two ways: BEACON-strict (verdict == BEACON) and
SUSPICIOUS+ (verdict != SAFE, i.e. what an analyst actually gets surfaced).

Outputs: data/_c3_fusion_weight_sweep.json
Writes no production file; the weight change itself is applied by hand after
reading the table.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, precision_recall_fscore_support,
                             roc_auc_score)

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from core.c3 import risk_fusion as RF
from core.c3.analyzer import C3Analyzer
from core.c3.anomaly_engine import c3_ml_engine
from train_c3_18feat import FEATURES_18, DATASET
from train_c3_scoped_model import build_scoped

OUT = REPO_ROOT / "data" / "_c3_fusion_weight_sweep.json"

WEIGHTS = [0.45, 0.50, 0.55, 0.60, 0.65, 0.70]
N_SEEDS = 5

CONTEXT_B = {"user_active_ratio": 0.0, "background_tab_ratio": 1.0,
             "avg_idle_time_ms": 200_000.0}


def heuristic_scores(df: pd.DataFrame, context: dict) -> np.ndarray:
    out = np.empty(len(df), dtype=float)
    recs = df[FEATURES_18].to_dict("records")
    for i, feats in enumerate(recs):
        feats.update(context)
        s, _ = C3Analyzer._heuristic_score(feats)
        out[i] = float(s)
    return out


def fused(ml: np.ndarray, heur: np.ndarray, w_ml: float) -> tuple:
    """Call the REAL fuse() with only the weights patched."""
    old_ml, old_h = RF.ML_WEIGHT, RF.HEURISTIC_WEIGHT
    RF.ML_WEIGHT, RF.HEURISTIC_WEIGHT = w_ml, round(1.0 - w_ml, 4)
    try:
        scores = np.empty(len(ml))
        verdicts = np.empty(len(ml), dtype=object)
        for i in range(len(ml)):
            r = RF.c3_risk_fusion.fuse(float(ml[i]), None, float(heur[i]))
            scores[i] = r["score"]
            verdicts[i] = r["verdict"]
    finally:
        RF.ML_WEIGHT, RF.HEURISTIC_WEIGHT = old_ml, old_h
    return scores, verdicts


def balanced_metrics(y, score, pred) -> dict:
    ip, ineg = np.flatnonzero(y == 1), np.flatnonzero(y == 0)
    k = min(len(ip), len(ineg))
    acc, pr, rc, f1, auc = [], [], [], [], []
    for s in range(N_SEEDS):
        rng = np.random.default_rng(1000 + s)
        sel = np.concatenate([rng.choice(ip, k, replace=False),
                              rng.choice(ineg, k, replace=False)])
        ys, ps, sc = y[sel], pred[sel], score[sel]
        p_, r_, f_, _ = precision_recall_fscore_support(
            ys, ps, average="binary", zero_division=0)
        acc.append(accuracy_score(ys, ps)); pr.append(p_); rc.append(r_); f1.append(f_)
        auc.append(roc_auc_score(ys, sc) if 0 < ys.sum() < len(ys) else float("nan"))
    return {"accuracy": round(float(np.mean(acc)), 4),
            "precision": round(float(np.mean(pr)), 4),
            "recall": round(float(np.mean(rc)), 4),
            "f1": round(float(np.mean(f1)), 4),
            "roc_auc": round(float(np.nanmean(auc)), 4)}


def main() -> None:
    raw = pd.read_csv(DATASET)
    df, _ = build_scoped(raw)
    df = df.reset_index(drop=True)
    y = df["label"].to_numpy(int)
    print(f"in-scope: {len(df):,} windows, {int(y.sum())} C2\n")

    X = df[FEATURES_18].to_numpy(float)
    ml = np.array([c3_ml_engine.score(dict(zip(FEATURES_18, row)))[0] or 0.0
                   for row in X])
    print(f"ML score  C2 median={np.median(ml[y==1]):.3f}  "
          f"benign median={np.median(ml[y==0]):.3f}")

    results = {"weights_tested": WEIGHTS, "conditions": {}}
    for cond, ctx in (("A_context_blind", {}), ("B_background_idle", CONTEXT_B)):
        heur = heuristic_scores(df, ctx)
        print(f"\n--- {cond} ---")
        print(f"heuristic C2 median={np.median(heur[y==1]):.3f}  "
              f"benign median={np.median(heur[y==0]):.3f}")
        rows = {}
        for w in WEIGHTS:
            sc, vd = fused(ml, heur, w)
            beacon = (vd == "BEACON").astype(int)
            susp = (vd != "SAFE").astype(int)
            rows[f"{w:.2f}"] = {
                "BEACON_strict": balanced_metrics(y, sc, beacon),
                "SUSPICIOUS_plus": balanced_metrics(y, sc, susp),
                "beacon_rate_on_c2": round(float(beacon[y == 1].mean()), 4),
                "beacon_rate_on_benign": round(float(beacon[y == 0].mean()), 4),
            }
            b = rows[f"{w:.2f}"]["BEACON_strict"]
            s = rows[f"{w:.2f}"]["SUSPICIOUS_plus"]
            print(f"  ML={w:.2f} | BEACON  acc={b['accuracy']:.4f} "
                  f"prec={b['precision']:.4f} rec={b['recall']:.4f} f1={b['f1']:.4f}"
                  f" | SUSP+ acc={s['accuracy']:.4f} prec={s['precision']:.4f} "
                  f"rec={s['recall']:.4f} f1={s['f1']:.4f}")
        results["conditions"][cond] = rows

    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=1, default=str)
    print(f"\nwrote {OUT}")


if __name__ == "__main__":
    main()
