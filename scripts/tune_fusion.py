"""
scripts/tune_fusion.py
──────────────────────
Tune C2's fusion stage from the captured six-layer vectors
(notebooks/C2/eval/fusion_vectors.csv, produced by capture_fusion_vectors.py):

  1. Train a logistic-regression meta-classifier over the 6 layer scores → a calibrated
     phishing probability. Saved to models/c2_fusion.pkl ONLY if it beats the current
     weighted-sum baseline on a held-out split (so we never regress production).
  2. Derive interpretable weighted-sum weights from the logistic coefficients (the
     fallback used when no meta-classifier is loaded).
  3. Grid-search the SUSPICIOUS / PHISHING verdict thresholds on the production scorer to
     maximize F1 — this is what fixes the under-flagging (BitB pages crossing the line).
  4. Write tuned weights + thresholds into core/settings.json (backed up first).

Usage:
    python scripts/tune_fusion.py
    python scripts/tune_fusion.py --vectors notebooks/C2/eval/fusion_vectors.csv
"""
import argparse
import json
import pickle
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LAYERS    = ["L1", "L2", "L3", "L4", "L5", "L6"]
DEFAULT_WEIGHTS = {"L1": 0.15, "L2": 0.25, "L3": 0.15, "L4": 0.10, "L5": 0.20, "L6": 0.15}

VEC_DEFAULT   = REPO_ROOT / "notebooks" / "C2" / "eval" / "fusion_vectors.csv"
FUSION_OUT    = REPO_ROOT / "models" / "c2_fusion.pkl"
SETTINGS_FILE = REPO_ROOT / "core" / "settings.json"
REPORT_OUT    = REPO_ROOT / "notebooks" / "C2" / "eval" / "tuning_fusion.json"

try:
    import numpy as np
    import pandas as pd
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import roc_auc_score, f1_score, precision_recall_curve
except ImportError as e:
    sys.exit(f"Missing dependency: {e}\nRun: pip install scikit-learn pandas numpy")


def weighted_sum(X, weights):
    return np.clip(sum(X[c].values * weights[c] for c in LAYERS) * 100, 0, 100)


def best_threshold(scores, y):
    """Threshold maximizing F1, plus a higher-recall 'suspicious' threshold."""
    prec, rec, thr = precision_recall_curve(y, scores)
    f1 = (2 * prec * rec) / (prec + rec + 1e-9)
    i = int(np.nanargmax(f1[:-1])) if len(thr) else 0
    phish_thr = float(thr[i]) if len(thr) else 60.0
    # suspicious = lowest threshold keeping precision >= 0.5 (more recall), below phish_thr
    susp_thr = phish_thr
    for p, r, t in zip(prec[:-1], rec[:-1], thr):
        if p >= 0.5 and t < phish_thr:
            susp_thr = float(t); break
    return round(susp_thr, 1), round(phish_thr, 1), float(f1[i])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vectors", type=Path, default=VEC_DEFAULT)
    ap.add_argument("--apply", action="store_true",
                    help="write tuned weights/thresholds to settings.json and save "
                         "c2_fusion.pkl. Default is a dry-run report only (recommended "
                         "until you trust the capture corpus — batch-rendered saved HTML "
                         "under-represents the live L6/L3 signals).")
    args = ap.parse_args()

    if not args.vectors.exists():
        sys.exit(f"Vectors not found: {args.vectors}\nRun capture_fusion_vectors.py first.")
    df = pd.read_csv(args.vectors)
    X, y = df[LAYERS], df["label"].astype(int)
    print(f"[fusion] {len(df)} vectors  (phish {int(y.sum())} / legit {int((y==0).sum())})")
    if y.nunique() < 2:
        sys.exit("Need both classes in the vectors to tune fusion.")

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)

    # Baseline: current weighted-sum on the test split.
    base_scores = weighted_sum(Xte, DEFAULT_WEIGHTS)
    base_auc = float(roc_auc_score(yte, base_scores))

    # Learned meta-classifier.
    clf = LogisticRegression(max_iter=1000, class_weight="balanced")
    clf.fit(Xtr, ytr)
    proba = clf.predict_proba(Xte)[:, 1]
    learned_auc = float(roc_auc_score(yte, proba))

    # Weights from logistic coefficients (clip negatives, normalize to sum 1).
    coefs = np.clip(clf.coef_[0], 0, None)
    weights = (dict(DEFAULT_WEIGHTS) if coefs.sum() == 0
               else {c: round(float(w), 4) for c, w in zip(LAYERS, coefs / coefs.sum())})

    keep_pkl = learned_auc >= max(0.80, base_auc)
    if keep_pkl:
        production_scores = proba * 100
        scorer = "learned meta-classifier (c2_fusion.pkl)"
    else:
        production_scores = weighted_sum(Xte, weights)
        scorer = "weighted sum (tuned weights)"

    susp_thr, phish_thr, best_f1 = best_threshold(production_scores, yte)

    # ── Persist (only with --apply) ───────────────────────────────────────────
    if args.apply:
        if keep_pkl:
            with open(FUSION_OUT, "wb") as f:
                pickle.dump(clf, f)
            print(f"[fusion] saved learned model -> {FUSION_OUT}")
        else:
            if FUSION_OUT.exists():
                FUSION_OUT.unlink()  # remove stale model so analyze() uses weighted sum
            print("[fusion] learned model did not beat baseline — keeping weighted-sum fusion")

        if SETTINGS_FILE.exists():
            shutil.copy2(SETTINGS_FILE, SETTINGS_FILE.with_suffix(".json.bak"))
            cfg = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        else:
            cfg = {}
        cfg["weights"] = weights
        cfg["verdict_suspicious"] = int(round(susp_thr))
        cfg["verdict_phishing"]   = int(round(phish_thr))
        cfg["warn_threshold"]     = int(round(susp_thr))
        cfg["block_threshold"]    = int(round(phish_thr))
        SETTINGS_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    else:
        print("[fusion] DRY-RUN — no files written (re-run with --apply to persist)")

    report = {
        "n_vectors": int(len(df)),
        "baseline_weighted_auc": round(base_auc, 4),
        "learned_auc": round(learned_auc, 4),
        "kept_learned_model": keep_pkl,
        "production_scorer": scorer,
        "tuned_weights": weights,
        "verdict_suspicious": int(round(susp_thr)),
        "verdict_phishing": int(round(phish_thr)),
        "f1_at_phishing_threshold": round(best_f1, 4),
    }
    REPORT_OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\n========== C2 FUSION TUNING ==========")
    print(f"baseline weighted AUC : {base_auc:.4f}")
    print(f"learned meta AUC      : {learned_auc:.4f}  (kept={keep_pkl})")
    print(f"production scorer     : {scorer}")
    print(f"tuned weights         : {weights}")
    print(f"verdict thresholds    : SUSPICIOUS>={int(round(susp_thr))}  PHISHING>={int(round(phish_thr))}")
    print(f"F1 @ phishing cutoff  : {best_f1:.4f}")
    print(f"\nreport -> {REPORT_OUT}")
    if args.apply:
        print(f"settings updated -> {SETTINGS_FILE} (backup .json.bak)")
        print("Restart the backend to load the tuned fusion.")
    else:
        print("dry-run: settings.json and models/c2_fusion.pkl unchanged — add --apply to persist")


if __name__ == "__main__":
    main()
