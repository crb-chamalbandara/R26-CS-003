"""
scripts/tune_models.py
──────────────────────
Fine-tune the C2 per-layer models:
  • L1 BitB HTML classifier  ← data/html_features.csv          (16 features)
  • L2 URL classifier        ← notebooks/C2/data/urls_labeled.csv (13 features)

For each: RandomizedSearchCV over XGBoost hyper-parameters (F1-scored, stratified CV),
evaluate on a held-out test split, find the best decision threshold from the PR curve,
and save the retuned model (the previous .pkl is backed up to .pkl.bak). Best params +
metrics are written to notebooks/C2/eval/tuning.json.

Retraining in the current environment also clears the sklearn/xgboost version-mismatch
warnings the shipped pickles emit.

Usage:
    python scripts/tune_models.py            # tune both
    python scripts/tune_models.py --only l1
    python scripts/tune_models.py --n-iter 20
"""
import argparse
import json
import pickle
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EVAL_DIR  = REPO_ROOT / "notebooks" / "C2" / "eval"

try:
    import numpy as np
    import pandas as pd
    from scipy.stats import randint, uniform
    from sklearn.model_selection import train_test_split, RandomizedSearchCV
    from sklearn.metrics import (f1_score, roc_auc_score, precision_recall_curve,
                                 classification_report)
    from xgboost import XGBClassifier
except ImportError as e:
    sys.exit(f"Missing dependency: {e}\nRun: pip install scikit-learn pandas numpy scipy xgboost")

# Feature order MUST match what the layers build at inference time.
L1_FEATURES = ["n_iframes", "has_fixed_iframe", "max_zindex", "full_viewport",
               "drag_prevent", "n_forms", "n_inputs", "n_pw_inputs",
               "n_hidden_inputs", "n_ext_scripts", "form_ext_action",
               "title_brand", "favicon_brand", "has_overlay", "has_redirect",
               "html_size_kb"]
L2_FEATURES = ["url_len", "dots_in_host", "subdomain_depth", "has_ip",
               "is_free_tld", "is_http", "has_free_host", "has_phish_kw",
               "is_short_svc", "brand_in_host", "hyphen_count", "query_len",
               "special_in_path"]

JOBS = {
    "l1": {"csv": REPO_ROOT / "data" / "html_features.csv",
           "features": L1_FEATURES,
           "out": REPO_ROOT / "models" / "bitb_classifier.pkl"},
    "l2": {"csv": REPO_ROOT / "notebooks" / "C2" / "data" / "urls_labeled.csv",
           "features": L2_FEATURES,
           "out": REPO_ROOT / "models" / "url_classifier.pkl"},
}

PARAM_DIST = {
    "n_estimators":     randint(150, 500),
    "max_depth":        randint(3, 9),
    "learning_rate":    uniform(0.02, 0.28),
    "subsample":        uniform(0.7, 0.3),
    "colsample_bytree": uniform(0.7, 0.3),
    "min_child_weight": randint(1, 6),
}


def best_threshold(y_true, proba):
    """Threshold on the PR curve that maximizes F1."""
    prec, rec, thr = precision_recall_curve(y_true, proba)
    f1 = (2 * prec * rec) / (prec + rec + 1e-9)
    i = int(np.nanargmax(f1[:-1])) if len(thr) else 0
    return float(thr[i]) if len(thr) else 0.5, float(f1[i]) if len(thr) else 0.0


def tune_one(key, n_iter):
    job = JOBS[key]
    if not job["csv"].exists():
        print(f"[{key}] CSV missing: {job['csv']} — skipping")
        return None

    df = pd.read_csv(job["csv"])
    X = df[job["features"]]
    y = df["label"].astype(int)
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2,
                                              random_state=42, stratify=y)
    pos_weight = float((y_tr == 0).sum() / max(1, (y_tr == 1).sum()))
    print(f"[{key}] train={len(X_tr):,} test={len(X_te):,} scale_pos_weight={pos_weight:.2f}")

    base = XGBClassifier(eval_metric="logloss", tree_method="hist", device="cpu",
                         scale_pos_weight=pos_weight, random_state=42, n_jobs=-1)
    search = RandomizedSearchCV(base, PARAM_DIST, n_iter=n_iter, scoring="f1",
                                cv=3, random_state=42, n_jobs=-1, verbose=1)
    search.fit(X_tr, y_tr)
    model = search.best_estimator_

    proba = model.predict_proba(X_te)[:, 1]
    auc = float(roc_auc_score(y_te, proba))
    thr, thr_f1 = best_threshold(y_te, proba)
    f1_default = float(f1_score(y_te, (proba >= 0.5).astype(int)))
    print(f"[{key}] best CV F1={search.best_score_:.4f}  test AUC={auc:.4f}  "
          f"F1@0.5={f1_default:.4f}  F1@{thr:.2f}={thr_f1:.4f}")
    print(classification_report(y_te, (proba >= thr).astype(int),
                                target_names=["Legit", "Phish"]))

    # Back up the existing model, then save the retuned one.
    if job["out"].exists():
        shutil.copy2(job["out"], job["out"].with_suffix(".pkl.bak"))
    with open(job["out"], "wb") as f:
        pickle.dump(model, f)
    print(f"[{key}] saved -> {job['out']} (old backed up to .pkl.bak)")

    return {
        "cv_f1": round(float(search.best_score_), 4),
        "test_auc": round(auc, 4),
        "f1_at_0.5": round(f1_default, 4),
        "best_threshold": round(thr, 4),
        "f1_at_best_threshold": round(thr_f1, 4),
        "best_params": {k: (int(v) if isinstance(v, (np.integer,)) else
                            float(v) if isinstance(v, (np.floating,)) else v)
                        for k, v in search.best_params_.items()},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", choices=["l1", "l2"], default=None)
    ap.add_argument("--n-iter", type=int, default=15)
    args = ap.parse_args()

    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    keys = [args.only] if args.only else ["l1", "l2"]
    results = {}
    for k in keys:
        print(f"\n===== Tuning {k.upper()} =====")
        r = tune_one(k, args.n_iter)
        if r:
            results[k] = r

    out = EVAL_DIR / "tuning.json"
    out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\ntuning summary -> {out}")
    print("Restart the backend to load the retuned models.")


if __name__ == "__main__":
    main()
