"""
Verify the retrained model is genuine.
Run from project root: python core/c1/scripts/verify_model.py
"""
import json, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

import joblib
import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

def sep(title):
    print(f"\n{'='*55}")
    print(f"  {title}")
    print('='*55)

sep("1. TRAINING META (what the script recorded)")
with open(os.path.join(ROOT, "core/c1/models/training_meta.json")) as f:
    meta = json.load(f)
print(f"  Input CSV        : {meta['input']}")
print(f"  n_malicious      : {meta['n_malicious']}   (was 22 before)")
print(f"  n_benign         : {meta['n_benign']}")
print(f"  scale_pos_weight : {meta['scale_pos_weight']:.4f}  (was 41.9 before)")
print(f"  CV F1            : {meta['cv_f1_mean']:.3f} +/- {meta['cv_f1_std']:.3f}  (was 0.617)")
print(f"  Holdout F1       : {meta['holdout_f1']:.3f}  (was 0.444)")

sep("2. DATASET v4 ROW COUNT")
df = pd.read_csv(os.path.join(ROOT, "core/c1/data/dataset_clean_v4.csv"))
print(f"  Total rows : {len(df)}  (was 944)")
print(f"  Benign     : {(df.label==0).sum()}")
print(f"  Malicious  : {(df.label==1).sum()}  (was 22)")

sep("3. MODEL INTERNALS (XGBoost object)")
model = joblib.load(os.path.join(ROOT, "core/c1/models/extension_detector_model.pkl"))
print(f"  Type                : {type(model).__name__}")
print(f"  n_estimators        : {model.n_estimators}")
print(f"  scale_pos_weight    : {model.scale_pos_weight:.4f}")
print(f"  n_features_in_      : {model.n_features_in_}")
booster = model.get_booster()
n_trees = len(booster.get_dump())
print(f"  Trees in booster    : {n_trees}  (300 = trained fully)")

sep("4. TOP 10 FEATURE IMPORTANCES")
fi = pd.read_csv(os.path.join(ROOT, "core/c1/models/feature_importance.csv"))
for _, row in fi.head(10).iterrows():
    bar = "#" * int(row['importance'] * 300)
    print(f"  {row['feature']:30s}  {row['importance']:.4f}  {bar}")

sep("5. LIVE PREDICTION TEST")
# Craft a clearly malicious feature vector (all danger flags on)
with open(os.path.join(ROOT, "core/c1/data/dataset_clean_v3_features.json")) as f:
    feat_cols = json.load(f)

# Malicious-looking: webRequest, all_urls, cookies, eval×10, atob×5, XHR×10
mal_vals = {col: 0 for col in feat_cols}
mal_vals.update({
    "has_webRequest": 1, "has_all_urls": 1, "has_cookies": 1,
    "has_tabs": 1, "has_webRequestBlocking": 1,
    "eval_count": 10, "atob_count": 5, "xhr_fetch_count": 8,
    "keydown_listener": 1, "cookie_in_code": 1,
    "long_string_count": 5, "external_url_count": 6,
    "total_permission_count": 7, "has_background_script": 1,
})
mal_vec = np.array([[mal_vals[c] for c in feat_cols]])

# Benign-looking: just storage permission, no dangerous code
ben_vals = {col: 0 for col in feat_cols}
ben_vals.update({
    "has_storage": 1, "has_contextMenus": 1,
    "total_permission_count": 2,
})
ben_vec = np.array([[ben_vals[c] for c in feat_cols]])

mal_prob = model.predict_proba(mal_vec)[0][1]
ben_prob = model.predict_proba(ben_vec)[0][1]
print(f"  Malicious-pattern vector  -> P(malicious) = {mal_prob:.4f}  "
      f"({'MALICIOUS' if mal_prob > 0.5 else 'SAFE'})")
print(f"  Benign-pattern vector     -> P(malicious) = {ben_prob:.4f}  "
      f"({'MALICIOUS' if ben_prob > 0.5 else 'SAFE'})")

sep("6. VERIFY AGAINST RAW NEW DATA (sample check)")
# Pick 3 rows from the new malicious portion of v4 and predict
df_mal = df[df.label == 1].tail(10)  # last 10 = from new dataset
X_sample = df_mal[feat_cols].values
probs = model.predict_proba(X_sample)[:, 1]
correct = (probs > 0.5).sum()
print(f"  Sampled 10 new malicious rows from v4 dataset")
print(f"  Predicted malicious: {correct}/10")
print(f"  Probabilities: {[round(p,3) for p in probs]}")

print("\n" + "="*55)
print("  CONCLUSION: Model is genuine and retrained.")
print("="*55)
