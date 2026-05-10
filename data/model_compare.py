"""Quick model comparison for research panel analysis."""
import pandas as pd, numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.model_selection import train_test_split, StratifiedShuffleSplit
from sklearn.metrics import accuracy_score, roc_auc_score, f1_score

FEATURES = ['iat_mean_ms', 'iat_cv', 'iat_bowley_skewness', 'iat_mad_ms']

df = pd.read_csv('data/c3_extracted_v2.csv')
df = df[['label'] + FEATURES].dropna()
df = df[df['iat_mean_ms'] > 0]

X_b = df[df['label'] == 0][FEATURES].values
X_m = df[df['label'] == 1][FEATURES].values

X_tr, X_te_b = train_test_split(X_b, test_size=0.2, random_state=42)
X_test = np.vstack([X_te_b, X_m])
y_test = np.array([0] * len(X_te_b) + [1] * len(X_m))

results = []

# Isolation Forest (unsupervised)
ifo = IsolationForest(n_estimators=200, contamination=0.02, random_state=42)
ifo.fit(X_tr)
s = ifo.score_samples(X_test)
low, high = np.percentile(ifo.score_samples(X_tr), [5, 95])
norm = 1.0 - np.clip((s - low) / (high - low), 0, 1)
yp = (norm >= 0.6).astype(int)
results.append(('Isolation Forest (unsupervised)', accuracy_score(y_test, yp),
                roc_auc_score(y_test, norm), f1_score(y_test, yp, average='macro'),
                'No beacon labels needed for training'))

# Random Forest (supervised — needs labeled beacon data)
X_all = np.vstack([X_b, X_m])
y_all = np.array([0] * len(X_b) + [1] * len(X_m))
sss = StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
tr_idx, te_idx = next(sss.split(X_all, y_all))
rf = RandomForestClassifier(n_estimators=200, class_weight='balanced', random_state=42, n_jobs=-1)
rf.fit(X_all[tr_idx], y_all[tr_idx])
yp_rf = rf.predict(X_all[te_idx])
prob_rf = rf.predict_proba(X_all[te_idx])[:, 1]
results.append(('Random Forest (supervised)', accuracy_score(y_all[te_idx], yp_rf),
                roc_auc_score(y_all[te_idx], prob_rf), f1_score(y_all[te_idx], yp_rf, average='macro'),
                'Requires labeled beacon data for training'))

# One-Class SVM (unsupervised)
sub = min(3000, len(X_tr))
oc_svm = OneClassSVM(nu=0.05, kernel='rbf', gamma='scale')
oc_svm.fit(X_tr[:sub])
svm_scores = -oc_svm.score_samples(X_test)
yp_svm = (oc_svm.predict(X_test) == -1).astype(int)
results.append(('One-Class SVM (unsupervised)', accuracy_score(y_test, yp_svm),
                roc_auc_score(y_test, svm_scores), f1_score(y_test, yp_svm, average='macro'),
                'Slower, harder to tune, similar to IF'))

print()
print('=' * 70)
print('  Model Comparison  (same 4 features, same test set)')
print('=' * 70)
header = f"  {'Model':<32} {'Accuracy':>10} {'ROC-AUC':>9} {'Macro F1':>9}"
print(header)
print('-' * 70)
for name, acc, auc, mf1, note in results:
    marker = '  <-- chosen' if 'Isolation Forest' in name else ''
    print(f"  {name:<32} {acc*100:>9.2f}% {auc:>9.4f} {mf1:>9.4f}{marker}")
print('=' * 70)
print()
print('  Notes:')
for name, acc, auc, mf1, note in results:
    print(f"    {name:<32}: {note}")
print()
