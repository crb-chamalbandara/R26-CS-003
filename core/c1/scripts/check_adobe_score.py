"""Check Adobe Acrobat score after retraining. Run from project root."""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
import joblib, numpy as np

feat_cols = json.load(open("core/c1/data/dataset_clean_v3_features.json"))
model = joblib.load("core/c1/models/extension_detector_model.pkl")

def verdict(p):
    if p >= 0.7: return "MALICIOUS"
    if p >= 0.4: return "SUSPICIOUS"
    return "SAFE"

def check(label, overrides):
    row = {c: 0 for c in feat_cols}
    row.update(overrides)
    vec = np.array([[row[c] for c in feat_cols]])
    prob = model.predict_proba(vec)[0][1]
    print(f"  {label:35s}  ML={prob*100:.1f}%  -> {verdict(prob)}")

print("=== ML scores after retraining with power benign extensions ===\n")

# Adobe Acrobat (extracted features from actual CRX)
check("Adobe Acrobat (actual features)", {
    "has_all_urls": 1, "has_background_script": 1, "has_content_scripts": 1,
    "host_permission_count": 1, "total_permission_count": 3,
    "has_scripting": 1, "has_storage": 1,
})

# MetaMask (host_permission_count=6)
check("MetaMask (host_perm=6)", {
    "host_permission_count": 6, "has_background_script": 1,
    "total_permission_count": 5, "has_storage": 1, "has_tabs": 1,
})

# uBlock Origin
check("uBlock Origin (has_all_urls, complex)", {
    "has_all_urls": 1, "has_webRequest": 1, "has_background_script": 1,
    "has_storage": 1, "total_permission_count": 4,
})

# Clearly malicious: webRequestBlocking + eval + atob + external + cookies
check("Clearly malicious pattern", {
    "has_webRequest": 1, "has_webRequestBlocking": 1, "has_all_urls": 1,
    "has_cookies": 1, "eval_count": 10, "atob_count": 8,
    "xhr_fetch_count": 8, "long_string_count": 6, "external_url_count": 8,
    "has_background_script": 1, "total_permission_count": 8,
    "host_permission_count": 5,
})

# Simple benign
check("Simple benign (storage + contextMenus)", {
    "has_storage": 1, "has_contextMenus": 1, "total_permission_count": 2,
})

print()
print("=== Sandbox scoring changes ===")
print("  COOKIE_EXFILTRATION_RISK : only fires when extension READS cookies")
print("    (test page cookie_write no longer counted as evidence)")
print("  HIGH_REQUEST_VOLUME      : threshold raised 8 -> 20")
print("    (cloud extensions making 10-15 background requests no longer flagged)")
