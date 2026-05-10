"""
Check Google Translate and the test malicious extension against
the recalibrated rule boosters.
Run from project root: python core/c1/scripts/check_false_positive.py
"""
import asyncio, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

GOOGLE_TRANSLATE = "aapbdbdomjkkjkaonfhkkikfgjlloleb"
TEST_EXT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "test_malicious_ext")

async def score(label, manifest_str, source, ext_id):
    from core.c1.analyzer import analyze_extension
    from core.c1.features import extract_manifest_features
    import json as _json
    manifest = _json.loads(manifest_str)
    feats = extract_manifest_features(manifest, source)
    result = await analyze_extension(manifest_str, source, ext_id)
    print(f"\n  [{label}]")
    print(f"    atob_count   : {feats.get('atob_count', 0)}")
    print(f"    eval_count   : {feats.get('eval_count', 0)}")
    print(f"    long_strings : {feats.get('long_string_count', 0)}")
    print(f"    ML prob      : {result['static']['ml_score']*100:.1f}%")
    print(f"    Final score  : {result['score']*100:.1f} / 100")
    print(f"    Verdict      : {result['verdict']}")
    print(f"    Flags        : {result['flags']}")

async def main():
    from core.c1.features import extract_manifest_features
    from core.c1.analyzer import analyze_extension

    # Simulate Google Translate: ML=11.2%, atob_count=3 (confirmed from dashboard screenshot)
    # This was the false positive case — score was forced to 40 by old BASE64_OBFUSCATION rule
    print("Simulating Google Translate feature profile (from dashboard screenshot)...")
    gt_manifest = json.dumps({
        "manifest_version": 3,
        "name": "Google Translate",
        "permissions": ["storage", "contextMenus"],
        "host_permissions": ["<all_urls>"]
    })
    # Build source with exactly 3 atob calls (what Google Translate has) — no eval, no XHR
    gt_source = "atob('abc'); atob('def'); atob('ghi');"
    await score("Google Translate simulation (atob=3, ML=11.2%) — should be SAFE now",
                gt_manifest, gt_source, "google_translate_sim")

    print("\nLoading test malicious extension (should be SUSPICIOUS/MALICIOUS)...")
    with open(os.path.join(TEST_EXT_DIR, "manifest.json")) as f:
        mf2 = json.load(f)
    with open(os.path.join(TEST_EXT_DIR, "background.js")) as f:
        src2 = f.read()
    await score("Test malicious ext", json.dumps(mf2), src2, "test_malicious_ext")

if __name__ == "__main__":
    asyncio.run(main())
