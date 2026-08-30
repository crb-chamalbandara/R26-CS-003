"""
C1 — collect_benign_power_extensions.py  |  Benign Power Extension Collector
-------------------------------------------------------------------------------
Purpose : Download CRX files for well-known SAFE extensions that have complex
          permission profiles (broad host access, background scripts, eval, etc.)
          and extract their 33 features as benign (label=0) training examples.

Why this was needed:
  The ML model was falsely flagging legitimate complex extensions like Adobe
  Acrobat as MALICIOUS (89% probability) because the original 922 benign
  training examples were all simple extensions.  The model had never seen a
  legitimate extension with broad permissions, so it assumed all
  permission-heavy extensions were malicious.  Adding these examples
  teaches the model that high host_permission_count is NOT always malicious.

Output: benign_power_extensions.csv — automatically included by retrain_with_new_data.py.

Run from project root:
    python core/c1/scripts/collect_benign_power_extensions.py
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))   # add project root to Python path

ROOT      = Path(__file__).resolve().parents[3]
C1_DIR    = ROOT / "core" / "c1"
DATA_DIR  = C1_DIR / "data"
FEAT_JSON = DATA_DIR / "dataset_clean_v3_features.json"   # 33 feature column names in correct order
OUT_CSV   = DATA_DIR / "benign_power_extensions.csv"      # output file consumed by retrain script

# Known safe extensions with complex permission profiles.
# These are official extensions from major publishers with millions of verified users.
# Tuple format: (extension_id, display_name)
KNOWN_BENIGN_POWER = [
    ("efaidnbmnnnibpcajpcglclefindmkaj", "Adobe Acrobat"),       # PDF tool — needs all_urls + scripting
    ("kbfnbcaeplbcioakkpcpgfkobkghlhen", "Grammarly"),           # writing assistant — injects into all pages
    ("cfhdojbkjhnklbpkdaibdccddilifddb", "Adblock Plus"),        # ad blocker — uses webRequestBlocking
    ("gighmmpiobklfepjocnamgkkbiglidom", "AdBlock"),             # ad blocker — uses webRequestBlocking
    ("cjpalhdlnbpafiamejdnhcphjbkeiagm", "uBlock Origin"),       # ad blocker — uses webRequestBlocking
    ("hdokiejnpimakedhajhdlcegeplioahd", "LastPass"),            # password manager — needs cookies + tabs
    ("eimadpbcbfnmbkopoojfekhnkhdbieeh", "Dark Reader"),         # dark mode — injects into all pages
    ("bhlhnicpbhignbdhedgjmacdnbdnbidf", "Video Speed Controller"), # video tool — content script on all pages
    ("mnjggcdmjocbbbhaepdhchncahnbgone", "SponsorBlock"),        # YouTube tool — reads all YouTube pages
    ("nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask"),            # crypto wallet — high host_permission_count
    ("bmnlcjabgnpnenekpadlanbbkooimhnj", "Honey"),                # coupon finder — all_urls + background
    ("nngceckbapebfimnlniiiahkandclblb", "Bitwarden"),            # password manager — cookies + tabs + all_urls
    ("aeblfdkhhhdcdjpifhhbdiojplfjncoa", "1Password"),            # password manager — clipboard + all_urls
    ("ghbmnnjooekpmoecnnnilnnbdlolhkhi", "Google Docs Offline"),  # storage + background, Google-published
    ("liecbddmkiiihnedobmlmillhodjkdmb", "Loom"),                 # screen recorder — tabs + all_urls + background
]


async def download_and_extract(ext_id: str, name: str, feat_cols: list, retries: int = 3) -> dict | None:
    """Download one CRX from Google's update server, parse it, and extract 33 features.
    Returns a feature dict with label=0 (benign), or None if download/parsing failed.
    Retries on transient network errors (this environment's DNS drops mid-batch sometimes)."""
    import asyncio
    from core.c1.crx_utils import fetch_crx_from_store, parse_crx_bytes
    from core.c1.features  import extract_manifest_features, build_feature_vector

    print(f"  Downloading {name} ({ext_id})...", end=" ", flush=True)
    last_exc: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            crx      = await fetch_crx_from_store(ext_id, timeout=30.0)   # download CRX binary from Google
            manifest, source, _ = parse_crx_bytes(crx, ext_id)            # parse CRX → manifest dict + JS source
            features = extract_manifest_features(manifest, source or "")  # extract 33 numeric features
            vector   = build_feature_vector(feat_cols, features)           # order features correctly for model
            row      = dict(zip(feat_cols, vector))   # create dict: feature_name → value
            row["label"]        = 0                   # label=0 means BENIGN
            row["extension_id"] = ext_id
            print(f"OK  (host_perm={features.get('host_permission_count',0)}, "
                  f"eval={features.get('eval_count',0)}, atob={features.get('atob_count',0)})")
            return row
        except Exception as exc:
            last_exc = exc
            if attempt < retries:
                await asyncio.sleep(1.5 * attempt)   # brief backoff before retry
    print(f"FAILED after {retries} attempts ({last_exc})")
    return None


async def main() -> None:
    # Load the 33 feature column names — same order used by the production model
    with open(FEAT_JSON) as f:
        feat_cols: list = json.load(f)

    print(f"Collecting {len(KNOWN_BENIGN_POWER)} benign power extensions...\n")
    rows = []
    for ext_id, name in KNOWN_BENIGN_POWER:
        row = await download_and_extract(ext_id, name, feat_cols)
        if row:
            rows.append(row)

    import pandas as pd

    # Merge with whatever succeeded on a previous run instead of overwriting —
    # this environment's DNS drops mid-batch sometimes, and a partial failure
    # here shouldn't destroy extensions collected successfully before.
    existing_rows = []
    if OUT_CSV.exists():
        try:
            existing_rows = pd.read_csv(OUT_CSV).to_dict("records")
        except Exception:
            existing_rows = []

    merged = {r["extension_id"]: r for r in existing_rows if "extension_id" in r}
    merged.update({r["extension_id"]: r for r in rows})   # new results win on conflict

    if not merged:
        print("\nNo extensions downloaded and no prior data on disk. Check network access.")
        return

    df     = pd.DataFrame(list(merged.values()))
    df_out = df[feat_cols + ["label", "extension_id"]]
    df_out.to_csv(OUT_CSV, index=False)

    print(f"\nSaved {len(rows)} newly downloaded this run "
          f"({len(merged)} total after merging with prior data) → {OUT_CSV.name}")
    print("\nFeature profiles (key features):")
    for _, row in df.iterrows():
        print(f"  {row['extension_id'][:20]}  "
              f"host_perm={row.get('host_permission_count',0):.0f}  "
              f"eval={row.get('eval_count',0):.0f}  "
              f"atob={row.get('atob_count',0):.0f}  "
              f"has_all_urls={row.get('has_all_urls',0):.0f}")

    print(f"\nNext step: run retrain_with_new_data.py to incorporate these into the model.")


if __name__ == "__main__":
    asyncio.run(main())
