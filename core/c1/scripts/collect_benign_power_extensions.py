"""
Download CRX files for well-known legitimate power extensions and extract
their features into the benign training set.

These extensions have broad permissions, background scripts, content scripts,
and complex code — the same profile as malicious extensions. Without them,
the ML model falsely flags any permission-heavy extension as malicious.

Run from project root:
    python core/c1/scripts/collect_benign_power_extensions.py

This outputs benign_power_extensions.csv, which retrain_with_new_data.py
will automatically include in the next training run.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

ROOT     = Path(__file__).resolve().parents[3]
C1_DIR   = ROOT / "core" / "c1"
DATA_DIR = C1_DIR / "data"
FEAT_JSON = DATA_DIR / "dataset_clean_v3_features.json"
OUT_CSV   = DATA_DIR / "benign_power_extensions.csv"

# Well-known legitimate extensions with broad permissions.
# These teach the model that high host_permission_count is not always malicious.
KNOWN_BENIGN_POWER = [
    ("efaidnbmnnnibpcajpcglclefindmkaj", "Adobe Acrobat"),
    ("kbfnbcaeplbcioakkpcpgfkobkghlhen", "Grammarly"),
    ("cfhdojbkjhnklbpkdaibdccddilifddb", "Adblock Plus"),
    ("gighmmpiobklfepjocnamgkkbiglidom", "AdBlock"),
    ("cjpalhdlnbpafiamejdnhcphjbkeiagm", "uBlock Origin"),
    ("hdokiejnpimakedhajhdlcegeplioahd", "LastPass"),
    ("eimadpbcbfnmbkopoojfekhnkhdbieeh", "Dark Reader"),
    ("bhlhnicpbhignbdhedgjmacdnbdnbidf", "Video Speed Controller"),
    ("mnjggcdmjocbbbhaepdhchncahnbgone", "SponsorBlock"),
    ("nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask"),
]


async def download_and_extract(ext_id: str, name: str, feat_cols: list) -> dict | None:
    try:
        from core.c1.crx_utils import fetch_crx_from_store, parse_crx_bytes
        from core.c1.features import extract_manifest_features, build_feature_vector

        print(f"  Downloading {name} ({ext_id})...", end=" ", flush=True)
        crx = await fetch_crx_from_store(ext_id, timeout=30.0)
        manifest, source, _ = parse_crx_bytes(crx, ext_id)
        features = extract_manifest_features(manifest, source or "")
        vector   = build_feature_vector(feat_cols, features)
        row = dict(zip(feat_cols, vector))
        row["label"]        = 0   # benign
        row["extension_id"] = ext_id
        print(f"OK  (host_perm={features.get('host_permission_count',0)}, "
              f"eval={features.get('eval_count',0)}, atob={features.get('atob_count',0)})")
        return row
    except Exception as exc:
        print(f"FAILED ({exc})")
        return None


async def main() -> None:
    with open(FEAT_JSON) as f:
        feat_cols: list = json.load(f)

    print(f"Collecting {len(KNOWN_BENIGN_POWER)} benign power extensions...\n")
    rows = []
    for ext_id, name in KNOWN_BENIGN_POWER:
        row = await download_and_extract(ext_id, name, feat_cols)
        if row:
            rows.append(row)

    if not rows:
        print("\nNo extensions downloaded. Check network access.")
        return

    import pandas as pd
    df = pd.DataFrame(rows)
    df_out = df[feat_cols + ["label"]]
    df_out.to_csv(OUT_CSV, index=False)

    print(f"\nSaved {len(rows)} benign power extensions → {OUT_CSV.name}")
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
