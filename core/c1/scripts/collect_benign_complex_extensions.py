"""
Collect benign extensions that specifically have complex permission profiles —
has_scripting=1, broad host permissions, background scripts — so the ML model
learns these patterns are NOT inherently malicious.

Without these examples the model sees has_scripting + all_urls + background_script
only in malicious extensions and flags every legitimate power extension.

Source: popular, long-standing Chrome Web Store extensions with millions of users,
manually verified as benign by the security community.

Run from project root:
    python core/c1/scripts/collect_benign_complex_extensions.py
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

ROOT      = Path(__file__).resolve().parents[3]
DATA_DIR  = ROOT / "core" / "c1" / "data"
FEAT_JSON = DATA_DIR / "dataset_clean_v3_features.json"
OUT_CSV   = DATA_DIR / "benign_complex_extensions.csv"

# These extensions were specifically chosen because they have:
#   - has_scripting=1 and/or high host_permission_count
#   - Millions of users — extensively reviewed by security community
#   - Official developer pages confirming legitimate publisher
# Source validation: Chrome Web Store featured/Editor's picks + user count
COMPLEX_BENIGN = [
    # PDF / document tools that use scripting API
    ("efaidnbmnnnibpcajpcglclefindmkaj", "Adobe Acrobat PDF"),
    ("oemmndcbldboiebfnladdacbdfmadadm", "Google Docs Offline"),

    # Privacy / ad-blocking that use webRequest + all_urls
    ("cjpalhdlnbpafiamejdnhcphjbkeiagm", "uBlock Origin"),
    ("gighmmpiobklfepjocnamgkkbiglidom", "AdBlock"),
    ("cfhdojbkjhnklbpkdaibdccddilifddb", "Adblock Plus"),
    ("epcnnfbjfcgphgdmggkamkmgojdagdnn", "Ghostery"),

    # Writing assistants that inject into every page
    ("kbfnbcaeplbcioakkpcpgfkobkghlhen", "Grammarly"),
    ("lnkdbjbjpnpjeciipoaflmpcddinpjjp", "Wordtune"),

    # Password managers with broad host access
    ("hdokiejnpimakedhajhdlcegeplioahd", "LastPass"),
    ("fdjamakpfbbddfjaooikfcpapjohcfmg", "Dashlane"),
    ("inlghmklhgfgljglhjmpjllknlhgkkig", "1Password"),

    # Shopping / price comparison that scrape all pages
    ("nenlahapcbofgnanklpelkaejcehkggg", "Honey by PayPal"),
    ("ajlcnbbeidbackfknkgknjefhmbngdnj", "Capital One Shopping"),

    # Developer tools
    ("fmkadmapgofadopljbjfkapdkoienihi", "React Developer Tools"),
    ("nhdogjmejiglipccpnnnanhbledajbpd", "Vue.js DevTools"),
    ("jnkmfdileelhofjcijamephohjechhna", "ColorZilla"),

    # Dark mode / page styling that modify every page
    ("eimadpbcbfnmbkopoojfekhnkhdbieeh", "Dark Reader"),
    ("mjdepdfccjgcndkmemponafgioodelna", "Night Eye"),

    # Translation
    ("aapbdbdomjkkjkaonfhkkikfgjlloleb", "Google Translate"),
    ("ibggnolnpgfbgbpnhibnbibgngcgpgme", "ImTranslator"),

    # Screen capture / recording
    ("hniebljpgcogalllopieghgafnhdopdp", "Loom"),
    ("mcbpblocgmgfnpjjppndjkmgjaogfceg", "Nimbus Screenshot"),
]


async def download_and_extract(ext_id: str, name: str, feat_cols: list) -> dict | None:
    try:
        from core.c1.crx_utils import fetch_crx_from_store, parse_crx_bytes
        from core.c1.features import extract_manifest_features, build_feature_vector

        crx = await fetch_crx_from_store(ext_id, timeout=30.0)
        manifest, source, _ = parse_crx_bytes(crx, ext_id)
        features = extract_manifest_features(manifest, source or "")
        vector   = build_feature_vector(feat_cols, features)
        row = dict(zip(feat_cols, vector))
        row["label"]        = 0
        row["extension_id"] = ext_id

        scripting  = int(features.get("has_scripting", 0))
        host_perm  = int(features.get("host_permission_count", 0))
        all_urls   = int(features.get("has_all_urls", 0))
        print(f"  OK  {name:35s} scripting={scripting} host_perm={host_perm} all_urls={all_urls}")
        return row

    except Exception as exc:
        print(f"  --  {name:35s} FAILED ({type(exc).__name__})")
        return None


async def main() -> None:
    with open(FEAT_JSON) as f:
        feat_cols: list = json.load(f)

    print(f"Collecting {len(COMPLEX_BENIGN)} benign complex extensions...\n")
    print(f"  {'Name':35s} scripting  host_perm  all_urls")
    print(f"  {'-'*35} ---------  ---------  --------")

    rows = []
    for ext_id, name in COMPLEX_BENIGN:
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

    n_scripting  = int((df["has_scripting"] > 0).sum())
    n_all_urls   = int((df["has_all_urls"] > 0).sum())
    n_background = int((df["has_background_script"] > 0).sum())

    print(f"\nSaved {len(rows)} benign complex extensions → {OUT_CSV.name}")
    print(f"\nCoverage of underrepresented features:")
    print(f"  has_scripting=1      : {n_scripting}/{len(rows)} extensions")
    print(f"  has_all_urls=1       : {n_all_urls}/{len(rows)} extensions")
    print(f"  has_background=1     : {n_background}/{len(rows)} extensions")
    print(f"\nRun retrain_with_new_data.py to incorporate these into the model.")


if __name__ == "__main__":
    asyncio.run(main())
