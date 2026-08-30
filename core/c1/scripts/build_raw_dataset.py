"""
Build a human-readable RAW dataset for viva demonstration.

Shows the actual text values extracted from extension files BEFORE
they are converted to 0/1 numbers by features.py.

Columns produced:
  extension_id, name, manifest_version, permissions (text list),
  host_permissions (text list), has_background, has_content_scripts,
  eval_occurrences, atob_occurrences, websocket_occurrences,
  xhr_fetch_occurrences, keydown_listener, cookie_access,
  external_urls_sample, label (BENIGN / MALICIOUS)

Run from project root:
    python core/c1/scripts/build_raw_dataset.py
"""
from __future__ import annotations

import asyncio
import io
import json
import os
import re
import struct
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import pandas as pd

ROOT     = Path(__file__).resolve().parents[3]
DATA_DIR = ROOT / "core" / "c1" / "data"
OUT_CSV  = DATA_DIR / "dataset_raw_demo.csv"

MAL_FOLDERS = [
    DATA_DIR / "MaliciousBrowserExtensions" / "AutomatedExtensions",
    DATA_DIR / "MaliciousBrowserExtensions" / "Malicious Browser Extensions",
]

# Benign extension IDs to download for the benign side of the demo
BENIGN_IDS = [
    ("cjpalhdlnbpafiamejdnhcphjbkeiagm", "uBlock Origin"),
    ("kbfnbcaeplbcioakkpcpgfkobkghlhen", "Grammarly"),
    ("efaidnbmnnnibpcajpcglclefindmkaj", "Adobe Acrobat"),
    ("eimadpbcbfnmbkopoojfekhnkhdbieeh", "Dark Reader"),
    ("nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask"),
    ("cfhdojbkjhnklbpkdaibdccddilifddb", "Adblock Plus"),
    ("hdokiejnpimakedhajhdlcegeplioahd", "LastPass"),
    ("aapbdbdomjkkjkaonfhkkikfgjlloleb", "Google Translate"),
    ("mnjggcdmjocbbbhaepdhchncahnbgone", "SponsorBlock"),
    ("oemmndcbldboiebfnladdacbdfmadadm", "Google Docs Offline"),
]

# ── Regex patterns (same as features.py) ─────────────────────────────────────
_RE_EVAL     = re.compile(r'\beval\s*\(')
_RE_ATOB     = re.compile(r'\batob\s*\(')
_RE_WS       = re.compile(r'\bWebSocket\s*\(')
_RE_XHR      = re.compile(r'\b(XMLHttpRequest|fetch)\s*[(\.]')
_RE_KEYDOWN  = re.compile(r'\b(keydown|keypress|keyup)\b', re.IGNORECASE)
_RE_COOKIE   = re.compile(r'(document\.cookie|chrome\.cookies)')
_RE_EXT_URL  = re.compile(r'https?://[^\s\'">/]{10,}', re.IGNORECASE)
_RE_LONG_STR = re.compile(r'[A-Za-z0-9+/=]{100,}')


def _crx_to_zip(data: bytes) -> bytes:
    if data[:4] != b"Cr24":
        raise ValueError("Not a CRX file")
    version = struct.unpack_from("<I", data, 4)[0]
    if version == 2:
        pub = struct.unpack_from("<I", data, 8)[0]
        sig = struct.unpack_from("<I", data, 12)[0]
        start = 16 + pub + sig
    elif version == 3:
        hlen = struct.unpack_from("<I", data, 8)[0]
        start = 12 + hlen
    else:
        raise ValueError(f"Unsupported CRX version {version}")
    return data[start:]


def extract_raw(crx_bytes: bytes, ext_id: str, label: str) -> dict | None:
    """Extract human-readable raw fields from a CRX binary."""
    try:
        zip_bytes = _crx_to_zip(crx_bytes)
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            names = zf.namelist()

            # Read manifest.json
            mf_name = next((n for n in names if n.lower().endswith("manifest.json")), None)
            if not mf_name:
                return None
            manifest = json.loads(zf.read(mf_name).decode("utf-8", errors="ignore"))

            # Concatenate JS (up to 300k chars)
            parts, total = [], 0
            for n in names:
                if not n.lower().endswith(".js"):
                    continue
                try:
                    chunk = zf.read(n).decode("utf-8", errors="ignore")
                    remaining = 300_000 - total
                    if remaining <= 0:
                        break
                    parts.append(chunk[:remaining])
                    total += len(chunk)
                except Exception:
                    pass
            source = "\n".join(parts)

        # ── Raw manifest fields ──
        perms        = manifest.get("permissions", [])
        host_perms   = manifest.get("host_permissions", [])
        name         = manifest.get("name", "—")[:60]
        mv           = manifest.get("manifest_version", "?")
        has_bg       = "YES" if manifest.get("background") else "NO"
        has_cs       = "YES" if manifest.get("content_scripts") else "NO"
        has_war      = "YES" if manifest.get("web_accessible_resources") else "NO"

        # ── Raw JS pattern counts ──
        eval_n   = len(_RE_EVAL.findall(source))
        atob_n   = len(_RE_ATOB.findall(source))
        ws_n     = len(_RE_WS.findall(source))
        xhr_n    = len(_RE_XHR.findall(source))
        key_n    = len(_RE_KEYDOWN.findall(source))
        cookie_n = len(_RE_COOKIE.findall(source))
        long_n   = len(_RE_LONG_STR.findall(source))

        # Sample of external URLs found (first 3, truncated)
        ext_urls = list(set(_RE_EXT_URL.findall(source)))[:3]
        ext_url_sample = " | ".join(u[:60] for u in ext_urls) if ext_urls else "none"

        return {
            "extension_id"         : ext_id,
            "name"                 : name,
            "manifest_version"     : mv,
            "permissions"          : ", ".join(perms) if perms else "(none)",
            "host_permissions"     : ", ".join(host_perms[:5]) if host_perms else "(none)",
            "has_background_script": has_bg,
            "has_content_scripts"  : has_cs,
            "web_accessible_res"   : has_war,
            "eval_occurrences"     : eval_n,
            "atob_occurrences"     : atob_n,
            "websocket_usage"      : ws_n,
            "xhr_fetch_usage"      : xhr_n,
            "keydown_listener"     : "YES" if key_n > 0 else "NO",
            "cookie_access"        : "YES" if cookie_n > 0 else "NO",
            "long_encoded_strings" : long_n,
            "external_urls_sample" : ext_url_sample,
            "label"                : label,
        }
    except Exception as exc:
        return None


async def download_benign(ext_id: str) -> bytes | None:
    try:
        from core.c1.crx_utils import fetch_crx_from_store
        return await fetch_crx_from_store(ext_id, timeout=20.0)
    except Exception:
        return None


async def main() -> None:
    rows = []

    # ── 1. Malicious CRX files (from local dataset) ───────────────
    print("Processing malicious CRX files...")
    mal_count = 0
    for folder in MAL_FOLDERS:
        if not folder.exists():
            continue
        crx_files = list(folder.glob("*.crx"))
        # Take up to 20 per folder for a representative sample
        for crx_path in crx_files[:20]:
            ext_id = crx_path.stem.lower()
            try:
                data = crx_path.read_bytes()
                row  = extract_raw(data, ext_id, "MALICIOUS")
                if row:
                    rows.append(row)
                    mal_count += 1
            except Exception:
                pass
    print(f"  Malicious rows collected: {mal_count}")

    # ── 2. Benign CRX files (downloaded from Chrome Web Store) ────
    print("Downloading benign extension CRX files...")
    ben_count = 0
    for ext_id, friendly_name in BENIGN_IDS:
        print(f"  Downloading {friendly_name} ({ext_id})...", end=" ", flush=True)
        crx_bytes = await download_benign(ext_id)
        if crx_bytes:
            row = extract_raw(crx_bytes, ext_id, "BENIGN")
            if row:
                row["name"] = friendly_name   # override with known name
                rows.append(row)
                ben_count += 1
                print("OK")
            else:
                print("parse failed")
        else:
            print("download failed")
    print(f"  Benign rows collected: {ben_count}")

    if not rows:
        print("No rows collected.")
        return

    # ── 3. Save CSV ────────────────────────────────────────────────
    df = pd.DataFrame(rows)

    # Sort: malicious first, then benign
    df["_sort"] = df["label"].map({"MALICIOUS": 0, "BENIGN": 1})
    df = df.sort_values(["_sort", "extension_id"]).drop(columns="_sort").reset_index(drop=True)

    df.to_csv(OUT_CSV, index=False)

    print(f"\nDataset saved: {OUT_CSV}")
    print(f"Total rows   : {len(df)}")
    print(f"  MALICIOUS  : {(df.label=='MALICIOUS').sum()}")
    print(f"  BENIGN     : {(df.label=='BENIGN').sum()}")
    print("\nColumn list:")
    for col in df.columns:
        print(f"  {col}")
    print("\nSample rows:")
    print(df[["name","permissions","eval_occurrences","atob_occurrences","label"]].head(5).to_string())


if __name__ == "__main__":
    asyncio.run(main())
