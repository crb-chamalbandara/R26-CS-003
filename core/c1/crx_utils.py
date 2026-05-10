"""
Component 1 — CRX utilities
Parses Chrome Extension (.crx) files and downloads them from the Chrome Web Store.

Two entry points used by the rest of C1:
  parse_crx_bytes(data)          -> (manifest_dict, js_source, ext_id)
  fetch_crx_from_store(ext_id)   -> raw CRX bytes  (async)
  extract_ext_id_from_url(url)   -> "abcd...32chars" | None
"""
from __future__ import annotations

import io
import json
import os
import re
import struct
import zipfile
from typing import Optional, Tuple

# ── Chrome Web Store URL patterns ─────────────────────────────────────────────
# Matches both the old chrome.google.com/webstore and the new chromewebstore.google.com
_WEBSTORE_RE = re.compile(
    r"https?://(?:chrome\.google\.com/webstore/detail/[^/]*/|"
    r"chromewebstore\.google\.com/detail/(?:[^/]*/)?)"
    r"([a-p]{32})",
    re.IGNORECASE,
)

# ── CRX download URL (Chrome's update server) ────────────────────────────────
_CRX_DOWNLOAD_TPL = (
    "https://clients2.google.com/service/update2/crx"
    "?response=redirect"
    "&os=win&arch=x64&nacl_arch=x86-64"
    "&prod=chromecrx&prodchannel=unknown&prodversion=9999.0.9999.0"
    "&lang=en-US&acceptformat=crx3"
    "&x=id%3D{ext_id}%26installsource%3Dondemand%26uc"
)

_CRX_MAGIC = b"Cr24"
_MAX_JS_CHARS = 300_000   # cap per analysis to stay responsive


# ── URL helpers ───────────────────────────────────────────────────────────────

def extract_ext_id_from_url(url: str) -> Optional[str]:
    """Return the 32-char extension ID embedded in a Chrome Web Store URL, or None."""
    m = _WEBSTORE_RE.search(url)
    return m.group(1).lower() if m else None


def is_webstore_url(url: str) -> bool:
    return bool(_WEBSTORE_RE.search(url))


# ── CRX binary parsing ────────────────────────────────────────────────────────

def _read_u32le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _crx_to_zip_bytes(data: bytes) -> bytes:
    if data[:4] != _CRX_MAGIC:
        raise ValueError("Not a valid CRX file (bad magic bytes)")
    version = _read_u32le(data, 4)
    if version == 2:
        pub_len = _read_u32le(data, 8)
        sig_len = _read_u32le(data, 12)
        zip_start = 16 + pub_len + sig_len
    elif version == 3:
        header_len = _read_u32le(data, 8)
        zip_start = 12 + header_len
    else:
        raise ValueError(f"Unsupported CRX version: {version}")
    return data[zip_start:]


def parse_crx_bytes(
    data: bytes,
    ext_id: str = "",
    max_js_chars: int = _MAX_JS_CHARS,
) -> Tuple[dict, str, str]:
    """
    Parse raw CRX bytes into (manifest_dict, js_source_concat, extension_id).
    Raises ValueError on bad/unreadable CRX data.
    """
    zip_bytes = _crx_to_zip_bytes(data)
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        names = zf.namelist()

        # manifest.json
        mf_name = next(
            (n for n in names if n.lower().endswith("manifest.json")), None
        )
        if not mf_name:
            raise ValueError("manifest.json not found inside CRX")
        manifest = json.loads(zf.read(mf_name).decode("utf-8", errors="ignore"))

        # Concatenate all JS sources up to cap
        parts: list[str] = []
        total = 0
        for name in names:
            if not name.lower().endswith(".js"):
                continue
            try:
                chunk = zf.read(name).decode("utf-8", errors="ignore")
            except Exception:
                continue
            remaining = max_js_chars - total
            if remaining <= 0:
                break
            parts.append(chunk[:remaining])
            total += len(chunk)

    return manifest, "\n".join(parts), ext_id


def parse_crx_file(path: str) -> Tuple[dict, str, str]:
    """Read a .crx file from disk and return (manifest_dict, js_source, ext_id)."""
    import os
    ext_id = os.path.splitext(os.path.basename(path))[0].lower()
    with open(path, "rb") as fh:
        data = fh.read()
    return parse_crx_bytes(data, ext_id)


# ── Persistent extraction ─────────────────────────────────────────────────────

def extract_crx_to_persistent_dir(crx_data: bytes, ext_id: str) -> str:
    """
    Unzip a CRX into ~/.websentinel/extensions/<ext_id>/ and return the path.
    Used so the extension can be loaded into the Playwright session later.
    """
    ext_dir = os.path.join(
        os.path.expanduser("~"), ".websentinel", "extensions", ext_id
    )
    os.makedirs(ext_dir, exist_ok=True)
    zip_bytes = _crx_to_zip_bytes(crx_data)
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        zf.extractall(ext_dir)
    return ext_dir


# ── Chrome Web Store fetch ────────────────────────────────────────────────────

async def fetch_crx_from_store(ext_id: str, timeout: float = 20.0) -> bytes:
    """
    Download the CRX for ext_id from Chrome's update server.
    Returns raw CRX bytes.  Raises httpx.HTTPError on network/HTTP errors.
    """
    import httpx
    url = _CRX_DOWNLOAD_TPL.format(ext_id=ext_id)
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=timeout,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0"},
    ) as client:
        r = await client.get(url)
        r.raise_for_status()
        data = r.content
    if not data:
        raise ValueError(f"Empty response for extension {ext_id}")
    return data
