"""
Stage 1b — Chrome/Chromium saved-credential decryption for Component 4.

Chrome never stores saved passwords in plaintext. Every password in the
`Login Data` SQLite database is encrypted, and the AES master key itself is
stored — DPAPI-protected — inside the profile's `Local State` JSON file.

Decryption chain on Windows (Chrome 80+):
  1. Read os_crypt.encrypted_key from Local State (base64-encoded).
  2. Strip the 5-byte "DPAPI" prefix, then CryptUnprotectData() it -> AES key.
  3. Each password blob = b"v10"|b"v11" + nonce(12) + ciphertext + tag(16).
     Decrypt with AES-256-GCM using the master key.

Legacy blobs (pre-Chrome-80) have no version prefix and are DPAPI-encrypted
directly, so CryptUnprotectData() alone recovers them.

DPAPI keys are bound to the current Windows user account, so decryption only
succeeds when C4 runs as the same user that owns the browser profile — which
is exactly how the WebSentinel forensic engine is deployed.

This module talks to DPAPI through ctypes (crypt32.dll) so it needs no
pywin32 dependency; AES-GCM comes from the `cryptography` package.
"""
import base64
import ctypes
import ctypes.wintypes
import json
import os

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_AESGCM = True
except Exception:
    _HAS_AESGCM = False

# When False (default), decrypted passwords are masked in stored reports so the
# forensic artifacts on disk never contain full plaintext credentials. The
# engine still proves decryption succeeded via status + length + masked preview.
# Flip to True only for a controlled local demo of full recovery.
REVEAL_PLAINTEXT = False


# ── Windows DPAPI via ctypes (no pywin32) ─────────────────────────────────────
class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi_decrypt(blob):
    """CryptUnprotectData for the current user. Returns bytes, or None on failure."""
    if os.name != "nt" or not blob:
        return None
    blob_in = _DATA_BLOB(len(blob),
                         ctypes.cast(ctypes.c_char_p(blob), ctypes.POINTER(ctypes.c_char)))
    blob_out = _DATA_BLOB()
    try:
        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out))
    except Exception:
        return None
    if not ok:
        return None
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def load_master_key(profile_path):
    """Read and DPAPI-decrypt the AES master key from Local State.

    `profile_path` is the Chromium *Default* folder; Local State normally lives
    in its parent (the user-data dir), but some Playwright builds place it in the
    profile folder itself — try both.
    """
    candidates = [
        os.path.join(os.path.dirname(profile_path), "Local State"),
        os.path.join(profile_path, "Local State"),
    ]
    for ls in candidates:
        if not os.path.exists(ls):
            continue
        try:
            with open(ls, "r", encoding="utf-8", errors="ignore") as f:
                b64 = json.load(f)["os_crypt"]["encrypted_key"]
            enc = base64.b64decode(b64)
            if enc[:5] == b"DPAPI":
                enc = enc[5:]
            key = _dpapi_decrypt(enc)
            if key:
                return key
        except Exception:
            continue
    return None


def _mask(plaintext):
    """First + last char with length, e.g. 'hunter2' -> 'h*****2'. Proves
    decryption without exposing the full secret in on-disk reports."""
    n = len(plaintext)
    if n == 0:
        return ""
    if n <= 2:
        return "*" * n
    return f"{plaintext[0]}{'*' * (n - 2)}{plaintext[-1]}"


def decrypt_password(blob, master_key):
    """Decrypt one Chrome password blob.

    Returns a dict: {status, password, length} where status is one of
    'success', 'no-key', 'unavailable', 'empty', or 'failed'.
    `password` is masked unless REVEAL_PLAINTEXT is enabled.
    """
    if not blob:
        return {"status": "empty", "password": "", "length": 0}

    plaintext = None
    try:
        if blob[:3] in (b"v10", b"v11"):          # Chrome 80+ AES-256-GCM
            if not _HAS_AESGCM:
                return {"status": "unavailable", "password": "[AES-GCM lib missing]", "length": 0}
            if not master_key:
                return {"status": "no-key", "password": "[master key not recovered]", "length": 0}
            nonce, ciphertext = blob[3:15], blob[15:]
            plaintext = AESGCM(master_key).decrypt(nonce, ciphertext, None).decode("utf-8", "replace")
        else:                                      # legacy: DPAPI-encrypted directly
            dec = _dpapi_decrypt(blob)
            if dec is None:
                return {"status": "failed", "password": "[DPAPI decrypt failed]", "length": 0}
            plaintext = dec.decode("utf-8", "replace")
    except Exception:
        return {"status": "failed", "password": "[decrypt error]", "length": 0}

    length = len(plaintext)
    shown = plaintext if REVEAL_PLAINTEXT else _mask(plaintext)
    return {"status": "success", "password": shown, "length": length}
