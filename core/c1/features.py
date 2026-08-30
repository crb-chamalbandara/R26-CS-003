"""
C1 — features.py  |  The Feature Extractor
-------------------------------------------
Purpose : Convert raw extension data (manifest.json + JS source code) into
          exactly 33 numeric values that the XGBoost model can process.
Role    : Called by analyzer.py at runtime (live analysis) AND by
          build_manifest_dataset.py / retrain_with_new_data.py during
          offline dataset preparation.
"""
from __future__ import annotations

import json
import math
import re
from typing import Dict, List


def load_feature_columns(path: str) -> List[str]:
    """Read the ordered list of feature column names from a JSON file.
    This order must match what the model was trained on — order matters for XGBoost."""
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a text string.
    High entropy = random/obfuscated code (suspicious).
    Low entropy  = normal readable code with patterns (benign).
    Formula: H = -sum(p_i * log2(p_i)) where p_i is frequency of each character."""
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1     # count how many times each character appears
    total   = len(text)
    entropy = 0.0
    for count in counts.values():
        p        = count / total                # probability of this character
        entropy -= p * math.log2(p)            # Shannon formula contribution
    return entropy


# ── Pre-compiled regex patterns for code analysis ────────────────────────────
# Compiling once at module load is faster than re-compiling on every extension analysis.
_RE_EVAL         = re.compile(r'\beval\s*\(')                          # eval() — executes dynamically generated code
_RE_ATOB         = re.compile(r'\batob\s*\(')                          # atob() — base64 decoding (hides payloads)
_RE_FUNC_CTOR    = re.compile(r'\bFunction\s*\(')                      # new Function() — another dynamic code trick
_RE_XHR_FETCH    = re.compile(r'\b(XMLHttpRequest|fetch)\s*[(\.]')     # network requests — sends data externally
_RE_WEBSOCKET    = re.compile(r'\bWebSocket\s*\(')                     # WebSocket — persistent C2 channel
_RE_EXEC_SCRIPT  = re.compile(r'\b(executeScript|insertCSS)\s*\(')     # injects scripts/styles into web pages
_RE_KEYDOWN      = re.compile(r'\b(keydown|keypress|keyup)\b', re.IGNORECASE)  # keyboard listeners — potential keylogging
_RE_COOKIE_CODE  = re.compile(r'(document\.cookie|chrome\.cookies)')   # cookie access — credential theft risk
_RE_LONG_STR     = re.compile(r'[A-Za-z0-9+/=]{100,}')                # strings ≥100 chars — likely base64 payloads
_RE_HEX_ESCAPE   = re.compile(r'(?:\\x[0-9a-fA-F]{2}){4,}')           # hex escapes like \x41 — obfuscation technique
_RE_EXTERNAL_URL = re.compile(r'https?://[^\s\'">/]{4,}', re.IGNORECASE)  # hardcoded external URLs — exfiltration targets


def _is_host_pattern(permission: str) -> bool:
    """True if a permission string is a URL match pattern (a host permission)
    rather than a named API permission like "storage" or "tabs".

    Manifest V3 declares host permissions separately under "host_permissions".
    Manifest V2 (still common — MV3 only exists since 2021) has no such field
    at all; host access is just mixed into the main "permissions" array as
    match patterns like "https://*.example.com/*" or "<all_urls>". Without
    this check, host_permission_count silently reads 0 for every MV2
    extension regardless of how much host access it actually has — this
    matters a lot in practice since it's the single most important feature
    to the XGBoost classifier."""
    return permission == "<all_urls>" or "://" in permission


def extract_manifest_features(manifest: dict, source_code: str = "") -> Dict[str, float]:
    """Extract all 33 features from one extension's manifest and JS source.

    Feature groups:
      Group 1 — Manifest/permission features (22 features): what the extension DECLARES it needs.
      Group 2 — Code pattern features     (11 features): what the JS code ACTUALLY does.

    All values are numeric (0.0/1.0 binary flags or integer counts).
    """
    # Parse permission lists from manifest — convert to lowercase set for fast lookup
    permissions      = [str(p).lower() for p in manifest.get("permissions", [])]
    host_permissions = [str(p).lower() for p in manifest.get("host_permissions", [])]
    perm_set         = set(permissions)    # set lookup is O(1) — much faster than list search

    # MV2 manifests have no "host_permissions" field — match-pattern entries
    # (e.g. "https://*.example.com/*") live directly inside "permissions"
    # instead. Count those too so host_permission_count isn't blind to MV2.
    permission_host_patterns = [p for p in permissions if _is_host_pattern(p)]

    # ── Group 1: Manifest / Permission features ───────────────────
    # Each "has_X" feature is 1.0 if that permission is present, 0.0 if not.
    # These tell the model what capabilities the extension claims to need.
    features: Dict[str, float] = {
        "has_webRequest"        : 1.0 if "webrequest"        in perm_set else 0.0,   # can intercept network requests
        "has_all_urls"          : 1.0 if any(                                         # has access to ALL websites
                                      "<all_urls>" in p or "*://*/*" in p
                                      for p in permissions + host_permissions
                                  ) else 0.0,
        "has_cookies"           : 1.0 if "cookies"           in perm_set else 0.0,   # can read/write browser cookies
        "has_clipboardRead"     : 1.0 if "clipboardread"     in perm_set else 0.0,   # can read clipboard contents
        "has_nativeMessaging"   : 1.0 if "nativemessaging"   in perm_set else 0.0,   # can communicate with desktop apps
        "has_tabs"              : 1.0 if "tabs"              in perm_set else 0.0,   # can read tab URLs and titles
        "has_history"           : 1.0 if "history"           in perm_set else 0.0,   # can access browser history
        "has_downloads"         : 1.0 if "downloads"         in perm_set else 0.0,   # can manage downloads
        "has_storage"           : 1.0 if "storage"           in perm_set else 0.0,   # can store data persistently
        "has_background_script" : 1.0 if bool(manifest.get("background"))  else 0.0, # runs a background process always
        "has_content_scripts"   : 1.0 if bool(manifest.get("content_scripts")) else 0.0,  # injects into web pages
        "host_permission_count" : float(len(host_permissions) + len(permission_host_patterns)),  # MV3 host_permissions + MV2 URL patterns in permissions
        "total_permission_count": float(len(permissions)),                            # total permissions declared
        "content_script_entropy": _shannon_entropy(source_code),                     # code randomness (obfuscation signal)

        # Additional manifest features added in v3 of the feature set
        "has_webRequestBlocking": 1.0 if "webrequestblocking"      in perm_set else 0.0,  # can BLOCK network requests (dangerous)
        "has_scripting"         : 1.0 if "scripting"               in perm_set else 0.0,  # can inject scripts via chrome.scripting
        "has_management"        : 1.0 if "management"              in perm_set else 0.0,  # can control other extensions
        "has_webNavigation"     : 1.0 if "webnavigation"           in perm_set else 0.0,  # can monitor page navigations
        "has_contextMenus"      : 1.0 if "contextmenus"            in perm_set else 0.0,  # adds items to right-click menu
        "has_proxy"             : 1.0 if "proxy"                   in perm_set else 0.0,  # can route ALL browser traffic
        "has_declarativeNetRequest": 1.0 if "declarativenetrequest" in perm_set else 0.0, # MV3 network request blocking
        "web_accessible_resources" : 1.0 if bool(manifest.get("web_accessible_resources")) else 0.0,  # exposes files to web pages
    }

    # ── Group 2: Code-level features (from JS source) ─────────────
    # Count how many times each suspicious pattern appears in the JavaScript code.
    # More occurrences = stronger signal of malicious behavior.
    code = source_code or ""
    features.update({
        "eval_count"         : float(len(_RE_EVAL.findall(code))),          # dynamic code execution
        "atob_count"         : float(len(_RE_ATOB.findall(code))),          # base64 decoding (hides payloads)
        "function_ctor_count": float(len(_RE_FUNC_CTOR.findall(code))),     # Function() constructor (another eval trick)
        "xhr_fetch_count"    : float(len(_RE_XHR_FETCH.findall(code))),     # network calls (data exfiltration)
        "websocket_count"    : float(len(_RE_WEBSOCKET.findall(code))),     # persistent connections to external servers
        "exec_script_count"  : float(len(_RE_EXEC_SCRIPT.findall(code))),   # script injection into pages
        "keydown_listener"   : 1.0 if _RE_KEYDOWN.search(code) else 0.0,   # keyboard monitoring (keylogging)
        "cookie_in_code"     : float(len(_RE_COOKIE_CODE.findall(code))),   # cookie access in source
        "long_string_count"  : float(len(_RE_LONG_STR.findall(code))),      # encoded/obfuscated strings ≥100 chars
        "hex_escape_count"   : float(len(_RE_HEX_ESCAPE.findall(code))),    # \x41-style hex obfuscation
        "external_url_count" : float(len(set(_RE_EXTERNAL_URL.findall(code)))),  # unique external URLs (exfiltration targets)
    })

    return features


def build_feature_vector(feature_columns: List[str], feature_values: Dict[str, float]) -> List[float]:
    """Convert feature dict → ordered list matching the model's expected column order.
    If a feature is missing (e.g., new extension doesn't use WebSocket), default to 0.0."""
    return [float(feature_values.get(name, 0.0)) for name in feature_columns]
