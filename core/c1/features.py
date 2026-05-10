"""Feature extraction utilities for C1 static analysis."""
from __future__ import annotations

import json
import math
import re
from typing import Dict, List


def load_feature_columns(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


# Pre-compiled regex patterns for code analysis
_RE_EVAL         = re.compile(r'\beval\s*\(')
_RE_ATOB         = re.compile(r'\batob\s*\(')
_RE_FUNC_CTOR    = re.compile(r'\bFunction\s*\(')
_RE_XHR_FETCH    = re.compile(r'\b(XMLHttpRequest|fetch)\s*[(\.]')
_RE_WEBSOCKET    = re.compile(r'\bWebSocket\s*\(')
_RE_EXEC_SCRIPT  = re.compile(r'\b(executeScript|insertCSS)\s*\(')
_RE_KEYDOWN      = re.compile(r'\b(keydown|keypress|keyup)\b', re.IGNORECASE)
_RE_COOKIE_CODE  = re.compile(r'(document\.cookie|chrome\.cookies)')
_RE_LONG_STR     = re.compile(r'[A-Za-z0-9+/=]{100,}')
_RE_HEX_ESCAPE   = re.compile(r'(?:\\x[0-9a-fA-F]{2}){4,}')
_RE_EXTERNAL_URL = re.compile(r'https?://[^\s\'">/]{4,}', re.IGNORECASE)


def extract_manifest_features(manifest: dict, source_code: str = "") -> Dict[str, float]:
    permissions = [str(p).lower() for p in manifest.get("permissions", [])]
    host_permissions = [str(p).lower() for p in manifest.get("host_permissions", [])]
    perm_set = set(permissions)

    # ── Manifest / permission features ──────────────────────────
    features: Dict[str, float] = {
        # Original 14 features (kept for backward compat)
        "has_webRequest":         1.0 if "webrequest" in perm_set else 0.0,
        "has_all_urls":           1.0 if any(
                                      "<all_urls>" in p or "*://*/*" in p
                                      for p in permissions + host_permissions
                                  ) else 0.0,
        "has_cookies":            1.0 if "cookies" in perm_set else 0.0,
        "has_clipboardRead":      1.0 if "clipboardread" in perm_set else 0.0,
        "has_nativeMessaging":    1.0 if "nativemessaging" in perm_set else 0.0,
        "has_tabs":               1.0 if "tabs" in perm_set else 0.0,
        "has_history":            1.0 if "history" in perm_set else 0.0,
        "has_downloads":          1.0 if "downloads" in perm_set else 0.0,
        "has_storage":            1.0 if "storage" in perm_set else 0.0,
        "has_background_script":  1.0 if bool(manifest.get("background")) else 0.0,
        "has_content_scripts":    1.0 if bool(manifest.get("content_scripts")) else 0.0,
        "host_permission_count":  float(len(host_permissions)),
        "total_permission_count": float(len(permissions)),
        "content_script_entropy": _shannon_entropy(source_code),

        # New manifest features
        "has_webRequestBlocking": 1.0 if "webrequestblocking" in perm_set else 0.0,
        "has_scripting":          1.0 if "scripting" in perm_set else 0.0,
        "has_management":         1.0 if "management" in perm_set else 0.0,
        "has_webNavigation":      1.0 if "webnavigation" in perm_set else 0.0,
        "has_contextMenus":       1.0 if "contextmenus" in perm_set else 0.0,
        "has_proxy":              1.0 if "proxy" in perm_set else 0.0,
        "has_declarativeNetRequest": 1.0 if "declarativenetrequest" in perm_set else 0.0,
        "web_accessible_resources": 1.0 if bool(manifest.get("web_accessible_resources")) else 0.0,
    }

    # ── Code-level features (from JS source) ────────────────────
    code = source_code or ""
    features.update({
        "eval_count":          float(len(_RE_EVAL.findall(code))),
        "atob_count":          float(len(_RE_ATOB.findall(code))),
        "function_ctor_count": float(len(_RE_FUNC_CTOR.findall(code))),
        "xhr_fetch_count":     float(len(_RE_XHR_FETCH.findall(code))),
        "websocket_count":     float(len(_RE_WEBSOCKET.findall(code))),
        "exec_script_count":   float(len(_RE_EXEC_SCRIPT.findall(code))),
        "keydown_listener":    1.0 if _RE_KEYDOWN.search(code) else 0.0,
        "cookie_in_code":      float(len(_RE_COOKIE_CODE.findall(code))),
        "long_string_count":   float(len(_RE_LONG_STR.findall(code))),
        "hex_escape_count":    float(len(_RE_HEX_ESCAPE.findall(code))),
        "external_url_count":  float(len(set(_RE_EXTERNAL_URL.findall(code)))),
    })

    return features


def build_feature_vector(feature_columns: List[str], feature_values: Dict[str, float]) -> List[float]:
    return [float(feature_values.get(name, 0.0)) for name in feature_columns]
