"""
C1 — enrich.py  |  Live Blocklist Evidence Resolver
------------------------------------------------------------------------
Purpose : Fill in the evidence a blocklist row is missing, using what the
          live intercept actually observed instead of the placeholder text
          the sheet was imported with.

Why this exists
---------------
The finalized blocklist is a merge of two sources. The `malext_sentry`
half carries full evidence (name, reason, date, store, version, hash); the
`chrome-mal-ids` half is an ID-only dump — 573 of its rows carry the literal
strings "Not Found" / "Not yet confirmed" / "Not Confirmed" / "N/A" in every
evidence column. Rendering those straight into the Blocklist Match panel
showed the analyst nothing, even though the live intercept had *already*
downloaded the CRX and therefore knew the real name, the real version, the
real store and the real file hash.

So: on a blocklist hit with gaps, C1 stops short-circuiting. It runs the
full ML stack (XGBoost + rule boosters + Isolation Forest) and the dynamic
sandbox on the intercepted CRX, derives a reason from what those models
saw, and writes the completed record back to the sheet — so the next hit on
the same ID is already documented.

Public API
----------
    resolve_extension_name(...)  -> (name, provenance)
    build_live_evidence(...)     -> dict of sheet-ready field values
    derive_reason(...)           -> ReasonVerdict(reason, confidence, ...)
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Sequence, Tuple

# ── Store detection ───────────────────────────────────────────────────────────
_EDGE_HOST_RE   = re.compile(r"microsoftedge\.microsoft\.com", re.IGNORECASE)
_CHROME_HOST_RE = re.compile(r"(chromewebstore\.google\.com|chrome\.google\.com)", re.IGNORECASE)

# Chrome Web Store detail URLs carry a human-readable slug before the ID:
#   /detail/fastsave/pnlphjjfielecalmmjjdhjjninkbjdod
_SLUG_RE = re.compile(r"/detail/([^/]+)/[a-p]{32}", re.IGNORECASE)

# manifest "name" may be an i18n placeholder: "__MSG_appName__"
_MSG_RE = re.compile(r"^__MSG_(.+)__$")


def sha256_of(data: bytes) -> str:
    """SHA-256 of the raw CRX package — the same artefact VirusTotal indexes."""
    return hashlib.sha256(data).hexdigest()


def store_from_url(url: str, default: str = "Chrome") -> str:
    """Map an intercepted store URL to the sheet's Store vocabulary."""
    if not url:
        return default
    if _EDGE_HOST_RE.search(url):
        return "Edge"
    if _CHROME_HOST_RE.search(url):
        return "Chrome"
    return default


def sheet_date(when: Optional[datetime] = None) -> str:
    """Format a date the way the sheet already writes them (M/D/YYYY)."""
    when = when or datetime.now()
    return f"{when.month}/{when.day}/{when.year}"


# ── Offline fallback source ───────────────────────────────────────────────────
# Most undocumented blocklist rows are undocumented because the store already
# removed the extension — the CRX is simply not downloadable any more. For
# some of those the repo still holds a copy of the manifest in the
# chrome-extension-manifests-dataset corpus (103k manifests keyed by ID), which
# is enough to establish the name, the version, and the declared permissions
# the reason derivation reads. There is no JavaScript in that corpus, so
# callers must tell derive_reason() the code was unavailable.

_MANIFEST_CORPUS = os.path.join("chrome-extension-manifests-dataset", "manifests")


def find_local_manifest(ext_id: str, data_dir: str) -> Optional[dict]:
    """Return the archived manifest for a delisted extension, or None."""
    ext_id = (ext_id or "").strip().lower()
    if not ext_id:
        return None
    path = os.path.join(data_dir, _MANIFEST_CORPUS, f"{ext_id}.json")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


# ── Extension name resolution ────────────────────────────────────────────────

def _load_locale_messages(ext_path: str, preferred: str = "") -> Dict[str, dict]:
    """Read _locales/<lang>/messages.json, preferring the extension's own
    default_locale, then English, then whatever locale ships first."""
    locales_dir = os.path.join(ext_path, "_locales")
    if not os.path.isdir(locales_dir):
        return {}
    candidates: List[str] = []
    for lang in (preferred, "en", "en_US", "en_GB"):
        if lang and lang not in candidates:
            candidates.append(lang)
    try:
        candidates.extend(sorted(os.listdir(locales_dir)))
    except OSError:
        return {}
    for lang in candidates:
        path = os.path.join(locales_dir, lang, "messages.json")
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8-sig", errors="ignore") as handle:
                data = json.load(handle)
            if isinstance(data, dict) and data:
                return data
        except (OSError, ValueError):
            continue
    return {}


def _slug_to_title(slug: str) -> str:
    """'fast-save_pro' -> 'Fast Save Pro' — the Web Store URL slug is a decent
    last-resort name when the manifest gives us nothing usable."""
    words = [w for w in re.split(r"[-_+.\s]+", slug) if w]
    return " ".join(w[:1].upper() + w[1:] for w in words)


def _tidy_name(name: str) -> str:
    """Collapse whitespace and trim — the sheet stores single-line names."""
    return re.sub(r"\s+", " ", name).strip()[:120]


def resolve_extension_name(
    manifest: dict,
    ext_path: str = "",
    webstore_url: str = "",
    ext_id: str = "",
) -> Tuple[str, str]:
    """Best available display name for an extension, plus where it came from.

    Returns (name, provenance) where provenance is one of
    "manifest" | "manifest_i18n" | "webstore_slug" | "".
    """
    raw = str((manifest or {}).get("name") or "").strip()

    # i18n placeholder — resolve it against the extension's own _locales bundle
    msg_match = _MSG_RE.match(raw)
    if msg_match and ext_path:
        key = msg_match.group(1)
        messages = _load_locale_messages(ext_path, str((manifest or {}).get("default_locale") or ""))
        # message keys are case-insensitive in Chrome's i18n implementation
        lowered = {str(k).lower(): v for k, v in messages.items()}
        entry = lowered.get(key.lower())
        if isinstance(entry, dict):
            resolved = str(entry.get("message") or "").strip()
            if resolved:
                return _tidy_name(resolved), "manifest_i18n"
    elif raw and not msg_match:
        return _tidy_name(raw), "manifest"

    slug_match = _SLUG_RE.search(webstore_url or "")
    if slug_match:
        title = _slug_to_title(slug_match.group(1))
        if title:
            return _tidy_name(title), "webstore_slug"

    if raw and not msg_match:
        return _tidy_name(raw), "manifest"
    return "", ""


# ── Sheet-safe text ───────────────────────────────────────────────────────────
# The finalized CSV is Excel-exported cp1252. A name containing CJK or emoji
# would otherwise be written as "?" mojibake (the sheet already carries a few
# of those from its original import). Transliterate what we can, drop the rest.
_TRANSLITERATE = {
    "‘": "'", "’": "'", "“": '"', "”": '"',
    "–": "-", "—": "-", "…": "...", " ": " ",
    "•": "*", "™": "(TM)", "®": "(R)",
}


def sheet_safe(text: str) -> str:
    """Make a string writable to the cp1252 sheet without mojibake."""
    if not text:
        return ""
    for src, dst in _TRANSLITERATE.items():
        text = text.replace(src, dst)
    # Decompose accents to their base letters where cp1252 can't hold them
    out: List[str] = []
    for ch in text:
        try:
            ch.encode("cp1252")
            out.append(ch)
        except UnicodeEncodeError:
            folded = unicodedata.normalize("NFKD", ch)
            kept = "".join(c for c in folded if not unicodedata.combining(c))
            try:
                kept.encode("cp1252")
                out.append(kept)
            except UnicodeEncodeError:
                continue    # unrepresentable (emoji, CJK) — drop it
    return re.sub(r"\s+", " ", "".join(out)).strip()


# ══════════════════════════════════════════════════════════════════════════════
#  Reason derivation
# ══════════════════════════════════════════════════════════════════════════════
# A blocklist row with reason "Not yet confirmed" tells an analyst nothing.
# Once the ML stack and the sandbox have run on the intercepted CRX we have
# enough observed evidence to name the threat class. Each category below
# accumulates points from the evidence that actually fired; the highest
# scorer wins, and every contributing predicate is kept as rationale so the
# panel can show *why* the reason says what it says.
#
# Category names are drawn from the vocabulary the sheet already uses, so a
# derived reason sorts and colours identically to a hand-curated one.

CATEGORY_MALWARE       = "Malware"
CATEGORY_SPYWARE       = "Spyware"
CATEGORY_EXFIL         = "Spyware / Data Exfiltration"
CATEGORY_ADWARE        = "Adware"
CATEGORY_SEARCH_HIJACK = "Search Hijacking"
CATEGORY_BUNDLING      = "Bundling Unwanted Software"
CATEGORY_CRYPTO        = "Crypto Wallet Theft"
CATEGORY_POLICY        = "Policy Violation"
CATEGORY_SUSPICIOUS    = "In store but Suspicious"
# Floor for an extension the store has already removed: we can say the ID is
# blocklisted and that the archived manifest showed nothing conclusive, but
# not why it was pulled. The sheet already uses this exact wording for 263
# curated rows in the same position.
CATEGORY_REMOVED       = "Removal reason Unknown"

# Tie-break order when two categories score identically — most specific first.
_PRIORITY = [
    CATEGORY_CRYPTO, CATEGORY_EXFIL, CATEGORY_SPYWARE, CATEGORY_SEARCH_HIJACK,
    CATEGORY_ADWARE, CATEGORY_BUNDLING, CATEGORY_MALWARE, CATEGORY_POLICY,
    CATEGORY_SUSPICIOUS,
]

# The first seven name a specific threat class and have to be earned from
# observed behaviour. The last two are fallbacks: "Policy Violation" is what
# an over-permissioned extension gets when nothing more specific fired, and
# "In store but Suspicious" is the floor for a blocklisted ID whose CRX gives
# us almost nothing. A fallback can never outrank a specific class that
# cleared the evidence bar below — otherwise a long tail of small generic
# points would bury a real finding under a vague one.
_SPECIFIC  = _PRIORITY[:7]
_FALLBACKS = _PRIORITY[7:]

# Evidence points a specific class needs before it is allowed to win.
SPECIFIC_MIN_EVIDENCE = 30.0
# Points "Policy Violation" needs before it beats the bare "suspicious" floor.
POLICY_MIN_EVIDENCE = 20.0

# ── Code keyword probes ───────────────────────────────────────────────────────
_KW_CRYPTO = re.compile(
    r"\b(mnemonic|seed[\s_-]?phrase|privatekey|private_key|secretkey|keystore|"
    r"metamask|walletconnect|trustwallet|phantom|coinbasewallet|ethereum|web3|"
    r"bip39|xpub|wallet[\s_-]?address)\b", re.IGNORECASE)
_KW_ADS = re.compile(
    r"(doubleclick|googlesyndication|popunder|pop_under|adserver|ad_server|"
    r"banner_ad|/ads?/|affiliate|aff_id|clickid|click_id|subid|"
    r"taboola|outbrain|propellerads|adsterra|zeropark|revcontent)", re.IGNORECASE)
_KW_SEARCH = re.compile(
    r"(default_search|search_provider|searchTerms|/search\?|"
    r"chrome_settings_overrides|newtab|new_tab_url|keyword_search)", re.IGNORECASE)
_KW_INSTALLER = re.compile(
    r"(chrome\.downloads|\.exe\b|\.msi\b|installer|setup\.exe|bundle_offer|"
    r"nativeMessaging|sendNativeMessage)", re.IGNORECASE)
_KW_C2 = re.compile(
    r"(WebSocket\s*\(|/gate\.php|/panel/|beacon|heartbeat|c2_|cmd_exec)",
    re.IGNORECASE)
_KW_EXFIL_SINK = re.compile(
    r"(document\.cookie|chrome\.cookies\.getAll|localStorage|"
    r"chrome\.history\.search|chrome\.topSites|navigator\.credentials)",
    re.IGNORECASE)


@dataclass
class ReasonVerdict:
    """The derived Reason plus the evidence trail that produced it."""
    reason: str
    confidence: str                       # High | Medium | Low
    score: float                          # winning category's evidence points
    rationale: List[str] = field(default_factory=list)
    runners_up: List[Tuple[str, float]] = field(default_factory=list)
    method: str = "ml+sandbox"            # what actually ran

    def as_dict(self) -> Dict:
        return {
            "reason":     self.reason,
            "confidence": self.confidence,
            "score":      round(self.score, 1),
            "rationale":  self.rationale,
            "runners_up": [{"reason": r, "score": round(s, 1)} for r, s in self.runners_up],
            "method":     self.method,
        }


def _confidence_for(score: float) -> str:
    if score >= 60:
        return "High"
    if score >= 32:
        return "Medium"
    return "Low"


def derive_reason(
    *,
    manifest: dict,
    features: Dict[str, float],
    source_code: str,
    flags: Sequence[str],
    ml_prob: float,
    anomaly_score: float,
    static_score: float,
    dynamic_score: float,
    sandbox_ran: bool,
    code_available: bool = True,
) -> ReasonVerdict:
    """Name the threat class from what the models and the sandbox observed.

    Args are the raw outputs of the C1 pipeline: `features` from features.py,
    `flags` the merged static+dynamic flag list, `ml_prob` the XGBoost
    probability (0-1), and `anomaly_score` / `static_score` / `dynamic_score`
    on the 0-100 scale.

    Set `code_available=False` when only the manifest was recoverable (a
    delisted extension read back from the archived-manifest corpus). Eleven
    of the model's 33 features are code counts that are all zero in that
    case, so the ML probability is not trustworthy and is left out of the
    scoring — the derivation falls back to declared capability alone.
    """
    manifest      = manifest or {}
    code          = source_code or ""
    flagset       = {str(f).split(":")[0] for f in flags}
    overrides     = manifest.get("chrome_settings_overrides") or {}
    url_overrides = manifest.get("chrome_url_overrides") or {}

    points: Dict[str, float]    = {c: 0.0 for c in _PRIORITY}
    why:    Dict[str, List[str]] = {c: [] for c in _PRIORITY}

    def add(category: str, amount: float, note: str) -> None:
        points[category] += amount
        why[category].append(note)

    f = features or {}

    def feat(name: str) -> float:
        return float(f.get(name, 0.0) or 0.0)

    # ── Crypto wallet theft ───────────────────────────────────────
    crypto_hits = len({m.group(0).lower() for m in _KW_CRYPTO.finditer(code)})
    if crypto_hits >= 2:
        add(CATEGORY_CRYPTO, 30 + min(crypto_hits, 6) * 4,
            f"{crypto_hits} distinct crypto-wallet identifiers in the extension source")
    if crypto_hits and (feat("xhr_fetch_count") >= 1 or "DATA_POST_TO_EXTERNAL" in flagset):
        add(CATEGORY_CRYPTO, 22, "Wallet/seed-phrase strings combined with outbound network calls")
    if crypto_hits and feat("has_clipboardRead"):
        add(CATEGORY_CRYPTO, 18, "clipboardRead permission alongside wallet-related code (address swapping)")

    # ── Spyware / data exfiltration ───────────────────────────────
    if "COOKIE_EXFILTRATION_RISK" in flagset:
        add(CATEGORY_EXFIL, 45, "Sandbox observed cookie access followed by an external POST")
    if "COOKIE_READ_WITH_EXTERNAL" in flagset:
        add(CATEGORY_EXFIL, 28, "Sandbox observed cookie reads alongside external requests")
    if "DATA_POST_TO_EXTERNAL" in flagset:
        add(CATEGORY_EXFIL, 22, "Sandbox observed POST bodies sent to an external host")
    if "KEYBOARD_MONITORING" in flagset:
        add(CATEGORY_SPYWARE, 26, "Sandbox detected keyboard event listeners (keylogging behaviour)")
    elif feat("keydown_listener"):
        add(CATEGORY_SPYWARE, 12, "Keyboard event listeners present in the extension source")
    if "FORM_SUBMIT_OBSERVED" in flagset:
        add(CATEGORY_EXFIL, 16, "Sandbox observed a form submission routed to an external URL")
    if feat("has_cookies") and feat("has_all_urls"):
        add(CATEGORY_SPYWARE, 18, "cookies permission combined with all-URLs host access")
    if feat("cookie_in_code") >= 3:
        add(CATEGORY_SPYWARE, 12, f"{int(feat('cookie_in_code'))} cookie-access call sites in the source")
    if feat("has_history") or feat("has_clipboardRead"):
        add(CATEGORY_SPYWARE, 10, "Reads browsing history / clipboard contents")
    if _KW_EXFIL_SINK.search(code) and feat("external_url_count") >= 3:
        add(CATEGORY_SPYWARE, 14, "Credential/browsing data sinks paired with hardcoded external endpoints")

    # ── Search hijacking ──────────────────────────────────────────
    if overrides.get("search_provider"):
        add(CATEGORY_SEARCH_HIJACK, 42, "manifest overrides the browser's default search provider")
    if overrides.get("homepage") or overrides.get("startup_pages"):
        add(CATEGORY_SEARCH_HIJACK, 20, "manifest overrides the homepage / startup pages")
    if url_overrides.get("newtab"):
        add(CATEGORY_SEARCH_HIJACK, 22, "manifest replaces the new-tab page")
    search_hits = len(_KW_SEARCH.findall(code))
    if search_hits >= 4 and (feat("has_webRequest") or feat("has_declarativeNetRequest")):
        add(CATEGORY_SEARCH_HIJACK, 20,
            f"{search_hits} search-redirection patterns plus request-rewriting permissions")
    if feat("has_webRequestBlocking") and search_hits >= 2:
        add(CATEGORY_SEARCH_HIJACK, 14, "webRequestBlocking used around search-query handling")

    # ── Adware ────────────────────────────────────────────────────
    # One stray ad-network string is weak evidence — plenty of legitimate
    # extensions reference doubleclick once. Two or more, or one paired with
    # site-wide injection, is what actually distinguishes adware.
    ad_hits = len({m.group(0).lower() for m in _KW_ADS.finditer(code)})
    if ad_hits >= 3:
        add(CATEGORY_ADWARE, 26 + min(ad_hits, 8) * 2,
            f"{ad_hits} distinct ad-network / affiliate identifiers in the source")
    elif ad_hits == 2:
        add(CATEGORY_ADWARE, 14, "2 ad-network identifiers in the source")
    elif ad_hits:
        add(CATEGORY_ADWARE, 6, "1 ad-network identifier in the source")
    if feat("has_content_scripts") and feat("has_all_urls") and ad_hits >= 2:
        add(CATEGORY_ADWARE, 18, "Injects content scripts into every site alongside ad-network code")
    if "HIGH_REQUEST_VOLUME" in flagset:
        add(CATEGORY_ADWARE, 14, "Sandbox recorded an unusually high volume of external requests")
    if feat("has_declarativeNetRequest") and ad_hits >= 2:
        add(CATEGORY_ADWARE, 10, "Rewrites network requests while carrying ad-network code")

    # ── Bundling unwanted software ────────────────────────────────
    if feat("has_nativeMessaging"):
        add(CATEGORY_BUNDLING, 30, "nativeMessaging permission — can drive a companion desktop binary")
    if feat("has_downloads") and _KW_INSTALLER.search(code):
        add(CATEGORY_BUNDLING, 22, "downloads permission used around installer/executable references")
    if feat("has_management"):
        add(CATEGORY_BUNDLING, 16, "management permission — can install/disable other extensions")

    # ── Malware (obfuscation, dynamic code, C2) ───────────────────
    if "HIGH_EVAL_USAGE" in flagset:
        add(CATEGORY_MALWARE, 24, f"{int(feat('eval_count'))} eval() call sites — dynamic payload execution")
    if "DYNAMIC_CODE_INJECTION" in flagset:
        add(CATEGORY_MALWARE, 18, f"{int(feat('exec_script_count'))} script-injection call sites")
    if "BASE64_OBFUSCATION" in flagset:
        add(CATEGORY_MALWARE, 14, f"{int(feat('atob_count'))} base64 decode call sites — hidden payloads")
    if "OBFUSCATED_STRINGS" in flagset:
        add(CATEGORY_MALWARE, 12, f"{int(feat('long_string_count'))} long encoded strings — packed payload")
    if feat("hex_escape_count") >= 4:
        add(CATEGORY_MALWARE, 10, "Hex-escaped string obfuscation in the source")
    if "WEBSOCKET_TO_EXTERNAL" in flagset or _KW_C2.search(code):
        add(CATEGORY_MALWARE, 22, "Persistent external channel consistent with command-and-control")
    if "EVAL_AT_RUNTIME" in flagset:
        add(CATEGORY_MALWARE, 20, "Sandbox caught eval() executing at runtime")
    if "WEBREQUEST_BLOCKING_WITH_EVAL" in flagset:
        add(CATEGORY_MALWARE, 20, "webRequestBlocking combined with eval() — request tampering")
    if code_available:
        if ml_prob >= 0.90:
            add(CATEGORY_MALWARE, 32,
                f"XGBoost classified this as malicious with {ml_prob * 100:.1f}% probability")
        elif ml_prob >= 0.80:
            add(CATEGORY_MALWARE, 22,
                f"XGBoost classified this as malicious with {ml_prob * 100:.1f}% probability")
        elif ml_prob >= 0.60:
            add(CATEGORY_MALWARE, 12, f"XGBoost probability {ml_prob * 100:.1f}%")
    if "ZERO_DAY_ANOMALY" in flagset:
        add(CATEGORY_MALWARE, 14,
            f"Isolation Forest anomaly {anomaly_score:.0f}/100 — unlike any benign extension in training")

    # ── Policy violation (broad, unjustified capability) ──────────
    broad: List[str] = []
    if feat("has_all_urls"):
        broad.append("all-URLs host access")
    if feat("has_webRequest"):
        broad.append("webRequest")
    if feat("has_proxy"):
        broad.append("proxy")
    if feat("has_management"):
        broad.append("management")
    if feat("has_tabs"):
        broad.append("tabs")
    if feat("total_permission_count") >= 8:
        broad.append(f"{int(feat('total_permission_count'))} declared permissions")
    if len(broad) >= 2:
        add(CATEGORY_POLICY, 8 + 4 * min(len(broad), 4), "Over-broad capability set: " + ", ".join(broad))
    if code_available and ml_prob >= 0.50:
        add(CATEGORY_POLICY, 10, f"XGBoost probability {ml_prob * 100:.1f}% over the decision boundary")
    if code_available and static_score >= 40:
        add(CATEGORY_POLICY, 6, f"Static score {static_score:.0f}/100 in the suspicious band")

    # ── Baseline — the ID is blocklisted, so something is wrong ───
    add(CATEGORY_SUSPICIOUS, 12,
        "Extension ID is on the finalized blocklist but shows no dominant threat class")
    if dynamic_score > 0:
        add(CATEGORY_SUSPICIOUS, 4, f"Sandbox behaviour score {dynamic_score:.0f}/100")

    # ── Merge the spyware family ──────────────────────────────────
    # Spyware and its exfiltration variant are the same threat class scored
    # from two angles — capability (permissions/code) and observation
    # (sandbox). Sum them so a split vote doesn't hand the verdict to an
    # unrelated category that scored lower than either half combined.
    spy_total = points[CATEGORY_SPYWARE] + points[CATEGORY_EXFIL]
    if spy_total > 0:
        if points[CATEGORY_EXFIL] >= 20:
            # Behaviour was actually observed leaving the browser — say so.
            points[CATEGORY_EXFIL] = spy_total
            why[CATEGORY_EXFIL]    = why[CATEGORY_EXFIL] + why[CATEGORY_SPYWARE]
            points[CATEGORY_SPYWARE] = 0.0
        else:
            points[CATEGORY_SPYWARE] = spy_total
            why[CATEGORY_SPYWARE]    = why[CATEGORY_SPYWARE] + why[CATEGORY_EXFIL]
            points[CATEGORY_EXFIL]   = 0.0

    # ── Pick the winner ───────────────────────────────────────────
    # A specific threat class wins only once it has cleared the evidence bar;
    # below that we fall back to the sheet's own generic reasons rather than
    # naming a threat the analysis cannot actually support.
    ranked = sorted(points.items(), key=lambda kv: (-kv[1], _PRIORITY.index(kv[0])))
    specific = [(name, sc) for name, sc in ranked if name in _SPECIFIC]

    if specific and specific[0][1] >= SPECIFIC_MIN_EVIDENCE:
        best, best_score = specific[0]
    elif points[CATEGORY_POLICY] >= POLICY_MIN_EVIDENCE:
        best, best_score = CATEGORY_POLICY, points[CATEGORY_POLICY]
    else:
        # A delisted extension gets the sheet's "removed, reason unestablished"
        # wording; one still in the store gets "in store but suspicious".
        best = CATEGORY_SUSPICIOUS if code_available else CATEGORY_REMOVED
        best_score = points[CATEGORY_SUSPICIOUS]
        why[best] = list(why[CATEGORY_SUSPICIOUS])
        # Carry the strongest near-miss into the rationale so the analyst can
        # see what the analysis leaned towards without it being asserted.
        if specific and specific[0][1] > 0:
            near, near_score = specific[0]
            why[best] = why[best] + [
                f"Closest threat class was {near} at {near_score:.0f} evidence points "
                f"- below the {SPECIFIC_MIN_EVIDENCE:.0f}-point bar required to name it"
            ]

    if not code_available:
        method = "declared capability only (archived manifest — extension delisted)"
    elif sandbox_ran:
        method = "XGBoost + Isolation Forest + dynamic sandbox"
    else:
        method = "XGBoost + Isolation Forest (sandbox unavailable)"

    # Runners-up list only the *specific* classes that scored something. A
    # fallback's points aren't comparable with a specific class's (they are
    # awarded on different terms), so listing "Policy Violation: 40" next to a
    # winning "Malware: 32" would read as a contradiction rather than context.
    runners = [(name, sc) for name, sc in ranked
               if name != best and sc > 0 and name in _SPECIFIC][:3]

    return ReasonVerdict(
        reason=best,
        confidence=_confidence_for(best_score),
        score=best_score,
        rationale=why[best][:6],
        runners_up=runners,
        method=method,
    )


# ── Sheet-ready evidence bundle ───────────────────────────────────────────────

def build_live_evidence(
    *,
    manifest: dict,
    ext_id: str = "",
    ext_path: str = "",
    webstore_url: str = "",
    crx_sha256: str = "",
    store_hint: str = "",
    observed_at: Optional[datetime] = None,
) -> Dict[str, str]:
    """Everything the live intercept can state as fact about this extension.

    Only keys with a real value are returned — a caller must never overwrite
    a curated sheet field with an empty string.
    """
    name, provenance = resolve_extension_name(manifest, ext_path, webstore_url, ext_id)
    version = str((manifest or {}).get("version") or "").strip()
    evidence: Dict[str, str] = {}

    if name:
        evidence["extension_name"]  = sheet_safe(name)
        evidence["name_provenance"] = provenance
    if version:
        evidence["version"] = sheet_safe(version)
    store = store_hint or store_from_url(webstore_url, default="")
    if store:
        evidence["store"] = store
    if crx_sha256:
        evidence["sha256"] = crx_sha256.lower()
    evidence["date"] = sheet_date(observed_at)
    return evidence
