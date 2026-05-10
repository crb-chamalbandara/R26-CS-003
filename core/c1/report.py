"""
C1 — Verdict report builder.
Converts raw analyzer output into a structured, human-readable report
for the dashboard and research paper documentation.
"""
from __future__ import annotations

from typing import Dict, List

# ── Flag catalogue ────────────────────────────────────────────────────────────
# Each entry: severity (CRITICAL / HIGH / MEDIUM / LOW) + one-sentence description.
_FLAGS: Dict[str, Dict] = {
    # Static rule-based flags
    "HIGH_EVAL_USAGE": {
        "severity": "HIGH",
        "desc": "Uses eval() 5+ times — a common obfuscation technique to execute "
                "dynamically generated payloads that static scanners cannot read.",
    },
    "BASE64_OBFUSCATION": {
        "severity": "MEDIUM",
        "desc": "Decodes base64 strings (atob) 3+ times — used to hide malicious "
                "URLs, scripts, or exfiltration endpoints in encoded form.",
    },
    "WEBREQUEST_BLOCKING_WITH_EVAL": {
        "severity": "HIGH",
        "desc": "Combines webRequestBlocking permission with eval(). Can intercept "
                "and dynamically modify every web request, including login credentials.",
    },
    "DYNAMIC_CODE_INJECTION": {
        "severity": "HIGH",
        "desc": "Injects scripts into pages via executeScript 5+ times — can steal "
                "data, modify page content, or hijack user sessions.",
    },
    "OBFUSCATED_STRINGS": {
        "severity": "MEDIUM",
        "desc": "Contains 3+ unusually long encoded strings — indicates payload "
                "hiding where malicious URLs or scripts are stored in obfuscated form.",
    },
    "HASH_MATCH": {
        "severity": "CRITICAL",
        "desc": "Extension ID matches a known-malicious blocklist entry. "
                "This extension has been confirmed malicious by prior research.",
    },
    # Dynamic sandbox flags
    "EVAL_AT_RUNTIME": {
        "severity": "HIGH",
        "desc": "Sandbox observed eval() executing at runtime — the extension "
                "generates and runs code dynamically, a strong indicator of payload delivery.",
    },
    "COOKIE_EXFILTRATION_RISK": {
        "severity": "CRITICAL",
        "desc": "Sandbox detected cookie access combined with an external data POST — "
                "high risk of session token or credential theft.",
    },
    "COOKIE_READ_WITH_EXTERNAL": {
        "severity": "HIGH",
        "desc": "Sandbox observed cookie reads alongside external network requests — "
                "possible credential exfiltration.",
    },
    "DATA_POST_TO_EXTERNAL": {
        "severity": "HIGH",
        "desc": "Sandbox detected POST requests with body data sent to external domains — "
                "potential data exfiltration.",
    },
    "WEBSOCKET_TO_EXTERNAL": {
        "severity": "HIGH",
        "desc": "Sandbox observed WebSocket connections to external hosts — "
                "can enable persistent C2 (command-and-control) communication.",
    },
    "KEYBOARD_MONITORING": {
        "severity": "HIGH",
        "desc": "Sandbox detected keyboard event listeners — "
                "this extension may be capturing keystrokes (keylogging).",
    },
    "FORM_SUBMIT_OBSERVED": {
        "severity": "MEDIUM",
        "desc": "Sandbox observed a form submission sent to an external URL — "
                "risk of credential capture from login forms.",
    },
    "HIGH_REQUEST_VOLUME": {
        "severity": "MEDIUM",
        "desc": "Extension made more than 8 external requests during sandbox observation — "
                "unusual network activity for a browser extension.",
    },
    # Meta flags
    "SANDBOX_ERROR": {
        "severity": "LOW",
        "desc": "Dynamic sandbox encountered an error — verdict is based on static "
                "analysis only. Treat the result with additional caution.",
    },
    "SANDBOX_SKIPPED_NO_PATH": {
        "severity": "LOW",
        "desc": "Dynamic sandbox was not run (extension path unavailable) — "
                "verdict reflects static analysis only.",
    },
    "MODEL_NOT_LOADED": {
        "severity": "LOW",
        "desc": "ML model could not be loaded — static scoring unavailable. "
                "Manual review is recommended.",
    },
    "MANIFEST_PARSE_FAILED": {
        "severity": "LOW",
        "desc": "manifest.json could not be parsed — the extension may be "
                "malformed, corrupted, or using an unsupported format.",
    },
    "TRUSTED_PUBLISHER": {
        "severity": "LOW",
        "desc": "Extension ID matched the trusted publisher allowlist — "
                "this extension is from a verified, well-known developer "
                "and is considered safe without further ML analysis.",
    },
}

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

_RECOMMENDATIONS = {
    "MALICIOUS":   "Block installation. Multiple detection methods confirm malicious intent. "
                   "Do not install under any circumstances.",
    "SUSPICIOUS":  "Do not install without expert review. This extension exhibits patterns "
                   "associated with malicious behaviour. Treat with caution.",
    "SAFE":        "No significant threats detected. The extension appears safe based on "
                   "static analysis and sandbox behaviour.",
}

_RISK_LABEL = {
    "MALICIOUS":  "CRITICAL",
    "SUSPICIOUS": "HIGH",
    "SAFE":       "LOW",
}


def build_report(result: Dict) -> Dict:
    """
    Enrich a raw analyzer output dict with a structured report.
    Returns the report dict (does not mutate `result`).
    """
    verdict      = result.get("verdict", "SUSPICIOUS")
    final_score  = round(result.get("score", 0) * 100, 1)
    static_info  = result.get("static",  {})
    dynamic_info = result.get("dynamic", {})
    flags        = result.get("flags",   [])

    static_score  = round(static_info.get("score",    0) * 100, 1)
    dynamic_score = round(dynamic_info.get("score",   0) * 100, 1)
    ml_prob_pct   = round(static_info.get("ml_score", 0) * 100, 1)
    sandbox_ran   = dynamic_info.get("executed", False)

    # ── Flag explanations, sorted by severity ────────────────────────────────
    explained: List[Dict] = []
    for flag in flags:
        base = flag.split(":")[0]          # strip "SUSPICIOUS_DOMAIN:1.2.3.4" suffix
        info = _FLAGS.get(base, {
            "severity": "MEDIUM",
            "desc":     f"Detected signal: {flag}",
        })
        explained.append({
            "flag":        flag,
            "severity":    info["severity"],
            "description": info["desc"],
        })
    explained.sort(key=lambda f: _SEV_ORDER.get(f["severity"], 99))

    # ── Summary sentence ──────────────────────────────────────────────────────
    confidence = (
        "high"     if final_score >= 75 else
        "moderate" if final_score >= 50 else
        "low"
    )
    if sandbox_ran:
        sandbox_note = (
            f"Dynamic sandbox {'confirmed additional suspicious behaviour' if dynamic_score > 0 else 'found no additional signals'} "
            f"(dynamic score: {dynamic_score}/100)."
        )
    else:
        sandbox_note = (
            "Dynamic sandbox was not executed — verdict is based on static analysis only."
        )

    if static_info.get("hash_match"):
        summary = (
            f"MALICIOUS — extension ID matched the known-malicious blocklist. "
            f"No further analysis required."
        )
    else:
        summary = (
            f"{verdict} extension detected with {confidence} confidence "
            f"(final score: {final_score}/100). "
            f"ML classifier probability: {ml_prob_pct}%. {sandbox_note}"
        )

    # ── Score breakdown ───────────────────────────────────────────────────────
    if sandbox_ran:
        formula = f"0.7 × {static_score} + 0.3 × {dynamic_score} = {final_score}"
    else:
        formula = f"Static only: {static_score} (sandbox not run)"

    return {
        "summary":    summary,
        "risk_level": _RISK_LABEL.get(verdict, "HIGH"),
        "score_breakdown": {
            "final":       final_score,
            "static":      static_score,
            "dynamic":     dynamic_score,
            "sandbox_ran": sandbox_ran,
            "formula":     formula,
        },
        "flags":          explained,
        "recommendation": _RECOMMENDATIONS.get(verdict, ""),
    }
