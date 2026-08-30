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
    "ZERO_DAY_ANOMALY": {
        "severity": "HIGH",
        "desc": "Isolation Forest (trained only on benign extensions) flagged this "
                "extension as statistically unlike any known-benign pattern — a "
                "possible zero-day or novel attack technique not represented in "
                "the labelled malicious training data.",
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
    "EXTENSION_LOAD_FAILED": {
        "severity": "MEDIUM",
        "desc": "Chromium refused to load the extension in the sandbox, so no "
                "runtime behaviour could be observed. The dynamic layer gave no "
                "coverage for this analysis and the verdict rests on static "
                "evidence alone — it is NOT evidence that the extension is clean. "
                "Common causes: declarativeNetRequest rulesets that cannot be "
                "indexed, a manifest Chromium rejects, or a read-only extension "
                "directory.",
    },
    "SANDBOX_NOT_REQUESTED": {
        "severity": "LOW",
        "desc": "Dynamic sandbox was deliberately skipped for this run (bulk "
                "blocklist sweep) — the evidence derived here rests on static "
                "analysis alone and can be strengthened by re-running with the "
                "sandbox enabled.",
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

# How each isolation level is described in the human-readable summary.
_ISOLATION_NOTE = {
    "ephemeral_vm": "Observed inside a disposable virtual machine, created for "
                    "this analysis and destroyed afterwards.",
    "container":    "Observed inside a throwaway container sharing the host kernel.",
    "browser_profile": "Observed on the host in a throwaway browser profile — "
                       "browser state was isolated, the operating system was not.",
    "none":         "Observed with no containment.",
}


# ── Plain-language summary ────────────────────────────────────────────────────
# The `summary` field above is written for someone who knows what an ML
# probability is. This one is written for the person deciding whether to click
# Install, and it answers three questions in order: what was decided, what the
# extension is able to do, and what was actually seen happening.
#
# It is assembled from evidence already computed rather than from a per-verdict
# script, so it cannot drift out of agreement with the flags shown beside it.

_VERDICT_OPENER = {
    "MALICIOUS":  "This extension is dangerous and should not be installed.",
    "SUSPICIOUS": "This extension behaves in ways worth checking before you install it.",
    "SAFE":       "Nothing harmful was found in this extension.",
}


# The catalogue entries this summary is assembled from are written with em
# dashes, which is fine in a technical panel and wrong here: three of them in
# one paragraph is the single strongest "a machine wrote this" tell, and it
# reads as unfinished rather than authoritative. Normalise on the way out
# rather than rewriting every catalogue entry, so the technical panels keep
# their own voice.
_DASHES = ("—", "–", " -- ")


def _humanise(text: str) -> str:
    """Turn catalogue prose into something a person would have written."""
    out = str(text or "").strip()
    for dash in _DASHES:
        out = out.replace(f" {dash} ", ", ").replace(dash, ", ")
    # Lab jargon: the reader does not care which of our components saw it.
    for prefix, repl in (
        ("Sandbox detected ", "The test run found "),
        ("Sandbox observed ", "The test run saw "),
        ("Sandbox did not ",  "The test run did not "),
        ("Extension made ",   "It made "),
        ("Uses ",             "It uses "),
        ("Injects ",          "It injects "),
        ("Decodes ",          "It decodes "),
        ("Contains ",         "It contains "),
        ("Combines ",         "It combines "),
    ):
        if out.startswith(prefix):
            out = repl + out[len(prefix):]
            break
    out = out.replace(", ,", ",").replace(",,", ",").replace(" ,", ",")
    while "  " in out:
        out = out.replace("  ", " ")
    if out and not out.endswith((".", "!", "?")):
        out += "."
    return out


def _plain_summary(verdict: str, final_score: float, explained: List[Dict],
                   permissions: List[Dict], dynamic_info: Dict) -> str:
    """Two or three sentences, no jargon, safe to show a non-specialist."""
    parts: List[str] = [_VERDICT_OPENER.get(verdict, _VERDICT_OPENER["SUSPICIOUS"])]

    # What it is allowed to do. Capability is stated even on a clean verdict —
    # an extension that has done nothing yet still holds whatever it was granted.
    severe = [p for p in permissions
              if str(p.get("severity")) in ("CRITICAL", "HIGH")]
    if severe:
        lead = severe[0]
        others = len(severe) - 1
        cap = _humanise(lead.get("description", "")).rstrip(".")
        # Descriptions are already written as "Can read and change your data…"
        cap = cap[0].lower() + cap[1:] if cap else "hold wide-reaching access"
        parts.append(
            f"It {cap}"
            + (f", plus {others} other high-risk permission"
               f"{'s' if others != 1 else ''}." if others > 0 else ".")
        )

    # What was actually observed. Only claimed when the sandbox really ran —
    # "nothing was seen" is a false comfort if nothing was ever watched.
    observed = dynamic_info.get("observed") or {}
    counts = observed.get("counts") or {}
    if dynamic_info.get("executed"):
        hosts = int(counts.get("hosts") or 0)
        if hosts:
            bg = any("background" in (h.get("sources") or [])
                     for h in (observed.get("hosts") or []))
            sentence = (f"While running in an isolated test browser it contacted "
                        f"{hosts} external server{'s' if hosts != 1 else ''}")
            sentence += (", some of them from its background process, which keeps "
                         "running even when you are not using it." if bg else ".")
            parts.append(sentence)
        else:
            parts.append("While running in an isolated test browser it contacted "
                         "no external servers.")
    elif dynamic_info.get("extension_loaded") is False:
        parts.append("It could not be started in the test browser, so none of its "
                     "behaviour could be watched. That is not the same as it "
                     "being safe.")
    else:
        parts.append("Its behaviour was not tested, so this verdict is based only "
                     "on reading its code and permissions.")

    # Name the single worst finding, in its own words.
    if explained:
        worst = explained[0]
        if str(worst.get("severity")) in ("CRITICAL", "HIGH"):
            parts.append(_humanise(worst.get("description", "")))

    return " ".join(p for p in parts if p)


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
    anomaly_pct   = round(static_info.get("anomaly_score", 0) * 100, 1)
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
    isolation = dynamic_info.get("isolation") or None
    if sandbox_ran:
        sandbox_note = (
            f"Dynamic sandbox {'confirmed additional suspicious behaviour' if dynamic_score > 0 else 'found no additional signals'} "
            f"(dynamic score: {dynamic_score}/100)."
        )
        # Name the containment in the same sentence as the finding — a
        # behavioural result observed on the host is a weaker claim than the
        # same result observed inside a disposable VM, and the summary should
        # never leave the reader to assume which one happened.
        if isolation:
            sandbox_note += " " + _ISOLATION_NOTE.get(
                isolation.get("level", ""),
                f"Containment: {isolation.get('backend', 'unknown')}.")
    elif dynamic_info.get("extension_loaded") is False:
        # Distinct from "not executed": the sandbox ran, the extension did not.
        # Saying "no signals found" here would read as a clean bill of health
        # for an extension that was never observed.
        sandbox_note = (
            "Dynamic sandbox started but Chromium rejected the extension, so no "
            "runtime behaviour was observed. The verdict rests on static analysis "
            "alone; this is not evidence of safety."
        )
    else:
        sandbox_note = (
            "Dynamic sandbox was not executed — verdict is based on static analysis only."
        )

    blocklist_details = static_info.get("blocklist_details")

    if static_info.get("hash_match"):
        if blocklist_details:
            name   = blocklist_details.get("extension_name") or "an unnamed extension"
            reason = blocklist_details.get("reason") or "an unestablished reason"
            when   = blocklist_details.get("date")
            summary = f"MALICIOUS — matched the blocklist as {name!r} ({reason}"
            summary += f", reported {when})." if when else ")."
            if blocklist_details.get("reason_derived"):
                detail_block = blocklist_details.get("reason_detail") or {}
                summary += (
                    f" The sheet had no reason on record for this ID, so it was derived live "
                    f"from {detail_block.get('method', 'the detection stack')} "
                    f"with {str(detail_block.get('confidence', 'unrated')).lower()} confidence."
                )
            elif blocklist_details.get("enriched"):
                summary += (" Missing evidence was completed live from this intercept: "
                            + ", ".join(blocklist_details.get("enriched_fields", [])) + ".")
            else:
                summary += " No further analysis required."
        else:
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
    # A blocklist hit is scored by authority, not by fusion — printing the
    # 0.7/0.3 formula there would show arithmetic that doesn't hold, since the
    # sandbox may well have scored the extension lower than 100.
    if result.get("score_source") == "blocklist":
        formula = (f"Blocklist authority: {final_score} "
                   f"(models measured static {static_info.get('measured_static_score', 0) * 100:.1f}"
                   + (f", sandbox {dynamic_score}" if sandbox_ran else "") + ")")
    elif sandbox_ran:
        formula = f"0.7 × {static_score} + 0.3 × {dynamic_score} = {final_score}"
    else:
        formula = f"Static only: {static_score} (sandbox not run)"

    return {
        "summary":      summary,
        "risk_level":   _RISK_LABEL.get(verdict, "HIGH"),
        # Carried in the report so a result reloaded from SQLite can tell an
        # authoritative blocklist score apart from a classifier score — the
        # analyses table has no column for it.
        "score_source": result.get("score_source", ""),
        "score_breakdown": {
            "final":         final_score,
            "static":        static_score,
            "dynamic":       dynamic_score,
            "ml_score":      ml_prob_pct,
            "anomaly_score": anomaly_pct,
            "sandbox_ran":   sandbox_ran,
            "formula":       formula,
            # Present only when the models actually ran; None means the
            # verdict short-circuited on a documented blocklist record.
            "measured_static": (round(static_info["measured_static_score"] * 100, 1)
                                if "measured_static_score" in static_info else None),
        },
        "flags":             explained,
        "recommendation":    _RECOMMENDATIONS.get(verdict, ""),
        "blocklist_details": blocklist_details,
        # Full containment record for the dashboard and for the write-up —
        # None when the sandbox never ran.
        "isolation":         isolation,
        # ── Report-facing extras ────────────────────────────────────────────
        # These ride inside the report rather than beside it because the report
        # is the only part of a result that db.py persists whole. Anything kept
        # outside it is present on a live analysis and silently absent when the
        # same analysis is reopened from history.
        "identity":      result.get("identity") or {},
        "permissions":   result.get("permissions") or [],
        "observed":      dynamic_info.get("observed") or {},
        "plain_summary": _plain_summary(
            verdict, final_score, explained,
            result.get("permissions") or [],
            dynamic_info,
        ),
    }
