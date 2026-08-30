"""
C1 — analyzer.py  |  The Pipeline Orchestrator  (most important file)
-----------------------------------------------------------------------
Purpose : Coordinate the full detection pipeline — from raw manifest JSON
          to final SAFE/SUSPICIOUS/MALICIOUS verdict with a structured report.
Role    : The single entry point that main.py calls for every analysis.
          It knows nothing about the dashboard or the API — it only takes
          extension data in and returns a verdict dict out.

Detection pipeline order:
  1. Load models + blocklist (once at startup)
  2. Hash/ID blocklist check    → instant MALICIOUS if ID is known-bad
  3. XGBoost ML scoring         → static_score (0–100), known-pattern detection
  4. Rule-based boosters        → raise score if extreme code patterns found
  5. Isolation Forest (zero-day)→ anomaly_score (0–100); raises static_score
                                   when an extension looks nothing like any
                                   benign extension seen in training, even if
                                   XGBoost doesn't recognise it as malicious
  6. Dynamic sandbox (optional) → dynamic_score (0–100)  only if score ≥ 50
  7. Score fusion               → 0.7 × static + 0.3 × dynamic
  8. Verdict thresholds         → MALICIOUS ≥ 70 | SUSPICIOUS ≥ 40 | SAFE < 40
  9. Report generation          → human-readable explanation for dashboard
"""
from __future__ import annotations

import json
import os
from typing import Dict, List, Optional

from .features     import extract_manifest_features, build_feature_vector  # feature extraction
from .static_model import (                                                 # ML model runner
    load_model, load_feature_columns, predict_score, predict_anomaly_score,
)
from .report       import build_report                                      # human-readable report
from .blocklist    import (                                                 # finalized blocklist loader/writer
    load_blocklist, blocklist_stats, entry_gaps, apply_updates, update_entry,
    incomplete_ids, BlocklistEntry,
)
from .enrich       import build_live_evidence, derive_reason                # live evidence resolver
from .permissions  import explain_permissions                               # declared-capability risk catalogue

# Module-level singletons — loaded once at startup and reused for every analysis
_MODEL            = None
_ISO_FOREST       = None    # Isolation Forest — zero-day anomaly detector (optional; graceful if missing)
_FEATURE_COLUMNS: List[str] = []
# ext_id -> BlocklistEntry (rich evidence) if loaded from the finalized CSV,
# or ext_id -> None if only the legacy ID-only malicious_ids.json was found.
# Membership (`in _BLOCKLIST`) is the match check; `.get(ext_id)` is the detail.
_BLOCKLIST: Dict[str, Optional[BlocklistEntry]] = {}
_BLOCKLIST_PATH: str = ""   # sheet the entries came from — where enrichment is written back

# If static score is at or above this value, the dynamic sandbox will run
SANDBOX_TRIGGER_THRESHOLD = 50.0

# Isolation Forest anomaly score (0-100) at or above this is treated as a
# zero-day signal worth raising the static score for.
#
# NOT 50 (the notebook's draft "decision boundary" and the population-wide
# calibration in scripts/train_isolation_forest.py) — that value looks fine
# in aggregate (~2% benign false-positive rate across the whole benign set)
# but concentrates almost entirely on exactly the complex, legitimate power
# extensions this component works hardest to clear (Adobe Acrobat 56.4,
# LastPass 53.3, Honey 50.3, 1Password 56.6, Loom 50.2 all cleared 50, even
# though every one of them is IN the benign training set). Raised to 60,
# above which none of those known-benign extensions score, while a
# genuinely extreme synthetic outlier still reaches ~65-70. See
# scripts/README.md for the validation script and full numbers.
ISO_FOREST_ANOMALY_THRESHOLD = 60.0


def _load_resources() -> None:
    """Load the XGBoost model, Isolation Forest, feature column list, and
    malicious blocklist from disk. Uses a guard clause — only loads once
    and reuses for all subsequent calls."""
    global _MODEL, _ISO_FOREST, _FEATURE_COLUMNS, _BLOCKLIST, _BLOCKLIST_PATH
    if _MODEL is not None and _FEATURE_COLUMNS:
        return    # already loaded — skip

    base_dir       = os.path.dirname(os.path.abspath(__file__))
    model_path     = os.path.join(base_dir, "models", "extension_detector_model.pkl")
    if_model_path  = os.path.join(base_dir, "models", "isolation_forest_model.pkl")
    feature_path   = os.path.join(base_dir, "data",   "dataset_clean_v3_features.json")
    # Finalized blocklist (6,656 IDs + evidence: name, reason, source, date,
    # store, version, SHA256) — combines malext_sentry + chrome_mal_ids.
    # Supersedes the older ID-only malicious_ids.json (2,199 IDs, no evidence),
    # which is kept only as a fallback if the finalized sheet is ever missing.
    blocklist_path = os.path.join(base_dir, "data", "malext_sentry and chrome_mal_ids Finalized Blocklist IDs.csv")
    legacy_hash_db_path = os.path.join(base_dir, "data", "malicious_ids.json")

    if os.path.exists(model_path):
        _MODEL = load_model(model_path)                        # load trained XGBoost model into memory
    if os.path.exists(if_model_path):
        _ISO_FOREST = load_model(if_model_path)                # load Isolation Forest (same joblib format)
    if os.path.exists(feature_path):
        _FEATURE_COLUMNS = load_feature_columns(feature_path) # load the 33 feature column names in order

    if os.path.exists(blocklist_path):
        _BLOCKLIST      = load_blocklist(blocklist_path)         # ext_id -> rich evidence dict
        _BLOCKLIST_PATH = blocklist_path                         # where enrichment gets written back
    elif os.path.exists(legacy_hash_db_path):
        with open(legacy_hash_db_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        _BLOCKLIST = {ext_id: None for ext_id in data.get("malicious_extension_ids", [])}


# ══════════════════════════════════════════════════════════════════════════════
#  Blocklist introspection — used by the API and the backfill script
# ══════════════════════════════════════════════════════════════════════════════

def blocklist_probe(extension_id: str) -> Dict:
    """Answer "is this ID blocklisted, and is its row documented?" without
    downloading or analysing anything.

    main.py calls this the moment an install is intercepted so it can tell
    the dashboard whether this hit will take the instant path (row already
    has full evidence) or the evidence-gathering path (row has gaps, so the
    ML stack and the sandbox are about to run).
    """
    _load_resources()
    ext_id = (extension_id or "").strip().lower()
    entry  = _BLOCKLIST.get(ext_id) if ext_id in _BLOCKLIST else None
    matched = bool(ext_id) and ext_id in _BLOCKLIST
    gaps = entry_gaps(entry) if matched else []
    return {
        "match":       matched,
        "gaps":        gaps,
        "needs_evidence": bool(matched and gaps),
        "entry":       entry,
    }


def blocklist_coverage() -> Dict:
    """Documented-vs-undocumented counts for the whole sheet."""
    _load_resources()
    real = {k: v for k, v in _BLOCKLIST.items() if v}
    stats = blocklist_stats(real) if real else {
        "total": len(_BLOCKLIST), "documented": 0, "incomplete": len(_BLOCKLIST),
        "missing_by_field": {}, "coverage_pct": 0.0,
    }
    stats["sheet_path"] = _BLOCKLIST_PATH
    return stats


def blocklist_incomplete_ids(limit: int = 0) -> List[str]:
    """IDs whose sheet row still has at least one undocumented field."""
    _load_resources()
    ids = incomplete_ids({k: v for k, v in _BLOCKLIST.items() if v})
    return ids[:limit] if limit else ids


def reload_blocklist() -> Dict:
    """Re-read the sheet from disk and return the new coverage summary.

    The in-memory blocklist is loaded once at startup, so a sweep run from a
    separate process (scripts/backfill_blocklist_evidence.py) is invisible to a
    server that is already running. This picks those writes up without a
    restart.
    """
    global _BLOCKLIST
    _load_resources()
    if _BLOCKLIST_PATH and os.path.exists(_BLOCKLIST_PATH):
        _BLOCKLIST = load_blocklist(_BLOCKLIST_PATH)
    return blocklist_coverage()


# ══════════════════════════════════════════════════════════════════════════════
#  Report-facing extras — identity and declared capability
# ══════════════════════════════════════════════════════════════════════════════

def _identity(manifest_dict: dict, ext_id: str = "", ext_path: str = "",
              webstore_url: str = "") -> Dict:
    """Name/version to head the report with.

    Name resolution is delegated to enrich.resolve_extension_name, which
    already handles the `__MSG_appName__` i18n placeholder case by reading the
    extension's own _locales bundle — a manifest name is not reliably a
    literal string, and re-deriving that here would just be a worse copy.
    """
    from .enrich import resolve_extension_name
    try:
        name, provenance = resolve_extension_name(
            manifest_dict or {}, ext_path or "", webstore_url or "", ext_id or "")
    except Exception:
        name, provenance = "", ""
    return {
        "name":       name or "",
        "version":    str((manifest_dict or {}).get("version") or "").strip(),
        "ext_id":     ext_id or "",
        "provenance": provenance or "",
    }


def _observed_summary(sandbox_result: Dict) -> Dict:
    """Compact per-host rollup of what the sandbox saw, for the report."""
    try:
        from .sandbox import summarise_observations
        return summarise_observations(sandbox_result)
    except Exception:
        return {"hosts": [], "counts": {}, "truncated": False}


# ══════════════════════════════════════════════════════════════════════════════
#  Static stack — shared by the normal pipeline and the blocklist evidence run
# ══════════════════════════════════════════════════════════════════════════════

def _run_static_stack(manifest_dict: dict, source_code: str) -> Dict:
    """Steps 4-5b in one place: features -> XGBoost -> rule boosters ->
    Isolation Forest. Returns every intermediate the caller might need."""
    features       = extract_manifest_features(manifest_dict, source_code or "")  # 33 numeric features
    vector         = build_feature_vector(_FEATURE_COLUMNS, features)              # ordered list for model
    ml_score, prob = predict_score(_MODEL, vector)                                 # threat score 0–100, probability 0–1

    flags: List[str] = []
    static_score = ml_score    # start from what the ML model calculated

    if features.get("eval_count", 0) >= 8:         # 8+ eval() calls is extreme — nearly always malicious
        flags.append("HIGH_EVAL_USAGE")
        static_score = max(static_score, 50.0)     # force above sandbox threshold so sandbox runs
    elif features.get("eval_count", 0) >= 3:       # 3–7 eval() calls — flag it but don't override ML
        flags.append("HIGH_EVAL_USAGE")

    if features.get("exec_script_count", 0) >= 5:  # 5+ script injections is a strong injection signal
        flags.append("DYNAMIC_CODE_INJECTION")
        static_score = max(static_score, 42.0)

    if features.get("atob_count", 0) >= 8:         # 8+ base64 decodes suggests heavy payload obfuscation
        flags.append("BASE64_OBFUSCATION")
        static_score = max(static_score, 38.0)     # floor is below SUSPICIOUS (40) — avoids false positives
    elif features.get("atob_count", 0) >= 3:       # 3–7 atob calls (common in benign extensions too) — flag only
        flags.append("BASE64_OBFUSCATION")

    if features.get("long_string_count", 0) >= 6:  # 6+ very long strings = likely obfuscated payload storage
        flags.append("OBFUSCATED_STRINGS")
        static_score = max(static_score, 28.0)

    # webRequestBlocking + eval together = can intercept AND dynamically modify any network request
    if features.get("has_webRequestBlocking", 0) and features.get("eval_count", 0) >= 5:
        flags.append("WEBREQUEST_BLOCKING_WITH_EVAL")
        static_score = max(static_score, 60.0)    # strong signal — force into suspicious/malicious range

    anomaly_score = 0.0
    if _ISO_FOREST is not None:
        anomaly_score = predict_anomaly_score(_ISO_FOREST, vector)
        if anomaly_score >= ISO_FOREST_ANOMALY_THRESHOLD and anomaly_score > static_score:
            flags.append("ZERO_DAY_ANOMALY")
            static_score = anomaly_score

    return {
        "features":      features,
        "ml_score":      ml_score,
        "prob":          prob,
        "static_score":  static_score,
        "anomaly_score": anomaly_score,
        "flags":         flags,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  Step 2a — blocklist evidence run
# ══════════════════════════════════════════════════════════════════════════════

async def _gather_blocklist_evidence(
    *,
    ext_id: str,
    entry: Optional[BlocklistEntry],
    manifest_dict: dict,
    source_code: str,
    extension_path: str,
    webstore_url: str,
    crx_sha256: str,
    store_hint: str,
    persist: bool,
    run_sandbox_layer: bool = True,
    code_available: bool = True,
) -> Dict:
    """Document an under-reported blocklist row from the live intercept.

    The sheet knows this ID is malicious but not *why*, or under what name,
    version, store or hash. Everything needed to answer that is already on
    disk at this point — the CRX has been downloaded and unpacked — so this
    runs the real detection stack (XGBoost + rule boosters + Isolation
    Forest, then the dynamic sandbox) and turns what they observed into the
    sheet's own vocabulary via enrich.derive_reason().

    Unlike the normal pipeline the sandbox is NOT gated on the static score:
    the ID is already confirmed malicious, so runtime evidence is always
    worth collecting — and a reason derived with behavioural evidence is a
    far stronger record than one derived from static features alone.
    """
    # Work on a copy so a failed write never leaves the in-memory entry
    # claiming evidence the sheet doesn't have.
    working: BlocklistEntry = dict(entry) if entry else {
        "extension_id": ext_id, "extension_name": "", "reason": "",
        "source": "WebSentinel C1 live analysis", "source_is_url": False,
        "date": "", "store": "", "version": "", "sha256": None,
    }
    gaps = entry_gaps(working)

    # ── Observable facts: name, version, store, hash, date ────────
    evidence = build_live_evidence(
        manifest=manifest_dict, ext_id=ext_id, ext_path=extension_path,
        webstore_url=webstore_url, crx_sha256=crx_sha256, store_hint=store_hint,
    )
    name_provenance = evidence.pop("name_provenance", "")

    updates: Dict[str, str] = {k: v for k, v in evidence.items() if k in gaps}

    # ── Derived reason: run the models, then name the threat class ─
    reason_detail: Dict = {}
    static_info: Dict = {}
    dynamic_info: Dict = {"score": 0.0, "executed": False, "signals": []}
    observed_flags: List[str] = []

    can_score = bool(_MODEL and _FEATURE_COLUMNS)
    if can_score:
        stack = _run_static_stack(manifest_dict, source_code)
        observed_flags = list(stack["flags"])

        # Sandbox — always, when we have the unpacked extension on disk
        if extension_path and run_sandbox_layer:
            from .sandbox import run_sandbox
            try:
                sandbox_result = await run_sandbox(extension_path)
                dyn_raw = float(sandbox_result.get("score", 0))
                dynamic_info = {
                    "score":    round(dyn_raw / 100.0, 4),
                    "executed": bool(sandbox_result.get("executed", False)),
                    "signals":  sandbox_result.get("signals", []),
                    "isolation": sandbox_result.get("isolation"),
                    "extension_loaded": sandbox_result.get("extension_loaded"),
                    "load_error":       sandbox_result.get("load_error"),
                    "observed":         _observed_summary(sandbox_result),
                }
                observed_flags.extend(sandbox_result.get("signals", []))
                if sandbox_result.get("error"):
                    observed_flags.append("SANDBOX_ERROR")
            except Exception as exc:                       # sandbox must never sink the verdict
                print(f"[C1-ENRICH] Sandbox failed for {ext_id}: {exc}")
                observed_flags.append("SANDBOX_ERROR")
        elif not extension_path:
            observed_flags.append("SANDBOX_SKIPPED_NO_PATH")
        else:
            # Bulk sweeps run static-only — a headed Chromium per extension
            # across thousands of rows is not a sweep, it's an overnight job.
            observed_flags.append("SANDBOX_NOT_REQUESTED")

        verdict = derive_reason(
            manifest=manifest_dict,
            features=stack["features"],
            source_code=source_code,
            flags=observed_flags,
            ml_prob=stack["prob"],
            anomaly_score=stack["anomaly_score"],
            static_score=stack["static_score"],
            dynamic_score=dynamic_info["score"] * 100.0,
            sandbox_ran=dynamic_info["executed"],
            code_available=code_available,
        )
        reason_detail = verdict.as_dict()
        if "reason" in gaps:
            updates["reason"] = verdict.reason

        static_info = {
            "ml_score":              round(stack["prob"], 4),
            "anomaly_score":         round(stack["anomaly_score"] / 100.0, 4),
            "measured_static_score": round(stack["static_score"] / 100.0, 4),
        }

    # ── Persist: sheet first, memory only if the sheet took it ────
    written: List[str] = []
    if updates and persist and _BLOCKLIST_PATH:
        written = update_entry(
            _BLOCKLIST_PATH, ext_id, updates,
            confidence=str(reason_detail.get("confidence", "")),
            method=str(reason_detail.get("method", "")),
        )
    applied = apply_updates(working, updates)

    working["enriched"]        = bool(applied)
    working["enriched_fields"] = applied
    working["sheet_synced"]    = bool(written)
    working["reason_derived"]  = "reason" in applied and bool(reason_detail)
    if reason_detail:
        working["reason_detail"] = reason_detail
    if name_provenance and "extension_name" in applied:
        working["name_provenance"] = name_provenance
    working["evidence"] = {
        "observed_flags": list(dict.fromkeys(observed_flags)),
        "sandbox":        dynamic_info,
        "static":         static_info,
        "crx_sha256":     crx_sha256 or None,
        "webstore_url":   webstore_url or "",
    }
    working["gaps"]       = entry_gaps(working)
    working["documented"] = not working["gaps"]

    # Commit the enriched entry into the in-memory blocklist so the next hit
    # on this ID takes the instant path. Skipped on a dry run — memory must
    # never claim evidence the caller asked us not to record.
    if applied and persist and ext_id in _BLOCKLIST:
        _BLOCKLIST[ext_id] = working

    return {
        "entry":          working,
        "static_info":    static_info,
        "dynamic_info":   dynamic_info,
        "observed_flags": list(dict.fromkeys(observed_flags)),
        "reason_detail":  reason_detail,
    }


def _blocklist_result(
    ext_id: str,
    entry: Optional[BlocklistEntry],
    *,
    static_info: Optional[Dict] = None,
    dynamic_info: Optional[Dict] = None,
    observed_flags: Optional[List[str]] = None,
    identity: Optional[Dict] = None,
    permissions: Optional[List[Dict]] = None,
) -> dict:
    """Assemble the MALICIOUS verdict for a blocklist hit.

    The score stays pinned at 100 either way — a hit on the finalized
    blocklist is definitional, not probabilistic. What changes is how much
    evidence rides along: the instant path carries only the sheet's record,
    while the evidence path also carries the ML probabilities and sandbox
    signals that were used to derive the missing fields.
    """
    flags = ["HASH_MATCH"] + [f for f in (observed_flags or []) if f != "HASH_MATCH"]
    static_block = {
        "score":             1.0,        # blocklist authority, not a model output
        "hash_match":        True,
        "ml_score":          1.0,
        "anomaly_score":     0.0,
        "blocklist_details": entry,
    }
    if static_info:
        static_block.update(static_info)

    if entry:
        name   = entry.get("extension_name") or ext_id
        reason = entry.get("reason") or "reason not established"
        when   = entry.get("date")
        detail = f"Blocklist match — {name!r} flagged for {reason}"
        detail += f" ({when})." if when else "."
        if entry.get("enriched"):
            detail += (" Evidence completed live from this intercept: "
                       + ", ".join(entry.get("enriched_fields", [])) + ".")
    else:
        detail = "Extension ID matched malicious blocklist."

    result = {
        "score":        1.0,
        "verdict":      "MALICIOUS",
        "detail":       detail,
        "flags":        list(dict.fromkeys(flags)),
        "score_source": "blocklist",
        "static":       static_block,
        "dynamic":      dynamic_info or {"score": 0.0, "executed": False, "signals": []},
        "extension_id": ext_id,
        # A blocklist hit still gets the capability panel. The verdict needs no
        # help, but "what could it do" is the part a reader acts on, and on the
        # instant path (delisted extension, no CRX) these are simply empty
        # rather than fabricated.
        "identity":     identity or {"name": (entry or {}).get("extension_name", "") or "",
                                     "version": (entry or {}).get("version", "") or "",
                                     "ext_id": ext_id, "provenance": "blocklist"},
        "permissions":  permissions or [],
    }
    result["report"] = build_report(result)
    return result


# ── Main analysis function ────────────────────────────────────────────────────

async def analyze_extension(
    manifest: str,
    source_code: str,
    extension_id: str = "",
    extension_path: str = "",
    *,
    webstore_url: str = "",
    crx_sha256: str = "",
    store_hint: str = "",
    enrich_blocklist: bool = True,
) -> dict:
    """
    Run the full C1 detection pipeline on one Chrome extension.

    Args:
        manifest       : Raw JSON string of the extension's manifest.json
        source_code    : Concatenated JavaScript source from the extension's .js files
        extension_id   : 32-character Chrome extension ID — used for blocklist lookup
        extension_path : Path to unpacked extension directory — triggers sandbox if provided
        webstore_url   : Store URL the intercept came from — supplies the Store column
                         and a fallback display name from the URL slug
        crx_sha256     : SHA-256 of the downloaded CRX — supplies the SHA256 Hash column
        store_hint     : "Chrome" / "Edge" when the caller already knows the store
        enrich_blocklist : When True (default) a blocklist hit whose sheet row is
                         missing evidence runs the full ML + sandbox stack to derive
                         it, and writes the completed row back to the CSV

    Returns a dict (C1 output contract):
        {
          "score":        float 0-1  (final threat score)
          "verdict":      "SAFE" | "SUSPICIOUS" | "MALICIOUS"
          "detail":       str  (one-line score breakdown)
          "flags":        list[str]  (detected threat signals)
          "static":       { "score": float, "hash_match": bool, "ml_score": float, "anomaly_score": float,
                            "blocklist_details": dict | None }  # evidence when hash_match is True
          "dynamic":      { "score": float, "executed": bool, "signals": list }
          "extension_id": str
          "report":       dict  (full human-readable report from report.py)
        }
    """
    _load_resources()    # ensure model and blocklist are in memory

    flags: List[str] = []    # will accumulate all detected threat flags

    # ── Step 1: Parse manifest JSON string ────────────────────────
    try:
        manifest_dict = json.loads(manifest) if manifest else {}
    except json.JSONDecodeError:
        manifest_dict = {}
        flags.append("MANIFEST_PARSE_FAILED")    # malformed manifest is itself suspicious

    # ── Step 2: Hash / ID blocklist check ─────────────────────────
    # Fastest check — if the extension ID is a known-bad ID, skip ML entirely.
    #
    # Exception: rows imported from the ID-only `chrome-mal-ids` half of the
    # sheet have no evidence attached (name, reason, date, store, version and
    # hash all read as placeholder text). Short-circuiting those leaves the
    # analyst with a Blocklist Match panel full of "Not Found". So when the
    # matched row has gaps, C1 does NOT skip ML — it runs the whole stack plus
    # the sandbox on the CRX it just downloaded, derives the missing evidence
    # from what they observed, and writes the completed row back to the sheet.
    ext_id = extension_id.strip().lower()
    if ext_id and ext_id in _BLOCKLIST:
        blocklist_entry = _BLOCKLIST.get(ext_id)    # rich evidence dict, or None if only the legacy ID list matched
        gaps = entry_gaps(blocklist_entry)

        if gaps and enrich_blocklist:
            gathered = await _gather_blocklist_evidence(
                ext_id=ext_id,
                entry=blocklist_entry,
                manifest_dict=manifest_dict,
                source_code=source_code or "",
                extension_path=extension_path,
                webstore_url=webstore_url,
                crx_sha256=crx_sha256,
                store_hint=store_hint,
                persist=True,
            )
            return _blocklist_result(
                ext_id, gathered["entry"],
                static_info=gathered["static_info"],
                dynamic_info=gathered["dynamic_info"],
                observed_flags=gathered["observed_flags"],
                identity=_identity(manifest_dict, ext_id, extension_path, webstore_url),
                permissions=explain_permissions(manifest_dict),
            )

        return _blocklist_result(                            # instant path — row is already documented
            ext_id, blocklist_entry,
            identity=_identity(manifest_dict, ext_id, extension_path, webstore_url),
            permissions=explain_permissions(manifest_dict),
        )

    # ── Step 3: Guard — model must be loaded ──────────────────────
    if not _MODEL or not _FEATURE_COLUMNS:
        return {
            "score":   0.0,
            "verdict": "SUSPICIOUS",
            "detail":  "Model or feature list missing — static analysis unavailable.",
            "flags":   ["MODEL_NOT_LOADED"],
            "static":  {"score": 0.0, "hash_match": False, "ml_score": 0.0, "anomaly_score": 0.0, "blocklist_details": None},
            "dynamic": {"score": 0.0, "executed": False, "signals": []},
            # The models are what is missing here, not the manifest — the
            # capability panel is still fully derivable and is the only useful
            # thing this degraded path can offer.
            "identity":    _identity(manifest_dict, ext_id, extension_path, webstore_url),
            "permissions": explain_permissions(manifest_dict),
        }

    # ── Steps 4, 5 and 5b: features → XGBoost → rule boosters → Isolation Forest ─
    # All four live in _run_static_stack() so the blocklist evidence run above
    # scores an extension exactly the same way this path does.
    #   Step 4  — 33 manifest/code features, then the XGBoost probability.
    #   Step 5  — rule boosters raise the floor on extreme eval/atob/injection
    #             patterns (thresholds recalibrated after the v4 retrain to
    #             stop legitimate base64 use from tripping them).
    #   Step 5b — Isolation Forest, trained only on benign extensions, flags
    #             anything unlike the benign distribution (zero-day signal).
    #             It can only raise static_score, never lower it.
    stack         = _run_static_stack(manifest_dict, source_code or "")
    features      = stack["features"]
    prob          = stack["prob"]
    static_score  = stack["static_score"]
    anomaly_score = stack["anomaly_score"]
    flags.extend(stack["flags"])

    # Package static analysis results into a sub-dict
    static_info = {
        "score":            round(static_score / 100.0, 4),   # convert back to 0–1 scale
        "hash_match":       False,
        "ml_score":         round(prob, 4),
        "anomaly_score":    round(anomaly_score / 100.0, 4),  # Isolation Forest zero-day signal, 0-1 scale
        "blocklist_details": None,   # only populated on a Step 2 blocklist match, handled above
    }

    # ── Step 6: Dynamic sandbox ───────────────────────────────────
    # Only runs if: (a) static score is suspicious enough, AND (b) we have the extension on disk
    dynamic_info: Dict = {"score": 0.0, "executed": False, "signals": []}

    if static_score >= SANDBOX_TRIGGER_THRESHOLD and extension_path:
        from .sandbox import run_sandbox                                # lazy import — avoid loading Playwright at startup
        sandbox_result = await run_sandbox(extension_path)             # run extension in isolated browser
        dyn_score_raw  = float(sandbox_result.get("score", 0))
        dynamic_info   = {
            "score":    round(dyn_score_raw / 100.0, 4),
            "executed": sandbox_result.get("executed", False),
            "signals":  sandbox_result.get("signals", []),
            # Where the observation happened. Carried into the verdict so a
            # dynamic score is never read without knowing what contained it.
            "isolation": sandbox_result.get("isolation"),
            # Whether Chromium accepted the extension at all. When this is
            # False the sandbox observed nothing, `executed` is False, and
            # Step 7 falls back to the static score instead of averaging a
            # meaningless 0 into the verdict.
            "extension_loaded": sandbox_result.get("extension_loaded"),
            "load_error":       sandbox_result.get("load_error"),
            # Per-host rollup of what was contacted and from which JS realm —
            # what the report's network view is drawn from.
            "observed":         _observed_summary(sandbox_result),
        }
        flags.extend(sandbox_result.get("signals", []))                # merge sandbox flags into main flag list
        # EXTENSION_LOAD_FAILED already says what went wrong; a second generic
        # SANDBOX_ERROR next to it just adds noise.
        if sandbox_result.get("error") and "EXTENSION_LOAD_FAILED" not in flags:
            flags.append("SANDBOX_ERROR")
    elif static_score >= SANDBOX_TRIGGER_THRESHOLD and not extension_path:
        flags.append("SANDBOX_SKIPPED_NO_PATH")    # note why sandbox didn't run

    # ── Step 7: Score fusion ──────────────────────────────────────
    # Combine static and dynamic scores — 70% weight to static, 30% to dynamic.
    # This reflects that static analysis is the primary layer and always runs.
    dyn_score = dynamic_info["score"] * 100.0
    if dynamic_info["executed"]:
        final_score = 0.7 * static_score + 0.3 * dyn_score   # weighted fusion
    else:
        final_score = static_score    # sandbox didn't run — static score is the final score

    # ── Step 8: Verdict thresholds ────────────────────────────────
    if   final_score >= 70: verdict = "MALICIOUS"
    elif final_score >= 40: verdict = "SUSPICIOUS"
    else:                   verdict = "SAFE"

    # One-line detail string for the dashboard score display
    detail = (
        f"static_score={static_score:.1f}  "
        f"dynamic_score={dyn_score:.1f}  "
        f"final_score={final_score:.1f}  "
        f"(p_ml={prob:.3f})."
    )
    if flags:
        detail += "  Flags: " + ", ".join(dict.fromkeys(flags)) + "."

    # Assemble the final result dictionary
    output = {
        "score":        round(final_score / 100.0, 4),     # convert to 0–1 scale for API consistency
        "verdict":      verdict,
        "detail":       detail,
        "flags":        list(dict.fromkeys(flags)),         # deduplicated while preserving insertion order
        "static":       static_info,
        "dynamic":      dynamic_info,
        "extension_id": ext_id,
        # What the extension IS and what it is ALLOWED to do — distinct from
        # the flags above, which are what it did. A clean behavioural record
        # still leaves the granted capability in place, so the report shows
        # both halves.
        "identity":     _identity(manifest_dict, ext_id, extension_path, webstore_url),
        "permissions":  explain_permissions(manifest_dict),
    }
    output["report"] = build_report(output)    # attach human-readable report from report.py
    return output


# ── Convenience wrappers ──────────────────────────────────────────────────────

async def sandbox_extension(extension_path: str) -> dict:
    """Run only the dynamic sandbox (skip static ML). Used by /extension/sandbox API endpoint."""
    from .sandbox import run_sandbox
    return await run_sandbox(extension_path)


async def document_blocklist_entry(
    extension_id: str,
    *,
    run_sandbox_layer: bool = True,
    persist: bool = True,
) -> Dict:
    """Fill in one blocklist row's missing evidence, fetching the CRX ourselves.

    The live intercept path already has the CRX in hand; this is the entry
    point for everything that doesn't — the /extension/blocklist/document
    endpoint and scripts/backfill_blocklist_evidence.py, which walk the whole
    sheet and document every under-reported row in one pass.

    Returns {"status": ..., "ext_id": ..., ...}. `status` is one of:
        documented   — evidence gathered, sheet updated
        no_change    — analysis ran but produced nothing the sheet was missing
        already_documented — the row had no gaps to begin with
        unavailable  — the CRX could not be downloaded (delisted extension)
        not_blocklisted — the ID isn't in the sheet
    """
    _load_resources()
    ext_id = (extension_id or "").strip().lower()
    if not ext_id or ext_id not in _BLOCKLIST:
        return {"status": "not_blocklisted", "ext_id": ext_id}

    entry = _BLOCKLIST.get(ext_id)
    gaps  = entry_gaps(entry)
    if not gaps:
        return {"status": "already_documented", "ext_id": ext_id, "entry": entry}

    import io
    import shutil
    import tempfile
    import zipfile

    from .crx_utils import fetch_crx_from_store, parse_crx_bytes, _crx_to_zip_bytes
    from .enrich import sha256_of, find_local_manifest

    crx_data: bytes = b""
    source_code = ""
    manifest_dict: Dict = {}
    code_available = True
    evidence_source = "chrome web store"

    try:
        crx_data = await fetch_crx_from_store(ext_id)
        manifest_dict, source_code, _ = parse_crx_bytes(crx_data, ext_id)
    except Exception as exc:
        # Most undocumented IDs are undocumented precisely because the store
        # already removed them. Before giving up, check the archived-manifest
        # corpus shipped with the repo — it has no JavaScript, but the
        # declared name, version and permissions are still real evidence.
        archived = find_local_manifest(ext_id, os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
        if not archived:
            return {"status": "unavailable", "ext_id": ext_id, "error": str(exc), "gaps": gaps}
        manifest_dict   = archived
        code_available  = False
        evidence_source = "archived manifest corpus"

    # Unpack only when it buys something: the sandbox needs the extension on
    # disk, and so does resolving an i18n manifest name ("__MSG_appName__")
    # against the extension's own _locales bundle. A sweep of thousands of
    # rows should not leave thousands of unpacked extensions behind, so this
    # uses a temp dir and clears it once the evidence is gathered.
    needs_locales = str(manifest_dict.get("name") or "").startswith("__MSG_")
    ext_path = ""
    if crx_data and (run_sandbox_layer or needs_locales):
        try:
            ext_path = tempfile.mkdtemp(prefix=f"c1_doc_{ext_id[:8]}_")
            with zipfile.ZipFile(io.BytesIO(_crx_to_zip_bytes(crx_data))) as archive:
                archive.extractall(ext_path)
        except Exception as exc:
            print(f"[C1-ENRICH] Could not unpack {ext_id}: {exc}")
            ext_path = ""

    try:
        gathered = await _gather_blocklist_evidence(
            ext_id=ext_id,
            entry=entry,
            manifest_dict=manifest_dict,
            source_code=source_code,
            extension_path=ext_path,
            run_sandbox_layer=run_sandbox_layer and bool(ext_path),
            code_available=code_available,
            webstore_url=f"https://chromewebstore.google.com/detail/{ext_id}",
            # No CRX means no package hash to record — the sheet keeps its gap
            # rather than carrying a hash of something we never actually saw.
            crx_sha256=sha256_of(crx_data) if crx_data else "",
            store_hint="Chrome" if crx_data else "",
            persist=persist,
        )
    finally:
        if ext_path:
            shutil.rmtree(ext_path, ignore_errors=True)
    documented = gathered["entry"]
    return {
        "status":          "documented" if documented.get("enriched") else "no_change",
        "ext_id":          ext_id,
        "entry":           documented,
        "evidence_source": evidence_source,
        "filled":          documented.get("enriched_fields", []),
        "remaining_gaps":  documented.get("gaps", []),
        "sheet_synced":    documented.get("sheet_synced", False),
        "reason_detail":   gathered["reason_detail"],
    }
