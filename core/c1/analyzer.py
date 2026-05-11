"""Component 1 — Malicious Browser Extension Analyzer."""

from __future__ import annotations

import json
import os
from typing import Dict, List

from .features import extract_manifest_features, build_feature_vector
from .static_model import load_model, load_feature_columns, predict_score
from .report import build_report

_MODEL = None
_FEATURE_COLUMNS: List[str] = []
_MALICIOUS_IDS: set[str] = set()

# Static score threshold above which dynamic sandbox is triggered
SANDBOX_TRIGGER_THRESHOLD = 50.0


def _load_resources() -> None:
    global _MODEL, _FEATURE_COLUMNS, _MALICIOUS_IDS
    if _MODEL is not None and _FEATURE_COLUMNS:
        return

    base_dir = os.path.dirname(os.path.abspath(__file__))
    model_path   = os.path.join(base_dir, "models", "extension_detector_model.pkl")
    feature_path = os.path.join(base_dir, "data", "dataset_clean_v3_features.json")
    hash_db_path = os.path.join(base_dir, "data", "malicious_ids.json")

    if os.path.exists(model_path):
        _MODEL = load_model(model_path)
    if os.path.exists(feature_path):
        _FEATURE_COLUMNS = load_feature_columns(feature_path)
    if os.path.exists(hash_db_path):
        with open(hash_db_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        _MALICIOUS_IDS = set(data.get("malicious_extension_ids", []))


# ── Static analysis ───────────────────────────────────────────────────────────

async def analyze_extension(
    manifest: str,
    source_code: str,
    extension_id: str = "",
    extension_path: str = "",
) -> dict:
    """
    Full C1 analysis pipeline.

    Static analysis always runs.  If the static score exceeds
    SANDBOX_TRIGGER_THRESHOLD AND extension_path is supplied, the dynamic
    sandbox is also executed and scores are fused.

    Args:
        manifest:       Raw JSON string of the extension's manifest.json
        source_code:    Concatenated JS source of the extension's content scripts
        extension_id:   Chrome extension ID (32-char alphanumeric) — used for
                        blocklist hash check
        extension_path: Absolute path to the unpacked extension directory —
                        triggers sandbox when static score > threshold

    Returns (C1 output contract):
        {
          "score":   float 0-1,
          "verdict": "SAFE" | "SUSPICIOUS" | "MALICIOUS",
          "detail":  str,
          "flags":   list[str],
          "static":  { "score": float 0-1, "hash_match": bool, "ml_score": float },
          "dynamic": { "score": float 0-1, "executed": bool, "signals": list[str] },
        }
    """
    _load_resources()

    flags: List[str] = []

    # ── Parse manifest ────────────────────────────────────────────
    try:
        manifest_dict = json.loads(manifest) if manifest else {}
    except json.JSONDecodeError:
        manifest_dict = {}
        flags.append("MANIFEST_PARSE_FAILED")

    # ── Hash / ID blocklist check ─────────────────────────────────
    ext_id = extension_id.strip().lower()
    if ext_id and ext_id in _MALICIOUS_IDS:
        result = {
            "score":   1.0,
            "verdict": "MALICIOUS",
            "detail":  "Extension ID matched malicious blocklist.",
            "flags":   ["HASH_MATCH"],
            "static":  {"score": 1.0, "hash_match": True, "ml_score": 1.0},
            "dynamic": {"score": 0.0, "executed": False, "signals": []},
        }
        result["extension_id"] = ext_id
        result["report"] = build_report(result)
        return result

    # ── ML static scoring ─────────────────────────────────────────
    if not _MODEL or not _FEATURE_COLUMNS:
        return {
            "score":   0.0,
            "verdict": "SUSPICIOUS",
            "detail":  "Model or feature list missing — static analysis unavailable.",
            "flags":   ["MODEL_NOT_LOADED"],
            "static":  {"score": 0.0, "hash_match": False, "ml_score": 0.0},
            "dynamic": {"score": 0.0, "executed": False, "signals": []},
        }

    features = extract_manifest_features(manifest_dict, source_code or "")
    vector   = build_feature_vector(_FEATURE_COLUMNS, features)
    ml_score, prob = predict_score(_MODEL, vector)

    # ── Rule-based boosters ───────────────────────────────────────
    # Thresholds and floors were recalibrated after the ML model was retrained
    # on 322 malicious samples (CV F1=0.828).  The old thresholds (e.g. atob>=3)
    # caused false positives on legitimate extensions like Google Translate that
    # use base64 for icons or language data.  Rules now add FLAGS for the report
    # but only boost scores in genuinely extreme cases where the pattern alone is
    # dangerous enough to override a low ML score.
    static_score = ml_score  # starts from ML output

    if features.get("eval_count", 0) >= 8:          # was 5 — rare in legitimate code
        flags.append("HIGH_EVAL_USAGE")
        static_score = max(static_score, 50.0)
    elif features.get("eval_count", 0) >= 3:         # moderate eval — flag only
        flags.append("HIGH_EVAL_USAGE")

    if features.get("exec_script_count", 0) >= 5:
        flags.append("DYNAMIC_CODE_INJECTION")
        static_score = max(static_score, 42.0)

    if features.get("atob_count", 0) >= 8:           # was 3 — many legit extensions use atob
        flags.append("BASE64_OBFUSCATION")
        static_score = max(static_score, 38.0)        # floor below SUSPICIOUS threshold
    elif features.get("atob_count", 0) >= 3:          # low count — flag only, no score override
        flags.append("BASE64_OBFUSCATION")

    if features.get("long_string_count", 0) >= 6:    # was 3
        flags.append("OBFUSCATED_STRINGS")
        static_score = max(static_score, 28.0)

    # Keep this one strong — webRequestBlocking + eval is a very specific attack pattern
    if features.get("has_webRequestBlocking", 0) and features.get("eval_count", 0) >= 5:
        flags.append("WEBREQUEST_BLOCKING_WITH_EVAL")
        static_score = max(static_score, 60.0)

    static_info = {
        "score":      round(static_score / 100.0, 4),
        "hash_match": False,
        "ml_score":   round(prob, 4),
    }

    # ── Dynamic sandbox (triggered when static score is high enough) ──
    dynamic_info: Dict = {"score": 0.0, "executed": False, "signals": []}

    if static_score >= SANDBOX_TRIGGER_THRESHOLD and extension_path:
        from .sandbox import run_sandbox
        sandbox_result = await run_sandbox(extension_path)
        dyn_score_raw  = float(sandbox_result.get("score", 0))
        dynamic_info   = {
            "score":    round(dyn_score_raw / 100.0, 4),
            "executed": sandbox_result.get("executed", False),
            "signals":  sandbox_result.get("signals", []),
        }
        flags.extend(sandbox_result.get("signals", []))
        if sandbox_result.get("error"):
            flags.append("SANDBOX_ERROR")
    elif static_score >= SANDBOX_TRIGGER_THRESHOLD and not extension_path:
        flags.append("SANDBOX_SKIPPED_NO_PATH")

    # ── Score fusion ──────────────────────────────────────────────
    dyn_score = dynamic_info["score"] * 100.0
    if dynamic_info["executed"]:
        final_score = 0.7 * static_score + 0.3 * dyn_score
    else:
        final_score = static_score

    # ── Verdict ───────────────────────────────────────────────────
    if final_score >= 70:
        verdict = "MALICIOUS"
    elif final_score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    detail = (
        f"static_score={static_score:.1f}  "
        f"dynamic_score={dyn_score:.1f}  "
        f"final_score={final_score:.1f}  "
        f"(p_ml={prob:.3f})."
    )
    if flags:
        detail += "  Flags: " + ", ".join(dict.fromkeys(flags)) + "."

    output = {
        "score":        round(final_score / 100.0, 4),
        "verdict":      verdict,
        "detail":       detail,
        "flags":        list(dict.fromkeys(flags)),   # deduplicated, order-preserved
        "static":       static_info,
        "dynamic":      dynamic_info,
        "extension_id": ext_id,
    }
    output["report"] = build_report(output)
    return output


# ── Convenience wrapper kept for backwards compat ────────────────────────────

async def sandbox_extension(extension_path: str) -> dict:
    """Run only the dynamic sandbox on an unpacked extension directory."""
    from .sandbox import run_sandbox
    return await run_sandbox(extension_path)
