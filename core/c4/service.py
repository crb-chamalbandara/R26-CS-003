"""
Project-native service adapter for Component 4.

The original C4 source was a standalone Flask demo. This module keeps its
forensic pipeline intact and exposes it as functions that core/main.py can call.
"""
import json
import os
from datetime import datetime
from typing import Any, Dict, Optional

from .correlation import run_correlation
from .extractor import get_chrome_path, run_extraction
from .mitre import run_mitre_mapping
from .reporter import generate_html_report, generate_siem_export, save_all_outputs
from .rules import apply_single_artifact_rules

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
LAST_RESULT: Dict[str, Any] = {}


def get_default_profile_path() -> str:
    """Return the browser profile C4 will scan by default."""
    return get_chrome_path() or ""


def run_forensic_analysis(
    profile_path: Optional[str] = None,
    save_outputs: bool = True,
) -> Dict[str, Any]:
    """Run the full C4 browser artifact pipeline."""
    global LAST_RESULT

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    tmp_dir = os.path.join(OUTPUT_DIR, "tmp")

    raw = run_extraction(profile_path=profile_path or None, tmp_dir=tmp_dir)
    events = apply_single_artifact_rules(raw["events"])
    correlation = run_correlation(events)
    mitre_result = run_mitre_mapping(correlation, events)

    result = {
        "component": "C4",
        "profile_path": raw["profile_path"],
        "extracted_at": raw["extracted_at"],
        "warnings": raw.get("warnings", []),
        "total_events": len(events),
        "flagged_events": sum(1 for event in events if event.get("risk_flag")),
        "events": events,
        "artifact_manifest": raw.get("artifact_manifest", {}),
        "correlation": correlation,
        "mitre_result": mitre_result,
    }

    if save_outputs:
        result["output_paths"] = save_all_outputs(result, OUTPUT_DIR)

    LAST_RESULT = result
    return result


def get_summary(result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build a compact dashboard/API summary from a C4 result."""
    result = result or LAST_RESULT
    if not result:
        return {"status": "no_data", "default_profile_path": get_default_profile_path()}

    mitre = result.get("mitre_result", {})
    severity = mitre.get("by_severity", {})
    algorithm_summary = mitre.get("summary", {})
    return {
        "status": "ok",
        "profile_path": result.get("profile_path", ""),
        "extracted_at": result.get("extracted_at", ""),
        "total_events": result.get("total_events", 0),
        "flagged_events": result.get("flagged_events", 0),
        "high": severity.get("High", 0),
        "medium": severity.get("Medium", 0),
        "low": severity.get("Low", 0),
        "total_findings": algorithm_summary.get("total_findings", 0),
        "cooccurrence": algorithm_summary.get("cooccurrence_count", 0),
        "orphans": algorithm_summary.get("orphan_count", 0),
        "temporal": algorithm_summary.get("temporal_count", 0),
        "attack_chains": algorithm_summary.get("attack_chain_count", 0),
        "domain_clusters": algorithm_summary.get("domain_cluster_count", 0),
        "warnings": result.get("warnings", []),
        "output_paths": result.get("output_paths", {}),
    }


def get_last_result() -> Dict[str, Any]:
    return LAST_RESULT


def render_last_html() -> str:
    if not LAST_RESULT:
        return ""
    return generate_html_report(LAST_RESULT)


def render_last_json() -> str:
    if not LAST_RESULT:
        return ""
    return json.dumps(LAST_RESULT, indent=2, default=str)


def render_last_siem() -> str:
    if not LAST_RESULT:
        return ""
    return json.dumps(generate_siem_export(LAST_RESULT), indent=2, default=str)


def report_filename(kind: str) -> str:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"c4_{kind}_{stamp}"
