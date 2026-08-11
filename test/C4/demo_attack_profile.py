"""
C4 Demo Attack Profile — live end-to-end demonstration.

Builds a synthetic but realistic multi-stage browser attack timeline and drives
it through the REAL C4 pipeline (rules -> correlation -> MITRE -> reporter) so
every one of the 7 cross-table detectors fires. Produces the JSON/HTML/SIEM
forensic reports and opens the HTML report in the browser.

Usage (from project root):
    python test/C4/demo_attack_profile.py

Why this exists: the live browser profile used for automated scanning is nearly
empty, so real runs show few findings. This script demonstrates the engine's
full detection capability on a populated attack scenario — ideal for the demo.
"""
import os
import sys
import webbrowser
from datetime import datetime, timedelta

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.c4.extractor   import _event, collect_manifest, get_chrome_path
from core.c4.rules       import apply_single_artifact_rules
from core.c4.correlation import run_correlation
from core.c4.mitre       import run_mitre_mapping
from core.c4.reporter    import save_all_outputs

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "core", "c4", "output")


def ts(dt):
    return dt.isoformat()


def build_attack_timeline():
    """A single coherent breach narrative that exercises all 7 detectors."""
    events = []

    # ── Personal baseline: dense normal 9am–5pm browsing (temporal model) ───────
    # Dense enough that a handful of 2am events read as a genuine dead-hour spike.
    base_day = datetime(2026, 8, 10)
    for hour in range(9, 18):
        for minute in range(0, 60, 3):
            events.append(_event(
                ts(base_day.replace(hour=hour, minute=minute)),
                "history", "History.db",
                {"url": f"https://work-portal.com/task/{hour}{minute}",
                 "title": "Daily Work", "visit_count": 3}))

    # ── STAGE 1 — Phishing landing (co-occurrence + domain cluster) ─────────────
    # evil-phish.com touched by history + cookie + credential within 2 minutes.
    t = datetime(2026, 8, 11, 2, 5, 0)   # 2am — also drives TEMPORAL anomaly
    events += [
        _event(ts(t),                         "history",    "History.db",
               {"url": "https://evil-phish.com/office365/login",
                "title": "Sign in to your account", "visit_count": 1}),
        _event(ts(t + timedelta(seconds=25)), "cookie",     "Cookies.db",
               {"host": ".evil-phish.com", "name": "session_token", "path": "/",
                "secure": True, "httponly": True}),
        _event(ts(t + timedelta(seconds=70)), "credential", "Login Data",
               {"origin": "https://evil-phish.com", "username": "victim@corp.com",
                "times_used": 0, "password": "h******3", "password_length": 8,
                "decryption": "success"}),
    ]

    # ── STAGE 2 — Ordered attack chain (history -> download -> credential) ──────
    t = datetime(2026, 8, 11, 2, 8, 0)
    events += [
        _event(ts(t),                          "history",    "History.db",
               {"url": "https://cdn-update.net/patch", "title": "Critical Update",
                "visit_count": 1}),
        _event(ts(t + timedelta(seconds=35)),  "download",   "History.db",
               {"filename": "SecurityPatch.exe",
                "source_url": "https://cdn-update.net/patch",
                "size_bytes": 845000, "danger_type": 1,
                "target_path": "C:/Users/victim/Downloads/SecurityPatch.exe",
                "sha256": "demo-hash"}),
        _event(ts(t + timedelta(seconds=80)),  "credential", "Login Data",
               {"origin": "https://cdn-update.net", "username": "victim@corp.com",
                "times_used": 0, "password": "h******3", "password_length": 8,
                "decryption": "success"}),
    ]

    # ── STAGE 3 — Download -> exfil callback (different domain within window) ────
    t = datetime(2026, 8, 11, 2, 12, 0)
    events += [
        _event(ts(t),                          "download",   "History.db",
               {"filename": "collector.ps1",
                "source_url": "https://drop-zone.io/collector.ps1",
                "size_bytes": 12400, "danger_type": 1,
                "target_path": "C:/Users/victim/Downloads/collector.ps1",
                "sha256": "demo-hash-2"}),
        _event(ts(t + timedelta(seconds=50)),  "history",    "History.db",
               {"url": "https://c2-beacon.xyz/upload", "title": "",
                "visit_count": 1}),
    ]

    # ── STAGE 4 — Orphan artifacts (no browsing history for this domain) ────────
    t = datetime(2026, 8, 11, 2, 15, 0)
    events += [
        _event(ts(t),                          "cookie",       "Cookies.db",
               {"host": ".stealthy-inject.com", "name": "auth_bearer", "path": "/",
                "secure": False, "httponly": False}),
        _event(ts(t + timedelta(seconds=10)),  "localstorage", "Local Storage",
               {"origin": "https://stealthy-inject.com", "url": "https://stealthy-inject.com",
                "host": "stealthy-inject.com", "entry_hits": 7}),
    ]

    # ── STAGE 5 — Cross-domain credential reuse (same user, two domains) ────────
    t = datetime(2026, 8, 11, 2, 18, 0)
    events += [
        _event(ts(t),                          "credential", "Login Data",
               {"origin": "https://mail.corp.com", "username": "admin@corp.com",
                "times_used": 12, "password": "P******!", "password_length": 10,
                "decryption": "success"}),
        _event(ts(t + timedelta(seconds=15)),  "credential", "Login Data",
               {"origin": "https://vpn.external-partner.net", "username": "admin@corp.com",
                "times_used": 0, "password": "P******!", "password_length": 10,
                "decryption": "success"}),
    ]
    return events


def main():
    print("\n=== C4 DEMO — Multi-Stage Browser Attack ===\n")
    events = build_attack_timeline()
    print(f"Planted {len(events)} artifact events across a simulated breach.\n")

    events = apply_single_artifact_rules(events)
    correlation  = run_correlation(events)
    mitre_result = run_mitre_mapping(correlation, events)

    summary = correlation["summary"]
    labels = [
        ("cooccurrence_count",     "Co-occurrence"),
        ("orphan_count",           "Orphan detection"),
        ("temporal_count",         "Temporal anomaly"),
        ("attack_chain_count",     "Attack chain"),
        ("domain_cluster_count",   "Domain risk cluster"),
        ("credential_reuse_count", "Credential reuse"),
        ("download_exfil_count",   "Download -> exfil"),
    ]
    print("7 cross-table detectors:")
    fired = 0
    for key, name in labels:
        n = summary.get(key, 0)
        mark = "FIRED " if n else "  --  "
        if n:
            fired += 1
        print(f"   [{mark}] {name:22} {n} finding(s)")
    sev = mitre_result["by_severity"]
    print(f"\nMITRE findings: {len(mitre_result['all_findings'])}  "
          f"(High {sev['High']} / Medium {sev['Medium']} / Low {sev['Low']})")
    print(f"Detectors fired: {fired}/7\n")

    # Assemble a report-shaped result and generate JSON/HTML/SIEM outputs.
    result = {
        "component": "C4",
        "profile_path": "DEMO — simulated attack profile",
        "extracted_at": datetime.now().isoformat(),
        "warnings": [],
        "total_events": len(events),
        "flagged_events": sum(1 for e in events if e.get("risk_flag")),
        "events": events,
        "artifact_manifest": collect_manifest(get_chrome_path() or ""),
        "correlation": correlation,
        "mitre_result": mitre_result,
    }
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    paths = save_all_outputs(result, OUTPUT_DIR)

    html = os.path.abspath(paths["html"])
    print(f"\nOpening report: {html}")
    try:
        webbrowser.open(f"file:///{html.replace(os.sep, '/')}")
    except Exception:
        pass


if __name__ == "__main__":
    main()
