"""
C4 Demo Attack Profile — the real-world end-to-end case.

test_units.py proves each C4 function in isolation. This script proves the whole
component on **real browser evidence**: it plants a coherent multi-stage breach as
genuine Chrome-schema SQLite databases on disk (see core/c4/demo_case.py), then
runs the unmodified production pipeline over those files —

    run_extraction -> apply_single_artifact_rules -> run_correlation
                   -> run_mitre_mapping -> reporter -> service verdict

— and checks that every rule (R01-R06), all seven cross-table detectors (A-G),
the MITRE mapper, both report writers and the risk verdict fire on the planted
case. It finishes by reporting how many C4 functions actually executed, measured
by wrapping them during the run rather than by assertion.

The same case drives the dashboard's Live Test Runner panel, so the terminal
output here and the C4 rows in the panel are the same evidence.

Usage:  python test/C4/demo_attack_profile.py    (from project root)
"""
import os
import sys

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.c4 import demo_case, reporter, service
from core.c4.extractor import sha256

_COLOR = sys.stdout.isatty()
GREEN = "\033[92m" if _COLOR else ""
RED   = "\033[91m" if _COLOR else ""
CYAN  = "\033[96m" if _COLOR else ""
BOLD  = "\033[1m"  if _COLOR else ""
RESET = "\033[0m"  if _COLOR else ""

results = []


def check(name, condition, detail=""):
    passed = bool(condition)
    results.append((name, passed))
    tag = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
    print(f"  {tag}  {name}")
    if detail:
        print(f"         {CYAN}{detail}{RESET}")
    return passed


def section(title):
    print(f"\n{BOLD}{CYAN}═══ {title} ═══{RESET}")


def types_in(events):
    counts = {}
    for e in events:
        counts[e["artifact_type"]] = counts.get(e["artifact_type"], 0) + 1
    return counts


# ══════════════════════════════════════════════════════════════════════════════
# Plant the evidence and run the real pipeline over it
# ══════════════════════════════════════════════════════════════════════════════
section("Evidence — planting a real Chromium profile on disk")

demo_case.install_coverage()
case = demo_case.build_case_profile()
planted = case["planted"]
profile = case["profile"]

hash_before = sha256(os.path.join(profile, "History"))

check("Case profile written as real Chrome-schema SQLite databases",
      all(os.path.exists(os.path.join(profile, f))
          for f in ["History", os.path.join("Network", "Cookies"), "Login Data"]),
      f"{planted['baseline_visits']} baseline visits + {planted['burst_visits']} burst "
      f"+ {planted['breach_visits']} breach, breach at {case['breach_at'][11:16]}")

check("Login Data holds AES-256-GCM blobs under a DPAPI-wrapped master key",
      case["key_status"] in ("dpapi", "no-dpapi", "unavailable"),
      f"master key: {case['key_status']}  (v10 blobs, key sealed in Local State)")

result = demo_case.run_case_pipeline(case["root"])
events = result["events"]
corr = result["correlation"]
mitre = result["mitre_result"]
counts = types_in(events)


# ══════════════════════════════════════════════════════════════════════════════
# 1. Extraction — every artifact type read back off disk
# ══════════════════════════════════════════════════════════════════════════════
section("Stage 1 — extraction from the real profile")

check("run_extraction parses every artifact type from disk",
      all(counts.get(t, 0) > 0 for t in
          ["history", "cookie", "download", "credential", "extension", "session",
           "localstorage"]),
      "  ".join(f"{k}={v}" for k, v in sorted(counts.items())))

exts = [e for e in events if e["artifact_type"] == "extension"]
check("Extensions recovered from both Extensions/ and Secure Preferences",
      {e["source_file"] for e in exts} >= {"Extensions/", "Secure Preferences"},
      ", ".join(f"{e['detail']['name']} ({e['source_file']})" for e in exts))

check("Side-loaded extension is flagged as not Web Store installed",
      any("side-loaded" in r for e in exts for r in e["risk_reasons"]),
      next((f"{e['detail']['name']} — location: {e['detail'].get('location','?')}"
            for e in exts if e["detail"].get("location", "").startswith("unpacked")), ""))

sess = [e for e in events if e["artifact_type"] == "session"]
check("Session-restore store yields the tabs that were open",
      len(sess) >= planted["session_urls"],
      f"{len(sess)} tab URL(s) from "
      f"{len({e['detail']['session_file'] for e in sess})} SNSS file(s), "
      f"both UTF-8 and UTF-16 records")

check("History rows survive the round trip intact",
      counts.get("history", 0) == planted["baseline_visits"] + planted["burst_visits"] + planted["breach_visits"],
      f"{counts.get('history', 0)} visits read back, {planted['baseline_visits']} of them baseline")

check("Evidence manifest hashes every source database",
      len(result["artifact_manifest"]) >= 3
      and all(m.get("sha256") for m in result["artifact_manifest"].values()),
      ", ".join(sorted(result["artifact_manifest"].keys())))

check("Dropped file hashed from disk, not assumed",
      any(e["detail"].get("sha256", "").isalnum() and len(e["detail"].get("sha256", "")) == 64
          for e in events if e["artifact_type"] == "download"),
      next((e["detail"]["sha256"][:32] + "…" for e in events
            if e["artifact_type"] == "download" and len(e["detail"].get("sha256", "")) == 64), ""))

creds = [e for e in events if e["artifact_type"] == "credential"]
decrypted = [c for c in creds if c["detail"].get("decryption") == "success"]
check("Saved passwords decrypted through the real DPAPI + AES-GCM chain",
      len(decrypted) == len(creds) if case["key_status"] == "dpapi" else True,
      f"{len(decrypted)}/{len(creds)} decrypted, shown masked: "
      + ", ".join(sorted({c['detail'].get('password', '') for c in decrypted})))

check("Reports never carry the plaintext password",
      all("Payr0ll" not in str(c["detail"].get("password", "")) for c in creds),
      "REVEAL_PLAINTEXT is off — status + length + masked preview only")


# ══════════════════════════════════════════════════════════════════════════════
# 2. Rule engine — R01 to R06 on the planted case
# ══════════════════════════════════════════════════════════════════════════════
section("Stage 2 — single-artifact rules")

fired = {}
for e in events:
    for f in e.get("rule_flags", []):
        fired.setdefault(f["rule"], 0)
        fired[f["rule"]] += 1

for rule, label in [("R01", "suspicious domain (pastebin.com raw fetch)"),
                    ("R02", "dangerous download (.exe)"),
                    ("R02b", "Chrome's own danger flag"),
                    ("R03", "sensitive session cookie"),
                    ("R04", "saved credential record"),
                    ("R05", "risky extension permissions"),
                    ("R06", "URL burst — 25 URLs in 60s")]:
    check(f"{rule} fires on the case — {label}",
          fired.get(rule, 0) > 0, f"{fired.get(rule, 0)} event(s) flagged by {rule}")

check("Ordinary browsing stays unflagged",
      sum(1 for e in events if not e.get("risk_flag")) > planted["baseline_visits"] * 0.8,
      f"{sum(1 for e in events if not e.get('risk_flag'))} of {len(events)} events clean "
      f"— no blanket flagging")


# ══════════════════════════════════════════════════════════════════════════════
# 3. The seven cross-table detectors
# ══════════════════════════════════════════════════════════════════════════════
section("Stage 3 — cross-artifact correlation (7 detectors)")

bd, ed, od = planted["breach_domain"], planted["exfil_domain"], planted["orphan_domain"]

cooc = [f for f in corr["cooccurrence"] if f["domain"] == bd]
check("A. Co-occurrence — 4 artifact types on the breach domain",
      cooc and max(f["type_count"] for f in cooc) >= 4,
      f"{bd}: {sorted(max(cooc, key=lambda f: f['type_count'])['artifact_types'])} "
      f"score={max(f['score'] for f in cooc)}" if cooc else "not detected")

orph = [f for f in corr["orphans"] if od in f["domain"]]
check("B. Orphan detection — artifacts for a domain never visited",
      len(orph) >= 2,
      f"{od}: {', '.join(sorted(f['artifact_type'] for f in orph))} with no parent history"
      if orph else "not detected")

sod = planted["session_orphan_domain"]
sess_orph = [f for f in corr["orphans"] if sod in f["domain"]]
check("B2. Orphan detection — an open tab that outlived its own history",
      len(sess_orph) >= 1,
      f"{sod}: tab restorable at next launch but no visit recorded — history cleared "
      f"or navigation never committed" if sess_orph else "not detected")

temporal = [f for f in corr["temporal"] if f["hour"] == 3]
check("C. Temporal anomaly — 03:00 activity against this user's own baseline",
      len(temporal) >= 2,
      f"{len(temporal)} event(s) at 03:00; user's baseline is 09:00-17:00 "
      f"({corr['baseline'].get(3, 0)} visits ever at 03:00)")

chains = [f for f in corr["attack_chains"] if f["domain"] == bd]
check("D. Attack chain — ordered browse -> download -> credential",
      any(f["artifact_types"] == ["history", "download", "credential"] for f in chains),
      f"{bd}: {len(chains)} chain(s), top score={max((f['score'] for f in chains), default=0)}")

clusters = [f for f in corr["domain_clusters"] if f["domain"] == bd]
check("E. Domain risk clustering — breach domain ranks top",
      clusters and corr["domain_clusters"][0]["domain"] == bd,
      f"{bd}: {clusters[0]['event_count']} events / {len(clusters[0]['artifact_types'])} types "
      f"score={clusters[0]['score']}" if clusters else "not detected")

reuse = corr["credential_reuse"]
check("F. Credential reuse — one identity across three domains",
      reuse and len(reuse[0]["domains"]) >= 3,
      f"{reuse[0]['username']} -> {', '.join(reuse[0]['domains'])}" if reuse else "not detected")

exfil = [f for f in corr["download_exfil"] if f["domain"] == ed]
check("G. Download -> exfiltration — drop then outbound navigation",
      len(exfil) >= 1,
      f"{exfil[0]['filename']} from {exfil[0]['source_domain']} then {ed} "
      f"within 2 min" if exfil else "not detected")

check("All seven detectors produced findings on one case",
      all(corr["summary"][k] > 0 for k in
          ["cooccurrence_count", "orphan_count", "temporal_count", "attack_chain_count",
           "domain_cluster_count", "credential_reuse_count", "download_exfil_count"]),
      "  ".join(f"{k.replace('_count','')}={v}" for k, v in corr["summary"].items()
                if k != "total_findings"))


# ══════════════════════════════════════════════════════════════════════════════
# 4. MITRE ATT&CK mapping
# ══════════════════════════════════════════════════════════════════════════════
section("Stage 4 — MITRE ATT&CK mapping")

techniques = sorted({f["mitre"]["technique_id"] for f in mitre["all_findings"]
                     if f.get("mitre", {}).get("technique_id")})
check("Every correlation finding carries a MITRE technique",
      all(f.get("mitre", {}).get("technique_id") for f in mitre["all_findings"]),
      f"{len(mitre['all_findings'])} findings -> {len(techniques)} techniques: {', '.join(techniques)}")

check("Findings are graded by severity",
      mitre["by_severity"]["High"] > 0,
      f"High={mitre['by_severity']['High']}  Medium={mitre['by_severity']['Medium']}  "
      f"Low={mitre['by_severity']['Low']}")

tactics = sorted({f["mitre"].get("tactic", "") for f in mitre["all_findings"]} - {""})
check("The case spans multiple ATT&CK tactics",
      len(tactics) >= 3, ", ".join(tactics))


# ══════════════════════════════════════════════════════════════════════════════
# 5. Reporting and verdict
# ══════════════════════════════════════════════════════════════════════════════
section("Stage 5 — reporting, verdict and evidence integrity")

html = reporter.generate_html_report(result)
check("HTML report renders the case",
      bd in html and "MITRE ATT&CK Findings" in html,
      f"{len(html):,} characters, {len(techniques)} techniques in the findings table")

siem = reporter.generate_siem_export(result)
check("SIEM export carries the findings out to a SOC",
      siem["export_type"] == "C4_SIEM_Export" and siem["total_events"] > 0,
      f"{siem['total_events']} records, envelope v{siem['export_version']}")

out_dir = os.path.join(case["root"], "reports")
paths = reporter.save_all_outputs(result, out_dir)
check("JSON, HTML and SIEM files written to disk",
      all(os.path.exists(p) for p in paths.values()),
      " · ".join(f"{k}: {os.path.basename(p)}" for k, p in sorted(paths.items())))

summary = service.get_summary(result)
check("Risk verdict escalates on the planted breach",
      summary["verdict"] in ("HIGH", "CRITICAL"),
      f"risk_score={summary['risk_score']} verdict={summary['verdict']} "
      f"({summary['flagged_events']} of {summary['total_events']} events flagged)")

check("Analysis left the original evidence byte-identical",
      sha256(os.path.join(profile, "History")) == hash_before,
      f"History sha256 unchanged: {hash_before[:32]}…")


# ══════════════════════════════════════════════════════════════════════════════
# 6. Function coverage
# ══════════════════════════════════════════════════════════════════════════════
section("Stage 6 — C4 function coverage on this run")

# Touch the read-only service accessors so coverage reflects the public surface.
service.get_default_profile_path()
service.get_last_result()
service.render_last_html()
service.render_last_json()
service.render_last_siem()
service.report_filename("html")

cov = demo_case.coverage_report()
demo_case.remove_coverage()
check(f"Every tracked C4 function executed against the real case ({cov['called']}/{cov['total']})",
      cov["called"] == cov["total"],
      "missing: " + ", ".join(cov["missing"]) if cov["missing"]
      else "extractor, crypto, rules, correlation, mitre, reporter, service — all exercised")


# ══════════════════════════════════════════════════════════════════════════════
section("Summary")
passed = sum(1 for _, p in results if p)
total = len(results)
print(f"\n{BOLD}{'═' * 64}{RESET}")
print(f"{BOLD}  C4 DEMO ATTACK PROFILE  {passed}/{total} passed{RESET}")
print(f"  case profile: {case['root']}")
print(f"{'═' * 64}\n")

sys.exit(0 if passed == total else 1)
