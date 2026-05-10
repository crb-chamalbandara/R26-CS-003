"""
C4 Correlation Algorithm Test Suite
Runs 5 synthetic attack scenarios through the full C4 pipeline.
Usage:  python Test/C4/test_correlation.py   (from project root)
"""
import sys, os
sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from datetime import datetime, timedelta
from core.c4.rules       import apply_single_artifact_rules
from core.c4.correlation import run_correlation
from core.c4.mitre       import run_mitre_mapping

# ── Colour helpers ────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):   print(f"  {GREEN}PASS{RESET}  {msg}")
def fail(msg): print(f"  {RED}FAIL{RESET}  {msg}")
def info(msg): print(f"         {CYAN}{msg}{RESET}")

def _event(ts, atype, detail, risk=False, reasons=None):
    """Build a synthetic browser artifact event."""
    return {
        "timestamp":      ts,
        "artifact_type":  atype,
        "source_file":    "test",
        "detail":         detail,
        "risk_flag":      risk,
        "risk_reasons":   reasons or [],
        "anomaly_score":  0,
        "anomaly_reasons":[],
        "rule_flags":     [],
    }

def fmt_ts(dt): return dt.isoformat()

results = []   # (scenario_name, passed)

# ══════════════════════════════════════════════════════════════════════════════
# SCENARIO 1 — Co-occurrence
# Same domain touched by 3 artifact types within 2 minutes → must be detected
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{BOLD}{CYAN}═══ Scenario 1: Co-occurrence Analysis ═══{RESET}")
print("  Attack: history + cookie + credential all hit 'evil.com' within 2 min")

t0 = datetime(2024, 3, 15, 14, 0, 0)
events_s1 = [
    _event(fmt_ts(t0),               "history",    {"url":"https://evil.com/login","title":"Login","visit_count":1}, risk=True),
    _event(fmt_ts(t0 + timedelta(seconds=30)),  "cookie",     {"host":".evil.com","name":"session_token","path":"/","secure":True,"httponly":True}, risk=True),
    _event(fmt_ts(t0 + timedelta(seconds=90)),  "credential", {"origin":"https://evil.com","username":"victim@mail.com","times_used":0,"password":"[ENCRYPTED]"}, risk=True),
    # Unrelated domain — should NOT cluster with evil.com
    _event(fmt_ts(t0 + timedelta(seconds=50)),  "history",    {"url":"https://google.com","title":"Google","visit_count":10}),
]
events_s1 = apply_single_artifact_rules(events_s1)
corr_s1   = run_correlation(events_s1)

cooc = corr_s1["cooccurrence"]
passed = any(f.get("domain","").find("evil.com") >= 0 for f in cooc)
(ok if passed else fail)(f"Co-occurrence detected {len(cooc)} cluster(s)")
for f in cooc:
    info(f"domain={f['domain']}  types={f['artifact_types']}  score={f['score']}")
results.append(("Co-occurrence", passed))

# ══════════════════════════════════════════════════════════════════════════════
# SCENARIO 2 — Orphan Detection
# Cookie + credential for a domain that has ZERO history → injected artifacts
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{BOLD}{CYAN}═══ Scenario 2: Orphan Detection ═══{RESET}")
print("  Attack: session cookie + credential for 'stealthy.io' — no browsing history")

t0 = datetime(2024, 3, 15, 10, 0, 0)
events_s2 = [
    # Legitimate browsing on different site
    _event(fmt_ts(t0),               "history",    {"url":"https://github.com","title":"GitHub","visit_count":5}),
    _event(fmt_ts(t0),               "history",    {"url":"https://google.com","title":"Google","visit_count":20}),
    # Orphan cookie — no history for stealthy.io
    _event(fmt_ts(t0 + timedelta(hours=1)), "cookie", {"host":".stealthy.io","name":"auth_token","path":"/","secure":True,"httponly":False}, risk=True),
    # Orphan credential — no history for stealthy.io
    _event(fmt_ts(t0 + timedelta(hours=1)), "credential", {"origin":"https://stealthy.io","username":"admin","times_used":0,"password":"[ENCRYPTED]"}, risk=True),
]
events_s2 = apply_single_artifact_rules(events_s2)
corr_s2   = run_correlation(events_s2)

orphans = corr_s2["orphans"]
passed  = any("stealthy.io" in str(f.get("domain","")) for f in orphans)
(ok if passed else fail)(f"Orphan detection found {len(orphans)} orphan(s)")
for f in orphans:
    info(f"type={f['artifact_type']}  domain={f['domain']}  score={f['score']}")
results.append(("Orphan Detection", passed))

# ══════════════════════════════════════════════════════════════════════════════
# SCENARIO 3 — Temporal Anomaly
# User normally active 9am-5pm. Credential + download happen at 3am → anomaly
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{BOLD}{CYAN}═══ Scenario 3: Temporal Anomaly Detection ═══{RESET}")
print("  Attack: credential access at 3am — user never active at that hour")

day = datetime(2024, 3, 15)
# Build personal baseline: 50 history visits spread across 9am–5pm
events_s3 = []
for h in range(9, 18):
    for m in [0, 30]:
        events_s3.append(_event(
            fmt_ts(day.replace(hour=h, minute=m)),
            "history",
            {"url": f"https://work.com/page{h}{m}", "title": "Work", "visit_count": 1},
        ))

# Suspicious activity at 3am (hour=3 — outside 9-17 baseline)
t_3am = day.replace(hour=3, minute=15)
events_s3.append(_event(fmt_ts(t_3am), "credential",
    {"origin":"https://bank.com","username":"user@bank.com","times_used":0,"password":"[ENCRYPTED]"},
    risk=True))
events_s3.append(_event(fmt_ts(t_3am + timedelta(minutes=2)), "download",
    {"filename":"payload.exe","source_url":"https://attacker.com/payload.exe","size_bytes":204800,"danger_type":1},
    risk=True))

events_s3 = apply_single_artifact_rules(events_s3)
corr_s3   = run_correlation(events_s3)

temporal = corr_s3["temporal"]
passed   = any(f.get("hour") == 3 for f in temporal)
(ok if passed else fail)(f"Temporal anomaly found {len(temporal)} anomaly event(s) at unusual hours")
for f in temporal:
    info(f"type={f['artifact_type']}  hour={f['hour']:02d}:00  normal_count={f['normal_count']}  score={f['score']}")
results.append(("Temporal Anomaly", passed))

# ══════════════════════════════════════════════════════════════════════════════
# SCENARIO 4 — Attack Chain Detection
# history → download → credential on SAME domain within 2 min → ordered chain
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{BOLD}{CYAN}═══ Scenario 4: Attack Chain Detection ═══{RESET}")
print("  Attack: browse → download .exe → credential access — all on 'phish.net'")

t0 = datetime(2024, 3, 15, 20, 0, 0)
events_s4 = [
    _event(fmt_ts(t0),                          "history",    {"url":"https://phish.net/update","title":"Update","visit_count":1}, risk=True),
    _event(fmt_ts(t0 + timedelta(seconds=40)),  "download",   {"filename":"update.exe","source_url":"https://phish.net/update.exe","size_bytes":1024000,"danger_type":1}, risk=True),
    _event(fmt_ts(t0 + timedelta(seconds=90)),  "credential", {"origin":"https://phish.net","username":"victim","times_used":0,"password":"[ENCRYPTED]"}, risk=True),
]
events_s4 = apply_single_artifact_rules(events_s4)
corr_s4   = run_correlation(events_s4)

chains = corr_s4["attack_chains"]
passed  = len(chains) > 0
(ok if passed else fail)(f"Attack chain detection found {len(chains)} chain(s)")
for f in chains:
    info(f"domain={f['domain']}  sequence={f['artifact_types']}  score={f['score']}")
results.append(("Attack Chain", passed))

# ══════════════════════════════════════════════════════════════════════════════
# SCENARIO 5 — Domain Risk Clustering
# One domain accumulates history + cookie + credential + download → high cluster score
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{BOLD}{CYAN}═══ Scenario 5: Domain Risk Clustering ═══{RESET}")
print("  Attack: 'badactor.ru' touched by 4 artifact types with high anomaly scores")

t0 = datetime(2024, 3, 15, 15, 0, 0)
events_s5 = [
    _event(fmt_ts(t0),                         "history",    {"url":"https://badactor.ru/","title":"Bad","visit_count":3}, risk=True, reasons=["suspicious domain"]),
    _event(fmt_ts(t0 + timedelta(minutes=1)),  "cookie",     {"host":".badactor.ru","name":"tracker","path":"/","secure":False,"httponly":False}, risk=True),
    _event(fmt_ts(t0 + timedelta(minutes=2)),  "download",   {"filename":"dropper.ps1","source_url":"https://badactor.ru/dropper.ps1","size_bytes":8192,"danger_type":1}, risk=True),
    _event(fmt_ts(t0 + timedelta(minutes=3)),  "credential", {"origin":"https://badactor.ru","username":"target","times_used":0,"password":"[ENCRYPTED]"}, risk=True),
    _event(fmt_ts(t0 + timedelta(minutes=4)),  "history",    {"url":"https://badactor.ru/exfil","title":"Exfil","visit_count":1}, risk=True),
    _event(fmt_ts(t0 + timedelta(minutes=5)),  "history",    {"url":"https://badactor.ru/cmd","title":"Cmd","visit_count":1}, risk=True),
]
events_s5 = apply_single_artifact_rules(events_s5)
corr_s5   = run_correlation(events_s5)

clusters = corr_s5["domain_clusters"]
passed   = any("badactor.ru" in str(f.get("domain","")) for f in clusters)
(ok if passed else fail)(f"Domain clustering found {len(clusters)} cluster(s)")
for f in clusters:
    info(f"domain={f['domain']}  types={f['artifact_types']}  flagged={f['flagged_count']}  score={f['score']}")
results.append(("Domain Clustering", passed))

# ══════════════════════════════════════════════════════════════════════════════
# FULL PIPELINE — MITRE Mapping on combined scenario
# ══════════════════════════════════════════════════════════════════════════════
print(f"\n{BOLD}{CYAN}═══ Full Pipeline: MITRE ATT&CK Mapping ═══{RESET}")
print("  Combining all scenario events through rules → correlation → MITRE mapper")

all_events = events_s1 + events_s2 + events_s3 + events_s4 + events_s5
all_events = apply_single_artifact_rules(all_events)
full_corr  = run_correlation(all_events)
mitre_out  = run_mitre_mapping(full_corr, all_events)

findings = mitre_out["all_findings"]
by_sev   = mitre_out["by_severity"]
passed   = len(findings) > 0
(ok if passed else fail)(f"MITRE mapper produced {len(findings)} finding(s)  —  High:{by_sev['High']}  Medium:{by_sev['Medium']}  Low:{by_sev['Low']}")
print()
for f in findings[:10]:
    m   = f.get("mitre", {})
    sev = f.get("severity", "Low")
    col = RED if sev=="High" else YELLOW if sev=="Medium" else GREEN
    print(f"  {col}{sev:6}{RESET}  {m.get('technique_id','—'):10}  {m.get('technique_name','—')}")
    info(f.get("description","")[:80])
results.append(("MITRE Mapping", passed))

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
passed_count = sum(1 for _, p in results if p)
total        = len(results)
print(f"\n{BOLD}{'═'*52}{RESET}")
print(f"{BOLD}  TEST SUMMARY  {passed_count}/{total} passed{RESET}")
print(f"{'═'*52}")
for name, p in results:
    status = f"{GREEN}PASS{RESET}" if p else f"{RED}FAIL{RESET}"
    print(f"  {status}  {name}")
print(f"{'═'*52}\n")

sys.exit(0 if passed_count == total else 1)
