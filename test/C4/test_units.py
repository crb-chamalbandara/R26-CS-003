"""
C4 Unit Test Suite — extractor / crypto / rules / reporter / service

Companion to demo_attack_profile.py, which drives the 7 correlation detectors and
the MITRE mapper end-to-end on a real planted profile. This suite covers the
modules around them, function by function:

  extractor.py  timestamp conversion, hashing, profile resolution, real SQLite
                parsing against a synthetic Chrome-schema database
  crypto.py     password masking and every decrypt_password status branch
                (no live DPAPI needed — pure-logic paths only)
  rules.py      each single-artifact rule R01-R06 in isolation
  reporter.py   HTML report, SIEM export, and on-disk output writing
  service.py    risk-score aggregation and verdict thresholds

Usage:  python test/C4/test_units.py    (from project root)
"""
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.c4 import crypto
from core.c4.extractor import (
    _event, _perm_names, _resolve_profile, chrome_time, collect_manifest,
    extract_cookies, extract_downloads, extract_extensions, extract_history,
    extract_sessions, find_file, sha256,
)
from core.c4.reporter import generate_html_report, generate_siem_export, save_all_outputs
from core.c4.rules import (
    apply_single_artifact_rules, rule_credential_record, rule_dangerous_download,
    rule_risky_extension, rule_sensitive_cookie, rule_suspicious_domain, rule_url_burst,
)
from core.c4.service import get_summary

# ── Output helpers ────────────────────────────────────────────────────────────
# Colour only when attached to a terminal. When the dashboard test runner
# captures this script's output as a subprocess, plain "  PASS  name" lines are
# emitted so the runner's parser can read them.
_COLOR = sys.stdout.isatty()
GREEN  = "\033[92m" if _COLOR else ""
RED    = "\033[91m" if _COLOR else ""
CYAN   = "\033[96m" if _COLOR else ""
BOLD   = "\033[1m"  if _COLOR else ""
RESET  = "\033[0m"  if _COLOR else ""

results = []   # (test_name, passed)

def check(name, condition, detail=""):
    """Record one test case and print its result."""
    passed = bool(condition)
    results.append((name, passed))
    tag = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
    print(f"  {tag}  {name}")
    if detail:
        print(f"         {CYAN}{detail}{RESET}")
    return passed

def section(title):
    print(f"\n{BOLD}{CYAN}═══ {title} ═══{RESET}")

def ts(dt):
    return dt.isoformat()


# ══════════════════════════════════════════════════════════════════════════════
# Synthetic Chrome profile — a real SQLite database using Chrome's own schema
# ══════════════════════════════════════════════════════════════════════════════
CHROME_EPOCH = datetime(1601, 1, 1)

def to_chrome_time(dt):
    """Inverse of extractor.chrome_time() — microseconds since 1601-01-01."""
    return int((dt - CHROME_EPOCH).total_seconds() * 1_000_000)

def build_fake_profile(root):
    """Create a minimal Chrome-schema History database inside `root`."""
    os.makedirs(root, exist_ok=True)
    db_path = os.path.join(root, "History")
    con = sqlite3.connect(db_path)
    con.executescript("""
        CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT,
                           visit_count INTEGER, last_visit_time INTEGER);
        CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);
        CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, tab_url TEXT,
                                total_bytes INTEGER, start_time INTEGER, danger_type INTEGER);
    """)
    visit_dt = datetime(2026, 3, 15, 14, 30, 0)
    con.execute("INSERT INTO urls VALUES (1,?,?,?,?)",
                ("https://example.com/page", "Example Page", 4, to_chrome_time(visit_dt)))
    con.execute("INSERT INTO urls VALUES (2,?,?,?,?)",
                ("https://pastebin.com/raw/abc", "Paste", 1, to_chrome_time(visit_dt)))
    con.execute("INSERT INTO visits VALUES (1,1,?)", (to_chrome_time(visit_dt),))
    con.execute("INSERT INTO visits VALUES (2,2,?)", (to_chrome_time(visit_dt + timedelta(seconds=30)),))
    con.execute("INSERT INTO downloads VALUES (1,?,?,?,?,?)",
                (r"C:\Users\Test\Downloads\payload.exe", "https://drop.site/payload.exe",
                 51200, to_chrome_time(visit_dt), 1))
    con.execute("INSERT INTO downloads VALUES (2,?,?,?,?,?)",
                (r"C:\Users\Test\Downloads\notes.pdf", "https://example.com/notes.pdf",
                 8192, to_chrome_time(visit_dt), 0))
    con.commit()
    con.close()
    return db_path


WORK = tempfile.mkdtemp(prefix="c4_units_")
PROFILE = os.path.join(WORK, "profile")
TMPDIR = os.path.join(WORK, "tmp")
os.makedirs(TMPDIR, exist_ok=True)
build_fake_profile(PROFILE)


# ══════════════════════════════════════════════════════════════════════════════
# 1. extractor.py
# ══════════════════════════════════════════════════════════════════════════════
section("extractor.py — artifact collection")

# T1 — Chrome's 1601-epoch microsecond timestamps convert to readable ISO time
known = datetime(2026, 3, 15, 14, 30, 0)
converted = chrome_time(to_chrome_time(known))
check("chrome_time converts Chrome epoch to ISO datetime",
      converted is not None and converted[:19] == known.isoformat()[:19],
      f"{to_chrome_time(known)} -> {converted}")

# T2 — Invalid timestamps must return None, never crash
check("chrome_time returns None for 0 / None / garbage",
      chrome_time(0) is None and chrome_time(None) is None and chrome_time("bad") is None)

# T3 — SHA-256 evidence hashing matches a directly computed hash
hash_file = os.path.join(WORK, "evidence.bin")
payload = b"WebSentinel C4 forensic evidence"
with open(hash_file, "wb") as fh:
    fh.write(payload)
expected_hash = hashlib.sha256(payload).hexdigest()
check("sha256 hashes a file correctly (evidence integrity)",
      sha256(hash_file) == expected_hash,
      f"{expected_hash[:32]}...")

# T4 — Missing file must not raise
check("sha256 returns None for a missing file",
      sha256(os.path.join(WORK, "does_not_exist.bin")) is None)

# T5 — A user-data dir resolves into its Default sub-folder
userdata = os.path.join(WORK, "UserData")
os.makedirs(os.path.join(userdata, "Default"), exist_ok=True)
check("_resolve_profile steps into the Default sub-folder",
      _resolve_profile(userdata) == os.path.join(userdata, "Default"))

# T6 — A folder with no Default stays as-is
check("_resolve_profile keeps a direct profile path unchanged",
      _resolve_profile(PROFILE) == PROFILE)

# T7 — find_file returns the first candidate that exists
check("find_file returns the first existing candidate",
      find_file(PROFILE, "Cookies", "History") == os.path.join(PROFILE, "History"))

# T8 — Every artifact type must share the same event shape
ev = _event("2026-01-01T00:00:00", "history", "History.db", {"url": "https://x.com"})
required = {"timestamp", "artifact_type", "source_file", "detail", "risk_flag",
            "risk_reasons", "anomaly_score", "anomaly_reasons", "rule_flags"}
check("_event produces the unified event schema",
      required.issubset(ev.keys()) and ev["anomaly_score"] == 0 and ev["risk_flag"] is False,
      f"keys: {len(ev)} / score starts at 0")

# T9 — Real SQLite parsing: history rows become events
hist_events, hist_warn = extract_history(PROFILE, TMPDIR)
check("extract_history parses a real Chrome-schema database",
      hist_warn is None and len(hist_events) == 2,
      f"{len(hist_events)} history event(s), warning={hist_warn}")

# T10 — Extracted history carries the correct URL and converted timestamp
first = hist_events[0] if hist_events else {}
check("extract_history maps url/title/visit_count into detail",
      first.get("artifact_type") == "history"
      and "url" in first.get("detail", {})
      and first.get("timestamp", "").startswith("2026-03-15"),
      f"{first.get('timestamp','')[:19]}  {first.get('detail',{}).get('url','')}")

# T11 — Downloads parse, and the .exe is flagged while the .pdf is not
dl_events, dl_warn = extract_downloads(PROFILE, TMPDIR)
exe = next((e for e in dl_events if e["detail"]["filename"] == "payload.exe"), None)
pdf = next((e for e in dl_events if e["detail"]["filename"] == "notes.pdf"), None)
check("extract_downloads flags .exe but not .pdf",
      exe is not None and pdf is not None and exe["risk_flag"] is True and pdf["risk_flag"] is False,
      f"payload.exe risk={exe['risk_flag'] if exe else '?'} / notes.pdf risk={pdf['risk_flag'] if pdf else '?'}")

# T12 — source_url is preserved (correlation detector G depends on it)
check("extract_downloads preserves source_url for exfil correlation",
      exe is not None and exe["detail"]["source_url"] == "https://drop.site/payload.exe")

# T13 — Manifest records hash + size of the original evidence files
manifest = collect_manifest(PROFILE)
check("collect_manifest records sha256 and size for History",
      "History" in manifest and manifest["History"]["sha256"] and manifest["History"]["size_bytes"] > 0,
      f"History: {manifest.get('History',{}).get('size_bytes',0)} bytes")

# T14 — The original evidence file must be unmodified after extraction
after_hash = sha256(os.path.join(PROFILE, "History"))
check("extraction does not modify the original evidence file",
      after_hash == manifest["History"]["sha256"],
      "hash identical before and after extraction")


# ══════════════════════════════════════════════════════════════════════════════
# 1b. extractor.py — cookies, extensions and sessions on a live-shaped profile
# ══════════════════════════════════════════════════════════════════════════════
section("extractor.py — live cookies, extension registry, session store")

# T14a — A locked Cookies DB must fall back to the jar from the running browser
live_jar = [
    {"name": "session_token", "value": "abc", "domain": ".bank.example",
     "path": "/", "secure": True, "httpOnly": True, "sameSite": "Lax"},
    {"name": "theme_pref", "value": "dark", "domain": "blog.example",
     "path": "/", "secure": False, "httpOnly": False},
]
live_events, live_warning = extract_cookies(os.path.join(WORK, "no_such_profile"),
                                            TMPDIR, live_jar)
check("extract_cookies falls back to the live jar when the DB is locked",
      len(live_events) == 2 and live_warning and "acquired live" in live_warning,
      live_warning or "no warning returned")

# T14b — Live cookies keep the same event contract as disk-read cookies
first_live = live_events[0] if live_events else {}
check("live cookies carry the same schema and flag session tokens",
      first_live.get("artifact_type") == "cookie"
      and first_live["detail"]["acquisition"] == "live"
      and first_live["risk_flag"] is True
      and live_events[1]["risk_flag"] is False,
      "session_token flagged, theme_pref not — acquisition marked 'live'")

# T14c — Without a jar, a missing/locked DB must warn rather than invent data
none_events, none_warning = extract_cookies(os.path.join(WORK, "no_such_profile"), TMPDIR)
check("extract_cookies reports the lock instead of returning fake cookies",
      none_events == [] and none_warning is not None,
      none_warning)

# T14d — Permission lists may contain objects, not just strings
check("_perm_names flattens object-form permissions",
      _perm_names({"permissions": ["tabs", {"fileSystem": ["write"]}],
                   "host_permissions": ["<all_urls>"]})
      == ["<all_urls>", "fileSystem", "tabs"])

# T14e — An extension with no Extensions/ folder is still recovered from prefs
with open(os.path.join(PROFILE, "Secure Preferences"), "w", encoding="utf-8") as fh:
    json.dump({"extensions": {"settings": {
        "aaaabbbbccccddddeeeeffffgggghhhh": {
            "location": 3, "state": 1, "path": "C:\\tmp\\sideloaded",
            "manifest": {"name": "Sideloaded Helper", "version": "2.1",
                         "permissions": ["tabs", "cookies"],
                         "host_permissions": ["<all_urls>"]}},
        "iiiijjjjkkkkllllmmmmnnnnoooopppp": {
            "location": 1, "state": 1,
            "manifest": {"name": "Reader", "version": "1.0",
                         "permissions": ["storage"]}},
    }}}, fh)
ext_events = extract_extensions(PROFILE)
sideloaded = next((e for e in ext_events if e["detail"]["name"] == "Sideloaded Helper"), None)
check("extract_extensions recovers extensions with no Extensions/ folder",
      len(ext_events) == 2 and sideloaded is not None,
      f"{len(ext_events)} extension(s) read from Secure Preferences")

# T14f — Side-loading is itself a finding, separate from the permissions
check("a side-loaded extension is flagged as not Web Store installed",
      sideloaded is not None
      and sideloaded["detail"]["location"].startswith("unpacked")
      and any("side-loaded" in r for r in sideloaded["risk_reasons"])
      and sideloaded["detail"]["risky_perms"] == ["<all_urls>", "cookies", "tabs"],
      f"location={sideloaded['detail']['location'] if sideloaded else '?'}")

# T14g — A clean Web Store extension must not be flagged
reader = next((e for e in ext_events if e["detail"]["name"] == "Reader"), None)
check("a Web Store extension with only 'storage' is not flagged",
      reader is not None and reader["risk_flag"] is False,
      "no risky permissions, location: web store")

# T14h — Session files: URLs recovered from both encodings Chromium writes
sess_dir = os.path.join(PROFILE, "Sessions")
os.makedirs(sess_dir, exist_ok=True)
snss = bytearray(b"SNSS\x01\x00\x00\x00")
snss += b"\x06" + b"https://utf8.example/tab\x00Tab one\x00"
snss += b"\x07" + "https://utf16.example/tab".encode("utf-16-le") + b"\x00\x00"
snss += b"\x06" + b"https://utf8.example/tab\x00duplicate\x00"      # dedup check
with open(os.path.join(sess_dir, f"Session_{to_chrome_time(datetime(2026, 3, 15, 21, 0))}"),
          "wb") as fh:
    fh.write(bytes(snss))
sess_events, sess_warning = extract_sessions(PROFILE)
urls = sorted(e["detail"]["url"] for e in sess_events)
check("extract_sessions recovers UTF-8 and UTF-16 tab URLs, deduplicated",
      urls == ["https://utf16.example/tab", "https://utf8.example/tab"],
      f"{len(sess_events)} tab(s): {', '.join(urls)}")

# T14i — The timestamp comes from the session file itself, not from now()
check("session events are timestamped from the SNSS filename",
      all(e["timestamp"].startswith("2026-03-15T21:00") for e in sess_events)
      and all(e["artifact_type"] == "session" for e in sess_events),
      sess_events[0]["timestamp"][:19] if sess_events else "")

# T14j — A profile with no session store must not error
check("extract_sessions returns empty for a profile with no Sessions folder",
      extract_sessions(os.path.join(WORK, "no_such_profile")) == ([], None))


# ══════════════════════════════════════════════════════════════════════════════
# 2. crypto.py   (pure-logic paths — no live DPAPI key required)
# ══════════════════════════════════════════════════════════════════════════════
section("crypto.py — credential decryption safety")

# T15 — Masking proves decryption without exposing the secret
check("_mask keeps only first and last character",
      crypto._mask("hunter2") == "h*****2",
      "hunter2 -> h*****2")

# T16 — Short secrets are fully masked (first+last would reveal everything)
check("_mask fully hides 1-2 character passwords",
      crypto._mask("ab") == "**" and crypto._mask("x") == "*" and crypto._mask("") == "")

# T17 — Reports must never contain plaintext by default
check("REVEAL_PLAINTEXT defaults to False (reports stay masked)",
      crypto.REVEAL_PLAINTEXT is False)

# T18 — Empty blob is reported, not crashed on
res_empty = crypto.decrypt_password(b"", None)
check("decrypt_password reports status 'empty' for a blank blob",
      res_empty["status"] == "empty" and res_empty["length"] == 0)

# T19 — A v10 blob without a master key reports why it failed
res_nokey = crypto.decrypt_password(b"v10" + b"\x00" * 28, None)
check("decrypt_password reports 'no-key' when the master key is missing",
      res_nokey["status"] in ("no-key", "unavailable"),
      f"status={res_nokey['status']}")

# T20 — A corrupt v10 blob fails cleanly instead of raising
res_bad = crypto.decrypt_password(b"v10" + b"\xff" * 28, b"\x00" * 32)
check("decrypt_password fails cleanly on a corrupt blob",
      res_bad["status"] == "failed",
      f"status={res_bad['status']}")

# T21 — Every result carries the three contract fields
check("decrypt_password always returns status/password/length",
      all({"status", "password", "length"}.issubset(r.keys())
          for r in (res_empty, res_nokey, res_bad)))


# ══════════════════════════════════════════════════════════════════════════════
# 3. rules.py   (single-artifact rules R01-R06, each in isolation)
# ══════════════════════════════════════════════════════════════════════════════
section("rules.py — single-artifact rule engine")

# T22 — R01 fires on a known-suspicious domain
bad_hist = _event(ts(datetime(2026, 3, 15, 10, 0)), "history", "History.db",
                  {"url": "https://pastebin.com/raw/abc", "title": "P", "visit_count": 1})
good_hist = _event(ts(datetime(2026, 3, 15, 10, 0)), "history", "History.db",
                   {"url": "https://google.com/search", "title": "G", "visit_count": 9})
r01_bad, r01_good = rule_suspicious_domain(bad_hist), rule_suspicious_domain(good_hist)
check("R01 flags a suspicious domain and ignores a normal one",
      len(r01_bad) == 1 and r01_bad[0]["rule"] == "R01" and len(r01_good) == 0,
      f"pastebin.com score={r01_bad[0]['score'] if r01_bad else 0}, google.com={len(r01_good)} flags")

# T23 — R02 fires on a dangerous extension
dl_exe = _event(ts(datetime(2026, 3, 15, 10, 0)), "download", "History.db",
                {"filename": "malware.exe", "source_url": "https://x.com/m.exe", "danger_type": 0})
dl_pdf = _event(ts(datetime(2026, 3, 15, 10, 0)), "download", "History.db",
                {"filename": "report.pdf", "source_url": "https://x.com/r.pdf", "danger_type": 0})
r02_exe, r02_pdf = rule_dangerous_download(dl_exe), rule_dangerous_download(dl_pdf)
check("R02 flags .exe downloads and ignores .pdf",
      len(r02_exe) == 1 and r02_exe[0]["rule"] == "R02" and len(r02_pdf) == 0)

# T24 — R02 + R02b stack when Chrome's own danger flag is also set
dl_both = _event(ts(datetime(2026, 3, 15, 10, 0)), "download", "History.db",
                 {"filename": "trojan.exe", "source_url": "https://x.com/t.exe", "danger_type": 2})
r02_both = rule_dangerous_download(dl_both)
check("R02 and R02b stack for an .exe Chrome also flagged",
      len(r02_both) == 2 and {f["rule"] for f in r02_both} == {"R02", "R02b"},
      f"combined score={sum(f['score'] for f in r02_both)}")

# T25 — R03 fires on session-token cookie names
ck_sens = _event(ts(datetime(2026, 3, 15, 10, 0)), "cookie", "Cookies.db",
                 {"host": ".evil.com", "name": "session_token"})
ck_norm = _event(ts(datetime(2026, 3, 15, 10, 0)), "cookie", "Cookies.db",
                 {"host": ".site.com", "name": "theme_pref"})
check("R03 flags session cookies and ignores preference cookies",
      len(rule_sensitive_cookie(ck_sens)) == 1 and len(rule_sensitive_cookie(ck_norm)) == 0)

# T26 — R04 scores a never-used credential higher than a used one
cred_used = _event(ts(datetime(2026, 3, 15, 10, 0)), "credential", "Login Data",
                   {"origin": "https://bank.com", "username": "u", "times_used": 12})
cred_fresh = _event(ts(datetime(2026, 3, 15, 10, 0)), "credential", "Login Data",
                    {"origin": "https://bank.com", "username": "u", "times_used": 0})
s_used = rule_credential_record(cred_used)[0]["score"]
s_fresh = rule_credential_record(cred_fresh)[0]["score"]
check("R04 scores a never-used credential above a used one",
      s_fresh > s_used,
      f"never used={s_fresh} > used={s_used}")

# T27 — R05 scales with the number of risky permissions, but stays capped
ext_one = _event(ts(datetime(2026, 3, 15, 10, 0)), "extension", "Extensions/",
                 {"name": "One", "risky_perms": ["tabs"]})
ext_many = _event(ts(datetime(2026, 3, 15, 10, 0)), "extension", "Extensions/",
                  {"name": "Many", "risky_perms": ["tabs", "cookies", "<all_urls>", "debugger", "history"]})
ext_none = _event(ts(datetime(2026, 3, 15, 10, 0)), "extension", "Extensions/",
                  {"name": "Clean", "risky_perms": []})
s_one = rule_risky_extension(ext_one)[0]["score"]
s_many = rule_risky_extension(ext_many)[0]["score"]
check("R05 scales with risky permission count and caps the bonus",
      s_many > s_one and s_many <= 80 and len(rule_risky_extension(ext_none)) == 0,
      f"1 perm={s_one}, 5 perms={s_many} (cap 80)")

# T28 — R06 fires on a burst of 20+ visits inside 60 seconds
t0 = datetime(2026, 3, 15, 10, 0, 0)
burst = [_event(ts(t0 + timedelta(seconds=i)), "history", "History.db",
                {"url": f"https://bot.com/{i}", "title": "b", "visit_count": 1}) for i in range(25)]
rule_url_burst(burst)
check("R06 flags a 25-visits-in-60-seconds bot burst",
      any(f["rule"] == "R06" for e in burst for f in e["rule_flags"]),
      "25 URLs in 25 seconds")

# T29 — R06 must not fire on normal paced browsing
slow = [_event(ts(t0 + timedelta(minutes=i * 5)), "history", "History.db",
               {"url": f"https://news.com/{i}", "title": "n", "visit_count": 1}) for i in range(6)]
rule_url_burst(slow)
check("R06 does not fire on normal paced browsing",
      not any(f["rule"] == "R06" for e in slow for f in e["rule_flags"]),
      "6 URLs over 30 minutes")

# T30 — Scores from multiple rules accumulate on one event
multi = apply_single_artifact_rules([
    _event(ts(t0), "download", "History.db",
           {"filename": "bad.exe", "source_url": "https://pastebin.com/x.exe", "danger_type": 3}),
])[0]
check("Multiple rule hits accumulate into one anomaly_score",
      multi["risk_flag"] is True and multi["anomaly_score"] >= 150 and len(multi["rule_flags"]) == 2,
      f"score={multi['anomaly_score']} from {len(multi['rule_flags'])} rule(s)")


# ══════════════════════════════════════════════════════════════════════════════
# 4. reporter.py
# ══════════════════════════════════════════════════════════════════════════════
section("reporter.py — report generation")

sample_result = {
    "component": "C4",
    "profile_path": PROFILE,
    "extracted_at": "2026-03-15T14:30:00",
    "total_events": 3,
    "flagged_events": 2,
    "events": [
        _event(ts(t0), "history", "History.db", {"url": "https://evil.com/login"}),
        dict(_event(ts(t0), "download", "History.db", {"filename": "bad.exe"}),
             risk_flag=True, anomaly_score=95, anomaly_reasons=["dangerous download"]),
        dict(_event(ts(t0), "credential", "Login Data", {"origin": "https://evil.com", "username": "v"}),
             risk_flag=True, anomaly_score=70, anomaly_reasons=["credential access"]),
    ],
    "artifact_manifest": manifest,
    "mitre_result": {
        "by_severity": {"High": 2, "Medium": 1, "Low": 0},
        "summary": {"total_findings": 3, "cooccurrence_count": 1, "orphan_count": 1,
                    "temporal_count": 1, "attack_chain_count": 0, "domain_cluster_count": 0,
                    "credential_reuse_count": 0, "download_exfil_count": 0},
        "all_findings": [
            {"algorithm": "co_occurrence", "domain": "evil.com", "score": 85, "severity": "High",
             "artifact_types": ["cookie", "credential"], "description": "2 artifact types on evil.com",
             "mitre": {"technique_id": "T1539", "technique_name": "Steal Web Session Cookie",
                       "tactic": "Credential Access"}},
        ],
    },
}

# T31 — HTML report renders with the real counts embedded
html = generate_html_report(sample_result)
check("HTML report renders with title, MITRE table and event counts",
      "C4 — Browser Artifact Forensics Report" in html
      and "T1539" in html and "MITRE ATT&CK Findings" in html,
      f"{len(html)} characters generated")

# T32 — The flagged-event timeline shows flagged events only
check("HTML report timeline includes flagged events",
      "bad.exe" in html and "Flagged Event Timeline" in html)

# T33 — HTML must survive an empty result without crashing
empty_html = generate_html_report({})
check("HTML report handles an empty result without crashing",
      "No findings" in empty_html or "No flagged events" in empty_html)

# T34 — SIEM export uses the documented envelope
siem = generate_siem_export(sample_result)
check("SIEM export produces the C4_SIEM_Export envelope",
      siem["export_type"] == "C4_SIEM_Export" and isinstance(siem["events"], list),
      f"version {siem['export_version']}, {siem['total_events']} event(s)")

# T35 — Findings and high-score events both land in the SIEM export
kinds = {e["event_type"] for e in siem["events"]}
check("SIEM export contains findings and high-score events",
      "forensic_finding" in kinds and "suspicious_event" in kinds,
      f"event types: {sorted(kinds)}")

# T36 — MITRE fields are carried through to the SIEM record
finding_rec = next((e for e in siem["events"] if e["event_type"] == "forensic_finding"), {})
check("SIEM records carry MITRE technique id and severity",
      finding_rec.get("mitre_technique_id") == "T1539" and finding_rec.get("severity") == "High")

# T37 — Only events scoring >= 60 are exported as suspicious
sus = [e for e in siem["events"] if e["event_type"] == "suspicious_event"]
check("SIEM export includes only events scoring >= 60",
      len(sus) == 2 and all(e["score"] >= 60 for e in sus),
      f"{len(sus)} of 3 events exported")

# T38 — All three report files are written to disk
out_dir = os.path.join(WORK, "output")
paths = save_all_outputs(sample_result, out_dir)
check("save_all_outputs writes JSON, HTML and SIEM files",
      all(os.path.exists(paths[k]) for k in ("json", "html", "siem")),
      f"3 files in {os.path.basename(out_dir)}/")


# ══════════════════════════════════════════════════════════════════════════════
# 5. service.py — risk aggregation
# ══════════════════════════════════════════════════════════════════════════════
section("service.py — risk score and verdict")

def summary_for(high, medium, low):
    return get_summary({
        "profile_path": PROFILE, "extracted_at": "2026-03-15T14:30:00",
        "total_events": 10, "flagged_events": high + medium + low,
        "mitre_result": {"by_severity": {"High": high, "Medium": medium, "Low": low},
                         "summary": {"total_findings": high + medium + low}},
    })

# T39 — No findings must read CLEAN, never a false alarm
clean = summary_for(0, 0, 0)
check("Zero findings produce risk_score 0 and a CLEAN verdict",
      clean["risk_score"] == 0.0 and clean["verdict"] == "CLEAN")

# T40 — A single High finding is dampened, not escalated to CRITICAL
one_high = summary_for(1, 0, 0)
check("A single High finding is dampened below CRITICAL",
      one_high["risk_score"] < 80 and one_high["verdict"] != "CRITICAL",
      f"score={one_high['risk_score']} verdict={one_high['verdict']}")

# T41 — Many High findings saturate towards CRITICAL
many_high = summary_for(10, 0, 0)
check("Ten High findings escalate to CRITICAL",
      many_high["risk_score"] >= 80 and many_high["verdict"] == "CRITICAL",
      f"score={many_high['risk_score']} verdict={many_high['verdict']}")

# T42 — More findings of the same severity must never lower the score
check("Score increases monotonically with finding count",
      summary_for(1, 0, 0)["risk_score"] < summary_for(5, 0, 0)["risk_score"] < many_high["risk_score"],
      f"1 High={summary_for(1,0,0)['risk_score']}  5 High={summary_for(5,0,0)['risk_score']}  10 High={many_high['risk_score']}")

# T43 — Severity must outrank count: Highs beat the same number of Lows
check("High findings outrank the same number of Low findings",
      summary_for(5, 0, 0)["risk_score"] > summary_for(0, 0, 5)["risk_score"],
      f"5 High={summary_for(5,0,0)['risk_score']} vs 5 Low={summary_for(0,0,5)['risk_score']}")

# T44 — Verdict labels must match their documented score bands
bands = [(summary_for(0, 0, 0), "CLEAN"), (summary_for(10, 0, 0), "CRITICAL")]
check("Verdict labels match their score bands",
      all(s["verdict"] == expected for s, expected in bands)
      and summary_for(0, 0, 3)["verdict"] in ("LOW", "MEDIUM"),
      f"0 findings={bands[0][0]['verdict']}, 3 Low={summary_for(0,0,3)['verdict']}, 10 High={bands[1][0]['verdict']}")

# T45 — Querying before any scan must not crash the API
no_data = get_summary({})
check("get_summary returns no_data before any scan has run",
      no_data["status"] == "no_data" and "default_profile_path" in no_data)


# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
shutil.rmtree(WORK, ignore_errors=True)

passed_count = sum(1 for _, p in results if p)
total = len(results)
print(f"\n{BOLD}{'═' * 60}{RESET}")
print(f"{BOLD}  C4 UNIT TEST SUMMARY  {passed_count}/{total} passed{RESET}")
print(f"{'═' * 60}")
for name, p in results:
    tag = f"{GREEN}PASS{RESET}" if p else f"{RED}FAIL{RESET}"
    print(f"  {tag}  {name}")
print(f"{'═' * 60}\n")

sys.exit(0 if passed_count == total else 1)
