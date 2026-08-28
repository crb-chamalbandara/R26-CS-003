"""
C4 real-world forensic case profile.

Everything in this module writes **real browser evidence to disk** and then hands
it to the *unmodified production pipeline*. Nothing is mocked or injected:

  * `Default/History`            real SQLite, Chrome's own urls/visits/downloads schema
  * `Default/Network/Cookies`    real SQLite, Chrome's cookies schema
  * `Default/Login Data`         real SQLite, passwords encrypted exactly as Chrome
                                 does it — AES-256-GCM under a `v10` blob, with the
                                 AES master key DPAPI-protected inside `Local State`
  * `Default/Extensions/…`       a real manifest.json on disk
  * `Default/Local Storage/…`    real LevelDB .log records
  * `evidence/…`                 the dropped file itself, so its SHA-256 is genuine

C4 then reads those files back with `run_extraction()` — the same call the C4 scan
button makes against a live browser profile. So every PASS in the panel is the real
extractor parsing real SQLite, the real rule engine, the real correlation detectors
and the real DPAPI decryption chain running on this machine.

The planted case is a coherent multi-stage breach on top of two weeks of ordinary
browsing, laid out so that each of the seven cross-table detectors has exactly one
thing to find:

  02:10  automated URL harvesting burst (25 URLs in 36s)          -> R06
  03:00  victim lands on secure-payroll-login.top                 -> R01 chain start
  03:00  session_token cookie set by that domain                  -> R03, co-occurrence
  03:01  payroll_update.exe dropped, Chrome danger flag set       -> R02 + R02b
  03:01  credential harvested for the same domain, never used     -> R04, attack chain
  03:02  navigation to filetransfer-drop.io                       -> download -> exfil
  03:04  pastebin.com/raw fetch                                   -> R01
  ——     cookie + localStorage for a domain never visited         -> orphan detection
  ——     one credential reused across three corporate domains     -> credential reuse
  ——     all of it at 03:00, an hour this user is never awake     -> temporal anomaly
"""
import base64
import ctypes
import json
import os
import random
import shutil
import sqlite3
from datetime import datetime, timedelta

from .crypto import _DATA_BLOB

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_AESGCM = True
except Exception:                                        # pragma: no cover
    _HAS_AESGCM = False

CHROME_EPOCH = datetime(1601, 1, 1)
CASE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "output", "case_profile"))

# The breach domains. Deliberately not registrable look-alikes of real brands —
# they exist only inside this evidence set.
BREACH_DOMAIN = "secure-payroll-login.top"
EXFIL_DOMAIN = "filetransfer-drop.io"
ORPHAN_DOMAIN = "cdn-tracker-analytics.ru"
SESSION_ORPHAN_DOMAIN = "remote-shell-panel.click"
HARVEST_DOMAIN = "data-harvest-node.xyz"
VICTIM_USER = "d.sandeepa@corp-example.com"

BASELINE_SITES = [
    ("https://github.com/websentinel/r26-cs-003", "WebSentinel · GitHub"),
    ("https://stackoverflow.com/questions/tagged/sqlite", "SQLite questions"),
    ("https://mail.corp-example.com/inbox", "Corporate Mail"),
    ("https://vpn.corp-example.com/portal", "Corporate VPN Portal"),
    ("https://docs.google.com/document/d/1a2b3c", "Research Report"),
    ("https://www.google.com/search?q=browser+forensics", "browser forensics"),
    ("https://en.wikipedia.org/wiki/Digital_forensics", "Digital forensics"),
    ("https://www.youtube.com/watch?v=dQw4w9WgXcQ", "Lecture recording"),
]


# ── Chrome timestamp + DPAPI helpers ─────────────────────────────────────────
def to_chrome_time(dt):
    """Python datetime -> Chrome's microseconds-since-1601 integer."""
    return int((dt - CHROME_EPOCH).total_seconds() * 1_000_000)


def _dpapi_protect(blob):
    """CryptProtectData for the current user — the inverse of crypto._dpapi_decrypt.

    Lets the case profile carry a master key that only this Windows account can
    unwrap, which is exactly the trust boundary the real decryption relies on.
    """
    if os.name != "nt" or not blob:
        return None
    blob_in = _DATA_BLOB(len(blob),
                         ctypes.cast(ctypes.c_char_p(blob), ctypes.POINTER(ctypes.c_char)))
    blob_out = _DATA_BLOB()
    try:
        ok = ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out))
    except Exception:
        return None
    if not ok:
        return None
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def _encrypt_password(plaintext, master_key):
    """Produce a genuine Chrome 80+ password blob: b'v10' + nonce(12) + AES-GCM."""
    if not (_HAS_AESGCM and master_key):
        return b""
    nonce = os.urandom(12)
    return b"v10" + nonce + AESGCM(master_key).encrypt(nonce, plaintext.encode(), None)


# ── Evidence writers ─────────────────────────────────────────────────────────
def _write_history_db(path, visits, downloads):
    """Chrome's History database — urls, visits and downloads, real schema."""
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE urls (id INTEGER PRIMARY KEY AUTOINCREMENT, url LONGVARCHAR,
                           title LONGVARCHAR, visit_count INTEGER DEFAULT 0 NOT NULL,
                           typed_count INTEGER DEFAULT 0 NOT NULL,
                           last_visit_time INTEGER NOT NULL,
                           hidden INTEGER DEFAULT 0 NOT NULL);
        CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER NOT NULL,
                             visit_time INTEGER NOT NULL, from_visit INTEGER,
                             transition INTEGER DEFAULT 0 NOT NULL,
                             segment_id INTEGER,
                             visit_duration INTEGER DEFAULT 0 NOT NULL);
        CREATE TABLE downloads (id INTEGER PRIMARY KEY, guid VARCHAR NOT NULL,
                                current_path LONGVARCHAR NOT NULL,
                                target_path LONGVARCHAR NOT NULL,
                                start_time INTEGER NOT NULL,
                                received_bytes INTEGER NOT NULL,
                                total_bytes INTEGER NOT NULL,
                                state INTEGER NOT NULL, danger_type INTEGER NOT NULL,
                                interrupt_reason INTEGER NOT NULL,
                                end_time INTEGER NOT NULL, opened INTEGER NOT NULL,
                                referrer VARCHAR NOT NULL, tab_url VARCHAR NOT NULL,
                                tab_referrer_url VARCHAR NOT NULL,
                                mime_type VARCHAR NOT NULL);
    """)

    url_ids = {}
    for when, url, title in visits:
        if url not in url_ids:
            url_ids[url] = len(url_ids) + 1
            con.execute("INSERT INTO urls (id,url,title,visit_count,typed_count,"
                        "last_visit_time,hidden) VALUES (?,?,?,?,?,?,0)",
                        (url_ids[url], url, title, 0, 0, to_chrome_time(when)))
        con.execute("UPDATE urls SET visit_count = visit_count + 1, "
                    "last_visit_time = MAX(last_visit_time, ?) WHERE id = ?",
                    (to_chrome_time(when), url_ids[url]))
        con.execute("INSERT INTO visits (url,visit_time,from_visit,transition,"
                    "visit_duration) VALUES (?,?,0,805306368,?)",
                    (url_ids[url], to_chrome_time(when), random.randint(2, 90) * 1_000_000))

    for i, d in enumerate(downloads, start=1):
        con.execute("INSERT INTO downloads (id,guid,current_path,target_path,start_time,"
                    "received_bytes,total_bytes,state,danger_type,interrupt_reason,"
                    "end_time,opened,referrer,tab_url,tab_referrer_url,mime_type) "
                    "VALUES (?,?,?,?,?,?,?,1,?,0,?,0,?,?,'',?)",
                    (i, f"c4-demo-{i:04d}", d["path"], d["path"],
                     to_chrome_time(d["when"]), d["size"], d["size"], d["danger"],
                     to_chrome_time(d["when"] + timedelta(seconds=4)),
                     d["url"], d["url"], d["mime"]))
    con.commit()
    con.close()


def _write_cookies_db(path, cookies):
    """Chrome's Network/Cookies database — real schema, values left encrypted."""
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE cookies (creation_utc INTEGER NOT NULL, host_key TEXT NOT NULL,
                              top_frame_site_key TEXT NOT NULL, name TEXT NOT NULL,
                              value TEXT NOT NULL, encrypted_value BLOB,
                              path TEXT NOT NULL, expires_utc INTEGER NOT NULL,
                              is_secure INTEGER NOT NULL, is_httponly INTEGER NOT NULL,
                              last_access_utc INTEGER NOT NULL, has_expires INTEGER NOT NULL,
                              is_persistent INTEGER NOT NULL, priority INTEGER NOT NULL,
                              samesite INTEGER NOT NULL, source_scheme INTEGER NOT NULL,
                              source_port INTEGER NOT NULL, last_update_utc INTEGER NOT NULL);
    """)
    for c in cookies:
        stamp = to_chrome_time(c["when"])
        con.execute("INSERT INTO cookies VALUES (?,?,'',?,'',?,?,?,?,?,?,1,1,1,0,2,443,?)",
                    (stamp, c["host"], c["name"], b"v10" + os.urandom(24), c.get("path", "/"),
                     to_chrome_time(c["when"] + timedelta(days=30)),
                     int(c.get("secure", True)), int(c.get("httponly", True)), stamp, stamp))
    con.commit()
    con.close()


def _write_login_db(path, logins, master_key):
    """Chrome's Login Data database with genuinely AES-256-GCM encrypted passwords."""
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE logins (origin_url VARCHAR NOT NULL, action_url VARCHAR,
                             username_element VARCHAR, username_value VARCHAR,
                             password_element VARCHAR, password_value BLOB,
                             submit_element VARCHAR, signon_realm VARCHAR NOT NULL,
                             date_created INTEGER NOT NULL,
                             blacklisted_by_user INTEGER NOT NULL, scheme INTEGER NOT NULL,
                             password_type INTEGER, times_used INTEGER,
                             display_name VARCHAR, icon_url VARCHAR,
                             federation_url VARCHAR, skip_zero_click INTEGER,
                             id INTEGER PRIMARY KEY AUTOINCREMENT,
                             date_last_used INTEGER, date_password_modified INTEGER);
    """)
    for lg in logins:
        con.execute("INSERT INTO logins (origin_url,action_url,username_element,"
                    "username_value,password_element,password_value,submit_element,"
                    "signon_realm,date_created,blacklisted_by_user,scheme,password_type,"
                    "times_used,display_name,icon_url,federation_url,skip_zero_click,"
                    "date_last_used,date_password_modified) "
                    "VALUES (?,?,'username',?,'password',?,'',?,?,0,0,0,?,'','','',0,?,?)",
                    (lg["origin"], lg["origin"] + "/auth", lg["user"],
                     _encrypt_password(lg["password"], master_key),
                     lg["origin"] + "/", to_chrome_time(lg["created"]), lg["times_used"],
                     to_chrome_time(lg["last_used"]), to_chrome_time(lg["created"])))
    con.commit()
    con.close()


def _write_local_storage(leveldb_dir, origins):
    """Uncompacted LevelDB .log records — the form extract_local_storage scans for."""
    os.makedirs(leveldb_dir, exist_ok=True)
    blob = bytearray(b"\x00\x00\x00\x00\x01\x00\x01\x01VERSION\x001")
    for origin, keys in origins:
        for key in keys:
            record = b"\x01META:" + origin.encode() + b"\x00"
            record += b"_" + origin.encode() + b"\x00\x01" + key.encode()
            record += b"\x00" + os.urandom(8)
            blob += record
    with open(os.path.join(leveldb_dir, "000003.log"), "wb") as fh:
        fh.write(bytes(blob))


def _write_extension(ext_root, ext_id, version, manifest):
    ver_dir = os.path.join(ext_root, ext_id, f"{version}_0")
    os.makedirs(ver_dir, exist_ok=True)
    with open(os.path.join(ver_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)


def _write_secure_prefs(default_dir, records):
    """Chromium's extension registry — where a side-loaded extension really shows up.

    An extension started with --load-extension leaves no Extensions/ folder at
    all; its manifest lives here, which is why C4 reads both.
    """
    with open(os.path.join(default_dir, "Secure Preferences"), "w", encoding="utf-8") as fh:
        json.dump({"extensions": {"settings": records}}, fh, indent=2)


def _write_sessions(sess_dir, files):
    """Chromium session-restore files: the tabs that would come back on restart.

    The real container is a length-prefixed command log holding pickled tab
    navigations; the URLs sit inside it as UTF-8 and UTF-16LE strings, both of
    which are reproduced here so the reader is exercised against both encodings.
    """
    os.makedirs(sess_dir, exist_ok=True)
    for name, urls in files:
        blob = bytearray(b"SNSS\x01\x00\x00\x00")
        for i, (url, title) in enumerate(urls):
            payload = url.encode() + b"\x00" + title.encode() + b"\x00"
            blob += len(payload).to_bytes(4, "little") + b"\x06" + payload
            if i % 2 == 0:                      # half the records in UTF-16LE
                wide = url.encode("utf-16-le") + b"\x00\x00"
                blob += len(wide).to_bytes(4, "little") + b"\x07" + wide
        with open(os.path.join(sess_dir, name), "wb") as fh:
            fh.write(bytes(blob))


# ── Case builder ─────────────────────────────────────────────────────────────
def build_case_profile(root=None, seed=20260315):
    """Write the full evidence set to disk and describe what was planted.

    Returns a dict with the profile paths, the ground truth of the planted case,
    and the credential-encryption status so the panel can report honestly whether
    real DPAPI was available on this machine.
    """
    random.seed(seed)
    root = root or CASE_ROOT
    if os.path.isdir(root):
        shutil.rmtree(root, ignore_errors=True)
    default = os.path.join(root, "Default")
    os.makedirs(os.path.join(default, "Network"), exist_ok=True)
    evidence_dir = os.path.join(root, "evidence")
    os.makedirs(evidence_dir, exist_ok=True)

    now = datetime.now().replace(microsecond=0)
    breach = (now - timedelta(days=1)).replace(hour=3, minute=0, second=0, microsecond=0)

    # ── Two weeks of ordinary daytime browsing ───────────────────────────────
    # This is what makes the temporal detector meaningful: it learns *this*
    # user's hours from this baseline instead of assuming "night = bad".
    visits = []
    for day in range(1, 15):
        base_day = (now - timedelta(days=day)).replace(minute=0, second=0, microsecond=0)
        for _ in range(16):
            hour = random.choice([9, 10, 11, 13, 14, 15, 16, 17])
            url, title = random.choice(BASELINE_SITES)
            visits.append((base_day.replace(hour=hour,
                                            minute=random.randint(0, 59),
                                            second=random.randint(0, 59)), url, title))
    baseline_visits = len(visits)

    # ── 02:10 — automated harvesting burst (R06) ─────────────────────────────
    burst_start = breach - timedelta(minutes=50)
    for i in range(25):
        visits.append((burst_start + timedelta(milliseconds=int(i * 1450)),
                       f"https://{HARVEST_DOMAIN}/p/{1000 + i}", f"index {1000 + i}"))

    # ── 03:00 — the breach itself ────────────────────────────────────────────
    visits.append((breach + timedelta(seconds=10),
                   f"https://{BREACH_DOMAIN}/session/verify", "Payroll — Verify your session"))
    visits.append((breach + timedelta(seconds=150),
                   f"https://{EXFIL_DOMAIN}/upload?id=8f21c", "Upload complete"))
    visits.append((breach + timedelta(seconds=280),
                   "https://pastebin.com/raw/x9dK2p", "raw paste"))

    # The dropped file is written for real, so its SHA-256 in the report is real.
    dropped = os.path.join(evidence_dir, "payroll_update.exe")
    with open(dropped, "wb") as fh:
        fh.write(b"WEBSENTINEL C4 DEMO ARTIFACT - inert placeholder for the dropped "
                 b"payload, kept as plain text so nothing executable is created.\n"
                 + os.urandom(4096))

    downloads = [
        {"when": breach + timedelta(seconds=60), "path": dropped, "size": 4232, "danger": 1,
         "url": f"https://{BREACH_DOMAIN}/dl/payroll_update.exe",
         "mime": "application/x-msdownload"},
        {"when": (now - timedelta(days=4)).replace(hour=14, minute=12, second=0),
         "path": os.path.join(os.path.expanduser("~"), "Downloads", "lecture_notes.pdf"),
         "size": 812_004, "danger": 0,
         "url": "https://docs.google.com/document/d/1a2b3c/export?format=pdf",
         "mime": "application/pdf"},
    ]

    cookies = [
        # Breach session token, set 30s after landing on the phishing page.
        {"when": breach + timedelta(seconds=40), "host": f".{BREACH_DOMAIN}",
         "name": "session_token", "secure": True, "httponly": True},
        # A cookie for a domain that was never visited — orphan evidence.
        {"when": breach + timedelta(seconds=95), "host": f".{ORPHAN_DOMAIN}",
         "name": "__Secure-track_sid", "secure": True, "httponly": False},
    ]
    for day, host, name in [(2, ".github.com", "_gh_sess"), (3, ".google.com", "NID"),
                            (5, ".mail.corp-example.com", "theme_pref"),
                            (6, ".stackoverflow.com", "prov"),
                            (7, ".youtube.com", "VISITOR_INFO1_LIVE"),
                            (9, ".wikipedia.org", "GeoIP")]:
        cookies.append({"when": (now - timedelta(days=day)).replace(hour=11, minute=20, second=0),
                        "host": host, "name": name, "secure": True, "httponly": False})

    # ── Credentials: one identity reused across three origins ────────────────
    master_key = os.urandom(32) if _HAS_AESGCM else None
    logins = [
        {"origin": f"https://{BREACH_DOMAIN}", "user": VICTIM_USER,
         "password": "Payr0ll!Spring26", "times_used": 0,
         "created": breach + timedelta(seconds=100),
         "last_used": breach + timedelta(seconds=100)},
        {"origin": "https://mail.corp-example.com", "user": VICTIM_USER,
         "password": "Payr0ll!Spring26", "times_used": 42,
         "created": now - timedelta(days=190),
         "last_used": (now - timedelta(days=1)).replace(hour=16, minute=5, second=0)},
        {"origin": "https://vpn.corp-example.com", "user": VICTIM_USER,
         "password": "Payr0ll!Spring26", "times_used": 17,
         "created": now - timedelta(days=120),
         "last_used": (now - timedelta(days=2)).replace(hour=9, minute=40, second=0)},
    ]

    _write_history_db(os.path.join(default, "History"), visits, downloads)
    _write_cookies_db(os.path.join(default, "Network", "Cookies"), cookies)
    _write_login_db(os.path.join(default, "Login Data"), logins, master_key)
    _write_local_storage(os.path.join(default, "Local Storage", "leveldb"), [
        (f"https://{ORPHAN_DOMAIN}", ["track_id", "fp_hash", "beacon_queue"]),
        ("https://github.com", ["theme", "recent_repos"]),
    ])
    _write_extension(os.path.join(default, "Extensions"),
                     "nkbihfbeogaeaoehlefnkodbefgpgknn", "4.7.1", {
                         "manifest_version": 3, "name": "Tab Session Sync Pro",
                         "version": "4.7.1",
                         "permissions": ["tabs", "cookies", "webRequest",
                                         "nativeMessaging", "history"],
                         "host_permissions": ["<all_urls>"],
                     })
    _write_extension(os.path.join(default, "Extensions"),
                     "gighmmpiobklfepjocnamgkkbiglidom", "5.16.3", {
                         "manifest_version": 3, "name": "Reader Mode",
                         "version": "5.16.3", "permissions": ["storage"],
                     })
    # Side-loaded during the breach — no Extensions/ folder, registry record only.
    _write_secure_prefs(default, {
        "hjkmnbpcdefghijklmnopqrstuvwxyza": {
            "location": 3, "state": 1,
            "path": os.path.join(evidence_dir, "payroll_helper"),
            "install_time": str(to_chrome_time(breach + timedelta(seconds=200))),
            "manifest": {"manifest_version": 3, "name": "Payroll Helper",
                         "version": "1.0.2",
                         "permissions": ["tabs", "cookies", "debugger",
                                         "nativeMessaging", "webRequest"],
                         "host_permissions": ["<all_urls>"]},
        },
        "mhjfbmdgcfjbbpaeojofohoefgiehjai": {
            "location": 5, "state": 1, "path": "internal",
            "manifest": {"manifest_version": 2, "name": "Chromium PDF Viewer",
                         "version": "1", "permissions": ["resourcesPrivate"]},
        },
    })
    # Restorable tabs. The 03:00 file carries the breach tab plus a C2 panel that
    # appears in no history entry at all — a tab that outlived its own evidence.
    _write_sessions(os.path.join(default, "Sessions"), [
        (f"Session_{to_chrome_time(breach + timedelta(seconds=70))}", [
            (f"https://{BREACH_DOMAIN}/session/verify", "Payroll — Verify your session"),
            (f"https://{SESSION_ORPHAN_DOMAIN}/panel?id=8f21c", "Remote panel"),
            ("https://mail.corp-example.com/inbox", "Corporate Mail"),
        ]),
        (f"Tabs_{to_chrome_time(now - timedelta(hours=6))}", [
            ("https://github.com/websentinel/r26-cs-003", "WebSentinel · GitHub"),
            ("https://docs.google.com/document/d/1a2b3c", "Research Report"),
            ("https://stackoverflow.com/questions/tagged/sqlite", "SQLite questions"),
        ]),
    ])
    with open(os.path.join(default, "Bookmarks"), "w", encoding="utf-8") as fh:
        json.dump({"roots": {"bookmark_bar": {"children": [
            {"name": "Corporate Mail", "type": "url",
             "url": "https://mail.corp-example.com/inbox"}]}}, "version": 1}, fh, indent=2)

    # Local State carries the DPAPI-wrapped AES key, exactly where Chrome keeps it.
    key_status = "unavailable"
    if master_key:
        protected = _dpapi_protect(master_key)
        if protected:
            with open(os.path.join(root, "Local State"), "w", encoding="utf-8") as fh:
                json.dump({"os_crypt": {
                    "encrypted_key": base64.b64encode(b"DPAPI" + protected).decode()}}, fh)
            key_status = "dpapi"
        else:
            key_status = "no-dpapi"

    return {
        "root": root,
        "profile": default,
        "evidence_file": dropped,
        "key_status": key_status,
        "breach_at": breach.isoformat(),
        "planted": {
            "baseline_visits": baseline_visits,
            "burst_visits": 25,
            "breach_visits": 3,
            "downloads": len(downloads),
            "cookies": len(cookies),
            "credentials": len(logins),
            "extensions": 4,            # 2 unpacked folders + 2 registry records
            "localstorage_origins": 2,
            "session_files": 2,
            "session_urls": 6,
            "breach_domain": BREACH_DOMAIN,
            "exfil_domain": EXFIL_DOMAIN,
            "orphan_domain": ORPHAN_DOMAIN,
            "session_orphan_domain": SESSION_ORPHAN_DOMAIN,
            "victim_user": VICTIM_USER,
        },
    }


def run_case_pipeline(profile_root):
    """Run the production C4 pipeline over the case profile.

    Mirrors service.run_forensic_analysis but never touches its LAST_RESULT
    global, so running the demo can't overwrite a real scan on the dashboard.
    """
    from .correlation import run_correlation
    from .extractor import run_extraction
    from .mitre import run_mitre_mapping
    from .rules import apply_single_artifact_rules

    tmp_dir = os.path.join(profile_root, "tmp")
    raw = run_extraction(profile_path=profile_root, tmp_dir=tmp_dir)
    events = apply_single_artifact_rules(raw["events"])
    correlation = run_correlation(events)
    mitre_result = run_mitre_mapping(correlation, events)
    return {
        "component": "C4",
        "profile_path": raw["profile_path"],
        "extracted_at": raw["extracted_at"],
        "warnings": raw.get("warnings", []),
        "total_events": len(events),
        "flagged_events": sum(1 for e in events if e.get("risk_flag")),
        "events": events,
        "artifact_manifest": raw.get("artifact_manifest", {}),
        "clusters": raw.get("clusters", []),
        "correlation": correlation,
        "mitre_result": mitre_result,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Function coverage tracking
# ══════════════════════════════════════════════════════════════════════════════
# The panel claims "every C4 function ran". This proves it rather than asserting
# it: each listed function is wrapped with a counter for the duration of the demo,
# so the final row reports which functions actually executed against the evidence.
COVERAGE_TARGETS = {
    "extractor": ["chrome_time", "sha256", "_resolve_profile", "find_file", "safe_copy",
                  "query", "_event", "extract_history", "extract_cookies",
                  "extract_downloads", "extract_credentials", "extract_extensions",
                  "_extensions_from_folder", "_extensions_from_prefs", "_extension_event",
                  "_perm_names", "extract_sessions", "_snss_urls", "extract_clusters",
                  "extract_local_storage", "_domain_from_origin",
                  "collect_manifest", "run_extraction"],
    "crypto":    ["_dpapi_decrypt", "load_master_key", "_mask", "decrypt_password"],
    "rules":     ["_ts", "_domain", "rule_suspicious_domain", "rule_dangerous_download",
                  "rule_sensitive_cookie", "rule_credential_record", "rule_risky_extension",
                  "rule_url_burst", "apply_single_artifact_rules"],
    "correlation": ["_ts", "_domain", "_event_domain", "run_cooccurrence",
                    "run_orphan_detection", "run_temporal_anomaly",
                    "run_attack_chain_detection", "run_domain_risk_clustering",
                    "run_credential_reuse", "run_download_exfil", "run_correlation"],
    "mitre":     ["_severity", "map_cooccurrence", "map_orphan", "map_temporal",
                  "map_attack_chain", "map_domain_cluster", "map_credential_reuse",
                  "map_download_exfil", "map_rule_flags", "run_mitre_mapping"],
    "reporter":  ["generate_html_report", "generate_siem_export", "save_all_outputs"],
    "service":   ["get_default_profile_path", "get_summary", "get_last_result",
                  "render_last_html", "render_last_json", "render_last_siem",
                  "report_filename"],
}

# service.run_forensic_analysis is intentionally excluded: it rewrites the module's
# LAST_RESULT global and the on-disk reports, which belong to the operator's real
# scan. run_case_pipeline() executes the identical stage sequence instead.
COVERAGE_EXCLUDED = {"service.run_forensic_analysis": "mutates dashboard scan state",
                     "extractor.get_chrome_path": "resolves the live profile, not the case",
                     "extractor.cookies_from_live": "needs a locked live profile — covered by the live cookie row"}

_C4_MODULES = ["extractor", "crypto", "rules", "correlation", "mitre", "reporter", "service"]

_CALLED = set()
_PATCHED = []       # (module, attribute_name, original_function)


def _wrap(qualified, fn):
    def tracked(*args, **kwargs):
        _CALLED.add(qualified)
        return fn(*args, **kwargs)
    tracked.__name__ = getattr(fn, "__name__", qualified.split(".")[-1])
    tracked.__doc__ = getattr(fn, "__doc__", None)
    tracked._c4_tracked = True
    return tracked


def install_coverage():
    """Wrap every tracked C4 function with a call counter. Idempotent.

    A function must be replaced everywhere it is *bound*, not just where it is
    defined: `extractor` does `from .crypto import load_master_key`, so patching
    only `crypto.load_master_key` would leave the real call untracked. Every C4
    module is therefore scanned for aliases of the same function object.
    """
    import importlib
    _CALLED.clear()
    if _PATCHED:
        return
    modules = {name: importlib.import_module(f".{name}", __package__)
               for name in _C4_MODULES}
    for mod_name, fn_names in COVERAGE_TARGETS.items():
        for fn_name in fn_names:
            original = getattr(modules[mod_name], fn_name, None)
            if original is None or getattr(original, "_c4_tracked", False):
                continue
            wrapper = _wrap(f"{mod_name}.{fn_name}", original)
            for mod in modules.values():
                for attr, value in list(vars(mod).items()):
                    if value is original:
                        _PATCHED.append((mod, attr, original))
                        setattr(mod, attr, wrapper)


def remove_coverage():
    """Restore the original functions everywhere they were patched."""
    for mod, attr, original in reversed(_PATCHED):
        try:
            setattr(mod, attr, original)
        except Exception:
            pass
    _PATCHED.clear()


def coverage_report():
    """Which tracked functions ran, and which did not."""
    expected = {f"{mod}.{fn}" for mod, fns in COVERAGE_TARGETS.items() for fn in fns}
    called = {name for name in _CALLED if name in expected}
    return {
        "total": len(expected),
        "called": len(called),
        "missing": sorted(expected - called),
        "excluded": COVERAGE_EXCLUDED,
    }
