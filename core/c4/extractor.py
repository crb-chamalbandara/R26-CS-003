import os, shutil, sqlite3, json, hashlib, re as _re
from datetime import datetime, timedelta
from .crypto import load_master_key, decrypt_password

CHROME_EPOCH = datetime(1601, 1, 1)

def chrome_time(ts):
    if not ts or ts == 0: return None
    try: return (CHROME_EPOCH + timedelta(microseconds=ts)).isoformat()
    except: return None

def sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""): h.update(chunk)
        return h.hexdigest()
    except: return None

def _resolve_profile(path):
    """If path is a Chromium user-data dir (contains a Default sub-folder),
    return the Default sub-folder where the actual SQLite artifacts live."""
    if not path:
        return path
    default = os.path.join(path, "Default")
    return default if os.path.isdir(default) else path

def get_chrome_path():
    configured = os.environ.get("WEBSENTINEL_BROWSER_PROFILE", "").strip()
    if configured and os.path.exists(configured):
        return _resolve_profile(configured)

    # Playwright persistent-context profile (~/.websentinel/profile/Default)
    websentinel_profile = os.path.join(os.path.expanduser("~"), ".websentinel", "profile")
    if os.path.exists(websentinel_profile):
        return _resolve_profile(websentinel_profile)

    local = os.environ.get("LOCALAPPDATA", "")
    for p in [
        os.path.join(local, "Google", "Chrome", "User Data", "Default"),
        os.path.join(local, "Google", "Chrome", "User Data", "Profile 1"),
        os.path.join(local, "Chromium", "User Data", "Default"),
        os.path.join(local, "Microsoft", "Edge", "User Data", "Default"),
    ]:
        if os.path.exists(p): return p
    return None

def find_file(profile, *names):
    for n in names:
        p = os.path.join(profile, n)
        if os.path.exists(p): return p
    return None

def safe_copy(src, dst_dir, name):
    if not src or not os.path.exists(src): return None
    dst = os.path.join(dst_dir, name)
    try:
        shutil.copy2(src, dst); return dst
    except OSError:
        # Windows file-lock (WinError 32 sharing violation) or POSIX EACCES —
        # fall back to SQLite online backup via immutable read-only URI.
        try:
            sc = sqlite3.connect(f"file:{src}?mode=ro&immutable=1", uri=True)
            dc = sqlite3.connect(dst)
            sc.backup(dc); sc.close(); dc.close(); return dst
        except Exception: return None

def query(db, sql):
    if not db or not os.path.exists(db): return []
    try:
        c = sqlite3.connect(db); c.row_factory = sqlite3.Row
        r = c.execute(sql).fetchall(); c.close(); return r
    except: return []

def _event(ts, atype, src, detail, risk=False, reasons=None):
    return {"timestamp": ts, "artifact_type": atype, "source_file": src,
            "detail": detail, "risk_flag": risk,
            "risk_reasons": reasons or [], "anomaly_score": 0,
            "anomaly_reasons": [], "rule_flags": []}

# ══════════════════════════════════════════════════════════════════════════════
# ARTIFACT EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════

# ── [1] HISTORY ───────────────────────────────────────────────────────────────
def extract_history(profile, tmp):
    src = find_file(profile, "History")
    db  = safe_copy(src, tmp, "History_c4")
    if not db:
        cached = os.path.join(tmp, "History_c4")
        if os.path.exists(cached):
            db = cached
        else:
            return [], "History locked — close the browser and retry"
    events = []
    for r in query(db, """SELECT u.url,u.title,u.visit_count,u.last_visit_time,v.visit_time
        FROM urls u LEFT JOIN visits v ON u.id=v.url WHERE v.visit_time>0
        ORDER BY v.visit_time DESC LIMIT 5000"""):
        ts = chrome_time(r["visit_time"] or r["last_visit_time"])
        if ts: events.append(_event(ts,"history","History.db",
            {"url":r["url"] or "","title":r["title"] or "","visit_count":r["visit_count"] or 0}))
    return events, None

# ── [2] COOKIES ───────────────────────────────────────────────────────────────
SENSITIVE_COOKIE_NAMES = {"session","auth","token","jwt","jsessionid","phpsessid",
                          "__secure","sid","login","access_token","bearer","id_token"}

def cookies_from_live(jar, acquired_at=None):
    """Convert a live cookie jar (Playwright/CDP) into cookie events.

    Chromium holds `Network/Cookies` with an exclusive Windows lock for as long
    as the browser runs, so no file-based copy can succeed against a live
    profile. Reading the jar out of the running browser is the standard
    volatile-acquisition answer: the data is the same store, taken from memory
    instead of from disk, and is marked as such so the report never implies the
    events came off the file.
    """
    ts = acquired_at or datetime.now().isoformat()
    events = []
    for c in jar or []:
        name = str(c.get("name", "") or "")
        host = str(c.get("domain", "") or "")
        sens = any(s in name.lower() for s in SENSITIVE_COOKIE_NAMES)
        reasons = ["sensitive cookie name"] if sens else []
        events.append(_event(ts, "cookie", "live session (volatile)",
            {"host": host, "name": name, "path": str(c.get("path", "/") or "/"),
             "secure": bool(c.get("secure")), "httponly": bool(c.get("httpOnly")),
             "same_site": str(c.get("sameSite", "") or ""),
             "acquisition": "live"},
            risk=sens, reasons=reasons))
    return events

def extract_cookies(profile, tmp, live_cookies=None):
    src = find_file(profile, os.path.join("Network","Cookies"), "Cookies")
    db  = safe_copy(src, tmp, "Cookies_c4")
    if not db:
        cached = os.path.join(tmp, "Cookies_c4")
        if os.path.exists(cached):
            db = cached
        elif live_cookies is not None:
            events = cookies_from_live(live_cookies)
            return events, (f"Cookies DB locked by the running browser — "
                            f"{len(events)} cookie(s) acquired live from the session instead")
        else:
            return [], "Cookies locked — close the browser and retry"
    events = []
    for r in query(db, "SELECT host_key,name,path,expires_utc,is_secure,is_httponly,last_access_utc FROM cookies ORDER BY last_access_utc DESC"):
        ts = chrome_time(r["last_access_utc"])
        if not ts: continue
        sens = any(s in (r["name"] or "").lower() for s in SENSITIVE_COOKIE_NAMES)
        events.append(_event(ts,"cookie","Cookies.db",
            {"host":r["host_key"] or "","name":r["name"] or "","path":r["path"] or "",
             "secure":bool(r["is_secure"]),"httponly":bool(r["is_httponly"]),
             "acquisition":"disk"},
            risk=sens, reasons=["sensitive cookie name"] if sens else []))
    return events, None

# ── [3] DOWNLOADS ─────────────────────────────────────────────────────────────
def extract_downloads(profile, tmp):
    db = os.path.join(tmp, "History_c4")
    if not os.path.exists(db):
        db = safe_copy(find_file(profile,"History"), tmp, "History_c4")
    if not db: return [], "History locked"
    SUSP = {".exe",".bat",".cmd",".ps1",".vbs",".scr",".msi",".dll",".hta",".pif",".lnk",".com"}
    events = []
    for r in query(db, "SELECT target_path,tab_url,total_bytes,start_time,danger_type FROM downloads ORDER BY start_time DESC LIMIT 500"):
        ts = chrome_time(r["start_time"])
        if not ts: continue
        target_path = r["target_path"] or ""
        fname = os.path.basename(target_path)
        ext   = os.path.splitext(fname)[1].lower()
        risky = ext in SUSP or (r["danger_type"] or 0) > 0
        reasons = []
        if ext in SUSP: reasons.append(f"suspicious extension: {ext}")
        if (r["danger_type"] or 0) > 0: reasons.append("Chrome flagged dangerous")
        file_hash = sha256(target_path) if target_path and os.path.exists(target_path) else None
        if file_hash and risky: reasons.append(f"sha256: {file_hash}")
        events.append(_event(ts,"download","History.db",
            {"filename":fname,"source_url":r["tab_url"] or "","size_bytes":r["total_bytes"] or 0,
             "danger_type":r["danger_type"] or 0,"target_path":target_path,
             "sha256":file_hash or "file not on disk"}, risk=risky, reasons=reasons))
    return events, None

# ── [4] CREDENTIALS ───────────────────────────────────────────────────────────
def extract_credentials(profile, tmp):
    src = find_file(profile, "Login Data")
    db  = safe_copy(src, tmp, "LoginData_c4")
    if not db:
        cached = os.path.join(tmp, "LoginData_c4")
        if os.path.exists(cached):
            db = cached
        else:
            return [], "Login Data locked — close the browser and retry"
    # Recover the AES master key once (DPAPI-protected, bound to this Windows user)
    master_key = load_master_key(profile)
    events = []
    for r in query(db, "SELECT origin_url,username_value,password_value,date_created,date_last_used,times_used FROM logins ORDER BY date_last_used DESC"):
        ts = chrome_time(r["date_last_used"] or r["date_created"])
        if ts:
            dec = decrypt_password(r["password_value"], master_key)
            reasons = ["saved credential record"]
            if dec["status"] == "success":
                reasons.append("credential decrypted via DPAPI + AES-GCM")
            events.append(_event(ts,"credential","Login Data",
                {"origin":r["origin_url"] or "","username":r["username_value"] or "",
                 "times_used":r["times_used"] or 0,
                 "password":dec["password"],"password_length":dec["length"],
                 "decryption":dec["status"]},
                risk=True, reasons=reasons))
    return events, None

# ── [5] EXTENSIONS ────────────────────────────────────────────────────────────
RISKY_PERMS = {"<all_urls>","tabs","cookies","webRequest","webRequestBlocking",
               "nativeMessaging","debugger","clipboardRead","history"}

# Chromium's Extension::Location enum, as stored in (Secure) Preferences.
EXT_LOCATIONS = {1:"web store", 2:"external registry", 3:"unpacked (side-loaded)",
                 4:"external pref", 5:"component", 6:"external registry",
                 7:"unpacked (side-loaded)", 8:"command line", 9:"external policy",
                 10:"external policy download"}

def _perm_names(manifest):
    """Manifest permission lists may hold objects (e.g. {'fileSystem':['write']})."""
    raw = list(manifest.get("permissions", []) or []) \
        + list(manifest.get("host_permissions", []) or []) \
        + list(manifest.get("optional_permissions", []) or [])
    names = []
    for p in raw:
        if isinstance(p, str):
            names.append(p)
        elif isinstance(p, dict):
            names.extend(str(k) for k in p.keys())
        else:
            names.append(str(p))
    return sorted(set(names))

def _extension_event(eid, manifest, source, extra=None):
    perms = _perm_names(manifest)
    risky = sorted(set(perms) & RISKY_PERMS)
    reasons = [f"risky permission: {p}" for p in risky]
    detail = {"id": eid, "name": manifest.get("name", "Unknown"),
              "version": manifest.get("version", ""),
              "permissions": perms, "risky_perms": risky}
    detail.update(extra or {})
    if detail.get("location", "").startswith("unpacked"):
        reasons.append("side-loaded extension — not installed from the Web Store")
    return _event(datetime.now().isoformat(), "extension", source, detail,
                  risk=len(risky) > 0, reasons=reasons)

def _extensions_from_folder(profile):
    """Unpacked manifests under Default/Extensions/<id>/<version>/."""
    ext_dir = os.path.join(profile, "Extensions")
    events = []
    if not os.path.exists(ext_dir): return events
    for eid in os.listdir(ext_dir):
        vdir = os.path.join(ext_dir, eid)
        if not os.path.isdir(vdir): continue
        try: versions = sorted(os.listdir(vdir), reverse=True)
        except: continue
        for ver in versions:
            mp = os.path.join(vdir, ver, "manifest.json")
            if not os.path.exists(mp): continue
            try:
                with open(mp, encoding="utf-8", errors="ignore") as f: m = json.load(f)
            except Exception:
                continue
            events.append(_extension_event(eid, m, "Extensions/",
                                           {"path": os.path.join(vdir, ver)}))
            break
    return events

def _extensions_from_prefs(profile):
    """Extension records inside (Secure) Preferences.

    Automation and side-loaded profiles frequently have no Extensions/ folder at
    all — Chromium loads them from wherever --load-extension points and keeps the
    installed-extension record, with its full manifest, in Secure Preferences.
    Reading only the folder therefore reports "no extensions" on exactly the
    profiles where a hostile extension is most likely to be side-loaded.
    """
    events = []
    for prefs_name in ("Secure Preferences", "Preferences"):
        path = os.path.join(profile, prefs_name)
        if not os.path.exists(path): continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                prefs = json.load(f)
        except Exception:
            continue
        settings = (prefs.get("extensions", {}) or {}).get("settings", {}) or {}
        for eid, record in settings.items():
            if not isinstance(record, dict): continue
            manifest = record.get("manifest") or {}
            if not isinstance(manifest, dict): continue
            location = EXT_LOCATIONS.get(record.get("location"), "unknown")
            try:
                installed = chrome_time(int(record.get("install_time") or 0)) or ""
            except (TypeError, ValueError):
                installed = ""
            events.append(_extension_event(eid, manifest, prefs_name, {
                "location": location,
                "path": str(record.get("path", "")),
                "install_time": installed,
                "enabled": record.get("state", 1) == 1,
            }))
    return events

def extract_extensions(profile):
    """Installed extensions from every place Chromium records them."""
    events = _extensions_from_folder(profile)
    seen = {e["detail"]["id"] for e in events}
    for event in _extensions_from_prefs(profile):
        if event["detail"]["id"] in seen: continue
        seen.add(event["detail"]["id"])
        events.append(event)
    return events

# ── [6] SESSION CLUSTERS ──────────────────────────────────────────────────────
def extract_clusters(profile, tmp):
    """Read Chrome 110+ browsing session clusters from the History DB."""
    db = os.path.join(tmp, "History_c4")
    if not os.path.exists(db):
        db = safe_copy(find_file(profile, "History"), tmp, "History_c4")
    if not db:
        return [], None
    try:
        c = sqlite3.connect(db)
        tables = {r[0] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        c.close()
    except Exception:
        return [], None
    if "clusters" not in tables or "clusters_and_visits" not in tables:
        return [], None   # Chrome < 110 or Playwright build without cluster tables
    rows = query(db, """
        SELECT c.id AS cid, c.raw_label,
               cv.url_for_display, cv.score, cv.engagement_score,
               v.visit_time
        FROM clusters_and_visits cv
        JOIN clusters c ON cv.cluster_id = c.id
        JOIN visits v ON cv.url_id = v.url
        WHERE v.visit_time > 0
        ORDER BY c.id, v.visit_time DESC
        LIMIT 2000
    """)
    from collections import defaultdict as _dd
    cluster_map = _dd(lambda: {"label": "", "urls": [], "max_score": 0.0})
    for r in rows:
        cid = r["cid"]
        cluster_map[cid]["label"] = r["raw_label"] or f"Cluster {cid}"
        score = float(r["score"] or 0)
        cluster_map[cid]["max_score"] = max(cluster_map[cid]["max_score"], score)
        cluster_map[cid]["urls"].append({
            "url":        r["url_for_display"] or "",
            "score":      round(score, 4),
            "engagement": round(float(r["engagement_score"] or 0), 4),
            "ts":         chrome_time(r["visit_time"]),
        })
    clusters = [{"cluster_id": cid, **v} for cid, v in cluster_map.items()]
    clusters.sort(key=lambda x: x["max_score"], reverse=True)
    return clusters, None

# ── [7] SESSION RESTORE (SNSS) ────────────────────────────────────────────────
# Default/Sessions/{Session,Tabs}_<chrome-timestamp> hold what the browser will
# restore: the tabs that were open and every URL in their back/forward stack.
# Forensically this is the closest thing to "what was on screen", and it survives
# a cleared History — a tab whose URL appears nowhere in History is a strong
# signal on its own. The SNSS container is a length-prefixed command log with
# pickled payloads; URLs appear inside it as UTF-8 or UTF-16LE strings, which is
# what the bounded scan below recovers without depending on the command IDs of a
# particular Chromium version.
_SNSS_URL_U8  = _re.compile(rb"https?://[\x21-\x7e]{4,512}")
_SNSS_URL_U16 = _re.compile(rb"(?:h\x00t\x00t\x00p\x00s?\x00:\x00/\x00/\x00)"
                            rb"(?:[\x20-\x7e]\x00){4,512}")
_SNSS_MAX_PER_FILE = 300

def _snss_urls(blob):
    """Recover distinct URLs from one SNSS file, in the order they appear."""
    found, seen = [], set()
    for match in _SNSS_URL_U8.finditer(blob):
        url = match.group(0).decode("utf-8", "ignore").rstrip("\x00")
        if url not in seen:
            seen.add(url); found.append(url)
    for match in _SNSS_URL_U16.finditer(blob):
        url = match.group(0).decode("utf-16-le", "ignore").rstrip("\x00")
        if url not in seen:
            seen.add(url); found.append(url)
    return found[:_SNSS_MAX_PER_FILE]

def extract_sessions(profile):
    """Read the session-restore store: which tabs were open, and their URLs."""
    sess_dir = os.path.join(profile, "Sessions")
    if not os.path.isdir(sess_dir):
        return [], None
    events, locked = [], []
    for fn in sorted(os.listdir(sess_dir)):
        kind = "tabs" if fn.startswith("Tabs_") else "session" if fn.startswith("Session_") else ""
        if not kind:
            continue
        path = os.path.join(sess_dir, fn)
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
        except OSError:
            locked.append(fn)          # the session in progress stays open for writing
            continue
        # The filename suffix is the Chrome timestamp the session was written.
        try:
            ts = chrome_time(int(fn.split("_", 1)[1])) or datetime.now().isoformat()
        except (IndexError, ValueError):
            ts = datetime.now().isoformat()
        for url in _snss_urls(blob):
            host = _domain_from_origin(url)
            if not host:
                continue
            events.append(_event(ts, "session", f"Sessions/{fn}",
                {"url": url, "host": host, "kind": kind, "session_file": fn}))
    warning = None
    if locked:
        warning = (f"{len(locked)} session file(s) held open by the running browser "
                   f"({', '.join(locked[:2])}) — restored tabs read from the closed sessions")
    return events, warning


# ── [8] LOCAL STORAGE (LevelDB) ───────────────────────────────────────────────
_ORIGIN_RE = _re.compile(rb"_(https?://[\w.\-:]+)\x00")

def extract_local_storage(profile):
    """Best-effort scan of the Chromium Local Storage LevelDB store.

    A full LevelDB decode (block index + snappy) is out of scope; instead we
    read the uncompacted .log/.ldb records and recover which *origins* hold
    local-storage data plus a sample of their keys. Origins with stored state
    but no matching browsing history become orphan candidates downstream.
    """
    ls_dir = os.path.join(profile, "Local Storage", "leveldb")
    if not os.path.isdir(ls_dir):
        return []
    origins = {}
    for fn in os.listdir(ls_dir):
        if not fn.endswith((".log", ".ldb")):
            continue
        try:
            with open(os.path.join(ls_dir, fn), "rb") as f:
                blob = f.read()
        except OSError:
            continue
        for m in _ORIGIN_RE.finditer(blob):
            try:
                origin = m.group(1).decode("utf-8", "ignore")
            except Exception:
                continue
            if origin:
                origins[origin] = origins.get(origin, 0) + 1
    events = []
    for origin, hits in origins.items():
        host = _domain_from_origin(origin)
        events.append(_event(datetime.now().isoformat(), "localstorage", "Local Storage",
            {"origin": origin, "url": origin, "host": host, "entry_hits": hits},
            risk=False))
    return events

def _domain_from_origin(origin):
    try:
        from urllib.parse import urlparse
        return urlparse(origin).netloc.lower().replace("www.", "")
    except Exception:
        return ""

# ══════════════════════════════════════════════════════════════════════════════
# MANIFEST + ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

def collect_manifest(profile):
    files = {"History":find_file(profile,"History"),
             "Cookies":find_file(profile,os.path.join("Network","Cookies"),"Cookies"),
             "Login Data":find_file(profile,"Login Data"),
             "Bookmarks":find_file(profile,"Bookmarks"),
             "Secure Preferences":find_file(profile,"Secure Preferences")}
    manifest = {}
    for name, fpath in files.items():
        if not fpath: continue
        try:
            st = os.stat(fpath)
            manifest[name] = {"path":fpath,"sha256":sha256(fpath),
                "size_bytes":st.st_size,
                "mtime":datetime.fromtimestamp(st.st_mtime).isoformat(),
                "wal_exists":os.path.exists(fpath+"-wal")}
        except: continue
    return manifest

def run_extraction(profile_path=None, tmp_dir=None, live_cookies=None):
    """Collect every artifact type from a profile.

    `live_cookies` is an optional cookie jar read from a running browser. It is
    used only when the Cookies database is locked, which is always the case while
    Chromium is open — see cookies_from_live().
    """
    if not profile_path: profile_path = get_chrome_path()
    else: profile_path = _resolve_profile(profile_path)
    if not profile_path or not os.path.exists(profile_path):
        raise FileNotFoundError(f"Chrome profile not found: {profile_path}")
    if not tmp_dir:
        tmp_dir = os.path.join(os.path.dirname(__file__), "..", "output", "tmp")
    os.makedirs(tmp_dir, exist_ok=True)

    warnings = []
    history,   w = extract_history(profile_path, tmp_dir);   warnings += [w] if w else []
    cookies,   w = extract_cookies(profile_path, tmp_dir, live_cookies); warnings += [w] if w else []
    downloads, w = extract_downloads(profile_path, tmp_dir); warnings += [w] if w else []
    creds,     w = extract_credentials(profile_path, tmp_dir); warnings += [w] if w else []
    sessions,  w = extract_sessions(profile_path);           warnings += [w] if w else []
    extensions = extract_extensions(profile_path)
    localstore = extract_local_storage(profile_path)
    clusters, _w = extract_clusters(profile_path, tmp_dir)
    manifest   = collect_manifest(profile_path)

    all_events = (history + cookies + downloads + creds + sessions
                  + extensions + localstore)
    if not all_events:
        raise ValueError("No events extracted. Close Chrome completely and try again.")

    return {"profile_path":profile_path,"extracted_at":datetime.now().isoformat(),
            "warnings":warnings,"artifact_manifest":manifest,
            "events":all_events,"clusters":clusters}
