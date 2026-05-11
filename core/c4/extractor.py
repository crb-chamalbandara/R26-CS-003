import os, shutil, sqlite3, json, hashlib
from datetime import datetime, timedelta

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

def extract_cookies(profile, tmp):
    src = find_file(profile, os.path.join("Network","Cookies"), "Cookies")
    db  = safe_copy(src, tmp, "Cookies_c4")
    if not db:
        cached = os.path.join(tmp, "Cookies_c4")
        if os.path.exists(cached):
            db = cached
        else:
            return [], "Cookies locked — close the browser and retry"
    SENS = {"session","auth","token","jwt","jsessionid","phpsessid",
            "__secure","sid","login","access_token","bearer","id_token"}
    events = []
    for r in query(db, "SELECT host_key,name,path,expires_utc,is_secure,is_httponly,last_access_utc FROM cookies ORDER BY last_access_utc DESC"):
        ts = chrome_time(r["last_access_utc"])
        if not ts: continue
        sens = any(s in (r["name"] or "").lower() for s in SENS)
        events.append(_event(ts,"cookie","Cookies.db",
            {"host":r["host_key"] or "","name":r["name"] or "","path":r["path"] or "",
             "secure":bool(r["is_secure"]),"httponly":bool(r["is_httponly"])},
            risk=sens, reasons=["sensitive cookie name"] if sens else []))
    return events, None

def extract_downloads(profile, tmp):
    db = os.path.join(tmp, "History_c4")
    if not os.path.exists(db):
        db = safe_copy(find_file(profile,"History"), tmp, "History_c4")
    if not db: return [], "History locked"
    SUSP = {".exe",".bat",".cmd",".ps1",".vbs",".scr",".msi",".dll",".hta",".pif",".lnk"}
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

def extract_credentials(profile, tmp):
    src = find_file(profile, "Login Data")
    db  = safe_copy(src, tmp, "LoginData_c4")
    if not db:
        cached = os.path.join(tmp, "LoginData_c4")
        if os.path.exists(cached):
            db = cached
        else:
            return [], "Login Data locked — close the browser and retry"
    events = []
    for r in query(db, "SELECT origin_url,username_value,date_created,date_last_used,times_used FROM logins ORDER BY date_last_used DESC"):
        ts = chrome_time(r["date_last_used"] or r["date_created"])
        if ts:
            events.append(_event(ts,"credential","Login Data",
                {"origin":r["origin_url"] or "","username":r["username_value"] or "",
                 "times_used":r["times_used"] or 0,"password":"[ENCRYPTED-DPAPI]"},
                risk=True, reasons=["saved credential record"]))
    return events, None

def extract_extensions(profile):
    ext_dir = os.path.join(profile, "Extensions")
    events  = []
    if not os.path.exists(ext_dir): return events
    RISKY = {"<all_urls>","tabs","cookies","webRequest","webRequestBlocking",
             "nativeMessaging","debugger","clipboardRead","history"}
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
                perms = set(m.get("permissions",[]))|set(m.get("host_permissions",[]))
                risky = perms & RISKY
                events.append(_event(datetime.now().isoformat(),"extension","Extensions/",
                    {"id":eid,"name":m.get("name","Unknown"),"version":m.get("version",""),
                     "permissions":sorted(list(perms)),"risky_perms":sorted(list(risky))},
                    risk=len(risky)>0, reasons=[f"risky permission: {p}" for p in risky]))
                break
            except: continue
    return events

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


def collect_manifest(profile):
    files = {"History":find_file(profile,"History"),
             "Cookies":find_file(profile,os.path.join("Network","Cookies"),"Cookies"),
             "Login Data":find_file(profile,"Login Data"),
             "Bookmarks":find_file(profile,"Bookmarks")}
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

def run_extraction(profile_path=None, tmp_dir=None):
    if not profile_path: profile_path = get_chrome_path()
    else: profile_path = _resolve_profile(profile_path)
    if not profile_path or not os.path.exists(profile_path):
        raise FileNotFoundError(f"Chrome profile not found: {profile_path}")
    if not tmp_dir:
        tmp_dir = os.path.join(os.path.dirname(__file__), "..", "output", "tmp")
    os.makedirs(tmp_dir, exist_ok=True)

    warnings = []
    history,   w = extract_history(profile_path, tmp_dir);   warnings += [w] if w else []
    cookies,   w = extract_cookies(profile_path, tmp_dir);   warnings += [w] if w else []
    downloads, w = extract_downloads(profile_path, tmp_dir); warnings += [w] if w else []
    creds,     w = extract_credentials(profile_path, tmp_dir); warnings += [w] if w else []
    extensions = extract_extensions(profile_path)
    clusters, _w = extract_clusters(profile_path, tmp_dir)
    manifest   = collect_manifest(profile_path)

    all_events = history + cookies + downloads + creds + extensions
    if not all_events:
        raise ValueError("No events extracted. Close Chrome completely and try again.")

    return {"profile_path":profile_path,"extracted_at":datetime.now().isoformat(),
            "warnings":warnings,"artifact_manifest":manifest,
            "events":all_events,"clusters":clusters}
