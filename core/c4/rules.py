"""
Stage 2 — Single-artifact rule engine
Flags individually suspicious events BEFORE cross-artifact correlation.
Each rule checks one artifact type in isolation.
"""
from datetime import datetime, timedelta
from urllib.parse import urlparse

SUSPICIOUS_DOMAINS = {"onion","bit.ly","tinyurl.com","pastebin.com",
                      "ngrok.io","serveo.net","0.0.0.0","raw.githubusercontent.com"}
SUSPICIOUS_EXT     = {".exe",".bat",".cmd",".ps1",".vbs",".scr",".msi",".dll",".hta"}
SENSITIVE_COOKIES  = {"session","auth","token","jwt","jsessionid","phpsessid",
                      "sid","login","access_token","bearer","id_token","refresh_token"}

def _ts(s):
    try: return datetime.fromisoformat(s)
    except: return None

def _domain(url):
    try: return urlparse(url).netloc.lower().replace("www.","")
    except: return ""

# ── Rule 1: Suspicious domain in history ───────────────────────────────────
def rule_suspicious_domain(event):
    if event["artifact_type"] != "history": return []
    url = event["detail"].get("url","")
    dom = _domain(url)
    for bad in SUSPICIOUS_DOMAINS:
        if bad in dom:
            return [{"rule":"R01","name":"Suspicious domain",
                     "detail":f"Domain '{dom}' matches known suspicious pattern",
                     "score":60}]
    return []

# ── Rule 2: Dangerous file download ────────────────────────────────────────
def rule_dangerous_download(event):
    if event["artifact_type"] != "download": return []
    fname = event["detail"].get("filename","")
    ext   = fname.rsplit(".",1)[-1].lower() if "." in fname else ""
    flags = []
    if f".{ext}" in SUSPICIOUS_EXT:
        flags.append({"rule":"R02","name":"Dangerous file type",
                      "detail":f"Downloaded file has suspicious extension: .{ext}",
                      "score":70})
    if event["detail"].get("danger_type",0) > 0:
        flags.append({"rule":"R02b","name":"Chrome danger flag",
                      "detail":"Chrome's own safety check flagged this download",
                      "score":80})
    return flags

# ── Rule 3: Sensitive session cookie ───────────────────────────────────────
def rule_sensitive_cookie(event):
    if event["artifact_type"] != "cookie": return []
    name = event["detail"].get("name","").lower()
    if any(s in name for s in SENSITIVE_COOKIES):
        return [{"rule":"R03","name":"Sensitive session cookie",
                 "detail":f"Cookie name '{event['detail'].get('name','')}' is a known session token",
                 "score":40}]
    return []

# ── Rule 4: Credential record (always flagged) ──────────────────────────────
def rule_credential_record(event):
    if event["artifact_type"] != "credential": return []
    times = event["detail"].get("times_used",0)
    score = 35 if times > 0 else 55
    detail = "Saved credential record" if times > 0 else "Credential never used — possibly newly harvested"
    return [{"rule":"R04","name":"Credential access",
             "detail":detail,"score":score}]

# ── Rule 5: Risky extension permissions ────────────────────────────────────
def rule_risky_extension(event):
    if event["artifact_type"] != "extension": return []
    risky = event["detail"].get("risky_perms",[])
    if not risky: return []
    return [{"rule":"R05","name":"Risky extension permissions",
             "detail":f"Extension '{event['detail'].get('name','')}' has: {', '.join(risky)}",
             "score":50 + min(len(risky)*10, 30)}]

# ── Rule 6: High visit frequency (URL burst) ───────────────────────────────
def rule_url_burst(events):
    """Batch rule — needs full event list."""
    history = [e for e in events if e["artifact_type"]=="history"]
    history.sort(key=lambda x: x["timestamp"])
    flagged = set()
    for i, anchor in enumerate(history):
        t0 = _ts(anchor["timestamp"])
        if not t0: continue
        t1 = t0 + timedelta(seconds=60)
        count = sum(1 for e in history[i:] if _ts(e["timestamp"]) and _ts(e["timestamp"])<=t1)
        if count >= 20 and id(anchor) not in flagged:
            flagged.add(id(anchor))
            anchor["rule_flags"].append({"rule":"R06","name":"URL burst",
                "detail":f"{count} URLs visited in 60 seconds — bot/malware pattern",
                "score":70})
            anchor["anomaly_score"] += 70
            anchor["risk_flag"] = True

# ── Main entry: apply all single-artifact rules ─────────────────────────────
def apply_single_artifact_rules(events):
    for e in events:
        flags = (rule_suspicious_domain(e) +
                 rule_dangerous_download(e) +
                 rule_sensitive_cookie(e) +
                 rule_credential_record(e) +
                 rule_risky_extension(e))
        e["rule_flags"] = flags
        if flags:
            e["risk_flag"] = True
            e["anomaly_score"] += sum(f["score"] for f in flags)
            e["anomaly_reasons"] += [f["detail"] for f in flags]

    # Batch rules
    rule_url_burst(events)
    return events
