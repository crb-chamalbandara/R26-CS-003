"""
C2 Layer 2 — URL classifier
Loads trained model from models/url_classifier.pkl when available;
falls back to heuristic scoring so the app works before training.
Run scripts/prepare_dataset.py to train the model.
"""
import re
import os
import pickle
from urllib.parse import urlparse

# Model path is relative to the project root (two levels up from core/c2/)
_model = None
_MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "models", "url_classifier.pkl")
try:
    with open(_MODEL_PATH, "rb") as f:
        _model = pickle.load(f)
    print("[L2] Loaded trained URL classifier model")
except FileNotFoundError:
    print("[L2] No trained model found — using heuristics (run scripts/prepare_dataset.py to train)")


FREE_HOSTS = {
    "yolasite", "weebly", "wixsite", "wordpress", "blogspot",
    "sites.google", "duckdns", "ddns.net", "no-ip", "ngrok",
    "000webhostapp", "web.app", "firebaseapp", "surge.sh",
    "netlify.app", "vercel.app",
}

PHISH_KEYWORDS = {
    "login", "signin", "sign-in", "verify", "verification",
    "secure", "security", "update", "confirm", "account",
    "banking", "credential", "password", "recover", "support",
    "wallet", "webscr", "cmd=_login",
}

SHORT_SERVICES = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "rb.gy", "is.gd", "tiny.cc",
}

BRAND_NAMES = {
    "paypal", "microsoft", "apple", "amazon", "google",
    "facebook", "instagram", "netflix", "dropbox", "linkedin",
    "twitter", "wellsfargo", "bankofamerica", "chase", "hsbc",
    "dhl", "fedex", "ups", "irs", "gov",
}

FREE_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".pw"}


def extract_features(url: str) -> dict:
    """Extract URL features for ML model or heuristic scoring."""
    try:
        parsed = urlparse(url if "://" in url else "https://" + url)
        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        full = url.lower()
    except Exception:
        return {}

    url_len = len(url)
    dots_in_host = hostname.count(".")
    subdomains = hostname.split(".")[:-2] if len(hostname.split(".")) > 2 else []
    has_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))

    tld = "." + hostname.split(".")[-1] if "." in hostname else ""
    is_free_tld = tld in FREE_TLDS
    is_http = url.startswith("http://")

    has_free_host = any(fh in hostname for fh in FREE_HOSTS)
    has_phish_kw  = any(kw in full for kw in PHISH_KEYWORDS)
    is_short_svc  = any(ss in hostname for ss in SHORT_SERVICES)

    brand_in_host = False
    for brand in BRAND_NAMES:
        if brand in hostname:
            if not re.search(rf"\b{brand}\.(com|org|net|gov|co\.uk)$", hostname):
                brand_in_host = True
                break

    hyphen_count = hostname.count("-")
    query_len = len(parsed.query) if parsed.query else 0
    special_in_path = len(re.findall(r"[%@!#$^*]", path))

    return {
        "url_len": url_len,
        "dots_in_host": dots_in_host,
        "subdomain_depth": len(subdomains),
        "has_ip": int(has_ip),
        "is_free_tld": int(is_free_tld),
        "is_http": int(is_http),
        "has_free_host": int(has_free_host),
        "has_phish_kw": int(has_phish_kw),
        "is_short_svc": int(is_short_svc),
        "brand_in_host": int(brand_in_host),
        "hyphen_count": hyphen_count,
        "query_len": query_len,
        "special_in_path": special_in_path,
    }


def _heuristic_score(feats: dict) -> float:
    score = 0.0
    if feats.get("has_ip"):         score += 0.35
    if feats.get("is_free_tld"):    score += 0.25
    if feats.get("has_free_host"):  score += 0.30
    if feats.get("has_phish_kw"):   score += 0.20
    if feats.get("brand_in_host"):  score += 0.40
    if feats.get("is_short_svc"):   score += 0.15
    if feats.get("is_http"):        score += 0.10
    if feats.get("subdomain_depth", 0) >= 3: score += 0.15
    if feats.get("url_len", 0) > 100: score += 0.10
    if feats.get("hyphen_count", 0) >= 3: score += 0.10
    return min(1.0, score)


async def check_url(url: str) -> dict:
    feats = extract_features(url)
    if not feats:
        return {"score": 0.0, "detail": "Could not parse URL"}

    if _model is not None:
        try:
            import pandas as pd
            feat_order = [
                "url_len", "dots_in_host", "subdomain_depth", "has_ip",
                "is_free_tld", "is_http", "has_free_host", "has_phish_kw",
                "is_short_svc", "brand_in_host", "hyphen_count",
                "query_len", "special_in_path",
            ]
            X = pd.DataFrame([feats])[feat_order]
            prob = float(_model.predict_proba(X)[0][1])
            return {"score": round(prob, 4), "detail": f"ML model score: {prob:.2f}"}
        except Exception:
            pass

    score = _heuristic_score(feats)
    flags = [k for k, v in feats.items() if v and k not in
             ("url_len", "dots_in_host", "query_len", "special_in_path", "hyphen_count", "subdomain_depth")]
    detail = "Heuristic: " + (", ".join(flags) if flags else "no flags")
    return {"score": round(score, 4), "detail": detail}
