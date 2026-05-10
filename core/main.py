"""
WebSentinel — FastAPI API Gateway (All Components)
Integrates C1 (Extension Analyzer), C2 (BitB Phishing), C3 (Beacon Detector), C4 (Forensics)
Launch from project root: python -m uvicorn core.main:app --port 8000
"""
# ── Windows: switch to ProactorEventLoop so Playwright can spawn Chromium ──
import sys, os, asyncio
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

import json, tempfile
from datetime import datetime
from typing import List, Optional, Set

from fastapi import FastAPI, File, HTTPException, Response, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
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
from .c2.layer3_visual     import check_visual
from .c2.layer4_form       import check_form
from .c2.layer5_reputation import check_reputation

# ── C3 — Browser Execution-Aware C2 Beacon Detector ───────────────────────────
from .c3.context_tagger import c3_tagger
from .c3.interceptor    import c3_interceptor
from .c3.analyzer       import c3_analyzer
from .c3.alert_store    import c3_alert_store

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
app = FastAPI(title="WebSentinel API", version="4.0.0")

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
    dead: Set[WebSocket] = set()
    for ws in list(_ws_clients):
        try:
            await ws.send_json(data)
        except Exception:
            dead.add(ws)
    _ws_clients.difference_update(dead)

# ── In-memory state ────────────────────────────────────────────────────────────
alerts: list = []
c1_history: list = []
_pending_installs: dict = {}

settings: dict = {
    "layers": {"l1": True, "l2": True, "l3": True, "l4": True, "l5": True},
    "whitelist": [],
    "gsb_key": "",
    "pw_home_url": "",
}

# ── Request / response models ──────────────────────────────────────────────────
class AnalyzeReq(BaseModel):
    url: str
    dom: Optional[str] = None
    screenshot: Optional[str] = None

class SettingsReq(BaseModel):
    layers: dict
    whitelist: List[str] = []
    gsb_key: str = ""
    pw_home_url: str = ""

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
    layer_results = []
    weights = {"L1": 0.15, "L2": 0.30, "L3": 0.20, "L4": 0.15, "L5": 0.20}

    layer_jobs = []
    if ly.get("l1", True): layer_jobs.append(("L1", "BitB Detection",    check_bitb(url, req.dom or "")))
    if ly.get("l2", True): layer_jobs.append(("L2", "URL Analysis",      check_url(url)))
    if ly.get("l3", True): layer_jobs.append(("L3", "Visual Similarity", check_visual(url, req.screenshot or "")))
    if ly.get("l4", True): layer_jobs.append(("L4", "Form Destination",  check_form(url, req.dom or "")))
    if ly.get("l5", True): layer_jobs.append(("L5", "Reputation Check",  check_reputation(url, settings["gsb_key"])))

    for lid, lname, coro in layer_jobs:
        try:
            res = await coro
            layer_results.append({"id": lid, "name": lname,
                                   "score": round(float(res["score"]), 4),
                                   "detail": res.get("detail", "")})
        except Exception as e:
            layer_results.append({"id": lid, "name": lname, "score": 0.0, "detail": f"Error: {e}"})

    risk_score = sum(lr["score"] * weights.get(lr["id"], 0.2) * 100 for lr in layer_results)
    risk_score = round(min(100.0, max(0.0, risk_score)), 1)
    verdict = "PHISHING" if risk_score >= 60 else "SUSPICIOUS" if risk_score >= 30 else "SAFE"

    result = {"url": url, "verdict": verdict, "risk_score": risk_score,
              "layers": layer_results, "timestamp": datetime.now().isoformat()}
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
                      "gsb_key": req.gsb_key, "pw_home_url": req.pw_home_url})
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
        try:
            await pw_session.load_extension(ext_path)
            await _broadcast({"type": "c1_extension_installed",
                               "extension_id": ext_id,
                               "extension_path": ext_path,
                               "c1_result": c1_result})
            return {"status": "installed", "extension_id": ext_id,
                    "extension_path": ext_path, "c1_result": c1_result}
        except Exception as exc:
            raise HTTPException(status_code=500,
                detail=f"Session reload with extension failed: {exc}")
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
    try:
        await pw_session.load_extension(ext_path)
        if webstore_url and pw_session.is_running:
            try:
                await asyncio.sleep(1.2)
                await pw_session.navigate(webstore_url)
            except Exception:
                pass
        await _broadcast({"type": "c1_install_approved", "ext_id": req.ext_id,
                           "extension_path": ext_path, "webstore_url": webstore_url})
        return {"status": "installed", "ext_id": req.ext_id}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to load extension: {exc}")


@app.post("/session/block_install")
async def block_install(req: ApproveInstallReq):
    _pending_installs.pop(req.ext_id, None)
    await _broadcast({"type": "c1_install_blocked", "ext_id": req.ext_id})
    return {"status": "blocked", "ext_id": req.ext_id}


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
        const res = await fetch('/c3/test/beacon-target?ts=' + Date.now(), {{
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


@app.post("/forensic/extract")
async def forensic_extract(req: ForensicReq):
    profile_path = req.profile_path
    if not profile_path:
        if pw_session.is_running or os.path.isdir(PW_PROFILE_DIR):
            profile_path = PW_PROFILE_DIR
    try:
        result = await asyncio.to_thread(run_forensic_analysis, profile_path, req.save_outputs)
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

async def _pw_nav_handler(url: str, page=None) -> None:
    """C2 phishing analysis on every navigation. C1 runs on click, not navigation."""
    dom        = await pw_session.get_dom()
    screenshot = await pw_session.get_screenshot_b64()
    title      = await pw_session.get_title()
    req        = AnalyzeReq(url=url, dom=dom, screenshot=screenshot)
    result     = await analyze(req)
    await _broadcast({"type": "analysis",   "data": result})
    await _broadcast({"type": "url_change", "url": url, "title": title})


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
async def session_navigate(body: dict):
    url = body.get("url", "").strip()
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
