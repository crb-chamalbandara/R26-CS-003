"""
WebSentinel — FastAPI API Gateway
Runs on http://127.0.0.1:8001
Launch from project root: python -m uvicorn core.main:app --port 8001
"""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Set
from datetime import datetime
import json, os, asyncio, tempfile

from .c1.analyzer          import analyze_extension as analyze_extension_c1
from .c1.analyzer          import sandbox_extension as sandbox_extension_c1
from .c1.db                import save_result as c1_db_save, get_history as c1_db_history
from .c1.crx_utils         import (
    extract_ext_id_from_url, is_webstore_url,
    fetch_crx_from_store, parse_crx_bytes, parse_crx_file,
    extract_crx_to_persistent_dir,
)
from .c2.layer1_bitb       import check_bitb
from .c2.layer2_url        import check_url
from .c2.layer3_visual     import check_visual
from .c2.layer4_form       import check_form
from .c2.layer5_reputation import check_reputation
from .playwright_session   import pw_session

app = FastAPI(title="WebSentinel API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── WebSocket broadcast set ────────────────────────────────────
_ws_clients: Set[WebSocket] = set()

async def _broadcast(data: dict) -> None:
    dead: Set[WebSocket] = set()
    for ws in list(_ws_clients):
        try:
            await ws.send_json(data)
        except Exception:
            dead.add(ws)
    _ws_clients.difference_update(dead)

# ── In-memory state ───────────────────────────────────────────
alerts: list = []
c1_history: list = []          # stores last 50 extension analysis results
_pending_installs: dict = {}   # ext_id -> {c1_result, ext_path, webstore_url}

settings: dict = {
    "layers": {"l1": True, "l2": True, "l3": True, "l4": True, "l5": True},
    "whitelist": [],
    "gsb_key": "",
    "pw_home_url": "",
}

# ── Request/response models ───────────────────────────────────
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
    url_or_id: str          # Web Store URL or bare 32-char extension ID
    force: bool = False     # load even if C1 flags it as suspicious/malicious

class WebstoreLookupReq(BaseModel):
    url_or_id: str          # Chrome Web Store URL  OR  bare 32-char extension ID


# ── C1 result helper ──────────────────────────────────────────
def _store_c1_result(result: dict, source: str, webstore_url: str = "") -> dict:
    """Attach metadata, push into in-memory cache, and persist to SQLite."""
    result["timestamp"]    = datetime.now().isoformat()
    result["source"]       = source
    result["webstore_url"] = webstore_url
    # In-memory cache (fast reads for current session)
    c1_history.insert(0, result)
    if len(c1_history) > 50:
        c1_history.pop()
    # Persist to SQLite (survives server restarts)
    try:
        c1_db_save(result)
    except Exception as exc:
        print(f"[C1-DB] Save failed (non-fatal): {exc}")
    return result


# ── Endpoints — C2 phishing detection ─────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now().isoformat(), "alerts": len(alerts)}


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


# ── Endpoints — C1 Extension Analyzer ────────────────────────

@app.post("/extension/analyze")
async def analyze_extension(req: ExtensionAnalyzeReq):
    """Manual analysis: caller supplies manifest JSON + optional source code."""
    result = await analyze_extension_c1(
        req.manifest,
        req.source_code or "",
        req.extension_id or "",
        req.extension_path or "",
    )
    return _store_c1_result(result, "manual")


@app.post("/extension/upload")
async def upload_extension(file: UploadFile = File(...)):
    """
    CRX file upload — user drops a downloaded .crx file for pre-install analysis.
    Extracts manifest + JS, runs C1 static analysis, optionally triggers sandbox.
    """
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

    # For sandbox: extract to a temp directory
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
        pass   # sandbox simply won't run without a valid path

    result = await analyze_extension_c1(manifest_str, source_code, ext_id, ext_path)
    result["filename"] = file.filename
    return _store_c1_result(result, "upload")


@app.post("/extension/webstore")
async def webstore_lookup(req: WebstoreLookupReq):
    """
    Lookup by Chrome Web Store URL or bare extension ID.
    Downloads the CRX from Google's servers, analyzes it, returns verdict.
    """
    raw = req.url_or_id.strip()

    # Extract ID from URL or treat whole value as ID
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
async def sandbox_extension(req: SandboxReq):
    """Run only the dynamic sandbox on an unpacked extension directory."""
    return await sandbox_extension_c1(req.extension_path)


@app.get("/extension/history")
async def extension_history(limit: int = 20):
    """Return recent C1 analysis results from the persistent SQLite database."""
    try:
        return await asyncio.to_thread(c1_db_history, limit)
    except Exception:
        # Fall back to in-memory cache if DB is unavailable
        return c1_history[:limit]


@app.post("/session/install_extension")
async def session_install_extension(req: InstallExtensionReq):
    """
    Download a Chrome extension from the Web Store, run C1 analysis,
    then load it into the live Playwright browser session.

    This is the real-world install flow — bypasses the Web Store 'Add to Chrome'
    button (which only works in signed Chrome) by downloading the CRX directly
    from Google's update server, just like Chrome itself does.
    """
    raw = req.url_or_id.strip()
    ext_id = extract_ext_id_from_url(raw) or (raw.lower() if len(raw) == 32 else None)
    if not ext_id:
        raise HTTPException(status_code=400,
            detail="Provide a Chrome Web Store URL or a 32-character extension ID.")

    # Download CRX from Google's update server
    try:
        crx_data = await fetch_crx_from_store(ext_id)
    except Exception as exc:
        raise HTTPException(status_code=502,
            detail=f"Could not download from Chrome Web Store: {exc}")

    # Parse + C1 analysis
    try:
        manifest_dict, source_code, _ = parse_crx_bytes(crx_data, ext_id)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Could not parse CRX: {exc}")

    c1_result = await analyze_extension_c1(json.dumps(manifest_dict), source_code, ext_id)
    _store_c1_result(c1_result, "webstore_install")

    # Block malicious unless the user explicitly forces it
    if c1_result["verdict"] == "MALICIOUS" and not req.force:
        return {
            "status": "blocked",
            "reason": "C1 flagged this extension as MALICIOUS — installation prevented.",
            "extension_id": ext_id,
            "c1_result": c1_result,
        }

    # Extract to persistent directory
    try:
        ext_path = extract_crx_to_persistent_dir(crx_data, ext_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Extraction failed: {exc}")

    # Load into the live Playwright session
    if pw_session.is_running:
        try:
            await pw_session.load_extension(ext_path)
            await _broadcast({
                "type":         "c1_extension_installed",
                "extension_id": ext_id,
                "extension_path": ext_path,
                "c1_result":    c1_result,
            })
            return {
                "status":         "installed",
                "extension_id":   ext_id,
                "extension_path": ext_path,
                "c1_result":      c1_result,
            }
        except Exception as exc:
            raise HTTPException(status_code=500,
                detail=f"Session reload with extension failed: {exc}")
    else:
        # Session not running — extension is ready, will load when session starts
        return {
            "status":         "ready",
            "message":        "Extension extracted. Start the browser session to load it.",
            "extension_id":   ext_id,
            "extension_path": ext_path,
            "c1_result":      c1_result,
        }


@app.get("/session/extensions")
async def get_session_extensions():
    """List extensions currently loaded in the Playwright session."""
    return {
        "extensions": pw_session.loaded_extensions,
        "count": len(pw_session.loaded_extensions),
    }


class ApproveInstallReq(BaseModel):
    ext_id: str


# ── C1 "Add to Chrome" click interception ─────────────────────────────────────
# Triggered ONLY when user clicks "Add to Chrome" via the silent click hook.
# No nav-based detection. No visual changes in the browser.
# All feedback goes to the C1 Live tab in the Dashboard.

async def _on_extension_install_click(ext_id: str, webstore_url: str) -> None:
    """
    Called when user clicks 'Add to Chrome' in the Playwright session.
    Runs C1 analysis and streams results to the Dashboard Live tab.
    """
    if not ext_id:
        return
    print(f"[C1] 'Add to Chrome' clicked: {ext_id}")

    await _broadcast({
        "type":   "c1_install_intercepted",
        "ext_id": ext_id,
        "url":    webstore_url,
        "state":  "analyzing",
    })

    try:
        crx_data = await fetch_crx_from_store(ext_id)
        manifest_dict, source_code, _ = parse_crx_bytes(crx_data, ext_id)

        # Extract to persistent dir BEFORE analysis so the sandbox has a valid path
        ext_path = extract_crx_to_persistent_dir(crx_data, ext_id)
        manifest_str = json.dumps(manifest_dict)

        # Phase 1 — fast static-only pass (no path → sandbox skipped, result in <200ms)
        static_result = await analyze_extension_c1(manifest_str, source_code, ext_id)
        static_score_pct = static_result["static"]["score"] * 100

        if static_score_pct >= 50.0:
            # Let the dashboard know sandbox is starting before the ~20s wait
            await _broadcast({
                "type":         "c1_install_intercepted",
                "ext_id":       ext_id,
                "url":          webstore_url,
                "state":        "sandbox_running",
                "static_score": round(static_score_pct, 1),
            })
            # Phase 2 — re-run with extension_path so sandbox actually fires
            c1_result = await analyze_extension_c1(
                manifest_str, source_code, ext_id,
                extension_path=ext_path,
            )
        else:
            c1_result = static_result

        _store_c1_result(c1_result, "webstore_intercept", webstore_url)
        _pending_installs[ext_id] = {
            "c1_result":    c1_result,
            "ext_path":     ext_path,
            "webstore_url": webstore_url,
        }

        state = {"SAFE": "safe", "SUSPICIOUS": "suspicious", "MALICIOUS": "malicious"}.get(
            c1_result["verdict"], "suspicious"
        )
        print(f"[C1] {ext_id} → {c1_result['verdict']} (score={c1_result['score']:.3f})")

        await _broadcast({
            "type":   "c1_install_intercepted",
            "ext_id": ext_id,
            "url":    webstore_url,
            "state":  state,
            "result": c1_result,
        })

    except Exception as exc:
        print(f"[C1] Analysis FAILED for {ext_id}: {exc}")
        await _broadcast({
            "type":   "c1_install_intercepted",
            "ext_id": ext_id,
            "url":    webstore_url,
            "state":  "error",
            "error":  str(exc),
        })


@app.post("/session/approve_install")
async def approve_install(req: ApproveInstallReq):
    """
    Dashboard calls this when the user clicks Approve.
    Only succeeds if the pending extension's verdict is SAFE.
    """
    pending = _pending_installs.get(req.ext_id)
    if not pending:
        raise HTTPException(status_code=404,
            detail="No pending install found for this extension ID.")

    verdict = pending["c1_result"].get("verdict", "SUSPICIOUS")
    if verdict != "SAFE":
        raise HTTPException(status_code=403,
            detail=f"Cannot approve — extension verdict is {verdict}.")

    ext_path    = pending["ext_path"]
    webstore_url = pending.get("webstore_url", "")
    del _pending_installs[req.ext_id]

    try:
        # Browser stops + restarts with the extension loaded.
        # Playwright requires extensions to be specified at launch — they cannot
        # be injected into a running context.  This is the only correct approach.
        await pw_session.load_extension(ext_path)

        # After restart the browser is at about:blank.
        # Navigate back to the extension's Web Store page so the user can see
        # the extension is active and the icon shows in full colour.
        if webstore_url and pw_session.is_running:
            try:
                await asyncio.sleep(1.2)   # wait for browser to fully initialise
                await pw_session.navigate(webstore_url)
            except Exception:
                pass

        await _broadcast({
            "type":           "c1_install_approved",
            "ext_id":         req.ext_id,
            "extension_path": ext_path,
            "webstore_url":   webstore_url,
        })
        return {"status": "installed", "ext_id": req.ext_id}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to load extension: {exc}")


@app.post("/session/block_install")
async def block_install(req: ApproveInstallReq):
    """Dashboard calls this when the user clicks Block."""
    _pending_installs.pop(req.ext_id, None)
    await _broadcast({"type": "c1_install_blocked", "ext_id": req.ext_id})
    return {"status": "blocked", "ext_id": req.ext_id}


@app.post("/dev/simulate_click")
async def dev_simulate_click():
    """
    Development / verification endpoint.
    Feeds the local test_malicious_ext through the EXACT same code path
    as a real 'Add to Chrome' click, so you can verify the sandbox branch
    fires and the Live tab updates correctly — without needing a Web Store
    extension that scores above the static threshold.
    """
    import json as _json

    _BASE = os.path.dirname(os.path.abspath(__file__))
    ext_dir = os.path.join(_BASE, "c1", "test_malicious_ext")
    if not os.path.isdir(ext_dir):
        raise HTTPException(status_code=404,
            detail="test_malicious_ext directory not found next to main.py")

    manifest_path = os.path.join(ext_dir, "manifest.json")
    bg_path       = os.path.join(ext_dir, "background.js")
    with open(manifest_path, encoding="utf-8") as f:
        manifest_dict = _json.load(f)
    with open(bg_path, encoding="utf-8") as f:
        source_code = f.read()

    fake_ext_id  = "test_malicious_ext_simulate"
    fake_url     = "https://chromewebstore.google.com/detail/websentinel-test/simulate"
    manifest_str = _json.dumps(manifest_dict)

    # Run the full click-intercept pipeline asynchronously (same as a real click)
    asyncio.create_task(_simulate_click_task(
        manifest_str, source_code, ext_dir, fake_ext_id, fake_url
    ))
    return {"status": "simulation started — watch the C1 Live tab"}


async def _simulate_click_task(
    manifest_str: str,
    source_code:  str,
    ext_path:     str,
    ext_id:       str,
    webstore_url: str,
) -> None:
    """Mirrors _on_extension_install_click but uses local files instead of Web Store."""
    print(f"[C1-SIM] Simulating 'Add to Chrome' click: {ext_id}")
    await _broadcast({
        "type":  "c1_install_intercepted",
        "ext_id": ext_id,
        "url":    webstore_url,
        "state":  "analyzing",
    })
    try:
        static_result    = await analyze_extension_c1(manifest_str, source_code, ext_id)
        static_score_pct = static_result["static"]["score"] * 100

        if static_score_pct >= 50.0:
            await _broadcast({
                "type":         "c1_install_intercepted",
                "ext_id":       ext_id,
                "url":          webstore_url,
                "state":        "sandbox_running",
                "static_score": round(static_score_pct, 1),
            })
            c1_result = await analyze_extension_c1(
                manifest_str, source_code, ext_id,
                extension_path=ext_path,
            )
        else:
            c1_result = static_result

        _store_c1_result(c1_result, "simulated_click", webstore_url)
        _pending_installs[ext_id] = {
            "c1_result":    c1_result,
            "ext_path":     ext_path,
            "webstore_url": webstore_url,
        }

        state = {"SAFE": "safe", "SUSPICIOUS": "suspicious", "MALICIOUS": "malicious"}.get(
            c1_result["verdict"], "suspicious"
        )
        print(f"[C1-SIM] {ext_id} → {c1_result['verdict']} (score={c1_result['score']:.3f})")
        await _broadcast({
            "type":   "c1_install_intercepted",
            "ext_id": ext_id,
            "url":    webstore_url,
            "state":  state,
            "result": c1_result,
        })
    except Exception as exc:
        print(f"[C1-SIM] FAILED: {exc}")
        await _broadcast({
            "type":  "c1_install_intercepted",
            "ext_id": ext_id,
            "url":    webstore_url,
            "state":  "error",
            "error":  str(exc),
        })


@app.get("/session/pending_installs")
async def get_pending_installs():
    """Return all extensions currently awaiting install approval."""
    return {
        ext_id: {
            "verdict":      v["c1_result"]["verdict"],
            "score":        v["c1_result"]["score"],
            "webstore_url": v["webstore_url"],
        }
        for ext_id, v in _pending_installs.items()
    }


# ══════════════════════════════════════════════════════════════
#  Playwright session — nav handler with C1 webstore detection
# ══════════════════════════════════════════════════════════════

async def _pw_nav_handler(url: str, page=None) -> None:
    """C2 phishing analysis on every navigation. C1 runs on click, not navigation."""
    dom        = await pw_session.get_dom()
    screenshot = await pw_session.get_screenshot_b64()
    title      = await pw_session.get_title()
    req    = AnalyzeReq(url=url, dom=dom, screenshot=screenshot)
    result = await analyze(req)
    await _broadcast({"type": "analysis",   "data": result})
    await _broadcast({"type": "url_change", "url": url, "title": title})


async def _bg_start_session() -> None:
    try:
        await pw_session.start()
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


@app.get("/session/status")
async def session_status():
    url = await pw_session.current_url() if pw_session.is_running else ""
    return {"running": pw_session.is_running, "url": url}


@app.post("/session/start")
async def session_start():
    if pw_session.is_running:
        return {"status": "already_running"}
    pw_session.clear_callbacks()
    pw_session.add_nav_callback(_pw_nav_handler)
    pw_session.add_click_callback(_on_extension_install_click)
    asyncio.create_task(_bg_start_session())
    return {"status": "starting"}


@app.post("/session/stop")
async def session_stop():
    await pw_session.stop()
    await _broadcast({"type": "session_stopped"})
    return {"status": "stopped"}


@app.post("/session/navigate")
async def session_navigate(body: dict):
    url = body.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="url required")
    if not pw_session.is_running:
        raise HTTPException(status_code=400, detail="Playwright session not running")
    return {"url": await pw_session.navigate(url)}


# ── WebSocket ─────────────────────────────────────────────────
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
