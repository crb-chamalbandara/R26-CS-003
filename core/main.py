"""
WebSentinel — FastAPI API Gateway
Runs on http://127.0.0.1:8000
Launch from project root: python -m uvicorn core.main:app
"""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional, List, Set
from datetime import datetime
import json, os, asyncio

from .c3.context_tagger import c3_tagger
from .c3.interceptor import c3_interceptor
from .c3.analyzer import c3_analyzer
from .c3.alert_store import c3_alert_store
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
_session_starting = False

async def _broadcast(data: dict) -> None:
    global _ws_clients
    dead: Set[WebSocket] = set()
    for ws in list(_ws_clients):
        try:
            await ws.send_json(data)
        except Exception:
            dead.add(ws)
    _ws_clients -= dead

# ── In-memory state ───────────────────────────────────────────
alerts: list = []
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
    screenshot: Optional[str] = None   # base64-encoded JPEG

class SettingsReq(BaseModel):
    layers: dict
    whitelist: List[str] = []
    gsb_key: str = ""
    pw_home_url: str = ""

class C3CollectReq(BaseModel):
    label: int


# ── Endpoints ─────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now().isoformat(), "alerts": len(alerts)}


@app.post("/analyze")
async def analyze(req: AnalyzeReq):
    url = req.url

    # Skip internal / browser-chrome URLs
    for prefix in ("about:", "chrome:", "devtools:", "electron:"):
        if url.startswith(prefix):
            return {"url": url, "verdict": "SKIP", "risk_score": 0,
                    "layers": [], "timestamp": datetime.now().isoformat()}

    # Check whitelist
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

    risk_score = sum(
        lr["score"] * weights.get(lr["id"], 0.2) * 100
        for lr in layer_results
    )
    risk_score = round(min(100.0, max(0.0, risk_score)), 1)
    verdict = "PHISHING" if risk_score >= 60 else "SUSPICIOUS" if risk_score >= 30 else "SAFE"

    result = {
        "url": url,
        "verdict": verdict,
        "risk_score": risk_score,
        "layers": layer_results,
        "timestamp": datetime.now().isoformat(),
    }

    alerts.insert(0, result)
    if len(alerts) > 500:
        alerts.pop()

    return result


@app.get("/alerts")
async def get_alerts(limit: int = 50):
    return alerts[:limit]


@app.post("/settings")
async def save_settings(req: SettingsReq):
    settings["layers"]      = req.layers
    settings["whitelist"]   = req.whitelist
    settings["gsb_key"]     = req.gsb_key
    settings["pw_home_url"] = req.pw_home_url
    return {"status": "saved"}


@app.get("/settings")
async def get_settings():
    return settings


# C3 - Browser Execution Aware C2 Beacon Detector
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
    return {
        "ok": True,
        "component": "c3",
        "target": "beacon",
        "timestamp": datetime.now().isoformat(),
    }


@app.post("/c3/test/beacon-target")
async def c3_test_beacon_target_post(body: dict | None = None):
    return {
        "ok": True,
        "component": "c3",
        "target": "beacon",
        "received": body or {},
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/c3/test/beacon-page", response_class=HTMLResponse)
async def c3_test_beacon_page(interval: int = 30000, method: str = "GET"):
    interval = max(1000, min(int(interval), 300000))
    method = "POST" if str(method).upper() == "POST" else "GET"
    body = "JSON.stringify({ ts: Date.now(), component: 'c3' })" if method == "POST" else "undefined"
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


# ══════════════════════════════════════════════════════════════
#  Playwright session endpoints
# ══════════════════════════════════════════════════════════════

async def _pw_nav_handler(url: str) -> None:
    """Called by PlaywrightSession on every main-frame navigation."""
    dom        = await pw_session.get_dom()
    screenshot = await pw_session.get_screenshot_b64()
    title      = await pw_session.get_title()
    req        = AnalyzeReq(url=url, dom=dom, screenshot=screenshot)
    result     = await analyze(req)
    await _broadcast({"type": "analysis",  "data": result})
    await _broadcast({"type": "url_change", "url": url, "title": title})


async def _bg_start_session() -> None:
    global _session_starting
    try:
        await pw_session.start()
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
    asyncio.create_task(_bg_start_session())
    return {"status": "starting"}


@app.post("/session/stop")
async def session_stop():
    global _session_starting
    _session_starting = False
    await c3_analyzer.stop_loop()
    await c3_interceptor.stop()
    await pw_session.stop()
    await _broadcast({"type": "session_stopped"})
    return {"status": "stopped"}


@app.post("/session/navigate")
async def session_navigate(body: dict):
    from fastapi import HTTPException
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
    navigated_url = await pw_session.navigate(url)
    return {"url": navigated_url}


# ══════════════════════════════════════════════════════════════
#  WebSocket — real-time event stream
# ══════════════════════════════════════════════════════════════

@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    await websocket.accept()
    _ws_clients.add(websocket)
    await websocket.send_json({
        "type": "init",
        "session_running": pw_session.is_running,
        "url": await pw_session.current_url() if pw_session.is_running else "",
    })
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        _ws_clients.discard(websocket)
    except Exception:
        _ws_clients.discard(websocket)
