"""
WebSentinel — FastAPI API Gateway
Runs on http://127.0.0.1:8000
Launch from project root: python -m uvicorn core.main:app
"""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Set
from datetime import datetime
import json, os, asyncio

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
    asyncio.create_task(_bg_start_session())
    return {"status": "starting"}


@app.post("/session/stop")
async def session_stop():
    await pw_session.stop()
    await _broadcast({"type": "session_stopped"})
    return {"status": "stopped"}


@app.post("/session/navigate")
async def session_navigate(body: dict):
    from fastapi import HTTPException
    url = body.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="url required")
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
