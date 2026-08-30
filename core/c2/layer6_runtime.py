"""
C2 Layer 6 — Runtime behavioral detection
Scores live-page behaviour collected by the instrumentation hook installed in
core/playwright_session.py (_RUNTIME_HOOK → window.__ws_runtime).

Unlike L1–L5 (static DOM/URL/screenshot), L6 captures behaviours that only appear at
runtime and are characteristic of BitB / credential-phishing kits:
  • keystroke hooks (keylogger), especially on password fields
  • clipboard hooks (copy/cut/paste, navigator.clipboard)
  • drag / selection / context-menu blocking (kit anti-inspection)
  • off-origin exfil sinks (fetch / XHR / sendBeacon / form submit to another host)

The session collects the signals; this layer only scores them, so it keeps the same
async `check_*(...) -> {score, detail}` contract and stays unit-testable without a browser.
"""
from typing import Optional


def _host_etld1(host: str) -> str:
    """Cheap registrable-host comparison key (last two labels). Good enough for the
    same-site check here; verified_domains.py owns the precise eTLD+1 logic."""
    host = (host or "").lower().split(":")[0]
    parts = [p for p in host.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


async def check_runtime(url: str, runtime: Optional[dict]) -> dict:
    if not runtime:
        return {"score": 0.0, "detail": "No runtime data"}

    score = 0.0
    flags = []

    kb_listeners  = int(runtime.get("kb_listeners", 0) or 0)
    kb_password   = bool(runtime.get("kb_on_password", False))
    clip_listen   = int(runtime.get("clipboard_listeners", 0) or 0)
    clip_api      = bool(runtime.get("clipboard_api", False))
    drag_block    = int(runtime.get("drag_block", 0) or 0)
    page_host     = runtime.get("page_host", "")
    exfil_hosts   = runtime.get("exfil_hosts", []) or []
    form_external = bool(runtime.get("form_submit_external", False))

    # ── Keylogger ─────────────────────────────────────────────
    if kb_password:
        score += 0.45
        flags.append("keystroke hook on password field")
    elif kb_listeners > 0:
        score += 0.20
        flags.append(f"{kb_listeners} keystroke listener(s)")

    # ── Clipboard hooks ───────────────────────────────────────
    if clip_listen > 0 or clip_api:
        score += 0.20
        flags.append("clipboard hook")

    # ── Anti-inspection (drag/select/contextmenu block) ───────
    if drag_block > 0:
        score += 0.15
        flags.append("drag/select blocking")

    # ── Off-origin credential exfil ───────────────────────────
    page_key = _host_etld1(page_host)
    off = sorted({h for h in exfil_hosts
                  if h and _host_etld1(h) != page_key}) if page_key else sorted(set(exfil_hosts))
    if off:
        score += 0.45
        flags.append("exfil→" + ", ".join(off[:3]))
    if form_external:
        score += 0.30
        flags.append("form submits off-origin")

    score = min(1.0, score)
    detail = ", ".join(flags) if flags else "No runtime anomalies"
    return {"score": round(score, 4), "detail": detail}
