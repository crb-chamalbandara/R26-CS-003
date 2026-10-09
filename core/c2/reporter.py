"""
C2 report rendering — HTML, CSV and SIEM.

Built to the same shape as core/c4/reporter.py so the two components produce
comparable artefacts: the SIEM envelope reuses C4's field names (export_type /
export_version / generated_at / total_events / events) so one ingest pipeline
handles both, and the HTML is a single self-contained, print-friendly document
with no external assets.

The point of these is the per-layer `evidence` each alert now carries. A C2
report that only restated "L1 100%, L4 85%" would say no more than the alert card
already does; what makes it worth exporting is the measurements underneath —
which host the form posted to, which URL features tripped, what the fusion did.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from html import escape
from typing import Iterable

_LAYER_NAMES = {
    "L1": "BitB Detection",
    "L2": "URL Analysis",
    "L3": "Visual Similarity",
    "L4": "Form Destination",
    "L5": "Reputation Check",
    "L6": "Runtime Behavior",
}
_LAYER_ORDER = ["L1", "L2", "L3", "L4", "L5", "L6"]

_VERDICT_COLOUR = {
    "PHISHING":   "#dc2626",
    "SUSPICIOUS": "#d97706",
    "SAFE":       "#059669",
    "VERIFIED":   "#0284c7",
}


def report_filename(kind: str) -> str:
    """Mirrors core/c4/service.py::report_filename so exported files from the two
    components sort together and are obviously related."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"c2_{kind}_{stamp}"


def _fmt_value(value) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:.4f}".rstrip("0").rstrip(".")
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value) if value else "—"
    if isinstance(value, dict):
        return json.dumps(value, default=str)
    if value is None or value == "":
        return "—"
    return str(value)


def _evidence_table(evidence: dict) -> str:
    """Render one layer's evidence dict. Nested feature/flag groups are pulled out
    first so the reader sees the measurements before the bookkeeping."""
    if not isinstance(evidence, dict) or not evidence:
        return '<p class="none">No evidence recorded for this layer.</p>'

    out = []
    features = evidence.get("features")
    if isinstance(features, dict) and features:
        rows = "".join(
            f"<tr><td>{escape(str(k))}</td><td>{escape(_fmt_value(v))}</td></tr>"
            for k, v in sorted(features.items())
        )
        out.append(f'<div class="sub">Feature vector</div><table class="kv">{rows}</table>')

    flags = evidence.get("flags")
    if isinstance(flags, (list, tuple)) and flags:
        chips = "".join(f'<span class="chip">{escape(str(f))}</span>' for f in flags)
        out.append(f'<div class="sub">Signals tripped</div><div class="chips">{chips}</div>')

    rest = {k: v for k, v in evidence.items() if k not in ("features", "flags")}
    if rest:
        rows = "".join(
            f"<tr><td>{escape(str(k))}</td><td>{escape(_fmt_value(v))}</td></tr>"
            for k, v in sorted(rest.items())
        )
        out.append(f'<div class="sub">Measurements</div><table class="kv">{rows}</table>')

    return "".join(out) or '<p class="none">No evidence recorded for this layer.</p>'


_REPORT_CSS = """
  *{box-sizing:border-box}
  :root{--bg:#eef2f8;--card:#ffffff;--card2:#f6f9fc;--line:#dbe4ef;--ink:#0d1a2b;--soft:#33495f;
        --mut:#5d7288;--acc:#2563eb;--chip-bg:#fef2f2;--chip-bd:#fecaca;--chip-fg:#b91c1c;--lid:#0d1a2b}
  @media (prefers-color-scheme:dark){
    :root{--bg:#070d18;--card:#0e1828;--card2:#0a1220;--line:#1f3250;--ink:#e8f1ff;--soft:#a8c0dc;
          --mut:#7e98b8;--acc:#4d8ef8;--chip-bg:rgba(240,71,71,.12);--chip-bd:rgba(240,71,71,.35);
          --chip-fg:#fca5a5;--lid:#2a4470}}
  body{font-family:'Plus Jakarta Sans','Segoe UI Variable','Segoe UI',-apple-system,Roboto,Helvetica,Arial,sans-serif;
       margin:0;padding:32px 20px;background:var(--bg);color:var(--ink);line-height:1.55}
  .wrap{max-width:960px;margin:0 auto;background:var(--card);border:1px solid var(--line);
        border-radius:16px;padding:30px 34px;box-shadow:0 10px 34px rgba(15,23,42,.10)}
  h1{font-size:20px;margin:0 0 4px;letter-spacing:-.01em}
  .sub-hdr{font-size:12px;color:var(--mut);margin-bottom:22px}
  .top{display:flex;align-items:center;gap:24px;border:1px solid var(--line);border-radius:14px;
       padding:18px 22px;margin-bottom:26px;
       background:linear-gradient(135deg,color-mix(in srgb,var(--vc) 12%,var(--card2)),var(--card2))}
  .score{font-size:46px;font-weight:800;color:var(--vc);line-height:1;letter-spacing:-.02em}
  .unit{font-size:10px;color:var(--mut);letter-spacing:.08em;margin-top:2px}
  .when{font-size:11px;color:var(--mut);margin-top:6px}
  .verdict{display:inline-block;padding:5px 14px;border-radius:999px;color:#fff;
           font-weight:700;font-size:12px;letter-spacing:.05em;background:var(--vc)}
  .url{font-family:'JetBrains Mono',ui-monospace,Consolas,monospace;font-size:13px;word-break:break-all}
  h2{font-size:11.5px;text-transform:uppercase;letter-spacing:.09em;color:var(--mut);
     margin:28px 0 12px;padding-bottom:7px;border-bottom:1px solid var(--line)}
  .path{display:flex;flex-wrap:wrap;align-items:center;gap:0;margin-bottom:6px}
  .pnode{display:flex;align-items:center;gap:7px;padding:7px 12px;border:1px solid var(--line);
         border-radius:10px;background:var(--card2);position:relative;margin-right:22px}
  .pnode:not(:last-child)::after{content:"";position:absolute;right:-22px;top:50%;width:22px;height:2px;background:var(--line)}
  .pdot{width:9px;height:9px;border-radius:50%}
  .pid{font-weight:800;font-size:11.5px}
  .pval{font-weight:800;font-size:12px;font-variant-numeric:tabular-nums}
  .layer{border:1px solid var(--line);border-radius:12px;padding:15px 18px;margin-bottom:12px;background:var(--card2)}
  .lhead{display:flex;align-items:center;gap:10px;margin-bottom:9px}
  .lid{font-weight:800;font-size:12px;background:var(--lid);color:#fff;padding:2px 9px;border-radius:6px}
  .lname{font-weight:600;font-size:13px;flex:1}
  .lscore{font-weight:800;font-size:14px;font-variant-numeric:tabular-nums}
  .bar{height:6px;background:var(--line);border-radius:4px;overflow:hidden}
  .fill{height:100%;border-radius:4px}
  .detail{font-size:12.5px;color:var(--soft);margin:10px 0 4px}
  .sub{font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);font-weight:700;margin:13px 0 6px}
  table.kv{width:100%;border-collapse:collapse;font-size:12px}
  table.kv td{border:1px solid var(--line);padding:5px 10px;vertical-align:top;color:var(--soft)}
  table.kv td:first-child{width:38%;color:var(--mut);font-family:'JetBrains Mono',ui-monospace,Consolas,monospace}
  .chips{display:flex;flex-wrap:wrap;gap:5px}
  .chip{background:var(--chip-bg);border:1px solid var(--chip-bd);color:var(--chip-fg);
        padding:2px 10px;border-radius:999px;font-size:11px}
  .none{font-size:12px;color:var(--mut);font-style:italic;margin:6px 0 0}
  footer{margin-top:28px;padding-top:13px;border-top:1px solid var(--line);font-size:11px;color:var(--mut)}
  @media print{:root{--bg:#fff}body{background:#fff;padding:0}.wrap{border:none;box-shadow:none}}
"""


def generate_html_report(alert: dict) -> str:
    """Standalone HTML report for one alert. Self-contained and print-friendly —
    no external CSS, fonts or images, so it can be saved, emailed or attached to
    the research write-up and still render identically."""
    url        = str(alert.get("url") or "")
    verdict    = str(alert.get("verdict") or "SAFE").upper()
    risk       = float(alert.get("risk_score") or 0.0)
    timestamp  = str(alert.get("timestamp") or "")
    alert_id   = alert.get("id")
    layers     = alert.get("layers") or []
    fusion     = alert.get("fusion") or {}
    colour     = _VERDICT_COLOUR.get(verdict, "#475569")
    generated  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    by_id = {str(l.get("id")): l for l in layers}
    ordered = [by_id[k] for k in _LAYER_ORDER if k in by_id]
    ordered += [l for l in layers if str(l.get("id")) not in _LAYER_ORDER]

    layer_blocks = []
    path_nodes = []
    for l in ordered:
        lid   = str(l.get("id") or "")
        score = float(l.get("score") or 0.0)
        pct   = round(score * 100)
        bar   = "#dc2626" if pct > 60 else "#d97706" if pct > 28 else "#059669"
        path_nodes.append(
            f'<div class="pnode"><span class="pdot" style="background:{bar}"></span>'
            f'<span class="pid">{escape(lid)}</span>'
            f'<span class="pval" style="color:{bar}">{pct}%</span></div>')
        layer_blocks.append(f"""
        <section class="layer">
          <div class="lhead">
            <span class="lid">{escape(lid)}</span>
            <span class="lname">{escape(str(l.get('name') or _LAYER_NAMES.get(lid, '')))}</span>
            <span class="lscore" style="color:{bar}">{pct}%</span>
          </div>
          <div class="bar"><div class="fill" style="width:{pct}%;background:{bar}"></div></div>
          <p class="detail">{escape(str(l.get('detail') or ''))}</p>
          {_evidence_table(l.get('evidence') or {})}
        </section>""")

    if fusion:
        frows = "".join(
            f"<tr><td>{escape(str(k))}</td><td>{escape(_fmt_value(v))}</td></tr>"
            for k, v in sorted(fusion.items())
        )
        fusion_html = f'<table class="kv">{frows}</table>'
    else:
        fusion_html = '<p class="none">No fusion breakdown recorded.</p>'

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>WebSentinel C2 Report — {escape(url[:80])}</title>
<style>
{_REPORT_CSS}
</style></head>
<body><div class="wrap">
  <h1>C2 &mdash; Phishing / BitB Analysis Report</h1>
  <div class="sub-hdr">WebSentinel &middot; generated {escape(generated)}
    {f'&middot; alert #{escape(str(alert_id))}' if alert_id is not None else ''}</div>

  <div class="top" style="--vc:{colour}">
    <div><div class="score">{risk:.0f}</div>
         <div class="unit">RISK / 100</div></div>
    <div style="flex:1;min-width:0">
      <span class="verdict">{escape(verdict)}</span>
      <div class="url" style="margin-top:8px">{escape(url)}</div>
      <div class="when">Analysed {escape(timestamp)}</div>
    </div>
  </div>

  <h2>Detection path</h2>
  <div class="path">{''.join(path_nodes) if path_nodes else '<p class="none">No layers ran for this alert.</p>'}</div>

  <h2>Detection layers</h2>
  {''.join(layer_blocks) if layer_blocks else '<p class="none">No layers ran for this alert.</p>'}

  <h2>Score fusion</h2>
  {fusion_html}

  <footer>WebSentinel C2 &mdash; multilayer browser threat detection.
  Evidence shown is what each detection layer measured at analysis time.</footer>
</div></body></html>"""


def generate_csv(alerts: Iterable[dict]) -> str:
    """Flat one-row-per-alert table for spreadsheet analysis. Per-layer scores get
    their own columns so a batch can be sorted or pivoted by any single layer."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["id", "timestamp", "url", "verdict", "risk_score", "verified"]
                    + [f"{lid}_score" for lid in _LAYER_ORDER]
                    + ["fusion_method", "floor_applied", "flags"])
    for a in alerts:
        by_id = {str(l.get("id")): l for l in (a.get("layers") or [])}
        fusion = a.get("fusion") or {}
        flags = []
        for l in (a.get("layers") or []):
            ev = l.get("evidence") or {}
            for f in (ev.get("flags") or []):
                flags.append(f"{l.get('id')}:{f}")
        writer.writerow(
            [a.get("id", ""), a.get("timestamp", ""), a.get("url", ""),
             a.get("verdict", ""), a.get("risk_score", ""),
             "yes" if a.get("verified") else "no"]
            + [by_id[lid].get("score", "") if lid in by_id else "" for lid in _LAYER_ORDER]
            + [fusion.get("method", ""), fusion.get("floor_applied", "") or "",
               "; ".join(flags)]
        )
    return buf.getvalue()


def generate_siem_export(alerts: Iterable[dict]) -> dict:
    """SIEM-compatible envelope (Splunk / QRadar / ELK).

    Field names deliberately match core/c4/reporter.py::generate_siem_export so a
    single ingest pipeline handles C2 and C4 alike; only `source` and the
    event-specific keys differ.
    """
    now = datetime.now().isoformat()
    events = []
    for a in alerts:
        verdict = str(a.get("verdict") or "SAFE").upper()
        risk    = float(a.get("risk_score") or 0.0)
        severity = ("High" if verdict == "PHISHING" else
                    "Medium" if verdict == "SUSPICIOUS" else "Low")
        triggered, evidence = [], {}
        for l in (a.get("layers") or []):
            lid = str(l.get("id") or "")
            ev  = l.get("evidence") or {}
            if ev:
                evidence[lid] = ev
            for f in (ev.get("flags") or []):
                triggered.append(f"{lid}:{f}")
        events.append({
            "timestamp":      a.get("timestamp", now),
            "source":         "C2-PhishingDetector",
            "event_type":     "phishing_detection",
            "alert_id":       a.get("id"),
            "url":            a.get("url", ""),
            "verdict":        verdict,
            "severity":       severity,
            "score":          risk,
            "verified_domain": bool(a.get("verified")),
            "layer_scores":   {str(l.get("id")): l.get("score")
                               for l in (a.get("layers") or [])},
            "triggered_signals": triggered,
            "fusion":         a.get("fusion") or {},
            "evidence":       evidence,
        })

    return {
        "export_type":    "C2_SIEM_Export",
        "export_version": "1.0",
        "generated_at":   now,
        "total_events":   len(events),
        "events":         events,
    }
