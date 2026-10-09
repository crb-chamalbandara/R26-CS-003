"""
Stage 5 — Generate outputs
  1. Timeline JSON
  2. HTML attack report
  3. SIEM export (JSON — compatible with Splunk/QRadar/ELK)
"""
import json, os
from datetime import datetime
from html import escape
from .linkchart import build_link_chart, render_svg

TYPE_COLORS = {
    "history":    ("#E6F1FB","#0C447C"),
    "cookie":     ("#FAEEDA","#633806"),
    "credential": ("#FCEBEB","#791F1F"),
    "download":   ("#EAF3DE","#27500A"),
    "extension":  ("#EEEDFE","#3C3489"),
    "localstorage": ("#E4F5F0","#0F5C48"),
    "session":    ("#FDEFF6","#7A1F52"),
}
SEV_COLORS = {"High":("#FCEBEB","#791F1F","#A32D2D"),
              "Medium":("#FAEEDA","#633806","#854F0B"),
              "Low":("#EAF3DE","#27500A","#0F6E56")}

# ─── HTML Report ────────────────────────────────────────────────────────────
# Dot / chip colours for the timeline, as plain values so they work in both the
# light and the dark theme of the report.
_TL_COLORS = {
    "history": "#4d8ef8", "download": "#f5a623", "cookie": "#9165f7",
    "credential": "#f04747", "extension": "#10b981", "localstorage": "#14b8a6",
    "session": "#ec4899",
}
_SEV_CHIP = {"High": "#f04747", "Medium": "#f5a623", "Low": "#10b981"}

_REPORT_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#eef2f8;--card:#fff;--card2:#f6f9fc;--line:#dbe4ef;--ink:#0d1a2b;--soft:#33495f;--mut:#5d7288;
      --acc:#047857;--hdr1:#0d1a2b;--hdr2:#13304a}
@media (prefers-color-scheme:dark){
  :root{--bg:#070d18;--card:#0e1828;--card2:#0a1220;--line:#1f3250;--ink:#e8f1ff;--soft:#a8c0dc;
        --mut:#7e98b8;--acc:#10b981;--hdr1:#0a1626;--hdr2:#0f2a3a}}
body{font-family:'Plus Jakarta Sans','Segoe UI Variable','Segoe UI',-apple-system,sans-serif;
     background:var(--bg);color:var(--ink);font-size:13px;line-height:1.55}
.page{max-width:1100px;margin:0 auto;padding:32px 22px}
.header{background:linear-gradient(135deg,var(--hdr1),var(--hdr2));color:#f4f8ff;border-radius:16px;
        padding:28px 32px;margin-bottom:22px;box-shadow:0 10px 34px rgba(15,23,42,.18)}
.header h1{font-size:21px;font-weight:700;margin-bottom:8px;letter-spacing:-.01em}
.header .meta{font-size:12px;color:#a9bdd6;line-height:1.9}
.badge{display:inline-block;font-size:11px;padding:2px 11px;border-radius:20px;margin-right:6px;
       background:rgba(255,255,255,.1);color:#d8e6f7;border:1px solid rgba(255,255,255,.14)}
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:22px}
.stat-card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px 18px;
           border-top:3px solid var(--sc,var(--acc))}
.stat-label{font-size:11px;color:var(--mut);margin-bottom:4px;text-transform:uppercase;letter-spacing:.07em;font-weight:600}
.stat-val{font-size:28px;font-weight:800;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.section{background:var(--card);border:1px solid var(--line);border-radius:14px;margin-bottom:20px;overflow:hidden}
.section-header{padding:14px 20px;border-bottom:1px solid var(--line);font-size:14px;font-weight:700;
                background:linear-gradient(90deg,color-mix(in srgb,var(--acc) 9%,transparent),transparent 60%)}
.pad{padding:16px 20px}
table{width:100%;border-collapse:collapse}
th{padding:9px 16px;text-align:left;font-size:10.5px;font-weight:700;color:var(--mut);text-transform:uppercase;
   letter-spacing:.06em;border-bottom:1px solid var(--line);background:var(--card2)}
td{padding:9px 16px;border-bottom:1px solid var(--line);vertical-align:middle;color:var(--soft)}
tr:last-child td{border-bottom:none}
.mono{font-family:'JetBrains Mono',ui-monospace,Consolas,monospace;font-size:11px}
.chip{display:inline-block;font-size:10.5px;padding:2px 9px;border-radius:20px;font-weight:700;
      color:var(--ch);border:1px solid color-mix(in srgb,var(--ch) 40%,transparent);
      background:color-mix(in srgb,var(--ch) 11%,transparent)}
.tl-title{font-size:10.5px;font-weight:800;letter-spacing:.09em;text-transform:uppercase;color:var(--mut);margin:0 0 10px}
.chain{border:1px solid var(--line);border-radius:12px;padding:12px 14px;margin-bottom:12px;background:var(--card2)}
.chain-h{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px}
.chain-dom{font-weight:700;color:var(--acc)}
.flow{display:flex;align-items:stretch;gap:6px;flex-wrap:wrap}
.arrow{align-self:center;color:var(--mut)}
.step{min-width:150px;max-width:240px;padding:8px 11px;border-radius:10px;
      border:1px solid color-mix(in srgb,var(--st) 45%,transparent);
      background:color-mix(in srgb,var(--st) 10%,transparent)}
.step b{display:block;font-size:9.5px;letter-spacing:.07em;text-transform:uppercase;color:var(--st)}
.step span{display:block;font-size:11px;color:var(--soft);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rail{position:relative;padding-left:24px}
.rail::before{content:"";position:absolute;left:7px;top:6px;bottom:6px;width:2px;border-radius:2px;
              background:linear-gradient(180deg,var(--acc),transparent)}
.tnode{position:relative;margin-bottom:9px}
.tdot{position:absolute;left:-23px;top:12px;width:11px;height:11px;border-radius:50%;background:var(--st);
      box-shadow:0 0 0 4px color-mix(in srgb,var(--st) 22%,transparent)}
.tcard{border:1px solid var(--line);border-radius:10px;padding:8px 13px;background:var(--card2)}
.trow{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.tdet{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--ink)}
.tscore{font-weight:800;color:#d97706;font-variant-numeric:tabular-nums}
.ttime{color:var(--mut);font-size:11px}
.treason{font-size:11.5px;color:var(--mut);margin-top:4px}
.empty{padding:16px 20px;color:var(--mut)}
.lc-wrap{padding:12px 16px 16px}
.lc-svg{width:100%;height:auto;display:block;border:1px solid var(--line);border-radius:12px;background:var(--card2);color:var(--mut)}
.lc-l{fill:var(--soft);font-size:11px;font-family:inherit;paint-order:stroke;stroke:var(--card2);stroke-width:3px}
.lc-legend{display:flex;flex-wrap:wrap;gap:6px 16px;margin-top:10px;font-size:11px;color:var(--mut)}
.lc-legend i{display:inline-block;width:10px;height:10px;margin-right:5px;vertical-align:-1px}
.lc-note{margin-top:8px;font-size:11px;color:var(--mut)}
.footer{text-align:center;font-size:11px;color:var(--mut);margin-top:30px;padding-bottom:22px}
@media (max-width:760px){.stat-grid{grid-template-columns:repeat(2,1fr)}}
@media print{:root{--bg:#fff}body{background:#fff}.header{box-shadow:none}.section{break-inside:avoid}}
"""


def _esc(value):
    return escape(str(value if value is not None else ""))


def _event_detail(e):
    d = e.get("detail") or {}
    return (d.get("url") or d.get("filename") or d.get("host") or d.get("origin") or "—")


def generate_html_report(result):
    now           = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    profile       = result.get("profile_path","Unknown")
    extracted_at  = result.get("extracted_at","")[:19]
    events        = result.get("events",[])
    mitre         = result.get("mitre_result",{})
    manifest      = result.get("artifact_manifest",{})
    by_sev        = mitre.get("by_severity",{})
    all_findings  = mitre.get("all_findings",[])
    chains        = (result.get("correlation") or {}).get("attack_chains") or []
    flagged       = [e for e in events if e.get("risk_flag")]

    # Manifest rows
    mrows = ""
    for name, info in manifest.items():
        sha = (info.get("sha256") or "—")[:32]+"..."
        mrows += (f"<tr><td>{_esc(name)}</td><td>{round(info.get('size_bytes',0)/1024,1)} KB</td>"
                  f"<td class='mono'>{_esc(sha)}</td><td>{_esc((info.get('mtime',''))[:19])}</td>"
                  f"<td>{'Yes' if info.get('wal_exists') else 'No'}</td></tr>")

    # Findings rows
    frows = ""
    for f in all_findings[:30]:
        sev = f.get("severity","Low")
        m = f.get("mitre",{})
        algo = f.get("algorithm","").replace("_"," ").title()
        desc = f.get("description","")
        frows += f"""<tr>
          <td><span class='chip' style='--ch:{_SEV_CHIP.get(sev, "#7e98b8")}'>{_esc(sev)}</span></td>
          <td style='font-weight:700;'>{_esc(m.get("technique_id","—"))}</td>
          <td>{_esc(m.get("technique_name","—"))}</td>
          <td>{_esc(m.get("tactic","—"))}</td>
          <td style='font-size:12px;'>{_esc(algo)}</td>
          <td style='font-size:12px;'>{_esc(desc[:80])}</td>
        </tr>"""

    # Detected attack chains: ordered artifact steps on one domain
    chain_html = ""
    for ch in chains[:6]:
        steps = ""
        for i, e in enumerate(ch.get("events") or []):
            col = _TL_COLORS.get(e.get("artifact_type",""), "#7e98b8")
            steps += ("<span class='arrow'>&#8594;</span>" if i else "") + (
                f"<div class='step' style='--st:{col}'><b>{_esc(e.get('artifact_type','event'))}</b>"
                f"<span title='{_esc(_event_detail(e))}'>{_esc(str(_event_detail(e))[:48])}</span>"
                f"<span>{_esc(str(e.get('timestamp',''))[:19])}</span></div>")
        chain_html += (f"<div class='chain'><div class='chain-h'><span class='chain-dom mono'>{_esc(ch.get('domain',''))}</span>"
                       f"<span>{_esc(ch.get('description',''))}</span>"
                       f"<span class='chip' style='--ch:#f04747;margin-left:auto'>Chain score {_esc(ch.get('score',0))}</span></div>"
                       f"<div class='flow'>{steps}</div></div>")

    # Flagged event timeline: newest first, as a rail
    trows = ""
    for e in sorted(flagged, key=lambda x:x.get("timestamp",""), reverse=True)[:50]:
        atype = e.get("artifact_type","")
        col = _TL_COLORS.get(atype, "#7e98b8")
        detail = str(_event_detail(e))
        reasons = "; ".join((e.get("anomaly_reasons") or [])[:2])
        score   = e.get("anomaly_score",0)
        trows += f"""<div class='tnode' style='--st:{col}'><span class='tdot'></span><div class='tcard'>
          <div class='trow'><span class='chip' style='--ch:{col}'>{_esc(atype)}</span>
            <span class='tdet mono' title='{_esc(detail)}'>{_esc(detail[:90])}</span>
            <span class='tscore'>Score {_esc(score)}</span>
            <span class='ttime mono'>{_esc(e.get("timestamp","")[:19])}</span></div>
          {f"<div class='treason'>{_esc(reasons[:140])}</div>" if reasons else ""}
        </div></div>"""

    link_chart_html = ""
    try:
        graph = result.get("link_chart") or build_link_chart(result)
        svg = render_svg(graph)
        if svg:
            st = graph.get("stats", {})
            shown = min(60, st.get("nodes", 0))
            note = (f"Showing the {shown} highest-risk of {st.get('nodes', 0)} entities. "
                    if st.get("nodes", 0) > shown else "")
            link_chart_html = (
                '<div class="section"><div class="section-header">Link Chart</div><div class="lc-wrap">'
                f'{svg}<div class="lc-legend">'
                '<span><i style="background:#10b981;border-radius:50%"></i>Domain</span>'
                '<span><i style="background:#7e98b8;border-radius:3px"></i>File</span>'
                '<span><i style="background:#7e98b8;transform:rotate(45deg) scale(.8)"></i>Account</span>'
                '<span><i style="background:#f04747"></i>Attack chain / exfiltration link</span>'
                '<span><i style="background:#f5a623"></i>Flagged link</span>'
                '<span>Colour = risk (green low, amber medium, red high)</span></div>'
                f'<div class="lc-note">{note}Open the dashboard Link Chart to explore every entity interactively.</div>'
                '</div></div>')
    except Exception:
        link_chart_html = ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>C4 Forensic Report — {_esc(extracted_at)}</title>
<style>{_REPORT_CSS}</style>
</head>
<body>
<div class="page">
  <div class="header">
    <h1>C4 — Browser Artifact Forensics Report</h1>
    <div class="meta">
      <span class="badge">Chrome</span><span class="badge">Windows</span><span class="badge">C4 v2.0</span><br>
      <strong>Profile:</strong> {_esc(profile)}<br>
      <strong>Extracted:</strong> {_esc(extracted_at)} &nbsp;|&nbsp; <strong>Report:</strong> {_esc(now)}
    </div>
  </div>

  <div class="stat-grid">
    <div class="stat-card" style="--sc:#4d8ef8"><div class="stat-label">Total events</div><div class="stat-val">{len(events)}</div></div>
    <div class="stat-card" style="--sc:#f04747"><div class="stat-label">Risk flagged</div><div class="stat-val" style="color:#f04747;">{len(flagged)}</div></div>
    <div class="stat-card" style="--sc:#f04747"><div class="stat-label">High severity</div><div class="stat-val" style="color:#f04747;">{by_sev.get("High",0)}</div></div>
    <div class="stat-card" style="--sc:#f5a623"><div class="stat-label">MITRE findings</div><div class="stat-val" style="color:#d97706;">{len(all_findings)}</div></div>
  </div>

  <div class="section">
    <div class="section-header">Executive Summary</div>
    <div class="pad" style="line-height:1.8;font-size:13px;">
      Analysis of Chrome browser profile from <strong>{_esc(profile)}</strong> identified
      <strong>{len(events)}</strong> total events. The single-artifact rule engine flagged
      <strong style="color:#f04747;">{len(flagged)}</strong> suspicious events.
      Cross-artifact correlation using co-occurrence analysis, orphan detection, and temporal
      anomaly detection produced <strong>{len(all_findings)}</strong> MITRE ATT&amp;CK-mapped findings —
      <strong style="color:#f04747;">{by_sev.get("High",0)}</strong> High,
      <strong style="color:#d97706;">{by_sev.get("Medium",0)}</strong> Medium,
      <strong style="color:#10b981;">{by_sev.get("Low",0)}</strong> Low severity.
    </div>
  </div>

  {f'<div class="section"><div class="section-header">Attack Chains</div><div class="pad">{chain_html}</div></div>' if chain_html else ''}

  {link_chart_html}

  <div class="section">
    <div class="section-header">Artifact Manifest</div>
    <table><thead><tr><th>File</th><th>Size</th><th>SHA-256</th><th>Modified</th><th>WAL</th></tr></thead>
    <tbody>{mrows or "<tr><td colspan='5' class='empty'>No artifacts found</td></tr>"}</tbody></table>
  </div>

  <div class="section">
    <div class="section-header">MITRE ATT&CK Findings — All Algorithms</div>
    <table><thead><tr><th>Severity</th><th>Technique ID</th><th>Technique</th><th>Tactic</th><th>Algorithm</th><th>Description</th></tr></thead>
    <tbody>{frows or "<tr><td colspan='6' class='empty'>No findings</td></tr>"}</tbody></table>
  </div>

  <div class="section">
    <div class="section-header">Flagged Event Timeline (top 50)</div>
    <div class="pad">{f'<div class="rail">{trows}</div>' if trows else "<div class='empty' style='padding:0'>No flagged events</div>"}</div>
  </div>

  <div class="footer">C4 Browser Artifact Forensics Tool — R26-CS-003 — SLIIT Faculty of Computing<br>Generated {_esc(now)}</div>
</div>
</body>
</html>"""


# ─── SIEM Export ────────────────────────────────────────────────────────────
def generate_siem_export(result):
    """
    SIEM-compatible JSON export (Splunk/QRadar/ELK format).
    Each finding becomes a separate SIEM event with standard fields.
    """
    now     = datetime.now().isoformat()
    profile = result.get("profile_path","unknown")
    mitre   = result.get("mitre_result",{})
    events  = result.get("events",[])

    siem_events = []

    # Export all MITRE-mapped findings as SIEM events
    for f in mitre.get("all_findings",[]):
        m = f.get("mitre",{})
        siem_events.append({
            "timestamp":        now,
            "source":           "C4-BrowserForensics",
            "profile_path":     profile,
            "event_type":       "forensic_finding",
            "algorithm":        f.get("algorithm",""),
            "severity":         f.get("severity","Low"),
            "mitre_technique_id":   m.get("technique_id",""),
            "mitre_technique_name": m.get("technique_name",""),
            "mitre_tactic":         m.get("tactic",""),
            "domain":           f.get("domain",""),
            "artifact_types":   f.get("artifact_types",[]),
            "score":            f.get("score",0),
            "description":      f.get("description",""),
        })

    # Export high-risk individual events
    for e in events:
        if e.get("anomaly_score",0) >= 60:
            siem_events.append({
                "timestamp":    e.get("timestamp",""),
                "source":       "C4-BrowserForensics",
                "profile_path": profile,
                "event_type":   "suspicious_event",
                "artifact_type":e.get("artifact_type",""),
                "severity":     "High" if e.get("anomaly_score",0)>=70 else "Medium",
                "score":        e.get("anomaly_score",0),
                "reasons":      e.get("anomaly_reasons",[]),
                "detail":       e.get("detail",{}),
                "rule_flags":   [r.get("rule","") for r in e.get("rule_flags",[])],
            })

    return {
        "export_type":    "C4_SIEM_Export",
        "export_version": "2.0",
        "generated_at":   now,
        "profile_path":   profile,
        "total_events":   len(siem_events),
        "events":         siem_events
    }


# ─── Save all outputs ────────────────────────────────────────────────────────
def save_all_outputs(result, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # 1. JSON report
    json_path = os.path.join(output_dir, f"c4_report_{ts}.json")
    with open(json_path,"w",encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)

    # 2. HTML report
    html_path = os.path.join(output_dir, f"c4_report_{ts}.html")
    with open(html_path,"w",encoding="utf-8") as f:
        f.write(generate_html_report(result))

    # 3. SIEM export
    siem_path = os.path.join(output_dir, f"c4_siem_{ts}.json")
    siem_data = generate_siem_export(result)
    with open(siem_path,"w",encoding="utf-8") as f:
        json.dump(siem_data, f, indent=2, default=str)

    print(f"[+] Reports saved:\n    JSON: {json_path}\n    HTML: {html_path}\n    SIEM: {siem_path}")
    return {"json":json_path, "html":html_path, "siem":siem_path}
