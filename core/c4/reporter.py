"""
Stage 5 — Generate outputs
  1. Timeline JSON
  2. HTML attack report
  3. SIEM export (JSON — compatible with Splunk/QRadar/ELK)
"""
import json, os
from datetime import datetime

TYPE_COLORS = {
    "history":    ("#E6F1FB","#0C447C"),
    "cookie":     ("#FAEEDA","#633806"),
    "credential": ("#FCEBEB","#791F1F"),
    "download":   ("#EAF3DE","#27500A"),
    "extension":  ("#EEEDFE","#3C3489"),
}
SEV_COLORS = {"High":("#FCEBEB","#791F1F","#A32D2D"),
              "Medium":("#FAEEDA","#633806","#854F0B"),
              "Low":("#EAF3DE","#27500A","#0F6E56")}

# ─── HTML Report ────────────────────────────────────────────────────────────
def generate_html_report(result):
    now           = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    profile       = result.get("profile_path","Unknown")
    extracted_at  = result.get("extracted_at","")[:19]
    events        = result.get("events",[])
    mitre         = result.get("mitre_result",{})
    manifest      = result.get("artifact_manifest",{})
    by_sev        = mitre.get("by_severity",{})
    all_findings  = mitre.get("all_findings",[])
    flagged       = [e for e in events if e.get("risk_flag")]

    # Manifest rows
    mrows = ""
    for name, info in manifest.items():
        sha = (info.get("sha256") or "—")[:32]+"..."
        mrows += f"<tr><td>{name}</td><td>{round(info.get('size_bytes',0)/1024,1)} KB</td><td style='font-family:monospace;font-size:11px;'>{sha}</td><td>{(info.get('mtime',''))[:19]}</td><td>{'Yes' if info.get('wal_exists') else 'No'}</td></tr>"

    # Findings rows
    frows = ""
    for f in all_findings[:30]:
        sev = f.get("severity","Low")
        bg,fg,bc = SEV_COLORS.get(sev,("#F1EFE8","#5f5e5a","#888780"))
        m = f.get("mitre",{})
        algo = f.get("algorithm","").replace("_"," ").title()
        desc = f.get("description","")
        frows += f"""<tr>
          <td><span style='background:{bg};color:{fg};font-size:11px;padding:2px 8px;border-radius:20px;font-weight:500;'>{sev}</span></td>
          <td style='font-weight:500;'>{m.get("technique_id","—")}</td>
          <td>{m.get("technique_name","—")}</td>
          <td style='color:#5f5e5a;'>{m.get("tactic","—")}</td>
          <td style='font-size:12px;'>{algo}</td>
          <td style='font-size:12px;'>{desc[:80]}</td>
        </tr>"""

    # Flagged timeline rows
    trows = ""
    for e in sorted(flagged, key=lambda x:x["timestamp"], reverse=True)[:50]:
        atype = e.get("artifact_type","")
        bg,fg = TYPE_COLORS.get(atype,("#F1EFE8","#5f5e5a"))
        detail = (e.get("detail",{}).get("url") or e.get("detail",{}).get("filename") or
                  e.get("detail",{}).get("host") or e.get("detail",{}).get("origin") or "—")
        reasons = "; ".join((e.get("anomaly_reasons") or [])[:2])
        score   = e.get("anomaly_score",0)
        trows += f"""<tr>
          <td style='font-family:monospace;font-size:11px;white-space:nowrap;'>{e.get("timestamp","")[:19]}</td>
          <td><span style='background:{bg};color:{fg};font-size:10px;padding:2px 7px;border-radius:20px;font-weight:500;'>{atype}</span></td>
          <td style='font-size:12px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;' title='{detail}'>{detail[:70]}</td>
          <td style='font-size:12px;color:#854F0B;'>{score}</td>
          <td style='font-size:11px;color:#5f5e5a;'>{reasons[:60]}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>C4 Forensic Report — {extracted_at}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f5f4f0;color:#1a1a18;font-size:13px;}}
.page{{max-width:1100px;margin:0 auto;padding:32px 24px;}}
.header{{background:#1a1a18;color:#f5f4f0;border-radius:12px;padding:28px 32px;margin-bottom:24px;}}
.header h1{{font-size:20px;font-weight:500;margin-bottom:6px;}}
.header .meta{{font-size:12px;color:#888780;line-height:1.8;}}
.badge{{display:inline-block;font-size:11px;padding:2px 10px;border-radius:20px;margin-right:6px;background:#333;color:#ccc;}}
.stat-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px;}}
.stat-card{{background:#fff;border:0.5px solid #e0ded8;border-radius:12px;padding:16px;}}
.stat-label{{font-size:11px;color:#888780;margin-bottom:4px;}}
.stat-val{{font-size:26px;font-weight:500;}}
.section{{background:#fff;border:0.5px solid #e0ded8;border-radius:12px;margin-bottom:20px;overflow:hidden;}}
.section-header{{padding:14px 20px;border-bottom:0.5px solid #e0ded8;font-size:14px;font-weight:500;}}
table{{width:100%;border-collapse:collapse;}}
th{{padding:9px 16px;text-align:left;font-size:11px;font-weight:500;color:#888780;text-transform:uppercase;letter-spacing:.04em;border-bottom:0.5px solid #e0ded8;background:#fafaf8;}}
td{{padding:9px 16px;border-bottom:0.5px solid #f0eee8;vertical-align:middle;}}
tr:last-child td{{border-bottom:none;}}
.footer{{text-align:center;font-size:11px;color:#888780;margin-top:32px;padding-bottom:24px;}}
</style>
</head>
<body>
<div class="page">
  <div class="header">
    <h1>C4 — Browser Artifact Forensics Report</h1>
    <div class="meta">
      <span class="badge">Chrome</span><span class="badge">Windows</span><span class="badge">C4 v2.0</span><br>
      <strong>Profile:</strong> {profile}<br>
      <strong>Extracted:</strong> {extracted_at} &nbsp;|&nbsp; <strong>Report:</strong> {now}
    </div>
  </div>

  <div class="stat-grid">
    <div class="stat-card"><div class="stat-label">Total events</div><div class="stat-val">{len(events)}</div></div>
    <div class="stat-card"><div class="stat-label">Risk flagged</div><div class="stat-val" style="color:#A32D2D;">{len(flagged)}</div></div>
    <div class="stat-card"><div class="stat-label">High severity</div><div class="stat-val" style="color:#A32D2D;">{by_sev.get("High",0)}</div></div>
    <div class="stat-card"><div class="stat-label">MITRE findings</div><div class="stat-val" style="color:#854F0B;">{len(all_findings)}</div></div>
  </div>

  <div class="section">
    <div class="section-header">Executive Summary</div>
    <div style="padding:16px 20px;line-height:1.8;font-size:13px;">
      Analysis of Chrome browser profile from <strong>{profile}</strong> identified
      <strong>{len(events)}</strong> total events. The single-artifact rule engine flagged
      <strong style="color:#A32D2D;">{len(flagged)}</strong> suspicious events.
      Cross-artifact correlation using co-occurrence analysis, orphan detection, and temporal
      anomaly detection produced <strong>{len(all_findings)}</strong> MITRE ATT&CK-mapped findings —
      <strong style="color:#A32D2D;">{by_sev.get("High",0)}</strong> High,
      <strong style="color:#854F0B;">{by_sev.get("Medium",0)}</strong> Medium,
      <strong style="color:#27500A;">{by_sev.get("Low",0)}</strong> Low severity.
    </div>
  </div>

  <div class="section">
    <div class="section-header">Artifact Manifest</div>
    <table><thead><tr><th>File</th><th>Size</th><th>SHA-256</th><th>Modified</th><th>WAL</th></tr></thead>
    <tbody>{mrows or "<tr><td colspan='5' style='padding:16px;color:#888;'>No artifacts found</td></tr>"}</tbody></table>
  </div>

  <div class="section">
    <div class="section-header">MITRE ATT&CK Findings — All Algorithms</div>
    <table><thead><tr><th>Severity</th><th>Technique ID</th><th>Technique</th><th>Tactic</th><th>Algorithm</th><th>Description</th></tr></thead>
    <tbody>{frows or "<tr><td colspan='6' style='padding:16px;color:#888;'>No findings</td></tr>"}</tbody></table>
  </div>

  <div class="section">
    <div class="section-header">Flagged Event Timeline (top 50)</div>
    <table><thead><tr><th>Timestamp</th><th>Type</th><th>Detail</th><th>Score</th><th>Reasons</th></tr></thead>
    <tbody>{trows or "<tr><td colspan='5' style='padding:16px;color:#888;'>No flagged events</td></tr>"}</tbody></table>
  </div>

  <div class="footer">C4 Browser Artifact Forensics Tool — R26-CS-003 — SLIIT Faculty of Computing<br>Generated {now}</div>
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
