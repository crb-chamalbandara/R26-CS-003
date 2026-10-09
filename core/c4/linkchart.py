"""
C4 - Link chart builder
=======================
Turns a finished C4 result (events + correlation + MITRE mapping) into an
entity/relationship graph an analyst can read at a glance:

  nodes   domain | file | account
  links   navigation | download | exfil | credential | chain

The graph is built once, on the server, and attached to the result as
``result["link_chart"]`` so the dashboard, the JSON export and the HTML report
all draw the same picture. Nothing here reads a password or a cookie value:
node/event summaries only carry domains, file names, user names and titles.

Output is deterministic (sorted ids, stable tie-breaks) so a re-scan of the same
profile does not reshuffle the chart.
"""
import hashlib
import math
from collections import defaultdict
from html import escape

from .correlation import WINDOW_SECONDS, _domain, _event_domain, _ts   # noqa: F401  (WINDOW_SECONDS kept for callers)

MAX_DOMAINS   = 100      # domains kept before the long tail is folded
MAX_FILES     = 40
MAX_ACCOUNTS  = 30
MAX_EDGES     = 250
MAX_NODE_EVENTS = 20
SESSION_GAP_S = 30 * 60  # visits further apart than this are not "one navigation flow"
OTHER_ID      = "d:__other__"


# ── helpers ───────────────────────────────────────────────────────────────────
def _did(domain):   return f"d:{domain}"
def _fid(name, src): return f"f:{name}|{src}"
def _aid(user):     return f"a:{user}"


def _summary(e):
    """One safe line describing an event (never a password or cookie value)."""
    d = e.get("detail") or {}
    t = e.get("artifact_type", "")
    if t == "history":
        text = d.get("title") or d.get("url") or ""
    elif t == "download":
        text = d.get("filename") or d.get("source_url") or ""
    elif t == "credential":
        text = f"{d.get('username', '')} @ {d.get('origin', '')}".strip(" @")
    elif t == "cookie":
        text = f"{d.get('name', '')} @ {d.get('host', '')}".strip(" @")
    elif t == "extension":
        text = d.get("name") or d.get("id") or ""
    elif t == "session":
        text = d.get("url") or d.get("host") or ""
    elif t == "localstorage":
        text = d.get("origin") or d.get("host") or ""
    else:
        text = ""
    return {"timestamp": e.get("timestamp", ""), "type": t, "text": str(text)[:140],
            "score": int(e.get("anomaly_score") or 0), "flagged": bool(e.get("risk_flag"))}


def _event_node_id(e, file_ids):
    """Which graph node an event belongs to (None if it has no entity)."""
    t, d = e.get("artifact_type", ""), e.get("detail") or {}
    if t == "download":
        src = _domain(d.get("source_url", ""))
        return file_ids.get((d.get("filename", ""), src))
    if t == "credential":
        user = (d.get("username") or "").strip().lower()
        return _aid(user) if user else None
    dom = _event_domain(e)
    return _did(dom) if dom else None


# ── builder ───────────────────────────────────────────────────────────────────
def build_link_chart(result):
    events = result.get("events") or []
    corr   = result.get("correlation") or {}
    mitre  = (result.get("mitre_result") or {}).get("all_findings") or []

    nodes, edges = {}, {}          # id -> node, (src,tgt,kind) -> edge
    node_events = defaultdict(list)

    def node(nid, ntype, label):
        n = nodes.get(nid)
        if n is None:
            n = nodes[nid] = {"id": nid, "type": ntype, "label": label, "risk": 0,
                              "event_count": 0, "flagged_count": 0, "artifact_types": set(),
                              "techniques": set(), "chains": [], "_score_sum": 0}
        return n

    def edge(src, tgt, kind, label="", flagged=False, ts=None):
        k = (src, tgt, kind)
        e = edges.get(k)
        if e is None:
            e = edges[k] = {"source": src, "target": tgt, "kind": kind, "weight": 0, "label": label,
                            "flagged": False, "techniques": set(), "chain": False,
                            "first": ts or "", "last": ts or ""}
        e["weight"] += 1
        e["flagged"] = e["flagged"] or flagged
        if ts:
            e["first"] = min(e["first"], ts) if e["first"] else ts
            e["last"]  = max(e["last"], ts)
        return e

    # 1. entities from events ----------------------------------------------------
    file_ids = {}
    for ev in events:
        t, d = ev.get("artifact_type", ""), ev.get("detail") or {}
        flagged, score = bool(ev.get("risk_flag")), int(ev.get("anomaly_score") or 0)
        ts = ev.get("timestamp", "")

        dom = _event_domain(ev)
        if dom:
            n = node(_did(dom), "domain", dom)
            n["event_count"] += 1; n["flagged_count"] += flagged; n["_score_sum"] += score
            n["artifact_types"].add(t)
            node_events[n["id"]].append(ev)

        if t == "download" and d.get("filename"):
            src = _domain(d.get("source_url", ""))
            fid = _fid(d["filename"], src)
            file_ids[(d["filename"], src)] = fid
            n = node(fid, "file", d["filename"])
            n["event_count"] += 1; n["flagged_count"] += flagged; n["_score_sum"] += score
            n["artifact_types"].add("download"); n["risk"] = max(n["risk"], score)
            if d.get("danger_type"):
                n["risk"] = max(n["risk"], 70)
            node_events[fid].append(ev)
            if src:
                edge(_did(src), fid, "download", "downloaded", flagged, ts)

        if t == "credential":
            user = (d.get("username") or "").strip().lower()
            origin = _domain(d.get("origin", ""))
            if user:
                aid = _aid(user)
                n = node(aid, "account", user)
                n["event_count"] += 1; n["flagged_count"] += flagged; n["_score_sum"] += score
                n["artifact_types"].add("credential"); n["risk"] = max(n["risk"], score)
                node_events[aid].append(ev)
                if origin:
                    edge(aid, _did(origin), "credential", "saved login", flagged, ts)

    # 2. navigation flow ---------------------------------------------------------
    hist = sorted((e for e in events if e.get("artifact_type") == "history"
                   and _ts(e.get("timestamp")) and _event_domain(e)),
                  key=lambda e: e["timestamp"])
    for a, b in zip(hist, hist[1:]):
        da, db = _event_domain(a), _event_domain(b)
        if da == db:
            continue
        gap = (_ts(b["timestamp"]) - _ts(a["timestamp"])).total_seconds()
        if 0 <= gap <= SESSION_GAP_S:
            edge(_did(da), _did(db), "navigation", "visited next",
                 bool(a.get("risk_flag") or b.get("risk_flag")), b["timestamp"])

    # 3. findings: exfil, reuse, chains, clusters, MITRE ---------------------------
    for f in corr.get("download_exfil") or []:
        src, dst, fname = f.get("source_domain", ""), f.get("domain", ""), f.get("filename", "")
        fid = file_ids.get((fname, src)) or next((v for (nm, _s), v in file_ids.items() if nm == fname), None)
        if fid and dst:
            node(_did(dst), "domain", dst)
            e = edge(fid, _did(dst), "exfil", "then visited", True, f.get("window_end"))
            e["weight"] = max(e["weight"], 1)
            nodes[fid]["risk"] = max(nodes[fid]["risk"], int(f.get("score") or 0))
            nodes[_did(dst)]["risk"] = max(nodes[_did(dst)]["risk"], int(f.get("score") or 0))

    for f in corr.get("credential_reuse") or []:
        aid = _aid((f.get("username") or "").lower())
        if aid in nodes:
            nodes[aid]["risk"] = max(nodes[aid]["risk"], int(f.get("score") or 0))
            for dom in f.get("domains") or []:
                k = (aid, _did(dom), "credential")
                if k in edges:
                    edges[k]["flagged"] = True
                    edges[k]["label"] = "reused login"

    for f in corr.get("domain_clusters") or []:
        nid = _did(f.get("domain", ""))
        if nid in nodes:
            nodes[nid]["risk"] = max(nodes[nid]["risk"], int(f.get("score") or 0))
    for f in (corr.get("cooccurrence") or []) + (corr.get("attack_chains") or []):
        nid = _did(f.get("domain", ""))
        if nid in nodes:
            nodes[nid]["risk"] = max(nodes[nid]["risk"], int(f.get("score") or 0))

    chains = []
    for i, f in enumerate(corr.get("attack_chains") or []):
        steps = []
        for ev in f.get("events") or []:
            nid = _event_node_id(ev, file_ids)
            if nid and nid in nodes and (not steps or steps[-1] != nid):
                steps.append(nid)
        eids = []
        for a, b in zip(steps, steps[1:]):
            hit = next((edges[k] for k in ((a, b, "download"), (a, b, "exfil"), (a, b, "navigation"),
                                           (a, b, "credential"), (b, a, "credential"), (b, a, "download"))
                        if k in edges), None)
            if hit is None:
                hit = edge(a, b, "chain", "chain step", True)
            hit["chain"] = True
            eids.append(f"{hit['source']}>{hit['target']}>{hit['kind']}")
        for nid in steps:
            nodes[nid]["chains"].append(i)
        chains.append({"id": i, "domain": f.get("domain", ""), "score": int(f.get("score") or 0),
                       "description": f.get("description", ""), "steps": steps, "edges": eids})

    for f in mitre:                                   # MITRE technique ids -> nodes / links
        tid = (f.get("mitre") or {}).get("technique_id")
        if not tid:
            continue
        doms = f.get("domains") or ([f["domain"]] if f.get("domain") else [])
        for dom in doms:
            if _did(dom) in nodes:
                nodes[_did(dom)]["techniques"].add(tid)
        algo = f.get("algorithm")
        if algo == "download_exfil":
            for k, e in edges.items():
                if k[2] == "exfil" and k[1] == _did(f.get("domain", "")):
                    e["techniques"].add(tid)
        elif algo == "credential_reuse":
            aid = _aid((f.get("username") or "").lower())
            if aid in nodes:
                nodes[aid]["techniques"].add(tid)
            for k, e in edges.items():
                if k[2] == "credential" and k[0] == aid:
                    e["techniques"].add(tid)

    # 4. risk, events, finish ------------------------------------------------------
    for nid, n in nodes.items():
        if n["type"] == "domain":
            base = min(100, 12 * n["flagged_count"] + min(40, n["_score_sum"] // 8))
            n["risk"] = max(n["risk"], base)
        n["risk"] = int(min(100, n["risk"]))
        evs = sorted(node_events.get(nid, []),
                     key=lambda e: (-int(e.get("anomaly_score") or 0), e.get("timestamp", "")))
        n["events"] = [_summary(e) for e in evs[:MAX_NODE_EVENTS]]

    total_domains = sum(1 for n in nodes.values() if n["type"] == "domain")
    folded = _fold_long_tail(nodes, edges)

    # 5. edge cap + serialise -------------------------------------------------------
    elist = [e for e in edges.values() if e["source"] in nodes and e["target"] in nodes]
    if len(elist) > MAX_EDGES:
        strong = [e for e in elist if e["kind"] != "navigation" or e["flagged"] or e["chain"]]
        weak = sorted((e for e in elist if e not in strong), key=lambda e: (-e["weight"], e["source"], e["target"]))
        elist = strong + weak[:max(0, MAX_EDGES - len(strong))]
    out_edges = []
    for e in sorted(elist, key=lambda e: (e["source"], e["target"], e["kind"])):
        out_edges.append({**e, "id": f"{e['source']}>{e['target']}>{e['kind']}",
                          "techniques": sorted(e["techniques"])})
    live_ids = {n["id"] for n in nodes.values()}
    out_nodes = []
    for n in sorted(nodes.values(), key=lambda n: n["id"]):
        n = dict(n); n.pop("_score_sum", None)
        n["artifact_types"] = sorted(n["artifact_types"]); n["techniques"] = sorted(n["techniques"])
        out_nodes.append(n)
    for c in chains:                                   # folded nodes cannot be chain steps
        c["steps"] = [s for s in c["steps"] if s in live_ids]

    by_type = defaultdict(int)
    for n in out_nodes:
        by_type[n["type"]] += 1
    return {"nodes": out_nodes, "edges": out_edges, "chains": chains,
            "stats": {"nodes": len(out_nodes), "edges": len(out_edges), "by_type": dict(by_type),
                      "total_domains": total_domains, "folded_domains": folded,
                      "truncated": bool(folded) or len(elist) < len(edges)}}


def _fold_long_tail(nodes, edges):
    """Keep the interesting domains; fold quiet ones past MAX_DOMAINS into one node."""
    doms = [n for n in nodes.values() if n["type"] == "domain"]
    linked = set()
    for (s, t, k) in edges:
        if k != "navigation":
            linked.add(s); linked.add(t)
    must = {n["id"] for n in doms if n["flagged_count"] or n["risk"] >= 40 or n["chains"] or n["id"] in linked}
    rest = sorted((n for n in doms if n["id"] not in must),
                  key=lambda n: (-n["event_count"], n["id"]))
    keep = set(must)
    for n in rest:
        if len(keep) < MAX_DOMAINS:
            keep.add(n["id"])
    drop = [n["id"] for n in doms if n["id"] not in keep]
    if not drop:
        return 0
    other = {"id": OTHER_ID, "type": "domain", "label": f"{len(drop)} other domains", "risk": 0,
             "event_count": sum(nodes[i]["event_count"] for i in drop), "flagged_count": 0,
             "artifact_types": {"history"}, "techniques": set(), "chains": [], "_score_sum": 0,
             "collapsed": True, "events": []}
    dropset = set(drop)
    remap = lambda x: OTHER_ID if x in dropset else x
    moved = {}
    for (s, t, k), e in list(edges.items()):
        s2, t2 = remap(s), remap(t)
        if s2 == t2:
            del edges[(s, t, k)]; continue
        if (s2, t2) != (s, t):
            del edges[(s, t, k)]
            m = moved.get((s2, t2, k))
            if m is None:
                e["source"], e["target"] = s2, t2
                moved[(s2, t2, k)] = e
            else:
                m["weight"] += e["weight"]; m["flagged"] = m["flagged"] or e["flagged"]
    edges.update(moved)
    for i in drop:
        del nodes[i]
    nodes[OTHER_ID] = other
    return len(drop)


# ── static SVG for the HTML report ───────────────────────────────────────────
def _risk_colour(r):
    return "#f04747" if r >= 60 else "#f5a623" if r >= 30 else "#10b981"


def _radius(n):
    return 7 + min(11, math.log2(1 + n["event_count"]) * 2)


def _fr_component(idxs, links, nodes, w, h, iterations=260):
    """Fruchterman-Reingold inside one connected group's own box (deterministic)."""
    m = len(idxs)
    local = {g: i for i, g in enumerate(idxs)}
    pos = []
    for g in idxs:                                      # seeded start on a ring
        hsh = int(hashlib.md5(nodes[g]["id"].encode()).hexdigest()[:8], 16)
        ang = (hsh % 3600) / 3600 * 2 * math.pi
        rad = 0.2 + (hsh >> 12) % 100 / 100 * 0.25
        pos.append([w / 2 + math.cos(ang) * w * rad, h / 2 + math.sin(ang) * h * rad])
    if m == 1:
        return [[w / 2, h / 2]]
    ll = [(local[a], local[b]) for a, b in links if a in local and b in local]
    radii = [_radius(nodes[g]) for g in idxs]
    k = math.sqrt(w * h / m) * 0.85
    t = w / 6
    for _ in range(iterations):
        disp = [[0.0, 0.0] for _ in range(m)]
        for a in range(m):
            for b in range(a + 1, m):
                dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
                d = math.hypot(dx, dy) or 0.01
                f = k * k / d
                gap = radii[a] + radii[b] + 30          # keep nodes and their labels apart
                if d < gap:
                    f += (gap - d) * 14
                disp[a][0] += dx / d * f; disp[a][1] += dy / d * f
                disp[b][0] -= dx / d * f; disp[b][1] -= dy / d * f
                if abs(dy) < 30 and abs(dx) < 120:        # labels are wide: keep same-height nodes apart sideways
                    push = (120 - abs(dx)) * 6
                    sgn = 1.0 if dx >= 0 else -1.0
                    disp[a][0] += sgn * push; disp[b][0] -= sgn * push
        for a, b in ll:
            dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
            d = math.hypot(dx, dy) or 0.01
            f = d * d / k
            disp[a][0] -= dx / d * f; disp[a][1] -= dy / d * f
            disp[b][0] += dx / d * f; disp[b][1] += dy / d * f
        for a in range(m):
            disp[a][0] += (w / 2 - pos[a][0]) * 0.12
            disp[a][1] += (h / 2 - pos[a][1]) * 0.12
            d = math.hypot(*disp[a]) or 0.01
            step = min(d, t)
            pos[a][0] = min(w - 45, max(45, pos[a][0] + disp[a][0] / d * step))
            pos[a][1] = min(h - 35, max(35, pos[a][1] + disp[a][1] / d * step))
        t *= 0.98
    return pos


def layout(graph, max_nodes=60, width=1000, height=560):
    """Deterministic layout for the report's SVG.

    Connected groups are laid out on their own and then packed side by side, so an
    isolated domain never drags the real story (the linked entities) off to a corner.
    """
    nodes = sorted(graph["nodes"], key=lambda n: (-n["risk"], -n["event_count"], n["id"]))[:max_nodes]
    idx = {n["id"]: i for i, n in enumerate(nodes)}
    links = [(idx[e["source"]], idx[e["target"]]) for e in graph["edges"]
             if e["source"] in idx and e["target"] in idx]
    parent = list(range(len(nodes)))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]; x = parent[x]
        return x
    for a, b in links:
        parent[find(a)] = find(b)
    groups = defaultdict(list)
    for i in range(len(nodes)):
        groups[find(i)].append(i)
    comps = sorted(groups.values(), key=lambda g: (-len(g), nodes[g[0]]["id"]))
    big = [g for g in comps if len(g) > 1]
    singles = [g[0] for g in comps if len(g) == 1]

    pos = [None] * len(nodes)
    cx = cy = 0.0
    row_h = 0.0
    placed = []                                         # (x0, y0, w, h) boxes
    for g in big:
        w = max(240.0, 150 * math.sqrt(len(g)))
        h = max(190.0, 105 * math.sqrt(len(g)))
        if cx and cx + w > width - 40:
            cx, cy, row_h = 0.0, cy + row_h + 20, 0.0
        local = _fr_component(g, links, nodes, w, h)
        for gi, p in zip(g, local):
            pos[gi] = [cx + p[0], cy + p[1]]
        placed.append((cx, cy, w, h))
        cx += w + 20
        row_h = max(row_h, h)
    # isolated entities go in a tidy grid underneath
    if singles:
        top = cy + row_h + (30 if big else 0)
        per_row = max(1, int((width - 80) // 170))
        for n_i, gi in enumerate(singles):
            pos[gi] = [60 + (n_i % per_row) * 170, top + 30 + (n_i // per_row) * 85]
    xs, ys = [p[0] for p in pos], [p[1] for p in pos]
    bw, bh = (max(xs) - min(xs)) or 1.0, (max(ys) - min(ys)) or 1.0
    sc = min(1.35, (width - 150) / bw, (height - 90) / bh)
    mx, my = (max(xs) + min(xs)) / 2, (max(ys) + min(ys)) / 2
    for p in pos:
        p[0] = width / 2 + (p[0] - mx) * sc
        p[1] = height / 2 + (p[1] - my) * sc
    return nodes, pos


def render_svg(graph, max_nodes=60, width=1000, height=560):
    """Inline SVG of the top entities. No scripts, no external assets."""
    if not graph or not graph.get("nodes"):
        return ""
    nodes, pos = layout(graph, max_nodes, width, height)
    idx = {n["id"]: i for i, n in enumerate(nodes)}
    out = [f'<svg class="lc-svg" viewBox="0 0 {width} {height}" role="img" '
           f'aria-label="Link chart of domains, files and accounts">',
           '<defs><marker id="lc-arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" '
           'orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="currentColor"/></marker></defs>']
    for e in graph["edges"]:
        if e["source"] not in idx or e["target"] not in idx:
            continue
        ia, ib = idx[e["source"]], idx[e["target"]]
        a, b = pos[ia], pos[ib]
        dx, dy = b[0] - a[0], b[1] - a[1]
        dist = math.hypot(dx, dy) or 1.0
        ra = 7 + min(11, math.log2(1 + nodes[ia]["event_count"]) * 2)
        rb = 7 + min(11, math.log2(1 + nodes[ib]["event_count"]) * 2) + 3
        a = (a[0] + dx / dist * ra, a[1] + dy / dist * ra)          # start at the source's edge
        b = (b[0] - dx / dist * rb, b[1] - dy / dist * rb)          # end just short of the target
        hot = e["chain"] or e["kind"] == "exfil"
        col = "#f04747" if hot else "#f5a623" if e["flagged"] else "#7e98b8"
        op = 0.95 if hot else 0.7 if e["flagged"] else 0.35
        w = 2.4 if hot else min(3, 1 + e["weight"] * 0.25)
        out.append(f'<line x1="{a[0]:.1f}" y1="{a[1]:.1f}" x2="{b[0]:.1f}" y2="{b[1]:.1f}" stroke="{col}" '
                   f'stroke-opacity="{op}" stroke-width="{w:.1f}" style="color:{col}" marker-end="url(#lc-arr)"/>')
    for n, (x, y) in zip(nodes, pos):
        col = _risk_colour(n["risk"])
        r = 7 + min(11, math.log2(1 + n["event_count"]) * 2)
        if n["type"] == "file":
            shape = f'<rect x="{x - r:.1f}" y="{y - r:.1f}" width="{2 * r:.1f}" height="{2 * r:.1f}" rx="4"/>'
        elif n["type"] == "account":
            shape = f'<polygon points="{x:.1f},{y - r * 1.2:.1f} {x + r * 1.2:.1f},{y:.1f} {x:.1f},{y + r * 1.2:.1f} {x - r * 1.2:.1f},{y:.1f}"/>'
        else:
            shape = f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r:.1f}"/>'
        label = escape(n["label"] if len(n["label"]) <= 26 else n["label"][:25] + "…")
        out.append(f'<g class="lc-n" fill="{col}" fill-opacity="0.85" stroke="{col}" stroke-width="2"><title>'
                   f'{escape(n["type"])}: {escape(n["label"])} (risk {n["risk"]})</title>{shape}</g>')
        if n["risk"] >= 30 or n["type"] != "domain" or len(nodes) <= 25:
            out.append(f'<text class="lc-l" x="{x:.1f}" y="{y + r + 12:.1f}" text-anchor="middle">{label}</text>')
    out.append("</svg>")
    return "".join(out)
