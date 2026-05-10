"""
Stage 3 — Cross-artifact correlation engine
2-minute sliding window with 3 algorithms:
  A. Co-occurrence analysis
  B. Orphan detection
  C. Temporal anomaly detection
"""
from datetime import datetime, timedelta
from collections import defaultdict
from urllib.parse import urlparse

WINDOW_SECONDS = 120

def _ts(s):
    try: return datetime.fromisoformat(s)
    except: return None

def _domain(url):
    try: return urlparse(url).netloc.lower().replace("www.","")
    except: return ""

def _event_domain(event):
    """Extract the best domain value for any supported browser artifact event."""
    atype = event.get("artifact_type", "")
    detail = event.get("detail", {})
    if atype == "history":
        return _domain(detail.get("url", ""))
    if atype == "cookie":
        return detail.get("host", "").lstrip(".").lower()
    if atype == "credential":
        return _domain(detail.get("origin", ""))
    if atype == "download":
        return _domain(detail.get("source_url", ""))
    return ""

# ═══════════════════════════════════════════════════════════════════════════
# A. CO-OCCURRENCE ANALYSIS
# How many artifact types relate to the SAME domain within the time window?
# More types = higher risk score
# ═══════════════════════════════════════════════════════════════════════════
COOCCURRENCE_SCORES = {1:0, 2:40, 3:70, 4:85, 5:100}

def run_cooccurrence(events):
    """
    For each 2-min window, group events by domain.
    Count how many artifact types touch the same domain.
    """
    results = []
    candidates = [e for e in events if e.get("risk_flag")]
    candidates.sort(key=lambda x: x["timestamp"])

    seen = set()
    for anchor in candidates:
        t0 = _ts(anchor["timestamp"])
        if not t0: continue
        t1 = t0 + timedelta(seconds=WINDOW_SECONDS)

        cluster = [e for e in candidates
                   if _ts(e["timestamp"]) and t0 <= _ts(e["timestamp"]) <= t1]

        # Group by domain
        domain_map = defaultdict(lambda: defaultdict(list))
        for e in cluster:
            dom = ""
            if e["artifact_type"] == "history":
                dom = _domain(e["detail"].get("url",""))
            elif e["artifact_type"] == "cookie":
                dom = e["detail"].get("host","").lstrip(".").lower()
            elif e["artifact_type"] == "credential":
                dom = _domain(e["detail"].get("origin",""))
            elif e["artifact_type"] == "download":
                dom = _domain(e["detail"].get("source_url",""))
            if dom:
                domain_map[dom][e["artifact_type"]].append(e)

        for dom, type_map in domain_map.items():
            if len(type_map) < 2: continue
            key = f"{dom}_{anchor['timestamp']}"
            if key in seen: continue
            seen.add(key)
            score = COOCCURRENCE_SCORES.get(len(type_map),
                                            min(100, len(type_map)*20))
            results.append({
                "algorithm":    "co_occurrence",
                "domain":       dom,
                "artifact_types": sorted(list(type_map.keys())),
                "type_count":   len(type_map),
                "score":        score,
                "window_start": anchor["timestamp"],
                "description":  f"{len(type_map)} artifact types linked to '{dom}' within 2 minutes",
                "events":       [e for elist in type_map.values() for e in elist]
            })

    results.sort(key=lambda x: x["score"], reverse=True)
    return results


# ═══════════════════════════════════════════════════════════════════════════
# B. ORPHAN DETECTION
# An event that has NO supporting history entry for its domain.
# Normal: visit site → site sets cookie.
# Orphan: cookie exists for domain NEVER visited → suspicious injection.
# ═══════════════════════════════════════════════════════════════════════════
ORPHAN_SCORES = {"cookie":40, "credential":60, "download":70, "extension":50}

def run_orphan_detection(events):
    """
    Build known_domains from history.
    Flag cookies/credentials/downloads whose domain has no history entry.
    """
    # Build set of all domains from history
    known_domains = set()
    for e in events:
        if e["artifact_type"] == "history":
            dom = _domain(e["detail"].get("url",""))
            if dom: known_domains.add(dom)

    orphans = []
    for e in events:
        atype = e["artifact_type"]
        if atype not in ORPHAN_SCORES: continue

        # Extract domain for this event
        if atype == "cookie":
            dom = e["detail"].get("host","").lstrip(".").lower()
        elif atype == "credential":
            dom = _domain(e["detail"].get("origin",""))
        elif atype == "download":
            dom = _domain(e["detail"].get("source_url",""))
        elif atype == "extension":
            dom = ""
        else:
            continue

        if not dom: continue

        # Check if domain has a parent history entry
        has_parent = any(dom in kd or kd in dom for kd in known_domains)
        if not has_parent:
            score = ORPHAN_SCORES.get(atype, 40)
            orphans.append({
                "algorithm":   "orphan_detection",
                "artifact_type": atype,
                "domain":      dom,
                "score":       score,
                "description": f"{atype} from '{dom}' has no parent history entry — possible injection",
                "event":       e
            })
            # Also update the event itself
            e["anomaly_score"] += score
            e["anomaly_reasons"].append(f"ORPHAN: {atype} from '{dom}' has no matching history visit")
            e["risk_flag"] = True

    return orphans


# ═══════════════════════════════════════════════════════════════════════════
# C. TEMPORAL ANOMALY DETECTION
# Learn the user's PERSONAL hourly activity baseline from their history.
# Flag events that happen at hours when this user is NEVER normally active.
# Personalised per user — not a generic "2am is suspicious" threshold.
# ═══════════════════════════════════════════════════════════════════════════
TEMPORAL_SCORES = {"credential":70, "download":50, "cookie":40, "history":30, "extension":35}

def run_temporal_anomaly(events):
    """
    Build personal hourly baseline from history visits.
    Flag risk events at hours with near-zero personal activity.
    """
    # Build hourly baseline from ALL history events
    hour_counts = defaultdict(int)
    total = 0
    for e in events:
        if e["artifact_type"] == "history":
            t = _ts(e["timestamp"])
            if t:
                hour_counts[t.hour] += 1
                total += 1

    if total < 10:
        return [], hour_counts  # Not enough data for baseline

    # Threshold: an hour is "inactive" if it has <2% of total activity
    threshold = total * 0.02
    inactive_hours = {h for h in range(24) if hour_counts.get(h, 0) <= threshold}

    anomalies = []
    for e in events:
        atype = e["artifact_type"]
        if atype == "history": continue  # history itself builds the baseline
        t = _ts(e["timestamp"])
        if not t: continue
        if t.hour in inactive_hours:
            score = TEMPORAL_SCORES.get(atype, 30)
            anomalies.append({
                "algorithm":    "temporal_anomaly",
                "artifact_type": atype,
                "hour":         t.hour,
                "normal_count": hour_counts.get(t.hour, 0),
                "score":        score,
                "description":  f"{atype} at {t.hour:02d}:00 — user has only "
                                f"{hour_counts.get(t.hour,0)} visits at this hour "
                                f"(personal inactive period)",
                "event":        e
            })
            e["anomaly_score"] += score
            e["anomaly_reasons"].append(
                f"TEMPORAL: activity at {t.hour:02d}:00 deviates from personal baseline")
            e["risk_flag"] = True

    return anomalies, hour_counts


# ═══════════════════════════════════════════════════════════════════════════
# Main correlation runner
# ═══════════════════════════════════════════════════════════════════════════
CHAIN_PATTERNS = [
    (("history", "download", "credential"), 90, "Browse, download, and credential access sequence"),
    (("history", "credential", "cookie"), 85, "Browse, credential, and session cookie sequence"),
    (("history", "download", "cookie"), 80, "Browse, download, and session cookie sequence"),
    (("download", "credential"), 75, "Download followed by credential access"),
    (("credential", "cookie"), 70, "Credential and session cookie activity sequence"),
]

def run_attack_chain_detection(events):
    """
    Find ordered artifact-type chains for the same domain inside the time window.
    This is stricter than co-occurrence because the event order must match.
    """
    domain_events = defaultdict(list)
    for event in events:
        domain = _event_domain(event)
        ts = _ts(event.get("timestamp", ""))
        if domain and ts:
            domain_events[domain].append((ts, event))

    chains = []
    seen = set()
    for domain, items in domain_events.items():
        items.sort(key=lambda item: item[0])
        for i, (start_ts, _start_event) in enumerate(items):
            window_end = start_ts + timedelta(seconds=WINDOW_SECONDS)
            window = [(ts, event) for ts, event in items[i:] if ts <= window_end]

            for pattern, base_score, description in CHAIN_PATTERNS:
                cursor = 0
                matched = []
                for _ts_value, event in window:
                    if event.get("artifact_type") == pattern[cursor]:
                        matched.append(event)
                        cursor += 1
                        if cursor == len(pattern):
                            break
                if cursor != len(pattern):
                    continue

                key = (domain, pattern, matched[0].get("timestamp"), matched[-1].get("timestamp"))
                if key in seen:
                    continue
                seen.add(key)

                risk_bonus = min(10, sum(1 for event in matched if event.get("risk_flag")) * 3)
                score = min(100, base_score + risk_bonus)
                chains.append({
                    "algorithm": "attack_chain",
                    "domain": domain,
                    "artifact_types": list(pattern),
                    "score": score,
                    "window_start": matched[0].get("timestamp"),
                    "window_end": matched[-1].get("timestamp"),
                    "description": f"{description} for '{domain}' within 2 minutes",
                    "events": matched,
                })

                for event in matched:
                    event["risk_flag"] = True
                    event["anomaly_score"] += score // len(pattern)
                    event["anomaly_reasons"].append(f"CHAIN: {' -> '.join(pattern)} on {domain}")

    chains.sort(key=lambda finding: finding["score"], reverse=True)
    return chains


def run_domain_risk_clustering(events):
    """Score domains by artifact diversity, flagged events, and accumulated rule scores."""
    clusters = defaultdict(list)
    for event in events:
        domain = _event_domain(event)
        if domain:
            clusters[domain].append(event)

    findings = []
    for domain, domain_events in clusters.items():
        artifact_types = sorted({event.get("artifact_type", "") for event in domain_events})
        flagged = [event for event in domain_events if event.get("risk_flag")]
        rule_score = sum(event.get("anomaly_score", 0) for event in domain_events)
        diversity_score = max(0, len(artifact_types) - 1) * 18
        flagged_score = min(35, len(flagged) * 7)
        density_score = min(20, len(domain_events) // 3)
        score = min(100, diversity_score + flagged_score + density_score + min(25, rule_score // 20))

        if score < 45 or len(artifact_types) < 2:
            continue

        findings.append({
            "algorithm": "domain_risk_cluster",
            "domain": domain,
            "artifact_types": artifact_types,
            "event_count": len(domain_events),
            "flagged_count": len(flagged),
            "score": score,
            "description": (
                f"Domain '{domain}' has {len(domain_events)} events across "
                f"{len(artifact_types)} artifact types with {len(flagged)} flagged events"
            ),
            "events": domain_events,
        })

        if flagged:
            for event in flagged:
                event["anomaly_reasons"].append(f"CLUSTER: {domain} has concentrated cross-artifact risk")

    findings.sort(key=lambda finding: finding["score"], reverse=True)
    return findings


def run_correlation(events):
    cooccurrence       = run_cooccurrence(events)
    orphans            = run_orphan_detection(events)
    temporal, baseline = run_temporal_anomaly(events)
    attack_chains      = run_attack_chain_detection(events)
    domain_clusters    = run_domain_risk_clustering(events)

    return {
        "cooccurrence": cooccurrence,
        "orphans":      orphans,
        "temporal":     temporal,
        "attack_chains": attack_chains,
        "domain_clusters": domain_clusters,
        "baseline":     dict(baseline),
        "summary": {
            "cooccurrence_count": len(cooccurrence),
            "orphan_count":       len(orphans),
            "temporal_count":     len(temporal),
            "attack_chain_count": len(attack_chains),
            "domain_cluster_count": len(domain_clusters),
            "total_findings": (
                len(cooccurrence) + len(orphans) + len(temporal) +
                len(attack_chains) + len(domain_clusters)
            ),
        }
    }
