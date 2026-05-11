"""
Stage 4 — MITRE ATT&CK mapping
Maps detected findings to MITRE ATT&CK framework techniques.
Assigns severity: Low / Medium / High
"""

# MITRE ATT&CK technique mappings for browser forensics
MITRE_MAP = {
    # Co-occurrence patterns
    "download+credential": {
        "technique_id":   "T1555.003",
        "technique_name": "Credentials from Web Browsers",
        "tactic":         "Credential Access",
        "severity":       "High",
        "description":    "Adversary extracted saved browser credentials following malicious download"
    },
    "cookie+credential": {
        "technique_id":   "T1539",
        "technique_name": "Steal Web Session Cookie",
        "tactic":         "Credential Access",
        "severity":       "High",
        "description":    "Session cookies and credentials accessed together — session hijacking pattern"
    },
    "history+cookie+credential": {
        "technique_id":   "T1185",
        "technique_name": "Browser Session Hijacking",
        "tactic":         "Collection",
        "severity":       "High",
        "description":    "Full browser session hijacking — history, cookies, and credentials all compromised"
    },
    "extension+credential": {
        "technique_id":   "T1176",
        "technique_name": "Browser Extensions",
        "tactic":         "Persistence",
        "severity":       "High",
        "description":    "Malicious browser extension with access to credentials"
    },
    "download+cookie": {
        "technique_id":   "T1204.002",
        "technique_name": "Malicious File",
        "tactic":         "Execution",
        "severity":       "Medium",
        "description":    "Malicious file downloaded followed by session cookie access"
    },

    # Orphan patterns
    "orphan_cookie": {
        "technique_id":   "T1550.004",
        "technique_name": "Web Session Cookie",
        "tactic":         "Lateral Movement",
        "severity":       "Medium",
        "description":    "Cookie injected without corresponding browser visit — possible token injection"
    },
    "orphan_credential": {
        "technique_id":   "T1555.003",
        "technique_name": "Credentials from Web Browsers",
        "tactic":         "Credential Access",
        "severity":       "High",
        "description":    "Credential record exists for domain with no browsing history — malware injection"
    },
    "orphan_download": {
        "technique_id":   "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic":         "Command and Control",
        "severity":       "High",
        "description":    "File downloaded from domain with no history — silent malware delivery"
    },

    # Temporal patterns
    "temporal_credential": {
        "technique_id":   "T1555.003",
        "technique_name": "Credentials from Web Browsers",
        "tactic":         "Credential Access",
        "severity":       "High",
        "description":    "Credentials accessed outside user's normal active hours — possible remote access"
    },
    "temporal_download": {
        "technique_id":   "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic":         "Command and Control",
        "severity":       "Medium",
        "description":    "File downloaded at unusual hour for this user"
    },
    "temporal_cookie": {
        "technique_id":   "T1539",
        "technique_name": "Steal Web Session Cookie",
        "tactic":         "Credential Access",
        "severity":       "Medium",
        "description":    "Session cookie accessed outside personal active hours"
    },

    # Single-artifact rules
    "R01": {
        "technique_id":   "T1566.002",
        "technique_name": "Spearphishing Link",
        "tactic":         "Initial Access",
        "severity":       "Medium",
        "description":    "User visited a known suspicious or phishing-related domain"
    },
    "R02": {
        "technique_id":   "T1204.002",
        "technique_name": "Malicious File",
        "tactic":         "Execution",
        "severity":       "High",
        "description":    "Potentially malicious file type downloaded"
    },
    "R03": {
        "technique_id":   "T1539",
        "technique_name": "Steal Web Session Cookie",
        "tactic":         "Credential Access",
        "severity":       "Low",
        "description":    "Sensitive session cookie identified in browser storage"
    },
    "R04": {
        "technique_id":   "T1555.003",
        "technique_name": "Credentials from Web Browsers",
        "tactic":         "Credential Access",
        "severity":       "Medium",
        "description":    "Saved browser credential record found"
    },
    "R05": {
        "technique_id":   "T1176",
        "technique_name": "Browser Extensions",
        "tactic":         "Persistence",
        "severity":       "Medium",
        "description":    "Browser extension with dangerous permissions detected"
    },
    "R06": {
        "technique_id":   "T1056",
        "technique_name": "Input Capture",
        "tactic":         "Collection",
        "severity":       "High",
        "description":    "Abnormal URL visit frequency — automated or malicious browsing"
    },
}

SEVERITY_ORDER = {"High": 3, "Medium": 2, "Low": 1}

def _severity(score):
    if score >= 70: return "High"
    if score >= 40: return "Medium"
    return "Low"

def map_cooccurrence(finding):
    types = sorted(finding.get("artifact_types", []))
    key   = "+".join(types)
    mitre = MITRE_MAP.get(key, {
        "technique_id":   "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic":         "Discovery",
        "severity":       _severity(finding.get("score", 0)),
        "description":    f"Co-occurrence of {key} artifacts on same domain"
    })
    return {**finding, "mitre": mitre, "severity": mitre["severity"]}

def map_orphan(finding):
    key   = f"orphan_{finding.get('artifact_type','')}"
    mitre = MITRE_MAP.get(key, {
        "technique_id":   "T1055",
        "technique_name": "Process Injection",
        "tactic":         "Defense Evasion",
        "severity":       _severity(finding.get("score", 0)),
        "description":    "Orphan artifact with no parent history"
    })
    return {**finding, "mitre": mitre, "severity": mitre["severity"]}

def map_temporal(finding):
    key   = f"temporal_{finding.get('artifact_type','')}"
    mitre = MITRE_MAP.get(key, {
        "technique_id":   "T1078",
        "technique_name": "Valid Accounts",
        "tactic":         "Persistence",
        "severity":       _severity(finding.get("score", 0)),
        "description":    "Activity at unusual time for this user"
    })
    return {**finding, "mitre": mitre, "severity": mitre["severity"]}

def map_attack_chain(finding):
    types = sorted(finding.get("artifact_types", []))
    key = "+".join(types)
    mitre = MITRE_MAP.get(key, {
        "technique_id":   "T1566.002",
        "technique_name": "Spearphishing Link",
        "tactic":         "Initial Access",
        "severity":       _severity(finding.get("score", 0)),
        "description":    "Ordered browser artifact chain indicates possible staged browser attack"
    })
    return {**finding, "mitre": mitre, "severity": mitre["severity"]}

def map_domain_cluster(finding):
    mitre = {
        "technique_id":   "T1185",
        "technique_name": "Browser Session Hijacking",
        "tactic":         "Collection",
        "severity":       _severity(finding.get("score", 0)),
        "description":    "Concentrated cross-artifact browser risk around one domain"
    }
    return {**finding, "mitre": mitre, "severity": mitre["severity"]}

def map_rule_flags(events):
    """Map single-artifact rule flags to MITRE for each event."""
    for e in events:
        mapped = []
        for flag in e.get("rule_flags", []):
            rule_id = flag.get("rule","")
            mitre   = MITRE_MAP.get(rule_id, {})
            mapped.append({**flag, "mitre": mitre,
                           "severity": mitre.get("severity", _severity(flag.get("score",0)))})
        e["rule_flags"] = mapped
    return events

def run_mitre_mapping(correlation_result, events):
    """Apply MITRE mapping to all correlation findings."""
    mapped_cooc  = [map_cooccurrence(f) for f in correlation_result.get("cooccurrence",[])]
    mapped_orph  = [map_orphan(f)       for f in correlation_result.get("orphans",[])]
    mapped_temp  = [map_temporal(f)     for f in correlation_result.get("temporal",[])]
    mapped_chain = [map_attack_chain(f) for f in correlation_result.get("attack_chains",[])]
    mapped_clust = [map_domain_cluster(f) for f in correlation_result.get("domain_clusters",[])]
    events       = map_rule_flags(events)

    # Count by severity
    all_findings = mapped_cooc + mapped_orph + mapped_temp + mapped_chain + mapped_clust
    by_severity  = {"High":0,"Medium":0,"Low":0}
    for f in all_findings:
        sev = f.get("severity","Low")
        by_severity[sev] = by_severity.get(sev,0) + 1

    return {
        "cooccurrence": mapped_cooc,
        "orphans":      mapped_orph,
        "temporal":     mapped_temp,
        "attack_chains": mapped_chain,
        "domain_clusters": mapped_clust,
        "by_severity":  by_severity,
        "all_findings": sorted(all_findings,
                               key=lambda x: SEVERITY_ORDER.get(x.get("severity","Low"),0),
                               reverse=True),
        "baseline":     correlation_result.get("baseline",{}),
        "summary":      correlation_result.get("summary",{})
    }
