# Component 4 - Browser Artifact Forensic Correlation Engine

> **Status:** Implemented and integrated with the WebSentinel FastAPI backend.

## Research Question

Can automated cross-artifact correlation of browser forensic data reliably
reconstruct suspicious activity timelines and map findings to MITRE ATT&CK
techniques?

## Architecture Overview

```text
Browser profile directory
      |
      |-- History SQLite database
      |-- Cookies SQLite database
      |-- Login Data SQLite database
      |-- Downloads table
      |-- Extensions manifests
      |
      v
Artifact Extractor
      |
      v
Single-Artifact Rule Engine
      |
      v
Cross-Artifact Correlation
      |-- Co-occurrence analysis
      |-- Orphan artifact detection
      |-- Temporal anomaly detection
      |-- Ordered attack-chain detection
      |-- Domain risk clustering
      |
      v
MITRE ATT&CK Mapper
      |
      v
JSON report, HTML forensic report, SIEM export
```

## Runtime Files

| File             | Role                                                                                                                                               |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `extractor.py`   | Finds browser profiles, copies locked SQLite artifacts safely, extracts history, cookies, downloads, credentials, extensions, and artifact hashes. |
| `rules.py`       | Applies single-artifact rules for suspicious domains, dangerous downloads, sensitive cookies, credentials, risky extensions, and URL bursts.       |
| `correlation.py` | Runs the cross-artifact correlation algorithms: co-occurrence, orphan detection, temporal anomaly detection, ordered attack-chain detection, and domain risk clustering. |
| `mitre.py`       | Maps rule and correlation findings to MITRE ATT&CK techniques with Low, Medium, and High severity.                                                 |
| `reporter.py`    | Generates the detailed HTML forensic report, JSON report, and SIEM-compatible export.                                                              |
| `service.py`     | WebSentinel adapter that runs the full pipeline and stores the latest result for FastAPI endpoints.                                                |
| `__init__.py`    | Package exports for the C4 service API.                                                                                                            |

## Browser Profile Resolution

C4 scans the first available profile in this order:

1. `WEBSENTINEL_BROWSER_PROFILE` environment variable
2. WebSentinel Playwright profile: `~/.websentinel/profile`
3. Local Chrome default profile
4. Local Chrome `Profile 1`
5. Local Chromium default profile
6. Local Microsoft Edge default profile

If the browser databases are locked, stop the WebSentinel Playwright session or
close Chrome/Edge and run the scan again.

## FastAPI Integration

`core/main.py` exposes these C4 endpoints:

| Endpoint                    | Purpose                                                                             |
| --------------------------- | ----------------------------------------------------------------------------------- |
| `GET /forensic/debug`       | Shows the detected default browser profile and whether it exists.                   |
| `POST /forensic/extract`    | Runs the full C4 pipeline. Body: `{ "profile_path": "...", "save_outputs": true }`. |
| `GET /forensic/report`      | Returns the latest full C4 result and compact summary.                              |
| `GET /forensic/summary`     | Returns only the compact latest summary.                                            |
| `GET /forensic/timeline`    | Returns extracted events, optionally filtered by artifact type and flagged state.   |
| `GET /forensic/mitre`       | Returns all MITRE-mapped findings from the latest run.                              |
| `GET /forensic/report/html` | Downloads the latest HTML forensic report.                                          |
| `GET /forensic/report/json` | Downloads the latest JSON forensic report.                                          |
| `GET /forensic/report/siem` | Downloads the latest SIEM export.                                                   |

Example request:

```bash
curl -X POST http://127.0.0.1:8000/forensic/extract \
  -H "Content-Type: application/json" \
  -d "{\"save_outputs\": true}"
```

## Output Location

When `save_outputs` is true, reports are written to:

```text
core/c4/output/
```

The generated files are:

- `c4_report_<timestamp>.json`
- `c4_report_<timestamp>.html`
- `c4_siem_<timestamp>.json`

## MITRE ATT&CK Examples

| Pattern                           | Technique                                 |
| --------------------------------- | ----------------------------------------- |
| Cookie + credential co-occurrence | `T1539` Steal Web Session Cookie          |
| Browser credential records        | `T1555.003` Credentials from Web Browsers |
| Dangerous download                | `T1204.002` Malicious File                |
| Orphan download                   | `T1105` Ingress Tool Transfer             |
| Risky extension permissions       | `T1176` Browser Extensions                |

## Test Result From Bundled Source Profile

The adapted service was verified against the archive's `scenario_B` sample
profile:

```text
total_events: 31
flagged_events: 14
total_findings: 6
high: 3
medium: 1
low: 2
cooccurrence: 2
orphans: 2
temporal: 2
```
