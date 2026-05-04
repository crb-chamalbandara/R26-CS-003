# Component 4 — Forensics: Browser Artifact Forensic Correlation Engine

> **Status:** 🔲 Not yet implemented — contributor welcome

## Research Question
Can automated cross-artifact correlation of browser forensic data (history, cookies,
downloads, localStorage) reliably reconstruct attack timelines and map them to
MITRE ATT&CK techniques?

---

## Architecture Overview

```
Browser Profile Directory (Chromium)
      │
      ├── History.db (SQLite)
      ├── Cookies (SQLite)
      ├── Login Data (SQLite)
      ├── Cache/
      ├── Local Storage/
      └── IndexedDB/
              │
              ▼
        Artifact Extractor
        (normalise → unified event timeline)
              │
              ▼
        Sliding-Window Correlator
        (detect multi-artifact attack patterns)
              │
              ▼
        MITRE ATT&CK Mapper
              │
              ▼
        Forensic JSON Report
```

---

## Tech Stack
| Layer | Recommended Technology |
|-------|----------------------|
| SQLite reading | Python `sqlite3` (stdlib) |
| Normalisation | Custom data classes / Pydantic models |
| Correlation | Sliding window (pure Python or pandas) |
| ATT&CK mapping | MITRE ATT&CK Python library (`mitreattack-python`) |
| Report format | JSON → exportable PDF (optional: `reportlab`) |

---

## File Map

| File | Role |
|------|------|
| `__init__.py` | Package marker |
| `extractor.py` | **(create)** Read + normalise SQLite browser artifacts |
| `integrity.py` | **(create)** SHA-256 + WAL tamper detection |
| `anomaly.py` | **(create)** Behavioural anomaly detection on artifact data |
| `chain.py` | **(create)** Sliding-window cross-artifact chain correlator |
| `mitre.py` | **(create)** Map detected chains to ATT&CK techniques |

---

## Integration Interface
`core/main.py` will call (once implemented):

```python
from c4.extractor  import extract_artifacts
from c4.integrity  import check_integrity
from c4.anomaly    import detect_anomalies
from c4.chain      import correlate_chains

# Combined forensic report
report = {
    "artifacts": await extract_artifacts(),
    "integrity": await check_integrity(),
    "anomalies": await detect_anomalies(artifacts),
    "chains":    await correlate_chains(artifacts),
    "timestamp": datetime.now().isoformat(),
}
```

Endpoint: `POST /forensic/extract` → triggers scan; `GET /forensic/report` → latest JSON.

---

## Chromium Profile Path
Default Playwright persistent context profile: `~/.websentinel/profile/`
Override via environment variable: `WEBSENTINEL_BROWSER_PROFILE`

---

## Implementation TODO
- [ ] Implement `extractor.py` — History, Cookies, Login Data SQLite readers
- [ ] Implement `integrity.py` — WAL/SHM tamper checks + SHA-256 hashing
- [ ] Implement `anomaly.py` — Late-night browsing, URL burst, suspicious TLD detection
- [ ] Implement `chain.py` — 2-minute sliding window, BROWSE+CREDENTIAL+COOKIE patterns
- [ ] Implement `mitre.py` — Map chains to ATT&CK T-codes (T1539, T1555, T1074, etc.)
- [ ] Add `/forensic/extract` + `/forensic/report` endpoints to `core/main.py`
- [ ] Add C4 live panel to frontend dashboard with timeline visualisation

---

## MITRE ATT&CK Technique Mapping (suggested)
| Chain Pattern | Technique |
|---------------|-----------|
| Credential + Cookie in window | T1539 Steal Web Session Cookie |
| Login Data access | T1555.003 Credentials from Web Browsers |
| Download + Browse sequence | T1074 Data Staged |
| Extension install + exfil | T1176 Browser Extensions |

---

## AI Session Starter
> Paste this into a new AI chat to get instant context:
>
> "I'm building Component 4 of WebSentinel — a Browser Artifact Forensic Correlation Engine.
> Project root: `WebSentinel/`. Shared infra in `core/`. My component code goes in `c4/`.
> The browser profile is at `~/.websentinel/profile/` (Playwright persistent context).
> I need to extract SQLite artifacts (History, Cookies, Login Data), detect anomalies,
> run sliding-window cross-artifact correlation, and map findings to MITRE ATT&CK.
> Endpoints `POST /forensic/extract` and `GET /forensic/report` live in `core/main.py`.
> I need help with: [YOUR TASK]"
