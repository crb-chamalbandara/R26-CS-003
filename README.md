<p align="center">
  <img src="docs/logo.png" alt="WebSentinel logo" width="128">
</p>

<h1 align="center">WebSentinel</h1>

<p align="center">
  <b>Browser threat detection research platform</b><br>
  Malicious extension analysis &middot; BiTB phishing detection &middot; C2 beacon detection &middot; Browser forensic correlation
</p>

<p align="center">
  <a href="https://github.com/crb-chamalbandara/R26-CS-003/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/crb-chamalbandara/R26-CS-003?label=release"></a>
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows%2010%2F11-0078D6">
  <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-3776AB">
  <img alt="Electron" src="https://img.shields.io/badge/electron-27-47848F">
</p>

---

## Overview

**WebSentinel** (SLIIT research project **R26-CS-003**) is a desktop application that watches a
live browsing session and scores it for threats. It drives a persistent Chromium browser through
Playwright and passes everything the user does there to four detection components. Their results
appear together in one real-time dashboard.

| | Component | What it detects | How |
|---|---|---|---|
| **C1** | Malicious Extension Analyzer | Malicious or risky Chrome extensions, including at the moment of "Add to Chrome" | Blocklist, 33-feature XGBoost classifier, Isolation Forest anomaly layer, rule boosters, and a dynamic sandbox |
| **C2** | BitB Phishing Detector | Browser-in-the-Browser and credential-phishing pages | Layered DOM, URL, visual, form, reputation and runtime-behaviour analysis |
| **C3** | C2 Beacon Detector | Command-and-control beaconing from pages and extensions | Per-host traffic windows, behavioural features, ML classifier, reputation and risk fusion |
| **C4** | Forensic Correlation Engine | Suspicious activity reconstructed from browser artifacts | Cross-artifact correlation, timeline and MITRE ATT&CK mapping |

> WebSentinel is a research prototype. It is not intended to replace a production endpoint security product.

## Download and install (Windows)

1. Download **`WebSentinel-Setup-1.0.0.exe`** from the [latest release](https://github.com/crb-chamalbandara/R26-CS-003/releases/latest).
2. Run it. The installer is not code-signed, so Windows SmartScreen may warn you. Choose **More info > Run anyway**.
3. Pick an install folder, and choose whether to add Desktop and Start Menu shortcuts. You can also choose to always run as administrator.
4. Start **WebSentinel**. The analysis backend starts by itself and the dashboard opens when it is ready.

The installer bundles Python, the trained models and Chromium, so the target machine needs no other software.
It is about 480 MB for that reason.

**Requirements:** Windows 10/11 (64-bit), and port **8765** free. Only one instance can run at a time.

User data (settings, alert databases, the browser profile and C4 reports) is kept per user in
`%USERPROFILE%\.websentinel`.

## Components

### C1 &mdash; Malicious Browser Extension Analyzer
Decides whether an extension is safe before it can do damage, by combining static and dynamic analysis.

- **Blocklist** of 6,656 known-malicious extension IDs with per-ID evidence.
- **Static ML:** 33 manifest and code features (permissions, `eval`/`atob` use, entropy, and so on) feed an XGBoost classifier. Measured false-positive rate on 103,632 real Chrome Web Store extensions is 0.38%.
- **Anomaly layer:** an Isolation Forest, trained on its own benign-only dataset, flags zero-day behaviour.
- **Dynamic sandbox:** extensions are loaded in headed Chromium, optionally inside a disposable Windows Sandbox VM. Every result reports the isolation it actually had, so a verdict never implies containment it did not have.
- **Live install interception:** clicking "Add to Chrome" in the monitored session pauses the install for a block or approve decision.
- **Reports:** simple and advanced views, a permission-risk panel, a network graph, and PDF, JSON and text export.

Details: [`core/c1/ARCHITECTURE.md`](core/c1/ARCHITECTURE.md)

### C2 &mdash; Browser-in-the-Browser (BiTB) Phishing Detector
Scores each page the user visits and reports SAFE, SUSPICIOUS or PHISHING with the evidence behind it.

- **L1 BitB:** DOM heuristics plus a trained HTML classifier (fake windows, fixed iframes, drag-blocking).
- **L2 URL:** a URL classifier on lexical features.
- **L3 Visual:** perceptual-hash comparison against reference brand logos.
- **L4 Form:** off-domain form posts and password fields.
- **L5 Reputation:** Google Safe Browsing and PhishTank lookups (optional API keys), plus a verified-domain allow-list.
- **L6 Runtime:** a behaviour probe for keylogging, clipboard access and exfiltration.
- Alerts are stored in SQLite and can be exported as HTML, JSON, CSV or SIEM format.

Details: [`core/c2/ARCHITECTURE.md`](core/c2/ARCHITECTURE.md) &middot; research notes in [`researches/C2`](researches/C2)

### C3 &mdash; Browser-Execution-Aware C2 Beacon Detector
Finds command-and-control beaconing in the traffic the browser session produces, whichever page or extension it comes from.

- Groups requests into per-host windows and computes behavioural features (timing regularity, size consistency, and so on).
- An ML classifier, trained on 52,909 real traffic windows, is combined with heuristic rules, a reputation engine and a context tagger through risk fusion.
- Optional **auto-block** of confirmed beacon hosts, with an unblock control and analyst feedback on alerts.
- Includes a built-in beacon test page and target for demonstrations.

Details: [`researches/C3/ARCHITECTURE.md`](researches/C3/ARCHITECTURE.md) &middot; model results in [`researches/C3/C3_Final_Model_Results.md`](researches/C3/C3_Final_Model_Results.md)

### C4 &mdash; Browser Artifact Forensic Correlation Engine
Reads a browser profile and reconstructs what happened.

- Extracts history, cookies, saved logins (DPAPI plus AES-GCM decryption, masked in reports by default), downloads, extensions, sessions and Local Storage.
- Applies single-artifact rules, then **seven cross-artifact detectors**: co-occurrence, orphan artifacts, temporal anomalies, ordered attack chains, domain risk clustering, cross-domain credential reuse, and download-to-exfiltration.
- Maps findings to **MITRE ATT&CK** techniques with severity levels.
- Produces JSON and HTML forensic reports and a SIEM export.

Details: [`core/c4/ARCHITECTURE.md`](core/c4/ARCHITECTURE.md)

## Architecture

```
 +----------------------------------------------------------------+
 |  Electron desktop app  (electron/main.js)                      |
 |  Dashboard UI  (frontend/dashboard.html)                       |
 +---------------+---------------------------^--------------------+
                 | REST                      | WebSocket /ws/events
 +---------------v---------------------------+--------------------+
 |  FastAPI backend  127.0.0.1:8765   (core/main.py)              |
 |   - Playwright session: persistent Chromium                    |
 |   - C1  core/c1   extension analysis + sandbox                 |
 |   - C2  core/c2   BiTB / phishing layers                       |
 |   - C3  core/c3   beacon detection                             |
 |   - C4  core/c4   forensic correlation                         |
 +----------------------------------------------------------------+
```

In the installed app the backend is a PyInstaller executable (`core/server_entry.py`) that Electron
launches and health-checks before opening the window. In development it runs under Uvicorn.

Interactive API docs are available at <http://127.0.0.1:8765/docs> while the app is running.

## Run from source (development)

**Prerequisites:** Windows, Python 3.10+, Node.js 18+.

```bat
git clone https://github.com/crb-chamalbandara/R26-CS-003.git
cd R26-CS-003
run.bat
```

`run.bat` checks for Python and Node, installs the Python requirements, the Playwright Chromium build
and the Electron dependencies if they are missing, frees port 8765, and starts the app.

Manual steps, if you prefer:

```bash
pip install -r requirements.txt
python -m playwright install chromium
python -m uvicorn core.main:app --host 127.0.0.1 --port 8765   # backend only
cd electron && npm install && npm start                        # desktop UI
```

## Build the Windows installer

```bat
build_installer.bat
```

The script creates a build venv, installs requirements, downloads a bundled Chromium, freezes the
backend with PyInstaller (`packaging/backend.spec`), and runs `electron-builder` (NSIS). The result is
`electron\dist\WebSentinel-Setup-<version>.exe`. The version comes from `electron/package.json`.

Notes:
- electron-builder needs permission to create symbolic links on Windows. Turn on **Developer Mode** (Settings > System > For developers) or run the build from an administrator terminal.
- The custom installer pages live in [`electron/installer/installer.nsh`](electron/installer/installer.nsh).
- Pushing a `v*` tag runs [`.github/workflows/release.yml`](.github/workflows/release.yml), which builds the installer on GitHub Actions.

## Configuration

Settings are available through the dashboard and `GET/POST /settings`. Optional values include
the Google Safe Browsing API key and PhishTank access for C2 reputation checks, and sandbox isolation options for C1.

| Variable | Purpose |
|---|---|
| `WEBSENTINEL_PORT` | Backend port (default `8765`) |
| `WEBSENTINEL_BROWSER_PROFILE` | Browser profile that C4 scans (otherwise the WebSentinel profile, then Chrome, Chromium or Edge) |
| `PYTHON_PATH` | Python interpreter used by Electron in development mode |

## Project layout

```
core/            FastAPI gateway, Playwright session, and the c1 / c2 / c3 / c4 components
electron/        Desktop shell (main process, preload, NSIS installer script)
frontend/        Dashboard UI (HTML/JS, bundled Chart.js)
models/          Trained models (XGBoost, Isolation Forest, classifiers)
data/            Datasets, brand logo hashes, verified-domain list
scripts/         Dataset preparation, training, tuning and evaluation scripts
packaging/       PyInstaller spec for the backend
researches/      Per-component research notes, results and papers
test/            Tests for C1, C2, C3 and C4
docs/            README assets
```

## Testing

Each component has its own tests under `test/`, for example:

```bash
python test/C3/test_c3_units.py
```

C1 tests live in `test/C1/`, C2 in `test/C2/` and C4 in `test/C4/` (`python test/C4/test_units.py`). Component research notes, evaluation results
and test cases are in [`researches/`](researches).

## Troubleshooting

- **The app opens and closes straight away, or says the backend did not start:** another program, or an old `websentinel-backend.exe`, is using port 8765. Close it, or check with `netstat -ano | findstr 8765`.
- **Nothing happens when launching a second time:** WebSentinel is single-instance. Look for a hidden `WebSentinel.exe` in Task Manager.
- **C1 sandbox or browser features fail:** try the installer option to always run as administrator.
- **C4 cannot read a profile:** the browser has its databases locked. Close Chrome or Edge, or stop the WebSentinel session, then scan again.

## License

No license has been set for this repository. All rights are reserved by the authors.
