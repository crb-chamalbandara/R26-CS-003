# Component 1 (C1) - Malicious Browser Extension Analyzer

> Status: Implemented and integrated. Full pipeline live in `core/main.py` and
> `frontend/dashboard.html`. Last verified 2026-08-28.

## Implementation Status (accurate as of 2026-08-29)
- ✅ Hash/ID blocklist check (6,656 known-malicious IDs, combined malext_sentry + chrome_mal_ids sheet with per-ID evidence — name, reason, source, date, store, version, SHA256; added 2026-08-27, supersedes the earlier 2,199-ID `malicious_ids.json`)
- ✅ Blocklist evidence completion (2026-08-29) — a hit on an under-reported row no longer short-circuits: the ML stack and the sandbox run on the intercepted CRX, the threat class is derived from what they observed, and the completed row is written back to the sheet with an audit trail — `blocklist.py` / `enrich.py`, swept offline by `scripts/backfill_blocklist_evidence.py`
- ✅ Manifest + code feature extraction (33 features) — `features.py`
- ✅ XGBoost supervised classifier, trained + cross-validated on `data/dataset_clean_v4.csv` (1,779 rows: 1,457 benign, 322 malicious) — `static_model.py` / `models/extension_detector_model.pkl`
  - Rebuilt 2026-08-28 from raw CRX after two dataset defects were found and fixed (see "Training-data corrections" below). Holdout precision 0.889 / recall 0.750 / F1 0.814; measured false-positive rate on 103,632 real Chrome Web Store extensions: **0.38%** (was 63.45% before the rebuild).
- ✅ Rule-based score boosters (eval/atob/exec_script/webRequestBlocking patterns) — `analyzer.py`
- ✅ Isolation Forest zero-day/anomaly layer, trained on its own **separate, independently-sourced dataset** — `models/isolation_forest_model.pkl` (design drafted in `C1_ML_Analysis.ipynb` §12; productionized 2026-08-25 via `scripts/train_isolation_forest.py`; moved to a genuinely separate benign-only dataset 2026-08-28 via `scripts/build_isolation_forest_dataset.py` + `scripts/train_isolation_forest_separate.py` — see "Isolation Forest dataset" below)
- ✅ Dynamic Playwright sandbox (headed Chromium — extensions require `headless=False`, a Playwright constraint not a bug) — `sandbox.py`
- ✅ Pluggable sandbox isolation (2026-08-29) — `isolation/`: a disposable Windows Sandbox VM backend (fresh per analysis, destroyed after) with honest fallback to host execution; every dynamic result now carries an `IsolationReport` stating the containment it actually had, so a verdict can never imply isolation it did not have
- ✅ Score fusion (0.7×static + 0.3×dynamic) + verdict thresholds — `analyzer.py`
- ✅ Human-readable report generation with severity-ranked flags — `report.py`
- ✅ SQLite history persistence — `db.py`
- ✅ CRX parsing (v2 + v3) and Chrome Web Store download — `crx_utils.py`
- ✅ Full FastAPI integration: upload, webstore lookup, live "Add to Chrome" click interception with block/approve flow — `core/main.py`
- ✅ Dashboard panel (upload, webstore lookup, live install monitor, history) — `frontend/dashboard.html`
- ✅ Report surface (2026-08-30) — Simple/Advanced report modes, plain-language verdict, threat gauge, honest stat cards, declared-permission risk panel (`permissions.py`), realm-attributed network graph, and PDF/JSON/text export — `report.py` / `frontend/dashboard.html`
- ✅ Evidence layer (2026-10-10) — a static extension profile (`profile.py`), request attribution and real-page observation in the sandbox, and network intelligence (`netintel.py`: domain roles, IP addresses, defanged indicators). Evidence for the reviewer: none of it changes the score. See "Evidence layer" below.
- ⬜ Puppeteer/Docker container sandbox from the original proposal — the VM route was taken instead (`isolation/windows_sandbox.py`); a Docker backend remains a registered extension point in `isolation/__init__.py` if a Linux/CI target is needed

## Purpose
Detect malicious browser extensions before they cause harm by combining static analysis
(manifest + code patterns + ML + hash match + unsupervised anomaly detection) with optional
dynamic sandbox behavior analysis.

This component is based on the project proposal and the C1 guides.

---

## Problem Context and Gap
- Malicious extensions can pass store checks, then steal credentials or inject scripts at runtime.
- Existing extension analyzers focus on static checks only and miss conditionally triggered behavior.
- No single tool combines ML-based static classification with live sandboxed behavior monitoring.

---

## Novelty (C1)
This component fuses ML-based static code classification with live runtime sandbox observation
in a single automated pipeline for browser extensions. It catches obfuscated or delayed
malicious behavior that static-only tools like CRXcavator or Tarnish miss.

---

## Research Question
Can a combination of ML-based static analysis and sandboxed dynamic execution accurately
detect malicious browser extensions before they cause harm?

---

## Architecture Overview

```
Extension Input (CRX or unpacked)
      |
      v
Static Analysis Module
  - Hash check (known malicious)
  - Manifest permission features
  - Source code pattern features
  - ML classifier (score_static 0-100)
      |
      | if score_static > 50
      v
Dynamic Sandbox Module (Playwright + Chromium)
  - Isolation backend: disposable Windows Sandbox VM,
    else host process with a throwaway browser profile
  - Load extension in headed Chromium (extensions cannot
    be loaded headless — a Playwright constraint)
  - Capture API calls, DOM access, cookies, network
  - Behavior rules -> score_dynamic 0-100
  - Emit an IsolationReport describing the containment used
      |
      v
Verdict Engine
  - Fuse static + dynamic scores
  - Output verdict + evidence list
```

---

## Implementation Modules (WBS)
1) Static Analysis Module
2) Dynamic Analysis Module (Sandbox)
3) Verdict Engine (score fusion + reporting)

---

## Tech Stack (from proposal)
| Layer | Technology |
|------|------------|
| Static ML | Python + scikit-learn / XGBoost |
| Sandbox | Puppeteer (Node.js) + Headless Chromium |
| Isolation | Docker Desktop |
| Baselines | Tarnish, CRXcavator |

**As built** (the proposal's stack above is kept for traceability; two rows
changed during implementation):

| Layer | Technology | Why it differs |
|------|------------|----------------|
| Static ML | Python + XGBoost + Isolation Forest | as proposed, plus an unsupervised zero-day layer |
| Sandbox | **Playwright (Python) + headed Chromium** | Chromium cannot load an unpacked extension in headless mode, so `headless=False` is required; Playwright replaced Puppeteer to keep the whole component in one language |
| Isolation | **Windows Sandbox (Hyper-V VM), Docker as an extension point** | Docker Desktop needs WSL2/Hyper-V plus a large install; Windows Sandbox gives a genuinely disposable VM with no third-party dependency and matches the "fresh per analysis, destroyed after" design directly |
| Baselines | Tarnish, CRXcavator | unchanged |

---

## Inputs and Outputs

### Inputs
- CRX file (preferred) or unpacked extension directory
- Optional: manifest.json + concatenated JS source for testing

### Output (contract)
```json
{
  "score": 0,
  "verdict": "SAFE|SUSPICIOUS|MALICIOUS",
  "detail": "short summary",
  "flags": ["evidence_1", "evidence_2"],
  "static": {
    "score": 0,
    "hash_match": false,
    "ml_score": 0
  },
  "dynamic": {
    "score": 0,
    "executed": false,
    "signals": []
  }
}
```

---

## Data Sources

### Malicious
- chrome-mal-ids (extension ID blocklist)
- palant/malicious-extensions-list (curated IDs + behavior descriptions)
- chrome-stats malware removals (confirmed by Google, 7000+ IDs)
- refade/GoogleChromeExtension dataset (1,012 CRX, 1,098 features)

### Benign
- Top Chrome Web Store extensions (500-1000), collected via CRXcavator

---

## Static Analysis Module

### 1) Hash Check
- Compute SHA-256 of the CRX
- Compare with malicious hash database
- If match, set score_static to 100 and verdict MALICIOUS

#### 1a) Blocklist evidence completion (added 2026-08-29)
The finalized sheet merges two sources of very different quality. The
`malext_sentry` half carries full evidence per ID; the `chrome-mal-ids` half is
an ID-only dump whose evidence columns hold literal placeholder text — `Not
Found` for name and hash, `Not yet confirmed` for reason, `Not Confirmed` for
store and version, `N/A` for date. Short-circuiting on those rows produced a
Blocklist Match panel that told the analyst nothing.

`blocklist.py` now treats those placeholders as *missing* (`entry_gaps()`), and
the panel renders them as an explicit "not established" state rather than
echoing the sheet's placeholder text. When a matched row has gaps, `analyzer.py`
stops short-circuiting and runs the full stack on the CRX it has just
downloaded:

```
blocklist hit
   |
   +-- row fully documented  -> instant MALICIOUS (unchanged fast path)
   |
   +-- row has gaps          -> 33 features -> XGBoost
                                            -> rule boosters
                                            -> Isolation Forest
                                            -> dynamic sandbox (always, not
                                               gated on the 50-point threshold —
                                               the ID is already confirmed bad,
                                               so runtime evidence is always
                                               worth collecting)
                                            -> enrich.derive_reason()
                                            -> write the completed row back to
                                               the CSV + audit log
```

The verdict is unchanged either way: a blocklist hit is MALICIOUS at 100 by
authority, and `score_source: "blocklist"` says so. What changes is that the
result now carries the models' own numbers alongside it (`ml_score`,
`anomaly_score`, `measured_static_score`, real sandbox signals) instead of the
hardcoded 1.0 the fast path used to report.

`enrich.derive_reason()` scores nine threat classes drawn from the sheet's own
reason vocabulary (Malware, Spyware, Spyware / Data Exfiltration, Adware, Search
Hijacking, Bundling Unwanted Software, Crypto Wallet Theft, Policy Violation, In
store but Suspicious, plus Removal reason Unknown for delisted extensions).
Each class accumulates evidence points from the flags, features, manifest and
sandbox signals that actually fired. A *specific* class must clear 30 evidence
points before it can be named; below that the derivation falls back to the
sheet's generic reasons rather than asserting a threat the analysis cannot
support. Every contributing predicate is kept as rationale and shown in the
panel under "Why this reason".

Evidence written back to the sheet is append-only in spirit: `update_entry()`
never overwrites a cell that already holds curated evidence (unless explicitly
asked to), the rewrite is atomic under a process-wide lock, and every changed
cell is appended to `data/blocklist_enrichment_log.csv` with its old value, new
value, confidence and method.

Coverage as loaded (6,656 rows): 3,614 fully documented, 3,042 with at least one
gap — 597 missing a name, 573 missing a reason, 578 missing a date, 681 missing a
store, 2,988 missing a version, 2,194 missing a hash.

Sweeping the rest offline: `python researches/C1/scripts/backfill_blocklist_evidence.py
--all`. Most undocumented IDs are undocumented precisely because the store
already removed the extension, so the CRX cannot be downloaded; those rows come
back `unavailable` and are left exactly as they were. Where the repo's archived
manifest corpus still holds the manifest, the sweep falls back to it and derives
from declared capability alone (the ML probability is excluded in that mode —
eleven of the 33 features are code counts that would all read zero).

### 2) Manifest Feature Extraction
Minimum features from manifest.json:
- Permission binary flags (webRequest, cookies, tabs, nativeMessaging)
- host_permissions count and all_urls presence
- background/service_worker existence
- content_scripts presence and count
- web_accessible_resources presence

Additional static features:
- Content script entropy (simple obfuscation signal)
- API call frequency for high-risk APIs

### 3) Source Code Pattern Features
Lightweight patterns (regex or AST):
- eval / Function / setTimeout with string
- WebSocket / fetch / XMLHttpRequest usage
- chrome.cookies / chrome.webRequest usage
- Input listeners (keylogging risk)

### 4) ML Classifier
- Primary: XGBoost (supervised, known-pattern detection) — `models/extension_detector_model.pkl`,
  trained on `data/dataset_clean_v4.csv`
- Secondary: Isolation Forest (unsupervised, zero-day/novel-technique coverage) — `models/isolation_forest_model.pkl`,
  trained on its **own separate dataset**, not derived from the XGBoost training data — see
  "Isolation Forest dataset" below.
- Handle class imbalance via scale_pos_weight, **capped at 2.0** rather than the raw
  benign/malicious ratio. Measured against 103,632 real extensions, the flagged-MALICIOUS
  rate is 0.10% at 1.0, 0.38% at 2.0, 2.77% at 3.0 and 14.51% at 4.52, while holdout F1
  peaks flat across 2.0–3.0. Left uncapped, every benign sample added to the training set
  *raises* the ratio and makes the model more trigger-happy — the opposite of the intent.
  See the comment in `scripts/retrain_with_new_data.py`.

Optional imbalance strategy:
- Repeat sampling of malicious vs benign subsets (balanced batches)

### Training-data corrections (2026-08-28)
Two defects were found by investigating a single false positive — Google Input Tools
(published by Google, 3M users) scoring 89.7% malicious. Both were dataset artifacts,
not model or code faults, and both are fixed.

**1. `host_permission_count` was blind to Manifest V2.** MV3 declares host access in a
separate `host_permissions` field; MV2 has no such field and mixes match patterns
(`https://*.example.com/*`) straight into `permissions`. The extractor only read the MV3
field, so every MV2 extension reported 0 regardless of actual host access. Because the
benign corpus is 90% MV2 and the malicious corpus is not, this manufactured a spurious
rule — benign rows sat at 3.6% "has host permissions" against a real-world rate of ~62%,
and the model learned *any host permission ⇒ malicious* (11% malicious at count 0 rising
to 93% at count ≥4). Fixed in `features.py::_is_host_pattern`, then the dataset was
rebuilt from raw CRX so training and inference agree.

**2. The benign corpus had almost no Manifest V3 extensions.** It is a ~2019 crawl, so
MV3-only permissions became proxies for the label: `has_scripting` appeared in 3.5% of
benign vs 21.4% of malicious rows, and removing it alone dropped Google Input Tools from
89.5% to 4.2%. Neither permission is inherently dangerous — they are simply the MV3
replacements for MV2 APIs. Corrected by collecting 515 modern Chrome Web Store extensions
(`scripts/collect_modern_benign_mv3.py`). Among the MV3 ones, `has_scripting` occurs at
20.5% — statistically indistinguishable from the 21.4% malicious rate, confirming it
carries no signal once the corpus is balanced.

Net effect: false positives on 103,632 real extensions fell from **63.45% to 0.38%**.
Holdout F1 moved 0.839 → 0.814, but the earlier figure was measured on the same
artifact-contaminated data that produced the 63% real-world failure, so it was never a
trustworthy number — this is precisely the case where in-sample metrics hide the problem.

### Isolation Forest dataset — deliberately separate from the supervised dataset
Two datasets, two different purposes:

| | XGBoost (`dataset_clean_v4.csv`) | Isolation Forest (`isolation_forest_benign_dataset.csv`) |
|---|---|---|
| Rows | 1,779 (1,457 benign, 322 malicious) | 103,632 (100% benign, no malicious rows at all) |
| Source | refade academic dataset + GherardoFiori CRX batch + curated power extensions + 515 modern Chrome Web Store extensions collected 2026-08-28 | `mandatoryprogrammer/chrome-extension-manifests-dataset` — 103,773 real manifests scraped from the live Chrome Web Store, minus 120 rows cross-matched against our own blocklist and minus 21 unreadable files |
| Features available | Full 33 (manifest + JS-derived code patterns) — real CRX files, JS included | Only the 22 manifest features — this source has no JS source, so the 11 code-pattern columns are 0 for every row here |
| Why separate | XGBoost needs contrastive malicious examples to learn a decision boundary | Isolation Forest is a one-class / novelty detector — it's deliberately restricted to only the "normal" class, using labels purely as a selection filter (see `scripts/build_isolation_forest_dataset.py`), never as a supervisory signal |

Training and evaluation are also split correctly: `scripts/train_isolation_forest_separate.py` **trains** only
on the 103,632-row benign-only file, and separately pulls the 322 malicious rows from
`dataset_clean_v4.csv` **purely to measure catch-rate** — it is never trained on them. Contamination
is calibrated at 0.02; the anomaly-flag threshold in `analyzer.py` is 60 (not the notebook's drafted 50),
chosen because at 50 several real, verified-benign complex extensions (Adobe Acrobat, LastPass, 1Password,
etc.) cross the boundary despite being in the training set — see `analyzer.py`'s `ISO_FOREST_ANOMALY_THRESHOLD`
comment for the full reasoning and numbers.

Known, accepted limitation: because the benign pool is now much larger and more representative of real-world
extension diversity, Isolation Forest alone is less easily triggered by synthetic "obviously extreme"
permission profiles than a naive small-benign-set model would be. This is an intentional trade — it is the
cost of the much lower false-positive rate on real complex extensions, and XGBoost remains the primary
detector for extensions that are unambiguously high-risk by permissions/code alone.

### Static Score
```
score_static = 100 if hash_match else round(ml_score * 100)
score_static = max(score_static, anomaly_score)   # Isolation Forest can only raise the score
```

---

## Dynamic Sandbox Module

Triggered only if score_static > 50 (configurable), or unconditionally when a
blocklist row needs evidence (see §1a).

The module is split in two, deliberately:

| Half | Code | Responsibility |
|------|------|----------------|
| Observation | `sandbox.observe_extension()` | Launch Chromium with the extension loaded, instrument it, watch it, score what it did. Carries no containment of its own. |
| Containment | `sandbox.run_sandbox()` + `isolation/` | Choose an isolation backend, have it perform the observation, and attach an `IsolationReport` stating where the analysis actually happened. |

Callers use `run_sandbox()`. The split means the same detection logic runs
whether the analysis happens on the host or inside a VM, so results from the
two are directly comparable.

### Observation techniques

1. **JS built-in patching** — `page.add_init_script()` installs wrappers before
   any page script runs: `window.eval`, `fetch`, `XMLHttpRequest.open/send`,
   `WebSocket`, a `document.cookie` get/set property descriptor,
   `EventTarget.addEventListener` (keydown/keypress/keyup), and a capture-phase
   `submit` listener. Signals accumulate in `window.__c1_signals`.
2. **CDP network observation** — `context.on("request")`, registered *before*
   the first page is opened so background service-worker traffic is captured
   too (that is where MV3 extensions do their network work).
3. **Bait page** — an HTML page carrying a fake login form and session cookies,
   as material worth stealing.
4. **Fixed observation window** — 20 s by default, clamped to 5-30 s.
5. **Weighted scoring** — 9 signal types totalling 200 points, capped at 100.
6. **Request attribution and a real-page visit** (2026-10-10) — every request is
   tagged with who made it, and a few public pages are visited after the bait
   page. See "Evidence layer".

### Isolation backends (added 2026-08-29)

Before this, the sandbox launched Chromium as a child of the analysis process:
host kernel, host filesystem, host network identity, and `--no-sandbox` (a
Playwright requirement for loading unpacked extensions in a persistent context)
which also disables Chromium's own renderer sandbox. The only genuinely
ephemeral thing was the browser profile directory.

`core/c1/isolation/` makes containment pluggable and, more importantly, makes
every run *declare* what it had:

| Backend | Level | Isolation |
|---------|-------|-----------|
| `windows_sandbox` | `ephemeral_vm` | Hyper-V VM built from a clean Windows image for one analysis and destroyed afterwards. Own kernel, own filesystem; host sees only the result JSON. |
| `inprocess` | `browser_profile` | Chromium on the host with a throwaway profile. Fast, no prerequisites, weak containment. Fallback. |

`select_backend()` takes the strongest available unless one is named. **A
downgrade is never silent** — if the VM backend is requested and unavailable,
the run falls back and the reason is recorded in the result's warnings.

Every dynamic result now carries `result["isolation"]`:

```json
{"backend": "windows_sandbox", "level": "ephemeral_vm", "ephemeral": true,
 "fresh_per_analysis": true, "discarded_after": true,
 "shares_host_kernel": false, "shares_host_filesystem": false,
 "shares_host_network_identity": true, "chromium_own_sandbox": false,
 "network_policy": "unrestricted", "rank": 3, "warnings": [...]}
```

and `report.py` names the containment in the summary sentence, so a behavioural
finding is never read without knowing what contained it.

**Windows Sandbox mechanics.** Per run: stage the extension + guest agent +
observation module into a temp dir; generate a `.wsb` mapping a Python runtime,
the Playwright package tree, the Chromium build and the staged input **read-only**,
plus one **read-write** output folder; launch `WindowsSandbox.exe`; poll for the
guest's `done` marker; read `result.json`; wait for the guest to power itself
off; delete the staging directory. Clipboard and printer redirection are
disabled — they are host reachback paths the analysis does not need. The guest
agent reports `hostname`/`user` back as attestation (`WDAGUtilityAccount` and a
different Windows build number prove the run really happened in the VM).

**Disposal is done by the guest, not the host** — this was got wrong twice
during implementation and the reason matters. The container is owned by the
Host Compute Service (`vmcompute`). Force-killing the sandbox processes from
the host *orphans* it: `vmmemWindowsSandbox` keeps running with ~2.5 GB
resident and a lock on the mapped folders, and it cannot be terminated without
administrator rights. Killing the broker (`WindowsSandboxServer.exe`) makes it
worse, because the broker is the only thing that could have shut the container
down. A graceful `WM_CLOSE` to the sandbox window did not dispose of it either.
What works is ending the container from inside: the bootstrap finishes with
`shutdown /s /f /t 0`, the guest OS powers off, and Windows tears the container
down normally — no host privileges, nothing left behind. Host-side killing
remains only as a fallback for a guest that crashed before reaching that line.

Because disposal can fail, it is **verified rather than assumed**: `_teardown()`
returns whether `vmmemWindowsSandbox` actually exited, and the report's
`ephemeral` / `discarded_after` are set from that result, with an explicit
warning when the VM survives. A run that could not dispose of its VM says so
instead of claiming an ephemerality it did not achieve.

Constraints: Windows Pro/Enterprise/Education with the
`Containers-DisposableClientVM` feature enabled; **only one Windows Sandbox may
run at a time**, so analyses serialise behind a lock and a pre-run guard
refuses to start when a stale VM is resident. The sandbox memory cap is sized
from free host RAM (2048-4096 MB) rather than fixed — a 4 GB request on a host
with 2 GB free makes the guest thrash badly enough to look like a hang.

**Performance.** Measured on the reference machine (Win 11 Pro, 16 GB, VT-x,
20 s requested observation window), with the phase breakdown the backend now
reports in `isolation.timing`:

| | First working run | After optimisation |
|---|---|---|
| VM boot | 12.1 s | 10.9 s |
| Observation | 27.1 s | 14.2 s |
| VM disposal | 12.1 s | 6.5 s |
| Python start + staging | 0.2 s | 0.1 s |
| **Total** | **52.8 s** | **32.5 s** |

In-process backend over the same period: 16.6 s -> 9.7 s. Detection output is
*identical* across every one of these configurations (score 50, the same 3
signals, 28 network requests on the synthetic fixture) — which is the point of
separating observation from containment, and the check that the speed work did
not quietly cost coverage.

What produced the 38% cut:

* **Adaptive observation window** (the big one, 27 s -> 14 s). Most extensions
  do everything they are going to do in the first second and the rest of the
  window is dead time. The window now closes once the extension has produced no
  new network request and no new page signal for `_QUIET_PERIOD_SECONDS`, after
  a `_MIN_OBSERVE_SECONDS` floor, capped by the caller's timeout. In-process on
  the fixture: 21.6 s fixed -> 10.1 s adaptive, same three signals. The trade is
  explicit — a sleeper that waits longer than the quiet period before acting
  would be missed, so `observe_extension(..., early_exit=False)` restores the
  full fixed window for a deep scan.
* **Chromium startup flags.** `--no-first-run`, `--disable-component-update`,
  `--disable-sync`, `--disable-background-networking`, `--disable-default-apps`,
  `--metrics-recording-only`, `--mute-audio`, `--disable-gpu`. The
  background-networking flag also stops Chromium's own service traffic being
  attributed to the extension.
* **Anti-throttling flags** — `--disable-background-timer-throttling`,
  `--disable-renderer-backgrounding`,
  `--disable-backgrounding-occluded-windows`. The sandbox window is minimised,
  and Chromium throttles background renderers and timers; that was suppressing
  exactly the delayed activity the sandbox exists to catch. A detection fix as
  much as a speed one.
* **`domcontentloaded` instead of `networkidle`** for the bait page, which has
  no subresources for `networkidle` to wait on.
* **Result poll 2 s -> 0.5 s**, and the guest's pre-shutdown delay 3 s -> 1 s.

`<VGpu>Disable</VGpu>` is already set, so the guest uses software rendering and
skips GPU virtualisation setup entirely — there is no further graphics setting
to trim. Guest boot (~11 s) is Windows Sandbox's own floor and is not reducible
from here; keeping the VM warm between analyses would remove it but would
destroy the fresh-per-analysis guarantee, which is the whole point of the
backend.

The boot allowance stays at 420 s: the first measured run took 162 s end to end
against a 170 s deadline, leaving 8 s of margin, and a false timeout discards a
real analysis.

Network policy is selectable (`unrestricted` / `disabled`). Disabling egress
protects the network but means no network behaviour is observed — the two are
genuinely in tension and the choice is surfaced in the dashboard.

Adding a container backend (Docker + Xvfb, reporting `LEVEL_CONTAINER` and
enforcing network policy via `--network`) is a matter of implementing
`IsolationBackend` and registering it in `isolation/__init__.py`.

### The disposable VM in an installed build (2026-10-13)

**What went wrong.** An installed WebSentinel said "Disposable VM unavailable" and ran every analysis on the host, even on a PC where Windows Sandbox was already on. The backend's own reason, read from the packaged build, was `cannot stage the guest runtime: missing python.exe under ...\resources\backend\_internal`. In a checkout the VM is lent the host's Python and its `site-packages`, and the guest agent and observer are staged as `.py` source. The installed backend is a frozen (PyInstaller) program with none of those: no `python.exe`, no `site-packages` folder, no source files.

**The fix: ship the VM's runtime.** The installer now carries a ready-made guest runtime and the backend lends the VM that instead.

| Piece | Where | What it does |
|-------|-------|--------------|
| Guest runtime | `packaging/c1_guest.spec` builds `dist/c1_guest/c1-guest.exe` (about 123 MB), installed at `resources\c1_guest` | Python, Playwright with its driver, `guest_agent.py` and the observation code (`core/c1/sandbox.py`) in one folder. The two source files are copied at build time, not kept as second copies, so the code that observes inside the VM is the code that observes on the host and the results stay comparable. |
| Discovery | `windows_sandbox.py` `_guest_bundle()` | Looks next to the installed backend (`resources\c1_guest`). `C1_GUEST_DIR` names one explicitly, which is also how a developer exercises the installed path from a checkout. |
| The VM | `build_wsb_config(guest_bundle=...)`, `build_bootstrap_cmd(bundled=True)` | Maps the folder read-only at `C:\c1\guest` (in place of the host's Python and site-packages) and the logon command runs `c1-guest.exe`. Only the output folder is writable, as before. A checkout without a bundle behaves exactly as it did. |
| Build | `build_installer.bat` step 4 of 6, and an `extraResources` entry in `electron/package.json` | The build stops if `dist\c1_guest\c1-guest.exe` is missing, so an installer can never ship without it. |

An installed build that lacks the runtime (a damaged install) now says `the guest runtime (c1-guest.exe in a c1_guest folder). Reinstalling WebSentinel restores it`, and never asks for a `python.exe`.

**Knowing early when a VM cannot start.** Two things make Windows Sandbox "never answer", and without a check the analysis would wait out the full several-minute allowance and then report a timeout:

- *Preflight* (`_virtualization_problem()`, cached for 30 s): Windows Sandbox needs the hypervisor. If it is not running, the reason is either "virtualization is turned off in this PC's BIOS or UEFI settings (Intel VT-x or AMD-V)" or "restart Windows if Windows Sandbox was only just turned on", and the dashboard's "why?" shows it. It is deliberately conservative: it says nothing when the state cannot be read, and the firmware flag is consulted only when the hypervisor is *not* running, because on a PC where it is running (the normal working case) that flag reads False.
- *Fail fast*, from three signals probed every 2 s (`_running_images()` is one look at the process list): (1) neither the VM (`vmmemWindowsSandbox`) nor Windows Sandbox's broker (`WindowsSandboxServer.exe`) has appeared 150 s after the launch, so "Windows Sandbox did not start..."; (2) the VM was running and has been gone for 10 s with no result (an error window, someone closing it), so "closed before the analysis finished"; (3) no `agent.log` in the shared output folder 240 s after the launch. The guest's logon command creates that file the moment it starts and boot to that point measured 17 to 37 s, so this is several times the longest seen, and it does not depend on any process name. Process names alone are not trusted: after a failed start the broker stays alive behind the error window. A run that ends without a result has the sandbox's own windows closed (the VM and broker are left to Windows), so no error window stays on the user's screen.

Console tools run from the windowless installed backend (`tasklist`, `taskkill`, PowerShell) now use `CREATE_NO_WINDOW`, so they no longer flash a window on the user's screen.

**Never closing a sandbox WebSentinel did not start.** Only one Windows Sandbox can exist per machine. The old pre-run check closed whatever was open, and it ran *before* the lock that makes analyses take turns, so two overlapping analyses could close each other's VM, and a sandbox the user had opened for their own work could be closed too. The check now runs inside the lock (when nothing of ours can be running), waits up to 15 s for a leftover to finish by itself, and otherwise returns "Another Windows Sandbox is already open ... WebSentinel does not close a sandbox it did not start, because it may be yours". Only the VM an analysis itself launched is ever force-closed, at the end of that analysis. Whether the sandbox has started is judged by its VM *or* its broker process, so a Windows build that names one differently cannot make a healthy run look dead.

**Running as administrator (found 2026-10-13).** With the installer's "Always run as administrator" option ticked, Windows Sandbox failed to start with `Access is denied (0x80070005)` and the analysis sat on "Running sandbox analysis...". The per-run staging folder was made by `tempfile.mkdtemp()`, which since Python 3.12 gives a folder a permission list naming only the creator, SYSTEM and Administrators. When the app is elevated the "creator" is the Administrators group, so the folder could only be opened by an elevated process, and Windows Sandbox, which runs with the user's normal rights, was refused (even the user's own non-elevated session could not read it). The error was reproduced on purpose from a normal session by sharing a folder with that permission list. `_new_staging_dir()` now makes the folder with a plain `mkdir`, which inherits the temp folder's permissions (they name the user), so it works whether or not the app is elevated. Admin rights are not needed for the sandbox, and the installer's wording no longer suggests they are. With the failure re-created through the real code path (a staging folder only elevated processes can open), the analysis used to wait 7.6 minutes and leave the error window open; with the fix the folder is accessible and the analysis runs, and if some other fault keeps the guest from starting it gives up after 4.4 minutes, says why, and closes the window.

**Verified.** The installer was built with `build_installer.bat` (all six steps) and its installed layout (`electron\dist\win-unpacked`) run the way Electron runs it, with its own backend and browsers: the backend answered in 7 s and selected Windows Sandbox; with `c1_guest` hidden it reported the incomplete-installation reason and fell back to the host; a real analysis of Browsec VPN from the Web Store ran inside Windows Sandbox using only the shipped runtime (`isolation.level = ephemeral_vm`, `discarded_after = true`, guest boot 18 s, about 103 s in all) and came out MALICIOUS 69.8, the same as the host path. A separate run with a stand-in "user" sandbox open confirmed the analysis was refused without touching it. Tests: `test/C1/test_guest_runtime.py` (42 checks, no VM needed).

### Turning on Windows Sandbox at install time (2026-10-12)

Windows Sandbox is an optional Windows feature (`Containers-DisposableClientVM`), off by default, and turning it on needs administrator approval and a restart. Without it the analyzer falls back to the host-process backend and says so. The installer therefore offers to turn it on.

| Piece | Where | What it does |
|-------|-------|--------------|
| Page | `electron/installer/c1_sandbox.nsh` | One page after "Setup options", with a single checkbox, **unticked by default**. Skipped entirely when Windows Sandbox is already on. Disabled, with a one-line reason, on Windows Home or Windows 10 before 1903. |
| Script | `electron/installer/enable-windows-sandbox.ps1` | Shipped to `resources\c1\` (an `extraResources` entry in `electron/package.json`). Run at the end of the install only when the box was ticked. |
| Hooks | `electron/installer/installer.nsh` | Three additive lines: the include, the page, and the call after the shortcut step. |

**It never turns the feature on twice.** Three independent checks, in order:

1. *The page* is skipped when `System32\WindowsSandbox.exe` exists, which is the test the app itself uses to decide the VM backend is available (`WindowsSandboxBackend.is_available`). Nothing is asked and nothing is run.
2. *The installer* tests again just before it runs the script, in case the state changed while the page was open.
3. *The script* tests the launcher first, and otherwise asks Windows for the feature's state and changes it only when the state is `Disabled`. `EnablePending` (switched on, waiting for a restart) and `DisablePending` are reported and left alone, which is the case a second run would otherwise hit.

When Windows Sandbox was turned on (or was already waiting for a restart) the installer sets the NSIS reboot flag, so the Finish page offers the standard "restart now or later" choice and the analyzer uses the VM from the next start of Windows.

Administrator approval is requested by the script itself (it re-runs itself elevated, one UAC prompt, nothing if the installer is already elevated), and a 32-bit installer hands over to the 64-bit PowerShell through `Sysnative`, because the Windows feature commands do not work from a 32-bit one. The script reports through its exit code (0 already on, 10 pending restart, 11 and 12 turned on, 20 not available, 30 failed, 31 other change pending, 40 approval declined) and writes `%TEMP%\WebSentinel-sandbox-setup.log`. A failed or declined step never fails the install: the user gets one message and WebSentinel runs in its less isolated mode. Silent installs (`/S`) and an unticked box change nothing about Windows, and uninstalling does not turn the feature off, because other programs may use it.

Tests: `test/C1/test_enable_sandbox.py` loads the script with the two Windows cmdlets replaced by fakes and checks every state (already on, enabled, pending, unsupported, refused, not administrator), that a second run does not enable again, and runs the real script here without elevation.

### Extension load verification (added 2026-08-29)

Chromium refuses unpacked extensions for ordinary reasons, and when it does the
sandbox still starts, still browses the bait page, and still reports "no
malicious behaviour observed". Fusing that into the verdict **lowers** the
threat score of an extension the analysis never saw.

Found on `okockappikfndbdfphjklenhfpdlgkgi` (All-in-One Adblocker): Chromium
raised *"Failed to load extension … ublock-filters.json: Internal error while
parsing rules"*, the dynamic layer returned a clean 0, and
`0.7 × 86.3 + 0.3 × 0 = 60.4` **downgraded the verdict from MALICIOUS to
SUSPICIOUS**. A sandbox failure was manufacturing false negatives.

Three fixes:

1. **Root cause — the read-only mapping.** Chromium indexes
   `declarativeNetRequest` rulesets when it loads an unpacked extension, and
   writes into the extension's own directory to do it. The VM maps the staged
   extension read-only (deliberately — the guest must not write back to the
   host), so indexing failed. The guest agent now copies the extension to
   guest-local storage before loading it: writable, and destroyed with the VM
   either way. Measured on that extension: read-only dir → no background
   context at all; writable dir → service worker starts normally.
2. **The load is verified, not assumed.** `_verify_extension_loaded()` waits for
   the background context an extension's manifest declares. `False` means
   rejected; `None` means the manifest declares no background so nothing
   reliable can be checked. On `False` the run reports `executed: False` and
   the `EXTENSION_LOAD_FAILED` flag, which makes Step 7 fall back to the static
   score instead of averaging in a meaningless 0.
3. **`--noerrdialogs`.** The failed load raised a *modal* dialog that blocked
   the browser for the entire observation window with nobody there to dismiss
   it — which is why the failing run took 130 s and observed nothing.

The report and the dashboard both distinguish "sandbox did not run" from
"sandbox ran but the extension was rejected", and the second says explicitly
that it is not evidence of safety.

### Fixed 2026-08-29 — the three blind spots below

The three gaps this section used to describe are closed. All three were found
by the same method: build a synthetic extension that does exactly the thing in
question, run it, and check whether the resulting signal actually appears —
not by inspecting the code and assuming it would work.

1. **The bait page was a `data:` URI.** Chrome blocks cookies and refuses to
   run content scripts on `data:` pages at all, regardless of the extension's
   declared match patterns — so anything gated on either did nothing on the
   old bait page for reasons that had nothing to do with its actual behaviour.
   Fixed by intercepting a real `http://` navigation with Playwright's
   `page.route()` instead (`sandbox._BAIT_URL`, on the IANA-reserved
   `.invalid` TLD so a missed interception fails safe with a DNS error rather
   than reaching a real site) — no server process needed, but a genuine
   addressable origin.

2. **The background service worker was not instrumented.** `add_init_script`
   only reaches pages; a service worker has no `window` at all, and that
   matters because it is exactly where a real malicious extension has every
   reason to run persistent fetch/WebSocket C2 — nothing about it is ever
   rendered, so there was never a page for the old hook to attach to. Fixed by
   injecting a `self`-based equivalent (`sandbox._SW_MONITOR_JS`) into every
   service worker and MV2 background page as it appears
   (`ctx.on("serviceworker")` / `ctx.on("backgroundpage")`), with results read
   back into a new `background_signals` evidence bucket that feeds the same
   scoring as page signals.

3. **A content script's cookie/eval/keyboard activity was invisible even once
   it could run.** A content script executes in an isolated JS world — same
   DOM, different JS object graph, deliberately, so neither side can tamper
   with the other — so the page-level hook's `Object.defineProperty` override
   on `document.cookie` is a different object there and never fires. This one
   took two tries: an out-of-process injection attempt via CDP's
   `Page.addScriptToEvaluateOnNewDocument(worldName=...)` was tried first and
   *looked* like it worked (the script did run, confirmed via a console log),
   but a live check showed it had created a separate DevTools-only shadow
   world with the same display name rather than reaching the extension's real
   one — two different context ids for what DevTools shows as one named
   world. The fix that actually works: the monitor hook is spliced directly
   into the extension's own content script files on a staged copy
   (`sandbox._patch_content_scripts_with_monitor`), so it runs as literally
   the first lines of a file the browser was always going to execute, in the
   real world, with no injection race at all. Results are read back from that
   world via a raw CDP session (`Runtime.evaluate` targeted at the world's
   `contextId`, tracked from `Runtime.executionContextCreated` and matched by
   name) into a new `content_script_signals` bucket.

**Verified against `core/c1/test_malicious_ext`** (the project's own reference
fixture, purpose-built to exercise exactly these three paths — a `background.js`
service worker doing the fetch/WebSocket/beacon C2, a default-world `content.js`
doing the cookie/keydown read, and a `world: "MAIN"` `page_hook.js` for the
page-level path that already worked). Before this fixture existed as it does
now, none of `content.js`'s or `background.js`'s activity was visible to any
hook — only `page_hook.js`'s main-world signals and whatever showed up in raw
network requests were. Run end-to-end today: `dynamic_score=100`, all six
possible flags fire (`EVAL_AT_RUNTIME`, `KEYBOARD_MONITORING`,
`WEBSOCKET_TO_EXTERNAL`, `COOKIE_EXFILTRATION_RISK`, `SUSPICIOUS_DOMAIN`,
`HIGH_REQUEST_VOLUME`), with 5 page signals, 29 background signals and 2
content-script signals recorded — the full 200-point signal space is reachable
in a single run for the first time.

**Still open:**
- `navigator.webdriver` is `true`, so evasive extensions can stay dormant.
- `127.0.0.1` counts as external and suspicious, penalising legitimate
  native-bridge extensions.
- Dynamic code injected via `chrome.scripting.executeScript({func: ...})`
  (an inline function, not a file on disk) bypasses the content-script file
  patch, since there is no file to patch — the CDP context-tracking read-back
  would still see it if a hook were already installed in that world by the
  time it runs, but nothing currently guarantees that ordering for an
  ad hoc `executeScript` call the way the static file patch guarantees it for
  declared content scripts.
- If a manifest's `"name"` is an unresolved i18n placeholder (`__MSG_x__`),
  the isolated-world name match in fix 3 misses and that extension's
  content-script activity silently falls back to invisible — not worth a full
  `messages.json` resolver for what is, in practice, a rare manifest style.

---

## Report Surface (added 2026-08-30)

The verdict engine answers "is this dangerous". The report surface answers the
question the person in front of the screen actually has: *what does that mean,
and what do I do?* It is a presentation layer over data the pipeline already
produces — it adds no detection of its own.

### Two audiences, one payload

The result area runs in two modes, toggled top-right and remembered per user in
`localStorage`:

- **Simple** (default) — plain-language verdict, threat gauge, four stat cards,
  the capability list, and export. Written for someone deciding whether to
  install.
- **Advanced** — everything the dashboard showed before this change, unchanged:
  score bars, ML/anomaly figures, flag chips, blocklist card, isolation record,
  plus the full permission panel and network view.

Advanced is the fallback for a rendering failure: the new layer is wrapped in a
`try/catch` that drops to Advanced rather than leaving a blank report.

### Honest metrics

The reference UI this was modelled on shows "Chrome API Calls" and "DOM
Modifications". **C1 measures neither.** The sandbox instruments
eval / fetch / XHR / WebSocket / cookie / keyboard / form — not `chrome.*`
dispatch and not DOM mutation. The stat cards therefore report the four things
that are genuinely measured: network requests, distinct external hosts, runtime
signals, and declared permissions.

Two related rules, both of which exist because a plausible-looking zero is the
most dangerous thing this view could print:

- When the sandbox did not run, the cards show `—` and the reason
  ("sandbox not run" / "extension failed to load"), never `0`. A `0` meaning
  "never observed" reads as "nothing bad happened" — the same false-negative
  class already fixed once in the fusion step.
- The gauge is labelled **THREAT SCORE**, not "confidence". The number is
  `result.score`; calling it confidence would make a SAFE verdict at 12 read as
  "only 12% sure this is safe", the exact inverse of what was measured.

### Declared capability — `core/c1/permissions.py`

A flag says what the extension *did*; a permission says what it is *allowed* to
do. An extension can score clean on every behavioural signal and still hold
`<all_urls>` plus `cookies`, one update away from harvesting credentials — so
capability is shown regardless of verdict.

`explain_permissions(manifest)` returns severity-ranked entries with
plain-language descriptions. It reads both manifest versions by reusing
`features._is_host_pattern` (MV2 mixes host patterns into `permissions`; MV3
splits them out), rates blanket patterns (`<all_urls>`, `*://*/*`) CRITICAL
against a named origin's MEDIUM, and keeps unrated permissions with a generic
description rather than dropping them — an unknown permission is precisely the
one worth showing.

### Network view — realm attribution

`sandbox.summarise_observations()` rolls the raw observation into per-host
aggregates (capped at 40 busiest, `truncated` set when anything was dropped —
a real extension makes 200+ requests and the whole list would be persisted into
every stored row).

The graph is deliberately **not** a force simulation. Its axis is *which JS
realm issued the request*: background worker, content script, or page. That
distinction only exists because those realms are instrumented separately (see
"Fixed 2026-08-29"), and it is the one that matters — a host contacted by the
background worker is being reached with no page open, which is where persistent
C2 lives. A physics layout would scatter that; a radial layout grouped by realm
makes it the first thing visible.

#### Graph interaction (2026-10-10)

One builder, `c1GraphHtml()`, draws the graph for both the app and the exported
HTML report, and one self-contained function, `c1GraphInit()`, wires it (the report
embeds that function's source, so it stays interactive offline). Its CSS is
`_C1_GRAPH_CSS`, mapped onto each page's own colour tokens.

- **Bigger and readable.** The canvas matches the panel's shape, the layout uses
  one to three concentric rings by host count, labels get a halo and shorten when
  crowded, and a small pass nudges a node outward when its label would sit on
  another. A dense list (60 hosts) is still crowded in the default view; zoom
  handles the rest.
- **Zoom and move.** Wheel (and trackpad pinch), the plus and minus buttons, two-finger
  pinch on touch, drag to pan, double click or Fit to reset, and the keys `+`, `-`,
  `0` and the arrows when the graph is focused. A percentage shows the level.
- **Expand** uses real fullscreen (Esc leaves it) and falls back to a taller box
  where fullscreen is refused.
- **Detail.** Hovering or focusing a server dims the rest, lights its edge and shows a
  card (requests, methods, who made them, and from the network intelligence: what the
  host is and its IP addresses). A click keeps the card; a click elsewhere lets go.
- **Legend chips** switch a group on or off. The servers the sandbox's real-page visit
  touched are a hidden group on an outer ring: context, never the extension's own.
- **Graph or List** toggle in the app, and the graph is now shown for any number of
  servers (it used to fall back to a list under three).
- **Animation** is one-shot and transform only: the hub, a single ripple, edges growing
  out of the hub and nodes popping in, played when the graph first scrolls into view.
  Nothing loops, and `prefers-reduced-motion` and print turn it all off.
- Decorative layers (ripple, rings, edges) are `pointer-events:none`. The ripple ends up
  nine times its size and used to swallow every click until that was set.

### Persistence contract

**Everything the report needs must live inside `report`.** `db._to_dict()`
rebuilds a history entry from the stored report JSON alone, so anything kept
beside it is present on a live analysis and silently missing when the user
reopens the same analysis. `identity`, `permissions`, `observed` and
`plain_summary` are therefore written into the report dict by `report.py` and
restored in `db.py`, exactly as `isolation` and `blocklist_details` already
were. `test/C1/test_report_ui.py::TestHistoryRoundTrip` guards this.

### Report as an overlay (2026-08-30)

The report was rendered inline in the C1 panel, which pushed the input controls
and the history list far below the fold and made comparing two analyses a
scrolling exercise. It now opens as a modal over the panel: any history row
opens its own report, and closing returns the operator to exactly where they
were. Escape, the backdrop and the close button all dismiss it; focus moves to
the close button on open and back to the trigger on close.

The shell is capped at **1060px**. That cap is the fix for "a long description
looks ugly": an unbounded report stretched the plain-language summary to ~180
characters a line on a wide monitor. The summary measure is 92ch inside it,
which is within the readable band and uses the width the modal actually has
(620px measured, up from 404px).

Two consequences worth knowing before editing:

- The modal is a **direct child of `<body>`**, deliberately, so no ancestor can
  create a containing block for the fixed overlay. That also puts it outside
  `#panel-c1`, so the C1-scoped text tokens must list `#c1r-modal` too — they
  silently stopped applying when the report first moved, and the contrast audit
  is what caught it.
- Print rules must flatten the overlay (`position:static`, backdrop and title
  bar hidden, shell unbounded) or `printToPDF` captures a viewport-height slice
  with the backdrop painted over it.

**Recent analyses** no longer drops rows past the eighth — a session that
analysed a dozen extensions silently lost its earliest entries, which are the
ones an operator scrolls back for. Every analysis from the session is kept, the
list scrolls, and a count badge shows how many there are.

**Machine-written prose.** The plain summary is assembled from catalogue entries
written with em dashes; three of them in one paragraph is the strongest "an AI
wrote this" tell and reads as unfinished. `report._humanise()` normalises them
to commas on the way out and strips lab jargon ("Sandbox detected" →
"The test run found"), and the permission catalogue was rewritten the same way.

### Engine signatures and the level-panels problem (2026-08-30)

> **Superseded 2026-10-12.** The engine plates described below were removed from the popup: their sentences repeated the meters, the containment card and the notes beside them, and the case where a plate carried news (models not run, sandbox not run) is already said by the panel's own note. `c1EngineHtml`, the two marks and the slot divs are gone, and the two analysis panels again keep their own height (`align-items:start`). The rest of this section (containment moved out, meters, the time-spent bar, saying it once) still holds.

The Static and Dynamic panels sit side by side and hold unrelated amounts of
content, so one was always visibly shorter than the other. This has now been
solved twice, and the second answer supersedes the first:

- **First attempt — `align-items:start`.** Correct diagnosis (stretch was
  padding the short panel out with ~240px of dead space), wrong remedy: it
  stopped the padding but left the pair lopsided.
- **Now — `align-items:stretch` plus content that earns the height.** Three
  changes together:
  1. **Containment moved out.** `c1IsolationHtml()` used to be appended to the
     dynamic column, which made that side permanently taller and squeezed its
     phase legend until the labels truncated ("Observat…"). It renders into
     `#c1-isolation-card`, a full-width card below the pair. That is also the
     honest place for it: containment qualifies *every* dynamic number above
     it, so it is a statement about the run, not a footnote in one column.
  2. **Static gained visual weight.** Its two model outputs were plain text
     next to the dynamic side's chips and cards. They are now meters
     (`c1MeterHtml`) with the remaining single values as fact chips. Same
     numbers — presentation only; nothing here is a new measurement.
  3. **`.c1r-engine-slot{flex:1}`.** Whatever height is still uneven is
     absorbed by the engine plate, whose content centres in it. The slack
     becomes room around a mark instead of a void under the text.

**The engine plates.** Each panel closes with the machinery that produced its
numbers: an inline-SVG mark, the engine name, one line on what it does, and two
spec pills. Inline SVG rather than image files — they inherit the theme, stay
sharp at any DPI, print, and add nothing to load. Both marks use the same
64-unit grid and outer ring so they read as one family.

The marks are drawn from what the engines actually do, not from stock imagery:
the static mark's top wedge is a recursive partition with one point cut off on
its own (isolation forest) and its bottom wedge is three boosting rounds each
taller than the last (gradient boosting); the dynamic mark is a browser
mid-run, inside a shield, inside a *dashed* boundary — the dashes being the
point, since the machine holding it exists only for that analysis.

Both wordmarks are **derived, never hard-coded**, for the same reason the rest
of this report is:

- A blocklist hit that never reached the classifiers is signed *"Blocklist
  authority | models not run"*, not *"XGBoost | Isolation Forest"* — signing it
  otherwise would credit a verdict to two models that were never asked.
- A container or bare-profile run is signed with the containment it actually
  got, from `_C1_ENGINE_DYN[iso.level]`. Only `ephemeral_vm` gets *"Windows
  Sandbox | Hyper-V VM"*.
- A sandbox that did not run gets a greyed plate reading *"Sandbox | not run"*,
  shown rather than omitted: a missing panel reads as "nothing to report",
  which is the opposite of what it means.

**Time spent.** The phase timings printed as one run-on monospace line. They are
now a proportional bar plus a legend, because the question an operator actually
has is whether the time went on *observing the extension* or on *booting a
machine to do it in* — the fixture spends 40% observing and 59% on VM boot and
disposal. Two rules the bar follows: named phases that do not sum to
`total_s` get an explicit **Other** segment rather than being scaled up to
fill the bar, and a phase too small to round to a percent prints `<1%`, never
`0%` — it did happen.

**Saying it once.** With the engine plates in place the containment card was
stating the same fact four ways — the heading names the level, the fact row
proves it, the plate carries the sentence, and `iso.detail` repeated it again.
`iso.detail` is no longer rendered in the card (the field stays in the data for
the JSON export), and the backend warnings were cut roughly in half: the egress
warning keeps *why it matters* and drops the `network_policy='disabled'`
remedy, which belongs in docs rather than in every report, and the host-folder
warning no longer enumerates which four folders they are. Volume of text was
itself the defect — a card that restates its own heading reads as padding.

Verified: panel bottom edges level to **0px** across all three states (VM run,
sandbox not run, blocklist hit); segments sum to 100.0%; contrast **54 pass, 0
below WCAG AA**; print freezes both new animations and keeps the segment
colours via `print-color-adjust`.
The technical panels keep their own voice.

### UI audit (2026-08-30)

A pass over the shipped surface fixed a set of defects that were real quality
problems, not preferences:

- **Unreadable text.** Three places used `--t3` (the dimmest token on the ramp)
  for content rather than for labels: the extension identity line on a tinted
  hero, the score-formula box, and the per-flag explanations in the Verdict
  Report. All moved up the ramp; the identity line became its own chip, since
  the extension ID is the string a reader copies out of the report.
- **`—` for an unmeasured value.** The empty-state glyph became **N/A**. A dash
  still left the reader to guess whether it meant zero or unknown.
- **Verdict text crowding the gauge.** Hero gap and summary width adjusted so a
  long plain-language verdict cannot run into the arc.
- **`window.print()` for a Download button.** It raised Electron's printer
  picker ("This app doesn't support print preview") when the user asked for a
  file. Replaced with `webContents.printToPDF()` over IPC
  (`electron/main.js` → `report:savePdf`): one native Save dialog, a real PDF,
  and the file revealed on disk afterwards. Plain browsers still fall back to
  `print()`.
- **App chrome leaking into the PDF.** The panel header, isolation strip, mode
  toggle and the emptied input card all printed as dark bars on white; badges
  kept their dark fills. Print rules now hide them and repaint chips for paper.
- **Dated isolation strip.** Given the same card treatment as the rest of the
  panel, with a status dot carrying the state at a glance.
- **Sparse single-host network view.** Host rows now carry request-count,
  source and flag pills instead of a plain text suffix.

**Contrast is measured, not eyeballed.** A scripted audit walks every text node
in the rendered report, composites semi-transparent backgrounds down the
ancestor chain, and computes WCAG ratios. The first run returned **31 of 45
nodes below AA** — and the cause was the tokens, not the rules: the shared
`--t3` ramp measures **1.9:1** and `--t2` **4.0:1** against the surfaces this
panel paints on. Both were raised (`--t3` → `#788fb2`, `--t2` → `#9eb5d1`),
scoped to `#panel-c1` so custom-property inheritance fixes ~30 declarations at
once while leaving C2/C3/C4 untouched. Severity chips, which sit on a tint of
their own hue, were lightened separately. The audit now reports **45 pass, 0
failures**, with `t3 < t2 < t1` luminance so the hierarchy still reads.

**The two-column Advanced grid was `align-items: stretch`.** That padded the
short Static panel out to the height of the tall Dynamic one, leaving ~240px of
empty card and a dead seam above the panels below — the defect that survived
two earlier "fixes" because it was diagnosed by eye instead of measured.
`align-items:start` sizes each panel to its own content. Panel spacing is now a
single flex `gap` on the mode containers rather than a mix of child margins,
wrapper divs and inline `margin-top`, which had produced 0/10/20px gaps
depending on nesting depth; both modes now measure a uniform 10px throughout.
Note that the mode switch must set `display:flex` — an inline `block` silently
drops the gap.

Motion was added deliberately and narrowly — content arrives (a short staggered
rise+fade) and numbers resolve (gauge arc sweeps, figures count up). Everything
animates `transform`/`opacity` only, is disabled under
`prefers-reduced-motion`, and is frozen in print so a PDF can never capture a
mid-fade frame.

### Export

- **JSON** — full result payload via `Blob` download.
- **Summary** — plain-text report (verdict, plain summary, permissions, hosts,
  flags, containment).
- **PDF** — `window.print()` against a scoped `@media print` stylesheet that
  hides chrome, forces light-on-white and expands *both* modes so the PDF is
  complete regardless of what was on screen. No library added.

### Verified

Backend contract in `test/C1/test_report_ui.py` (27 tests). Rendering verified
by driving the real `dashboard.html` in Chromium against a genuine analyzer
payload for `core/c1/test_malicious_ext`: MALICIOUS / 92, 28 requests, 3 hosts,
36 signals, 13 permissions (9 high-risk), 3 graph nodes correctly attributed to
the background worker with the raw-IP and WebSocket hosts flagged; both exports
produced correct files; and a result round-tripped through SQLite rendered
identically to the live run.

---

## Panel redesign and performance (2026-10-07, revised 2026-10-08)

The C1 panel was rebuilt around what C1 is: a **gate** that holds an extension
install until a verdict is in. It deliberately does not share C3's layout (C3 is a
traffic monitor: stat tiles, a tab bar, tables). Its lag was measured and removed.
The panel is in `frontend/dashboard.html`, inside C1's own CSS, markup and JS
regions. The only backend change is wording: the report, permission, evidence and
isolation strings that reach the UI no longer use a dash as punctuation (see
"Writing for this panel" below).

### Layout

| Piece | What it does |
|-------|--------------|
| Session strip | A single row at the top of the panel, above the tabs, that applies to every section: the **session posture** on the left and the sandbox **containment** selects on the right. It wraps to two rows in a narrow window. |
| Session posture | A bar whose segment widths are the real malicious / suspicious / safe counts, with the totals. |
| Tabs | Folder-style tabs under the strip, grouped Gate / Analyze / Records (Install gate; Upload CRX, Web Store, Manual; Case ledger, Blocklist). The open tab is the same ink as the stage so it reads as attached. Left/Right (also Up/Down), Home and End move through them. The layout is a vertical flow: strip, tabs, stage. An earlier revision used a left rail; it was dropped because a side-oriented panel did not suit the dashboard. |
| Install gate | The default view. A hero with four live facts (blocklist size as an approximate figure such as "around 7K", containment, analyses this session, last verdict), the **detection pipeline**, then the intercept cards. Descriptions run the full width of the panel instead of wrapping at a character cap. |
| Detection pipeline | Five stages (Intercept, Blocklist, Static analysis, Sandbox, Decision) joined by a line. At rest every stage is armed and the blocklist and sandbox chips show what the machine reports. During an intercept it follows the most recent install, driven by the same WebSocket messages as the live cards: `analyzing` runs blocklist and static, `sandbox_running` runs the sandbox, and the result marks every stage done, with the sandbox shown as "Not run" for a static only case, a blocklist hit marked on its stage, and the decision stage taking the verdict colour. A stage is never marked done on a guess. The line and the stages draw in once each time the gate is opened; the only loop is the ring on a stage that is genuinely running. It is built once and updated by class, so updates do not replay the entrance. |
| Score ring | `.c1-rs`: a circle whose arc is the threat score out of 100, coloured by verdict, with the number inside. Used in the ledger (48px) and on live cards (80px, with a "risk" caption and a count up). The arc draws in once on the top ten ledger rows and on live cards. |
| Case ledger | Every analysis as a **case file**: score ring, name and ID, risk tags (blocklist hit, high risk permissions, permission count, sandbox hosts or "static only") and a verdict **badge**, in aligned score / name / verdict / time columns. Filter by verdict, search by name or ID, and a **threat skyline** where each bar's height is that case's score. **Restored from `GET /extension/history` on start**, so the ledger and posture survive a restart instead of beginning empty. |
| Visual language | Violet-ink surfaces with a faint dot grid, 6px corners, scanner-bracket corners on the gate, live cards and report hero, verdict badges, and "key" buttons with a hard bottom edge. Lavender paper in the light theme. |
| Verdict badge | `.c1-vb`: a solid icon cell (tick / exclamation / cross, so colour is never the only cue) plus the verdict word in sentence case on a tint of the same colour. One element; the glyph is a CSS mask on `::before`, so a ledger of 50 cases adds no extra nodes. Sizes `md` (live cards) and `lg` (report hero). Static, never rotated or animated. On paper it keeps its colour (`print-color-adjust`) but the word stays dark ink, and the hero's scanner brackets are hidden. |
| Report modal | Same content; restyled to the same vocabulary, and the cost below removed. |
| Report export | **HTML report** (the main export), JSON and a plain text summary. The HTML report is one self-contained file built by `c1BuildHtmlReport()`: no external requests, light and dark themes (system default plus a toggle), a contents bar, a score gauge and a 0 to 100 scale showing where the score lands, how the score was combined, findings, a permission table that filters by risk, a host table with request bars, the sandbox containment summary, and a short "about" section. Every analysis value is escaped, and it prints cleanly. **The PDF export was removed on 2026-10-10**; the older notes below describe it for history only (`electron/main.js` still carries the unused `report:savePdf` handler). |

### Why it was laggy, and the rules that now apply

The dashboard runs in Electron with `app.disableHardwareAcceleration()`, so
everything is software-rasterised. Measured in headless Chromium with the GPU off,
a 4x-throttled CPU and a 1920x1010 window:

| Scenario | Before (avg frame) | After |
|----------|--------------------|-------|
| Open a report | 67 ms | 17 ms |
| Report open, idle | 72 ms (14 fps) | 18 ms |
| Click a history row | 70 ms | 17 ms |
| Toggle Simple/Advanced | 77 ms | 22 ms |
| Idle on C1: paint + raster per 4 s | 571 ms | 0 ms |

The cause was one `backdrop-filter:blur()` over the whole viewport under the
report modal, re-run every frame because of the animations running behind it.

Rules for anything added to this panel:

- **No `backdrop-filter`.** Use a flat translucent fill.
- **No infinite animations.** The gate indicator and status dot are static; the only looping motion is a ring on something that is genuinely running (an analysis spinner, a running pipeline stage). Entrances are one shot and stop.
- **Bound entrance animations.** The pipeline entrance is six animations, the ledger ring draw is capped at the top ten rows (a burst of new cases must not start a burst of animations; adding 40 cases at once measured 46 ms per frame without the cap and about 30 with it).
- The verdict filter is pure CSS (`data-f` on the ledger), so it costs one attribute write however many cases there are; only the text search touches rows.
- **No `transition:all`**, and bars grow with `transform:scaleX`, never an animated `width`.
- **No per-item staggered entrance animations.** Opening a report used to start 15 animations in the Simple view and 76 in the Advanced one; it is now 7 and 20.
- Long lists use `content-visibility:auto`; counters share one rAF driver.
- `innerHTML +=` in a loop is banned; build one string and assign once.

### Things worth knowing before editing

- **`.c1-btn` is shared.** The C2 panel and the Live Test Runner use the same class. The global rules are therefore kept exactly as they were and the new button look is scoped to `#panel-c1` / `#c1r-modal`. Restyling it globally changed those panels' buttons; a pixel comparison caught it.
- **One rule reaches into C3, deliberately.** `body:has(#panel-c1.active) #c3-beacon-overlay:not(.active) #c3-beacon-ring{animation:none}`. C3's hidden beacon overlay animates a 50px-blur `box-shadow` forever, which costs ~280 ms of paint per 4 s on every panel. The rule pauses it only while C1 is on screen and the overlay is inactive, so C3's alert is unchanged when it fires. Delete the rule to undo it; the proper fix is to scope that animation to `.active` in C3's own CSS.
- The extension ID in a WebSocket message and extension names in history rows are escaped / sanitised before they reach `innerHTML` or an inline handler; both can be influenced by the monitored browser.
- Failures in this panel use `showToast`, not `alert()` (a modal alert freezes the whole window).

### Buttons (2026-10-10)

One family for everything clickable in C1, scoped to `#panel-c1` and `#c1r-modal` so C2 and the Test Runner keep their own look.

| Role | Class | Used for |
|------|-------|----------|
| Primary | `.c1-btn.primary` | The one main action on a screen: Analyze, Document this ID, Install into Browser. A violet key with a hard bottom edge. |
| Ghost | `.c1-btn.ghost` | Supporting actions: Simulate a click, Try malicious example, Clear, Run sweep, Reload sheet. Outlined, accent icon, tinted on hover. |
| Success | `.c1-btn.success` (with `.primary`) | Approve Install on the live card. A green key. |
| Danger | `.c1-btn.ghost.danger`, `.c1-btn.danger.solid` | Block (outlined, fills red on hover); Force Install is the solid red key. |

- **Sizes:** 34 px by default, `.sm` 28 px. Chips, segmented switches, the dismiss and close icon buttons, the export buttons and the two link buttons ("View full technical report", "+ N more") follow the same hover, pressed and focus behaviour.
- **States every button has:** a hover lift, a pressed state, a visible keyboard focus ring, and a disabled state that stops reacting. `.is-busy` puts a spinner in front of the label while the work runs; `_c1BtnBusy(btn, on)` toggles it (with `aria-busy`) for Analyze file, Check extension, Analyze, Document this ID, Run sweep, Install into Browser and Approve. The spinner is the only thing that loops, and only while the work does.
- **Icons:** the export buttons, Try malicious example, Clear, Reload sheet and Copy indicators have icons. **Document this ID and Run sweep deliberately do not**: their scripts rewrite the label with `textContent` while they run, which would wipe an icon.
- **Colour:** green and red fills use deeper shades so white text keeps its contrast (the same reason `#c8232f` is used for the red).
- **Motion** is transform and colour only and is removed under `prefers-reduced-motion`. The exported HTML report's own buttons and the graph controls got the same hover, pressed and focus treatment.

### Report popup (2026-10-10)

The popup that opens when a case in the ledger is clicked (`#c1r-modal`). Its Advanced view runs to several screens, so it now says where you are and lets you move. Everything is scoped to `#c1r-modal`.

- **Header:** a score badge in the verdict colour (dark ink on the amber and green fills, white on red, for contrast), the extension name, and chips for version, verdict and date. The text still reads "v2.4 / MALICIOUS / date": the separators stay in the markup and are hidden by CSS.
- **Reading progress:** a thin line under the header fills as you scroll.
- **Jump bar (Advanced only):** one chip per section that is actually present (Overview, Analysis, Containment, Permissions, Setup, Network, Activity, Servers, Verdict report, Export). It follows the scroll position (`c1ReportScroll`, one passive, frame-throttled listener), clicking a chip scrolls to the section (smooth, or immediate under reduced motion), and jumping to a folded section opens it. Presence is judged from rendered content, not height, because the popup is still closed when the bar is built.
- **Folding:** each long panel has a chevron in its heading (`c1AddCollapsers`, idempotent, re-run when the permissions panel is rebuilt by "Show all"). *Collapse all / Expand all* sits at the end of the jump bar. The two Analysis panels do not fold, because they are laid out as an equal-height pair.
- **Back to top** appears after scrolling, and the Advanced view now ends with the export buttons (the same row as the Simple view, built by `_c1ExportInner`).
- **Tables** are banded with a hover row. Print hides the new controls and shows folded panels in full.
- **Profile wording:** an alarm whose name is a variable is shown by that name with a "variable" tag instead of `(variable r.Name)`, and an unknown schedule reads "Set at run time" rather than "Not set". `profile.py` stops a URL at `$` or `{` (template literals) and ignores documentation links that framework bundles carry (Vue, Angular and similar).

#### Popup type scale and layout (2026-10-10)

The popup's text used to run at 8 to 11 px (314 of 339 text elements were under 12.5 px), which is too small to read for the length of a report. Two earlier passes (13.5 px, then 12.5 px body text) were still a little large at real desktop size, so the scale was stepped down to the settled middle below. One scale governs it, defined as variables on `#c1r-modal` and applied by scoped overrides:

| Step | Size | Used for |
|------|------|----------|
| micro | 10 px | table column heads, badges, small uppercase labels |
| small | 11 px | secondary text, descriptions, notes, chips |
| body | 12 px | table cells, list items, key and value rows, permission text |
| lead | 13 to 13.5 px | the summary and the recommendation |
| h3 | 14.5 px | panel titles (the header title is 16 px) |

- **Layout:** the popup is 1040 px wide, panels have 17 x 20 px padding and 12 px between them, the score badge is 40 px, the key-fact numbers 24 px and the verdict score 48 px, and the scrollbar is thin and themed.
- **Richer text:** every section heading has an icon tile (`c1AddHeadIcons`, chosen from the heading's own title); the Simple view has a **What to do** callout in the verdict's colour; the Advanced view opens with the same four key-fact cards as the Simple view; the verdict report's flags are class-based rows with a coloured edge, and its recommendation is a callout. None of these used inline font sizes any more.
- **Edit rule:** change a size by editing the variables or the scoped rule in the "Report popup: type scale and layout" block, not by adding an inline `font-size`. The survey that found the problem (every text element with its computed size) is easy to rerun in a browser console.
- **Graph:** labels are 13.5 px (11.5 px when the extension has more than 26 servers), and the label spacing estimate follows the font size.
- **Phones:** below 760 px the padding, hero text, gauge and heading sizes step down.

#### Popup reading aids (2026-10-12)

The Advanced view held a lot of correct information in a flat layout: sentences with the key value buried in them, the same fact stated in a note, a table row and a second table, and lists of 60 near-identical rows. These changes are presentation only; no data, score or backend field changed. All of it is `#c1r-modal` scoped, in the "Report popup: reading aids" CSS block.

- **Values are picked out.** A name is a violet mono chip, a time or count is an amber chip, an address is a blue mono chip, and a zero is quiet grey (a count of 0 is not an alert). `_c1Hl()` does this for prose (the Simple view's notes, which also show `"(variable O)"` as `O`); the Advanced panels build the chips directly from the profile's structured data (`_c1HlTag`).
- **How it is set up** has three parts instead of sentences, a table and a second table: *Worth a look* (flag cards built from the profile: schedule, uninstall page, runtime code, remote scripts, plain http, rewritten traffic, executables, files visible to websites, each with a one line reason where one is useful), *At a glance* (neutral fact tiles; anything already flagged is not repeated), and the browser and data API chips (a name and a count, the few that touch private data tinted). The schedule card lists each alarm as `name` then `every 1 min`; a name set in code shows its own name with a "name set in code" tag. The "Servers named in its code" table is gone from this panel because the Servers panel already lists those hosts.
- **What it did when run.** Only what was seen is lit (amber chips); what was not seen is one line ("None seen: ..."). Requests show a summary line (how many, to how many hosts, how many sent data, how many over plain http, and who made them), then the first 8 rows with the one that sent data first; the "Made by" column is dropped when every request has the same source. The standard test pages are one tag under the heading (the list is its tooltip); the page-owned counts and "busiest servers" sentence were removed because they describe those sites, not the extension.
- **Servers and indicators.** Role (Contacted, Opened by it, Named in its code) and type (Its own server, Shared service, Unexplained, Raw IP address) are colour coded badges, with a legend that counts each in the same colours. The first 10 rows show, then "Show all N servers". Hosts that use plain http carry a tag (from the profile). The Domains, IP addresses and URLs lists start folded with a count each; *Copy indicators* copies all of them.
- **Folding** is one function, `c1Fold(btn)`: it toggles `.open` on the nearest `.c1r-fold`, and CSS hides `.more` rows or lists until then. Print shows everything and hides the buttons. A folded panel (the heading chevron) keeps only its heading, with a rule strong enough to beat the display values the new classes set.
- **Removed as filler:** the two engine plates, the "Scored against extensions already known..." line, the setup and servers subtitles that restated their titles, and the permissions subtitle was shortened.
- **Palette.** One small set (`--tn-pu/bl/gr/am/rd`) with a light variant, tints made with `color-mix`. In light theme every lit label is at least 4.5:1 against its tint (checked in the popup test).
- **HTML report.** Only the real-page block changed (one line instead of a section); the report's other sections are as before.

#### Popup scores, logos and the gate (2026-10-12)

- **Anomaly score from history.** It was never lost: it is saved inside the stored report (`score_breakdown.anomaly_score`) but `db._to_dict` did not read it back, so only an analysis still in memory showed it and every reopened one read 0.0. It is now restored into `static.anomaly_score`. An analysis saved without it shows "Not recorded", never a 0.
- **Score displays.** The header badge and the Advanced card's big score are rings (a CSS conic gradient filled to the score, in the verdict colour, drawn once). The number driving the arc is a plain custom property, `--c1p`, moved by a short `requestAnimationFrame` ease (`_c1RingIn`); it is deliberately not registered with `@property`, which would apply page-wide and C2 uses its own `--p`. The Simple summary's verdict is a pill with a round icon, and its gauge draws three zones (green, amber, red), a tick at 40 and 70, a gradient arc and an end marker.
- **Logos.** Each model has a small mark beside its own score (XGBoost: three boosting rounds, each taller than the last; Isolation Forest: a tree with the isolated point in amber), and the Dynamic panel opens with a mark and two short lines for what the sandbox ran in: Windows Sandbox (a closed ring, a shield and a tick), Host process (an open amber ring, partial isolation), Container (dashed blue) and No containment (slashed red), chosen from `isolation.level`, so a history row shows the same mark it had live. They draw in once and never loop; under reduced motion they appear finished. The engine plates removed earlier are not back: these carry no sentences.
- **Install gate.** A card shows Block while it analyses, and Approve Install only when the verdict is Safe. The greyed out button that used to carry the verdict word is gone (it could not be clicked); a later, worse result removes Approve again.

### Writing for this panel

- **No dash as punctuation** in anything the user reads: no em dash, en dash or spaced hyphen. Use a full stop, a comma or a colon. Plain compound words (read only, sign in) are written as words where that reads naturally. Extension names are data and are shown exactly as the extension spells them.
- **Descriptions are not width capped.** A `max-width` in `ch` leaves a wrapped column and a blank right half on a wide window. Let the text fill its container.
- **Stored analyses carry the wording of the backend that wrote them.** `_c1Prose()` normalises generated prose (summary, flag and permission descriptions, recommendation, detail) when it is rendered: a comma before a connective such as "including", a colon otherwise, and a short list of old hyphenated compounds as plain words. Apply it to generated prose only, never to names.
- **The blocklist size is approximate on the Install gate** (`c1ApproxCount`, for example "around 7K"). The Blocklist tab is a coverage audit and keeps the exact counts.

## Install, approve and block (2026-10-08)

Three ways an extension reaches the monitored browser, and what each guarantees.

| Action | Where | What happens |
|--------|-------|--------------|
| **Approve Install** | Install gate card, SAFE verdicts only | `POST /session/approve_install` takes the held approval and loads the unpacked extension into the live session. |
| **Install into Browser** | Report (Web Store lookups and live intercepts) | `POST /session/install_extension` downloads and analyses the extension, then loads it into the live session. A MALICIOUS verdict needs the explicit "Force Install" label. |
| **Block** | Install gate card | `POST /session/block_install` drops the held approval and remembers the ID until the next Add to Chrome click on it. |

Chromium only accepts extensions at launch, so loading one **restarts the browser session** (about 5 s). Both install paths answer at once and finish in the background through `_bg_install_extension` and `_load_extension_into_session` in `core/main.py`, then report over the WebSocket: `c1_install_approved` (gate), `c1_extension_installed` (report), or `c1_install_error`.

What the restart has to get right, each of which used to look like "the button does nothing":

- **C3 is detached and re-attached.** It holds handles on the browser context that gets closed. The same stop and start calls as `/session/stop` and `/session/start` are made around the restart.
- **Success is checked, not assumed.** `--load-extension` skips an extension it cannot load without any error. `PlaywrightSession.extension_loaded()` reads `chrome://extensions-internals` and confirms the path is really loaded; a rejected one is dropped from the launch list and reported.
- **A failed launch is retried** (the profile can stay locked for a moment after the old browser exits), and one restart runs at a time (`_ext_install_lock`).
- **A stopped session is not started by an install.** The extension is queued and the approval is kept, with a message saying so. Starting a bare browser would leave it with no monitoring attached.
- **A failure keeps the approval**, so the card offers "Retry install" instead of hanging on "Installing...".

The dashboard side: the report's install button is shared by every report, so it is reset on each render (it used to stay disabled after the first use) and shows an Installed state for extensions loaded this session. Block updates the card itself and reports failure instead of relying on the WebSocket to echo it. A second Add to Chrome click on an extension builds a new card (the old one kept its Blocked actions, so the extension could not be approved).

Block is remembered for the session: an analysis still running when Block is clicked finishes onto a card that cannot be approved, and `approve_install` answers 409 for a blocked ID. The next click on that extension clears the block.

## Evidence layer (added 2026-10-10)

The verdict answers "how malicious does this look". A reviewer also needs to know
what the extension *is*, what it did, and who it talked to. This layer records
that, using a comparison against another analyzer's report for the same
extension (Ad Blocker Pro) as the yardstick. **None of it changes a score or a
verdict**; it is evidence beside them, kept in the stored report so a reopened
analysis still has it.

| Piece | Code | What it adds |
|-------|------|--------------|
| Static profile | `profile.py` `build_profile()` | Background process, content scripts declared **and registered from code** (with JS world and sites), alarms with their schedule (names resolved through constants and `importScripts`), domains named in the code, uninstall page, sensitive API use, eval and remote-script counts, declarativeNetRequest rule counts by action, package inventory. Reads the unpacked folder when there is one, because the classifier input is capped at 300 KB. Offline, never raises. |
| Request attribution | `sandbox.py` `_request_source()` | Each request is tagged `background`, `bait_page`, `browse_page`, `other_page` or `page`. A real site's own traffic (`browse_page`, `other_page`) is **listed but never scored**. |
| Request detail | `sandbox.py` `summarise_observations()` | One row per distinct call: method, address, who made it, size and **field names** of any body (never values). Plus behaviour counts, pages the extension opened by itself, and the traffic of the visited sites kept apart. |
| Real-page visit | `sandbox.py` `_browse_real_pages()` | After the bait page, visits `example.com`, a Wikipedia page and a news page so a content blocker or content script has something real to act on. Reported only, and shown in the popup as one small tag ("Also run on 3 standard test pages"), because it is the same for every extension. Skipped when the extension did not load; failures (no network) are recorded, not fatal. |
| Content-script world | `sandbox.py` `_track_isolated_world()`, `_display_name()` | Resolves `__MSG_x__` display names from `_locales`, so the content-script world of a translated extension is matched and read (the old "known gap"). Read only: see the limit below about hooking. |
| Time limits | `sandbox.py` `_bounded()`, `_step()` | Every read-back from the browser (page, worker, content-script world) and every step of the real-page visit has a time limit, and the visit has a 60 s budget, so a busy or hung page costs seconds, never the analysis. Phase lines (`[c1-observe] ...`) go to stdout, which inside the VM is the guest log the host returns when a run times out. |
| Network intelligence | `netintel.py` `build_network_intel()` | Each host is classed as the extension's own server (named in its code), a shared service, a raw IP or unexplained; DNS adds IP addresses; defanged domain, IP and URL indicators for the extension's own infrastructure only. Query strings are dropped from URL indicators because they often carry an install identifier. |

How it connects: `analyzer._evidence_extras()` builds `profile` and
`network_intel` once and every result path attaches them (normal, blocklist
evidence, blocklist instant). `report.build_report()` copies them into the report
dict. The dashboard shows them as "How it is set up", "What it did when run" and
"Servers and indicators" in the Advanced view, a short "Worth knowing" list in the
Simple view, and the same sections in the HTML report.

### Rules worth keeping

- **Evidence, not score.** The profile, the real-page visit and the network
  intelligence never feed `_score()` or the fusion. Only attributable activity
  (bait page, background worker, content script) is scored, exactly as before;
  on the bundled malicious test extension the dynamic score and flags are
  identical with and without this layer.
- **Empty means not looked up.** A lookup that fails or is switched off is
  recorded in `network_intel.lookups`; it is never shown as clean.
- **`sandbox.py` stays self-contained.** The VM guest stages that file alone, so
  it must not import other C1 modules (`test_c1_intel.py` checks this). The
  host-only modules (`profile.py`, `netintel.py`) are free to import each other.
- **Sizes are capped.** 60 request rows, 40 hosts, 12 page hosts and 1,500 raw
  requests per run, so a noisy extension cannot bloat the stored report.

### Lookups and settings

- DNS runs on the host after the sandbox, for at most 12 hosts, 4 s each.
- No third-party reputation service is used (a VirusTotal column was tried and
  removed on 2026-10-10: it needs an API key the project does not have, so it only
  ever said "not checked").
- `C1_NETINTEL_LOOKUPS=off` switches the DNS lookup off (the test suite sets it).
- The real-page visit is the `browse` argument of `observe_extension()`
  (default on) and the `_BROWSE_URLS` list in `sandbox.py`.

### Known limits

- The real-page visit uses three public pages. It shows how an extension behaves
  on ordinary sites, not on a bank or a shop, so it can miss behaviour keyed to
  specific sites or to a later date.
- The first request of a tab the extension opens is not visible to the network
  listener, so the opened page is reported as a page, with its sub-requests
  listed as the site's own traffic.
- Content scripts an extension registers from code are not hooked, only reported
  in the profile. Installing the monitor into such a world after it exists was
  tried and removed: inside the Windows Sandbox VM it starved the extension's own
  background worker (found by running variants of the observer in the VM, with
  the display-name match and the reads on and only the hook off). Declared
  content scripts are still hooked from the first line, as before.
- If a VM run is cut off, an orphaned sandbox can stay resident. `wsb list` shows
  it and `wsb stop --id <id>` removes it without administrator rights (the
  elevated `Restart-Service vmcompute -Force` the backend suggests is not needed
  on this Windows version).
- No library vulnerability scan (RetireJS style) and no automated "benign
  confidence" are included, to keep the layer simple.
- A broad-permission ad blocker can still score high on the static model. That
  is the classifier's behaviour, not something this layer changes; the profile
  and the attributed requests are there so a reviewer can see why and judge it.

### Verified

`test/C1/test_c1_intel.py` (35 tests): profile facts, alarm-name resolution,
request attribution and the unchanged score for a site's own traffic, the summary
shape and size cap, domain roles and defanging, lookups with fakes, and the
history round trip. Live: Ad Blocker Pro analysed through the real pipeline in a
headless-patched in-process sandbox and in the Windows Sandbox VM (about 65 s end to
end, same score and verdict as the in-process run), and the bundled malicious test
extension in the VM (score 100 and the same 36 signals as before this layer); the dashboard
panels and the HTML report were driven in Chromium (31 checks including hostile
input, mobile width, print and old stored analyses) and the computed style of the
964 elements outside C1 was identical to the previous version.

---

## Verdict Engine

### Score Fusion
```
score_final = (0.7 * score_static) + (0.3 * score_dynamic)
```

### Verdict Rules
- MALICIOUS if the score is 70 or more
- SUSPICIOUS if it is 40 or more
- SAFE otherwise

The score is the **whole number the dashboard shows** (half up), not the decimal behind it. `report.verdict_for()` is the single place that decides, and `analyzer.py` uses it. Before 2026-10-12 the comparison used the unrounded score, so a score of 69.84 was shown as 70 (the malicious threshold) but labelled SUSPICIOUS. The dashboard's colours (`c1Color`, `c1BadgeClass`) round the same way, so label and colour cannot disagree with the number.

An analysis saved under the old rule is corrected when it is read back (`db._to_dict`): only a label the old rule itself produced, for a score in the rounding gap (69.5 to 69.99, or 39.5 to 39.99), is changed, and the report text that states the verdict (`risk_level`, `recommendation`, the summary opener, the plain summary opener) is rewritten to match by `report.restate_verdict()`. The stored row is not rewritten, and a verdict the old rule would not have produced (an authority decision such as a blocklist hit) is left as stored.

### Evidence Output
- Human-readable report string
- Evidence flags aligned to behavior signals

---

## File Map (C1)
| File | Role |
|------|------|
| analyzer.py | Orchestrates static + dynamic analysis |
| features.py | Manifest + code feature extraction |
| static_model.py | ML loading + inference (XGBoost + Isolation Forest) |
| sandbox.py | Playwright sandbox runner (headed Chromium) |
| blocklist.py | Finalized blocklist loader, gap detection, and CSV write-back |
| enrich.py | Live evidence resolution (name/version/store/hash) + reason derivation |
| ../../packaging/c1_guest.spec | Builds the guest runtime the installer ships for the disposable VM (see "The disposable VM in an installed build") |
| ../../electron/installer/c1_sandbox.nsh, enable-windows-sandbox.ps1 | The installer's optional "Turn on Windows Sandbox" page and the script behind it (see "Turning on Windows Sandbox at install time") |
| isolation/ | Sandbox containment backends — `base.py` (contract + IsolationReport), `inprocess.py` (host fallback), `windows_sandbox.py` (disposable VM), `guest_agent.py` (runs inside the VM) |
| report.py | Human-readable report + flag catalogue + plain-language summary |
| profile.py | Static extension profile: background and content scripts, alarms, endpoints, API use, rule sets, package |
| netintel.py | Domain roles, DNS and defanged indicators for the hosts an extension contacts or names |
| permissions.py | Declared-capability risk catalogue (severity + plain-English description per permission) |
| db.py | SQLite analysis history |
| crx_utils.py | CRX v2/v3 parsing + Chrome Web Store download |
| models/ | Trained model artifacts (XGBoost `.pkl`, Isolation Forest `.pkl`, metadata) |
| scripts/ | Dataset prep and training scripts — see `scripts/README.md` |
| data/ | Local datasets and CSVs (gitignored) |

---

## Integration Points

### Backend Endpoint
- POST /extension/analyze (to add in core/main.py)
  - payload: {"extension_path": "..."} or {"manifest": "...", "source": "..."}
  - response: C1 output contract

Blocklist evidence endpoints (core/main.py):
| Endpoint | Purpose |
|----------|---------|
| GET  /extension/sandbox/isolation | Available containment backends, which is active, and why the VM is unavailable if it is |
| GET  /extension/blocklist/stats | Documented-vs-undocumented counts for the sheet |
| GET  /extension/blocklist/incomplete?limit=N | IDs whose row still has gaps |
| GET  /extension/blocklist/{ext_id} | One row plus its remaining gaps |
| POST /extension/blocklist/document | Download, analyse, and document one ID |
| POST /extension/blocklist/backfill | Sweep a batch; progress over the dashboard WebSocket |

WebSocket messages added for the dashboard: `c1_install_intercepted` gains a
`blocklist_evidence` state (fired when a hit needs evidence, carrying the gap
list), plus `c1_blocklist_documented` and `c1_blocklist_backfill`.

### Dashboard Output
- Include C1 verdict, score, and flags in the central dashboard
- Share Extension ID + score with Component 4 for attribution

---

## Development Phases (from plan)

### Phase 1: Data Collection (Now)
- Download malicious datasets
- Collect benign extension manifests
- Build unified CSV (label 0/1)
- Gather CRX samples for sandbox testing

### Phase 2: Static Analysis (Weeks 3-5)
- Build hash detection
- Manifest parser + feature vector
- Add content script entropy + API call frequency features
- Train XGBoost and compare baselines
- Output static_score (0-100)

### Phase 3: Dynamic Sandbox (Weeks 6-9)
- Docker + headless Chrome + Puppeteer
- Log API calls, DOM access, network traffic
- Track cookie access and cross-origin fetches
- Validate against known malicious samples

### Phase 4: Verdict Engine + Dashboard (Weeks 10-12)
- Merge static + dynamic scores
- Provide evidence list and reasoning
- Full evaluation vs baselines

---

## Development Start (Post-Training)

After model training, begin development by wiring the model into the static pipeline:

1) Define runtime inputs
  - Decide how the analyzer receives data (manifest.json + JS source initially; CRX later).
  - Confirm output contract (score, verdict, evidence flags).

2) Build the feature extractor
  - Implement features.py to convert manifest + code into model features.
  - Load dataset_clean_features.json to keep feature order consistent.

3) Load and run the trained model
  - Implement static_model.py to load extension_detector_model.pkl.
  - Return ml_score (0-100).

4) Add hash check
  - Load malicious_ids.txt (and other blocklists).
  - Short-circuit to MALICIOUS on match.

5) Implement analyze_extension()
  - Orchestrate: hash -> features -> model -> score -> verdict.

6) Wire the backend endpoint
  - Add /extension/analyze and return the full C1 output contract.

---

## Evaluation Metrics
- Precision, Recall, F1-score
- Compare static-only vs dynamic-only vs fused
- False positive rate on benign set
- Verdict time (end-to-end latency)

---

## AI Session Starter
"I am working on WebSentinel Component 1 (C1) - Malicious Browser Extension Analyzer.
The architecture and steps are in core/c1/ARCHITECTURE.md. I need help implementing
static feature extraction, ML training, and Puppeteer sandbox checks."
- Precision, recall, F1
- Compare: static-only vs dynamic-only vs fused
- False positives on benign set

---

## AI Session Starter
"I am working on WebSentinel Component 1 (C1) - Malicious Browser Extension Analyzer.
I need help implementing static analysis, ML training, and sandbox behavior checks.
The C1 architecture is in core/c1/ARCHITECTURE.md and the entry point stubs are in
core/c1/analyzer.py."
