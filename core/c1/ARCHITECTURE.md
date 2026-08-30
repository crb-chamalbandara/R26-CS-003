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

Sweeping the rest offline: `python -m core.c1.scripts.backfill_blocklist_evidence
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

## Verdict Engine

### Score Fusion
```
score_final = (0.7 * score_static) + (0.3 * score_dynamic)
```

### Verdict Rules
- MALICIOUS if score_final >= 70
- SUSPICIOUS if score_final >= 40
- SAFE otherwise

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
| isolation/ | Sandbox containment backends — `base.py` (contract + IsolationReport), `inprocess.py` (host fallback), `windows_sandbox.py` (disposable VM), `guest_agent.py` (runs inside the VM) |
| report.py | Human-readable report + flag catalogue + plain-language summary |
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
